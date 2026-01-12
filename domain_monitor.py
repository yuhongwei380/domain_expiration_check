import os
import sqlite3
import whois
import concurrent.futures
import pandas as pd
import socket
import re
import requests
import json
import time
import hmac
import hashlib
import base64
import urllib.parse
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from datetime import datetime, date, timezone, timedelta

# --- Flask & Auth 模块 ---
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# 1. 配置密钥：优先从环境变量读取，否则使用默认值（生产环境建议在 docker-compose 中配置 SECRET_KEY）
app.secret_key = os.environ.get('SECRET_KEY', 'secret_key_v6_cn_fix_auth_docker')

# 2. 配置数据存储路径：支持 Docker 挂载
DATA_DIR = os.environ.get('DATA_DIR', '.')
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)
DB_FILE = os.path.join(DATA_DIR, 'domains.db')

# 定义 UTC+8 时区
TZ_CN = timezone(timedelta(hours=8))

# --- Flask-Login 初始化 ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录管理员账号'

# --- 用户模型 ---
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if row:
            return User(id=row[0], username=row[1], password_hash=row[2])
    return None

# --- 数据库操作 ---

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        
        # 1. 域名表
        c.execute('''CREATE TABLE IF NOT EXISTS domains (
                        domain TEXT PRIMARY KEY,
                        registrar TEXT,
                        expiry_date TEXT,
                        days_left INTEGER,
                        status TEXT,
                        last_update TEXT
                    )''')
        
        # 2. 配置表
        c.execute('''CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT
                    )''')
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('alert_days', '30'))
        
        # 3. 用户表
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password_hash TEXT
                    )''')
        
        # 4. 初始化/更新管理员账号
        # 从环境变量获取密码，默认 admin888
        env_password = os.environ.get('ADMIN_PASSWORD', 'admin888')
        p_hash = generate_password_hash(env_password)
        
        c.execute("SELECT id FROM users WHERE username = 'admin'")
        row = c.fetchone()
        
        if row:
            # 如果管理员已存在，强制更新密码（确保 Docker 环境变量修改后生效）
            c.execute("UPDATE users SET password_hash = ? WHERE username = 'admin'", (p_hash,))
            print(f"系统启动: 管理员(admin) 密码已根据环境变量更新。")
        else:
            # 如果不存在，创建默认管理员
            c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ('admin', p_hash))
            print(f"系统启动: 管理员(admin) 已创建，初始密码: {env_password}")
            
        conn.commit()

def get_setting(key, default=None):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key=?", (key,))
        res = c.fetchone()
        return res[0] if res else default

def save_setting(key, value):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()

def get_all_domains():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM domains ORDER BY days_left ASC")
        return [dict(row) for row in c.fetchall()]

def add_or_update_domain_db(domain_data):
    current_time_cn = datetime.now(TZ_CN).strftime('%Y-%m-%d %H:%M:%S')
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO domains 
                     (domain, registrar, expiry_date, days_left, status, last_update) 
                     VALUES (?, ?, ?, ?, ?, ?)''', 
                     (domain_data['domain'], domain_data['registrar'], 
                      domain_data['expiry_date'], domain_data['days_left'], 
                      domain_data['status'], current_time_cn))
        conn.commit()

def delete_domains_db(domain_list):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for d in domain_list:
            c.execute("DELETE FROM domains WHERE domain=?", (d,))
        conn.commit()

# --- 核心查询逻辑 ---

def calculate_days_left(exp_date):
    if not exp_date: return None
    now = datetime.now(TZ_CN)
    if isinstance(exp_date, date) and not isinstance(exp_date, datetime):
        exp_date = datetime(exp_date.year, exp_date.month, exp_date.day)
    if exp_date.tzinfo is None:
        exp_date = exp_date.replace(tzinfo=TZ_CN)
    else:
        exp_date = exp_date.astimezone(TZ_CN)
    delta = exp_date - now
    return delta.days

def query_cn_socket(domain):
    """ Socket 深度查询 .cn 域名 """
    print(f"尝试使用 Socket 深度查询: {domain}")
    whois_server = "whois.cnnic.cn"
    port = 43
    response = b""
    try:
        with socket.create_connection((whois_server, port), timeout=10) as s:
            s.sendall(f"{domain}\r\n".encode())
            while True:
                data = s.recv(4096)
                if not data: break
                response += data
        text = response.decode('utf-8', errors='ignore')
        exp_match = re.search(r'Expiration Time:\s*(\d{4}-\d{2}-\d{2})', text, re.IGNORECASE)
        reg_match = re.search(r'Sponsoring Registrar:\s*(.+)', text, re.IGNORECASE)
        result = {}
        if exp_match:
            date_str = exp_match.group(1)
            result['expiry_date'] = datetime.strptime(date_str, '%Y-%m-%d')
        if reg_match:
            result['registrar'] = reg_match.group(1).strip()
        return result
    except Exception as e:
        print(f"Socket 查询失败 {domain}: {e}")
        return None

def query_whois_online(domain):
    domain = domain.strip().lower()
    info = {'domain': domain, 'registrar': '-', 'expiry_date': '-', 'days_left': 99999, 'status': 'Pending'}
    found_date = None
    found_registrar = None

    try:
        w = whois.whois(domain)
        exp_date = w.expiration_date
        if isinstance(exp_date, list): exp_date = exp_date[0]
        registrar = w.registrar
        if isinstance(registrar, list): registrar = registrar[0]
        if exp_date:
            found_date = exp_date
            found_registrar = registrar
    except Exception as e:
        print(f"标准库查询失败 {domain}: {e}")

    if not found_date and domain.endswith('.cn'):
        fallback_data = query_cn_socket(domain)
        if fallback_data:
            if 'expiry_date' in fallback_data: found_date = fallback_data['expiry_date']
            if 'registrar' in fallback_data: found_registrar = fallback_data['registrar']

    if found_date:
        info['expiry_date'] = found_date.strftime('%Y-%m-%d')
        info['registrar'] = str(found_registrar) if found_registrar else 'Unknown'
        days = calculate_days_left(found_date)
        info['days_left'] = days
        
        try: alert_days = int(get_setting('alert_days', 30))
        except: alert_days = 30
            
        if days is not None:
            if days < 0: info['status'] = 'Expired'
            elif days < alert_days: info['status'] = 'Warning'
            else: info['status'] = 'Active'
        else: info['status'] = 'Calc Error'
    else:
        info['status'] = 'Query Failed'
        if found_registrar: info['registrar'] = str(found_registrar)
    return info

def refresh_domains_task(domain_list):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_domain = {executor.submit(query_whois_online, d): d for d in domain_list}
        for future in concurrent.futures.as_completed(future_to_domain):
            try:
                data = future.result()
                add_or_update_domain_db(data)
                results.append(data)
            except: pass
    return results

# --- 告警发送逻辑 (含加签) ---

def send_alert_messages(expiring_domains):
    if not expiring_domains: return

    msg_title = f"⚠️ 域名过期预警 ({len(expiring_domains)}个)"
    msg_body = "以下域名即将过期或已过期，请及时处理：\n\n"
    for item in expiring_domains:
        msg_body += f"- {item['domain']}: 剩余 {item['days']} 天 ({item['date']})\n"
    
    full_text = f"{msg_title}\n{msg_body}"
    print("触发告警:\n" + full_text)

    ding_token = get_setting('ding_webhook')
    ding_secret = get_setting('ding_secret')
    feishu_token = get_setting('feishu_webhook')
    feishu_secret = get_setting('feishu_secret')
    smtp_host = get_setting('smtp_host')
    
    # 钉钉
    if ding_token:
        try:
            target_url = ding_token
            if ding_secret:
                timestamp = str(round(time.time() * 1000))
                secret_enc = ding_secret.encode('utf-8')
                string_to_sign = '{}\n{}'.format(timestamp, ding_secret)
                string_to_sign_enc = string_to_sign.encode('utf-8')
                hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
                sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
                separator = '&' if '?' in ding_token else '?'
                target_url = f"{ding_token}{separator}timestamp={timestamp}&sign={sign}"
            
            headers = {'Content-Type': 'application/json'}
            data = {"msgtype": "text", "text": {"content": full_text}}
            requests.post(target_url, headers=headers, data=json.dumps(data), timeout=5)
            print("钉钉发送成功")
        except Exception as e: print(f"钉钉发送失败: {e}")

    # 飞书
    if feishu_token:
        try:
            headers = {'Content-Type': 'application/json'}
            data = {"msg_type": "text", "content": {"text": full_text}}
            if feishu_secret:
                timestamp = str(int(time.time()))
                string_to_sign = '{}\n{}'.format(timestamp, feishu_secret)
                hmac_code = hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
                sign = base64.b64encode(hmac_code).decode('utf-8')
                data['timestamp'] = timestamp
                data['sign'] = sign
            requests.post(feishu_token, headers=headers, data=json.dumps(data), timeout=5)
            print("飞书发送成功")
        except Exception as e: print(f"飞书发送失败: {e}")

    # 邮件
    if smtp_host:
        try:
            smtp_port = int(get_setting('smtp_port', 465))
            smtp_user = get_setting('smtp_user')
            smtp_pass = get_setting('smtp_pass')
            smtp_to = get_setting('smtp_to')
            
            if smtp_user and smtp_pass and smtp_to:
                message = MIMEText(msg_body, 'plain', 'utf-8')
                message['From'] = Header(f"DomainMonitor <{smtp_user}>", 'utf-8')
                message['To'] =  Header(smtp_to, 'utf-8')
                message['Subject'] = Header(msg_title, 'utf-8')
                if smtp_port == 465:
                    server = smtplib.SMTP_SSL(smtp_host, smtp_port)
                else:
                    server = smtplib.SMTP(smtp_host, smtp_port)
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, smtp_to, message.as_string())
                server.quit()
                print("邮件发送成功")
        except Exception as e: print(f"邮件发送失败: {e}")

# --- 路由配置 ---

# 1. 游客主页 (只读)
@app.route('/')
def index():
    domains = get_all_domains()
    try: alert_days = int(get_setting('alert_days', 30))
    except: alert_days = 30
    return render_template('guest.html', domains=domains, count=len(domains), alert_days=alert_days)

# 2. 登录页
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            if row and check_password_hash(row[2], password):
                user = User(id=row[0], username=row[1], password_hash=row[2])
                login_user(user)
                flash('登录成功')
                return redirect(request.args.get('next') or url_for('admin_dashboard'))
            else:
                flash('账号或密码错误')
    return render_template('login.html')

# 3. 退出登录
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('已退出登录')
    return redirect(url_for('index'))

# 4. 管理员后台
@app.route('/admin')
@login_required
def admin_dashboard():
    domains = get_all_domains()
    try: alert_days = int(get_setting('alert_days', 30))
    except: alert_days = 30
    return render_template('admin.html', domains=domains, count=len(domains), alert_days=alert_days)

# 5. 设置页面
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        save_setting('alert_days', request.form.get('alert_days', '30'))
        save_setting('ding_webhook', request.form.get('ding_webhook', '').strip())
        save_setting('ding_secret', request.form.get('ding_secret', '').strip())
        save_setting('feishu_webhook', request.form.get('feishu_webhook', '').strip())
        save_setting('feishu_secret', request.form.get('feishu_secret', '').strip())
        save_setting('smtp_host', request.form.get('smtp_host', '').strip())
        save_setting('smtp_port', request.form.get('smtp_port', '465').strip())
        save_setting('smtp_user', request.form.get('smtp_user', '').strip())
        save_setting('smtp_pass', request.form.get('smtp_pass', '').strip())
        save_setting('smtp_to', request.form.get('smtp_to', '').strip())
        flash('配置已保存')
        return redirect(url_for('settings'))
    
    config = {
        'alert_days': get_setting('alert_days', '30'),
        'ding_webhook': get_setting('ding_webhook', ''),
        'ding_secret': get_setting('ding_secret', ''),
        'feishu_webhook': get_setting('feishu_webhook', ''),
        'feishu_secret': get_setting('feishu_secret', ''),
        'smtp_host': get_setting('smtp_host', ''),
        'smtp_port': get_setting('smtp_port', '465'),
        'smtp_user': get_setting('smtp_user', ''),
        'smtp_pass': get_setting('smtp_pass', ''),
        'smtp_to': get_setting('smtp_to', ''),
    }
    return render_template('settings.html', config=config)

# 6. 后台操作接口 (需登录)

@app.route('/refresh_all')
@login_required
def refresh_all():
    current_domains = [row['domain'] for row in get_all_domains()]
    if not current_domains:
        flash('列表中没有域名')
        return redirect(url_for('admin_dashboard'))
    
    flash(f'正在后台更新 {len(current_domains)} 个域名...')
    updated_data = refresh_domains_task(current_domains)
    
    try: threshold = int(get_setting('alert_days', 30))
    except: threshold = 30
    
    expiring_list = [d for d in updated_data 
                     if d.get('days_left') is not None and isinstance(d.get('days_left'), int) and d.get('days_left') < threshold]
    
    if expiring_list:
        send_alert_messages(expiring_list)
        flash(f'更新完成，发现 {len(expiring_list)} 个域名即将过期，已触发告警。')
    else:
        flash('更新完成，所有域名状态良好。')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/add_single', methods=['POST'])
@login_required
def add_single():
    domain = request.form.get('domain')
    if domain:
        domain = domain.strip().lower()
        add_or_update_domain_db({
            'domain': domain, 'registrar': 'Loading...', 
            'expiry_date': '-', 'days_left': 0, 'status': 'New'
        })
        info = query_whois_online(domain)
        add_or_update_domain_db(info)
        flash(f'已添加: {domain}')
    return redirect(url_for('admin_dashboard'))

@app.route('/batch_delete', methods=['POST'])
@login_required
def batch_delete():
    selected = request.form.getlist('selected_domains')
    if selected:
        delete_domains_db(selected)
        flash(f'已删除 {len(selected)} 个域名')
    else:
        flash('未选择域名')
    return redirect(url_for('admin_dashboard'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files: return redirect(request.url)
    file = request.files['file']
    if not file or file.filename == '': return redirect(request.url)
    try:
        filename = file.filename.lower()
        df = None
        if filename.endswith('.csv'): df = pd.read_csv(file, header=None)
        elif filename.endswith(('.xlsx', '.xls')): df = pd.read_excel(file, header=None)
        
        new_domains = []
        if df is not None and not df.empty:
            raw_list = df.iloc[:, 0].dropna().astype(str).tolist()
            for d in raw_list:
                clean_d = d.strip().lower()
                if '.' in clean_d and ' ' not in clean_d and len(clean_d)>3:
                    new_domains.append(clean_d)
        if new_domains:
            for d in new_domains:
                try:
                    with sqlite3.connect(DB_FILE) as conn:
                        c = conn.cursor()
                        c.execute("INSERT OR IGNORE INTO domains (domain, registrar, days_left, status) VALUES (?, ?, ?, ?)", 
                                  (d, 'Pending', 99999, 'Pending'))
                except: pass
            flash(f'已导入 {len(new_domains)} 个域名')
    except Exception as e:
        flash(f'导入错误: {e}')
    return redirect(url_for('admin_dashboard'))

@app.route('/favicon.ico')
def favicon(): return '', 204

if __name__ == '__main__':
    # 初始化数据库 (自动创建表和管理员)
    init_db()
    print(f"服务启动中...")
    print(f"数据路径: {DB_FILE}")
    print(f"管理员账号: admin (密码见环境变量 ADMIN_PASSWORD，默认 admin888)")
    app.run(host='0.0.0.0', port=5000, debug=True)
