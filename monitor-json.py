import os
import json
import whois
import concurrent.futures
import pandas as pd
import socket
import re
import requests
import time
import hmac
import hashlib
import base64
import urllib.parse
import smtplib
import threading
from pathlib import Path
from email.mime.text import MIMEText
from email.header import Header
from datetime import datetime, date, timezone, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify

app = Flask(__name__)

# --- 1. 基础配置 ---
# 环境变量配置
app.secret_key = os.environ.get('SECRET_KEY', 'secret_key_json_mode')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin888')
DATA_DIR = Path(os.environ.get('DATA_DIR', 'data'))

# 确保数据目录存在
DATA_DIR.mkdir(parents=True, exist_ok=True)

# 文件路径
DOMAINS_FILE = DATA_DIR / "domains.json"
SETTINGS_FILE = DATA_DIR / "settings.json"

# 线程锁 (仿照参考代码，防止并发写入冲突)
DOMAIN_LOCK = threading.Lock()
SETTINGS_LOCK = threading.Lock()

# 定义 UTC+8 时区
TZ_CN = timezone(timedelta(hours=8))

# --- 2. JSON 数据操作辅助函数 ---

def load_json(file_path, default=None):
    if default is None: default = {}
    if not file_path.exists():
        return default
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default

def save_json(file_path, data, lock):
    with lock:
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving {file_path}: {e}")

# --- 3. 业务数据操作 ---

def get_settings():
    return load_json(SETTINGS_FILE, {})

def get_setting(key, default=None):
    data = get_settings()
    return data.get(key, default)

def save_setting(key, value):
    with SETTINGS_LOCK:
        data = load_json(SETTINGS_FILE, {})
        data[key] = value
        # 内部直接调用 json dump，复用锁逻辑需要小心，这里为了简单重新写一遍
        try:
            with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Save setting error: {e}")

def get_all_domains():
    data = load_json(DOMAINS_FILE, {})
    # 转换为列表并按剩余天数排序
    domain_list = list(data.values())
    # 处理可能的 None 值防止排序报错
    domain_list.sort(key=lambda x: x.get('days_left') if x.get('days_left') is not None else 99999)
    return domain_list

def add_or_update_domain_file(domain_data):
    current_time_cn = datetime.now(TZ_CN).strftime('%Y-%m-%d %H:%M:%S')
    domain_data['last_update'] = current_time_cn
    
    with DOMAIN_LOCK:
        data = load_json(DOMAINS_FILE, {})
        # 以域名为 Key 存储
        data[domain_data['domain']] = domain_data
        try:
            with open(DOMAINS_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Save domain error: {e}")

def delete_domains_file(domain_list):
    with DOMAIN_LOCK:
        data = load_json(DOMAINS_FILE, {})
        for d in domain_list:
            if d in data:
                del data[d]
        try:
            with open(DOMAINS_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Delete domain error: {e}")

# --- 4. 核心查询逻辑 (保持不变) ---

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
    """ Socket 深度查询 .cn """
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
                add_or_update_domain_file(data)
                results.append(data)
            except: pass
    return results

# --- 5. 告警发送逻辑 ---

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
    
    # DingTalk
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

    # Feishu
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

    # SMTP
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

# --- 6. 权限控制装饰器 ---
# 参照你的 Azure 代码，使用 session + 装饰器来做鉴权
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('请先登录管理员账号')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- 7. 路由配置 ---

# 游客主页 (只读)
@app.route('/')
def index():
    domains = get_all_domains()
    try: alert_days = int(get_setting('alert_days', 30))
    except: alert_days = 30
    return render_template('guest.html', domains=domains, count=len(domains), alert_days=alert_days)

# 登录页
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # 简单校验：用户名固定 admin，密码对比环境变量
        if username == 'admin' and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            flash('登录成功')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('admin_dashboard'))
        else:
            flash('账号或密码错误')
            
    return render_template('login.html')

# 退出登录
@app.route('/logout')
@admin_required
def logout():
    session.pop('admin_logged_in', None)
    flash('已退出登录')
    return redirect(url_for('index'))

# 管理员后台
@app.route('/admin')
@admin_required
def admin_dashboard():
    domains = get_all_domains()
    try: alert_days = int(get_setting('alert_days', 30))
    except: alert_days = 30
    return render_template('admin.html', domains=domains, count=len(domains), alert_days=alert_days)

# 设置页面
@app.route('/settings', methods=['GET', 'POST'])
@admin_required
def settings():
    if request.method == 'POST':
        # 批量保存配置
        config_keys = [
            'alert_days', 
            'ding_webhook', 'ding_secret', 
            'feishu_webhook', 'feishu_secret',
            'smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass', 'smtp_to'
        ]
        
        with SETTINGS_LOCK:
            data = load_json(SETTINGS_FILE, {})
            for key in config_keys:
                data[key] = request.form.get(key, '').strip()
                if key == 'alert_days' and not data[key]:
                    data[key] = '30' # 默认值
            
            try:
                with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"Save settings error: {e}")

        flash('配置已保存')
        return redirect(url_for('settings'))
    
    # 读取配置
    return render_template('settings.html', config=get_settings())

# 后台操作接口

@app.route('/refresh_all')
@admin_required
def refresh_all():
    domains_data = load_json(DOMAINS_FILE, {})
    current_domains = list(domains_data.keys())
    
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
@admin_required
def add_single():
    domain = request.form.get('domain')
    if domain:
        domain = domain.strip().lower()
        # 先存个初始状态
        add_or_update_domain_file({
            'domain': domain, 'registrar': 'Loading...', 
            'expiry_date': '-', 'days_left': 0, 'status': 'New'
        })
        # 立即查询
        info = query_whois_online(domain)
        add_or_update_domain_file(info)
        flash(f'已添加: {domain}')
    return redirect(url_for('admin_dashboard'))

@app.route('/batch_delete', methods=['POST'])
@admin_required
def batch_delete():
    selected = request.form.getlist('selected_domains')
    if selected:
        delete_domains_file(selected)
        flash(f'已删除 {len(selected)} 个域名')
    else:
        flash('未选择域名')
    return redirect(url_for('admin_dashboard'))

@app.route('/upload', methods=['POST'])
@admin_required
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
            with DOMAIN_LOCK:
                data = load_json(DOMAINS_FILE, {})
                for d in new_domains:
                    if d not in data:
                        data[d] = {'domain': d, 'registrar': 'Pending', 'days_left': 99999, 'status': 'Pending'}
                try:
                    with open(DOMAINS_FILE, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                except Exception as e:
                    print(f"Import error: {e}")
                    
            flash(f'已导入 {len(new_domains)} 个域名')
    except Exception as e:
        flash(f'导入错误: {e}')
    return redirect(url_for('admin_dashboard'))

@app.route('/favicon.ico')
def favicon(): return '', 204

if __name__ == '__main__':
    print(f"服务启动中 (JSON 存储模式)...")
    print(f"数据目录: {DATA_DIR}")
    print(f"管理员账号: admin (密码由环境变量 ADMIN_PASSWORD 控制，默认 admin888)")
    app.run(host='0.0.0.0', port=5000, debug=True)
