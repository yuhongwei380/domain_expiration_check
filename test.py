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
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'secret_key_v6_cn_fix'

DB_FILE = 'domains.db'

# 定义 UTC+8 时区
TZ_CN = timezone(timedelta(hours=8))

# --- 数据库操作 ---

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        # 域名表
        c.execute('''CREATE TABLE IF NOT EXISTS domains (
                        domain TEXT PRIMARY KEY,
                        registrar TEXT,
                        expiry_date TEXT,
                        days_left INTEGER,
                        status TEXT,
                        last_update TEXT
                    )''')
        # 新增：配置表
        c.execute('''CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT
                    )''')
        
        # 初始化默认阈值 (如果不存在)
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('alert_days', '30'))
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

# --- 核心逻辑 ---

def calculate_days_left(exp_date):
    """计算剩余天数 (UTC+8)"""
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
    """
    Socket 深度查询 .cn
    """
    print(f"尝试使用 Socket 深度查询: {domain}")
    whois_server = "whois.cnnic.cn"
    port = 43
    response = b""
    
    try:
        with socket.create_connection((whois_server, port), timeout=10) as s:
            s.sendall(f"{domain}\r\n".encode())
            while True:
                data = s.recv(4096)
                if not data:
                    break
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
    info = {
        'domain': domain,
        'registrar': '-',
        'expiry_date': '-',
        'days_left': 99999,
        'status': 'Pending'
    }

    found_date = None
    found_registrar = None

    # 1. 尝试标准库查询
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

    # 2. 备用 Socket 查询
    if not found_date and domain.endswith('.cn'):
        fallback_data = query_cn_socket(domain)
        if fallback_data:
            if 'expiry_date' in fallback_data:
                found_date = fallback_data['expiry_date']
            if 'registrar' in fallback_data:
                found_registrar = fallback_data['registrar']

    # 3. 整合结果
    if found_date:
        info['expiry_date'] = found_date.strftime('%Y-%m-%d')
        info['registrar'] = str(found_registrar) if found_registrar else 'Unknown'
        
        days = calculate_days_left(found_date)
        info['days_left'] = days
        
        # 获取动态阈值
        try:
            alert_days = int(get_setting('alert_days', 30))
        except:
            alert_days = 30
        
        if days is not None:
            if days < 0:
                info['status'] = 'Expired'
            elif days < alert_days:
                info['status'] = 'Warning'
            else:
                info['status'] = 'Active'
        else:
            info['status'] = 'Calc Error'
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
            except Exception:
                pass
    return results

# --- 🔥 新增: 告警发送逻辑 (含加签) ---

def send_alert_messages(expiring_domains):
    """
    发送告警（支持钉钉/飞书加签）
    """
    if not expiring_domains:
        return

    # 1. 构造消息内容
    msg_title = f"⚠️ 域名过期预警 ({len(expiring_domains)}个)"
    msg_body = "以下域名即将过期或已过期，请及时处理：\n\n"
    for item in expiring_domains:
        msg_body += f"- {item['domain']}: 剩余 {item['days']} 天 ({item['date']})\n"
    
    full_text = f"{msg_title}\n{msg_body}"
    print("触发告警:\n" + full_text)

    # 2. 读取配置
    ding_token = get_setting('ding_webhook')
    ding_secret = get_setting('ding_secret')
    feishu_token = get_setting('feishu_webhook')
    feishu_secret = get_setting('feishu_secret')
    smtp_host = get_setting('smtp_host')
    
    # 3. 发送钉钉 (支持加签)
    if ding_token:
        try:
            target_url = ding_token
            # 如果配置了 Secret，进行加签计算
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
            data = {
                "msgtype": "text",
                "text": {"content": full_text}
            }
            requests.post(target_url, headers=headers, data=json.dumps(data), timeout=5)
            print("钉钉发送成功")
        except Exception as e:
            print(f"钉钉发送失败: {e}")

    # 4. 发送飞书 (支持加签)
    if feishu_token:
        try:
            headers = {'Content-Type': 'application/json'}
            data = {
                "msg_type": "text",
                "content": {"text": full_text}
            }
            
            # 如果配置了 Secret，进行加签计算
            if feishu_secret:
                timestamp = str(int(time.time()))
                string_to_sign = '{}\n{}'.format(timestamp, feishu_secret)
                hmac_code = hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
                sign = base64.b64encode(hmac_code).decode('utf-8')
                
                data['timestamp'] = timestamp
                data['sign'] = sign

            requests.post(feishu_token, headers=headers, data=json.dumps(data), timeout=5)
            print("飞书发送成功")
        except Exception as e:
            print(f"飞书发送失败: {e}")

    # 5. 发送邮件
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
        except Exception as e:
            print(f"邮件发送失败: {e}")

# --- 路由 ---

@app.route('/')
def index():
    domains = get_all_domains()
    # 动态获取阈值传给前端
    try:
        alert_days = int(get_setting('alert_days', 30))
    except:
        alert_days = 30
    return render_template('index.html', domains=domains, count=len(domains), alert_days=alert_days)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        # 保存基础配置
        save_setting('alert_days', request.form.get('alert_days', '30'))
        
        # 保存 Webhook 及 Secret
        save_setting('ding_webhook', request.form.get('ding_webhook', '').strip())
        save_setting('ding_secret', request.form.get('ding_secret', '').strip())
        
        save_setting('feishu_webhook', request.form.get('feishu_webhook', '').strip())
        save_setting('feishu_secret', request.form.get('feishu_secret', '').strip())
        
        # SMTP
        save_setting('smtp_host', request.form.get('smtp_host', '').strip())
        save_setting('smtp_port', request.form.get('smtp_port', '465').strip())
        save_setting('smtp_user', request.form.get('smtp_user', '').strip())
        save_setting('smtp_pass', request.form.get('smtp_pass', '').strip())
        save_setting('smtp_to', request.form.get('smtp_to', '').strip())
        
        flash('配置已保存')
        return redirect(url_for('settings'))
    
    # 读取配置
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

@app.route('/refresh_all')
def refresh_all():
    current_domains = [row['domain'] for row in get_all_domains()]
    if not current_domains:
        flash('列表中没有域名')
        return redirect(url_for('index'))
    
    flash(f'正在后台更新 {len(current_domains)} 个域名...')
    
    # 1. 更新所有域名
    updated_data = refresh_domains_task(current_domains)
    
    # 2. 检查告警
    try:
        threshold = int(get_setting('alert_days', 30))
    except:
        threshold = 30
        
    expiring_list = []
    for d in updated_data:
        days = d.get('days_left')
        if days is not None and isinstance(days, int) and days < threshold:
            expiring_list.append({
                'domain': d['domain'],
                'days': days,
                'date': d['expiry_date']
            })
    
    # 3. 触发通知
    if expiring_list:
        send_alert_messages(expiring_list)
        flash(f'更新完成，发现 {len(expiring_list)} 个域名即将过期，已触发告警。')
    else:
        flash('更新完成，所有域名状态良好。')
        
    return redirect(url_for('index'))

@app.route('/add_single', methods=['POST'])
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
    return redirect(url_for('index'))

@app.route('/batch_delete', methods=['POST'])
def batch_delete():
    selected = request.form.getlist('selected_domains')
    if selected:
        delete_domains_db(selected)
        flash(f'已删除 {len(selected)} 个域名')
    else:
        flash('未选择域名')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files: return redirect(request.url)
    file = request.files['file']
    if not file or file.filename == '': return redirect(request.url)
    try:
        filename = file.filename.lower()
        df = None
        if filename.endswith('.csv'):
            df = pd.read_csv(file, header=None)
        elif filename.endswith(('.xlsx', '.xls')):
            df = pd.read_excel(file, header=None)
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
    return redirect(url_for('index'))

@app.route('/favicon.ico')
def favicon(): return '', 204

if __name__ == '__main__':
    init_db()
    print("服务运行中: http://0.0.0.0:5000 (支持 .cn 深度解析)")
    app.run(host='0.0.0.0', port=5000, debug=True)
