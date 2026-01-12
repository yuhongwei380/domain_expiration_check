import os
import sqlite3
import whois
import concurrent.futures
import pandas as pd
import socket
import re
from datetime import datetime, date, timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'secret_key_v6_cn_fix'

DB_FILE = 'domains.db'

# 定义 UTC+8 时区
TZ_CN = timezone(timedelta(hours=8))

# --- 数据库操作 (保持不变) ---

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS domains (
                        domain TEXT PRIMARY KEY,
                        registrar TEXT,
                        expiry_date TEXT,
                        days_left INTEGER,
                        status TEXT,
                        last_update TEXT
                    )''')
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
    
    # 转为 datetime
    if isinstance(exp_date, date) and not isinstance(exp_date, datetime):
        exp_date = datetime(exp_date.year, exp_date.month, exp_date.day)
    
    # 统一时区
    if exp_date.tzinfo is None:
        exp_date = exp_date.replace(tzinfo=TZ_CN)
    else:
        exp_date = exp_date.astimezone(TZ_CN)
        
    delta = exp_date - now
    return delta.days

# --- 🔥 新增: 专门处理 .cn 的 Socket 查询函数 ---
def query_cn_socket(domain):
    """
    备用方案：通过 Socket 直接连接 whois.cnnic.cn 查询
    解决 'Whois command returned no output' 和格式解析问题
    """
    print(f"尝试使用 Socket 深度查询: {domain}")
    whois_server = "whois.cnnic.cn"
    port = 43
    response = b""
    
    try:
        # 1. 建立连接
        with socket.create_connection((whois_server, port), timeout=10) as s:
            # 2. 发送查询指令 (域名 + 回车换行)
            s.sendall(f"{domain}\r\n".encode())
            # 3. 接收数据
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
        
        # 4. 解码 (尝试 UTF-8)
        text = response.decode('utf-8', errors='ignore')
        
        # 5. 正则提取信息
        # 提取 Expiration Time: 2026-06-29 15:07:39
        exp_match = re.search(r'Expiration Time:\s*(\d{4}-\d{2}-\d{2})', text, re.IGNORECASE)
        # 提取 Registrant (注册商或注册人)
        reg_match = re.search(r'Sponsoring Registrar:\s*(.+)', text, re.IGNORECASE)
        
        result = {}
        if exp_match:
            date_str = exp_match.group(1) # 拿到 2026-06-29
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
        # 获取过期时间
        exp_date = w.expiration_date
        if isinstance(exp_date, list): exp_date = exp_date[0]
        
        # 获取注册商
        registrar = w.registrar
        if isinstance(registrar, list): registrar = registrar[0]
        
        if exp_date:
            found_date = exp_date
            found_registrar = registrar

    except Exception as e:
        # 记录错误但不立即放弃，尝试备用方案
        print(f"标准库查询失败 {domain}: {e}")

    # 2. 🔥 如果标准库没查到，且是 .cn 域名，尝试 Socket 备用方案
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
        
        if days is not None:
            if days < 0:
                info['status'] = 'Expired'
            elif days < 30:
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
    # .cn 查询较慢，并发稍微调小一点，防止被封
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

# --- 路由 (保持不变) ---

@app.route('/')
def index():
    domains = get_all_domains()
    return render_template('index.html', domains=domains, count=len(domains))

@app.route('/refresh_all')
def refresh_all():
    current_domains = [row['domain'] for row in get_all_domains()]
    if not current_domains:
        flash('列表中没有域名')
        return redirect(url_for('index'))
    flash(f'正在后台更新 {len(current_domains)} 个域名 (含 Socket 深度查询)...')
    refresh_domains_task(current_domains)
    flash('更新完成')
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
