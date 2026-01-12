import os
import sqlite3
import whois
import concurrent.futures
import pandas as pd
from datetime import datetime, date
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'secret_key_v3_advanced'

# 使用 SQLite 数据库文件，不再只依赖 CSV
DB_FILE = 'domains.db'

# --- 数据库操作函数 ---

def init_db():
    """初始化数据库表"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        # 创建表：存储域名、注册商、到期日、剩余天数、状态、最后更新时间
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
    """获取所有域名数据"""
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row # 允许通过列名访问
        c = conn.cursor()
        c.execute("SELECT * FROM domains ORDER BY days_left ASC")
        return [dict(row) for row in c.fetchall()]

def add_or_update_domain_db(domain_data):
    """更新或插入单个域名数据"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO domains 
                     (domain, registrar, expiry_date, days_left, status, last_update) 
                     VALUES (?, ?, ?, ?, ?, ?)''', 
                     (domain_data['domain'], domain_data['registrar'], 
                      domain_data['expiry_date'], domain_data['days_left'], 
                      domain_data['status'], datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()

def delete_domains_db(domain_list):
    """批量删除域名"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for d in domain_list:
            c.execute("DELETE FROM domains WHERE domain=?", (d,))
        conn.commit()

# --- 核心逻辑函数 ---

def calculate_days_left(exp_date):
    """计算剩余天数，处理各种日期格式问题"""
    if not exp_date:
        return None
    
    now = datetime.now()
    
    # 兼容性处理：如果 exp_date 是 datetime.date 类型（不带时分秒），转为 datetime
    if isinstance(exp_date, date) and not isinstance(exp_date, datetime):
        exp_date = datetime(exp_date.year, exp_date.month, exp_date.day)
        
    delta = exp_date - now
    return delta.days

def query_whois_online(domain):
    """
    执行真实的 Whois 网络查询
    """
    domain = domain.strip().lower()
    info = {
        'domain': domain,
        'registrar': '-',
        'expiry_date': '-',
        'days_left': 99999, # 默认设大一点，排在后面
        'status': 'Pending'
    }

    try:
        # 针对 .cn 域名的特殊处理建议：有时 python-whois 对 .cn 解析不稳
        # 这里使用标准库查询
        w = whois.whois(domain)
        
        # 1. 获取过期时间
        exp_date = w.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
            
        # 2. 获取注册商
        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]

        if exp_date:
            # 格式化显示
            info['expiry_date'] = exp_date.strftime('%Y-%m-%d')
            info['registrar'] = str(registrar) if registrar else 'Unknown'
            
            # 计算天数
            days = calculate_days_left(exp_date)
            info['days_left'] = days
            
            if days < 0:
                info['status'] = 'Expired'
            elif days < 30:
                info['status'] = 'Warning'
            else:
                info['status'] = 'Active'
        else:
            info['status'] = 'Date Not Found'
            # 即使没找到日期，如果能查到注册商，也存下来
            if registrar:
                info['registrar'] = str(registrar)

    except Exception as e:
        error_str = str(e)
        print(f"查询出错 {domain}: {error_str}")
        if "connect" in error_str or "time out" in error_str:
            info['status'] = 'Timeout'
        else:
            info['status'] = 'Error'
            
    return info

def refresh_domains_task(domain_list):
    """
    多线程批量更新域名信息，并写入数据库
    """
    results = []
    # 只有5个并发，防止被封
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_domain = {executor.submit(query_whois_online, d): d for d in domain_list}
        for future in concurrent.futures.as_completed(future_to_domain):
            try:
                data = future.result()
                add_or_update_domain_db(data) # 存入数据库
                results.append(data)
            except Exception:
                pass
    return results

# --- 路由 ---

@app.route('/')
def index():
    # 首页直接读取数据库，不做网络请求，解决刷新卡顿问题
    domains = get_all_domains()
    return render_template('index.html', domains=domains, count=len(domains))

@app.route('/refresh_all')
def refresh_all():
    """强制刷新所有域名的状态"""
    current_domains = [row['domain'] for row in get_all_domains()]
    if not current_domains:
        flash('列表中没有域名，请先添加')
        return redirect(url_for('index'))
    
    flash(f'正在后台更新 {len(current_domains)} 个域名，请稍候...')
    refresh_domains_task(current_domains)
    flash('更新完成！')
    return redirect(url_for('index'))

@app.route('/add_single', methods=['POST'])
def add_single():
    """手动添加单个域名"""
    domain = request.form.get('domain')
    if domain:
        domain = domain.strip().lower()
        # 先存一个初始状态到数据库
        initial_data = {
            'domain': domain, 'registrar': 'Loading...', 
            'expiry_date': '-', 'days_left': 0, 'status': 'New'
        }
        add_or_update_domain_db(initial_data)
        
        # 立即尝试联网查询一次
        info = query_whois_online(domain)
        add_or_update_domain_db(info)
        
        flash(f'已添加并查询: {domain}')
    return redirect(url_for('index'))

@app.route('/batch_delete', methods=['POST'])
def batch_delete():
    """批量删除"""
    # 获取选中的域名列表
    selected_domains = request.form.getlist('selected_domains')
    if selected_domains:
        delete_domains_db(selected_domains)
        flash(f'已删除 {len(selected_domains)} 个域名')
    else:
        flash('未选择任何域名')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    """文件导入 (CSV/Excel)"""
    if 'file' not in request.files:
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    
    if file:
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
                    # 简单校验
                    if '.' in clean_d and ' ' not in clean_d and len(clean_d) > 3:
                        new_domains.append(clean_d)
            
            if new_domains:
                # 1. 先全部存入数据库（状态设为待更新）
                for d in new_domains:
                     # 只有当数据库里没有这个域名时才插入
                    try:
                        with sqlite3.connect(DB_FILE) as conn:
                            c = conn.cursor()
                            c.execute("INSERT OR IGNORE INTO domains (domain, registrar, days_left, status) VALUES (?, ?, ?, ?)", 
                                      (d, 'Pending', 99999, 'Pending'))
                    except:
                        pass
                
                flash(f'已导入 {len(new_domains)} 个域名，请点击右上角“一键更新状态”获取详细信息')
            else:
                flash('文件中未找到有效域名')
                
        except Exception as e:
            flash(f'导入失败: {str(e)}')
            
        return redirect(url_for('index'))

@app.route('/favicon.ico')
def favicon():
    return '', 204

if __name__ == '__main__':
    init_db() # 启动时初始化数据库
    print("服务运行中: http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
