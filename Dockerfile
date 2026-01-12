# 使用轻量级 Python 基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 安装系统依赖
# python-whois 依赖系统底层的 whois 命令
# gcc 可能会被某些 python 库编译时需要
RUN apt-get update && apt-get install -y \
    whois \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目代码
COPY . .

# 创建数据目录挂载点
VOLUME /app/data

# 设置环境变量默认值
ENV DATA_DIR=/app/data
ENV PYTHONUNBUFFERED=1

# 暴露端口 (容器内部端口)
EXPOSE 5000

# 启动命令 (使用 gunicorn 生产级服务器，或者直接用 python app.py)
CMD ["python", "app.py"]
