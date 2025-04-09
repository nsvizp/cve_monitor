#!/bin/bash
#！Author ：myxfc
# 要运行的 Python 脚本路径
PYTHON_SCRIPT="/xxx/xxx.py"

# 日志文件路径（可选）
LOG_FILE="/xxx/xxx.log"

# 检查 Python 脚本是否存在
if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "错误：Python 脚本不存在: $PYTHON_SCRIPT"
    exit 1
fi

# 无限循环，确保 Python 脚本一直运行
while true; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') - 启动 Python 脚本: $PYTHON_SCRIPT" >> "$LOG_FILE"
    
    # 运行 Python 脚本，并将输出重定向到日志文件
    python3 "$PYTHON_SCRIPT" >> "$LOG_FILE" 2>&1

    # 如果 Python 脚本退出，记录日志并等待 5 秒后重启
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Python 脚本退出，5 秒后重启..." >> "$LOG_FILE"
    sleep 5
done

