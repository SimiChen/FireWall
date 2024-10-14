"""
作为main中的一下基础常量设置
"""

# 默认设置
#LISTEN_PORT = 'tcp port 80'
#LISTEN_PORT = 'dst host 192.168.0.48 and dst port 8000'
LISTEN_PORT = "dst port 80 or dst port 8000"
#LISTEN_PORT = 'dst host 192.168.0.48'
# LISTEN_PORT = 'dst host 192.168.9.15'


LISTEN_COUNT = 4

# 特征库名
PATTERN_LIST = [
    {'sql': ('SQL注入', '高危')},
    {'xss': ('XSS', '高危')},
    {'shell': ('远程命令执行', '高危')},
    {'serialize': ('反序列化', '高危')},
    {'dir_search': ('目录遍历', '低危')},
    {'csrf': ('CSRF', '中危')},
    {'file_upload': ('文件上传', '高危')},
    {'random_charactor': ('随机字符', '中危')},
    {'file_read': ('文件读取', '中危')},
]


def get_risk_level(pattern):
    for item in PATTERN_LIST:
        if pattern in item:
            return item[pattern]


