from collections import defaultdict
from datetime import datetime, timedelta

from celery import shared_task
import pyshark
from scapy.layers.inet import TCP, IP, UDP
from scapy.packet import Raw
from scapy.layers import http
import re
import main.config as config

# Maintain a count of requests from each source IP
request_counts = defaultdict(int)
# Maintain the timestamp of the first request from each source IP
request_timestamps = defaultdict(datetime.now)

# Define the DDoS detection parameters
REQUEST_THRESHOLD = 50  # Number of requests threshold for detection
TIME_WINDOW = timedelta(seconds=10)  # Time window for detection


@shared_task
def start_capture_task(interface, filter, tshark_path):
    capture = pyshark.LiveCapture(interface=interface, tshark_path=tshark_path, bpf_filter=filter)
    capture.apply_on_packets(packet_callback)

def packet_callback(pkt):
    if 'TCP' in pkt and pkt['TCP'].dstport == '8000':
        if 'HTTP' in pkt:
            http_layer = pkt['HTTP']
            if hasattr(http_layer, 'request_uri'):
                # print("URL:", http_layer.request_uri)
                http_attack(http_layer.request_uri)
        ddos_attack_detection(pkt)


def ddos_attack_detection(packet):
    global request_counts, request_timestamps

    # Extract the source IP from the packet
    src_ip = packet[IP].src

    # Update the count of requests from the source IP
    request_counts[src_ip] += 1
    print(request_counts)
    # If this is the first request from the source IP, save the timestamp
    if src_ip not in request_timestamps:
        request_timestamps[src_ip] = datetime.now()

    # Check if the source IP has exceeded the request threshold
    if request_counts[src_ip] > REQUEST_THRESHOLD:
        # Check if the time since the first request exceeds the time window
        if datetime.now() - request_timestamps[src_ip] > TIME_WINDOW:
            # Log the detected DDoS attack
            log_ddos_attack(src_ip)

    # Check for DDoS attack
    if (request_counts[src_ip] > REQUEST_THRESHOLD and
            datetime.now() - request_timestamps[src_ip] < TIME_WINDOW):
        # Log the detected DDoS attack
        log_ddos_attack(src_ip)

def log_ddos_attack(src_ip):
    # Log the detected DDoS attack
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"DDoS attack detected from {src_ip} at {timestamp}"
    print(message)


# @add_timestamp
# 用于ip信息值的提取
def extract_packet_ip(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        if proto == 6:
            tcp_layer = packet[TCP]
            dport = tcp_layer.dport
            sport = tcp_layer.sport
        elif proto == 17:
            udp_layer = packet[UDP]
            dport = udp_layer.dport
            sport = udp_layer.sport
    else:
        src_ip = dst_ip = proto = dport = sport = 'UnKnown'
        print("数据包中不存在IP层，无法识别")

    return src_ip, dst_ip, sport, dport, proto


# HTTP协议攻击告警触发，只针对url进行过滤
def http_attack(url):
    try:
        url = url.decode('utf-8')
    except UnicodeDecodeError:
        print("Could not decode url as UTF-8. Skipping this packet.")
        pattern_name = 'random_charactor'
        attack, threat = config.get_risk_level(pattern_name)
        feature = 'Random character in URL'
        print(attack)
        print("威胁程度: %s " % threat)
        print("攻击特征: %s " % feature)

        return attack, threat, feature

    # ... rest of the function ...
    print(url)
    # sql注入, xss 远程命令执行，ddos，缓冲区溢出漏洞， 目录遍历， 未授权访问， 暴力破解...
    # sql注入漏洞利用特征
    pattern_sql = re.compile(
        r'(\=.*\-\-)|(\w+(%|\$|#)\w+)|(.*\|\|.*)|(\s+(and|or)\s+)|(\b(select|update|union|and|or|delete|insert|trancate|char|into|'
        r'substr|ascii|declare|exec|count|master|drop|execute)\b)')
    """
    http://127.0.0.1/test.php?id=1 and (select count(*) from sysobjects)>0 and 1=1

    """
    # 跨站脚本攻击漏洞特征
    pattern_xss = re.compile(r'''(<.*>)|\{|}|"|>|<|(script)''')
    # 命令执行漏洞特征
    pattern_shell = re.compile(
        r"(eval)|(ping)|echo|(cmd)|(/etc/).+|(whoami)|(ipconfig)|(/bin/).+|(array_map)|(phpinfo)|(\$_).+|(var_dump)|(call_user_func)|(/usr/).+|((C|c):/).+")
    # 目录遍历特征
    pattern_dir_search = re.compile(r'''(/robots.txt)|(\.\./)|(\w*.conf)|(/admin)|(/etc/passwd)|(/etc/shadow)''')
    # 反序列化漏洞特征
    pattern_serialize = re.compile(r"""(‘/[oc]:\d+:/i’, \$var)""")

    patterns = {
        'sql': pattern_sql,
        'xss': pattern_xss,
        'shell': pattern_shell,
        'dir_search': pattern_dir_search,
        'serialize': pattern_serialize
    }

    for pattern_name, pattern in patterns.items():
        match = pattern.search(url)
        if match is not None:
            attack, threat = config.get_risk_level(pattern_name)
            feature = match[0]
            # return res, level, feature
            break
        else:
            attack = threat = feature = None
    print(attack)
    print("威胁程度: %s " % threat)
    print("攻击特征: %s " % feature)

    return attack, threat, feature


