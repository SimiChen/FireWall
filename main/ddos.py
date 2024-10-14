from collections import defaultdict
from datetime import datetime, timedelta
import socket
import re

import psutil
import pyshark
import config

import os

request_counts = defaultdict(int)
# Maintain the timestamp of the first request from each source IP
request_timestamps = defaultdict(datetime.now)

# Define the DDoS detection parameters
REQUEST_THRESHOLD = 100  # Number of requests threshold for detection
TIME_WINDOW = timedelta(seconds=1)  # Time window for detection
triggered_ips = set()
ddos_ip = set()
regular_count = 0


def log_attack_to_file(pkt, http_layer, attack, threat, feature):
    # Log the attack to a file
    timestamp = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    with open(f"main/logs/att-{timestamp}.log", "a") as file:
        file.write('\n攻击者信息')
        file.write(f"\n{attack}")
        file.write(f"\n威胁程度: {threat} ")
        file.write(f"\n攻击特征: {feature} ")
        file.write(f"\n源IP:  {pkt['IP'].src} -> 目的IP:  {pkt['IP'].dst}")
        file.write(f"\nFull URI:  {http_layer.request_uri}")
        file.write(f"\n客户端端口:  {pkt['TCP'].srcport} -> 服务器端口: {pkt['TCP'].dstport}")
        file.write(f"\nUser_Agent:  {http_layer.User_Agent}")
        file.write(f"\nanalysis:  {pkt['TCP'].analysis}")
        file.write(f"\nprotocol:  {pkt['IP'].proto}")
        file.write(f"\nRequest Method:  {http_layer.request_method}")
        file.write('\n------------------------')

    # remove outdated log files
    try:
        log_dir = 'main/logs'
        if not os.path.exists(log_dir):
            return "Log directory does not exist."

        current_time = datetime.now()
        log_files = os.listdir(log_dir)
        for log_file in log_files:
            if log_file.startswith('att-'):
                log_time = datetime.strptime(log_file[4:23], "%Y-%m-%d %H-%M-%S")
                if current_time - log_time > timedelta(seconds=5):
                    print(f"Removing outdated log file: {log_file}")
                    os.remove(f"{log_dir}/{log_file}")
    except Exception as e:
        print(f"An error occurred while removing outdated log files: {str(e)}")

def packet_callback(pkt):
    if 'TCP' in pkt and pkt['TCP'].dstport == '8000':
        if 'HTTP' in pkt:
            http_layer = pkt['HTTP']
            if hasattr(http_layer, 'request_uri'):
                #print("URL:", http_layer.request_uri)
                attack, threat, feature = http_attack(http_layer.request_uri.encode('utf-8'))
                if attack:
                    print('攻击者信息')
                    print('源IP: ', pkt['IP'].src,' -> 目的IP: ', pkt['IP'].dst)
                    print('Full URI: ', http_layer.request_uri)
                    print('客户端端口: ', pkt['TCP'].srcport, ' -> 服务器端口: ', pkt['TCP'].dstport)
                    print('User_Agent: ', http_layer.User_Agent)
                    print('analysis: ', pkt['TCP'].analysis)
                    print('protocol: ', pkt['IP'].proto)
                    print('Request Method: ', http_layer.request_method)
                    print('------------------------')
                    log_attack_to_file(pkt, http_layer, attack, threat, feature)


        else:
            if 'IP' in pkt:
                if pkt['IP'].src not in ddos_ip:
                    global regular_count
                    if regular_count % 10 == 0:
                        print('正常流量')
                        print('------------------------')
                    regular_count += 1

        ddos_ip.add(ddos_attack_detection(pkt))


                #print ip information



def ddos_attack_detection(packet):
    global request_counts, request_timestamps, triggered_ips
    # Extract the source IP from the packet
    src_ip = str(packet['IP'].src)

    # Update the count of requests from the source IP
    request_counts[src_ip] = request_counts.get(src_ip, 0) + 1
    # If this is the first request from the source IP, save the timestamp
    if src_ip not in request_timestamps:
        request_timestamps[src_ip] = datetime.now()

    # Check if the source IP has exceeded the request threshold
    if request_counts[src_ip] > REQUEST_THRESHOLD:
        # Check if the time since the first request exceeds the time window
        if datetime.now() - request_timestamps[src_ip] > TIME_WINDOW:
            # Check if the source IP has already triggered an alert during the current time window
            if src_ip not in triggered_ips:
                # Log the detected DDoS attack
                log_ddos_attack(src_ip)
                # Add the source IP to the set of triggered IPs
                triggered_ips.add(src_ip)
                return src_ip

    else:
        # If the request count falls below the threshold, remove the source IP from triggered_ips
        triggered_ips.discard(src_ip)

    # Check if the current time has exceeded the time window
    if datetime.now() - request_timestamps[src_ip] > TIME_WINDOW:
        # Reset triggered_ips for the new time window
        triggered_ips.clear()
        # Update the timestamp for the new time window
        request_timestamps[src_ip] = datetime.now()

    return None
def log_ddos_attack(src_ip):
    # Log the detected DDoS attack
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"DDoS attack detected from {src_ip} at {timestamp}"
    print(message)
    timestamp = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    with open(f"main/logs/att-{timestamp}.log", "a") as file:
        file.write('\n攻击者信息')
        file.write(f"\nDDoS attack detected from {src_ip} at {timestamp}")
        file.write('\n------------------------')


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
        print('---------------------------------')

        return attack, threat, feature

    # ... rest of the function ...
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
    # 反序列化漏洞特征
    pattern_serialize = re.compile(r"""(‘/[oc]:\d+:/i’, \$var)""")
    # 命令执行漏洞特征
    pattern_shell = re.compile(
        r"(eval)|(ping)|echo|(cmd)|(/etc/).+|(whoami)|(ipconfig)|(/bin/).+|(array_map)|(phpinfo)|(\$_).+|(var_dump)|(call_user_func)|(/usr/).+|((C|c):/).+")
    # 目录遍历特征
    pattern_dir_search = re.compile(r'''(/robots.txt)|(\.\./)|(\w*.conf)|(/admin)|(/etc/passwd)|(/etc/shadow)''')


    patterns = {

        'xss': pattern_xss,
        'shell': pattern_shell,
        'dir_search': pattern_dir_search,
        'serialize': pattern_serialize,
        'sql': pattern_sql,
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
            # return attack, threat, feature
    if attack is not None:
        print(attack)
        print("威胁程度: %s " % threat)
        print("攻击特征: %s " % feature)

    return attack, threat, feature


def get_current_interface():
    # Get a list of network interfaces
    interfaces = psutil.net_if_addrs()
    # Iterate through the interfaces and find the one that is up and has an IPv4 address
    for interface, addresses in interfaces.items():
        for address in addresses:
            if address.family == socket.AF_INET and address.address != '127.0.0.1' and address.address.startswith('192.168'):
                return interface, address.address

    return None


if __name__ == "__main__":

    # Get the current network interface
    #tshark_path = 'C:\\Program Files\\Wireshark\\tshark.exe'
    tshark_path = 'E:\\Program Files\\Wireshark\\tshark.exe'
    interface, address = get_current_interface()
    filter = f'dst host {address} and tcp dst port 8000'
    print(f"Using interface: {interface} ({address})")
    print('监听开始')

    capture = pyshark.LiveCapture(interface=interface, tshark_path=tshark_path, bpf_filter=filter)

    # Start capturing packets
    capture.apply_on_packets(packet_callback)



