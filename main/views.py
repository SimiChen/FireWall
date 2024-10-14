import os
from datetime import datetime, timedelta

from django.contrib import messages
from django.contrib.auth import authenticate, login
from scapy.layers import http
import subprocess
from django.shortcuts import render, redirect
import json
from django.http import JsonResponse
import sqlite3
from django.http import StreamingHttpResponse
import time
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User

@csrf_exempt
def return_json(request):
    return JsonResponse({'status': 'success'})

def login_handler(packet):
    # 处理抓到的数据包
    # 检查数据包是否为HTTP请求
    if packet.haslayer(http.HTTPRequest):
        handle_http_request(packet)

def add_timestamp(func):
    # 时间装饰器
    def wrapper(*args, **kwargs):
        current_time = datetime.datetime.now() + datetime.timedelta(hours=8)
        current_time_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
        result = func(*args, **kwargs)
        print(f"[{current_time_str}] {result}")
        return result

    return wrapper

def handle_http_request(packet):
    # 处理HTTP请求
    # 获取请求方法、URL和请求头
    method = packet[http.HTTPRequest].Method
    url = packet[http.HTTPRequest].Path
    headers = packet[http.HTTPRequest].fields

    # 添加时间戳
    headers = add_timestamp(headers)

    # 保存数据到数据库
    save_data_to_db(method, url, headers)

def save_data_to_db(method, url, headers):
    conn = None
    try:
        conn = sqlite3.connect('db.sqlite3')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO main_packetbaseinfo (method, url, headers) VALUES (?, ?, ?)",
            (method, url, json.dumps(headers))
        )
        conn.commit()
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        print(username, password)
        if username and password:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                print('login success')
                return JsonResponse({'status': 'success'})
        print('login failed')
        return JsonResponse({'status': 'error', 'message': 'Invalid username or password'})
    else:
        return render(request, 'main/login.html')


@csrf_exempt
def register_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        if username and password:
            # Check if the username is already taken
            if User.objects.filter(username=username).exists():
                return JsonResponse({'status': 'error', 'message': 'Username already exists'})
            # Create a new user
            user = User.objects.create_user(username=username, password=password)
            if user:
                # Log the user in after registration
                login(request, user)
                return JsonResponse({'status': 'success'})
        return JsonResponse({'status': 'error', 'message': 'Invalid username or password'})
    else:
        return render(request, 'main/login.html')


def show_login(request):
    return render(request, 'main/login.html')

def show_index(request):
    username = request.GET.get('username')

    db = sqlite3.connect('db.sqlite3')
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE username=? ", (username,))
    users = cursor.fetchall()
    print(users)

    # 提交事务
    db.commit()

    # 关闭数据库连接
    db.close()


    return render(request, 'main/index.html')

subprocess_handle = None

def start(request):
    # 开启监听
    global subprocess_handle
    subprocess_handle = subprocess.Popen(['python', 'main/ddos.py'])

    messages.success(request, '系统已启动！')

    return render(request, 'main/index.html')

def stop(request):
    print("监听已停止")
    global subprocess_handle
    if subprocess_handle is not None:
        subprocess_handle.terminate()
        subprocess_handle = None
        messages.success(request, '监听已停止！')
    return render(request, 'main/index.html')


def update_info(request):
    def event_stream():
        while True:
            # Fetch updated information from your data source
            updated_info = fetch_data()
            # Yield the updated information as an SSE event
            yield f"data: {updated_info}\n\n"
            # Sleep for a while before sending the next update
            time.sleep(1)  # Example: Update every 1 seconds

    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    return response


def fetch_data():
    try:
        log_dir = 'main/logs'
        if not os.path.exists(log_dir):
            return "Log directory does not exist."

        files_data = []
        for file_name in os.listdir(log_dir):
            # remove outdated log files
            try:
                current_time = datetime.now()
                log_files = os.listdir(log_dir)
                for log_file in log_files:
                    if log_file.startswith('att-'):
                        log_time = datetime.strptime(log_file[4:23], "%Y-%m-%d %H-%M-%S")
                        if current_time - log_time > timedelta(seconds=5):
                            print(f"Removing outdated log file: {log_file}")
                            os.remove(f"{log_dir}/{log_file}")
                            pass
            except Exception as e:
                print(f"An error occurred while removing outdated log files: {str(e)}")

            file_path = os.path.join(log_dir, file_name)
            if os.path.isfile(file_path):
                with open(file_path, 'r') as file:
                    files_data.append(file.read().replace('\n', '<br>'))
                    #files_data.append('----------------------<br>')

        # Replace newline characters with <br> tags
        return_str = '<br>'.join(files_data)
        return return_str
    except Exception as e:
        return f"Error reading log files: {str(e)}"

def main(request):
    return render(request, 'main/main.html')