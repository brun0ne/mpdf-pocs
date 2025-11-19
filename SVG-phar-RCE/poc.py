import requests

URL = "http://localhost:5005"

def trigger_phar_rce():
    r = requests.get(f"{URL}/pwned")
    if r.status_code == 404:
        print("Sanity check passed, 'pwned' file does not exist.")

    r = requests.get(URL)
    if r.status_code == 200:
        print("Request successful, check for RCE effects.")

        r = requests.get(f"{URL}/pwned")

        if r.status_code == 200:
            print("RCE successful, 'pwned' file accessed.")
        else:
            print("RCE failed, 'pwned' file not found.")
    else:
        print("Failed to trigger RCE.")

if __name__ == "__main__":
    trigger_phar_rce()
