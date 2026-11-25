# WinHelm Unified Desktop Console & Multi-Platform Ingress Gateway

ศูนย์ควบคุมเดสก์ท็อป (**Control Console**), ระบบ **System Tray**, และ **OAuth/MCP Ingress Gateway** สำหรับ **WinHelm MCP Core** (รองรับ **Google Gemini**, **Anthropic Claude**, และ **OpenAI ChatGPT**)

โปรเจกต์นี้ออกแบบให้แยกส่วนจากแกนหลัก (`winhelm-mcp`) อย่างชัดเจน โดยใช้ Node.js Standard Library 100% (ไร้ external npm dependencies) ทำงานร่วมกับ WinHelm Core ผ่าน Local HTTP/Bearer Token และ Windows DPAPI

---

## 🌟 ฟีเจอร์หลัก (Key Features)

1. **⚙️ ตั้งค่า & เชื่อมต่อ (Setup & OAuth):**
   - ซิงค์โดเมนสาธารณะจาก **Tailscale Funnel** อัตโนมัติ (`⚡ ซิงค์ Tailscale`)
   - สร้างและจัดการ **OAuth Static Clients** (`Client ID` / `Client Secret` เข้ารหัสด้วย Windows DPAPI)
   - จัดการ **WinHelm Core Bearer Token** (อ่านอัตโนมัติจาก `~/.winhelm/auth-token`, ปุ่ม `⚡ ซิงค์อัตโนมัติ`, หรือกรอก Token เองเมื่อรัน Core ด้วย `--auth`)
   - **Health Checklist** ตรวจความพร้อมระบบ 8 จุดแบบเรียลไทม์

2. **🎫 จัดการ Invites (`#invites`):**
   - สร้าง Invite Code พร้อมกำหนดโควตา (Quota) และคัดลอกลง Clipboard ในคลิกเดียว
   - แก้ไขโควตา, รีเซ็ตการใช้งาน, ปลดการจองค้าง (`Release Stale`), ยกเลิก (`Revoke`), หรือลบถาวร

3. **🛠️ นโยบาย Tools — Schema v2 (`#tools`):**
   - ควบคุมสิทธิ์ **56 Canonical Tools** ของ WinHelm แบบเจาะจงราย Tool (`🟢 Auto` / `🟡 Ask` / `🔴 Off`)
   - ปุ่ม Quick Presets: `Power (Auto ทั้งหมด)`, `Balanced (Ask คำสั่งอันตราย)`, `Safe (Read-only)`
   - ตั้งค่า **Terminal Mode**, **Approval Mode** (`smart` / `manual` / `trusted`), และจัดการ **Approved Folders** ได้จากหน้าเดียว

4. **🖥️ จัดการ Services & 📜 บันทึก Logs (`#services`, `#logs`):**
   - สั่ง `Start` / `Stop` / `Restart` แยกสำหรับ **WinHelm Core (`18790`)** และ **Gateway (`18788`)**
   - หน้า **บันทึก Logs** เต็มจอ (แนวบน-ล่าง `stdout` 2/3 และ `stderr` 1/3) พร้อมล้าง ANSI color codes และ Auto-Refresh

5. **📊 Core Monitor & Global Approval Popup (`#monitor`):**
   - แสดง **CPU Load**, **RAM**, **GPU VRAM/Temp**, **Uptime/Sessions**, **Disk Drives (Compact Grid)**, และ **Activity Logs** ของ Core
   - **Approval Queue + Global Popup:** เมื่อมีคำสั่งติดสิทธิ์ `ask` ระบบจะเด้ง Popup แจ้งเตือนมุมขวาบนทันทีไม่ว่าอยู่แท็บไหน กด `✔ อนุมัติ` หรือ `✕ ปฏิเสธ` ได้จาก Console โดยตรง

6. **⚡ Silent System Tray (`WinHelm Tray.lnk`):**
   - เปิดแอป System Tray ได้โดย **ไม่มีหน้าต่าง PowerShell ค้าง** (ผ่าน `wscript.exe` + `tray\launch-tray.vbs`)
   - ไอคอนโลโก้ WinHelm พร้อมจุดสถานะที่มุมขวาล่าง (เทา = Stopped, น้ำเงิน = Local, แดง = Public)

---

## 🚀 วิธีเปิดใช้งาน (เครื่องที่ติดตั้งแล้ว)

- **วิธีที่แนะนำ (ผ่าน Tray):** ดับเบิลคลิก **`WinHelm Tray.lnk`** (หรือ `start-tray.cmd`) แล้วคลิกขวาที่ไอคอน WinHelm มุมขวาล่าง Taskbar → **Open Control Console**
- **เปิดเฉพาะหน้า Console:** รัน `.\start-console.ps1` (เปิดหน้าต่าง Edge App 1280×900 ไร้แถบ URL พร้อม Single-Use Launch Ticket)
- **เปิดเฉพาะ Gateway / Core:** รัน `.\start-gateway.ps1` / `.\start-core.ps1` หรือกดปุ่ม **`🚀 เริ่มระบบทั้งหมด`** ในหน้า Console

---

## 📦 คู่มือนำไปติดตั้งและทดสอบบนเครื่องอื่น

### 1. ข้อกำหนดเบื้องต้นของเครื่องปลายทาง
- **Windows 11 / Windows 10** พร้อม **Microsoft Edge** (ติดตั้งมาในระบบอยู่แล้ว)
- **Node.js v20+**
- **Tailscale** (ติดตั้ง ล็อกอิน และเปิด Funnel ชี้มาที่พอร์ต `18788` เช่น `tailscale funnel --bg 18788`)
- **WinHelm Core** (`npx -y winhelm-mcp` หรือติดตั้ง global `npm i -g winhelm-mcp` หรือวางโฟลเดอร์ `winhelm-mcp` ไว้ข้างๆ กัน)

### 2. ขั้นตอนตั้งค่าครั้งแรกบนเครื่องใหม่ (1 คลิกด้วย `setup.cmd`)
1. Clone หรือคัดลอกโฟลเดอร์ `winhelm-console-gateway` ไปวางที่ใดก็ได้บนเครื่องใหม่
2. ดับเบิลคลิก **`setup.cmd`** (สคริปต์จะตรวจเช็ก Node.js, Edge, Tailscale, WinHelm Core, สร้าง `config.json` พร้อมดึงโดเมน Tailscale และสร้าง Shortcut `WinHelm Tray.lnk` ให้ตรงกับโฟลเดอร์ปัจจุบันอัตโนมัติ)
3. ดับเบิลคลิก **`WinHelm Tray.lnk`** แล้วคลิกขวาที่ไอคอน WinHelm มุมขวาล่าง → **Open Control Console** (`http://127.0.0.1:18789`)
4. กดปุ่ม **`🚀 เริ่มระบบทั้งหมด`** ที่มุมล่างซ้าย (หรือเปิด **Tailscale Funnel** ในแท็บ **จัดการ Services**):
   - การรันครั้งแรก WinHelm Core จะสุ่มสร้าง Bearer Token ไว้ที่ `%USERPROFILE%\.winhelm\auth-token` ให้อัตโนมัติ
   - *หมายเหตุ:* หากคุณรัน WinHelm Core เองจากภายนอกด้วย `--auth <token>` ให้กด **`✏️ แก้ไข`** ตรงแถว **WinHelm Bearer Token** เพื่อวาง Token ของคุณ
5. ในแท็บ **ตั้งค่า & เชื่อมต่อ**:
   - กด **`⚡ ซิงค์ Tailscale`** (หากยังไม่ได้ซิงค์)
   - กด **`➕ สร้าง Client`** (เช่น `winhelm-gemini-01`) ระบบจะสร้าง Secret และคัดลอกลง Clipboard ให้
   - กด **`🎫 สร้าง Invite ด่วน`** เพื่อสร้าง Invite Code สำหรับยืนยันตัวตนครั้งแรก
6. นำ **MCP Server URL**, **Client ID**, **Client Secret**, และ **Invite Code** ไปเชื่อมต่อกับ AI Platform ที่ต้องการ (ดูขั้นตอนด้านล่าง)

---

## 🔌 วิธีเชื่อมต่อ AI Platforms (Gemini / Claude / ChatGPT)

> แนะนำให้สร้าง **Client ID แยกตามแพลตฟอร์ม** (เช่น `winhelm-gemini-01`, `winhelm-claude-01`, `winhelm-chatgpt-01`) และเตรียม **Invite Code** ที่ยังไม่ถูกใช้งานไว้ 1 รหัสต่อการเชื่อมต่อ (ระบบรองรับการตรวจจับ callback URL ของทั้ง 3 เจ้าอัตโนมัติ)

### 1. Google Gemini
1. ไปที่ **Settings → Connected Apps → Add custom app**
2. วาง **MCP Server URL** (`https://<your-tailscale-host>/mcp`)
3. เปิด **Additional settings (Show more)** → กรอก **Client ID** และ **Client Secret**
4. กด **Connect** → กรอก **Invite Code** ในหน้าล็อกอิน WinHelm → กด **Continue** (ระบบจะ redirect กลับให้อัตโนมัติ)

### 2. Anthropic Claude
1. ไปที่ **Settings → Connectors → Add custom connector**
2. วาง **MCP Server URL** (`https://<your-tailscale-host>/mcp`)
3. เปิด **Advanced settings** → กรอก **Client ID** และ **Client Secret**
4. กด **Add / Connect** → กรอก **Invite Code** → กด **Continue**

### 3. OpenAI ChatGPT
1. ไปที่ **Plugins / Apps → Add custom MCP server**
2. ตั้งค่าฝั่งซ้าย:
   - **Connection:** `Server URL` → `https://<your-tailscale-host>/mcp`
   - **Authentication:** `OAuth`
3. เปิด **Advanced OAuth settings** ด้านขวา:
   - **Registration method:** `User-Defined OAuth Client`
   - **OAuth client ID / OAuth client secret:** กรอกค่าของ Client ที่สร้างใน WinHelm Console
   - **Token endpoint auth method:** เลือก **`client_secret_post`** (หรือ `client_secret_basic` — *ห้ามเลือก `none`*)
   - **Scopes (หากต้องระบุ):** `lnwjud:mcp`
   - *(ช่อง OAuth endpoints ระบบค้นหาอัตโนมัติจาก `/.well-known/*` ให้เอง)*
4. ติ๊ก **I understand and want to continue** → กด **Create as a plugin** → กรอก **Invite Code** → กด **Continue** แล้วรอหน้า `Authorization complete` เด้งกลับอัตโนมัติ

> **หมายเหตุการตรวจสอบ:** หากต้องการเช็กว่า Gateway เปิดใช้งานอยู่หรือไม่โดยไม่ใช้ Token สามารถทดสอบเรียก `/healthz` (`{"ok":true}`) ส่วน endpoint `/mcp` จะตอบ `401 Unauthorized` เสมอเมื่อไม่มี OAuth Bearer Token

---

## 🔒 โครงสร้างความปลอดภัย (Security Model)
- **Local Admin Isolation:** Admin Console (`18789`) รับการเชื่อมต่อเฉพาะ `127.0.0.1` เท่านั้น ไม่ถูกเผยแพร่ออก Tailscale Funnel
- **Single-Use Launch Ticket & Strict Cookie:** ป้องกัน Token รั่วไหลผ่าน Command Line ของเบราว์เซอร์
- **Windows DPAPI:** Client Secret และ Invite Code เข้ารหัสด้วย DPAPI ระดับผู้ใช้
- **ไฟล์ที่ห้าม Commit ขึ้น Git:** `*.dpapi`, `*.pid`, `*.log`, `config-backups/`, และไฟล์ `config.json` ที่มีโดเมน/ข้อมูลส่วนตัวของเครื่องจริง
