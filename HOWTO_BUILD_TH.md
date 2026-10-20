# วิธี build liburlhook.so ด้วย GitHub Actions

โปรเจกต์นี้คือ hook (Dobby) ที่ปรับให้ชี้ Cry4Me → `zxx.alwaysdata.net`
สิ่งที่แก้จากต้นฉบับ:
- `TARGET_HOST = "zxx.alwaysdata.net"`, `TARGET_PATHS = /api/client/login, /api/client/heartbeat, /api/lib/`
- `getaddrinfo`: ดักเฉพาะชื่อที่มี `cry4me.best`
- `SSL_set_tlsext_host_name` (SNI): เปลี่ยนเฉพาะ `cry4me.best`
- `SSL_write`: ไม่แก้ path แล้ว แก้เฉพาะ header `Host:`
- `curl_easy_setopt`: เปลี่ยน URL เป็น `https://zxx.alwaysdata.net<path>` โดยคง path เดิม
- **เพิ่ม hook แบบ by-address**: สำหรับ `libpd267…so` (curl ถูก link แบบ static + strip → dlsym ไม่เจอ)
  ใช้ `base + 0x620b71c` (offset ของ `curl_easy_setopt` ในบิลด์ 1.0.1)

## ขั้นตอน
1. สร้าง repo ใหม่ (private ได้) แล้ว push โฟลเดอร์นี้ทั้งก้อน:
   ```sh
   cd hook_cry4me
   git init && git add -A && git commit -m "cry4me hook"
   git remote add origin https://github.com/<user>/<repo>.git
   git push -u origin main
   ```
2. เปิดแท็บ **Actions** → workflow `build-liburlhook` จะรันเอง (หรือกด Run workflow)
3. โหลด artifact **liburlhook-arm64** → ได้ `liburlhook.so` (arm64)
4. ส่งไฟล์มาให้ผม (หรือวางที่ `/storage/emulated/0/MCP/` ก็ได้) — ผมจะฝังเข้า APK + ทดสอบให้

> หมายเหตุ: ผมรัน GitHub แทนไม่ได้ถ้าไม่มี token/repo — ถ้าสะดวกให้สร้าง token (repo scope) แล้วบอก ผมจะ push/run ให้ทั้งหมด
