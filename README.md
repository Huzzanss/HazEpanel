# 🦅 PteroPanel

Panel manajemen server lokal bergaya **Pterodactyl** — 2 halaman HTML terpisah.

## Struktur File

```
PteroPanel/
├── server.js          ← Backend Node.js
├── package.json
├── README.md
└── public/
    ├── index.html     ← Dashboard semua server (halaman utama)
    └── console.html   ← Template konsol per server (dipanggil via /server/:id)
```

## Install & Jalankan

> Butuh **Node.js v16+**

```bash
cd PteroPanel
npm install
node server.js
```

Buka browser → **http://localhost:3000**

## Navigasi

| URL | Halaman |
|---|---|
| `http://localhost:3000` | Dashboard semua server |
| `http://localhost:3000/server/nama_server` | Konsol server tertentu |

## Ubah Folder Server

Edit di `server.js`:
```js
SERVERS_DIR: "D:\\Server",   // ← ganti path di sini
```

## Deteksi Tipe Server

| File | Tipe | Start |
|---|---|---|
| `server.jar` | Minecraft Java | `start.bat` atau `java -jar server.jar` |
| `bedrock_server.exe` | Bedrock | langsung |
| `package.json` | Node.js | `npm start` atau `node` |
| `main.py` / `app.py` / `bot.py` | Python | `python file.py` |
| `start.bat` | Batch | `cmd /c start.bat` |
| `start.sh` | Shell | `bash start.sh` |
| `*.exe` | Executable | langsung |

## Fitur

**Dashboard (`index.html`)**
- Grid semua server mirip Pterodactyl
- Status badge real-time (Online/Offline/Starting)
- Resource bar CPU & Memory per card
- Search & filter Online/Offline
- Live update via WebSocket
- Uptime counter per server

**Console (`console.html`)**
- Sidebar navigasi (Console / File Manager / Startup)
- Resource strip: CPU%, Memory, Uptime, Network, Disk
- Console real-time dengan warna ANSI
- Start / Stop / Restart / Kill
- File Manager: browse, baca, edit, hapus file
- Tab Startup: info konfigurasi server
- Auto-reconnect WebSocket
