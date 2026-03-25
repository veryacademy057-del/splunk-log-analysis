# 🚨 RDP Brute Force — Simulasi Serangan & Deteksi dengan Splunk SIEM

> **Seri Lab:** Blue Team SOC Lab  
> **YouTube:** [▶️ Tonton Tutorial di YouTube](https://youtu.be/CI4TYjWS2u4?si=nVrpK8PY93BsGg4_)  
> **Tools:** `Hydra, Nmap, Remmina, Splunk` | **Kategori:** `Attack Simulation, Log Analysis`

---

## 📋 Deskripsi

Lab ini mensimulasikan **serangan brute force terhadap layanan RDP** (*Remote Desktop Protocol*) menggunakan Kali Linux, kemudian mendeteksi dan menganalisis log serangan tersebut menggunakan **Splunk SIEM**. Lab ini memberikan perspektif dari dua sisi — **attacker** dan **defender (Blue Team)**.

**Tujuan Lab:**
- Memahami bagaimana attacker melakukan brute force terhadap RDP
- Mengidentifikasi log Windows yang dihasilkan dari serangan
- Menganalisis pola serangan di Splunk
- Membangun kemampuan deteksi dari perspektif SOC Analyst

---

## 🎬 Video Tutorial

[![RDP Brute Force Detection - Splunk SIEM](https://img.youtube.com/vi/CI4TYjWS2u4/maxresdefault.jpg)](https://youtu.be/CI4TYjWS2u4?si=nVrpK8PY93BsGg4_)

> 📺 **[Tonton di YouTube → RDP Brute Force Simulation & Detection](https://youtu.be/CI4TYjWS2u4?si=nVrpK8PY93BsGg4_)**

---

## 🏗️ Lingkungan Lab

| Peran | OS | IP Address |
|------|----|------------|
| **Attacker** | Kali Linux | `10.200.200.10` |
| **Target** | Windows Server 2012 | `10.200.200.20` |
| **SIEM** | Splunk (via Forwarder) | Terhubung ke Windows Server |

---

## 🗺️ Alur Lab

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   [Kali Linux]                    [Windows Server]         │
│   10.200.200.10                   10.200.200.20            │
│                                                             │
│   1. Nmap Scan ──────────────────► Port 3389 (RDP)         │
│   2. Hydra Attack ───────────────► Brute Force RDP         │
│   3. Remmina ────────────────────► Manual RDP Login        │
│                                          │                  │
│                                          │ Log (4625/4624)  │
│                                          ▼                  │
│                                   [Splunk SIEM]            │
│                                   10.200.200.100           │
│                                   Analisis & Deteksi       │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚔️ Bagian 1 — Reconnaissance (Scanning Target)

Sebelum menyerang, attacker selalu melakukan reconnaissance untuk mengetahui port apa saja yang terbuka.

```bash
nmap 10.200.200.20
```

**Hasil Scan:**

| Port | Layanan | Keterangan |
|------|---------|------------|
| `88` | Kerberos | Autentikasi domain |
| `389` | LDAP | Direktori Active Directory |
| `445` | SMB | File sharing Windows |
| `3389` | **RDP** | **← Target utama brute force** |

> 💡 **Insight:** Kombinasi port 88 (Kerberos), 389 (LDAP), dan 3389 (RDP) mengindikasikan bahwa target adalah **Windows Server yang berperan sebagai Domain Controller** — target bernilai tinggi bagi attacker.

---

## ⚔️ Bagian 2 — Brute Force Attack dengan Hydra

### Percobaan 1 — Username Tidak Valid

```bash
hydra -l fufufafa -p rdp.txt rdp://10.200.200.20
```

**Hasil:**

```
❌ Tidak ada password ditemukan
❌ Username tidak valid
✅ Menghasilkan log Event ID 4625 di Windows
```

---

### Percobaan 2 — Username Valid (Administrator)

```bash
hydra -l administrator -P rockyou.txt rdp://10.200.200.20
```

**Hasil:**

```
⚠️  Banyak percobaan login terkirim
⚠️  Error: "account not active for remote desktop"
```

> 💡 **Insight:** Error ini berarti username `administrator` **valid**, tetapi akun tersebut tidak memiliki izin untuk login via RDP. Attacker perlu mencari akun lain yang memiliki hak RDP.

---

### ⚠️ Catatan Penting — Keterbatasan Hydra untuk RDP

| Keterbatasan | Penjelasan |
|-------------|------------|
| Eksperimental | Modul RDP Hydra tidak stabil |
| Mudah gagal koneksi | Sering muncul error `freerdp error` |
| Log tidak lengkap | IP attacker kadang tidak terekam di Windows log |
| Tidak cocok untuk high-speed | Koneksi RDP membutuhkan handshake yang berat |

---

## 🖥️ Bagian 3 — Simulasi Login Manual (Remmina)

Selain Hydra, simulasikan login manual menggunakan **Remmina** (RDP client di Kali Linux):

```
Buka Remmina → New Connection
Protocol : RDP
Server   : 10.200.200.20
Username : administrator
Password : (coba beberapa password)
```

> 💡 Login manual via Remmina menggunakan **Logon Type 10** (Remote Interactive) yang menghasilkan log lebih lengkap dan konsisten dibanding Hydra — IP attacker hampir selalu tercatat.

---

## 📊 Bagian 4 — Analisis Log di Splunk SIEM

### 4.1 — Query Dasar

```splunk
index=main sourcetype="WinEventLog:Security"
```

---

### 4.2 — Deteksi Login Gagal (Brute Force)

```splunk
index=main sourcetype="WinEventLog:Security" EventCode=4625
```

> **Event ID 4625** = Login gagal. Jika muncul dalam jumlah besar dalam waktu singkat, ini adalah indikasi kuat serangan brute force.

---

### 4.3 — Deteksi Login Berhasil

```splunk
index=main sourcetype="WinEventLog:Security" EventCode=4624
```

---

### 4.4 — Lacak IP Attacker

```splunk
index=main sourcetype="WinEventLog:Security" EventCode=4624
Source_Network_Address=10.200.200.10
```

> 💡 **Insight:** Query ini menunjukkan kapan attacker berhasil login dari IP `10.200.200.10`. Ini adalah **bukti kompromasi** yang paling kritis.

---

### 4.5 — Deteksi Pola Brute Force (Advanced)

```splunk
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address
| sort - count
```

> 👉 Query ini menampilkan akun dan IP mana yang paling banyak melakukan login gagal — langsung menunjuk ke attacker.

---

## 🧠 Bagian 5 — Analisis Perilaku Log

### Field Penting di Event ID 4625

| Field | Keterangan |
|-------|------------|
| `Account_Name` | Username yang dicoba |
| `Source_Network_Address` | IP asal login |
| `Workstation_Name` | Nama mesin attacker |
| `Logon_Type` | Tipe login (lihat tabel di bawah) |
| `Authentication_Package` | Protokol autentikasi (NTLM/Kerberos) |

---

### Tabel Logon Type

| Logon Type | Deskripsi | Relevansi |
|------------|-----------|-----------|
| `2` | Interactive (login langsung di mesin) | Login fisik ke server |
| `3` | Network (SMB, Hydra RDP) | Hydra brute force |
| `10` | Remote Interactive (RDP) | Login via Remmina/RDP client |

---

### ⚠️ Kenapa IP Attacker Kadang Tidak Muncul?

Ini adalah fenomena nyata yang akan ditemui di lab:

```
Source Network Address: -
Workstation Name     : kali
Authentication Package: NTLM
```

**Penyebabnya:**

| Penyebab | Penjelasan |
|----------|------------|
| NTLM authentication | Tidak selalu menyimpan source IP |
| Koneksi gagal terlalu cepat | Hydra mengirim request sebelum handshake selesai |
| Username tidak valid | Windows tidak mencatat IP untuk user yang tidak ada |
| Logon Type 3 | Network logon kadang tidak merekam IP lengkap |

> 💡 **Lesson:** Ini adalah alasan mengapa SOC Analyst tidak boleh hanya bergantung pada **satu field** — analisis harus melihat kombinasi beberapa field dan pola log secara keseluruhan.

---

## 🔥 Bagian 6 — Pola Serangan Brute Force di Splunk

Ciri-ciri serangan brute force yang terlihat di Splunk:

```
✅ Banyak Event ID 4625 dalam waktu sangat singkat
✅ Username sama (administrator) dengan password berbeda-beda
✅ Logon Type 3 (Hydra) atau 10 (RDP manual)
✅ Source IP yang sama berulang kali
✅ Timestamp yang sangat berdekatan (milliseconds)
```

---

## 🛡️ Bagian 7 — Strategi Deteksi (Perspektif SOC)

### Indikator Brute Force

```splunk
# Spike besar Event 4625 dalam waktu singkat
index=main sourcetype="WinEventLog:Security" EventCode=4625
| timechart count span=1m

# Cari IP dengan login gagal terbanyak
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Source_Network_Address
| sort - count

# Korelasi: login gagal kemudian berhasil dari IP sama
index=main sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| stats count by EventCode, Source_Network_Address
| sort Source_Network_Address
```

---

## 💡 Bagian 8 — Key Findings

### Temuan 1 — Hydra Tidak Selalu Menghasilkan Log Lengkap
Hydra menggunakan protokol yang bisa menyebabkan IP attacker tidak tercatat di log Windows. Ini adalah celah yang perlu dipahami SOC Analyst.

### Temuan 2 — RDP Manual Menghasilkan Log Lebih Jelas
Login via Remmina menggunakan Logon Type 10 yang hampir selalu mencatat source IP — lebih mudah dideteksi dan diinvestigasi.

### Temuan 3 — Satu Log Tidak Cukup
Satu Event ID 4625 tidak berarti apa-apa. Yang berbahaya adalah **pola** — ratusan 4625 dalam satu menit dari IP yang sama adalah brute force.

### Temuan 4 — Perilaku Lebih Penting dari Satu Log

> *"SOC tidak hanya melihat satu log, tapi pola dari ribuan log."*

---

## 📌 Kesimpulan

| Poin | Kesimpulan |
|------|------------|
| Deteksi | Brute force RDP dapat dideteksi melalui **Event ID 4625** |
| Keterbatasan | Tidak semua log memberikan informasi lengkap (IP bisa kosong) |
| Tools | Kombinasi Hydra + Remmina memberikan gambaran serangan yang lebih lengkap |
| SIEM | Splunk sangat efektif untuk analisis pola dan deteksi otomatis |

---

## 📚 Referensi

- [Hydra Documentation](https://github.com/vanhauser-thc/thc-hydra)
- [Windows Event ID 4625 Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4625)
- [Windows Event ID 4624 Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [MITRE ATT&CK — Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)

---

*📺 Ikuti tutorialnya di [YouTube](https://youtu.be/CI4TYjWS2u4?si=nVrpK8PY93BsGg4_) | ⭐ Star repo ini jika membantu!*
