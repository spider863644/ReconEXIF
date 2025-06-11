# 🔍 ReconEXIF - Forensic Metadata Extraction Tool

![ReconEXIF Banner](https://your-image-link.com/banner.png) <!-- Optional -->

**Version 1.0 - Forensic Edition**  
Developed by **Spider Anongreyhat** & **TheNooB**  
Community: TermuxHackz Society  
Telegram: [@Anonspideyy](https://t.me/Anonspideyy)

---

## 📽️ Demo Video

https://www.youtube.com/watch?v=YOUR_DEMO_VIDEO_LINK

> 🔁 Replace the above link with your actual demo or walkthrough video.

---

## 🧰 Features

- ✅ Extract EXIF & GPS metadata from images
- ✅ Extract metadata from PDFs, audio, and video files
- ✅ Forensic timeline (created, modified, accessed)
- ✅ Calculate MD5, SHA1, and SHA256 hashes
- ✅ Steganography detection (LSB, entropy, steghide support)
- ✅ Detect suspicious content (Base64 strings, URLs, emails)
- ✅ Automatic file type detection (via `magic` or headers)
- ✅ JSON export support
- ✅ Interactive & CLI modes

---

## 📦 Supported File Types

| File Type | Supported Metadata |
|-----------|--------------------|
| Images (JPG, PNG, BMP, etc) | EXIF, GPS, hashes, LSB, entropy |
| PDFs | Author, title, producer, etc. |
| Audio (MP3, FLAC, etc) | ID3 tags, hashes |
| Videos (MP4, MKV, etc) | Codec, duration, resolution |
| Any file | Hashes, entropy, filetype, suspicious strings |

---

## 🚀 Installation

```bash
git clone https://github.com/yourusername/ReconEXIF.git
cd ReconEXIF
pip install -r requirements.txt
```

## 🔌 Optional Tools

**Steghide** (for hidden data in images)

- **Linux**:  
  ```bash
  sudo apt install steghide
  ```
  **Mac OS**
  ```bash
  brew install steghide
```
