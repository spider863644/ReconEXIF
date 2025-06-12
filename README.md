# 🔍 ReconEXIF - Forensic Metadata Extraction Tool


**Version 1.0 - Forensic Edition**  
Developed by **Spider Anongreyhat** & **TheNooB**  
Community: TermuxHackz Society  
Telegram: [@Anonspideyy](https://t.me/Anonspideyy)

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
git clone https://github.com/spider863644/ReconEXIF.git
cd ReconEXIF
pip install -r requirements.txt
```
## ⚠️ Dependencies

Install manually if needed:

```bash
pip install exifread PyPDF2 mutagen hachoir python-magic numpy Pillow colorama
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
## 🛠️ Usage
**Basic Usage**
```bash
python exif.py file.jpg
python exif.py document.pdf
```
**Specific Flags**
```bash
python exif.py file.jpg --photo_info --forensic --output result.json
python exif.py audio.mp3 --audio_info
python exif.py file.jpg --steghide
```
**Interactive Mode**
```
python exif.py
```
## 🔧 CLI Options

| Option           | Description                                     |
|------------------|-------------------------------------------------|
| `--device_info`  | Basic file info                                 |
| `--photo_info`   | Extract EXIF & GPS from image                   |
| `--pdf_info`     | PDF metadata                                    |
| `--audio_info`   | Audio metadata (ID3 tags)                       |
| `--video_info`   | Video file metadata                             |
| `--forensic`     | Hashes, steganography, entropy, timeline        |
| `--steghide`     | Steganography extraction (Steghide) only        |
| `--output`       | Save results to a JSON file                     |


## 👨‍💻 Developers

- **Spider Anongreyhat** – Telegram: [@Anonspideyy](https://t.me/Anonspideyy)
- **TheNooB** – Support & Community: TermuxHackz Society

  ## 📜 License

This project is licensed under the [MIT License](LICENSE).

> Use responsibly. For educational and forensic purposes only.

## 🤝 Contributors

Thanks to the following people who have contributed to this project:

- [@SpiderAnongreyhat](https://github.com/Spider863644) – 💻 Developer & Maintainer
- [@TheNooB](https://github.com/TheNooB4) – 🔧 Support & Testing
