# 🎣 Phishing Link Detector

> ML-based tool to detect and classify malicious phishing URLs using domain patterns, URL length, special character ratios, and keyword analysis. Trained on real-world phishing datasets.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![ML](https://img.shields.io/badge/Model-Random%20Forest-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📌 Overview

Phishing URLs follow detectable patterns — suspicious TLDs, brand names in subdomains, hex encoding, excessive hyphens, and phishing keywords. This tool extracts **18 handcrafted features** from any URL and classifies it as safe or phishing with a confidence score.

**Built by:** Om Awachar — Security Analyst & Bug Bounty Researcher

---

## 🎯 Features Extracted (18 total)

| Feature | Description |
|---|---|
| IP as domain | Phishers use IPs to avoid domain tracking |
| @ symbol | Redirects browser to different host |
| Brand in subdomain | `paypal.fake-site.com` pattern |
| Suspicious TLD | `.tk`, `.ml`, `.ga`, `.xyz`, `.click` etc. |
| Hex encoding | `%20`, `%2F` used to obscure URLs |
| Phishing keywords | login, verify, secure, account, suspend... |
| Subdomain depth | `a.b.c.evil.com` = depth 3 |
| HTTPS usage | HTTP-only is a weak signal |
| URL / path length | Phishing URLs tend to be long |
| Special char ratio | High `!`, `=`, `?`, `&` density |
| + 8 more | Hyphens, port numbers, double slashes... |

---

## 🚀 Quick Start

```bash
git clone https://github.com/om-awachar/phishing-detector.git
cd phishing-detector
pip install -r requirements.txt

# Check a single URL
python detector.py --url "http://paypal-secure.tk/login/verify"

# Check a file of URLs
python detector.py --file data/sample_urls.csv --output report.json

# Verbose mode (shows all 18 features)
python detector.py --url "http://192.168.1.1/login" --verbose
```

---

## 📊 Sample Output

```
  🔴 PHISHING  (94.2%)  http://paypal-secure-login.tk/verify/account
  🟢 SAFE      (98.1%)  https://paypal.com/login
  🔴 PHISHING  (91.7%)  http://192.168.1.1/login/paypal/secure

=======================================================
  SCAN SUMMARY
  Total URLs : 3
  Phishing   : 2
  Safe       : 1
=======================================================

  ⚠️  PHISHING URLs DETECTED:

  URL      : http://paypal-secure-login.tk/verify/account
  Score    : 31.0  |  Confidence: 94.2%
    • Suspicious free TLD
    • Brand name in subdomain (spoofing)
    • 3 phishing keywords
    • No HTTPS
```

---

## 🤖 Training Your Own Model

```bash
# Use the provided sample dataset or bring your own
python model/train.py --dataset data/sample_urls.csv

# Dataset format (CSV):
# url,label
# https://paypal.com,0
# http://paypal-fake.tk/login,1
```

The trainer uses **Random Forest (100 estimators)** from scikit-learn and saves the model to `model/phishing_model.pkl`. Public phishing datasets are available from [PhishTank](https://phishtank.org) and [OpenPhish](https://openphish.com).

---

## 📁 Project Structure

```
phishing-detector/
├── detector.py             # CLI entry point
├── requirements.txt
├── utils/
│   ├── extractor.py        # 18-feature URL extractor
│   ├── predictor.py        # Weighted scoring + confidence
│   └── report.py           # Output formatting + JSON export
├── model/
│   └── train.py            # Random Forest training script
└── data/
    └── sample_urls.csv     # Sample labelled dataset
```

---

## ⚠️ Disclaimer

For educational and security research purposes only.

---

## 👤 Author

**Om Awachar** — Security Analyst  
HackerOne Hall of Fame × 2 | RBI-recognised Audit Quality | AI Security & LLM Red Teaming
