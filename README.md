## ⚙️ Features
- Rate limiting to prevent DDoS attacks
- IP blocking system
- XSS detection using regex patterns
- Logging suspicious requests

# 😈 Huỳnh Trịnh

## 💻 Backend & Security Learner

- 🛡️ Web Security (DDoS, XSS)
- 💀 Kali Linux (Nmap, sqlmap)
- 🧠 Python Developer

A lightweight web security system designed to detect and mitigate common attacks such as DDoS and XSS using Python.

## 🔥 Current Project
Mini Web Security System

A lightweight web protection tool that detects and blocks spam, bots, and suspicious traffic automatically.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Focus-Cybersecurity-red)

# 🛡️ BAY-CPU - Advanced Security Toolkit

A powerful Python-based security toolkit designed to detect and mitigate various types of cyber attacks including:

- 🔥 DDoS Attacks
- 💉 SQL Injection
- ⚡ XSS (Cross-Site Scripting)
- 🧬 CSRF Attacks
- 🧠 AI-based Threat Detection

## 🚀 Features
- Real-time traffic analysis
- Intelligent attack detection
- Modular security architecture
- Easy to deploy and extend

## ⚠️ Disclaimer
This tool is developed for educational and defensive purposes only.
Do not use it for illegal activities.



BAY-CPU/
├── core/
│   ├── engine.py
│   ├── defender.py
├── modules/
│   ├── antibot.py
│   ├── xss.py
├── utils/
│   ├── logger.py
│   ├── config.py
├── cli.py bạn
└── main.py

baycpu start
baycpu monitor
baycpu block --ip 192.168.1.1

git commit -m "Add DDoS protection with rate limiting"
git commit -m "Implement XSS detection using regex"
git commit -m "Add logging system"

# 💀 Mini WAF API
> A lightweight Web Application Firewall built to detect and block real-world attacks.

---

## 🛡️ Overview

This project is a self-built Web Application Firewall designed to simulate real-world defense mechanisms against common web attacks.

Instead of only learning theory, this project focuses on **practical implementation of attack detection and mitigation**.

---

## 🔥 Features

- 🚫 **DDoS Protection**
  - Rate limiting per IP
  - Temporary IP blocking

- 💀 **XSS Detection**
  - Pattern-based detection
  - Input normalization to prevent bypass

- 🧠 **SQL Injection Detection**
  - Detects common injection patterns
  - Filters malicious payloads

- 📊 **Logging System**
  - Tracks suspicious activity
  - Helps analyze attack behavior

---

## ⚔️ Attack Simulation

### XSS Attack
```json
{"data": "<script>alert(1)</script>"}

# 🔥 Mini WAF API

A lightweight Web Application Firewall built with FastAPI.

## 🛡️ Features
- Anti DDoS (Rate Limiting)
- XSS Detection
- SQL Injection Detection
- IP Blacklisting
- Logging System

## 💀 Demo

Example attack:
```json
{"data":"<script>alert(1)</script>"}