# Cybersecurity-portfolio
I'm cybersecurity enthusiast.I am learning and developing projects regarding this field.In this portfolio ,there is all information which i have gain in my journey,for becoming SOC ANALYST
# 🔒 Python Security Log Analyzer

A Python-based security tool that analyzes Linux authentication logs to detect suspicious login activity, identify repeated failed login attempts, assess risk levels, and generate security reports with mitigation recommendations.

---

## 📌 Project Overview

The Python Security Log Analyzer is designed to help security analysts monitor Linux authentication logs for potential security threats. It processes log files, extracts important information such as usernames and IP addresses, identifies suspicious login patterns, and generates a structured security report.

This project was developed to strengthen practical skills in Python, Linux, and Information Security while gaining hands-on experience with security log analysis.

---

## ✨ Features

- Analyze Linux authentication log files
- Detect failed and successful login attempts
- Extract usernames and source IP addresses
- Count failed login attempts for each IP address
- Identify the most suspicious IP address
- Identify the most frequently attacked user account
- Classify risk level as Low, Medium, High, or No Risk
- Generate a detailed security report
- Provide security recommendations based on the detected activity

---

## 🛠 Technologies Used

- Python 3
- Linux (Ubuntu)
- File Handling
- Dictionaries
- String Processing
- Log Analysis

---

## 📂 Project Structure

```text
Python-Security-Log-Analyzer/
│
├── analyzer.py          # Main Python program
├── log.txt              # Sample log file
├── auth.log             # Ubuntu authentication log (optional)
├── report.txt           # Generated security report
├── README.md            # Project documentation
└── screenshots/         # Project screenshots
```

---

## 🚀 How to Run

1. Clone the repository.

```bash
git clone https://github.com/yourusername/Python-Security-Log-Analyzer.git
```

2. Open the project folder.

3. Run the program.

```bash
python analyzer.py
```

4. Select one of the options:

```
1. Analyze Sample Log
2. Analyze Ubuntu Authentication Log
```

5. The program will analyze the selected log file and generate a security report.

---

## 📊 Sample Output

```text
==================================================
            SECURITY REPORT
==================================================

Log File Analyzed      : log.txt
Total Log Entries      : 25
Failed Login Attempts  : 12
Successful Logins      : 5
Unique IP Addresses    : 4
Most Attacked User     : admin
Most Suspicious IP     : 192.168.1.10
Risk Level             : HIGH
Severity Score         : 9/10
```

---

## 🔐 Security Recommendations

The analyzer provides recommendations such as:

- Block suspicious IP addresses using a firewall
- Enable Multi-Factor Authentication (MFA)
- Review compromised user accounts
- Monitor authentication logs regularly
- Configure Fail2Ban
- Update Linux packages regularly
- Change weak passwords

---

---

## 📚 Skills Demonstrated

- Python Programming
- Linux Fundamentals
- Authentication Log Analysis
- Security Monitoring
- Basic Threat Detection
- Risk Assessment
- Information Security Fundamentals

---

## 🔮 Future Improvements

- Export reports in CSV and PDF formats
- Real-time log monitoring
- Email alert notifications
- Graphical dashboard
- SIEM integration
- Support for additional Linux log formats

---

## 👩‍💻 Author

**Madiha Faheem**

Computer Science Student

Aspiring Information Security Analyst

---

## 📄 License

This project is intended for educational and portfolio purposes.
