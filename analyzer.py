# ==========================================
# Python Security Log Analyzer
# ==========================================
from datetime import datetime
print("=" * 50)
print("        Python Security Log Analyzer")
print("=" * 50)
print("1. Analyze Sample Log")
print("2. Analyze Ubuntu Authentication Log")

choice = input("\nEnter your choice (1 or 2): ")

if choice == "1":
    filename = "log.txt"
elif choice == "2":
    filename = "auth.log"
else:
    print("Invalid choice!")
    exit()

# Read selected log file
with open(filename, "r") as file:
    log = file.readlines()

print(f"\nAnalyzing {filename}...\n")

# ==========================================
# Variables
# ==========================================

failed_count = 0
success_count = 0

failed_ips = {}
failed_users = {}

# ==========================================
# Analyze Logs
# ==========================================

for line in log:

    # Failed Login Detection
    if (
        "Failed password" in line
        or "authentication failure" in line
        or "password check failed" in line
    ):

        failed_count += 1

        parts = line.split()

        # ------------------------
        # Username
        # ------------------------

        if "for" in parts:
            username = parts[parts.index("for") + 1].strip("()")

        elif "user" in parts:
            username = parts[parts.index("user") + 1].strip("()")

        else:
            username = "Unknown"

        # ------------------------
        # IP Address
        # ------------------------

        if "from" in parts:
            ip = parts[parts.index("from") + 1]
        else:
            ip = "Unknown"

        # Count Failed IPs
        failed_ips[ip] = failed_ips.get(ip, 0) + 1

        # Count Failed Users
        failed_users[username] = failed_users.get(username, 0) + 1

    # Successful Login
    elif "Accepted password" in line:
        success_count += 1

# ==========================================
# Security Summary
# ==========================================

total_logs = len(log)
unique_ips = len(failed_ips)

if failed_ips:
    suspicious_ip = max(failed_ips, key=failed_ips.get)
    highest_attempts = failed_ips[suspicious_ip]
else:
    suspicious_ip = "None"
    highest_attempts = 0

if failed_users:
    attacked_user = max(failed_users, key=failed_users.get)
else:
    attacked_user = "None"

# ==========================================
# Risk Level
# ==========================================

# ==========================================
# Risk Assessment
# ==========================================

if highest_attempts >= 5:
    risk_level = "HIGH"
    severity_score = "9/10"

    reason = [
        f"{highest_attempts} failed login attempts detected.",
        f"Repeated attacks against the '{attacked_user}' account.",
        f"Suspicious IP identified: {suspicious_ip}"
    ]

elif highest_attempts >= 3:
    risk_level = "MEDIUM"
    severity_score = "6/10"

    reason = [
        f"{highest_attempts} failed login attempts detected.",
        "Repeated login failures observed.",
        f"Suspicious IP identified: {suspicious_ip}"
    ]

elif highest_attempts > 0:
    risk_level = "LOW"
    severity_score = "3/10"

    reason = [
        "A small number of failed login attempts detected.",
        "Continue monitoring authentication logs."
    ]

else:
    risk_level = "NO RISK"
    severity_score = "0/10"

    reason = [
        "No suspicious authentication activity detected."
    ]
# ==========================================
# Print Security Report
# ==========================================

print("=" * 50)
print("             SECURITY REPORT")
print("=" * 50)

print(f"Log File Analyzed      : {filename}")
print(f"Total Log Entries      : {total_logs}")
print(f"Failed Login Attempts  : {failed_count}")
print(f"Successful Logins      : {success_count}")
print(f"Unique IP Addresses    : {unique_ips}")
print(f"Most Attacked User     : {attacked_user}")
print(f"Most Suspicious IP     : {suspicious_ip}")
print(f"Risk Level             : {risk_level}")
print(f"Severity Score         : {severity_score}")

print("\nRISK ASSESSMENT")
print("-" * 50)

for item in reason:
    print(f"• {item}")

print("\nFailed Login Count Per IP")
print("-" * 50)

for ip, count in failed_ips.items():
    print(f"{ip} : {count}")

current_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

# ==========================================
# Security Recommendations
# ==========================================

print("\nSecurity Recommendations")
print("-" * 50)

if suspicious_ip != "None":

    print(f"⚠ High-Risk IP: {suspicious_ip}")

    print("\nRecommended Actions:")

    print("✔ Block the suspicious IP using a firewall (UFW/iptables).")

    print("✔ Enable Multi-Factor Authentication (MFA).")

    print(f"✔ Review the '{attacked_user}' account.")

    print("✔ Monitor authentication logs regularly.")

    print("✔ Configure Fail2Ban to block repeated login attempts.")

    print("✔ Change weak passwords if necessary.")

    print("✔ Keep Linux packages updated.")

else:

    print("✔ No suspicious activity detected.")

print("=" * 50)

# ==========================================
# Save Report
# ==========================================

with open("report.txt", "w") as report:

    report.write("=" * 50 + "\n")
    report.write("             SECURITY REPORT\n")
    report.write("=" * 50 + "\n\n")

    report.write(f"Log File Analyzed      : {filename}\n")
    report.write(f"Total Log Entries      : {total_logs}\n")
    report.write(f"Failed Login Attempts  : {failed_count}\n")
    report.write(f"Successful Logins      : {success_count}\n")
    report.write(f"Unique IP Addresses    : {unique_ips}\n")
    report.write(f"Most Attacked User     : {attacked_user}\n")
    report.write(f"Most Suspicious IP     : {suspicious_ip}\n")
    report.write(f"Risk Level             : {risk_level}\n\n")

    report.write("Failed Login Count Per IP\n")
    report.write("-" * 50 + "\n")
    print(f"Report Generated : {current_time}")
    report.write(f"Report Generated : {current_time}\n")

    for ip, count in failed_ips.items():
        report.write(f"{ip} : {count}\n")

    report.write("\n")

    report.write("Security Recommendations\n")
    report.write("-" * 50 + "\n")

    if suspicious_ip != "None":

        report.write(f"High-Risk IP: {suspicious_ip}\n\n")

        report.write("Recommended Actions:\n")

        report.write("- Block the suspicious IP using a firewall (UFW/iptables).\n")

        report.write("- Enable Multi-Factor Authentication (MFA).\n")

        report.write(f"- Review the '{attacked_user}' account.\n")

        report.write("- Monitor authentication logs regularly.\n")

        report.write("- Configure Fail2Ban to block repeated login attempts.\n")

        report.write("- Change weak passwords if necessary.\n")

        report.write("- Keep Linux packages updated.\n")

    else:

        report.write("No suspicious activity detected.\n")

    report.write("\n")
    report.write("=" * 50 + "\n")

print("\n✅ Report saved successfully as report.txt")