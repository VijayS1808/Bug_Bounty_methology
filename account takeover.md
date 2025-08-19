# 🔐 From Pre-Account Takeover ➝ Full Account Takeover via Google OAuth

## ✨ Summary
This report highlights a **critical authentication flaw** in the Google OAuth integration.  
By abusing the **lack of email verification** and **improper identity linking**, an attacker can:
- 🕵️ **Pre-create accounts** with victim’s email (Pre-Account Takeover).  
- 🔑 **Retain access** even after the victim signs up with Google OAuth.  
- 🚪 Maintain a **persistent backdoor** into the victim’s account, even after password resets.  

Severity: **🔥 Critical (Full Account Compromise)**

---

## 🧪 Steps to Reproduce

### 🅰️ Scenario A — Pre-Account Takeover
1. 🧑‍💻 **Attacker creates a local account** with the victim’s email (`victim@example.com`).  
   - App allows instant login without verifying ownership.  

2. ✅ Attacker is **logged in** as that email.  

3. 👤 **Victim signs up via Google OAuth** with their real Google account (`victim@example.com`).  
   - App merges it into the attacker-created account.  
   - Victim receives a **password setup link** and sets a password.  

4. 🔄 **Check attacker’s session** in Browser A.  
   - ❗ Attacker is **still logged in** and has access to the victim’s account.  

💥 **Impact:** Victim’s account is compromised immediately upon signup.

---

### 🅱️ Scenario B — Full & Persistent Takeover (OAuth Backdoor)
1. 🧑‍💻 **Attacker signs up via Google** with their own Google (`attacker@gmail.com`).  

2. ✏️ In profile settings, attacker **changes the account email** to victim’s email (`victim@example.com`).  

3. 👤 Later, **victim signs up via Google OAuth** with their real Google (`victim@example.com`).  
   - Victim is redirected into attacker’s account (now labeled with victim’s email).  
   - Victim sets a new password.  

4. 🔄 **Persistence test:**  
   - Attacker logs in again via **their original Google (`attacker@gmail.com`)**.  
   - ❗ Attacker is still redirected into the **victim’s account**.  
   - Password resets do not help — OAuth bypasses them.  

💥 **Impact:** Attacker maintains a **permanent backdoor** to the victim’s account.

---
