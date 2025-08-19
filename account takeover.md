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

# 0-Click Account Takeover via OAuth Misconfiguration

## Steps to Reproduce:

1.Identify the victim and get their email address.

2.Go to the login page: https://www.[Redacted].com/login

3.Click on Sign in with Google. Before choosing the account, intercept the request in Burp Suite.

4.Forward the requests one by one until you reach the endpoint:

5.In the request body, change the values of email and name to the victim’s email and name.

6.Forward all subsequent requests.

7.You will now be logged into the victim’s account and can view or edit their data.


# Password Reset Poisoning via Middleware: The Hidden Flaw That Can Lead to Account Takeover

# OAuth Open Redirect to ATO:

```
https://0xoverlord.medium.com/oauth-open-redirect-to-ato-one-link-all-platforms-compromised-c4b54fb51396
```


