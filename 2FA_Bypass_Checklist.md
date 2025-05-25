
# ⚠️ 2FA Bypass Techniques
> _A curated checklist to test and exploit common Two-Factor Authentication (2FA) weaknesses_

---

### 🔍 Logic Flaws
- [ ] ✅ **Flawed 2FA Verification Logic**  
   Change the `account` cookie after logging in with your own credentials.
   ```http
   Cookie: account=victim-user
   ```
- [ ] ✅ **Direct Request After Login Step 1**  
   Access authenticated endpoints without completing the 2FA step.

---

### 🖼️ Clickjacking
- [ ] 🕵️‍♂️ **Clickjacking on 2FA Disable Page**  
   Embed the disable-2FA page inside an `<iframe>` and use social engineering.

---

### 🔁 Response & Status Manipulation
- [ ] 🔧 **Edit "Success": false to "Success": true**  
- [ ] 🚫 **Change HTTP Status from 4XX to 200 OK**

---

### 🔄 OTP Reuse & Expiry
- [ ] ♻️ **Reuse the Same 2FA Code Multiple Times**
- [ ] 🕰️ **Re-use After Long Delay (e.g., 24h)**
- [ ] 🧪 **Check if Previous Codes Expire Properly**

---

### 🛡️ CSRF on 2FA Settings
- [ ] 🧬 **Disable 2FA via CSRF**  
   Attempt a CSRF attack on the 2FA disable functionality.

---

### 🔐 Backup Codes
- [ ] 🧨 **Abuse Backup Codes**  
   Use brute force, response tampering, or reuse techniques.

---

### 🌐 Session Control Weaknesses
- [ ] 🧍‍♂️➡️🧍‍♂️ **Session Not Expired After Enabling 2FA**
- [ ] 📲 **Use Old Session After Enabling 2FA**
- [ ] 🧠 **Session Role Confusion Between Users**

---

### 🔗 Referer Header Bypass
- [ ] 🧩 **Fake Referer to Simulate Passing 2FA Step**  
   ```http
   Referer: /2fa-page
   ```

---

### 📤 Code Exposure & Leaks
- [ ] 📦 **2FA Code in Response Body**
- [ ] 📜 **Sensitive Info in JavaScript Files**

---

### 🛑 Rate Limiting Issues
- [ ] 🧱 **No OTP Brute-Force Protection**
- [ ] 🧯 **Brute Force OTP While Requesting New OTP Simultaneously**
- [ ] 🔃 **Resend Button Resets Rate Limit**
- [ ] 💻 **Client-Side Rate Limit Only**
- [ ] 💸 **Abuse SMS OTP Sending – Drain Resources**
- [ ] 🔁 **Infinite OTP Generation**

---

### 🔁 Password Reset Abuse
- [ ] 🔓 **Resetting Password Disables 2FA**
- [ ] 🙈 **No Password Check When Disabling 2FA**

---

### 📩 Email-Based 2FA Weakness
- [ ] ✉️ **Switch OTP Mode from SMS to Email via Request Interception**

---

### 🔕 Bypass with Empty Code
- [ ] 🏳️ **Submit Empty or "000000" Code**

---

### 📬 Unverified Emails Allowed
- [ ] 🧑‍💻 **Add 2FA Before Email is Verified**

---

### 🔐 Token Reuse & Sharing
- [ ] 🔁 **Use Old or Leaked Tokens**
- [ ] 📤 **Token Sharing Across Accounts**

---

### 🌍 Other Interesting Vectors
- [ ] 🍪 **Guessable "Remember Me" Cookie**
- [ ] 📡 **IP-Based Trust Weakness**
- [ ] 🧪 **Test/Staging Subdomains**
- [ ] 🔎 **Legacy APIs (e.g., `/v1/`, `/v2/`)**
- [ ] 🔒 **Improper Access Control for Backup Codes**
- [ ] 🕵️ **Info Disclosure on 2FA Pages**

---

### 🎯 Special Cases
- [ ] 🧪 **Previously Created Sessions Remain Valid Post-2FA**
- [ ] 💻 **2FA Can Be Enabled Without Email Verification**
- [ ] ❌ **2FA Disabled Without Password Validation**
- [ ] 🧙 **Switch MFA Modes in Request for Bypass (e.g., SMS ➝ Email)**
