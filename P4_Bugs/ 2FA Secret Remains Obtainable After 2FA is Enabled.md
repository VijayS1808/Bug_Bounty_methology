# 🔐🔥 2FA Secret Leakage 💀 — Full 2FA Bypass Reproduction 🧨

## 🧠 Overview

💡 **Issue**: The application allows retrieval of the TOTP (Time-based One-Time Password) secret **even after 2FA is enabled**.

⚠️ This allows an attacker to:
- 🔓 Bypass 2FA any time if credentials are leaked
- 🔁 Reuse the secret to generate valid OTPs forever
- 👀 Extract secret via browser or API even post-setup

---

## 🛠️ Step-by-Step Reproduction

### ✅ 1. 🧍 Create or Use a Test Account
- Register a new account on the target site/app.
- Or use an existing test account.

---

### 🔐 2. Enable 2FA Setup 🔒
- Go to **Account Settings → Security → 2FA**
- Scan the QR code or manually copy the **Base32 secret** (e.g., `JBSWY3DPEHPK3PXP`) into your authenticator app (Google Authenticator, Authy, etc.) ✅
- 🔥 **Save this secret** for later!

---

### 🧪 3. Confirm 2FA is Enabled
- Enter the 6-digit OTP to confirm 2FA setup.
- You should now be logged in with 2FA active 🔐

---

### 🕵️ 4. Inspect API/Browser Traffic 🛰️
- Open **DevTools** (`F12` / `Ctrl+Shift+I`)
- Go to **Network tab**
- Refresh the **Profile** or **2FA Settings** page

Look for API responses that leak something like:
```json
{
  "2fa_enabled": true,
  "2fa_secret": "JBSWY3DPEHPK3PXP"
}
