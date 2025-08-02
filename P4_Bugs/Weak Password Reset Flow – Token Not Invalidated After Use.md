# 🔐💣 Weak Password Reset Flow – Token Not Invalidated After Use

## 🧠 Summary

💡 The application allows the **password reset token to remain valid even after it has been used**, exposing users to replay attacks and potential account takeover.

🛠️ Combined with:
- **Insufficient Security Configurability** (no reset/revoke/token lifecycle controls)
- **Weak password reset logic**
- ❌ Missing or broken invalidation of token after usage

➡️ This results in a **high-severity vulnerability**.

---

## 🧪 Step-by-Step Reproduction

### ✅ 1. Initiate Password Reset
- Go to `Forgot Password` page.
- Submit user email (e.g., `victim@example.com`).
- Receive reset email containing a URL like:

