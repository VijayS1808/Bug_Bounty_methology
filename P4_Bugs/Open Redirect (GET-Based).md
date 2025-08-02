# 🔁 Unvalidated Redirects and Forwards: Open Redirect (GET-Based) 🚨🌐

## 🧠 Summary

The application allows user-controlled redirection via URL parameters without proper validation. An attacker can manipulate the `redirect` or similar parameter to redirect users to malicious sites (e.g., phishing pages). This is commonly known as an **Open Redirect vulnerability**.

---

## ⚠️ Impact

- 🎯 Phishing attacks using trusted domain names.
- 🛑 Potential Bypass of Security Controls (e.g., login flows).
- 📉 Loss of user trust if redirected to malicious content.
- 🧩 May assist in **OAuth token hijacking** or **SSO abuse**.

---

## 🧪 Reproduction Steps

1. 🔍 Identify a URL with a redirect parameter. Example:
