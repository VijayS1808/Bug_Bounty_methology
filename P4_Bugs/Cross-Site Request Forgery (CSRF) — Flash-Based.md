# ⚡ Cross-Site Request Forgery (CSRF) — Flash-Based 🚨🔥

## 🧠 Summary

A **Flash-based CSRF vulnerability** exists in the application. Even though Flash is deprecated, legacy Flash endpoints or files (`.swf`) can still be exploited to perform **unauthorized actions** on behalf of authenticated users without their knowledge or consent.

> 🧨 This vulnerability allows attackers to craft malicious `.swf` files that auto-submit forged requests to the vulnerable application when a user visits a malicious site.

---

## 💥 Impact: HIGH

- 🎯 Unauthorized actions (e.g., change email, reset password, transfer funds).
- 🧍‍♂️ Compromised user accounts or privilege escalation.
- 🛡️ Bypasses CSRF token protections via Flash sandbox bypass.
- 🔐 Potential **session hijack** or **data theft**.

---

## 🧪 Reproduction Steps

1. ✅ Ensure the victim is authenticated on the target web app (with an active session).
2. 🔎 Locate or upload a `.swf` file that makes POST/GET requests to sensitive endpoints:
   ```actionscript
   var request:URLRequest = new URLRequest("https://vulnerable.com/profile/update");
   request.method = URLRequestMethod.POST;
   request.data = new URLVariables("email=hacker@evil.com");

   var loader:URLLoader = new URLLoader();
   loader.load(request);
