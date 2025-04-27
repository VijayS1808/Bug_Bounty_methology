❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️
📖 IDOR TESTING TECHNIQUES — CLEAN GUIDE
❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️❤️

1️⃣ Find and Replace IDs in URLs, Headers, and Body

📝 Example:
/users/01 → /users/02

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

2️⃣ Try Parameter Pollution

📝 Example:
users=01 → users=01&users=02

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

3️⃣ Test with Special Characters

📝 Example:
/users/01* or /users/*
➡️ May disclose every single user.

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

4️⃣ Try Older Versions of API Endpoints

📝 Example:
/api/v3/users/01 → /api/v1/users/02

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

5️⃣ Add Extensions to Endpoints

📝 Example:
/users/01 → /users/02.json

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

6️⃣ Change HTTP Request Methods

📝 Example:
POST /users/01 → GET, PUT, PATCH, DELETE

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

7️⃣ Check if Referer or Other Headers Validate IDs

📝 Example:

bash
Copy
Edit
GET /users/02 → 403 Forbidden
Referer: example.com/users/01

GET /users/02 → 200 OK
Referer: example.com/users/02
▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

8️⃣ Encrypted IDs

If the app uses encrypted IDs — try to decrypt them using tools like:
🔗 hashes.com

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

9️⃣ Swap GUID with Numeric ID or Email

📝 Example:

/users/1b04c196-89f4-426a-b18b-ed85924ce283 → /users/02

/users/1b04c196-89f4-426a-b18b-ed85924ce283 → /users@qb.com

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

🔟 Try Common GUIDs

00000000-0000-0000-0000-000000000000

11111111-1111-1111-1111-111111111111

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

1️⃣1️⃣ GUID Enumeration Techniques

Search for exposed GUIDs using:

Google Dorks

GitHub Repositories

Wayback Machine

Burp Suite History

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

1️⃣2️⃣ If Enumeration Fails — Try These Endpoints

Often these endpoints leak user IDs or GUIDs:

Sign-Up

Reset Password

Profile or Account endpoints

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

1️⃣3️⃣ 403/401 Bypass Techniques

If you get a 403 or 401:

Use Burp Intruder

Send 50–100 requests changing IDs

📝 Example:
/users/01 → /users/100

📌 Important:
Even if 403/401 appears, sometimes the action still happens in the background.
✅ Always verify app behavior!

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

1️⃣4️⃣ Blind IDOR Discovery

When no direct response is shown — look for indirect leaks like:

Exported files

Email notifications

Message alerts

Logs or internal messages

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬

1️⃣5️⃣ Chain IDOR with XSS

Combine IDOR findings with stored or reflected XSS payloads to attempt:

Account Takeovers

Privilege Escalation

Admin Session Theft

▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬
