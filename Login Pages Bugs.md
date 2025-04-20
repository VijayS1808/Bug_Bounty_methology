🔐 Authentication Bugs:

1️⃣ SQL Injection in Login:

Payloads: ```' OR '1'='1 --, ' UNION SELECT null, version() --```

✅ Steps:

Open login page.

In username field, input: ' OR '1'='1 --

In password field, input anything (e.g., test).

Click Login.

✅ If successfully logged in → SQL Injection exists.

2️⃣ Login Without Email Verification
✅ Steps:

Register a new account with a fake/unverified email.

Skip clicking the verification link in the email.

Attempt to login directly with your credentials.

✅ If login works without email verification → Business logic flaw.

3️⃣ Username Enumeration
✅ Steps:

Try logging in with a known valid username and incorrect password.

Example: Username: admin, Password: wrongpass

Observe the error message (e.g., "Invalid password").

Try logging in with a non-existent username and any password.

Example: Username: nonexistent, Password: wrongpass

Observe the error message (e.g., "User not found").

✅ If the system gives different error messages for valid vs. invalid usernames → Username enumeration possible.

4️⃣ Weak Password Acceptance
✅ Steps:

Try registering with weak passwords like 123, password, admin, etc.

If weak passwords are accepted without error or restriction, the system is vulnerable to poor password policies.

✅ If weak passwords are accepted → Password policy flaw.

🔁 Authorization Bugs
5️⃣ Privilege Escalation
✅ Steps:

Login as a normal user.

Intercept the request or inspect cookies.

Modify role=user → role=admin.

Submit the modified request.

✅ If you gain admin access or privileges → Privilege escalation flaw.

6️⃣ Insecure Direct Object Reference (IDOR)
✅ Steps:

Login as a normal user and visit a page that displays user-specific data (e.g., /dashboard?id=123).

Modify the id parameter in the URL (e.g., /dashboard?id=124).

Observe if you can access another user’s data.

✅ If data from another user appears → IDOR vulnerability.

7️⃣ Access Control Failure
✅ Steps:

Login as a normal user.

Attempt to access an admin page by modifying the URL or using a known path (e.g., /admin).

✅ If the admin panel loads → Access control is broken.

💉 Injection Bugs
8️⃣ XSS (Cross-Site Scripting)
Payloads: <script>alert(1)</script>, "><img src=x onerror=alert(1)> ✅ Steps:

Input the payload in username or password field.

Submit the form.

✅ If the payload executes (i.e., alert box appears) → Reflected XSS exists.

9️⃣ Command Injection
Payloads: ; whoami, && ls, | id ✅ Steps:

Input the payload in username or password field.

Submit the form.

✅ If the OS command is executed (e.g., user or file listing appears) → Command injection exists.

🔟 SSTI (Server-Side Template Injection)
Payloads: {{7*7}}, ${7*7}, <%= 7 * 7 %> ✅ Steps:

Input {{7*7}} or ${7*7} in the username field.

Submit the login form.

✅ If the system evaluates the expression and returns 49 or a calculated value → SSTI vulnerability exists.

1️⃣1️⃣ XXE (XML External Entity Injection)
✅ Steps:

Intercept the login request (if it uses XML for payloads).

Inject the following into the XML request body:

xml
Copy
Edit
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<login><user>&xxe;</user></login>
Submit the form.

✅ If you receive the content of /etc/passwd or any file → XXE vulnerability.

1️⃣2️⃣ CRLF Injection
Payloads: %0d%0aSet-Cookie: evil=true ✅ Steps:

Input %0d%0aSet-Cookie: evil=true in username field.

Submit the form.

✅ If a new cookie appears in the response → CRLF Injection exists.

1️⃣3️⃣ Host Header Injection
Payloads: Modify Host: yoursite.com → Host: attacker.com ✅ Steps:

Intercept the login request and modify the Host header.

Replace Host: yoursite.com with Host: attacker.com.

Submit the request.

✅ If password reset or email links redirect to attacker-controlled domains → Host Header Injection exists.

🍪 Session Management Bugs
1️⃣4️⃣ Session Fixation
✅ Steps:

Open the login page in your browser.

Copy the session ID cookie.

Log in with valid credentials.

Check if the session ID remains the same even after login.

✅ If session ID does not change → Session fixation exists.

1️⃣5️⃣ Session Not Expired on Logout
✅ Steps:

Login to the application.

Logout from the app.

Manually or via automation, send a request with the previous session's cookie.

✅ If the session is still valid → Session not expired after logout.

1️⃣6️⃣ Insecure Cookie Flags
✅ Steps:

Inspect cookies for the session.

Look for the flags: Secure, HttpOnly, SameSite.

✅ If these flags are missing → Insecure cookie configuration.

🔄 Rate Limiting & Brute Force
1️⃣7️⃣ No Rate Limiting
✅ Steps:

Try logging in with a wrong password more than 5-10 times (based on expected rate limit).

✅ If no lockout, CAPTCHA, or rate-limiting mechanism occurs → Brute-force attack possible.

1️⃣8️⃣ No CAPTCHA
✅ Steps:

Try logging in with invalid credentials 10+ times.

✅ If CAPTCHA or rate limiting is not triggered → Brute force possible.

1️⃣9️⃣ Timing Attack (User Enumeration)
✅ Steps:

Measure the time it takes to receive a login response for both valid and invalid users.

Look for significant differences in response times for valid vs invalid usernames.

✅ If there's a noticeable time difference → Timing attack exists.

🧠 Business Logic Bugs
2️⃣0️⃣ Login Without Verification
✅ Steps:

Register with a fake/unverified email.

Skip clicking on the verification link.

Try logging in.

✅ If login works → Login logic flaw (verification is not enforced).

2️⃣1️⃣ Reset Password Without Email
✅ Steps:

Initiate a password reset flow.

Modify the email parameter in the request to an email you control.

✅ If the reset link is sent to a different email → Reset logic flaw.

2️⃣2️⃣ Privilege Escalation via Role Change
✅ Steps:

Intercept the role information in the login request or modify cookies.

Change role=user → role=admin.

✅ If admin rights are granted → Role manipulation exists.

2️⃣3️⃣ Multiple Coupon Abuse
✅ Steps:

Apply a coupon or discount during checkout.

Reapply the same coupon or discount again (e.g., through a modified request or manually).

✅ If the coupon works more than once → Business logic flaw.

2️⃣4️⃣ Change Price via Client-Side Manipulation
✅ Steps:

Add an item to the cart.

Modify the item price via browser developer tools (inspect element).

Proceed to checkout and submit payment.

✅ If the price manipulation is successful → Business logic flaw in pricing.


2️⃣5️⃣ No Password Complexity Enforcement
✅ Steps:

Try registering with simple passwords like 123, password, abc123, etc.

Submit the registration form.

✅ If the system allows registration with weak passwords → Weak password policy.

2️⃣6️⃣ Unencrypted Password Storage
✅ Steps:

Access the database or intercept the traffic where login credentials are being transmitted (e.g., during the login process).

Check if passwords are stored in plain text or weakly hashed (e.g., MD5).

✅ If the password is found in plain text or weak hashing → Password storage vulnerability.

2️⃣7️⃣ Missing CSRF Protection
✅ Steps:

Log in as a user with session cookies.

Open a different tab or use a separate browser to access the login page.

Create a malicious form that submits a request (e.g., changing account details or sending a message).

✅ If the form can be submitted without a CSRF token or without triggering an error → CSRF vulnerability.

2️⃣8️⃣ Session Hijacking via Cookie Stealing
✅ Steps:

Log in and capture the session cookie from your browser's developer tools.

Use the session cookie in another browser or incognito window.

✅ If you can access the user’s session on a different browser or window → Session hijacking vulnerability.

2️⃣9️⃣ Unencrypted Communication (No HTTPS)
✅ Steps:

Attempt to log in on a website using HTTP (instead of HTTPS).

Observe if the credentials (username/password) are sent in plaintext in the URL or request body.

✅ If credentials are sent over HTTP instead of HTTPS → Insecure communication.

3️⃣0️⃣ Sensitive Data Exposure in URL
✅ Steps:

Log in to the application with valid credentials.

After logging in, check the URL for any sensitive data (e.g., username, password, tokens).

✅ If sensitive data like password=12345 or token=abc123 appears in the URL → Sensitive data exposure vulnerability.

3️⃣1️⃣ Email Header Injection
Payloads: From: attacker@evil.com\nBcc: victim@target.com ✅ Steps:

Submit a login form with a crafted email address (e.g., attacker@evil.com\nBcc: victim@target.com).

Observe if the email headers are reflected.

✅ If the email headers are manipulated or allow BCC injection → Email header injection vulnerability.

3️⃣2️⃣ Uncontrolled File Upload
✅ Steps:

Go to the file upload page.

Upload a file with an executable extension like .php, .jsp, .exe.

✅ If the file is uploaded successfully and can be executed → Uncontrolled file upload vulnerability.

3️⃣3️⃣ Session Timeout Not Triggered
✅ Steps:

Log in to the system and leave the session idle for a prolonged period (e.g., 30 minutes).

Attempt to use the session after a long idle time.

✅ If the session remains active and does not prompt for re-authentication → Session timeout flaw.

3️⃣4️⃣ Login Page Redirect After Login
✅ Steps:

Log in with valid credentials.

Observe the page you are redirected to.

✅ If you are redirected to a page that could potentially lead to an open redirect vulnerability (e.g., via URL manipulation) → Login page redirect flaw.

3️⃣5️⃣ Clickjacking Protection Missing
✅ Steps:

Visit the login page in a regular browser.

Try embedding the login page inside an iframe hosted on a different domain.

✅ If you can successfully load the login page inside the iframe without restrictions (like X-Frame-Options), it is vulnerable to clickjacking.
