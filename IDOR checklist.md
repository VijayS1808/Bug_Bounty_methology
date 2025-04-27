### Find and Replace IDs in URLs, headers, and body:

Example: /users/01 → /users/02
Try Parameter Pollution:

Example: users=01 → users=01&users=02
Special Characters:

Example: /users/01* or /users/* → Disclosure of every single user
Try Older Versions of API Endpoints:

Example: /api/v3/users/01 → /api/v1/users/02
Add Extension:

Example: /users/01 → /users/02.json
Change Request Methods:

Example: POST /users/01 → GET, PUT, PATCH, DELETE
Check if Referer or Some Other Headers are Used to Validate IDs:

Example:
GET /users/02 → 403 Forbidden
Referer: example.com/users/01
GET /users/02 → 200 OK
Referer: example.com/users/02
Encrypted IDs:

### If the application uses encrypted IDs, try to decrypt using tools like hashes.com.
Swap GUID with Numeric ID or Email:

Example:
/users/1b04c196-89f4-426a-b18b-ed85924ce283 → /users/02 or /users@qb.com
Try GUIDs Such as:

00000000-0000-0000-0000-000000000000
11111111-1111-1111-1111-111111111111
GUID Enumeration:

Try to disclose GUIDs using:
Google Dorks
GitHub
Wayback Machine
Burp History
If None of the GUID Enumeration Methods Work, Then Try:

Sign-Up
Reset Password
Other Endpoints
These endpoints mostly disclose user GUIDs.
403/401 Bypass:

If the server responds with a 403/401, use Burp Intruder and send 50-100 requests with different IDs.
Example: /users/01 to /users/100
If the Server Responds with 403/401:

Double-check the function within the application.
Sometimes 403/401 is thrown, but the action is still performed.
Blind IDORs:

Sometimes information is not directly disclosed.
Look for endpoints and features that may disclose information like:
Export files
Emails
Message alerts
Chain IDOR with XSS for Account Takeovers.






