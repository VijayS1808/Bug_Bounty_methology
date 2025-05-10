### Broken Authentication and Session Management Flaw After Change Password and Logout:

```
1.Open your account (signin) on two different browser (i used Firefox and Incognito)
2.Changes your account password on one of browser then logout account
3.Refresh your account page in another browser
4.And you account will stay alive

Normally it will logout automatically too due to your account password has changed

```

### Broken authentication and session management flaw

```
1. Go to coursera.org.

2. Log in to your account.

3. Get the cookies using Burp Suite or EditThisCookie.

4. Log out of your account.

5. Clear all cookies related to coursera.org.

6. Save the copied cookies in a text file.

7. Now, inject/import the old cookies into coursera.org using EditThisCookie.

As you can see, you’ll be logged back into your coursera.org account using the old session cookies.

```

### Broken authentication and session management flaw:

```

1. Request a password reset using https://en.instagram-brand.com/register/signin.

2. Go to your email inbox.

3. Right-click on the password reset hyperlink and copy its link address. Paste it into a text editor like Notepad. (Note: The link initially uses the HTTP scheme here.)

4. Attach a local proxy tool (like Burp Suite) to your browser.

5. Request the copied link in your browser with interception enabled.

The first intercepted request looks like this:

```
```
GET /track/click/30956340/instagram-brand.com?p=<token> HTTP/1.1
Host: mandrillapp.com
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```
```
```
The server responds with:

```
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.6.3
Date: Thu, 16 Feb 2017 02:58:53 GMT
Content-Type: text/html; charset=utf-8
Set-Cookie: PHPSESSID=dc43ed4a78f737e1cff9ecf05ede3680; expires=Thu, 16-Feb-2017 12:58:01 GMT; path=/; secure; HttpOnly
Location: https://instagram-brand.com/register/reset/<new token>?email=<your email>
```
The next request made by the browser is:

```
GET /register/reset/<token>?email=<email> HTTP/1.1
Host: instagram-brand.com
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Cookie: pll_language=en; _ga=GA1.2.1670792457.1487004320; _gat=1
Connection: keep-alive
Upgrade-Insecure-Requests: 1

```
The server responds with:

```
HTTP/1.1 302 Found
Server: nginx
Date: Thu, 16 Feb 2017 03:00:30 GMT
Location: https://en.instagram-brand.com/register/reset/<token>?email=<email>
```
The final request is:

```
GET /register/reset/<token>?email=<email> HTTP/1.1
Host: en.instagram-brand.com
```
And its response is:
```
HTTP/1.1 404 Not Found
Server: nginx
Date: Thu, 16 Feb 2017 03:01:58 GMT
```
Key Insight:

In steps 6 and 7, you can observe that the password reset token is transmitted over plain HTTP — making it vulnerable to interception. By the time you reach steps 8 and onwards, the token is transferred via HTTPS, which is secure.

An attacker monitoring the HTTP request in steps 6–7 can capture the token before it transitions to HTTPS. They can then craft an automated exploit that requests the reset link immediately, changing the victim's password. When the victim later clicks the reset link from their email (now in the browser), they’ll find it expired — but in reality, the attacker has already used it.
