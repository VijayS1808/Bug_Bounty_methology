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

### Broken authentication and session management flaw
