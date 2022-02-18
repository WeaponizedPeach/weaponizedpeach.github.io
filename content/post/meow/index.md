---
title: "HackTheBox: Meow"
description:
date: 2022-02-18T20:38:56+02:00
image: cover.png
math: 
license: 
hidden: false
comments: false
draft: false
categories:
    - HTB
    - Writeup
    - Very Easy
    - Starting Point
    - Linux
    - Network
    - Account Misconfiguration

---
## Intro
This is a Very Easy machine from the Starting Point section on HackTheBox. It is meant to be an introductory box, to fully clear it, in addition to getting flags, we will also need to answer some questions.

## Tasks

### Task 1: What does the acronym `VM` stand for?
```
Virtual Machine
```

### Task 2: What tool do we use to interact with the operating system in order to start our VPN connection?
```
Terminal
```

### Task 3: What service do we use to form our VPN connection?
```
OpenVPN
```

### Task 4: What is the abreviated name for a tunnel interface in the output of your VPN boot-up sequence output?
For this, we should start our VPN connection: `sudo openvpn our_openvpn_file_here.ovpn`.

We get a lot of output, but the relevant part for us is this part:
```bash
Fri Feb 18 21:38:17 2022 TUN/TAP device tun0 opened
Fri Feb 18 21:38:17 2022 TUN/TAP TX queue length set to 100
Fri Feb 18 21:38:17 2022 /sbin/ip link set dev tun0 up mtu 1500
Fri Feb 18 21:38:17 2022 /sbin/ip addr add dev tun0 10.10.15.16/23 broadcast 10.10.15.255
Fri Feb 18 21:38:17 2022 /sbin/ip -6 addr add dead:beef:2::110e/64 dev tun0
Fri Feb 18 21:38:17 2022 /sbin/ip route add 10.10.10.0/23 via 10.10.14.1
Fri Feb 18 21:38:17 2022 /sbin/ip route add 10.129.0.0/16 via 10.10.14.1
Fri Feb 18 21:38:17 2022 add_route_ipv6(dead:beef::/64 -> dead:beef:2::1 metric -1) dev tun0
Fri Feb 18 21:38:17 2022 /sbin/ip -6 route add dead:beef::/64 dev tun0 
```
Here we can identify the tunnel interface/device as tun0. However, we need the 'abreviated name for a tunnel interface', not our specific one.

Thus, the answer is simply:
```
tun
```

### Task 5: What tool do we use to test our connection to the target?
```
ping
```

We might aswell just go and ping the box itself:
```bash
weaponizedpeach@Akatosh:~$ ping 10.129.255.195
PING 10.129.255.195 (10.129.255.195) 56(84) bytes of data.
64 bytes from 10.129.255.195: icmp_seq=18 ttl=63 time=48.8 ms
64 bytes from 10.129.255.195: icmp_seq=19 ttl=63 time=48.6 ms
64 bytes from 10.129.255.195: icmp_seq=20 ttl=63 time=48.6 ms
64 bytes from 10.129.255.195: icmp_seq=21 ttl=63 time=49.1 ms
64 bytes from 10.129.255.195: icmp_seq=22 ttl=63 time=48.6 ms
64 bytes from 10.129.255.195: icmp_seq=23 ttl=63 time=48.8 ms
^C
--- 10.129.255.195 ping statistics ---
23 packets transmitted, 6 received, 73.913% packet loss, time 22720ms
rtt min/avg/max/mdev = 48.558/48.745/49.101/0.194 ms
weaponizedpeach@Akatosh:~$
```

### Task 6: What is the name of the tool we use to scan the target's ports?
```
nmap
```

Let's go and run a simple nmap scan:

```bash
weaponizedpeach@Akatosh:~$ nmap 10.129.255.195
Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-18 21:47 EET
Nmap scan report for 10.129.255.195
Host is up (0.048s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
23/tcp open  telnet

Nmap done: 1 IP address (1 host up) scanned in 1.91 seconds
weaponizedpeach@Akatosh:~$
```

### Task 7: What service do we identify on port 23/tcp during our scans? 
Nmap already identified the service for us:
```
telnet
```

### Task 8: What username ultimately works with the remote management login prompt for the target?
For this we will need to establish a telnet connection to the machine: `telnet MACHINE_IP`

After a short period of time we are welcomed by a login screen:

```bash
Trying 10.129.255.195...
Connected to 10.129.255.195.
Escape character is '^]'.

  █  █         ▐▌     ▄█▄ █          ▄▄▄▄
  █▄▄█ ▀▀█ █▀▀ ▐▌▄▀    █  █▀█ █▀█    █▌▄█ ▄▀▀▄ ▀▄▀
  █  █ █▄█ █▄▄ ▐█▀▄    █  █ █ █▄▄    █▌▄█ ▀▄▄▀ █▀█


Meow login:
```

Since this is a introductory box, let's just try `root` as the login.

```
Meow login: root
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)
                                                                  
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
                                                           
System information as of Fri 18 Feb 2022 08:04:01 PM UTC
...
...
...
Last login: Fri Feb 18 20:01:31 UTC 2022 on pts/0
root@Meow:~#
```

Success!

Thus, the answer to the question is:
```
root
```

### Submit root flag
Since we have root access, this should be easy.
```bash
root@Meow:~# ls
flag.txt  snap
root@Meow:~# cat flag.txt
b40abdfe23665f766f9c61ecba8a4c19
root@Meow:~#
```

And there's our flag. The question wants the answer in the form `HTB{_flag_}`

Let's try: `HTB{b40abdfe23665f766f9c61ecba8a4c19}`

![Meow: Pwned](pwned.png)

## Outro

Although I am used to harder boxes, I was still interested what the Starting Point machines had to offer. I am glad that newcomers to HTB (and likely CTFs in general) have a place to ease into machines like this, rather than just diving into the deep end. I plan to make a write-up for each of the Starting Point machines.