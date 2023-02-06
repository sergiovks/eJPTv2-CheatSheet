# Host & Network Auditing

Transferir files to and from the objective:&#x20;

ftp (put & get, ? for help)

scp (ssh copy) [TUTORIAL SCP](https://geekytheory.com/copiar-archivos-a-traves-de-ssh-con-scp/)

curl (HTTP, HTTPS, SCP, SFTP, FTP) [TUTORIAL CURL](https://noviello.it/es/como-transferir-archivos-hacia-y-desde-un-servidor-con-el-comando-curl/)

python3 -m http.server port (host a server)

python -m SimpleHTTPServer port (host a server)

wget (for downloading files [TUTO WGET](https://www.hostinger.es/tutoriales/usar-comando-wget/))

certuril & powershell (for downloading files [Powershell + certutil](https://superuser.com/questions/25538/how-to-download-files-from-command-line-in-windows-like-wget-or-curl))

Enumerate info from the target OS (Post Exploitation):

Linux:

uname -a ([kernel, OS, hostname, processorr](https://computernewage.com/2013/04/21/como-obtener-informacion-del-sistema-desde-la-terminal-de-linux/#sistema))

cat /etc/issue (distribution + version)

```
cat /etc/*release (distribution + version, codename in parenthesis)
```

env (to see ENV variables)

lscpu (CPU info.)

free -h (RAM consumption)

df -h (list hard drives & mounted units)

df -ht ext4 (only lists units that are in format ext4)

lsblk | grep sd (list hard disks & filter by “sd” annotation)

dpkg -l (lists packages installed in debian & their version)

Meterpreter:

getuid (to see the user you are, like whoami)

sysinfo (hostname, O.S. & Service Pack, arch, system language & domain or hostname, distribution + release version, kernel & arch)

C:\Windows\system32\eula.txt (info OS, nº build, service pack)

show\_mount (show all active units)

Windows cmd:

hostname (PC name)

systeminfo (hostname, OS name, OS version, OS manufacturer, OS config, processor, Win directory, system directory, boot device, keyboard & system language, total physical memory (RAM), domain, logon server y hotfixes, network card, hyper-v)

wmic qfe get Caption,Description,HotFixID,InstalledOn (additional info about hotfixes. The security updates are important for PrivEsc)

Compile information from files on the target:

cat, bat, batcat, less, more, type. (KNOW WHAT YOU'RE LOOKING FOR)

Recolectar información de cuentas en el objetivo:

Meterpreter:

getuid (actual user or user ID & group ID)

getprivs (display the privileges of the actual user)

search logged\_on (all the info. about users logged in now & recently y SID)

Linux:

whoami (actual user)

groups (to see the groups of the system)

groups xuser (to see the groups of xuser)

cat /etc/passwd (to see the system accounts, users account have a shell at the end “/bin/sh ó /bin/bash”)

last (last users connected to the system rightfully)

lastlog (users that connected the system \[SSH or rightfully])

Windows cmd:

whoami (actual user)

whoami /priv (actual user privileges)

query user (logged in users)

net users (all the user accounts)

net user x (info about x user)

net localgroup (lists all the groups on the system)

net localgroup xgrupo (to see the users from x group)

Recolectar información de hash/password desde el objetivo:

YOU HAVE TO BE A PRIVILEGED USER:

Meterpreter:

hashdump (Windows: pgrep lsass -> migrate PID lsass -> hashdump)

kiwi -> help or ? -> creds\_all (dump all the credentials hashes) -> lsa\_dump\_sam (dump all the NTLM hashes of the users) -> lsa\_dump\_secrets (sometimes dump credentials in plain text) -> password\_change (to change the pass or the hash of a user)

Linux:

cat /etc/shadow (NEED PRIVS.)

$1 -> MD5

$2 -> Blowfish

$5 -> SHA-256

$6 -> SHA-512&#x20;

Metasploit: search hashdump (post/linux/gather/hashdump)

Crack SHA512-> john –format=sha512crypt archivo.txt –wordlist=/route/of/the/wordlist.txt

List hash formats in john: john -list=formats

hashcat -m 1800 -a 0 or 3 hash.txt /route/to/the/wordlist.txt

List hash formats and type of attacks in hashcat: hashcat -h

Hashcat: a 0 = dictionary attack; a 3 = bruteforce attack;

Windows cmd:

Mimikatz -> help or ? -> privilege::debug (if says 20 OK) -> lsadump::sam (we get the syskey;SAMkey;RID\[500=admin]) -> lsadump::secrets -> sekurlsa::logonpassword (to get passwords in plain text if they're used &/or available)

Crack NTLM -> john –format=NT hash.txt –wordlist=/route/to/wordlist.txt

hashcat -m 1000 -a 0 ó 3 hashNTLM.txt /route/to/wordlist.txt

In the dump: 1º LM & 2º NTLM (LM is not used anymore, separated by ":")

Enumerar información de la red desde archivos en el objetivo:

Meterpreter:

ifconfig (IP address + interfaces + MAC + IPv4 + Netmask)

netstat (list active TCP/UDP services & their ports + other PCs in the network)

route (routing table, gateway is important)

arp (hosts connected to the network)

Linux:

ifconfig (network card, MAC + IP + segment/netmask)

ip a s (MAC, IP + segment)

cat /etc/networks (interfaces & their config.)

cat /etc/hosts (hosts + local domains)

cat /etc/resolv.conf (DNS server by default)

arp -a (hosts connected to the network)

Windows cmd:

ipconfig (network adapters, DNS suffix, IPv4 & 6 addresses, netmask y gateway)

ipconfig /all (hostname, IP routing enabled, MAC Address, DHCP enabled \[dynamic IPs], Lease expires, DHCPserver-gateway, DNS Server)

route print (routing table)

arp -a (all the hosts on the network, displays IP address & MAC)

netstat -ano (Protocols & ports of the services \[the 0.0.0.0 are from the host])

netsh firewall show state (firewall state)

netsh advfirewall firewall dump (dumpe config file of the firewall)

netsh advfirewall show allprofiles check if the firewall is active or not)
