
DNS Zone Transfer

traceroute (follow the path from the source to the destination and backwards)
  
ping (test if a host is active, it may have the ICMP response shutted down)

arp-scan -I eth0 -g IP/segment (scan the hosts on the network giving it CIDR notation and don't show the duplicate packets)

fping -I eth0 -g IP/segment -a 2>/dev/null (ping sweep to the hosts on the network, -g enerating a target list & only output active hosts)
 
  

-  <font color="red">SMB enum:</font>

  

1.  NMAP SCRIPTS:

  

–script smb-enum-users (PC users)

  

–script smb-protocols (SMB version)

  

–script smb-security-mode (user & privileges)

  

–script smb-enum-sessions (name of a user with an open session)

  

–script smb-enum-shares (list all the shares of SMB)


smb-os-discovery (OS & SMB version, gives us the username [computer name] and the name of the PC NetBIOS)  


–script smb-enum-sessions –script-args smbusername=administrator,smbpassword=passwordadmin IP (to check if a session works) 


–script smb-enum-shares –script-args smbusername=administrator,smbpassword=passwordadmin IP (to list permissions and shared folders)


–script smb-enum-users –script-args smbusername=administrator,smbpassword=passwordadmin IP (PC users + flags)


smb-server-stats –script-args smbusername=administrator,smbpassword=passwordadmin IP (to see the data received & transmitted, how many logins failed, permission errors, system errors, printer jobs, open files)

  
smb-enum-domains –script-args smbusername=administrator,smbpassword=passwordadmin IP (to see users, info about passwords, complexity requirements, and all of that is applied to the groups)
  

smb-enum-groups –script-args smbusername=administrator,smbpassword=passwordadmin IP (divide the users in different groups)
  

smb-enum-services –script-args smbusername=administrator,smbpassword=passwordadmin IP (enumerate services used)
  

smb-shares,smb-ls –script-args smbusername=administrator,smbpassword=passwordadmin IP (enumerate the shared contents and what is in there [ls])
  

2.  SMB MAP


smbmap -u guest -p “” -d . -H IPobj (where u is the SMB user, p is password, d is the directory you want to list, & H is the objective host)
  

smbmap -u administrator -p passadmin -d . -H IPobj (to see the permissions of the administrator)
  

smbmap -H IPobj -u administrator -p passadmin -x ‘ipconfig’ (with this command we can do Remote Code Execution)
  

smbmap -H IPobj -u administrator -p ‘passadmin’ -L (this command lists the shares)


smbmap -H IPobj -u administrator -p ‘passadmin’ -r ‘C$’ (list the contents of a directory in specific, in this case "C")

  
smbmap -H IPobj -u administrator -p ‘passadmin’ –upload ‘/ruta/archivolocal’ ‘C$\backdoor’ (this command is for uploading a file [for example a backdoor])

  
smbmap -H IPobj -u administrator -p ‘passadmin’ –download ‘C$\flag.txt’ (to download files to our local machine)


3.  nmblookup
  

nmblookup -h
  

nmblookup -A IPobj (this shows different groups and what connections do [in <nº>], a 20 that we can connect to that resource)


4.  Metasploit enum


SMB 1: use auxiliary/scanner/smb/smb_version (Windows & SMB version)

SMB2: use auxiliary/scanner/smb/smb2 (to see if it support SMBv2)

SMB3: use auxiliary/scanner/smb/smb_enumshares (enum shares & read/write permissions, types of shares, directories, files, time stamps, etc…)


5.  enum4linux


enum4linux -h (help panel, use the parameter that scans everything or simply do enum4linux IP)



6.  SMB CONNECTION
  

smbclient -h
  

smbclient -L IPobj -N (using a null session, enum shares, if there's a IPC$ we could connect to that share)


smbclient //IPobj/Public -N (connect to a public share, normally have write permissions)


smbclient //IP/share -U user (to connect to a share of SMB as x user [try the username "Anonymous" without password]) 

-  SSH

a ID RSA key (ID_RSA) needs the permission 600 (chmod +600 id_rsa)

Now we can attempt to ssh into the main server! Before that, check the id_rsa.pub file to find the username at the end of the file.

ssh user@$ip

Quick troubleshoot:

  Load key “/home/kali/.ssh/id_rsa”: bad permissions: revisit chmod step

   load pubkey “/home/kali/.ssh/id_rsa”: invalid format: download/copy the public key into .ssh, or generate it with ssh-keygen -y -f id_rsa > id_rsa.pub


user@IP -i id_rsa
  

ssh-keygen -y -f id_rsa > id_rsa.pub


-  RPC CONNECTION

  
rpcclient -h (help panel)


rpcclient -U “” -N IPobj (once the session is open type the ? command to see help) 


dentro de rpcclient: srvinfo (displays the OS info); enumdomusers (shows the PC users); lookupnames admin (shows the admin SID) enumdomgroups (show the PC groups)


-  SSH:
  

nc IPobj sshport (this displays the SSH & OS version)
  

scripts nmap SSH:


ssh2-enum-algos (this SSH script shows the algorithm used to create SSH keys)


ssh-hostkey –script-args ssh_hostkey=full (this gives us the hostkey SSH password in RSA)


ssh-auth-methods –script-args=”ssh.user=xuser” (to see if there are weak password for x user [to see the auth method: password or id_rsa])


-  HTTP:


whatweb IPobj to see the technologies used for a website)

  
http IPobj (makes a request to the webservers and show the headers, here you can enumerate the execution of a vulnerable file)


dirb http://IPobj (enum directories and subdirectories)


browsh –startup-url http://IPobj/Default.aspx (website enumer with the URL that we give & simulate the webpage) Control + W to quit.


lynx http://IPobj (to see the source code of the website)
  

curl IPobj | more (Doctype html; title Apache2 Ubuntu) [IS THE SAME AS]] wget “http://IPobj/index” -> cat index | more (to see the source code)
  

robots.txt (to see disallowed entries and see if you can impersonate a User-Agent)
  

curl http://IPobj/cgi-bin | more (error 403 forbidden = useful for exploitation)


NMAP SCRIPTS:
  

http-enum (show common but interesting directories)
  

http-headers (show headers of a request to a website & if it's vulnerable to XSS [XSS protection 0]; X-powered-by: asp.net)


http-methods –script-args http.methods.url-path=/directory/ (shows the types of request that a directory admits)


http-webdav-scan –script-args http.methods.url-path=/webdav/ (helpful to identify the webdav installs)


-  SQL (puerto 1433/3306 TCP)

MySQL:


Connection to MySQL:


mysql -h IPobj -u root (h is the host & u the user we authenticate with)

if works:

	show databases; -> use xdatabase -> select count(*) from xtable; (show the options for xtables) -> select * from xitem (to see everything of xitem of a xtbale) -> help to see options

  
select load_file(“/etc/shadow”) to see if we gain access to the shadow file of Linux.

  
Metasploit:

  
search mysql_writable_dirs (to see direcories with writing permissions)


search mysql_hashdump (this shows the user hashes to crack them later)
  

NMAP SCRIPTS:


–script=mysql-empty-password (to see if we can connect without password)


–script=mysql-info (displays the version & in some capabilities we find InteractiveClient which gives us access to the system via MySQL)


–script=mysql-users –script-args=”mysqluser=’root’,mysqlpass=’’” (enumerate the PC users)


–script=mysql-databases –script-args=”mysqluser=’root’,mysqlpass=’’” (enumerate the databases)


–script=mysql-variables –script-args=”mysqluser=’root’,mysqlpass=’’” (displays the variables of MySQL & in datadir: shows where are them stored in the PC)
  

–script=mysql-audit –script-args=”mysql-audit.username=’root’,mysql-audit.password=’’,mysql-audit.filename=/usr/share/nmap/nselib/data/mysql-cis.audit” (this command shows the properties of MySQL [configs], if = PASS don't grant privileges to users that aren't the admin)

  
–script=mysql-dump-hashes –script-args=”mysqluser=’root’,mysqlpass=’’” (show the hashes of the victim PC users)


	–script=mysql-query –script-args=”query=’select count(*) from books.authors;’,username=’root’,password=’’” (query sintax)


MSSQL (microsoft SQL):

nmap scripts:

ms-sql-info (service info)
  
ms-sql-ntlm-info –script-args mssql.instance-port=1433 (info of the auth. protocol)

ms-sq-brute –script-args userdb=/common_users.txt,passdb=/100-common-passwords.txt (bruteforce users & passwords)

ms-sql-empty-password (info about users who haven't got password)

ms-sql-query –script-args mssql.username=admin,mssql.password=pass,ms-sql-query.query=”SELECT * FROM master..syslogins” -oN output.txt (make querys with credentials)
 
ms-sql-dump-hashes –script-args mssql.username=admin,mssql.password=pass (to display the PC accounts & hashes)

ms-sql-xp-cmdshell –script-args mssql.username=admin,mssql.password=pass,ms-sql-xp-cmdshell.cmd=’ipconfig’ (tries to make RCE)
  
ms-sql-xp-cmdshell –script-args mssql.username=admin,mssql.password=pass,ms-sql-xp-cmdshell.cmd=”type C:\flag.txt” (RCE but for reading files)

  
Metasploit:

  
search mssql_login -> configurar opciones -> set verbose false -> run (displays users, passwords -> bruteforce)


search mssql_enum (displays config. info. of mssql)


search mysql_enum_sql_logins (saca los logins que hay para mssql)


search mssql_exec (remote command execution)


search mssql_ednum_domain_accounts (enumerate domain acccounts)
