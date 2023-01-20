 
<font color="yellow">Locate endpoints on a network:</font>


<font color="yellow">Identify vulnerabilities in services:</font>

Scan services & versions with nmap.

searchsploit (to search for exploits & vulnerabilities)

[NATIONAL VULNERABILITIES DATABASE](https://nvd.nist.gov/)

nmap scripts: locate /usr/share/nmap/scripts | grep service

msf: db_autopwn making db_nmap before or analyze command and then vuln



<font color="yellow">Identify the OS of an objective:</font>

nmap -O

rpcclient -U “” -N IPobj -> srvinfo

smb-os-discovery (script nmap)

enum4linux -O IPobj

enum4linux -S IPobj

nc IPobj 22 (the SSH service tells you the O.S.)

  

<font color="yellow">Identify open ports & services from an objective</font>

nmap -sS -p- -n -Pn --open IPobj

nmap -sV -p 21,22,etc -n -Pn --open IPobj

metasploit (search portscan or db_nmap)

  

<font color="yellow">Extract information from Open Source Platforms:</font>

In the webpage.

robots.txt (hidden directories of the web server)

Source code (it may be hidden things)

Sitemap.xml/sitemaps.xml (facilitates the index of the web for the browser)

whois xwebpage (to extract information of the website: when it was registered, who owns it, what hosting company were registered through, CIDR =network range; Orgname= name of the organization)

Netcraft.com > services > internet data mining > internet research tools (combine whois, if there are SSL or TLS, the web technologies of the website, the name servers)

dnsrecon -d xpage.com (identify the records of a particular domain; NS = name server addresses; MX = mail service address (the “postman”); A=IPv4 address; AAAA=IPv6 address; TXT=txtrecord)

dnsdumpster.com

sublist3r -d xpage.com (search for subdomains using OSINT)

![](https://lh3.googleusercontent.com/hNZrcUklkDhjRrY2fQnhwa88Ds259CnvnEMlS3e1J261n04P5Eykh_YVAWCyDiMUikLDdtuGBGJa3M2gS1AfWa_sO-8Xaa83wmhzWeYXvA8JVuRyTOZxxlJ2WNh6syGweUdDDHzLrIrzm0vGNkDIQiV6YPdOyXCC9lxrm_wtu7DrTdhAUDSulFh66LF9AA)

<font color="yellow">Compile technical information from open sources:</font>

In the webpage may be information.

whatweb -a=1 xpage.com (enumerate technologies doing a stealth scan)

wafw00f xpage.com (can add the -a parameter)

  

<font color="yellow">Recopilar correos electrónicos de fuentes públicas:</font>

In the webpage may be information.

theHarvester -d xpage.com -b google,linkedin,yahoo,dnsdumpster,duckduckgo,crtsh (search for emails doing OSINT, found mails can be used to search on leaked passwords databases like the below, because sometimes they use to reutilice passwords).

[HaveIbeenPwned](https://haveibeenpwned.com/)

[BreachDirectory](https://breachdirectory.org/) (the best)

  

<font color="yellow">Evaluate information & criticality or impact of vulnerabilities:</font>

[NATIONAL VULNERABILITIES DATABASE](https://nvd.nist.gov/)

[MITRE SEARCH CVE LIST](https://cve.mitre.org/cve/search_cve_list.html)

Nessus or OpenVAS

exploit-db or searchsploit

Search in google “service version CVE”

SCAP scan & STIGVIEWER (scan the PC and evaluate the vulnerabilities that it have).

  
