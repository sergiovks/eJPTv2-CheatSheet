# EXTRA CONTENT

extract .tar.gz file -> tar xzf archive.tar.gz

* WEB APPS VULNERABILITY SCAN:

With wmap:

In meterpreter:

load wmap -> wmap\_TAB (to see commands)

wmap\_sites -h  (to specify a webpage to scan)

wmap\_sites -a IPobj (add that page/IP to wmap)

wmap\_targets -h (if we have more targets)

wmap\_targets -t http://IPobj/youcanspecifyadirectory (to input targets)

wmap\_run -h (run auxiliar modules to detect vulns)

wmap\_run -t (displays the auxiliar modules that we can use and try some basics like http-version, etc)

With NIKTO:

[TUTORIAL NIKTO WEB APP VULN SCAN](https://ciberseguridad.com/herramientas/software/nikto/#10\_comandos\_de\_Nikto\_para\_realizar\_un\_escaneo\_de\_vulnerabilidades)

With WPscan (wordpress scan):

[WP SCAN USER DOCUMENTATION](https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation)

* CROSS COMPILING EXPLOITS:

[pre compiled to download and use directly](http://github.com/offensive-security/exploitdb-bin-sploits)

or:

Select the exploits to compile or cross compile:

The C language exploits should have information for how to compile with con mingwif they are well configured, if you don't find the information use the default mode for compiling.

Windows:

x64:&#x20;

i686-w64-mingw32-gcc exploit.c -o exploit (export to portable executable)

if a error is shown, after -gcc there are more -args, tab too see them.

x32:&#x20;

i686-w64-mingw32-gcc exploit.c -o exploit -lws2\_32

Linux:

use gcc directly.

* REVERSE SHELLS CHEATSHEET:
