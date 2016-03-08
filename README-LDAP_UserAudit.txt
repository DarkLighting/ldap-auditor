ABOUT LDAP UserAudit
----------------------------------

LDAP UserAudit is an open source tool to help administrators, penetration testers, or any security related user to audit different aspects related to account management in LDAP environment. It is LDAP configuration independent, it may be used with Active Directory or OpenLDAP. Currently, only Active Directory support is enabled, but the interface is simple and separated enought to develop other LDAP user management.
This tool use ldap searches to fetch data related to unused, expired, locked accounts as well as accounts with passwords that never expires, among others. It also helps letting the user fetch attributes of users and groups, get user groups, get group members, as well as transforming Active Directory timestamps.
It has support for different output formats, like pretty tables (mysql client style) and raw output to standar output, and CSV files.


FEATURES
----------------------------------

The tool is comprised of a module and a command line interface (cli). The module (useraudit.py) may be use by any other python program and is fully independent of the cli. This brings you the possibility to develop other interfaces (graphical interfaces with GTK, QT, etc), or other tools that use useraudit to get ldap accounts information.
useraudit_cli.py lets you interact with the module through a series of parameters so you can list different group of users, depending on the type of request you need.
Let's list some features:
* Supports Simple LDAP authentication with or without user and password, as well as SASL-GSSAPI Kerberos.
* Supports SSL.
* Supports simple configuration through file.
* Many types of auditing aspects, that let's you list:
  * any/all ldap attribute/s of a given username/groupname.
  * groups of a given user.
  * users of a given group.
  * last logon time of a given user.
  * user accounts that haven't logged-in the a certain period of time.
  * user accounts that have expired.
  * user accounts that have locked their account after many password attempt.
  * user accounts that have password that doesn't expires.
* Transform Active Directory timestamp to a human readable form.
* Different output formats:
  * Pretty table format, in mysql client style
  * Raw output: user list printed with their attributes separated by commas
  * CSV file: the classic comma separated format file, that can be imported in Calc or Excel easily.


REQUIREMENTS
----------------------------------

The tool is written in python and makes heavy use of the ldap library, so the requirements are:
  python interpreter >= 2.5
  python-ldap library
python-ldap library is available for GNU/Linux and comes in the repositories of the most used distrubutions. Hope you find it for Windows... if you whant to use that crap =P


CONFIGURATION
----------------------------------

The configuration is pretty simple. Because the number of parameters to connect to the LDAP servers may be overwhelming, LDAP UserAudit provides a configuration file named useraudit.cfg, with ini like format. In this file the user can configure parameters like the domain name to query, LDAP server DNS names, and preferred ldap server.
The program configuration is pretty straightforward and the comments help you as well.
If you're in GNU/Linux and want to use SASL-GSSAPI, some kerberos packages and configuration are needed. You'll find very helpful the following links:
https://help.ubuntu.com/community/ActiveDirectoryHowto
https://wiki.jasig.org/pages/viewpage.action?pageId=10650669
http://wiki.samba.org/index.php/Samba_&_Active_Directory
http://www.symantec.com/connect/articles/active-directory-and-linux
http://research.imb.uq.edu.au/~l.rathbone/ldap/gssapi.shtml


LICENSE
----------------------------------

The module and the cli are free software: you can redistribute it and/or modify it under the terms of the GNU General Public License v2 as published by the Free Software Foundation.
They are distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.


COMMAND LINE EXAMPLES
----------------------------------

By deffault LDAP Useraudit uses SASL-GSSAPI authentication. If you want simple authentication, use the parameter --simple-auth and -u (if user is needed). If -u is pressent, the program will ask you for a password, if None is needed, just hit enter.

Use a specific server and get my common name (useraudit will take this parameters from useraudit.cfg if they aren't present in the command line):
  useraudit.py -U ldap://ldap1.yourdomain.com:389 -i vbatista -f cn
Use a specific server list and get my last logon time (-U is needed for the primary ldap server):
  useraudit.py -U ldap://ldap1.yourdomain.com --ldap-servers ldap2.yourdomain.com,ldap3.yourdomain.com -i vbatista -f cn
List the user accounts that haven't logged-on in the last 90 days:
  useraudit.py --unused-users 90
List the locked users:
  useraudit.py --locked-users
Print the members of the group security:
  useraudit.py -m security
Send expired users to a CSV file:
  useraudit.py --expired-users --csv expired.csv
Get all the ldap entries for a given user:
  useraudit.py -i vbatista
  

ABOUT THE AUTHOR
----------------------------------
I am Victor H. Batista, a systems engineer that work as security administrator at an important company in Argentina, and I develop tools (mostly python, php and bash) as my work requires, or just for fun =)
If you want to contact me, send me a mail to my account vhbatista.it at gmail. 
I have a blog with a coworker friend where we share our knowledge in IT with others, and we like to receive others retribution, so feel free to post. Sadly it's only in spanish for now =S
  http://itfreekzone.blogspot.com
The blog also have a facebook page, visit us any time: http://www.facebook.com/itfreekzone