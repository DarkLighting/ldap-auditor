#!/usr/bin/python
# -*- coding: utf-8 -*-

######################################################
# Created by: Victor H. Batista
# Date: 2011-05-29
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License v2 as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
######################################################

import ldap,ldap.sasl
from optparse import OptionParser
import ConfigParser
import getpass
import sys
from os import path
from datetime import datetime

from useraudit import useraudit_oldap,useraudit_ad,print_ldap_tuple

#configuration file path
config_file='useraudit.cfg'

# The authentication method used by default is sasl-gssapi-kerberos

'''
The cli provides many parameters so the user can do different things.
Many of the parameters may be set in the configuration file (useraudit.cfg), 
so they musn't be specified in every command call.
'''
########################################
#OUTPUT formatting
########################################
'''
Prints the given table to stout without formating
@param rows a list containing the registries (lists) of the table. The format is:
'''
def print_raw_output(rows):
  output = ""
  for row in rows:
    for cell in row:
      output = output+str(cell).replace("[", "\[")+", "
    output = output+"\n"
  print output

'''
Takes a table array and print it in stout with pretty formatting.
@param col_names a list containning the name of the columns of the table
@param rows a list containing the registries (lists) of the table. The format is:
  [
    [cell11, col12, ..., cell1N]
    [cell21, cell22, ..., cell2N]
    ...
    [cellN1, cellN2, ..., cellNN]
  ]
'''
def print_pretty_table(col_names, rows):
  c = 0
  colsize = []
  #Get sizes of the column names
  for col_name in col_names:
    colsize.append(len(col_name))

  #Adapt the size to the largest column
  for row in rows:
    c = 0
    for cell in row:
      row[c] = str(cell).replace("[", "\[")
      if(len(row[c])>colsize[c]):
	colsize[c] = len(row[c])
      c += 1
  
  #Make an hyphen row
  hyphenrow = ''
  for s in colsize:
    hyphenrow += "+"+"-"*(s+2)
  hyphenrow += "+\n"
  
  c = 0
  sys.stdout.write(hyphenrow)
  for col in col_names:
    sys.stdout.write("| "+col+" "*(colsize[c] - len(col))+" ")
    c += 1
  sys.stdout.write("|\n")
  output = ""
  for row in rows:
    c = 0
    output += hyphenrow
    for cell in row:
      output += "| "+cell+" "*(colsize[c] - len(cell))+" "
      c += 1      
    output += "|\n"
  output += hyphenrow
  print output

'''
Exports a table to CSV format
@param col_names the names of the columns (header) in a list
@param rows the rows containing the data of the table in a list:
  [
    [cell11, cell12, ..., cell1N]
    [cell21, cell22, ..., cell2N]
    ...
    [cellN1, cellN2, ..., cellNN]
  ]
@param filename the name of the file to export
'''
def export_CSV(col_names, rows, filename):
  f = open(filename, 'w')
  for cname in col_names:
    if(cname.find(",") != -1):
      f.write('"'+str(cname)+'",')
    else:
      f.write(str(cname)+',')
  f.write('\n')
  for r in rows:
    for cell in r:
      if(str(cell).find(",") != -1):
	f.write('"'+str(cell)+'",')
      else:
	f.write(str(cell)+',')
    f.write('\n')
  f.close()

'''
Depending on the output option chosen, prints the result in the corresponding format
@param users a table containing the users and the attributes to show
'''
def output_results(table, col_names=[]):
  #print options.csv_file
  if(options.csv_file):
    export_CSV(col_names, table, options.csv_file)
  elif(options.raw_output):
    print_raw_output(table)
  else:
    print_pretty_table(col_names, table)
########################################


########################################
#command line interface parsing
########################################

#callback function for OptionParser, so we can store 0 o more values in the variable
def store_default(option, opt_str, value, parser, args):
  if((parser.rargs == []) or (parser.rargs[0].startswith("-"))):
    if(args != []):
      setattr(parser.values, option.dest, args)
    else:
      setattr(parser.values, option.dest, None)
  else:
    #try:
    setattr(parser.values, option.dest, parser.rargs[0])
    #except ValueError:
      #setattr(parser.values, option.dest, None)

#configuration parameters
parser = OptionParser(usage="usage: %prog [-r|-d realm|domain] [-s server | -U url] [options]", version="%prog v0.04")
parser.add_option("-r", "--realm",
                  metavar="REALM", dest="domain", type="string", help="the realm to search in")
parser.add_option("-d", "--domain",
                  metavar="REALM", dest="domain", type="string", help="same as -r")
parser.add_option("-s", "--server",
                  metavar="SERVER", dest="ldap_server", type="string", help="the ldap server to query")
parser.add_option("--ldap-servers",
                  metavar="SERVER_LIST", dest="ldap_servers_list", type="string", help="a coma separated list with the ldap servers to query")
parser.add_option("-p", "--port",
                  metavar="PORT", dest="ldap_port", type="int", help="the ldap server port")
parser.add_option("-U", "--url",
                  metavar="URL", dest="ldap_url", type="string", help="the url of the ldap server (ie: ldap://<host>:[port], ldaps://<host>:[port]")
parser.add_option("-v", "--verbose", 
		  dest="verbose", action='count', default=0, help="get last logon of the given user")
parser.add_option("--ssl", 
		  dest="ssl", action='store_true', default=False, help="use ssl (ssl usage is implicit if ldaps:// URI is used)")
parser.add_option("-x", "--simple-auth",
		  dest="simple_auth", action='store_true', default=False, help="use simple ldap authentication")
parser.add_option("-u", "--user",
                  metavar="USER", dest="user", type="string", help="username to use with simple authentication")
parser.add_option("-o", "--open-ldap",
		  dest="open_ldap", action='store_true', default=False, help="use OpenLDAP structure")
parser.add_option("-a", "--active-directory",
		  dest="active_directory", action='store_true', default=False, help="use Active Directory structure")

#functionality parameters
parser.add_option("-l", "--last-logon",
                  metavar="LLOGON", dest="llogon_username", type="string", help="get last logon of the given user")
parser.add_option("--unused-users",
                  metavar="LLOGON", action="callback", callback=store_default, dest="unused_days", callback_args=("60",), callback_kwargs={}, help="get a list of the users that haven't logged-on in the last <number of days> (default 60)")
parser.add_option("--locked-users",
		  dest="locked_users", action='store_true', default=False, help="print the list of user accounts that are locked")
parser.add_option("-e", "--expired-users",
		  dest="expired_users", action='store_true', default=False, help="print the list of user accounts that has expired")
parser.add_option("--password-never-expires",
		  dest="password_nexpires", action='store_true', default=False, help="get the users whose password never expires")
parser.add_option("-i", "--user-info",
                  metavar="USERNAME", dest="info_username", type="string", help="get user/group ldap registries")
parser.add_option("-f", "--find-attribute",
                  metavar="USERNAME", dest="info_attr", type="string", help="get user/group ldap attribute")
parser.add_option("-t", "--decode-timestamp",
                  metavar="TIMESTAMP", dest="ad_timestamp", type="string", help="convert Active Directory timestamp to a human readable form")
parser.add_option("-g", "--groups",
		  metavar="USERNAME", dest="list_groups", type="string", help="get the groups for the given user")
parser.add_option("-m", "--group-members",
		  metavar="GROUPNAME", dest="group_members", type="string", help="fetch the members of the given group")
parser.add_option("--recursive",
		  action="store_true", dest="recursive", default=False, help="do a recursive members search for groups that have group members")

#output formatting
parser.add_option("--csv", metavar="CSV_FILE", 
		  action="callback", callback=store_default, dest="csv_file", callback_args=("output.csv",), callback_kwargs={}, help="store output (if possible) in CSV file. If none name is given, the output file is output.csv")
parser.add_option("--raw",
		  action="store_true", dest="raw_output", help="print the output without format")

(options, args) = parser.parse_args()

#Open the configuration file
if(not path.exists(config_file)):
  print("Configuration file not found!\nAborting...")
  quit(-1)

config = ConfigParser.ConfigParser()
config.read(config_file)

if(options.open_ldap):
  structure = "OLDAP"
elif(options.active_directory):
  structure = "AD"
else:
  structure = config.get('ldap_connection', 'structure')

if(not options.domain):
  options.domain = config.get('ldap_connection', 'domain')
  if(not options.domain):
    parser.print_help()
    quit(-1)

if((not options.ldap_server) and (not options.ldap_url) and (not options.ldap_servers_list)):
  #if not cli for ldap_url, fetch from config file, and print help if none is found
  options.ldap_url = config.get('ldap_connection', 'primary_server')
  if(not options.ldap_url):
    parser.print_help()
    quit(-1)
  #if not cli for ldap_servers_list, fetch from config file
  options.ldap_servers_list = config.get('ldap_connection', 'servers_list')
  
  
if(options.ldap_server):
  ldap_url = 'ldap://'+options.ldap_server
  if(options.ldap_port):
    ldap_url = ldap_url+':'+options.ldap_port
else:
  ldap_url=options.ldap_url

if(not options.verbose):
  options.verbose = 0

username = password = ""
if(options.simple_auth):  
  if(options.user):
    username = options.user
    password = getpass.getpass()
    

#end command line interface parsing
########################################

########################################
# MAIN
########################################

try:
  if(structure.upper() == "AD"):
    audit = useraudit_ad(options.domain, ldap_url, options.verbose, options.ssl, options.simple_auth, username, password)
  elif(structure.upper() == "OLDAP"):
    audit = useraudit_oldap(options.domain, ldap_url, options.verbose, options.ssl, options.simple_auth, username, password)
  else:
    print "None structure set"
    quit(-1)
      

  #if have other ldap servers, get their URLs and set them in the audit class
  if(options.ldap_servers_list):
    ldap_servers = options.ldap_servers_list.split(' ')
    size = len(ldap_servers)
    for i in range(size):
      if((ldap_servers[i].find("ldap://") == -1) and (ldap_servers[i].find("ldaps://") == -1)):
	ldap_servers[i] = "ldap://"+ldap_servers[i]
    audit.set_servers_list(ldap_servers)


  #Execute request
  users = None
  if(options.llogon_username):
    (llogon, lserver) = audit.last_logon(options.llogon_username)
    if(llogon > 0):
      print "Last Logon: "+str(datetime.fromtimestamp(llogon))
      print "Server: "+lserver
    elif(llogon == -1):
      print "The user doesn't exists"
    else:
      print "The user "+options.llogon_username+" has never logged-on on the given ldap servers"
  elif(options.unused_days != None):
    print "List of users that haven't logged-in on the domain controllers "+str(ldap_servers)+" in the last "+str(options.unused_days)+" days"
    #users = audit.unused_users(int(options.unused_days), True)
    output_results(audit.unused_users(int(options.unused_days), True), ['Username', 'Name', 'Last Logon'])
  elif(options.locked_users):
    unlock_time = config.get('account_policies', 'unlock_time')
    output_results(audit.locked_users(unlock_time, True), ['Username', 'Name', 'Lockout Time'])
  elif(options.expired_users):
    output_results(audit.expired_users(True), ['Username', 'Name', 'Expiration Date'])
  elif(options.password_nexpires):
    output_results(audit.password_nexpires(), ['Username', 'Name'])
  elif(options.info_username):
    print_ldap_tuple(audit.user_information(options.info_username, options.info_attr))
  elif(options.ad_timestamp):
    print datetime.fromtimestamp(useraudit.ad2unix_timestamp(options.ad_timestamp))
  elif(options.list_groups):
    output_results(audit.list_groups(options.list_groups, options.recursive), ['Group Name', 'Description'])
  elif(options.group_members):
    output_results(audit.list_members(options.group_members, options.recursive), ['Username', 'Name'])
  else:
    parser.print_help()

except KeyboardInterrupt:
  print "Stoped by the user..."
  quit(-1)
  
#ldap library
#http://www.python-ldap.org/doc/html/ldap.html

#ldap con ssl
# http://python-ldap.cvs.sourceforge.net/viewvc/python-ldap/python-ldap/Demo/initialize.py?revision=1.9&view=markup

#searchs
#http://technet.microsoft.com/en-us/library/cc978021.aspx
#http://support.microsoft.com/default.aspx?scid=kb;en-us;269181