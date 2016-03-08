# -*- coding: utf-8 -*-

######################################################
# Created by: Victor H. Batista
# Date: 2011-05-29
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License v2 as published by
# the Free Software Foundation.
#
# This module is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
######################################################

import ldap, sys

from time import time
from datetime import datetime

#ca_certs='/etc/ssl/certs/ca-certificates.crt'
# Force cert validation
#ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
# Set path name of file containing all trusted CA certificates
#ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, ca_certs)

def print_ldap_tuple(ldap_tuple):
  if(ldap_tuple):
    for dn,entry in ldap_tuple:
      if(dn != None):
	#print DN
	print "DN: "+dn
	#print attributes
	for attr_name, attr_values in entry.items():
	  for attr_val in attr_values:
	    print attr_name+" = "+attr_val.replace("[", "\[") #.encode('string-escape')
  else:
    print "There are no entries to display"


'''
  Escape chars that have speacial meaning in filter searchs
  @param s the string to escape
  @return the string escaped
'''
def filter_escape(s):
  escaped = s.replace("(", "\\(")
  return(escaped.replace(")", "\\)"))

class useraudit:
  
  ldap_servers = []
  servers_ldap_objs = {}
  '''
  Class constructor
  It takes basic parameters to bind to a single or multiple ldap servers. If simple_auth is not
  specified or is False, a sasl-gssapi authentication would be used for the bind process.
  The resulting class attributes would be, the authentication method, username and password
  if specified, a baseDN (base domain name Distinguished Name) to use in searchs, and
  a binded object.
  The LDAPObject that is binded at this time is a preferred ldap server, in case many ldap servers
  are listed. It's taken from the first listed name from ldap_server param, in case of a list.
  @param domain the domain to audit
  @param ldap_server an ldap server url.
  @param verbose indicates the verbosity level
  @param use_ssl indicates if an ssl layer is needed.
  @param simple_auth a boolean value that indicates if the bind would use simple authentication.
  @param username a username to make a simple authentication.
  @param password the corresponding password for the given username, if necesary in the simple auth.
  '''
  def __init__(self, domain, ldap_server, verbose=0, use_ssl=False, simple_auth=False, username="", password=""):
    #self.ldap_obj = ldap_obj
    self.base_DN = 'dc='+domain.replace('.', ',dc=')
    self.verbose = verbose
    self.ssl = use_ssl
    self.simple_auth = simple_auth
    self.ldap_server = ldap_server
    if(username):
      self.user="cn="+username+","+base_DN
      self.password=password
    else:
      self.user=""
    
    self.ldap_obj = self.get_ldap_obj(ldap_server)
  
  def __del__(self):
    try:
      self.ldap_obj.unbind()
    except:
      return

  '''
  Bind to the given ldap server and return the corresponding LDAPObject.
  The credentials must be available in class attributes.
  @param ldap_url the ldap server url in the form ldap://<hostname/ip>[:port] or ldaps://<hostname/ip>[:port]
  @return an LDAPObject corresponding to the server already binded
  '''
  def get_ldap_obj(self, ldap_url):
    try:
      ldap_obj = ldap.initialize(ldap_url, self.verbose, sys.stderr)
      ldap_obj.protocol_version = ldap.VERSION3
      ldap_obj.set_option(ldap.OPT_REFERRALS, 0)
      
      if(self.ssl):
	ldap_obj.start_tls_s()
      
      try:
	#use simple bind?
	if(self.simple_auth):
	  if(self.user):
	    ldap_obj.simple_bind_s(self.user, self.password)
	  else:
	    ldap_obj.simple_bind_s()
	else:
	  #use kerberos (default)
	  auth = ldap.sasl.gssapi()
	  #auth = ldap.sasl.sasl({},'GSSAPI')
	  ldap_obj.sasl_interactive_bind_s('', auth)
      
	return ldap_obj
      
      except ldap.INVALID_CREDENTIALS as e:
	print "Invalid credentials: "+e.args[0]['info']+" "+e.args[0]['desc']
	raise
    except ldap.LDAPError as e:
      print "LDAP Error: "+str(e) #e.args[0]['info']+" "+e.args[0]['desc']

  '''
  Sets a list of ldap servers to use along with the principal server, defined in the constructor.
  Some attributes, like lastlogin, is kept different in each server because is not always replicated, so
  the user must specifye all the participating ldap servers to return an accurate result.
  @param ldap_servers a list of ldap servers urls to query
  '''
  def set_servers_list(self, ldap_servers):
    self.ldap_servers = ldap_servers
  
  '''
  Binds the servers and generates a dictionary with format server url -> LDAPObject
  '''
  def bind_servers(self):
    if((self.ldap_servers) and (not self.servers_ldap_objs)):
      for serv in self.ldap_servers:
	self.servers_ldap_objs[serv] = self.get_ldap_obj(serv)
  
  ''' 
  Translate Active Directory timestamp to Unix timestamp
  AD timestamp is the 100-nanosecond intervals that have elapsed since the 0 hour on January 1, 1601 till the date/time that is being stored.
  Unix timestamp is the seconds that have elapsed since 0 hour of January 1, 1970.
  @param ad_ts the Active Directory Timestamp to convert
  @return the Unix Timestamp corresponding to the AD Timestamp
  '''
  @staticmethod
  def ad2unix_timestamp(ad_ts=0):
    return((long(ad_ts)/10000000)-11644473600)
  
  '''
  Translate Unix timestamp to Active Directory timestamp
  AD timestamp is the 100-nanosecond intervals that have elapsed since the 0 hour on January 1, 1601 till the date/time that is being stored.
  Unix timestamp is the seconds that have elapsed since 0 hour of January 1, 1970.
  @param unix_ts the Unix Timestamp to convert
  @return the Active Directory Timestamp corresponding to the Unix Timestamp
  '''
  @staticmethod
  def unix2ad_timestamp(unix_ts):
    return((long(unix_ts)+11644473600)*10000000)

  '''
  Builds a users table with the ldap tuple suplied
  @param users_tuple the ldap tupled to format
  @param time_keyname the name of the key that refers to the time param in the ldap tuple. This is necesary because this parameter
  changes in the different requests.
  @param human_readable If set to True, the returned list will use human readable dates instead of unix timestamps
  @return a table containing the username, the Name, and the timestamp of the given request
  '''
  def build_users_table(self, users_tuple, time_keyname, human_readable=True):
    return None

  '''
  Check whether the user exists or not. Every ldap implementation may vary in the search parameters,
  so this function must be inherited
  @param username the user to check
  @return True if the user exists, False otherwise
  '''
  def user_exists(self, username):
    return(False)
  
  '''
  Retrieves user information from an ldap server
  @param username the user to fetch information
  @param attr_name [optional] fetch the given attribute, if None set, the search
    returns every entrie for the given user.
  @return the information in ldap tuple form, or None if the looked info doesn't exists
  '''
  def user_information(self, username, attr_name=None):
    return None
  
  '''
  LastLogon LDAP Search. This function must be inherited by the diffrent ldap user implementations (for ex: AD)
  @param ldap_obj the ldap object to contact the server
  @param username the username to check
  @return the last logon in unix timestamp on success, -1 if user doesn't exists, 0 if the user has never logged in
  '''
  def lastlogon_search(self, ldap_obj, username):
    return -1

  '''
  Returns a tuple containig the last login in Unix timestamp format and the last server name that authenticated the account
  @param username the username to check
  @return a tuple containig:
    the last logon in unix timestamp on success, -1 if user doesn't exists, 0 if the user has never logged in
    the last server that authenticated the account
  '''
  def last_logon(self, username):
    #global_ts = self.ldap_obj.search_s('cn=Users,'+self.base_DN, ldap.SCOPE_SUBTREE, '(samAccountName='+username+')', ['lastLogon'])[0][1]['lastLogon'][0]
    if(not self.user_exists(username)):
      return(-1)
    
    global_ts = self.lastlogon_search(self.ldap_obj, username)
    if(self.ldap_servers):
      if(not self.servers_ldap_objs):
	self.bind_servers()
      
      last_server = self.ldap_server
      for server,ldap_obj in self.servers_ldap_objs.items():
	#local_ts = ldap_obj.search_s('cn=Users,'+self.base_DN, ldap.SCOPE_SUBTREE, '(samAccountName='+username+')', ['lastLogon'])[0][1]['lastLogon'][0]
	local_ts = self.lastlogon_search(ldap_obj, username)
	if(local_ts > 0):
	  if(local_ts > global_ts):
	    global_ts = local_ts
	    last_server = server
    return([global_ts, last_server])
    #search_s(base_DN, ldap.SCOPE_SUBTREE, '(cn=vbatista)', ['cn'])
  
  '''  
  Returns a list of the users that has not logged-in in the past days
  @param days: the number of days withing which the user hasn't logged-on (ex: 30, list users that hasn't logged-on in 30 days)
  @param human_readable If set to True, the returned list will use human readable dates instead of unix timestamps
  @return the table of users that haven't logged-on in the last given days with the following format:
    [
      [username1, cn1, lastlogon1 (unix timestamp of last logon)]
      [username2, cn2, lastlogon2]
      ...
      ...
    ]
    if lastlogon == 0, it means that the user has never logged in on the given ldap servers
  '''
  def unused_users(self, days, human_readable=True):
    return None

  '''
  Returns locked user accounts
  @param unlock_time [optional] the time in minues after which a locked account is unlocked
  @param human_readable If set to True, the returned list will use human readable dates instead of unix timestamps  
  @return the table of locked accounts with the format:
    [
      [username1, cn1, lockedtime1]
      [username2, cn2, lockedtime2]
      ...
      ...
    ]
  '''
  def locked_users(self, unlock_time=0, human_readable=True):
    return None
  
  '''
  Returns the expired users
  @param human_readable If set to True, the returned list will use human readable dates instead of unix timestamps
  @return the table of locked accounts with the format:
    [
      [username1, cn1, expirationtime1]
      [username2, cn2, expirationtime2]
      ...
      ...
    ]
  '''
  def expired_users(self, human_readable=True):
    return None
  
  '''
  Fetchs the users whose password never expires
  @return a table containing the users (username and common name) whose password never expires.
  '''
  def password_nexpires(self):
    return None
  
  '''
  List the groups of the given username/groupname
  @param name a username or groupname to find the membership
  @return a list containing the group names
  '''
  def list_groups(self, name):
    return None
  
  '''
  List the members of the given group. 
  If recursive is true, get the members of the members that are groups. For example, 
  if the group Administrators has the member Security_Administrators, the recursive search 
  gets the Security_Administrators members, instead of return the group name Security_Administrators.
  It doesn't return duplicates.
  @param groupname the name of the group to fetch the users.
  @recursive [optional] do recursive group resolve. Default in false.
  @return a table containing the users (username, common name) of the given group.
  '''
  def list_members(self, groupname, recursive=False):
    return None

'''
useraudit class with functions specific for Active Directory ldap
'''
class useraudit_ad(useraudit):
  
  def build_users_table(self, users_tuple, time_keyname, human_readable=True):
    users_table = []
    
    for user in users_tuple:
      #items = user[1].items()
      #print items
      if(human_readable and (user[1][time_keyname][0] > 0)):
	users_table.append([user[1]['sAMAccountName'][0], user[1]['cn'][0], datetime.fromtimestamp(self.ad2unix_timestamp(user[1][time_keyname][0]))])
      else:
	users_table.append([user[1]['sAMAccountName'][0], user[1]['cn'][0], user[1][time_keyname][0]])
    return(users_table)
  
  def user_exists(self, username):
    result = self.ldap_obj.search_s('cn=Users,'+self.base_DN, ldap.SCOPE_SUBTREE, '(samAccountName='+filter_escape(username)+')', ['cn'])
    if(len(result) > 0):
      return(True)
    else:
      return(False)

  def user_information(self, username, attr_name=None):
    try:
      if(attr_name):
	user = self.ldap_obj.search_s('cn=Users,'+self.base_DN, ldap.SCOPE_SUBTREE, '(samAccountName='+filter_escape(username)+')', [attr_name])
      else:
	user = self.ldap_obj.search_s('cn=Users,'+self.base_DN, ldap.SCOPE_SUBTREE, '(samAccountName='+filter_escape(username)+')')
      if(len(user)>0):
	return(user)
      else:
	return(None)
    except ldap.NO_SUCH_OBJECT as e:
      print 'cn=Users,'+self.base_DN+" doesn't exist in the directory"
      return None
    except ldap.FILTER_ERROR as e:
      print 'user_information error: '+e[0]['desc']
      return None

  def lastlogon_search(self, ldap_obj, username):
    llogon = ldap_obj.search_s('cn=Users,'+self.base_DN, ldap.SCOPE_SUBTREE, '(samAccountName='+filter_escape(username)+')', ['lastLogon'])
    if((llogon != []) and (len(llogon[0][1])>0) and (long(llogon[0][1]['lastLogon'][0]) > 0)):
      return(self.ad2unix_timestamp(llogon[0][1]['lastLogon'][0]))
    else:
      return(0)


  def unused_users(self, days, human_readable=True):
    xtoday_timestamp = int(time())    
    
    ad_today_ts = self.unix2ad_timestamp(int(time()))
    
    #Unix timestamp for the lower day to check
    xlower_logon = xtoday_timestamp - (days*86400)
    
    ## Get the AD timestamp for the lower day to check    
    adlower_logon = self.unix2ad_timestamp(xlower_logon)
    
    # Query filters:
    #	lastLogon gives the last logon timestamp. 
    #	objectClass=user gives the user records
    #	objectCategory=person returns only entries of persons
    #	!(objectClass=computer) removes computers from the result (maybe unnecesary)
    #	!(userAccountControl:1.2.840.113556.1.4.803:=2) removes disabled users (:1.2.840.113556.1.4.803: is a bit AND rule, 2 is the code for disabled user)
    users = self.ldap_obj.search_s('cn=Users,'+self.base_DN, ldap.SCOPE_SUBTREE, '(&(lastLogon<='+str(adlower_logon)+')(objectCategory=person)(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(accountExpires=*)(accountExpires<='+str(ad_today_ts)+'))', ['samAccountName', 'cn'])
    unused = []
    for user in users:
      #this call makes 2 searchs in the same server, this is a waste of time! 
      #TODO: change the architecture
      (llogon, controller) = self.last_logon(user[1]['sAMAccountName'][0])
      
      if(llogon < xlower_logon):
	if(human_readable and (llogon > 0)):
	  unused.append([user[1]['sAMAccountName'][0], user[1]['cn'][0], datetime.fromtimestamp(llogon)])
	else:
	  unused.append([user[1]['sAMAccountName'][0], user[1]['cn'][0], llogon])
	#unused.append({'user': user[1]['sAMAccountName'][0], 'lastlogon': llogon})
    return unused

  def locked_users(self, unlock_time=0, human_readable=True):
    # Query filters:
    #	lastLogon gives the last logon timestamp.
    #	objectCategory=person returns only entries of persons
    #users = self.ldap_obj.search_s('cn=Users,'+self.base_DN, ldap.SCOPE_SUBTREE, '(&(objectCategory=person)(!(userAccountControl=514))(lockoutTime=*)(!(lockoutTime=0))(!(userAccountControl=66050)))', ['sAMAccountName', 'cn', 'lockoutTime'])
    #	!(userAccountControl:1.2.840.113556.1.4.803:=2) removes disabled users (:1.2.840.113556.1.4.803: is a bit AND rule, 2 is the code for disabled user)
    #	(lockoutTime=*) the attribute lockoutTime exists
    #	lockoutTime>=lock_timestamp removes the users that were unlocked automaticaly by AD policy.
    
    # If automatic lock resets are present, calculate the correct timestamp for locked users.
    # AD don't reset lockoutTime when the system automaticaly unlock an account, so locked users
    # must be search calculating if the lockoutTime is bigger than the current time less the lock time
    if(unlock_time > 0):
      lock_ts = self.unix2ad_timestamp(int(time()) - (int(unlock_time) * 60))
    else:
      lock_ts = 1

    users = self.ldap_obj.search_s('cn=Users,'+self.base_DN, ldap.SCOPE_SUBTREE, '(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lockoutTime=*)(lockoutTime>='+str(lock_ts)+'))', ['sAMAccountName', 'cn', 'lockoutTime'])
    
    return(self.build_users_table(users, 'lockoutTime', human_readable))

  def expired_users(self, human_readable=True):
    ad_today_ts = self.unix2ad_timestamp(int(time()))
    # Query filters:
    #	objectCategory=person returns only entries of persons
    #	!(userAccountControl:1.2.840.113556.1.4.803:=2) removes disabled users (:1.2.840.113556.1.4.803: is a bit AND rule, 2 is the code for disabled user)
    #	(accountExpires=*) the attribute accountExpires exists
    #	accountExpires<=today_timestamp returns the accounts with expiration date lower than today
    #	!(accountExpires=0) expiration time is diffrent to 0, which means that the account doesn't expires.
    users = self.ldap_obj.search_s('cn=Users,'+self.base_DN, ldap.SCOPE_SUBTREE, '(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(accountExpires=*)(accountExpires<='+str(ad_today_ts)+')(!(accountExpires=0)))', ['sAMAccountName', 'cn', 'accountExpires'])
    
    return(self.build_users_table(users, 'accountExpires', human_readable))
  
  def password_nexpires(self):
    # Query filters:
    #	objectCategory=person returns only entries of persons
    #	userAccountControl=66048 user account enabled, password never expires
    users_ldap = self.ldap_obj.search_s('cn=Users,'+self.base_DN, ldap.SCOPE_SUBTREE, '(&(objectCategory=person)(userAccountControl=66048))', ['sAMAccountName', 'cn'])
    
    users = []
    for user in users_ldap:
      users.append([user[1]['sAMAccountName'][0], user[1]['cn'][0]])
    return(users)
  
  '''
  Private function to resolve groups of a user and the groups of the groups of the user (recursively)
  @param name the user/group name to resolv
  @return a list containing all the groups of the given user/group
  '''
  def recursive_list_groups(self, name, total_groups, recursive=False):
    groups_ldap = self.user_information(name, 'memberOf')
    
    # If the user/group is not member of any other group, return
    if('memberOf' not in groups_ldap[0][1]):
      return
    for group in groups_ldap[0][1]['memberOf']:
      result = self.ldap_obj.search_s(group, ldap.SCOPE_SUBTREE, '(objectClass=*)', ['sAMAccountName', 'description'])
      if(len(result) > 0):
	if(recursive):
	  self.recursive_list_groups(result[0][1]['sAMAccountName'][0], total_groups, recursive)
	if(len(result[0][1]) > 1):
	  if([result[0][1]['sAMAccountName'][0], result[0][1]['description'][0]] not in total_groups):
	    total_groups.append([result[0][1]['sAMAccountName'][0], result[0][1]['description'][0]])
	else:
	  if([result[0][1]['sAMAccountName'][0], ''] not in total_groups):
	    total_groups.append([result[0][1]['sAMAccountName'][0], ''])
  
  def list_groups(self, name, recursive=False):
    if(not self.user_exists(name)):
      print "user/group "+name+" doesn't exists"
      return []
    
    total_groups = []
    self.recursive_list_groups(name, total_groups, recursive)
    return(total_groups)
  
  def old_list_groups(self, name, recursive=False):
    groups_ldap = self.user_information(name, 'memberOf')
    groups = []
    for group in groups_ldap[0][1]['memberOf']:
      result = self.ldap_obj.search_s(group, ldap.SCOPE_SUBTREE, '(objectClass=*)', ['sAMAccountName', 'description'])
      if(len(result) > 0):
	if(len(result[0][1]) > 1):
	  groups.append([result[0][1]['sAMAccountName'][0], result[0][1]['description'][0]])
	else:
	  groups.append([result[0][1]['sAMAccountName'][0], ''])
    return(groups)

  '''
  Private function to resolve members of a group recursively
  @param groupname
  @return a list containing all the group members
  '''
  def recursive_list_members(self, groupname, total_members, recursive=False):
    members_ldap = self.user_information(groupname, 'member')
    if(members_ldap):
      #members = []
      for member in members_ldap[0][1]['member']:
	result = self.ldap_obj.search_s(member, ldap.SCOPE_SUBTREE, '(objectClass=*)', ['sAMAccountName', 'cn', 'groupType'])
	if(len(result) > 0):
	  if(recursive and ('groupType' in result[0][1])):
	    #members = list(set(members) & set(self.list_members(result[0][1]['cn'][0])))
	    self.recursive_list_members(result[0][1]['cn'][0], total_members, recursive)
	  else:
	    if([result[0][1]['sAMAccountName'][0], result[0][1]['cn'][0]] not in total_members):
	      total_members.append([result[0][1]['sAMAccountName'][0], result[0][1]['cn'][0]])
      #return(total_members)
    #return([])

  def list_members(self, groupname, recursive=False):
    total_members = []
    self.recursive_list_members(groupname, total_members, recursive)
    return(total_members)

  #def old_list_members(self, groupname, recursive=False):
    #members_ldap = self.user_information(groupname, 'member')
    #if(members_ldap):
      #members = []
      #for member in members_ldap[0][1]['member']:
	#result = self.ldap_obj.search_s(member, ldap.SCOPE_SUBTREE, '(objectClass=*)', ['sAMAccountName', 'cn', 'groupType'])
	#if(len(result) > 0):
	  #if(recursive and ('groupType' in result[0][1])):
	    #members = members + self.list_members(result[0][1]['cn'][0])
	  #else:
	    #members.append([result[0][1]['sAMAccountName'][0], result[0][1]['cn'][0]])
      #return(members)
    #return([])


'''
useraudit class with functions specific for OpenLDAP ldap
'''
class useraudit_oldap(useraudit):
  def user_exists(self, username):
    result = self.ldap_obj.search_s('ou=People,'+self.base_DN, ldap.SCOPE_SUBTREE, '(uid='+filter_escape(username)+')', ['uid'])
    if(len(result) > 0):
      return(True)
    else:
      return(False)
  
  def user_information(self, username, attr_name=None):
    try:
      if(attr_name):
	user = self.ldap_obj.search_s('ou=People,'+self.base_DN, ldap.SCOPE_SUBTREE, '(uid='+filter_escape(username)+')', [attr_name])
      else:
	user = self.ldap_obj.search_s('ou=People,'+self.base_DN, ldap.SCOPE_SUBTREE, '(uid='+filter_escape(username)+')')
      if(len(user)>0):
	return(user)
      else:
	return(None)
    except ldap.NO_SUCH_OBJECT as e:
      print self.base_DN+" doesn't exist in the directory"

# User Flags in MS support
# http://msdn.microsoft.com/en-us/library/aa772300.aspx
# http://support.microsoft.com/default.aspx?scid=kb;en-us;269181