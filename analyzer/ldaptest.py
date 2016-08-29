#! /usr/bin/env python2
import sys
import ldap, ldapurl
import time

url = sys.argv[1]

start = time.time()
if( ldapurl.isLDAPUrl( url ) ):
    url_parts = ldapurl.LDAPUrl( url )
    connectionstring = "{0}://{1}".format(url_parts.urlscheme, url_parts.hostport)
    
    try:
        l = ldap.initialize(connectionstring)
        try:
            l.bind_s('','') #anonymous bind
            scope = url_parts.scope if url_parts.scope != None else 0
            if url_parts.filterstr == None:
                res = l.search_s(url_parts.dn, scope, attrlist=url_parts.attrs)
            else:
                res = l.search_s(url_parts.dn, scope, url_parts.filterstr, attrlist=url_parts.attrs)
            
            for item in res:
                for key in item[1]:
                    for crlraw in item[1][key]:
                        print("got crlraw!")
        except ldap.LDAPError, e:
                if type(e.message) == dict:
                    for (k, v) in e.message.iteritems():
                       print("%s: %sn" % (k, v) )
                else:
                    print(e)
                end = time.time()
                print("LDAPError after {0} seconds: {1}".format((end-start), e))
    finally:
        try:
            l.unbind()
        except Error:
            pass
# HTTP(S)
else:
    print("not an LDAP url")