--- satellite_inventory.py	(original)
+++ satellite_inventory.py	(refactored)
@@ -19,8 +19,8 @@
 import json
 import getpass
 import os
-import urllib2
-import urllib
+import urllib.request, urllib.error, urllib.parse
+import urllib.request, urllib.parse, urllib.error
 import base64
 import sys
 import ssl
@@ -197,7 +197,7 @@
 parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")
 parser.add_option("-d", "--debug", dest="debug", action="store_true", help="Debugging output (debug output enables verbose)")
 parser.add_option("-c", "--columns", dest="columns", help="coma separated list of columns to add to the output")
-parser.add_option("-f", "--format", dest="format", help="use an predefined output format (available formats: %s)" % ", ".join(_format_columns_mapping.keys()),choices=_format_columns_mapping.keys())
+parser.add_option("-f", "--format", dest="format", help="use an predefined output format (available formats: %s)" % ", ".join(list(_format_columns_mapping.keys())),choices=list(_format_columns_mapping.keys()))
 parser.add_option("-S", "--search", dest="search", help="limit report to machines matching this search")
 (options, args) = parser.parse_args()
 
@@ -211,9 +211,9 @@
     ENDC = '\033[0m'
 
 if not (options.login and options.satellite):
-    print "Must specify login, server, and orgid options.  See usage:"
+    print("Must specify login, server, and orgid options.  See usage:")
     parser.print_help()
-    print "\nExample usage: ./sat6Inventory.py -l admin -s satellite.example.com -o ACME_Corporation"
+    print("\nExample usage: ./sat6Inventory.py -l admin -s satellite.example.com -o ACME_Corporation")
     sys.exit(1)
 else:
     login = options.login
@@ -226,11 +226,11 @@
 if options.debug:
     DEBUG = True
     VERBOSE = True
-    print "[%sDEBUG%s] LOGIN -> %s " % (error_colors.OKBLUE, error_colors.ENDC, login)
-    print "[%sDEBUG%s] PASSWORD -> %s " % (error_colors.OKBLUE, error_colors.ENDC, password)
-    print "[%sDEBUG%s] SATELLITE -> %s " % (error_colors.OKBLUE, error_colors.ENDC, satellite)
-    print "[%sDEBUG%s] ORG ID -> %s " % (error_colors.OKBLUE, error_colors.ENDC, options.orgid)
-    print "[%sDEBUG%s] ORG NAME -> %s " % (error_colors.OKBLUE, error_colors.ENDC, options.org)
+    print("[%sDEBUG%s] LOGIN -> %s " % (error_colors.OKBLUE, error_colors.ENDC, login))
+    print("[%sDEBUG%s] PASSWORD -> %s " % (error_colors.OKBLUE, error_colors.ENDC, password))
+    print("[%sDEBUG%s] SATELLITE -> %s " % (error_colors.OKBLUE, error_colors.ENDC, satellite))
+    print("[%sDEBUG%s] ORG ID -> %s " % (error_colors.OKBLUE, error_colors.ENDC, options.orgid))
+    print("[%sDEBUG%s] ORG NAME -> %s " % (error_colors.OKBLUE, error_colors.ENDC, options.org))
 else:
     DEBUG = False
     VERBOSE = False
@@ -243,7 +243,7 @@
 elif options.columns:
     columns = options.columns.split(',')
     for c in columns:
-        if c not in _title_mapping.keys():
+        if c not in list(_title_mapping.keys()):
             parser.error("unknown column '%s'" % (c))
 else:
     if not options.format:
@@ -255,58 +255,58 @@
 
 try:
     url = "https://" + satellite + "/api/status"
-    request = urllib2.Request(url)
+    request = urllib.request.Request(url)
     if VERBOSE:
-        print "=" * 80
-        print "[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, url)
+        print("=" * 80)
+        print("[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, url))
     base64string = base64.encodestring('%s:%s' % (login, password)).strip()
     request.add_header("Authorization", "Basic %s" % base64string)
-    result = urllib2.urlopen(request)
+    result = urllib.request.urlopen(request)
     jsonresult = json.load(result)
     api_version = jsonresult['api_version']
     if VERBOSE:
-        print "=" * 80
-        print "[%sVERBOSE%s] API Version -> %s " % (error_colors.OKGREEN, error_colors.ENDC, api_version)
-except urllib2.URLError, e:
-    print "Error: cannot connect to the API: %s" % (e)
-    print "Check your URL & try to login using the same user/pass via the WebUI and check the error!"
+        print("=" * 80)
+        print("[%sVERBOSE%s] API Version -> %s " % (error_colors.OKGREEN, error_colors.ENDC, api_version))
+except urllib.error.URLError as e:
+    print("Error: cannot connect to the API: %s" % (e))
+    print("Check your URL & try to login using the same user/pass via the WebUI and check the error!")
     sys.exit(1)
-except Exception, e:
-    print "FATAL Error - %s" % (e)
+except Exception as e:
+    print("FATAL Error - %s" % (e))
     sys.exit(2)
 
 if options.orgid:
   orgid = options.orgid
   url = "https://" + satellite + "/katello/api/organizations/" + orgid
-  request = urllib2.Request(url)
+  request = urllib.request.Request(url)
   base64string = base64.encodestring('%s:%s' % (login, password)).strip()
   request.add_header("Authorization", "Basic %s" % base64string)
   try:
-    result = urllib2.urlopen(request)
+    result = urllib.request.urlopen(request)
     jsonresult = json.load(result)
     orgname = jsonresult['name']
-  except urllib2.HTTPError:
-    print "Could not find Organization with id '%s'" % orgid
+  except urllib.error.HTTPError:
+    print("Could not find Organization with id '%s'" % orgid)
     sys.exit(1)
 elif options.org:
   orgname = options.org
   search_key = 'name="%s"' % orgname
-  url = "https://" + satellite + "/katello/api/organizations/?" + urllib.urlencode([('search', '' + str(search_key))])
-  request = urllib2.Request(url)
+  url = "https://" + satellite + "/katello/api/organizations/?" + urllib.parse.urlencode([('search', '' + str(search_key))])
+  request = urllib.request.Request(url)
   base64string = base64.encodestring('%s:%s' % (login, password)).strip()
   request.add_header("Authorization", "Basic %s" % base64string)
-  result = urllib2.urlopen(request)
+  result = urllib.request.urlopen(request)
   jsonresult = json.load(result)
   if jsonresult['results']:
     orgid = jsonresult['results'][0]['id']
   else:
-    print "Could not find Organization with name '%s'" % orgname
+    print("Could not find Organization with name '%s'" % orgname)
     sys.exit(1)
 else:
   orgid = None
   orgname = "all"
 
-print "Fetching systems for org '%s' (id: %s)" % (orgname, orgid)
+print("Fetching systems for org '%s' (id: %s)" % (orgname, orgid))
 
 systemdata = []
 
@@ -320,30 +320,30 @@
             q.append(('search', options.search))
         if api_version == 2:
             if orgid:
-                url = "https://" + satellite + "/api/v2/organizations/" + str(orgid) + "/hosts?" + urllib.urlencode(q)
+                url = "https://" + satellite + "/api/v2/organizations/" + str(orgid) + "/hosts?" + urllib.parse.urlencode(q)
             else:
-                url = "https://" + satellite + "/api/v2/hosts?" + urllib.urlencode(q)
+                url = "https://" + satellite + "/api/v2/hosts?" + urllib.parse.urlencode(q)
         else:
             if orgid:
-                url = "https://" + satellite + "/katello/api/v2/organizations/" + str(orgid) + "/systems?" + urllib.urlencode(q)
+                url = "https://" + satellite + "/katello/api/v2/organizations/" + str(orgid) + "/systems?" + urllib.parse.urlencode(q)
             else:
-                url = "https://" + satellite + "/katello/api/v2/systems?" + urllib.urlencode(q)
-        request = urllib2.Request(url)
+                url = "https://" + satellite + "/katello/api/v2/systems?" + urllib.parse.urlencode(q)
+        request = urllib.request.Request(url)
         if VERBOSE:
-            print "=" * 80
-            print "[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, url)
+            print("=" * 80)
+            print("[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, url))
         base64string = base64.encodestring('%s:%s' % (login, password)).strip()
         request.add_header("Authorization", "Basic %s" % base64string)
-        result = urllib2.urlopen(request)
+        result = urllib.request.urlopen(request)
         jsonresult = json.load(result)
         systemdata += jsonresult['results']
 
-except urllib2.URLError, e:
-    print "Error: cannot connect to the API: %s" % (e)
-    print "Check your URL & try to login using the same user/pass via the WebUI and check the error!"
+except urllib.error.URLError as e:
+    print("Error: cannot connect to the API: %s" % (e))
+    print("Check your URL & try to login using the same user/pass via the WebUI and check the error!")
     sys.exit(1)
-except Exception, e:
-    print "FATAL Error - %s" % (e)
+except Exception as e:
+    print("FATAL Error - %s" % (e))
     sys.exit(2)
 
 csv_writer_subs = csv.writer(open(orgname + "_inventory_report.csv", "wb"), delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
@@ -353,7 +353,7 @@
 csv_writer_subs.writerow(title_row)
 
 if VERBOSE:
-    print "[%sVERBOSE%s] Data will be written to %s_inventory_report.csv" % (error_colors.OKGREEN, error_colors.ENDC, orgname)
+    print("[%sVERBOSE%s] Data will be written to %s_inventory_report.csv" % (error_colors.OKGREEN, error_colors.ENDC, orgname))
 
 
 
@@ -368,22 +368,22 @@
 
 def report_sysdata():
     global key
-    for key in _sysdata_mapping.keys():
+    for key in list(_sysdata_mapping.keys()):
         if _sysdata_mapping[key] in sysdata:
             host_info[key] = sysdata[_sysdata_mapping[key]]
     if 'subscription_facet_attributes' in sysdata and sysdata['subscription_facet_attributes']:
-        for key in _sysdata_subscription_facet_attributes_mapping.keys():
+        for key in list(_sysdata_subscription_facet_attributes_mapping.keys()):
             if _sysdata_subscription_facet_attributes_mapping[key] in sysdata['subscription_facet_attributes']:
                 host_info[key] = sysdata['subscription_facet_attributes'][_sysdata_subscription_facet_attributes_mapping[key]]
     if 'content_facet_attributes' in sysdata and sysdata['content_facet_attributes']:
-        for key in _sysdata_content_facet_attributes_mapping.keys():
+        for key in list(_sysdata_content_facet_attributes_mapping.keys()):
             if _sysdata_content_facet_attributes_mapping[key] in sysdata['content_facet_attributes']:
                 host_info[key] = sysdata['content_facet_attributes'][_sysdata_content_facet_attributes_mapping[key]]
     if 'facts' in sysdata and sysdata['facts']:
-        for key in _sysdata_facts_mapping.keys():
+        for key in list(_sysdata_facts_mapping.keys()):
             if _sysdata_facts_mapping[key] in sysdata['facts']:
                 host_info[key] = sysdata['facts'][_sysdata_facts_mapping[key]]
-        for key in _sysdata_facts_mapping_v2.keys():
+        for key in list(_sysdata_facts_mapping_v2.keys()):
             if _sysdata_facts_mapping_v2[key] in sysdata['facts']:
                 host_info[key] = sysdata['facts'][_sysdata_facts_mapping_v2[key]]
         ipv4s = []
@@ -397,14 +397,14 @@
         host_info['ip_addresses'] = ';'.join(ipv4s)
         host_info['ipv6_addresses'] = ';'.join(ipv6s)
     if 'virtual_host' in sysdata and sysdata['virtual_host']:
-        for key in _sysdata_virtual_host_mapping.keys():
+        for key in list(_sysdata_virtual_host_mapping.keys()):
             if _sysdata_virtual_host_mapping[key] in sysdata['virtual_host']:
                 host_info[key] = sysdata['virtual_host'][_sysdata_virtual_host_mapping[key]]
     if 'virtual_guests' in sysdata and sysdata['virtual_guests']:
         host_info['virtual_guests'] = ','.join([x['name'] for x in sysdata['virtual_guests']])
         host_info['num_virtual_guests'] = len(sysdata['virtual_guests'])
     if 'subscription_facet_attributes' in sysdata and sysdata['subscription_facet_attributes'] and 'virtual_host' in sysdata['subscription_facet_attributes'] and sysdata['subscription_facet_attributes']['virtual_host']:
-        for key in _sysdata_virtual_host_mapping.keys():
+        for key in list(_sysdata_virtual_host_mapping.keys()):
             if _sysdata_virtual_host_mapping[key] in sysdata['subscription_facet_attributes']['virtual_host']:
                 host_info[key] = sysdata['subscription_facet_attributes']['virtual_host'][_sysdata_virtual_host_mapping[key]]
     if 'subscription_facet_attributes' in sysdata and sysdata['subscription_facet_attributes'] and 'virtual_guests' in sysdata['subscription_facet_attributes'] and sysdata['subscription_facet_attributes']['virtual_guests']:
@@ -413,15 +413,15 @@
     if 'subscription_facet_attributes' in sysdata and sysdata['subscription_facet_attributes'] and 'activation_keys' in sysdata['subscription_facet_attributes'] and sysdata['subscription_facet_attributes']['activation_keys']:
         host_info['activation_keys'] = ','.join([x['name'] for x in sysdata['subscription_facet_attributes']['activation_keys']])
     if 'errata_counts' in sysdata and sysdata['errata_counts']:
-        for key in _sysdata_errata_mapping.keys():
+        for key in list(_sysdata_errata_mapping.keys()):
             if _sysdata_errata_mapping[key] in sysdata['errata_counts']:
                 host_info[key] = sysdata['errata_counts'][_sysdata_errata_mapping[key]]
     if 'content_facet_attributes' in sysdata and sysdata['content_facet_attributes'] and 'errata_counts' in sysdata['content_facet_attributes'] and sysdata['content_facet_attributes']['errata_counts']:
-        for key in _sysdata_errata_mapping.keys():
+        for key in list(_sysdata_errata_mapping.keys()):
             if _sysdata_errata_mapping[key] in sysdata['content_facet_attributes']['errata_counts']:
                 host_info[key] = sysdata['content_facet_attributes']['errata_counts'][_sysdata_errata_mapping[key]]
     if hostdata['subtotal'] > 0:
-        for key in _facts_mapping.keys():
+        for key in list(_facts_mapping.keys()):
             if _facts_mapping[key] in sysdata['facts']:
                 host_info[key] = hostdata['results'][system['name']][_sysdata_facts_mapping[key]]
     if ('virtual_guests' in sysdata and sysdata['virtual_guests']) or ('subscription_facet_attributes' in sysdata and sysdata['subscription_facet_attributes'] and 'virtual_guests' in sysdata['subscription_facet_attributes'] and sysdata['subscription_facet_attributes']['virtual_guests']):
@@ -443,10 +443,10 @@
         sysdetailedurl = "https://" + satellite + "/katello/api/v2/systems/" + system["uuid"] + "?fields=full"
         subdetailedurl = "https://" + satellite + "/katello/api/v2/systems/" + system["uuid"] + "/subscriptions"
     if VERBOSE:
-        print "=" * 80
-        print "[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, sysdetailedurl)
-        print "[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, subdetailedurl)
-        print "[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, hostdetailedurl)
+        print("=" * 80)
+        print("[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, sysdetailedurl))
+        print("[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, subdetailedurl))
+        print("[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, hostdetailedurl))
 
     hostdata = {'subtotal': 0}
 
@@ -454,50 +454,50 @@
         base64string = base64.encodestring('%s:%s' % (login, password)).strip()
 
         try:
-            sysinfo = urllib2.Request(sysdetailedurl)
+            sysinfo = urllib.request.Request(sysdetailedurl)
             sysinfo.add_header("Authorization", "Basic %s" % base64string)
-            sysresult = urllib2.urlopen(sysinfo)
+            sysresult = urllib.request.urlopen(sysinfo)
             sysdata = json.load(sysresult)
-        except urllib2.HTTPError:
+        except urllib.error.HTTPError:
             sysdata = system
 
         try:
-            subinfo = urllib2.Request(subdetailedurl)
+            subinfo = urllib.request.Request(subdetailedurl)
             subinfo.add_header("Authorization", "Basic %s" % base64string)
-            subresult = urllib2.urlopen(subinfo)
+            subresult = urllib.request.urlopen(subinfo)
             subdata = json.load(subresult)
-        except urllib2.HTTPError:
+        except urllib.error.HTTPError:
             subdata = {'results': []}
 
         if 'type' in sysdata and sysdata['type'] != 'Hypervisor':
             # skip fetching facts for Hypervisors, they do not submit them anyways
-            hostinfo = urllib2.Request(hostdetailedurl)
+            hostinfo = urllib.request.Request(hostdetailedurl)
             hostinfo.add_header("Authorization", "Basic %s" % base64string)
-            hostresult = urllib2.urlopen(hostinfo)
+            hostresult = urllib.request.urlopen(hostinfo)
             hostdata = json.load(hostresult)
 
         if DEBUG:
             filename = orgname + '_' + system['name'] + '_system-output.json'
-            print "[%sDEBUG%s] System output in -> %s " % (error_colors.OKBLUE, error_colors.ENDC, filename)
+            print("[%sDEBUG%s] System output in -> %s " % (error_colors.OKBLUE, error_colors.ENDC, filename))
             with open(filename, 'w') as outfile:
                 json.dump(sysdata, outfile)
             outfile.close()
             filename = orgname + '_' + system['name'] + '_subscription-output.json'
-            print "[%sDEBUG%s] Subscription output in -> %s " % (error_colors.OKBLUE, error_colors.ENDC, filename)
+            print("[%sDEBUG%s] Subscription output in -> %s " % (error_colors.OKBLUE, error_colors.ENDC, filename))
             with open(filename, 'w') as outfile:
                 json.dump(subdata, outfile)
             outfile.close()
             filename = orgname + '_' + system['name'] + '_system-facts.json'
-            print "[%sDEBUG%s] Facts output in -> %s " % (error_colors.OKBLUE, error_colors.ENDC, filename)
+            print("[%sDEBUG%s] Facts output in -> %s " % (error_colors.OKBLUE, error_colors.ENDC, filename))
             with open(filename, 'w') as outfile:
                 json.dump(hostdata, outfile)
             outfile.close()
-    except Exception, e:
-        print "Error - %s" % (e)
+    except Exception as e:
+        print("Error - %s" % (e))
 
     host_info = {}
     fake = ['software_channel', 'configuration_channel', 'system_group', 'amount', 'entitlement', 'entitlements', 'organization', 'account_number', 'contract_number', 'start_date', 'end_date', 'hypervisor', 'virtual', 'compliant', 'ip_addresses', 'ipv6_addresses', 'num_virtual_guests', 'virtual_guests', 'activation_keys', 'derived_entitlement']
-    for key in _sysdata_mapping.keys() + _sysdata_facts_mapping.keys() + _sysdata_virtual_host_mapping.keys() + _sysdata_errata_mapping.keys() + _facts_mapping.keys() + fake:
+    for key in list(_sysdata_mapping.keys()) + list(_sysdata_facts_mapping.keys()) + list(_sysdata_virtual_host_mapping.keys()) + list(_sysdata_errata_mapping.keys()) + list(_facts_mapping.keys()) + fake:
         host_info[key] = 'unknown'
 
     # it's possible a server does not have an entitlement applied to it so we need to check for this and skip if not.
@@ -525,11 +525,11 @@
             host_info['end_date'] = entitlement['end_date']
             host_info['hypervisor'] = "NA"
             virtual = "NA"
-            if entitlement.has_key('host'):
+            if 'host' in entitlement:
                 host_info['hypervisor'] = entitlement['host']['id']
                 host_info['virtual'] = 'virtual'
             host_info['compliant'] = "NA"
-            if sysdata.has_key('compliance'):
+            if 'compliance' in sysdata:
                 host_info['compliant'] = sysdata['compliance']['compliant']
                 if not host_info['compliant']:
                     incompliant[system['uuid']] = system['name']
@@ -547,9 +547,9 @@
                 sub_summary[subName][virtual] = host_info['amount']
 
             if VERBOSE:
-                print json.dumps(host_info, sort_keys = False, indent = 2)
-                print "=" * 80
-                print
+                print(json.dumps(host_info, sort_keys = False, indent = 2))
+                print("=" * 80)
+                print()
 
             row = [host_info[x] for x in columns]
             csv_writer_subs.writerow(row)
@@ -562,21 +562,21 @@
         report_sysdata()
 
         if VERBOSE:
-            print json.dumps(host_info, sort_keys = False, indent = 2)
-            print "=" * 80
-            print
+            print(json.dumps(host_info, sort_keys = False, indent = 2))
+            print("=" * 80)
+            print()
 
         row = [host_info[x] for x in columns]
         csv_writer_subs.writerow(row)
 
-print "\nSubscription Usage Summary:"
+print("\nSubscription Usage Summary:")
 for subscription in sub_summary:
-    print "%s -->" % subscription
+    print("%s -->" % subscription)
     for virtual in sub_summary[subscription]:
-        print "\t%s\t- %s" % (virtual,sub_summary[subscription][virtual])
+        print("\t%s\t- %s" % (virtual,sub_summary[subscription][virtual]))
 
 if len (incompliant) > 0:
-    print "\nThere are %s incompliant systems:" % len(incompliant)
-    print "\t\tUUID\t\t\t\tName"
+    print("\nThere are %s incompliant systems:" % len(incompliant))
+    print("\t\tUUID\t\t\t\tName")
     for system in incompliant:
-        print "%s\t- %s" % (system, incompliant[system])
+        print("%s\t- %s" % (system, incompliant[system]))
