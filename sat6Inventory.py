#!/usr/bin/env python

# File: sat6Inventory.py
# Author: Rich Jerrido <rjerrido@outsidaz.org>
# Purpose: Given a username, password & organization, inventory
#          Satellite 6 and return a report
#          of the registered systems, which suscriptions cover them
#          and which hardware facts that they have.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import json
import getpass
import urllib2
import base64
import sys
import ssl
import csv
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-l", "--login", dest="login", help="Login user", metavar="LOGIN")
parser.add_option("-p", "--password", dest="password", help="Password for specified user. Will prompt if omitted", metavar="PASSWORD")
parser.add_option("-s", "--satellite", dest="satellite", help="FQDN of Satellite - omit https://", metavar="SATELLITE")
parser.add_option("-o", "--orgid",  dest="orgid", help="Label of the Organization in Satellite that is to be queried", metavar="ORGID")
parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")
parser.add_option("-d", "--debug", dest="debug", action="store_true", help="Debugging output (debug output enables verbose)")
(options, args) = parser.parse_args()


class error_colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

if not (options.login and options.satellite and options.orgid):
    print "Must specify login, server, and orgid options.  See usage:"
    parser.print_help()
    print "\nExample usage: ./sat6Inventory.py -l admin -s satellite.example.com -o ACME_Corporation"
    sys.exit(1)
else:
    login = options.login
    password = options.password
    satellite = options.satellite
    orgid = options.orgid

if not password:
    password = getpass.getpass("%s's password:" % login)

if options.debug:
    DEBUG = True
    VERBOSE = True
    print "[%sDEBUG%s] LOGIN -> %s " % (error_colors.OKBLUE, error_colors.ENDC, login)
    print "[%sDEBUG%s] PASSWORD -> %s " % (error_colors.OKBLUE, error_colors.ENDC, password)
    print "[%sDEBUG%s] SATELLITE -> %s " % (error_colors.OKBLUE, error_colors.ENDC, satellite)
    print "[%sDEBUG%s] ORG ID -> %s " % (error_colors.OKBLUE, error_colors.ENDC, orgid)
else:
    DEBUG = False
    VERBOSE = False

if options.verbose:
    VERBOSE = True

if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context


url = "https://" + satellite + "/katello/api/v2/systems?full=true"

try:
    request = urllib2.Request(url)
    if VERBOSE:
        print "=" * 80
        print "[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, url)
    base64string = base64.encodestring('%s:%s' % (login, password)).strip()
    request.add_header("Authorization", "Basic %s" % base64string)
    result = urllib2.urlopen(request)
except urllib2.URLError, e:
    print "Error: cannot connect to the API: %s" % (e)
    print "Check your URL & try to login using the same user/pass via the WebUI and check the error!"
    sys.exit(1)
except Exception, e:
    print "FATAL Error - %s" % (e)
    sys.exit(2)

csv_writer_subs = csv.writer(open(orgid + "_inventory_report.csv", "wb"), delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

title_row = ['Name', 'Subscription Name', 'Amount', 'Account #', 'Contract #',
             'Start Date', 'End Date', 'BIOS Vendor', 'BIOS Version',
             'BIOS Release Date', 'System Manufacturer', 'System Product Name',
             'Serial Number', 'UUID', 'Chassis Manufacturer', 'Type',
             'Chassis Serial #', 'Chassis Product Name']

csv_writer_subs.writerow(title_row)

if VERBOSE:
    print "[%sVERBOSE%s] Data will be written to %s_inventory_report.csv" % (error_colors.OKGREEN, error_colors.ENDC, orgid)

systemdata = json.load(result)


if DEBUG:
    with open(orgid + '_all_systems-output.json', 'w') as outfile:
        json.dump(systemdata, outfile)

for system in systemdata["results"]:
    detailedurl = "https://" + satellite + "/katello/api/v2/systems/" + system["uuid"] + "/subscriptions"
    hostdetailedurl = "https://" + satellite + "/api/v2/hosts/" + system["name"] + "/facts?per_page=99999"

    if VERBOSE:
        print "=" * 80
        print "[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, detailedurl)
        print "[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, hostdetailedurl)
    try:
        sysinfo = urllib2.Request(detailedurl)
        hostinfo = urllib2.Request(hostdetailedurl)
        base64string = base64.encodestring('%s:%s' % (login, password)).strip()
        sysinfo.add_header("Authorization", "Basic %s" % base64string)
        sysresult = urllib2.urlopen(sysinfo)
        hostinfo.add_header("Authorization", "Basic %s" % base64string)
        hostresult = urllib2.urlopen(hostinfo)
        sysdata = json.load(sysresult)
        hostresult = urllib2.urlopen(hostinfo)
        hostdata = json.load(hostresult)
        if DEBUG:
            filename = orgid + '_' + system['name'] + '_system-output.json'
            print "[%sDEBUG%s] System output in -> %s " % (error_colors.OKBLUE, error_colors.ENDC, filename)
            with open(filename, 'w') as outfile:
                json.dump(systemdata, outfile)
            outfile.close()
            filename = orgid + '_' + system['name'] + '_system-facts.json'
            print "[%sDEBUG%s] System output in -> %s " % (error_colors.OKBLUE, error_colors.ENDC, filename)
            with open(filename, 'w') as outfile:
                json.dump(hostdata, outfile)
            outfile.close()
    except Exception, e:
        print "FATAL Error - %s" % (e)
    for entitlement in sysdata["results"]:
        # Get the Amount of subs
        amount = entitlement['amount']
        subName = entitlement['product_name']
        acctNumber = entitlement['account_number']
        contractNumber = entitlement['contract_number']
        startDate = entitlement['start_date']
        endDate = entitlement['end_date']
        biosvendor = "NA"
        biosversion = "NA"
        biosreleasedate = "NA"
        manufacturer = "NA"
        productname = "NA"
        serialnumber = "NA"
        uuid = "NA"
        boardmanufacturer = "NA"
        systype = "NA"
        boardserialnumber = "NA"
        boardproductname = "NA"
        billingCode = "NA"
        if hostdata['subtotal'] > 0:
            if 'bios_vendor' in hostdata['results'][system['name']]:
                biosvendor = hostdata['results'][system['name']]['bios_vendor']
            if 'bios_version' in hostdata['results'][system['name']]:
                biosversion = hostdata['results'][system['name']]['bios_version']
            if 'bios_release_date' in hostdata['results'][system['name']]:
                biosreleasedate = hostdata['results'][system['name']]['bios_release_date']
            if 'manufacturer' in hostdata['results'][system['name']]:
                manufacturer = hostdata['results'][system['name']]['manufacturer']
            if 'proudctname' in hostdata['results'][system['name']]:
                productname = hostdata['results'][system['name']]['productname']
            if 'serialnumber' in hostdata['results'][system['name']]:
                serialnumber = hostdata['results'][system['name']]['serialnumber']
            if 'uuid' in hostdata['results'][system['name']]:
                uuid = hostdata['results'][system['name']]['uuid']
            if 'boardmanufacturer' in hostdata['results'][system['name']]:
                boardmanufacturer = hostdata['results'][system['name']]['boardmanufacturer']
            if 'type' in hostdata['results'][system['name']]:
                systype = hostdata['results'][system['name']]['type']
            if 'boardserialnumber' in hostdata['results'][system['name']]:
                boardserialnumber = hostdata['results'][system['name']]['boardserialnumber']
            if 'boardproductname' in hostdata['results'][system['name']]:
                boardproductname = hostdata['results'][system['name']]['boardproductname']

        if VERBOSE:
            print "\tSystem Name - %s" % system['name']
            print "\tSubscription Name - %s" % subName
            print "\tAmount - %s" % amount
            print "\tAccount Number - %s" % acctNumber
            print "\tContract Number - %s" % contractNumber
            print "\tStart Date - %s" % startDate
            print "\tEnd Date - %s" % endDate
            print "\tBIOS Vendor - %s" % biosvendor
            print "\tBIOS Version - %s" % biosversion
            print "\tBIOS Release Date - %s" % biosreleasedate
            print "\tBIOS manufacturer - %s" % manufacturer
            print "\tProduct Name - %s" % productname
            print "\tSerial Number - %s" % serialnumber
            print "\tUUID - %s" % uuid
            print "\tBoard Manufacturer - %s" % boardmanufacturer
            print "\tType - %s" % systype
            print "\tBoard Serial Number - %s" % boardserialnumber
            print "\tBoard Product Name - %s" % boardproductname
            print "=" * 80
            print

        csv_writer_subs.writerow([system['name'], subName, amount, acctNumber, contractNumber,
                                  startDate, endDate, biosvendor, biosversion, biosreleasedate,
                                  manufacturer, productname, serialnumber, uuid, boardmanufacturer,
                                  systype, boardserialnumber, boardproductname])
