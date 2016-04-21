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

_sysdata_mapping = {
    'uuid': 'uuid',
    'hostname': 'name',
    'registered_by': 'registered_by',
    'registration_time': 'created',
    'last_checkin_time': 'checkin_time',
    'katello_agent_installed': 'katello_agent_installed',
}

_sysdata_facts_mapping = {
    'ip_address': 'network.ipv4_address',
    'ipv6_address': 'network.ipv6_address',
    'virt_type': 'virt.host_type',
    'kernel_version': 'uname.release',
    'architecture': 'uname.machine',
    'is_virtualized': 'virt.is_guest',
    'cores': 'cpu.cpu(s)',
    'num_sockets': 'cpu.cpu_socket(s)',
}

_sysdata_virtual_host_mapping = {
    'virtual_host': 'uuid',
    'virtual_host_name': 'name',
}
_sysdata_errata_mapping = {
    'errata_out_of_date': 'total',
    'packages_out_of_date': 'total',
}

_facts_mapping = {
    'biosvendor': 'bios_vendor',
    'biosversion': 'bios_version',
    'biosreleasedate': 'bios_release_date',
    'manufacturer': 'manufacturer',
    'productname': 'productname',
    'serialnumber': 'serialnumber',
    'systemuuid': 'uuid',
    'boardmanufacturer': 'boardmanufacturer',
    'systype': 'type',
    'boardserialnumber': 'boardserialnumber',
    'boardproductname': 'boardproductname',
    'memorysize': 'memorysize',
    'virtual': 'virtual',
    'osfamiliy': 'osfamiliy',
    'operatingsystem': 'operatingsystem',
}

_title_mapping = {
    'uuid': 'UUID',
    'hostname': 'Name',
    'registered_by': 'registered by',
    'registration_time': 'registration time',
    'last_checkin_time': 'last checkin time',
    'katello_agent_installed': 'Katello agent installed',
    'ip_address': 'IPv4 Address',
    'ipv6_address': 'IPv6 Address',
    'virt_type': 'Virt Type',
    'kernel_version': 'Kernel version',
    'architecture': 'Architecture',
    'is_virtualized': 'is virtualized',
    'cores': 'Cores',
    'num_sockets': 'Phys CPU Count',
    'virtual_host': 'Virtual Host UUID',
    'virtual_host_name': 'Virtual Host Name',
    'errata_out_of_date': 'Errata out of date',
    'packages_out_of_date': 'Packages out of date',
    'biosvendor': 'BIOS vendor',
    'biosversion': 'BIOS version',
    'biosreleasedate': 'BIOS release data',
    'manufacturer': 'manufacturer',
    'productname': 'product name',
    'serialnumber': 'serialnumber',
    'systemuuid': 'System UUD',
    'boardmanufacturer': 'board manufacturer',
    'systype': 'System type',
    'boardserialnumber': 'board serialnumber',
    'boardproductname': 'board productname',
    'memorysize': 'memory size',
    'virtual': 'virtual',
    'osfamiliy': 'osfamiliy',
    'operatingsystem': 'operatingsystem',
    'entitlements': 'Subscription Name',
    'software_channel': 'Software Channel',
    'configuration_channel': 'Configuration Channel',
    'system_group': 'System group',
    'organization': 'Organization',
    'hardware': 'Hardware',
}


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

systemdata = []

try:
    page = 0
    per_page = 100
    while (page == 0 or int(jsonresult['per_page']) == len(jsonresult['results'])):
        page += 1
        url = "https://" + satellite + "/katello/api/v2/systems?page=" + str(page) + "&per_page=" + str(per_page)
        request = urllib2.Request(url)
        if VERBOSE:
            print "=" * 80
            print "[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, url)
        base64string = base64.encodestring('%s:%s' % (login, password)).strip()
        request.add_header("Authorization", "Basic %s" % base64string)
        result = urllib2.urlopen(request)
        jsonresult = json.load(result)
        systemdata += jsonresult['results']

except urllib2.URLError, e:
    print "Error: cannot connect to the API: %s" % (e)
    print "Check your URL & try to login using the same user/pass via the WebUI and check the error!"
    sys.exit(1)
except Exception, e:
    print "FATAL Error - %s" % (e)
    sys.exit(2)

csv_writer_subs = csv.writer(open(orgid + "_inventory_report.csv", "wb"), delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

title_row = ['UUID','Name', 'Compliant', 'Subscription Name', 'Amount',
             'Account #', 'Contract #', 'Start Date', 'End Date',
             'Phys CPU Count', 'Cores', 'Virtual', 'Hypervisor', 'OS Family',
             'Operating System', 'BIOS Vendor', 'BIOS Version',
             'BIOS Release Date', 'System Manufacturer', 'System Product Name',
             'Serial Number', 'Board UUID', 'Chassis Manufacturer', 'Type',
             'Chassis Serial #', 'Chassis Product Name']
columns = ['uuid', 'hostname', 'ip_address', 'ipv6_address', 'registered_by', 'registration_time', 'last_checkin_time', 'kernel_version', 'packages_out_of_date', 'errata_out_of_date', 'software_channel', 'configuration_channel', 'entitlements', 'system_group', 'organization', 'virtual_host', 'virtual_host_name', 'architecture', 'is_virtualized', 'virt_type', 'katello_agent_installed', 'hardware']
title_row = [_title_mapping[x] for x in columns]

csv_writer_subs.writerow(title_row)

if VERBOSE:
    print "[%sVERBOSE%s] Data will be written to %s_inventory_report.csv" % (error_colors.OKGREEN, error_colors.ENDC, orgid)



if DEBUG:
    with open(orgid + '_all_systems-output.json', 'w') as outfile:
        json.dump(systemdata, outfile)
    outfile.close()

sub_summary = {}
incompliant = {}

for system in systemdata:
    sysdetailedurl = "https://" + satellite + "/katello/api/v2/systems/" + system["uuid"] + "?fields=full"
    subdetailedurl = "https://" + satellite + "/katello/api/v2/systems/" + system["uuid"] + "/subscriptions"
    hostdetailedurl = "https://" + satellite + "/api/v2/hosts/" + system["name"] + "/facts?per_page=99999"

    if VERBOSE:
        print "=" * 80
        print "[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, sysdetailedurl)
        print "[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, subdetailedurl)
        print "[%sVERBOSE%s] Connecting to -> %s " % (error_colors.OKGREEN, error_colors.ENDC, hostdetailedurl)
    try:
        base64string = base64.encodestring('%s:%s' % (login, password)).strip()

        sysinfo = urllib2.Request(sysdetailedurl)
        sysinfo.add_header("Authorization", "Basic %s" % base64string)
        sysresult = urllib2.urlopen(sysinfo)
        sysdata = json.load(sysresult)

        subinfo = urllib2.Request(subdetailedurl)
        subinfo.add_header("Authorization", "Basic %s" % base64string)
        subresult = urllib2.urlopen(subinfo)
        subdata = json.load(subresult)

        if 'type' in sysdata and sysdata['type'] == 'Hypervisor':
            # skip fetching facts for Hypervisors, they do not submit them anyways
            hostdata = {'subtotal': 0}
        else:
            hostinfo = urllib2.Request(hostdetailedurl)
            hostinfo.add_header("Authorization", "Basic %s" % base64string)
            hostresult = urllib2.urlopen(hostinfo)
            hostdata = json.load(hostresult)

        if DEBUG:
            filename = orgid + '_' + system['uuid'] + '_system-output.json'
            print "[%sDEBUG%s] System output in -> %s " % (error_colors.OKBLUE, error_colors.ENDC, filename)
            with open(filename, 'w') as outfile:
                json.dump(sysdata, outfile)
            outfile.close()
            filename = orgid + '_' + system['uuid'] + '_subscription-output.json'
            print "[%sDEBUG%s] Subscription output in -> %s " % (error_colors.OKBLUE, error_colors.ENDC, filename)
            with open(filename, 'w') as outfile:
                json.dump(subdata, outfile)
            outfile.close()
            filename = orgid + '_' + system['uuid'] + '_system-facts.json'
            print "[%sDEBUG%s] Facts output in -> %s " % (error_colors.OKBLUE, error_colors.ENDC, filename)
            with open(filename, 'w') as outfile:
                json.dump(hostdata, outfile)
            outfile.close()
    except Exception, e:
        print "FATAL Error - %s" % (e)
    for entitlement in subdata["results"]:
        # Get the Amount of subs
        amount = entitlement['amount']
        subName = entitlement['product_name']
        acctNumber = entitlement['account_number']
        contractNumber = entitlement['contract_number']
        startDate = entitlement['start_date']
        endDate = entitlement['end_date']
        hypervisor = "NA"
        virtual = "NA"
        if entitlement.has_key('host'):
            hypervisor = entitlement['host']['id']
            virtual = 'virtual'
        compliant = "NA"
        if sysdata.has_key('compliance'):
            compliant = sysdata['compliance']['compliant']
            if not compliant:
                incompliant[system['uuid']] = system['name']

        host_info = {}
        fake = ['software_channel', 'configuration_channel', 'system_group']
        for key in _sysdata_mapping.keys() + _sysdata_facts_mapping.keys() + _sysdata_virtual_host_mapping.keys() + _sysdata_errata_mapping.keys() + _facts_mapping.keys() + fake:
            host_info[key] = 'unknown'

        for key in _sysdata_mapping.keys():
            if _sysdata_mapping[key] in sysdata:
                host_info[key] = sysdata[_sysdata_mapping[key]]

        if 'facts' in sysdata and sysdata['facts']:
            for key in _sysdata_facts_mapping.keys():
                if _sysdata_facts_mapping[key] in sysdata['facts']:
                    host_info[key] = sysdata['facts'][_sysdata_facts_mapping[key]]

        if 'virtual_host' in sysdata and sysdata['virtual_host']:
            for key in _sysdata_virtual_host_mapping.keys():
                if _sysdata_virtual_host_mapping[key] in sysdata['virtual_host']:
                    host_info[key] = sysdata['virtual_host'][_sysdata_virtual_host_mapping[key]]

        if 'errata_counts' in sysdata and sysdata['errata_counts']:
            for key in _sysdata_errata_mapping.keys():
                if _sysdata_errata_mapping[key] in sysdata['errata_counts']:
                    host_info[key] = sysdata['errata_counts'][_sysdata_errata_mapping[key]]

        if hostdata['subtotal'] > 0:
            for key in _facts_mapping.keys():
                if _facts_mapping[key] in sysdata['facts']:
                    host_info[key] = hostdata['results'][system['name']][_sysdata_facts_mapping[key]]


        if 'virtual_guests' in sysdata and sysdata['virtual_guests']:
            virtual = 'hypervisor'
        if not subName in sub_summary:
            sub_summary[subName] = {}
        if virtual in sub_summary[subName]:
            sub_summary[subName][virtual] += amount
        else:
            sub_summary[subName][virtual] = amount
        host_info['hardware'] = "%s CPUs %s Sockets" % (host_info['cores'], host_info['num_sockets'])
        host_info['entitlements'] = subName
        host_info['organization'] = orgid

        if VERBOSE:
            print json.dumps(host_info, sort_keys = False, indent = 2)
            print "=" * 80
            print

        row = [host_info[x] for x in columns]
        csv_writer_subs.writerow(row)

print "\nSubscription Usage Summary:"
for subscription in sub_summary:
    print "%s -->" % subscription
    for virtual in sub_summary[subscription]:
        print "\t%s\t- %s" % (virtual,sub_summary[subscription][virtual])

if len (incompliant) > 0:
    print "\nThere are %s incompliant systems:" % len(incompliant)
    print "\t\tUUID\t\t\t\tName"
    for system in incompliant:
        print "%s\t- %s" % (system, incompliant[system])
