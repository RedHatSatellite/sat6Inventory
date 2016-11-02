# Overview
Given a username, password & organization, inventory Satellite 6 and return a report
of the registered systems, which subscriptions cover them and which hardware facts that they have

# Requirements

* Python >= 2.6
* Satellite >= 6.1.x
* **OPTIONAL** - PyYAML. If PyYAML is installed, the script will attempt to read `/etc/hammer/cli.modules.d/foreman.yml` and `~/.hammer/cli_config.yml` to derive the correct username, password, and host to connect to. If PyYAML is not present, the script will require the parameters to be provided explicitly.

# Usage

~~~
↪ ./sat6Inventory.py -s satellite.example.com -l admin -o 'Example'
~~~

# Help Output

~~~
↪ ./sat6Inventory.py --help
Usage: sat6Inventory.py [options]

Options:
  -h, --help            show this help message and exit
  -l LOGIN, --login=LOGIN
                        Login user
  -p PASSWORD, --password=PASSWORD
                        Password for specified user. Will prompt if omitted
  -s SATELLITE, --satellite=SATELLITE
                        FQDN of Satellite - omit https://
  -o ORGID, --orgid=ORGID
                        Label of the Organization in Satellite that is to be
                        queried
  -v, --verbose         Verbose output
  -d, --debug           Debugging output (debug output enables verbose)
  -c COLUMNS, --columns=COLUMNS
                        coma separated list of columns to add to the output
  -f FORMAT, --format=FORMAT
                        use an predefined output format (available formats:
                        spacewalk-report-inventory-customized, original,
                        spacewalk-report-inventory)
  -S SEARCH, --search=SEARCH
                        limit report to machines matching this search
~~~
# Notes

* The script will prompt for password if not provided
* The **https_proxy** environmental variable, if set, will be used to connect via a proxy

# Example Output

When run without the -v/--verbose OR -d/--debug switches, sat6Inventory.py has no output,
suitable for a cron script.  Results are stored in $ORG_inventory_report.csv, where $ORG
represents your Organization's Name

When run with the -v/--verbose switch, sat6Inventory.py outputs the URLs used for the various
API calls and the parsed output for each system inventoried

~~~
↪ ./sat6Inventory.py -s satellite.example.com -l admin -o 'Example' -v
================================================================================
[VERBOSE] Connecting to -> https://satellite.example.com/katello/api/v2/systems?full=true
[VERBOSE] Data will be written to Example_inventory_report.csv
================================================================================

================================================================================
[VERBOSE] Connecting to -> https://satellite.example.com/katello/api/v2/systems/b5ddda0c-4331-491c-af44-1c855f886ccd/subscriptions
[VERBOSE] Connecting to -> https://satellite.example.com/api/v2/hosts/virtmgmt.example.com/facts?per_page=99999
	System Name - virtmgmt.example.com
	Subscription Name - Red Hat Enterprise Linux Server, Premium (Physical or Virtual Nodes)
	Amount - 2
	Account Number - 1234567
	Contract Number - 10010110
	Start Date - 2015-08-05
	End Date - 2016-08-05
	BIOS Vendor - American Megatrends Inc.
	BIOS Version - V10.6
	BIOS Release Date - 04/27/2011
	BIOS manufacturer - MSI
	Product Name - MS-7623
	Serial Number - To Be Filled By O.E.M.
	UUID - 00000000-0000-0000-0000-8C89A52DA606
	Board Manufacturer - MSI
	Type - Desktop
	Board Serial Number - To be filled by O.E.M.
	Board Product Name - NA
================================================================================

~~~

When run with the -d/--debug switch, in addition to the verbose output above, sat6Inventory.py
outputs debugging information. Additionally, the response to ALL API calls are saved to the
directory where sat6Inventory.py is invoked from.

~~~
↪ ./sat6Inventory.py -s satellite.example.com -l admin -o 'Example' -d
================================================================================
[DEBUG] LOGIN -> admin
[DEBUG] PASSWORD -> <REDACTED>
[DEBUG] SATELLITE -> satellite.example.com
[DEBUG] ORG ID -> Example
================================================================================
[VERBOSE] Connecting to -> https://satellite.example.com/katello/api/v2/systems?full=true
[VERBOSE] Data will be written to Example_inventory_report.csv
================================================================================
[VERBOSE] Connecting to -> https://satellite.example.com/katello/api/v2/systems/b5ddda0c-4331-491c-af44-1c855f886ccd/subscriptions
[VERBOSE] Connecting to -> https://satellite.example.com/api/v2/hosts/virtmgmt.example.com/facts?per_page=99999
[DEBUG] System output in -> Example_virtmgmt.example.com_system-output.json
[DEBUG] System output in -> Example_virtmgmt.example.com_system-facts.json
    System Name - virtmgmt.example.com
    Subscription Name - Red Hat Enterprise Linux Server, Premium (Physical or Virtual Nodes)
    Amount - 2
    Account Number - 1234567
    Contract Number - 10010110
    Start Date - 2015-08-05
    End Date - 2016-08-05
    BIOS Vendor - American Megatrends Inc.
    BIOS Version - V10.6
    BIOS Release Date - 04/27/2011
    BIOS manufacturer - MSI
    Product Name - MS-7623
    Serial Number - To Be Filled By O.E.M.
    UUID - 00000000-0000-0000-0000-8C89A52DA606
    Board Manufacturer - MSI
    Type - Desktop
    Board Serial Number - To be filled by O.E.M.
    Board Product Name - NA
~~~
