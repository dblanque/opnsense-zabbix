<a href='https://ko-fi.com/E1E2YQ4TG' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>

## Introduction
Out of pure personal need I adapted **R. Bicelli's** _pfSense Zabbix Template_ after the recent Home+Lab License Issue *encouraged* me to migrate to OPNSense.
This is not yet completely tested in all regards and some keys and functionalities may have errors.

I mostly centered myself on fixing OpenVPN monitoring and basic keys support. Feel free to contribute!

Original Zabbix pfSense Template by **R. Bicelli**
<https://github.com/rbicelli/pfsense-zabbix-template>

* 2024-02-01: Fix for OPNSense 24.1 `get_interfaces_info()` function deprecation was implemented. The templates were also updated with new item key implementations for the Network Interfaces.
* 2024-04-29:
	* Fixed Individual Gateway Status support.
	* Fixed OpenVPN Server Data Fetching to support both *Legacy* and *MVC* Instances.
	* Renamed all function prefixes from *pfz_* to *opnf_*.
	* Minor fixes to further implement IPSec (Both Strongswan and Legacy instances) detection and status reporting, not tested.
	* Other minor fixes.

*Tested on Zabbix 6.0 LTS*

## Functionalities

### Tested
* Service Discovery
* OpenVPN Server Discovery and Statistics
* OpenVPN Server Clients Discovery
* All default FreeBSD Items
* Network Statistics
* Gateway Discovery

### Added
* P2P TLS OpenVPN Server Remote Address Item Monitoring

## Known Issues, or untested
* OPNSense OpenVPN Clients (as in site to site clients) may not be discovered correctly yet.
* DHCP Lease Functions *probably* don't work.
* **IPSec Functions are untested**.
* **CARP Functions are untested**.

## Installation

### OPNSense Configuration
First you need to download the PHP Script onto your OPNSense.
Login with SSH and execute the following command:

`curl --create-dirs -o /root/scripts/opnsense_zbx.php https://raw.githubusercontent.com/dblanque/opnsense-zabbix/main/opnsense_zbx.php`

### Zabbix Configuration

To enable this template you must add the following custom keys in the Zabbix Service Configuration.
`Services → Zabbix Agent → Settings`

You may also copy paste it into the config file:
`/usr/local/etc/zabbix_agentd.conf`

```
UserParameter=opnsense.mbuf.current,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f1
UserParameter=opnsense.mbuf.cache,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f2
UserParameter=opnsense.mbuf.max,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f4
UserParameter=opnsense.discovery[*],sudo /usr/local/bin/php /root/scripts/opnsense_zbx.php discovery $1
UserParameter=opnsense.interfaces[*],sudo /usr/local/bin/php /root/scripts/opnsense_zbx.php interfaces $1
UserParameter=opnsense.value[*],sudo /usr/local/bin/php /root/scripts/opnsense_zbx.php $1 $2 $3
UserParameter=opnsense.states.max,grep "limit states" /tmp/rules.limits | cut -f4 -d ' '
UserParameter=opnsense.states.current,sudo /usr/local/bin/php /root/scripts/opnsense_zbx.php states
```

You may also enable Root by allowing it in the Zabbix Settings and add the keys on the *Advanced* tab.

![opnsense_zbx_01](https://github.com/dblanque/opnsense-zabbix/assets/68660667/9fd17b20-3c7c-4a09-a816-9e422137d1c6)

Do not forget to add the **Zabbix Server** or **Zabbix Proxy** *IP Address* to your 
**Active Check Servers** Field in the `Zabbix Features` tab as well as your
**Zabbix Servers** field in the `Main Settings` tab.

### Enable System Version Cron

Please add the following cronjob to your `/etc/cron.d/opnsense_sysversion`

```
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
0 9,21	* * *	root	sudo /usr/local/bin/php /root/scripts/opnsense_zbx.php sysversion_cron
```

Then restart cron with `/etc/rc.d/cron restart`

### Et Voilá

Happy monitoring!

![opnsense_zbx_02](https://github.com/dblanque/opnsense-zabbix/assets/68660667/d801d0b8-2b48-4b0e-b494-a6478123ce3e)
