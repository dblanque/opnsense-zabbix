# OPNSense Template for Zabbix

To enable this template you must add the following custom keys in the Zabbix Service Configuration.
`Services → Zabbix Agent → Settings`

You may also copy paste it into the config file:
`/usr/local/etc/zabbix_agentd.conf`

UserParameter=pfsense.mbuf.current,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f1
UserParameter=pfsense.mbuf.cache,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f2
UserParameter=pfsense.mbuf.max,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f4
UserParameter=pfsense.discovery[*],/usr/local/bin/php /root/scripts/opnsense_zbx.php discovery $1
UserParameter=pfsense.value[*],/usr/local/bin/php /root/scripts/opnsense_zbx.php $1 $2 $3
UserParameter=pfsense.states.max,grep "limit states" /tmp/rules.limits | cut -f4 -d ' '
UserParameter=pfsense.states.current,/usr/local/bin/php /root/scripts/opnsense_zbx.php states

You must also enable Root by changing `AllowRoot=0` to `AllowRoot=1` manually in the configuration file,
located in `/usr/local/etc/zabbix_agentd.conf`.
