# OPNSense Template for Zabbix

To enable this template you must add the following custom keys in the Zabbix Service Configuration.
`Services → Zabbix Agent → Settings`

You may also copy paste it into the config file:
`/usr/local/etc/zabbix_agentd.conf`

UserParameter=opnsense.mbuf.current,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f1
UserParameter=opnsense.mbuf.cache,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f2
UserParameter=opnsense.mbuf.max,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f4
UserParameter=opnsense.discovery[*],/usr/local/bin/php /root/scripts/opnsense_zbx.php discovery $1
UserParameter=opnsense.value[*],/usr/local/bin/php /root/scripts/opnsense_zbx.php $1 $2 $3
UserParameter=opnsense.states.max,grep "limit states" /tmp/rules.limits | cut -f4 -d ' '
UserParameter=opnsense.states.current,/usr/local/bin/php /root/scripts/opnsense_zbx.php states

You must also enable Root by changing `AllowRoot=0` to `AllowRoot=1` manually in the configuration file,
located in `/usr/local/etc/zabbix_agentd.conf`.

# Enable System Version Cron

To enable system version update checks, execute the following command in your console:
`/usr/local/bin/php /root/scripts/opnsense_zbx.php sysversion_cron`

# Cleanup Cron Jobs

To cleanup the cronjob:
`/usr/local/bin/php /root/scripts/opnsense_zbx.php cron_cleanup`