# OPNSense Template for Zabbix

To enable this template you must add the following custom keys in the Zabbix Service Configuration.
`Services → Zabbix Agent → Settings`

You may also copy paste it into the config file:
`/usr/local/etc/zabbix_agentd.conf`

```
UserParameter=opnsense.mbuf.current,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f1
UserParameter=opnsense.mbuf.cache,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f2
UserParameter=opnsense.mbuf.max,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f4
UserParameter=opnsense.discovery[*],/usr/local/bin/php /root/scripts/opnsense_zbx.php discovery $1
UserParameter=opnsense.value[*],/usr/local/bin/php /root/scripts/opnsense_zbx.php $1 $2 $3
UserParameter=opnsense.states.max,grep "limit states" /tmp/rules.limits | cut -f4 -d ' '
UserParameter=opnsense.states.current,/usr/local/bin/php /root/scripts/opnsense_zbx.php states
```

You must also enable Root by changing `AllowRoot=0` to `AllowRoot=1` manually in the configuration file,
located in `/usr/local/etc/zabbix_agentd.conf`.

# Enable System Version Cron

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
0 9,21	* * *	root	/bin/sh /usr/local/opnsense/scripts/firmware/check.sh
```

Then restart cron with `/etc/rc.d/cron restart`
