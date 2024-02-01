<?php

// Define function if not exists
// ! HOTFIX for OPNSense 24.1
/** Function was removed on commit opnsense/core@4d495ea
 * 	Problem reported by th3voic3, thank you!
 * Git Path: core/src/etc/inc
 * Real Path: /usr/local/etc/inc
**/
if (!function_exists('get_interfaces_info')) {
	function get_interfaces_info($include_unlinked = false)
	{
		global $config;

		$all_intf_details = legacy_interfaces_details();
		$all_intf_stats = legacy_interface_stats();
		$gateways = new \OPNsense\Routing\Gateways();
		$ifup = legacy_interface_listget('up');
		$result = [];
		$interfaces = legacy_config_get_interfaces(['virtual' => false]);
		$known_interfaces = [];
		foreach (array_keys($interfaces) as $ifdescr) {
			$interfaces[$ifdescr]['if'] = get_real_interface($ifdescr);
			if (!empty($interfaces[$ifdescr]['if'])) {
				$known_interfaces[] = $interfaces[$ifdescr]['if'];
			}
			$interfaces[$ifdescr]['ifv6'] = get_real_interface($ifdescr, 'inet6');
			if (!empty($interfaces[$ifdescr]['ifv6'])) {
				$known_interfaces[] = $interfaces[$ifdescr]['ifv6'];
			}
		}
	
		if ($include_unlinked) {
			$unassigned_descr = gettext("Unassigned");
			foreach ($all_intf_details as $if => $ifdata) {
				if (!in_array($if, $known_interfaces)) {
					$interfaces[$if] = ["descr" => $unassigned_descr, "if" => $if, "ifv6" => $if, 'unassigned' => true];
				}
			}
		}
	
		foreach ($interfaces as $ifdescr => $ifinfo) {
			$ifinfo['status'] = in_array($ifinfo['if'], $ifup) ? 'up' : 'down';
			$ifinfo['statusv6'] = in_array($ifinfo['ifv6'], $ifup) ? 'up' : 'down';
	
			/* undesired side effect of legacy_config_get_interfaces() */
			$ifinfo['ipaddr'] = $ifinfo['ipaddrv6'] = null;
	
			if (!empty($all_intf_details[$ifinfo['if']])) {
				if (
					isset($all_intf_details[$ifinfo['if']]['status']) &&
						in_array($all_intf_details[$ifinfo['if']]['status'], array('active', 'running'))
				) {
					$all_intf_details[$ifinfo['if']]['status'] = $ifinfo['status'];
				}
				$ifinfo = array_merge($ifinfo, $all_intf_details[$ifinfo['if']]);
			}
	
			if (!empty($ifinfo['ipv4'])) {
				list ($primary4,, $bits4) = interfaces_primary_address($ifdescr, $all_intf_details);
				if (!empty($primary4)) {
					$ifinfo['ipaddr'] = $primary4;
					$ifinfo['subnet'] = $bits4;
				} else {
					$ifinfo['ipaddr'] = $ifinfo['ipv4'][0]['ipaddr'];
					$ifinfo['subnet'] = $ifinfo['ipv4'][0]['subnetbits'];
				}
			}
	
			if (!empty($all_intf_details[$ifinfo['ifv6']]['ipv6'])) {
				/* rewrite always as it can be a different interface */
				$ifinfo['ipv6'] = $all_intf_details[$ifinfo['ifv6']]['ipv6'];
			} elseif ($ifinfo['if'] != !$ifinfo['ifv6']) {
				/* clear on a mismatch to avoid wrong data here */
				$ifinfo['ipv6'] = [];
			}
	
			if (!empty($ifinfo['ipv6'])) {
				list ($primary6,, $bits6) = interfaces_primary_address6($ifdescr, $all_intf_details);
				if (!empty($primary6)) {
					$ifinfo['ipaddrv6'] = $primary6;
					$ifinfo['subnetv6'] = $bits6;
				}
				foreach ($ifinfo['ipv6'] as $ipv6addr) {
					if (!empty($ipv6addr['link-local'])) {
						$ifinfo['linklocal'] = $ipv6addr['ipaddr'];
					} elseif (empty($ifinfo['ipaddrv6'])) {
						$ifinfo['ipaddrv6'] = $ipv6addr['ipaddr'];
						$ifinfo['subnetv6'] = $ipv6addr['subnetbits'];
					}
				}
	
				$aux = shell_safe('/usr/local/sbin/ifctl -6pi %s', $ifinfo['ifv6']);
				if (!empty($aux)) {
					$ifinfo['prefixv6'] = explode("\n", $aux);
				}
			}
	
			$ifinfotmp = $all_intf_stats[$ifinfo['if']];
			$ifinfo['inbytes'] = $ifinfotmp['bytes received'];
			$ifinfo['outbytes'] = $ifinfotmp['bytes transmitted'];
			$ifinfo['inpkts'] = $ifinfotmp['packets received'];
			$ifinfo['outpkts'] = $ifinfotmp['packets transmitted'];
			$ifinfo['inerrs'] = $ifinfotmp['input errors'];
			$ifinfo['outerrs'] = $ifinfotmp['output errors'];
			$ifinfo['collisions'] = $ifinfotmp['collisions'];
	
			$link_type = $config['interfaces'][$ifdescr]['ipaddr'] ?? 'none';
			switch ($link_type) {
				case 'dhcp':
					$ifinfo['dhcplink'] = isvalidpid("/var/run/dhclient.{$ifinfo['if']}.pid") ? 'up' : 'down';
					break;
				/* PPPoE/PPTP/L2TP interface? -> get status from virtual interface */
				case 'pppoe':
				case 'pptp':
				case 'l2tp':
					if ($ifinfo['status'] == "up") {
						/* XXX get PPPoE link status for dial on demand */
						$ifinfo["{$link_type}link"] = "up";
					} else {
						$ifinfo["{$link_type}link"] = "down";
					}
					break;
				/* PPP interface? -> get uptime for this session and cumulative uptime from the persistent log file in conf */
				case 'ppp':
					if ($ifinfo['status'] == "up") {
						$ifinfo['ppplink'] = "up";
					} else {
						$ifinfo['ppplink'] = "down";
					}
	
					if (empty($ifinfo['status'])) {
						$ifinfo['status'] = "down";
					}
	
					if (isset($config['ppps']['ppp'])) {
						foreach ($config['ppps']['ppp'] as $pppid => $ppp) {
							if ($config['interfaces'][$ifdescr]['if'] == $ppp['if']) {
								break;
							}
						}
					}
					if ($config['interfaces'][$ifdescr]['if'] != $ppp['if'] || empty($ppp['ports'])) {
						break;
					}
					if (!file_exists($ppp['ports'])) {
						$ifinfo['nodevice'] = 1;
						$ifinfo['pppinfo'] = $ppp['ports'] . " " . gettext("device not present! Is the modem attached to the system?");
					}
	
					// Calculate cumulative uptime for PPP link. Useful for connections that have per minute/hour contracts so you don't go over!
					if (isset($ppp['uptime'])) {
						$ifinfo['ppp_uptime_accumulated'] = "(" . get_ppp_uptime($ifinfo['if']) . ")";
					}
					break;
				default:
					break;
			}
	
			if (file_exists("/var/run/{$link_type}_{$ifdescr}.pid")) {
				$sec = intval(shell_safe('/usr/local/opnsense/scripts/interfaces/ppp-uptime.sh %s', $ifinfo['if']));
				if ($sec) {
					$ifinfo['ppp_uptime'] = convert_seconds_to_hms($sec);
				}
			}
	
			switch ($config['interfaces'][$ifdescr]['ipaddrv6'] ?? 'none') {
				case 'dhcp6':
					$ifinfo['dhcp6link'] = isvalidpid('/var/run/dhcp6c.pid') && file_exists("/var/etc/dhcp6c_{$ifdescr}.conf") ? 'up' : 'down';
					break;
				/* XXX more to do here in the future */
				default:
					break;
			}
	
			if ($ifinfo['status'] == "up") {
				$wifconfiginfo = array();
				if (isset($config['interfaces'][$ifdescr]['wireless'])) {
					exec("/sbin/ifconfig {$ifinfo['if']} list sta", $wifconfiginfo);
					array_shift($wifconfiginfo);
				}
				foreach ($wifconfiginfo as $ici) {
					$elements = preg_split("/[ ]+/i", $ici);
					if ($elements[0] != "") {
						$ifinfo['bssid'] = $elements[0];
					}
					if ($elements[3] != "") {
						$ifinfo['rate'] = $elements[3];
					}
					if ($elements[4] != "") {
						$ifinfo['rssi'] = $elements[4];
					}
				}
				$gateway = $gateways->getInterfaceGateway($ifdescr, 'inet');
				if (!empty($gateway)) {
					$ifinfo['gateway'] = $gateway;
				}
				$gatewayv6 = $gateways->getInterfaceGateway($ifdescr, 'inet6');
				if (!empty($gatewayv6)) {
					$ifinfo['gatewayv6'] = $gatewayv6;
				}
			}
	
			$bridge = link_interface_to_bridge($ifdescr);
			if ($bridge) {
				$bridge_text = shell_safe('/sbin/ifconfig %s', $bridge);
				if (stristr($bridge_text, 'blocking') != false) {
					$ifinfo['bridge'] = "<b><span class='text-danger'>" . gettext("blocking") . "</span></b> - " . gettext("check for ethernet loops");
					$ifinfo['bridgeint'] = $bridge;
				} elseif (stristr($bridge_text, 'learning') != false) {
					$ifinfo['bridge'] = gettext("learning");
					$ifinfo['bridgeint'] = $bridge;
				} elseif (stristr($bridge_text, 'forwarding') != false) {
					$ifinfo['bridge'] = gettext("forwarding");
					$ifinfo['bridgeint'] = $bridge;
				}
			}
	
			$result[$ifdescr] = $ifinfo;
		}
	
		return $result;
	}
}

?>