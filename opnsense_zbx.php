<?php

/***
opnsense_zbx.php - OPNSense Zabbix Interface
For 25.1.x - 2025-06-20

Original pfSense Template Written by Riccardo Bicelli <r.bicelli@gmail.com>
New OPNSense Modifications by Dylan Blanqué <dylan.blanque@gmail.com>
This program is licensed under Apache 2.0 License
 */

// Some Useful defines

define('CRON_TIME_LIMIT', 300); // Time limit in seconds of speedtest and sysinfo
define('DEFAULT_TIME_LIMIT', 30); // Time limit in seconds otherwise

// Imports
require_once('plugins.inc');
require_once('config.inc');
require_once('util.inc');

// For Interfaces Discovery
require_once('interfaces.inc');

// For OpenVPN Discovery
require_once('plugins.inc.d/openvpn.inc');

// For Wireguard Discovery
require_once('plugins.inc.d/wireguard.inc');

// For System
require_once('system.inc');

require_once("script/load_phalcon.php");


use OPNsense\Core\Config;

function get_mvc_config()
{
	return Config::getInstance()->toArray();
}

function execute_script($prog, $args, $json_decode = false)
{
	$ex = $prog;
	if (is_array($args))
		foreach ($args as $arg)
			$ex .= ' ' . $arg;
	else $ex .= ' ' . $args;
	$command = escapeshellcmd($ex);
	$result = shell_exec($command);
	if ($json_decode == true)
		$result = json_decode($result);
	return $result;
}

function system_get_version()
{
	$prog = "/usr/local/sbin/opnsense-version";
	$arg = "-v";
	return execute_script($prog, $arg);
}

function openvpn_get_connection_statuses($servers_only = true)
{
	$prog = "/usr/local/bin/python3";
	$script = "/usr/local/opnsense/scripts/openvpn/ovpn_status.py";
	$json_decode = true;
	$clients = execute_script($prog, $script, $json_decode);
	if ($servers_only == true) return $clients->server;
	return $clients;
}

function ipsec_get_status()
{
	$prog = "/usr/local/bin/python3";
	$script = "/usr/local/opnsense/scripts/ipsec/list_status.py";
	$json_decode = true;
	return execute_script($prog, $script, $json_decode);
}

function opnf_get_states()
{
	$prog = "/usr/local/bin/python3";
	$script = "/usr/local/opnsense/scripts/filter/list_states.py";
	$json_decode = true;
	return execute_script($prog, $script, $json_decode);
}

function opnf_get_dhcp_leases()
{
	$prog = "/usr/local/bin/python3";
	$script = "/usr/local/opnsense/scripts/dhcp/get_leases.py";
	$json_decode = true;
	return execute_script($prog, $script, $json_decode);
}

function opnf_get_states_count()
{
	return opnf_get_states()->total;
}

function opnf_get_gw_statuses()
{
	// For Gateways
	ob_start();
	require_once("/usr/local/opnsense/scripts/routes/gateway_status.php");
	$gw_status = ob_get_clean();
	return $gw_status;
}

function opnf_get_carp_status()
{
	$prog = "/usr/local/bin/php";
	$script = "/usr/local/opnsense/scripts/interfaces/carp_global_status.php";
	$json_decode = true;
	return execute_script($prog, $script, $json_decode);
}

//Testing function, for template creating purpose
function opnf_test()
{
	$line = "-------------------\n";

	$ovpn_servers = opnf_openvpn_get_all_servers();
	echo "OPENVPN Servers:\n";
	print_r($ovpn_servers);
	echo $line;

	$ovpn_clients = openvpn_get_connection_statuses();
	echo "OPENVPN Clients:\n";
	print_r($ovpn_clients);
	echo $line;

	// ! Deprecated
	echo "Network Interfaces:\n";
	print_r(opnf_interface_discovery());
	echo $line;

	echo "Interface Statistics:\n";
	print_r(legacy_interface_stats());
	echo $line;

	$services = plugins_services();
	echo "Services: \n";
	print_r($services);
	echo $line;

	echo "IPsec: \n";
	require_once("plugins.inc.d/ipsec.inc");
	global $config;
	$config = get_mvc_config();
	$a_phase2 = &$config['ipsec']['phase2'];
	$status = ipsec_get_status();
	echo "IPsec Status: \n";
	print_r($status);

	$a_phase1 = &$config['ipsec']['phase1'];
	$a_phase2 = &$config['ipsec']['phase2'];

	echo "IPsec Config Phase 1: \n";
	print_r($a_phase1);

	echo "IPsec Config Phase 2: \n";
	print_r($a_phase2);

	echo $line;

	//Packages
	echo "Packages: \n";
	require_once("plugins.inc");
	$installed_packages = plugins_scan();
	print_r($installed_packages);
}

// Interface Discovery
function opnf_interface_discovery($is_wan = false, $is_cron = false)
{
	// $ifdescrs = get_configured_interface_with_descr(true);
	$config = get_mvc_config();
	$ifaces = $config['interfaces']; // Keys: Friendly Interface Name
	$ifaces_details = array();
	$ifaces_info = array();
	$ifaces_details = legacy_config_get_interfaces(); // Keys: Friendly Interface Name
	$ifaces_info = legacy_interfaces_details(); // Keys: HW Interface Name
	$ppp_types = ['l2tp', 'pppoe', 'pptp'];
	$json_string = '{"data":[';

	foreach ($ifaces as $if_name => $if_val) {
		// Ignore virtual interfaces
		if (array_key_exists('virtual', $if_val)) continue;

		$eval_if = preg_replace('/[0-9]+/', '', $if_val['if']);
		if (in_array($eval_if, $ppp_types)) {
			if (function_exists("get_ppp_parent")) {
				$hwif = get_ppp_parent($if_val['if']);
			} elseif (function_exists("interface_ppps_hardware")) {
				$hwif = interface_ppps_hardware($if_val['if'])[0];
			}
		} else {
			$hwif = get_real_interface($if_val['if']);
		}
		$if_details = $ifaces_details[$if_name];
		$if_info = $ifaces_info[$if_val['if']];

		$has_gw = false;
		$is_vpn = false;
		$has_public_ip = false;

		if (array_key_exists("gateway", $if_details)) $has_gw = true;
		//	Issue #81 - https://stackoverflow.com/a/13818647/15093007
		$ip_versions = ['ipv4', 'ipv6'];
		foreach ($ip_versions as &$ip_ver) {
			if (!array_key_exists($ip_ver, $if_info)) continue;
			$list_of_ip_lists = $if_info[$ip_ver];
			if (count($list_of_ip_lists) >= 1)
				foreach ($if_info[$ip_ver] as &$ip_addr_list)
					if (filter_var($ip_addr_list['ipaddr'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
						$has_public_ip = true;
						break;
					}
		}
		if (strpos($if_val["if"], "ovpn") !== false) $is_vpn = true;
		if (($is_wan == false) || (($is_wan == true) && (($has_gw == true) || ($has_public_ip == true)) && ($is_vpn == false))) {
			if (strlen($if_details["descr"]) < 1)
				$out_descr = $if_details["if"];
			else
				$out_descr = $if_details["descr"];
			$json_string .= '{"{#IFNAME}":"' . $hwif . '"';
			$json_string .= ',"{#IFDESCR}":"' . $out_descr . '"';
			$json_string .= '},';
		}
	}
	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

function opnf_t_serverdiscovery($T)
{
	$callable = "opnf_${T}_get_all_servers";
	$servers = $callable();

	$json_string = '{"data":[';

	foreach ($servers as $server) {
		$json_string .= '{"{#SERVER}":"' . $server['vpnid'] . '"';
		$json_string .= ',"{#NAME}":"' . $server['description'] . '"';
		$json_string .= '},';
	}

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

// WireGuard Server Discovery
function opnf_wireguard_get_all_servers()
{
	$wg_enabled = ((new OPNsense\Wireguard\General())->enabled);
	$wg_server_ids = wireguard_services();
	$wg_servers = array();
	foreach ((new OPNsense\Wireguard\Server())->servers->server->iterateItems() as $key => $node) {
		$wg_server_instance = array();
		$wg_server_instance['vpnid'] = $key;
		$wg_server_instance['description'] = (string)$node->name;
		if ((bool)$node->enabled)
			array_push($wg_servers, $wg_server_instance);
	}
	return ($wg_servers);
}

// OpenVPN Server Discovery
function opnf_openvpn_get_all_servers()
{
	$ovpn_config = (new \OPNsense\OpenVPN\OpenVPN());
	$ovpn_server_ids = openvpn_services();
	$ovpn_servers = array();
	foreach ($ovpn_server_ids as $index => $ovpn_instance) {
		$ovpn_server_id = $ovpn_instance['id'];
		// ---------------------------------- getInstanceById(server_id,    server_type)
		$ovpn_server_instance = $ovpn_config->getInstanceById($ovpn_server_id, "server");
		if ($ovpn_server_instance)
			array_push($ovpn_servers, $ovpn_server_instance);
	}
	return ($ovpn_servers);
}

// Get OpenVPN Server Value
function opnf_openvpn_servervalue($server_id, $valuekey)
{
	$servers = opnf_openvpn_get_all_servers();
	$clients = openvpn_get_connection_statuses()->$server_id;

	foreach ($servers as $server) {
		if ($server['vpnid'] == $server_id) {
			$value = $server[$valuekey];
			switch ($valuekey) {
				case "status":
					if (($server['mode'] == "server_user") || ($server['mode'] == "server_tls_user") || ($server['mode'] == "server_tls")) {
						if ($value == "") $value = "server_user_listening";
					} else if ($server['mode'] == "p2p_tls") {
						// For p2p_tls, ensure we have one client, and return up if it's the case
						if ($value == "")
							$value = (is_array($server) && $clients->status == "connected") ? "up" : "down";
					}
					break;
				case "port":
					if ($value == "")
						$value = $server['local_port'];
					break;
				case "real_address":
					if (is_null($clients))
						$value = "";
					elseif ($value == "" && property_exists($clients, "real_address"))
						$value = $clients->real_address;
					break;
			}
		}
	}

	switch ($valuekey) {

		case "conns":
			//Client Connections: is an array so it is sufficient to count elements
			if (is_array($clients->client_list))
				$value = count($clients->client_list);
			else if (is_object($clients) && property_exists($clients, "status") && $clients->status == "connected")
				$value = "1";
			else
				$value = "0";
			break;

		case "status":

			$value = opnf_valuemap("openvpn.server.status", $value);
			break;

		case "mode":
			$value = opnf_valuemap("openvpn.server.mode", $value);
			break;
	}

	//if ($value=="") $value="none";
	echo $value;
}

//OpenVPN Server/User-Auth Discovery
function opnf_openvpn_server_userdiscovery()
{
	$servers = opnf_openvpn_get_all_servers();
	$all_clients = openvpn_get_connection_statuses();

	$json_string = '{"data":[';

	foreach ($servers as $server) {
		$server_id = $server['vpnid'];
		if (($server['mode'] == 'server_user') || ($server['mode'] == 'server_tls_user') || ($server['mode'] == 'server_tls')) {
			$clients = $all_clients->$server_id->client_list;
			if (is_array($clients)) {
				$name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $server['description']));
				foreach ($clients as $conn) {
					$common_name = opnf_replacespecialchars($conn->common_name);

					$json_string .= '{"{#SERVERID}":"' . $server_id . '"';
					$json_string .= ',"{#SERVERNAME}":"' . $name . '"';
					$json_string .= ',"{#UNIQUEID}":"' . $server_id . '+' . $common_name . '"';
					$json_string .= ',"{#USERID}":"' . $conn->common_name . '"';
					$json_string .= '},';
				}
			}
		}
	}

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

// Get OpenVPN User Connected Value
function opnf_openvpn_server_uservalue($unique_id, $valuekey, $default = "")
{

	$unique_id = opnf_replacespecialchars($unique_id, true);
	$atpos = strpos($unique_id, '+');
	$server_id = substr($unique_id, 0, $atpos);
	$user_id = substr($unique_id, $atpos + 1);

	$servers = opnf_openvpn_get_all_servers();
	$all_clients = openvpn_get_connection_statuses();
	foreach ($servers as $server) {
		if ($server['vpnid'] == $server_id) {
			$server_id = $server['vpnid'];
			$clients = $all_clients->$server_id->client_list;
			foreach ($clients as $client) {
				if ($client->common_name == $user_id) {
					$value = $client->$valuekey;
					switch ($valuekey) {
						case "username":
							if ($client->$valuekey == "UNDEF") $value = "None";
							break;
					}
				}
			}
		}
	}
	if ($value == "") $value = $default;
	echo $value;
}

// OpenVPN Client Discovery
function opnf_openvpn_clientdiscovery()
{
	$all_clients = openvpn_get_connection_statuses(false);
	$json_string = '{"data":[';

	if (property_exists($all_clients, "client")) {
		$all_clients = $all_clients->client;
		foreach ($all_clients as $client) {
			$name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $client->common_name));
			$json_string .= '{"{#CLIENT}":"' . $client->vpnid . '"';
			$json_string .= ',"{#NAME}":"' . $name . '"';
			$json_string .= '},';
		}
	}

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

function opnf_replacespecialchars($inputstr, $reverse = false)
{
	$specialchars = ",',\",`,*,?,[,],{,},~,$,!,&,;,(,),<,>,|,#,@,0x0a";
	$specialchars = explode(",", $specialchars);
	$resultstr = $inputstr;

	for ($n = 0; $n < count($specialchars); $n++) {
		if ($reverse == false)
			$resultstr = str_replace($specialchars[$n], '%%' . $n . '%', $resultstr);
		else
			$resultstr = str_replace('%%' . $n . '%', $specialchars[$n], $resultstr);
	}

	return ($resultstr);
}

function opnf_openvpn_clientvalue($client_id, $valuekey, $default = "none")
{
	$clients = openvpn_get_connection_statuses();
	foreach ($clients as $client) {
		if ($client['vpnid'] == $client_id)
			$value = $client[$valuekey];
	}

	switch ($valuekey) {

		case "status":
			$value = opnf_valuemap("openvpn.client.status", $value);
			break;
	}

	if ($value == "") $value = $default;
	echo $value;
}


// Services Discovery
function opnf_services_discovery()
{
	$services = plugins_services();

	$json_string = '{"data":[';

	foreach ($services as $service) {
		if (!empty($service['name'])) {

			$status = service_status($service);
			if ($status = "") $status = 0;

			$id = "";
			//id for OpenVPN
			if (!empty($service['id'])) $id = "." . $service["id"];
			//zone for Captive Portal
			if (!empty($service['zone'])) $id = "." . $service["zone"];

			$json_string .= '{"{#SERVICE}":"' . str_replace(" ", "__", $service['name']) . $id . '"';
			$json_string .= ',"{#DESCRIPTION}":"' . $service['description'] . '"';
			$json_string .= '},';
		}
	}
	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

// Get service value
// 2020-03-27: Added space replace in service name for issue #12
// 2020-09-28: Corrected Space Replace
function opnf_service_value($name, $value)
{
	$services = plugins_services();
	$name = str_replace("__", " ", $name);

	//List of service which are stopped on CARP Slave.
	//For now this is the best way i found for filtering out the triggers
	//Waiting for a way in Zabbix to use Global Regexp in triggers with items discovery
	$stopped_on_carp_slave = array("haproxy", "radvd", "openvpn.", "openvpn", "avahi");

	foreach ($services as $service) {
		$namecfr = $service["name"];
		$carpcfr = $service["name"];

		//OpenVPN
		if (!empty($service['id'])) {
			$namecfr = $service['name'] . "." . $service["id"];
			$carpcfr = $service['name'] . ".";
		}

		//Captive Portal
		if (!empty($service['zone'])) {
			$namecfr = $service['name'] . "." . $service["zone"];
			$carpcfr = $service['name'] . ".";
		}

		if ($namecfr == $name) {
			switch ($value) {

				case "status":
					$status = service_status($service);
					if ($status == "") $status = 0;
					echo $status;
					return;

				case "name":
					echo $namecfr;
					return;

				case "enabled":
					if (is_service_enabled($service['name']))
						echo 1;
					else
						echo 0;
					return;

				case "run_on_carp_slave":
					if (in_array($carpcfr, $stopped_on_carp_slave))
						echo 0;
					else
						echo 1;
					return;
				default:
					echo $service[$value];
					return;
			}
		}
	}

	echo 0;
}

//Gateway Discovery
function opnf_gw_rawstatus()
{
	// Return a Raw Gateway Status, useful for action Scripts (e.g. Update Cloudflare DNS config)
	$gws = return_gateways_status();
	$gw_string = "";
	foreach ($gws as $gw) {
		$gw_string .= ($gw['name'] . '.' . $gw['status'] . ",");
	}
	echo rtrim($gw_string, ",");
}

function opnf_gw_discovery()
{
	$gws = return_gateways_status();

	$json_string = '{"data":[';
	foreach ($gws as $gw) {
		$json_string .= '{"{#GATEWAY}":"' . $gw['name'] . '"';
		$json_string .= '},';
	}
	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

function opnf_gw_value($gw, $valuekey)
{
	$gws = return_gateways_status();
	if (array_key_exists($gw, $gws)) {
		$value = $gws[$gw][$valuekey];
		if ($valuekey == "status") {
			//Issue #70: Gateway Forced Down
			if ($gws[$gw]["status"] <> "none")
				$value = $gws[$gw]["status"];

			$value = opnf_valuemap("gateway.status", $value);
		}
		echo $value;
	}
}

// Accumulate all types (Legacy PH1, PH2, SWAN) // NOT NEEDED
// function opnf_ipsec_discovery($ipsec_types = array("all"))
// {
// 	$swanconns = array();
// 	$ph1_conns = array();
// 	$ph2_conns = array();
// 	if (in_array("all", $ipsec_types) || in_array("swan", $ipsec_types)) {
// 		$swanconns = opnf_ipsec_discovery_swan(true);
// 	}
// 	if (in_array("all", $ipsec_types) || in_array("legacy_ph1", $ipsec_types)) {
// 		$ph1_conns = opnf_ipsec_discovery_ph1(true);
// 	}
// 	if (in_array("all", $ipsec_types) || in_array("legacy_ph1", $ipsec_types)) {
// 		$ph2_conns = opnf_ipsec_discovery_ph2(true);
// 	}
// 	$connections = array_merge($swanconns, $ph1_conns, $ph2_conns);
// 	print_r($connections);
// 	return $connections;
// }

// IPSEC Discovery for Strongswan
function opnf_ipsec_discovery_swan($type, $as_array = false)
{
	$swanctl = (new \OPNsense\IPsec\Swanctl());
	$swan = $swanctl->getNodes()[$type];
	$connections = [];
	$json_string = '{"data":[';
	$opt = match ($type) {
		"Connections" => "Connection",
		"children" => "child",
	};
	//$opt =  ($type == "Connections")? "Connection" : "child";
	//print $swanconns;
	foreach ($swan[$opt] as $ikeid => $data) {
		if (!array_key_exists("description", $data))
			$description = "Strongswan IPSec Tunnel";
		else
			$description = $data["description"];

		if ($opt == "child") {
			if ($as_array === true) {
				$c = array(
					"ikeid"	=>	$ikeid,
					"name"	=>	$data["description"],
					"reqid" =>	$data["reqid"],
					"type"	=>	"swan child",
				);
				array_push($connections, $c);
			} else {
				$json_string .= '{"{#IKEID}":"' . $ikeid . '"';
				$json_string .= ',"{#NAME}":"' . $data['description'] . '"';
				$json_string .= ',"{#REQID}":"' .  $data['reqid'] . '"';
				$json_string .= '},';
			}
		} else {
			if ($as_array === true) {
				$c = array(
					"ikeid"	=>	$ikeid,
					"name"	=>	$data["description"],
					"type"	=>	"swan con",
				);
				array_push($connections, $c);
			} else {
				$json_string .= '{"{#IKEID}":"' . $ikeid . '"';
				$json_string .= ',"{#NAME}":"' . $data['description'] . '"';
				$json_string .= '},';
			}
		}
	}

	if ($as_array === true) return $connections;

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";
	echo $json_string;
}


function opnf_ipsec_swan($ikeid, $valuekey, $type)
{
	//Requests the config.xml "on disk"
	$swanctl = (new \OPNsense\IPsec\Swanctl());
	$opt = match ($type) {
		"Connections" => "Connection",
		"children" => "child",
	};
	$swan = $swanctl->getNodes()[$type];
	$value = "";
	switch ($valuekey) {
		case 'status':
			$value = opnf_ipsec_swan_status($ikeid, $opt);
			break;
		case 'disabled':
			$value = "0";
		default:
			foreach ($swan[$opt] as $current_ikeid => $connection) {
				if ($current_ikeid == $ikeid) {
					if (array_key_exists($valuekey, $connection)) {
						if ($valuekey == 'disabled')
							$value = "1";
						else
							$value = opnf_valuemap_swan("ipsec_swan." . $valuekey, $connection[$valuekey], $connection[$valuekey]);
						break;
					}
				}
			}
	}
	echo $value;
}


function opnf_ipsec_discovery_ph1($as_array = false)
{
	require_once("plugins.inc.d/ipsec.inc");

	global $config;
	$config = get_mvc_config();
	$a_phase1 = &$config['ipsec']['phase1'];
	$connections = [];
	$json_string = '{"data":[';
	if (array_key_exists("descr", $a_phase1)) {
		$a_phase1 = array($a_phase1);
	}

	foreach ($a_phase1 as $data) {
		if (!array_key_exists("descr", $data))
			$description = "Legacy IPSec Phase 1 Tunnel";
		else
			$description = $data['descr'];

		if ($as_array === true) {
			$c = array(
				"ikeid"	=>	$data['ikeid'],
				"name"	=>	$description,
				"type"	=>	"legacy_ph1",
			);
			array_push($connections, $c);
		} else {
			$json_string .= '{"{#IKEID}":"' . $data['ikeid'] . '"';
			$json_string .= ',"{#NAME}":"' . $description . '"';
			$json_string .= '},';
		}
	}

	if ($as_array === true) return $connections;

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

function opnf_ipsec_ph1($ikeid, $valuekey)
{
	// Get Value from IPsec Phase 1 Configuration
	// If Getting "disabled" value only check item presence in config array
	require_once("plugins.inc.d/ipsec.inc");
	global $config;
	$config = get_mvc_config();
	$a_phase1 = &$config['ipsec']['phase1'];
	if (array_key_exists("ikeid", $a_phase1)) {
		$a_phase1 = array($a_phase1);
	}
	$value = "";
	switch ($valuekey) {
		case 'status':
			$value = opnf_ipsec_status($ikeid);
			break;
		case 'disabled':
			$value = "0";
		default:
			foreach ($a_phase1 as $data) {
				if ($data['ikeid'] == $ikeid) {
					if (array_key_exists($valuekey, $data)) {
						if ($valuekey == 'disabled')
							$value = "1";
						else
							$value = opnf_valuemap("ipsec." . $valuekey, $data[$valuekey], $data[$valuekey]);
						break;
					}
				}
			}
	}
	echo $value;
}

function opnf_ipsec_discovery_ph2($as_array = false)
{
	require_once("plugins.inc.d/ipsec.inc");

	global $config;
	$config = get_mvc_config();
	$a_phase2 = &$config['ipsec']['phase2'];
	$connections = [];
	$json_string = '{"data":[';
	if (array_key_exists("ikeid", $a_phase2)) {
		$a_phase2 = array($a_phase2);
	}

	foreach ($a_phase2 as $data) {
		if (!array_key_exists("descr", $data))
			$description = "Legacy IPSec Phase 2 Tunnel";
		else
			$description = $data['descr'];

		if ($as_array === true) {
			$c = array(
				"ikeid"	=>	$data['ikeid'],
				"name"	=>	$description,
				"uniqid" =>	$data['uniqid'],
				"reqid" =>	$data['reqid'],
				"extid" =>	$data['ikeid'] . '.' . $data['reqid'],
				"type"	=>	"legacy_ph2",
			);
			array_push($connections, $c);
		} else {
			$json_string .= '{"{#IKEID}":"' . $data['ikeid'] . '"';
			$json_string .= ',"{#NAME}":"' .  $data['descr'] . '"';
			$json_string .= ',"{#UNIQID}":"' .  $data['uniqid'] . '"';
			$json_string .= ',"{#REQID}":"' .  $data['reqid'] . '"';
			$json_string .= ',"{#EXTID}":"' .  $data['ikeid'] . '.' . $data['reqid'] . '"';
			$json_string .= '},';
		}
	}

	if ($as_array === true) return $connections;
	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

function opnf_ipsec_ph2($uniqid, $valuekey)
{
	require_once("plugins.inc.d/ipsec.inc");
	global $config;
	$config = get_mvc_config();
	$a_phase2 = &$config['ipsec']['phase2'];
	if (array_key_exists("ikeid", $a_phase2)) {
		$a_phase2 = array($a_phase2);
	}
	$valuecfr = explode(".", $valuekey);

	switch ($valuecfr[0]) {
		case 'status':
			$idarr = explode(".", $uniqid);
			$statuskey = "state";
			if (isset($valuecfr[1])) $statuskey = $valuecfr[1];
			$value = opnf_ipsec_status($idarr[0], $idarr[1], $statuskey);
			break;
		case 'disabled':
			$value = "0";
	}

	foreach ($a_phase2 as $data) {
		if ($data['uniqid'] == $uniqid) {
			if (array_key_exists($valuekey, $data)) {
				if ($valuekey == 'disabled')
					$value = "1";
				else
					$value = opnf_valuemap("ipsec_ph2." . $valuekey, $data[$valuekey], $data[$valuekey]);
				break;
			}
		}
	}
	echo $value;
}

function opnf_ipsec_status($ikeid, $reqid = -1, $valuekey = 'state', $ipsec_type = "swan")
{
	require_once("plugins.inc.d/ipsec.inc");
	global $config;
	$config = get_mvc_config();

	$a_phase1 = &$config['ipsec']['phase1'];
	$conmap = array();
	if (array_key_exists("ikeid", $a_phase1)) {
		$a_phase1 = array($a_phase1);
	}
	foreach ($a_phase1 as $ph1ent) {
		$cname = "con" . $ph1ent['ikeid'];
		$conmap[$cname] = $ph1ent['ikeid'];
	}

	$status = ipsec_get_status();
	$ipsecconnected = array();

	$carp_status = opnf_carp_status(false);

	//Phase-Status match borrowed from status_ipsec.php	
	if (is_array($status)) {
		foreach ($status as $l_ikeid => $ikesa) {

			if (isset($ikesa['con-id'])) {
				$con_id = substr($ikesa['con-id'], 3);
			} else {
				$con_id = filter_var($ikeid, FILTER_SANITIZE_NUMBER_INT);
			}
			$con_name = "con" . $con_id;
			if ($ikesa['version'] == 1) {
				$ph1idx = $conmap[$con_name];
				$ipsecconnected[$ph1idx] = $ph1idx;
			} else {
				if (!ipsec_ikeid_used($con_id)) {
					// probably a v2 with split connection then
					$ph1idx = $conmap[$con_name];
					$ipsecconnected[$ph1idx] = $ph1idx;
				} else {
					$ipsecconnected[$con_id] = $ph1idx = $con_id;
				}
			}
			if ($ph1idx == $ikeid) {
				if ($reqid != -1) {
					// Asking for Phase2 Status Value
					foreach ($ikesa['child-sas'] as $childsas) {
						if ($childsas['reqid'] == $reqid) {
							if (strtolower($childsas['state']) == 'rekeyed') {
								//if state is rekeyed go on
								$tmp_value = $childsas[$valuekey];
							} else {
								$tmp_value = $childsas[$valuekey];
								break;
							}
						}
					}
				} else {
					$tmp_value = $ikesa[$valuekey];
				}

				break;
			}
		}
	}

	switch ($valuekey) {
		case 'state':
			$value = opnf_valuemap('ipsec.state', strtolower($tmp_value));
			if ($carp_status != 0) $value = $value + (10 * ($carp_status - 1));
			break;
		default:
			$value = $tmp_value;
			break;
	}

	return $value;
}
function opnf_ipsec_swan_status($ikeid, $type) //, $reqid = -1, $valuekey = 'state', $ipsec_type = "swan")
{
	//Connection,Child
	$statuses = ipsec_get_status();
	$states = [];
	if ($type == 'Connection') {
		foreach ($statuses as $current_ikeid => $connection) {
			if ($current_ikeid == $ikeid) {
				foreach ($connection->sas as $sas_item) {
					if (isset($sas_item->state)) {
						$states[] = $sas_item->state;
					}
				}
			}
		}
	}
	if ($type == 'child') {
		foreach ($statuses as $current_ikeid => $connection) {
			foreach ($connection->sas as $sas_item) {

				foreach ($sas_item->{'child-sas'} as $current_child_sa => $childSa) {
					if (isset($childSa->name) && $childSa->name == $ikeid) {
						if (isset($childSa->state)) {
							$states[] = $childSa->state;
						}
					}
				}
			}
		}
	}
	if (empty($states)) {
		return 'N/A';
	}
	if (in_array('ESTABLISHED', $states)) {
		return 'ESTABLISHED';
	} else if (in_array('INSTALLED', $states)) {
		return 'INSTALLED';
	} else {
		return $states[0];
	}
}

// Temperature sensors Discovery
function opnf_temperature_sensors_discovery()
{
	$json_string = '{"data":[';
	$sensors = [];
	exec("sysctl -a | grep temperature | cut -d ':' -f 1", $sensors, $code);
	if ($code != 0) {
		echo "";
		return;
	} else {
		foreach ($sensors as $sensor) {
			$json_string .= '{"{#SENSORID}":"' . $sensor . '"';
			$json_string .= '},';
		}
	}

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

// Temperature sensor get value
function opnf_get_temperature($sensorid)
{
	exec("sysctl '$sensorid' | cut -d ':' -f 2", $value, $code);
	if ($code != 0 or count($value) != 1) {
		echo "";
		return;
	} else {
		echo trim($value[0]);
	}
}

function opnf_carp_status($echo = true)
{
	//Detect CARP Status
	$config = get_mvc_config();
	$ret = 0;
	$status = opnf_get_carp_status();
	$carp_detected_problems = get_single_sysctl("net.inet.carp.demotion");

	if ($status->status_msg == "Could not locate any defined CARP interfaces.") {
		if ($echo == true) echo $ret;
		return $ret;
	}

	if ($status != 0) { //CARP is enabled

		if ($carp_detected_problems != 0) {
			//There's some Major Problems with CARP
			$ret = 4;
			if ($echo == true) echo $ret;
			return $ret;
		}

		$status_changed = false;
		$prev_status = "";
		foreach ($config['virtualip']['vip'] as $carp) {
			if ($carp['mode'] != "carp") {
				continue;
			}
			$if_status = get_carp_interface_status("_vip{$carp['uniqid']}");

			if (($prev_status != $if_status) && (empty($if_status) == false)) { //Some glitches with GUI
				if ($prev_status != "") $status_changed = true;
				$prev_status = $if_status;
			}
		}
		if ($status_changed) {
			//CARP Status is inconsistent across interfaces
			$ret = 3;
			echo 3;
		} else {
			if ($prev_status == "MASTER")
				$ret = 1;
			else
				$ret = 2;
		}
	}

	if ($echo == true) echo $ret;
	return $ret;
}

// DHCP Checks (copy of status_dhcp_leases.php)
function opnf_remove_duplicate($array, $field)
{
	foreach ($array as $sub) {
		$cmp[] = $sub[$field];
	}
	$unique = array_unique(array_reverse($cmp, true));
	foreach ($unique as $k => $rien) {
		$new[] = $array[$k];
	}
	return $new;
}

// Get DHCP Arrays
function opnf_dhcp_get($valuekey)
{

	require_once("config.inc");

	$leasesfile = "{$g['dhcpd_chroot_path']}/var/db/dhcpd.leases";

	$awk = "/usr/bin/awk";
	/* this pattern sticks comments into a single array item */
	$cleanpattern = "'{ gsub(\"#.*\", \"\");} { gsub(\";\", \"\"); print;}'";
	/* We then split the leases file by } */
	$splitpattern = "'BEGIN { RS=\"}\";} {for (i=1; i<=NF; i++) printf \"%s \", \$i; printf \"}\\n\";}'";

	/* stuff the leases file in a proper format into a array by line */
	@exec("/bin/cat {$leasesfile} 2>/dev/null| {$awk} {$cleanpattern} | {$awk} {$splitpattern}", $leases_content);
	$leases_count = count($leases_content);
	@exec("/usr/sbin/arp -an", $rawdata);

	$leases = [];
	$pools = [];

	$i = 0;
	$l = 0;
	$p = 0;

	foreach ($leases_content as $lease) {
		/* split the line by space */
		$data = explode(" ", $lease);
		/* walk the fields */
		$f = 0;
		$fcount = count($data);
		/* with less than 20 fields there is nothing useful */
		if ($fcount < 20) {
			$i++;
			continue;
		}
		while ($f < $fcount) {
			switch ($data[$f]) {
				case "failover":
					$pools[$p]['name'] = trim($data[$f + 2], '"');
					$pools[$p]['name'] = "{$pools[$p]['name']} (" . convert_friendly_interface_to_friendly_descr(substr($pools[$p]['name'], 5)) . ")";
					$pools[$p]['mystate'] = $data[$f + 7];
					$pools[$p]['peerstate'] = $data[$f + 14];
					$pools[$p]['mydate'] = $data[$f + 10];
					$pools[$p]['mydate'] .= " " . $data[$f + 11];
					$pools[$p]['peerdate'] = $data[$f + 17];
					$pools[$p]['peerdate'] .= " " . $data[$f + 18];
					$p++;
					$i++;
					continue 3;
				case "lease":
					$leases[$l]['ip'] = $data[$f + 1];
					$leases[$l]['type'] = $dynamic_string;
					$f = $f + 2;
					break;
				case "starts":
					$leases[$l]['start'] = $data[$f + 2];
					$leases[$l]['start'] .= " " . $data[$f + 3];
					$f = $f + 3;
					break;
				case "ends":
					if ($data[$f + 1] == "never") {
						// Quote from dhcpd.leases(5) man page:
						// If a lease will never expire, date is never instead of an actual date.
						$leases[$l]['end'] = gettext("Never");
						$f = $f + 1;
					} else {
						$leases[$l]['end'] = $data[$f + 2];
						$leases[$l]['end'] .= " " . $data[$f + 3];
						$f = $f + 3;
					}
					break;
				case "tstp":
					$f = $f + 3;
					break;
				case "tsfp":
					$f = $f + 3;
					break;
				case "atsfp":
					$f = $f + 3;
					break;
				case "cltt":
					$f = $f + 3;
					break;
				case "binding":
					switch ($data[$f + 2]) {
						case "active":
							$leases[$l]['act'] = $active_string;
							break;
						case "free":
							$leases[$l]['act'] = $expired_string;
							$leases[$l]['online'] = $offline_string;
							break;
						case "backup":
							$leases[$l]['act'] = $reserved_string;
							$leases[$l]['online'] = $offline_string;
							break;
					}
					$f = $f + 1;
					break;
				case "next":
					/* skip the next binding statement */
					$f = $f + 3;
					break;
				case "rewind":
					/* skip the rewind binding statement */
					$f = $f + 3;
					break;
				case "hardware":
					$leases[$l]['mac'] = $data[$f + 2];
					/* check if it's online and the lease is active */
					if (in_array($leases[$l]['ip'], $arpdata_ip)) {
						$leases[$l]['online'] = $online_string;
					} else {
						$leases[$l]['online'] = $offline_string;
					}
					$f = $f + 2;
					break;
				case "client-hostname":
					if ($data[$f + 1] <> "") {
						$leases[$l]['hostname'] = preg_replace('/"/', '', $data[$f + 1]);
					} else {
						$hostname = gethostbyaddr($leases[$l]['ip']);
						if ($hostname <> "") {
							$leases[$l]['hostname'] = $hostname;
						}
					}
					$f = $f + 1;
					break;
				case "uid":
					$f = $f + 1;
					break;
			}
			$f++;
		}
		$l++;
		$i++;
		/* slowly chisel away at the source array */
		array_shift($leases_content);
	}
	/* remove duplicate items by mac address */
	if (count($leases) > 0) {
		$leases = opnf_remove_duplicate($leases, "ip");
	}

	if (count($pools) > 0) {
		$pools = opnf_remove_duplicate($pools, "name");
		asort($pools);
	}

	switch ($valuekey) {
		case "pools":
			return $pools;
			break;
		case "failover":
			return $failover;
			break;
		case "leases":
		default:
			return $leases;
	}
}

// ! Not working or tested on OPNSense yet.
function opnf_dhcpfailover_discovery()
{
	//System functions regarding DHCP Leases will be available in the upcoming release of OPNSense, so let's wait
	require_once("system.inc");
	$leases = system_get_dhcpleases();

	$json_string = '{"data":[';

	if (count($leases['failover']) > 0) {
		foreach ($leases['failover'] as $data) {
			$json_string .= '{"{#FAILOVER_GROUP}":"' . str_replace(" ", "__", $data['name']) . '"';
		}
	}

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

// ! Not working or tested on OPNSense yet.
function opnf_dhcp_check_failover()
{
	// Check DHCP Failover Status
	// Returns number of failover pools which state is not normal or
	// different than peer state
	$failover = opnf_dhcp_get("failover");
	$ret = 0;
	foreach ($failover as $f) {
		if (($f["mystate"] != "normal") || ($f["mystate"] != $f["peerstate"])) {
			$ret++;
		}
	}
	return $ret;
}

// ! Not working or tested on OPNSense yet.
function opnf_dhcp($section, $valuekey = "")
{
	switch ($section) {
		case "failover":
			echo opnf_dhcp_check_failover();
			break;
		default:
	}
}

//Packages
function opnf_get_packages_upgrade()
{
	$command = escapeshellcmd('/bin/sh /usr/local/opnsense/scripts/firmware/check.sh');
	$result = shell_exec($command);
	$output = file_get_contents("/tmp/pkg_upgrade.json");
	return json_decode($output);
}

function opnf_packages_uptodate()
{
	$pkg_upgrade = opnf_get_packages_upgrade();
	if ($pkg_upgrade->download_size > 0)
		return false;
	return true;
}

// ! Not working or tested on OPNSense yet.
function opnf_sysversion_cron_install($enable = true)
{
	//Install Cron Job
	$command = "/usr/local/bin/php " . __FILE__ . " systemcheck_cron";
	install_cron_job($command, $enable, $minute = "0", "9,21", "*", "*", "*", "root", true);
}

// System information takes a long time to get on slower systems.
// So it is saved via a cronjob.
function opnf_sysversion_cron()
{
	$filename = "/tmp/pkg_upgrade.json";
	$upToDate = opnf_packages_uptodate();
	$sysVersion = system_get_version();
	$versionData = opnf_get_packages_upgrade();
	$versionData->new_version_available = $upToDate == true ? 0 : 1;
	$versionDataJson = json_encode($versionData);
	if (file_exists($filename)) {
		if ((time() - filemtime($filename) > CRON_TIME_LIMIT)) {
			@unlink($filename);
		}
	}
	if (file_exists($filename) == false) {
		touch($filename);
		file_put_contents($filename, $versionDataJson);
	}
	return true;
}

function opnf_get_version()
{
	return system_get_version();
}

function opnf_get_new_version($sysVersion, $currentVersion)
{
	$filename = "/tmp/pkg_upgrade.json";
	foreach ($sysVersion["upgrade_packages"] as $pkg_k => $pkg_v)
		if ($pkg_v["name"] == "opnsense") return $pkg_v["new_version"];
	return $currentVersion;
}

//System Information
function opnf_get_system_value($section)
{
	$filename = "/tmp/pkg_upgrade.json";
	$sysVersion_exists = file_exists($filename);
	if ($sysVersion_exists == true) {
		$sysVersion = json_decode(file_get_contents($filename), true);
	} else {
		if ($section == "new_version_available") {
			echo "0";
		}
	}
	switch ($section) {
		case "version":
			echo (opnf_get_new_version($sysVersion, opnf_get_version()));
			break;
		case "installed_version":
			echo (opnf_get_version());
			break;
		case "new_version_available":
			$new_version_available = false;
			foreach ($sysVersion["upgrade_packages"] as $pkg_k => $pkg_v)
				if ($pkg_v["name"] == "opnsense") $new_version_available = true;
			if ($new_version_available == true)
				echo "1";
			else
				echo "0";
			break;
		case "packages_update":
			echo $sysVersion["upgrade_packages"];
			break;
	}
}

//S.M.A.R.T Status
// Taken from /usr/local/www/widgets/widgets/smart_status.widget.php
function opnf_get_smart_status()
{

	$devs = get_smart_drive_list();
	$status = 0;
	foreach ($devs as $dev) { ## for each found drive do
		$smartdrive_is_displayed = true;
		$dev_ident = exec("diskinfo -v /dev/$dev | grep ident	| awk '{print $1}'"); ## get identifier from drive
		$dev_state = trim(exec("smartctl -H /dev/$dev | awk -F: '/^SMART overall-health self-assessment test result/ {print $2;exit}
/^SMART Health Status/ {print $2;exit}'")); ## get SMART state from drive
		switch ($dev_state) {
			case "PASSED":
			case "OK":
				//OK
				$status = 0;
				break;
			case "":
				//Unknown
				$status = 2;
				return $status;
				break;
			default:
				//Error
				$status = 1;
				return $status;
				break;
		}
	}

	echo $status;
}

// Certificats validity date
function opnf_get_cert_date($valuekey)
{
	global $config;

	// Contains a list of refs that were revoked and should not be considered
	$revoked_cert_refs = [];
	foreach ($config["crl"] as $crl) {
		foreach ($crl["cert"] as $revoked_cert) {
			$revoked_cert_refs[] = $revoked_cert["refid"];
		}
	}

	$value = 0;
	foreach (array("cert", "ca") as $cert_type) {
		switch ($valuekey) {
			case "validFrom.max":
				foreach ($config[$cert_type] as $cert) {
					if (! in_array($cert['refid'], $revoked_cert_refs)) {
						$certinfo = openssl_x509_parse(base64_decode($cert["crt"]));
						if ($value == 0 or $value < $certinfo['validFrom_time_t']) $value = $certinfo['validFrom_time_t'];
					}
				}
				break;
			case "validTo.min":
				foreach ($config[$cert_type] as $cert) {
					if (! in_array($cert['refid'], $revoked_cert_refs)) {
						$certinfo = openssl_x509_parse(base64_decode($cert["crt"]));
						if ($value == 0 or $value > $certinfo['validTo_time_t']) $value = $certinfo['validTo_time_t'];
					}
				}
				break;
		}
	}
	echo $value;
}

// File is present
function opnf_file_exists($filename)
{
	if (file_exists($filename))
		echo "1";
	else
		echo "0";
}


// Value mappings
// Each value map is represented by an associative array
function opnf_valuemap($valuename, $value, $default = "0")
{
	switch ($valuename) {
		case "openvpn.server.status":
			$valuemap = array(
				"down" => "0",
				"up" => "1",
				"connected (success)" => "1",
				"none" => "2",
				"reconnecting; ping-restart" => "3",
				"waiting" => "4",
				"server_user_listening" => "5"
			);
			break;

		case "openvpn.client.status":
			$valuemap = array(
				"up" => "1",
				"connected (success)" => "1",
				"down" => "0",
				"none" => "0",
				"reconnecting; ping-restart" => "2"
			);
			break;

		case "openvpn.server.mode":
			$valuemap = array(
				"p2p_tls" => "1",
				"p2p_shared_key" => "2",
				"server_tls" => "3",
				"server_user" => "4",
				"server_tls_user" => "5"
			);
			break;

		case "gateway.status":
			$valuemap = array(
				"online" => "0",
				"none" => "0",
				"loss" => "1",
				"highdelay" => "2",
				"highloss" => "3",
				"force_down" => "4",
				"down" => "5"
			);
			break;

		case "ipsec.iketype":
			$valuemap = array(
				"auto" => 0,
				"ikev1" => 1,
				"ikev2" => 2
			);
			break;

		case "ipsec.mode":
			$valuemap = array(
				"main" => 0,
				"aggressive" => 1
			);
			break;

		case "ipsec.protocol":
			$valuemap = array(
				"both" => 0,
				"inet" => 1,
				"inet6" => 2
			);
			break;

		case "ipsec_ph2.mode":
			$valuemap = array(
				"transport" => 0,
				"tunnel" => 1,
				"tunnel6" => 2
			);
			break;

		case "ipsec_ph2.protocol":
			$valuemap = array(
				"esp" => 1,
				"ah" => 2
			);
			break;

		case "ipsec.state":
			$valuemap = array(
				"established" => 1,
				"connecting" => 2,
				"installed" => 1,
				"rekeyed" => 2
			);
			break;
	}

	if (is_array($valuemap)) {
		$value = strtolower($value);
		if (array_key_exists($value, $valuemap))
			return $valuemap[$value];
	}
	return $default;
}
// Value mappings
// Each value map is represented by an associative array
function opnf_valuemap_swan($valuename, $value, $default = "0")
{
	switch ($valuename) {
		case "ipsec_swan.version":
			foreach ($value as $item) {
				if (isset($item['selected']) && $item['selected'] == 1) {
					return $item['value'];
				}
			}
			return 'N/A';
			break;
		case "ipsec_swan.remote_addrs":
		case "ipsec_swan.local_addrs":
		case "ipsec_swan.local_port":
		case "ipsec_swan.remote_port":
		case "ipsec_swan.esp_proposals":
		case "ipsec_swan.mode": {
				$selectedItems = array_filter($value, function ($item) {
					return isset($item['selected']) && $item['selected'] == 1;
				});
				$values = array_column($selectedItems, 'value');
				if (empty($values)) return 'N/A';
				return $value = implode(';', $values);
			}
	}


	return $default;
}

//Argument parsers for Discovery
function opnf_discovery($section)
{
	switch (strtolower($section)) {
		case "gw":
			opnf_gw_discovery();
			break;
		case "wan":
			opnf_interface_discovery(true);
			break;
		case "wireguard_server":
			opnf_t_serverdiscovery("wireguard");
			break;
		case "openvpn_server":
			opnf_t_serverdiscovery("openvpn");
			break;
		case "openvpn_server_user":
			opnf_openvpn_server_userdiscovery();
			break;
		case "openvpn_client":
			opnf_openvpn_clientdiscovery();
			break;
		case "services":
			opnf_services_discovery();
			break;
		case "interfaces":
			opnf_interface_discovery();
			break;
		case "ipsec_ph1":
			opnf_ipsec_discovery_ph1();
			break;
		case "ipsec_ph2":
			opnf_ipsec_discovery_ph2();
			break;
		case "ipsec_swan_connections":
			opnf_ipsec_discovery_swan("Connections");
			break;
		case "ipsec_swan_children":
			opnf_ipsec_discovery_swan("children");
			break;
		case "dhcpfailover":
			opnf_dhcpfailover_discovery();
			break;
		case "temperature_sensors":
			opnf_temperature_sensors_discovery();
			break;
	}
}

//Main Code
$mainArgument = strtolower($argv[1]);
if (substr($mainArgument, -4, 4) == "cron") {
	// A longer time limit for cron tasks.
	set_time_limit(CRON_TIME_LIMIT);
} else {
	// Set a timeout to prevent a blocked call from stopping all future calls.
	set_time_limit(DEFAULT_TIME_LIMIT);
}

switch ($mainArgument) {
	case "discovery":
		opnf_discovery($argv[2]);
		break;
	case "gw_value":
		opnf_gw_value($argv[2], $argv[3]);
		break;
	case "states":
		print(opnf_get_states_count());
		break;
	case "gw_status":
		opnf_gw_rawstatus();
		break;
	case "openvpn_servervalue":
		opnf_openvpn_servervalue($argv[2], $argv[3]);
		break;
	case "openvpn_server_uservalue":
		opnf_openvpn_server_uservalue($argv[2], $argv[3]);
		break;
	case "openvpn_server_uservalue_numeric":
		opnf_openvpn_server_uservalue($argv[2], $argv[3], "0");
		break;
	case "openvpn_clientvalue":
		opnf_openvpn_clientvalue($argv[2], $argv[3]);
		break;
	case "service_value":
		opnf_service_value($argv[2], $argv[3]);
		break;
	case "carp_status":
		opnf_carp_status();
		break;
	case "interfaces":
		echo json_encode(legacy_interface_stats($argv[2]));
		break;
	case "sysversion_cron":
		opnf_sysversion_cron();
		break;
	case "system":
		opnf_get_system_value($argv[2]);
		break;
	case "ipsec_ph1":
		opnf_ipsec_ph1($argv[2], $argv[3]);
		break;
	case "ipsec_ph2":
		opnf_ipsec_ph2($argv[2], $argv[3]);
		break;
	case "ipsec_swan_connections":
		opnf_ipsec_swan($argv[2], $argv[3], "Connections");
		break;
	case "ipsec_swan_children":
		opnf_ipsec_swan($argv[2], $argv[3], "children");
		break;
	case "dhcp":
		opnf_dhcp($argv[2], $argv[3]);
		break;
	case "file_exists":
		opnf_file_exists($argv[2]);
		break;
	case "cron_cleanup":
		opnf_sysversion_cron_install(false);
		break;
	case "smart_status":
		opnf_get_smart_status();
		break;
	case "cert_date":
		opnf_get_cert_date($argv[2]);
		break;
	case "temperature":
		opnf_get_temperature($argv[2]);
		break;
	default:
		opnf_test();
		break;
}