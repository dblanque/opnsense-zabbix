# CHANGELOG

* 2025-06-20:
	* Merged silureth's IPSec support branch.
* 2024-04-29:
	* Fixed Individual Gateway Status support.
	* Fixed OpenVPN Server Data Fetching to support both *Legacy* and *MVC* Instances.
	* Renamed all function prefixes from *pfz_* to *opnf_*.
	* Minor fixes to further implement IPSec (Both Strongswan and Legacy instances) detection and status reporting, not tested.
	* Other minor fixes.
* 2024-02-01: Fix for OPNSense 24.1 `get_interfaces_info()` function deprecation was implemented. The templates were also updated with new item key implementations for the Network Interfaces.
