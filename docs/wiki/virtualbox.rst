VirtualBox Notes
================

Configuring the OpenRPD VMDK as a VM
------------------------------------

When creating the OpenRPD VM in VirtualBox, assign two network interfaces. The
first interface will be the management interface (NAT internal to the VM host
is fine), and the second interface should be bridged to a physical adapter
connected (layer 2) to the CCAP core (or simulator). 

OpenRPD will attempt IPv6 first and will timeout after three retries and
fallback to IPv4.

