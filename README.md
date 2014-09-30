OpenStack Neutron LBaaS plugin for SteelApp (Stingray) Traffic Manager
======================================================================

This is an OpenStack Neutron LBaaS 2.0 driver to support the Riverbed SteelApp
(Stingray) traffic manager, running on either dedicated hardware devices or
virtual instances.

This is still beta software and has not been fully tested, but we plan to
use this in our production environment soon. We have been using a variant
of this in our production Havana stack, but it required a major re-write to
support the new 2.0 LBaaS API in Icehouse.

Installation
------------

Either clone this repository, or grab a [ZIP file] [zipfile] from GitHub and
put it into your Neutron LBaaS drivers directory. This will likely be something
like:
   - ```/usr/lib/python2.7/dist-packages/neutron/services/loadbalancer/drivers/``` (Ubuntu packages)
   - ```/opt/stack/neutron/neutron/services/loadbalancer/drivers/``` (DevStack)

You should also consult the [OpenStack LBaaS How-to-run] [LBaaSHowToRun] wiki
page.

Configuration
-------------

Your STMs should be up and running and the REST API should be enabled. You
should also consider adding a separate user account on the devices for LBaaS
operations, but using the admin account is fine.

You should also know which version of the REST API your SteelApp software
supports. You'll need to define this in the configuration file also.

| SteelApp Version | Supported REST API Versions |
|-----------------:|-----------------------------|
| 9.3              | 1.0                         |
| 9.4              | 1.0                         |
| 9.5              | 2.0, 1.1, 1.0               |
| 9.6              | 3.0, 2.0                    |
| 9.7              | 3.1, 3.0, 2.0               |
| 9.8              | 3.2, 3.1, 3.0, 2.0          |

API versions 3.0 or higher haven't been tested yet. Please file an issue if
there are any incompatibilities found.

In the LBaaS configuration file (```/etc/neutron/lbaas_agent.ini```) add the
following:

```
[DEFAULT]
# Show debugging output in log (sets DEBUG log level output)
debug = True

# The agent requires drivers to manage the loadbalancer
device_driver = neutron.services.loadbalancer.drivers.stingray.rest_driver.StingrayRestDriver

[stingray]
# The hostnames or IP addresses (comma separated) of the STM devices
device_addresses = stm1.my.domain,stm2.my.domain

# The REST API port number
device_port = 9070

# API version for the SteelApp devices.
device_api_version = 2.0

# STM credentials for REST API
tm_username = admin
tm_password = password

# SNMP community name (for stats)
tm_community = community
```

In the Neutron configuration (```/etc/neutron/neutron.conf```) add the
following entries:

```
[DEFAULT]
# Enable the Stingray agent driver
service_provider=LOADBALANCER:Stingray:neutron.services.loadbalancer.drivers.stingray.agent_driver.StingrayAgentDriver:default

# If using virtual SteelApp instances, provide the STM port IDs.
# This will add allowed_address_pairs entries to the STM ports for each VIP
loadbalancer_instance_ports = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```
Once you restart the Neutron and Neutron LBaaS agent services, Neutron LBaaS
configuration should apply to your STMs.

Hacking
-------

If you intend to hack or debug the SteelApp LBaaS driver, you should get
yourself set up with DevStack.

You'll want the these options added to your ```local.conf``` (before running
stack.sh) to enable LBaaS.

```
disable_service n-net
enable_service q-svc
enable_service q-agt
enable_service q-dhcp
enable_service q-l3
enable_service q-meta
enable_service q-lbaas
enable_service neutron
```

If you would like to use virtual STM instances, get yourself a copy of the
SteelApp (Stingray) Virtual Applicance. You can have the image added to Glance
using the ./stack.sh process, by adding this to your local.conf

```
IMAGE_URLS="http://download.cirros-cloud.net/0.3.2/cirros-0.3.2-x86_64-disk.img,
file:///path/to/StingrayTrafficManager-9.6.qcow2"
```

You should also read the DevStack parts of the [OpenStack LBaaS How-to-run]
[LBaaSHowToRun] wiki page for some useful setup and testing commands.

[ZipFile]:https://github.com/guardian/openstack-lbaas-stingray/archive/master.zip
[LBaaSHowToRun]:https://wiki.openstack.org/wiki/Neutron/LBaaS/HowToRun
