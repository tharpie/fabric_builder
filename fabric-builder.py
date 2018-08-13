#!/usr/bin/python
from cvplibrary import CVPGlobalVariables as cvp_vars
from cvplibrary import GlobalVariableNames as cvp_names
from cvplibrary import RestClient

import netaddr
import requests

'''
2c:c2:60:fd:3d:06 leaf1.arista.test
2c:c2:60:a7:83:ba leaf2.arista.test
2c:c2:60:0d:bd:7a leaf3.arista.test
2c:c2:60:b5:96:d9 leaf4.arista.test
'''

def get_session_id():
    payload = dict()
    payload['username'] = 'cvpadmin'
    payload['password'] = 'arista'

    url = 'http://localhost/cvp-ipam-api/login'
    r = requests.post(url, json=payload)
    return r.json()


def get_networks(session):
    payload = dict()
    payload['session_id'] = session['session_id']
    payload['token'] = session['token']

    url = 'http://localhost/cvp-ipam-api/networks'
    r = requests.get(url, params=payload)
    return r.json()


def get_network_allocations(session, network, pool_type):
    payload = dict()
    payload['session_id'] = session['session_id']
    payload['token'] = session['token']
    payload['network'] = network
    payload['type'] = pool_type

    url = 'http://localhost/cvp-ipam-api/networkallocations'
    r = requests.get(url, params=payload)
    return r.json()


def get_pools(session, pool_id):
    payload = dict()
    payload['session_id'] = session['session_id']
    payload['token'] = session['token']
    payload['id'] = pool_id

    url = 'http://localhost/cvp-ipam-api/pools'
    r = requests.get(url, params=payload)
    return r.json()


'''
parentsubnet mgmt
address 192.168.0.14
created 2018-08-09T22:17:10Z
description 2c:c2:60:fd:3d:06|leaf1
parentid management-ipv4-mgmt-192.168.0.14|
network management
hostname 
createdby cvpadmin
lastupdatedby cvpadmin
name 192.168.0.14
lastupdated 2018-08-09T22:17:10Z
id management-ipv4-mgmt-192.168.0.14|-192.168.0.14
lastseenat 0001-01-01T00:00:00Z
'''
'''
broadcast 192.168.0.255
emailwarning 0
dnslookup false
range 192.168.0.0/24
description management vrf subnet
emailcritical 0
percentavailable 99.609375
pingsweep false
createdby cvpadmin
children reservations
name mgmt
id management-ipv4-mgmt
gateway 192.168.0.1
mask 255.255.255.0
direction Management
'''

session = get_session_id()

system_mac = cvp_vars.getValue(cvp_names.CVP_MAC)
system_hostname = ''
system_ip = ''

allocs = get_network_allocations(session, 'management', 'ipv4')['data']
for item in allocs:
    desc = item['description'].split('|')
    mac = desc[0]
    hostname = desc[1]
    if system_mac == mac:
        system_hostname = hostname
        system_ip = item['address']

print system_hostname
print system_ip

print '-----------------'

network_gw = ''
network_cidr = ''

network_pools = get_pools(session, 'management-ipv4')['data']
for item in network_pools:
    if item['name'] == 'mgmt':
        network_gw = item['gateway']
        network = netaddr.IPNetwork(item['range'])
        network_cidr = network.prefixlen

print network_gw
print network_cidr
 


get CVP_MAC
Underlay Builder

Grab Management Network
 - build out configuration for management VRF
 - default route
 - eapi
 - configure ma1

def get_pool(session, name):
    payload = dict()
    payload['session_id'] = session['session_id']
    payload['token'] = session['token']
    payload['id'] = name

    url = 'http://localhost/cvp-ipam-api/allocation'
    r = requests.get(url, params=payload)
    return r.json()

def get_allocation(session, name):
    payload = dict()
    payload['session_id'] = session['session_id']
    payload['token'] = session['token']
    payload['id'] = name

    url = 'http://localhost/cvp-ipam-api/allocation'
    r = requests.get(url, params=payload)
    return r.json()

mgmt_info = get_allocation(session, name)
hostname = mgmt_info['hostname']
network = mgmt_info['network']
ip_addr = mgmt_info['address']




vrf management
ip route vrf management 0.0.0.0/0 dg


Based on network configure









Functions Needed

#POST
Grab Session() 
  returns 
{
         "session_id": "session_id",
         "token": "token",
         "permissions": 1024,
         "success": true
}

#GET


#GET
Get Network(name) 
{
         "success": true,
         "status": "Found network",
         "data": {
           "id": "network1",
           "name": "network1",
           "description": "default network1",
           "createdby": "init",
           "pools": {
             "asns": "0-65535",
             "ipv4": "0.0.0.0/0",
             "ipv6": "::/0",
             "vlans": "0-4095",
             "vxlans": "0-16777215"
} }
}

#GET, ID is string
Get Pool(id)

 {
         "success": true,
         "status": "Pool Found",
         "type": "IP",
         "data": {
           "id": "example-ipv4-mgmt",
           "name": "mgmt",
           "range": "10.0.0.0/24",
           "mask": "255.255.255.0",
           "description": "management subnet",
           "createdby": "cvpadmin",
           "direction": "Management",
           "broadcast": "10.0.0.255",
           "pingsweep": "false",
           "dnslookup": "false",
           "emailwarning": "0",
           "emailcritical": "0",
           "percentavailable": 100,
           "children": "none"
} }


# TYPE of NETWORKS
- Underlay
- Management
- USER VRF
- PROD VRF
- TEST VRF
