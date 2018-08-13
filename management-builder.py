from cvplibrary import CVPGlobalVariables as cvp_vars
from cvplibrary import GlobalVariableNames as cvp_names

import requests
import netaddr

def get_session_id():
    payload = dict()
    payload['username'] = 'cvpadmin'
    payload['password'] = 'arista'

    url = 'http://localhost/cvp-ipam-api/login'
    r = requests.post(url, json=payload)
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


network_gw = ''
network_cidr = ''

network_pools = get_pools(session, 'management-ipv4')['data']
for item in network_pools:
    if item['name'] == 'mgmt':
        network_gw = item['gateway']
        network = netaddr.IPNetwork(item['range'])
        network_cidr = network.prefixlen


print 'hostname %s' % system_hostname
print '!'
print 'vrf definition management'
print 'ip routing vrf management'
print 'ip route vrf management 0.0.0.0/0 %s' % network_gw
print 'ip name-server vrf management 192.168.0.2'
print 'ip domain-name arista.test'
print '!'

print 'interface Management1'
print '   vrf forwarding management'
print '   ip address %s/%s' % (system_ip, network_cidr)
print '   no lldp transmit'
print '   no lldp receive'
print '!'

print 'management api http-commands'
print '   no shutdown'
print '   protocol http'
print '   vrf management'
print '      no shutdown'
print '!'