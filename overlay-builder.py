from cvplibrary import CVPGlobalVariables as cvp_vars
from cvplibrary import GlobalVariableNames as cvp_names

import requests
import netaddr
import jsonrpclib


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

def get_systems(session):
    systems = dict()
    allocs = get_network_allocations(session, 'management', 'ipv4')['data']
    for item in allocs:
        desc = item['description'].split('|')
        mac = desc[0]
        hostname = desc[1]
        systems[mac] = hostname
    return systems

def get_pools(session, pool_id):
    payload = dict()
    payload['session_id'] = session['session_id']
    payload['token'] = session['token']
    payload['id'] = pool_id

    url = 'http://localhost/cvp-ipam-api/pools'
    r = requests.get(url, params=payload)
    return r.json()

def build_pools(session, pool_id):
    pools = dict()
    network_pools = get_pools(session, pool_id)['data']
    for item in network_pools:
        children = item['children']
        if children == 'none':
            name = item['name']
            pools[name] = item
        elif children == 'reservations':
            name = item['name']
            pools[name] = item
            pools[name]['allocations'] = dict()
        elif children != 'none':
            _network_pools = build_pools(session, item['id'])
            pools.update(_network_pools)
    return pools

def build_asns(session):
    asns = dict()
    asn_info = get_network_allocations(session, 'underlay', 'asns')['data']
    for asn in asn_info:
        hosts = asn['description'].split('|')
        for host in hosts:
            asns[host] = asn['value']
    return asns

def build_allocations(session, pools):
    allocs = get_network_allocations(session, 'overlay', 'ipv4')['data']
    for item in allocs:
        desc = item['description']
        parent = item['parentsubnet']
        if desc in pools[parent]['allocations'].keys():
            continue
        else:
            pools[parent]['allocations'][desc] = item
    
    return pools


session = get_session_id()
sys_mac = cvp_vars.getValue(cvp_names.CVP_MAC)
systems = get_systems(session)
sys_hostname = systems[sys_mac]
asns = build_asns(session)
sys_asn = asns[sys_hostname]
pools = build_pools(session, 'overlay-ipv4')
pools = build_allocations(session, pools)

vrfs = set()
vxlan_vlans = dict()
flood_list = set()
vtep = netaddr.IPNetwork(pools['%s_vtep' % sys_hostname]['range'])
varp_vtep = netaddr.IPNetwork(pools['varp_vtep']['range'])

for key in pools.keys():
    if 'group' in pools[key].keys() and 'vlan' in pools[key].keys():
        if pools[key]['group'] != 'none':
            vrfs.add(pools[key]['group'])
        if pools[key]['vlan'] != 'none' and pools[key]['vxlan'] != 'none':
            vlan = pools[key]['vlan']
            vxlan_vlans[vlan] = pools[key]['vxlan']
    if 'vtep' in key:
        ip_net = netaddr.IPNetwork(pools[key]['range'])
        flood_list.add(str(ip_net.ip))

for vrf in vrfs:
    print 'vrf definition %s' % vrf
    print 'ip routing vrf %s' % vrf
    print '!'

for key in sorted(vxlan_vlans.keys()):
    print 'vlan %s' % key
    print '   name VLAN%s_VXLAN%s' % (key, vxlan_vlans[key])
    print '!'

print 'ip virtual-router mac-address 00:1c:73:00:12:34'
print '!'

print 'interface Vxlan1'
print '   vxlan source-interface Loopback1'
for key in sorted(vxlan_vlans.keys()):
    print '   vxlan vlan %s vni %s' % (key, vxlan_vlans[key])
print '   vxlan flood vtep %s' % ' '.join(sorted(flood_list))
print '!'

print 'interface Loopback1'
print '   ip address %s/%s' % (vtep.ip, vtep.prefixlen)
print '   ip address %s/%s secondary' % (varp_vtep.ip, varp_vtep.prefixlen)
print '!'

for key in sorted(vxlan_vlans.keys()):
    name = 'vlan%s' % key
    if name in pools.keys():
        if 'allocations' in pools[name].keys():
            if sys_hostname in pools[name]['allocations'].keys():
                subnet = netaddr.IPNetwork(pools[name]['range'])
                ip = pools[name]['allocations'][sys_hostname]['address']
                print 'interface Vlan%s' % key
                print '   vrf forwarding %s' % pools[name]['group'] 
                print '   ip address %s/%s' % (ip, subnet.prefixlen)
                if 'default_out' not in pools[name]['description']:
                    print '   ip virtual-router address %s' % pools[name]['gateway']
    print '!'

for key in sorted(vxlan_vlans.keys()):
    name = 'vlan%s' % key
    desc = pools[name]['description']
    if 'default_out' in desc:
        print 'ip route vrf %s 0.0.0.0/0 %s' % (pools[name]['group'], pools[name]['gateway'])
print '!'

print 'router bgp %s' % sys_asn
print '   network %s/%s' % (vtep.ip, vtep.prefixlen)
print '   network %s/%s' % (varp_vtep.ip, varp_vtep.prefixlen)
