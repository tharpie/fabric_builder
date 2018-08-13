from cvplibrary import CVPGlobalVariables as cvp_vars
from cvplibrary import GlobalVariableNames as cvp_names

import requests
import netaddr
import jsonrpclib


class Link(object):
    def __init__(self, local_int, ip, cidr, neighbor_ip, neighbor_asn):
        self.local_int = local_int
        self.ip = ip
        self.cidr = cidr
        self.neighbor_ip = neighbor_asn
        self.neighbor_asn = neighbor_asn
    def __str__(self):
        return '%s %s %s %s %s' % (self.local_int, self.ip, self.cidr,
                             self.neighbor_ip, self.neighbor_asn)

def get_credentials(ztp=cvp_vars.getValue(cvp_names.ZTP_STATE)):
    if ztp == 'true':
        user = cvp_vars.getValue(cvp_names.ZTP_USERNAME)
        pwd = cvp_vars.getValue(cvp_names.ZTP_PASSWORD)
    else:
        user = cvp_vars.getValue(cvp_names.CVP_USERNAME)
        pwd = cvp_vars.getValue(cvp_names.CVP_PASSWORD)
        
    return (user, pwd)

def send_commands(commands):
    ip = cvp_vars.getValue(cvp_names.CVP_IP)
    usr, pwd = get_credentials()
    connection_url = 'http://%s:%s@%s/command-api' % (usr, pwd, ip)
    conn = jsonrpclib.Server(connection_url)
    result = conn.runCmds(1, commands)
    return result

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
        if item['children'] == 'none':
            name = item['name']
            pools[name] = item
        elif item['children'] != 'none':
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

def build_links(session, hostname, systems, lldp_info, pools, asns):
    links = dict()
    links['%s_routerid' % hostname] = Link('Loopback0', '', '', '', '')

    for key in sorted(lldp_info.keys()):
        if len(lldp_info[key]['lldpNeighborInfo']) == 0:
            continue
        neighbor_info = lldp_info[key]['lldpNeighborInfo'][0]
        mac = neighbor_info['chassisId'].replace('.','')
        mac = ':'.join(a+b for a,b in zip(mac[::2], mac[1::2]))
        if mac not in systems.keys():
            continue
        neigh_hostname = systems[mac]
        link = Link(key, '', '', '', asns[neigh_hostname])
        if 'leaf' in hostname and 'spine' in neigh_hostname:
            link_name = '%s_%s' % (neigh_hostname, hostname)
        elif 'spine' in hostname and 'leaf' in neigh_hostname:
            link_name = '%s_%s' % (hostname, neigh_hostname)

        links[link_name] = link

    for key in links:
        if key in pools.keys():
            pool = pools[key]
            subnet = netaddr.IPNetwork(pool['range'])
            cidr = subnet.prefixlen
            if 'routerid' in key:
                ip = subnet[0]
                neigh_ip = ''
            elif 'leaf' in hostname:
                ip = subnet[2]
                neigh_ip = subnet[1]
            elif 'spine' in hostname:
                ip = subnet[1]
                neigh_ip = subnet[2]
            
            links[key].ip = ip
            links[key].neighbor_ip = neigh_ip
            links[key].cidr = cidr
    
    return links


session = get_session_id()
sys_mac = cvp_vars.getValue(cvp_names.CVP_MAC)
systems = get_systems(session)
sys_hostname = systems[sys_mac]
neighbors = send_commands(['show lldp neighbors detail'])[0]
pools = build_pools(session, 'underlay-ipv4')
asns = build_asns(session)
sys_asn = asns[sys_hostname]

# build all link info for routed ports and bgp
links = build_links(session, sys_hostname, systems, 
                    neighbors['lldpNeighbors'], pools, asns)

loopback = links['%s_routerid' % sys_hostname]
del links['%s_routerid' % sys_hostname]

print 'ip routing'
print '!'
for key in sorted(links.keys()):
    link = links[key]
    print 'interface %s' % link.local_int
    print '   description %s' % key
    print '   no switchport'
    print '   ip address %s/%s' % (link.ip, link.cidr)
    print '!'
print 'interface %s' % loopback.local_int
print '   description %s_routerid' % sys_hostname
print '   ip address %s/%s' % (loopback.ip, loopback.cidr)
print '!'

print 'router bgp %s' % sys_asn
print '   router-id %s' % loopback.ip
for key in sorted(links.keys()):
    link = links[key]
    print '   neighbor %s remote-as %s' % (link.neighbor_ip, link.neighbor_asn)
print '   network %s/%s' % (loopback.ip, loopback.cidr)
print '!'
