# junos to fortigate firewall policy converter
# 
# reads parts of a juniper srx (junos) config and creates config snippets that
# can be imported into a fortigate vdom. 
#
# this is no forticonverter replacement, it has been created for a very special use case: 
# only access rules and nat configuration concerning a specific zone ('mig_zone', see below)  
# with only one interface and ip network ('mig_net') in it will be processed. 
#
# note: this script is only suitable for a manageable number of rules
#
# please note: all address and service objects are converted, even if not used.
# you may add a tag or special comment or a prefix in the output secions
# in order to easily clean up unused objects after migration
#
# requirements:
# - junos configuration export of the source device in xml format (DONT USE JSON EXPORT)
# - a linux machine/vm/container that is capable to run python3
# - a list with already defined service on you destination firewall / vdom (fortigate):
#   - generate file by issuing 'config firewall service custom' at fortigate
#   - copypaste output to local file (here: fortigate-services.txt)
#   - do a ''cat fortigate-services.txt | grep edit | awk '{print $2}' | tr -d '"' > fgt-svc-list.txt''
# - the name of the vdom to import into (see variable 'vdom' below')
# - source zone name and network, see 'mig_zone' and 'mig_net' below
# - a junos-to-fortigate topology conversion table, which maps junos zones to fortigate interfaces, see 'fg_topo' dict below.
#
# how it works:
# - copy this script, the junos config and the fortigate service list into one directory on you linux machine
# - run script
# - note 'skipped' messages
# - import created config snippets into your fortigate vdom, either via web gui 
#   using /ng/system/config/scripts or by copypasting with the cli
# - import snippets (SEQUENCE MATTERS):
#   - services
#   - service-groups
#   - address
#   - address-groups
#   - ippool-commands
#   - vip-commands
#   - firewall-rules
# - manually verify created rules and test the configuration

# djonz jul 25

import xmltodict, ipaddress, json, sys, os

###################
# -- Variables -- # 
###################

# exported junos configuration in xml format
infile = 'config.xml'

# vdom to import into
vdom = 'prod'

# zone and destination network to migrate
mig_zone = 'dmz'
mig_net = ipaddress.ip_network('192.0.2.0/24')

# network topology matrix. maps junos zones to fortigate interfaces
# item key is srx zone, value is the fortigate interface next to the network(s) behind the zone interface
fg_topo = { 
    'dmz' : 'port5',
    'untrust' : 'port2',
    'trust' : 'port4',
    'vpn' : 'port2',
    'internal' : 'port4',
    'transfer' : 'port3'
}

# external network - needed to create nat rules
ext_net = ipaddress.ip_network('203.0.113.0/24')

# firewall rule start index 
# the first rule index that will be taken by this script
# check with 'show firewall policy' or 'diagnose firewall iprope list 100004'
rules_index = 4

# service conversion table: map junos to fortinet services 
# https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-predefined-applications.html
service_map = { 
    'junos-ping' : 'PING',
    'junos-ftp' : 'FTP',
    'junos-ntp' : 'NTP',
    'junos-nfs' : 'NFS',
    'junos-ldap' : 'LDAP',
    'junos-http' : 'HTTP',
    'junos-https' : 'HTTPS',
    'junos-winframe' : 'WINFRAME',
    'junos-ms-sql' : 'MS-SQL',
    'junos-dns-tcp' : 'DNS',
    'junos-dns-udp' : 'DNS',
    'junos-smtp' : 'SMTP',
    'junos-mail' : 'SMTP',
    'junos-ssh' : 'SSH',
    'junos-syslog' : 'SYSLOG',
    'junos-pop3' : 'POP3' 
}

# read list of predefined services from fortigate
fgt_services_file = 'fgt-svc-list.txt'
with open(fgt_services_file, 'r') as service_file:
    fgt_predefined_services = service_file.read().splitlines()

###################
# -- Functions -- # 
###################

# check if element (interface, route) is deactivated
def inactive(element):
    try:
        state = element['@inactive']
        return True
    except KeyError:
        return False

# convert list to string with list elements separated by spaces and double-quoted
def list2str(liste):
    ausgabe = '"{}"'.format('" "'.join(liste))
    return(ausgabe)

# convert list to string with list elements separated by spaces
def convert(lst):
    return ' '.join(lst)

# return port range or a single port
def is_portrange(in_ports):
    if '-' in in_ports:
        port_range = in_ports.split('-')
        if port_range[0] == port_range[1]:
            return(port_range[0])
        else:
            return(in_ports)
    else:
        return(in_ports)

# transform source/destination of firewall rule to a format kompatible with fortigate
def srcdst(liste):
    if isinstance(liste, list):
        ausgabe = convert(liste)
    elif liste == 'any':
        ausgabe = 'all'
    else:
        ausgabe = liste
    return(ausgabe)

# firewall rule service/application lookup and transform
def app2svc(liste):
    if isinstance(liste, list):
        ausgabe = convert(liste)
    elif liste == 'any':
        ausgabe = 'ALL'
    else:
        ausgabe = liste
    return(ausgabe)

# create src nat rule
def create_src_nat_rule(zone,rule):
    out_name = rule['name']
    out_src = rule['src-nat-rule-match']['source-address']
    try:
        out_dst = rule['src-nat-rule-match']['destination-address']
    except:
        out_dst = '0.0.0.0/0'
    try:
        out_pool = rule['then']['source-nat']['pool']['pool-name']
    except:
        out_pool = ''
    out_rec = { 'name' : out_name,
                'source-address' : out_src,
                'destination-address' : out_dst,
                'pool-name' : out_pool,
                'destination-zone' : zone }
    return(out_rec)

# create destination nat rule ('vip')
def create_vip(rule,pool):
    mappedip = ''
    extip = ipaddress.ip_network(rule['dest-nat-rule-match']['destination-address']['dst-addr'].split('/')[0])
    # we only have two interfaces where nat happens...
    if extip.subnet_of(ext_net):
        extintf = 'port2'
    else:
        extintf = 'port4' 
    for item in pool:
        if item['name'] == rule['then']['destination-nat']['pool']['pool-name']:
            mappedip = item['address']['ipaddr'].split('/')[0]
    out_rec = { 'name' : rule['name'],
                'extip' : rule['dest-nat-rule-match']['destination-address']['dst-addr'].split('/')[0],
                'extintf' : extintf,
                'mappedip' : mappedip }
    return(out_rec)

# create destination nat rule ('vip') from 'static' rule
def create_static(rule):
    extip = ipaddress.ip_network(rule['static-nat-rule-match']['destination-address']['dst-addr'].split('/')[0])
    # we only have two interfaces where nat happens...
    if extip.subnet_of(ext_net):
        extintf = 'port2'
    else:
        extintf = 'port4'
    out_rec = { 'name' : rule['name'],
                'extip' : rule['static-nat-rule-match']['destination-address']['dst-addr'].split('/')[0],
                'extintf' : extintf,
                'mappedip' : rule['then']['static-nat']['prefix']['addr-prefix'].split('/')[0] }
    return(out_rec)

# read juniper xml config and create dictionary parsable by python
with open(infile) as file:
    srx_config = xmltodict.parse(file.read())

##############
# -- Main -- #
##############

#########################
# -- Address objects -- #
######################### 

# initialize lists
address_book = []
address_objects = []
group_objects = []

# get zone list
zones = srx_config['rpc-reply']['configuration']['security']['zones']['security-zone']
for zone in zones:
    try:
        address_objects.extend(zone['address-book']['address'])
    except KeyError:
        continue
    try:
        group_objects.extend(zone['address-book']['address-set'])
    except KeyError:
        continue

# create address book 
for address_object in address_objects:
    entry_name =  address_object['name']
    try:
        entry_addr = address_object['ip-prefix']
        obj_type = 'ip'
    except KeyError:
        try:
            entry_addr = address_object['dns-name']['name']
            obj_type = 'fqdn'
        except KeyError:
            try:
                entry_addr = address_object['range-address']
                obj_type = 'range'
            except KeyError:
                quit('Object Type Unknown')

    if obj_type == 'fqdn':
        addr_book_entry = { 'type' : obj_type, 'name' : entry_name, 'fqdn' : entry_addr }
    elif obj_type == 'ip':
        addr_book_entry = { 'type' : obj_type, 'name' : entry_name, 'ipaddress' : entry_addr }
    else:
        addr_book_entry = { 'type' : 'iprange', 'name' : entry_name, 'start-ip' : entry_addr['name'], 'end-ip' : entry_addr['to']['range-high'] } 
    address_book.append(addr_book_entry)
 
for group_object in group_objects:
    entry_name = group_object['name']
    entry_members = group_object['address']
    addr_book_entry = { 'type' : 'group', 'name' : entry_name, 'members' : entry_members }
    address_book.append(addr_book_entry)

# write address object creation commands to file
with open('address.txt', 'w') as outfile:
    outfile.write('config vdom\n') 
    outfile.write('edit ' + str(vdom) + '\n') 
    outfile.write('config firewall address\n') 
    for addr_obj in address_book:
        if addr_obj['type'] == 'group':
            continue
        obj_name = addr_obj['name']
        outfile.write('    edit "' + obj_name + '"' + '\n')
        if addr_obj['type'] == 'ip':
            obj_address = str(addr_obj['ipaddress'])
            outfile.write('        set subnet ' + obj_address + '\n')
        if addr_obj['type'] == 'fqdn':
            obj_fqdn = addr_obj['fqdn']
            outfile.write('        set type fqdn\n')
            outfile.write('        set fqdn "' + obj_fqdn + '"\n')
        if addr_obj['type'] == 'iprange':
            obj_start = addr_obj['start-ip']
            obj_end = addr_obj['end-ip']
            outfile.write('        set type iprange\n')
            outfile.write('        set start-ip ' + obj_start + '\n')
            outfile.write('        set end-ip ' + obj_end + '\n')
        outfile.write('    next\n')
    outfile.write('end\n')

# write group object creation commands to file
with open('address-groups.txt', 'w') as outfile:
    outfile.write('config vdom\n') 
    outfile.write('edit ' + str(vdom) + '\n') 
    outfile.write('config firewall addrgrp\n') 
    for group in group_objects:
        group_name = group['name']
        outfile.write('    edit "' + group_name + '"' + '\n')
        outfile.write('        set member ')
        if isinstance(group['address'], dict):
            member_name = group['address']['name']
            outfile.write('"' + member_name + '" ')
        else:
            for member in group['address']:
                member_name = member['name']
                outfile.write('"' + member_name + '" ')
        outfile.write('\n')
        outfile.write('    next\n')
    outfile.write('end\n')

#########################
# -- Service objects -- #
######################### 

# get applications from srx config
applications = srx_config['rpc-reply']['configuration']['applications']['application']
application_sets = srx_config['rpc-reply']['configuration']['applications']['application-set']

# initialize fortigate services lists
fg_services = []
fg_service_groups = []

# create services. intentionally ignoring source port and timeout settings.
for entry in applications:
    service_desc = ''
    port_list = []
    tcp_ports = []
    udp_ports = []
    icmp_services = []
    fg_service = []
    service_name = entry['name']
    if 'description' in entry:
        service_desc = entry['description']
    if 'term' in entry:
        port_list = entry['term']
        for port_list_entry in port_list:
            proto_prefix = port_list_entry['protocol']
            if proto_prefix == 'tcp':
                port = str(is_portrange(port_list_entry['destination-port']))
                tcp_ports.append(port)
            elif proto_prefix == 'udp':
                port = str(is_portrange(port_list_entry['destination-port']))
                udp_ports.append(port)
            else:
                continue
    else:
        proto_prefix = entry['protocol']
        if proto_prefix == 'tcp':
            port = str(is_portrange(entry['destination-port']))
            tcp_ports.append(port)
        elif proto_prefix == 'udp':
            port = str(is_portrange(entry['destination-port']))
            udp_ports.append(port)
        elif proto_prefix == 'icmp':
            icmp_type = entry['icmp-type']
            icmp_code = entry['icmp-code']
        else:
            continue
    fg_service = { 'name' : service_name,
                   'description' : service_desc,
                   'tcp_ports' : tcp_ports,
                   'udp_ports' : udp_ports,
                   'icmp_services' : icmp_services }
    if len(tcp_ports) > 0:
        fg_service['tcp_ports'] = tcp_ports
    if len(udp_ports) > 0:
        fg_service['udp_ports'] = udp_ports
    if proto_prefix == 'icmp':
        icmp_services = { 'icmptype' : icmp_type, 'icmpcode' : icmp_code }
        fg_service['icmp_services'] = icmp_services
    # populate services list
    fg_services.append(fg_service)

# create service groups
for entry in application_sets:
    group_member_list = []
    # junos service groups may contain a list of services...
    if isinstance(entry['application'], list):
        for member in entry['application']:
            group_member_list.append(member['name'])
    # ...or service groups and/or single applications
    else:
        if 'application' in entry:
            group_member_list.append(entry['application']['name'])
        if 'application-set' in entry:
            group_member_list.append(entry['application-set']['name'])
    # convert group members list to a "fortigate-compatible" format
    group_members = group_member_list
    fg_service_group = { 'name' : entry['name'], 'members' : group_members }
    # populate service groups list
    fg_service_groups.append(fg_service_group)    

# write command snippets for services and groups
with open('services.txt', 'w') as outfile:
    outfile.write('config vdom\n') 
    outfile.write('edit ' + str(vdom) + '\n') 
    outfile.write('config firewall service custom' + '\n')
    for service in fg_services:
        service_name = service['name']
        service_comment = service['description']
        outfile.write('    edit "' + service_name + '"' + '\n')
        if not service_comment == "":
            outfile.write('        set comment "' + service_comment + '"\n')
        service_tcp = service['tcp_ports']
        service_udp = service['udp_ports']
        service_icmp = service['icmp_services']
        if len(service_tcp) > 0:
            portrange = convert(service_tcp)
            outfile.write('        set tcp-portrange ' + portrange + '\n')
        if len(service_udp) > 0:
            portrange = convert(service_udp)
            outfile.write('        set udp-portrange ' + portrange + '\n')
        if bool(service_icmp):
            icmp_type = service_icmp['icmptype']
            icmp_code = service_icmp['icmpcode']
            outfile.write('        set protocol ICMP\n')
            outfile.write('        set icmptype ' + str(icmp_type) + '\n')
            outfile.write('        set icmpcode ' + str(icmp_code) + '\n')
        outfile.write('    next' + '\n')
    outfile.write('end' + '\n')

with open ('service-groups.txt', 'w') as outfile:
    outfile.write('config vdom\n')
    outfile.write('edit ' + str(vdom) + '\n')
    outfile.write('config firewall service group' + '\n')
    for service_group in fg_service_groups:
        group_name = service_group['name']
        if group_name in fgt_predefined_services:
            print('Skipping servicegroup ' + group_name)
            continue
        outfile.write('    edit "' + group_name + '"' + '\n')
        outfile.write('        set member ')
        for member in service_group['members']:
            if member in service_map:
                converted = service_map[member]
                outfile.write('"' + converted + '" ')
            else:
                outfile.write('"' + member + '" ')
        outfile.write('\n')
        outfile.write('    next\n')
    outfile.write('end\n')

###################
# -- NAT rules -- #
###################

# get source nat objects
srcnat_objects = srx_config['rpc-reply']['configuration']['security']['nat']['source']

# get src nat pools
src_nat_pools = []
for nat_object in srcnat_objects['pool']:
    src_nat_pools.append(nat_object)

# write ip pool commands to file
with open('ippool-commands.txt', 'w') as outfile:
    outfile.write('config vdom\n')
    outfile.write('edit ' + str(vdom) + '\n')
    outfile.write('config firewall ippool' + '\n')
    for pool in src_nat_pools:
        pool_name = pool['name']
        pool_addr = pool['address']['name'].split('/')[0]
        outfile.write('    edit "' + pool_name + '"' + '\n')
        outfile.write('        set type one-to-one' + '\n')
        outfile.write('        set startip ' + pool_addr + '\n')
        outfile.write('        set endip ' + pool_addr + '\n')
        outfile.write('    next' + '\n')
    outfile.write('end' + '\n')

# get src nat rules and create parsable datatypes, save in src_nat_rules
src_nat_rules = []
for ruleset in srcnat_objects['rule-set']:
    if ruleset['from']['zone'] == mig_zone:
        if not ruleset['to']['zone'] == mig_zone:
            destination_zone = ruleset['to']['zone']
            if isinstance(ruleset['rule'], list):
                for rule1 in ruleset['rule']:
                    nat_rule = create_src_nat_rule(destination_zone,rule1)
                    src_nat_rules.append(nat_rule)
            else:
                nat_rule = create_src_nat_rule(destination_zone,ruleset['rule'])
                src_nat_rules.append(nat_rule)

# get destination nat objects
dstnat_objects = srx_config['rpc-reply']['configuration']['security']['nat']['destination']

# get dst nat pools and rules
dst_nat_pools = []
dst_nat_rules = []
for nat_object in dstnat_objects['pool']:
    dst_address = ipaddress.ip_network(nat_object['address']['ipaddr'])
    if dst_address.subnet_of(mig_net):
        dst_nat_pools.append(nat_object)
for ruleset in dstnat_objects['rule-set']:
    if isinstance(ruleset['rule'], list):
        for rule in ruleset['rule']:
            if not inactive(rule):
                dst_nat_rules.append(create_vip(rule,dst_nat_pools))
    else:
        if not inactive(ruleset['rule']):
            dst_nat_rules.append(create_vip(ruleset['rule'],dst_nat_pools))

# static nat rules - handle like dst nat
# carefully test after migration, maybe additional source nat rules are needed
# because in junos, static nat seems to be dst *and* src nat...
static_nat_objects = srx_config['rpc-reply']['configuration']['security']['nat']['static']
for static_nat in static_nat_objects['rule-set']:
    rules = static_nat['rule']
    for rule in rules:
        if not inactive(rule):
            addr_prefix = ipaddress.ip_network(rule['then']['static-nat']['prefix']['addr-prefix'])
            if addr_prefix.subnet_of(mig_net):
                dst_nat_rules.append(create_static(rule))

# create command snippet from nat rules
with open('vip-commands.txt', 'w') as outfile:
    outfile.write('config vdom\n')
    outfile.write('edit ' + str(vdom) + '\n')
    outfile.write('config firewall vip' + '\n')
    for rule in dst_nat_rules:
        outfile.write('    edit "' + rule['name'] + '"\n')
        outfile.write('        set extip ' + rule['extip'] + '\n')
        outfile.write('        set extintf ' + rule['extintf'] + '\n')
        outfile.write('        set mappedip "' + rule['mappedip'] + '"\n')
        outfile.write('    next' + '\n')
    outfile.write('end' + '\n')

########################
# -- Firewall rules -- #
########################

# create fortigate policy
# 1. extract policy rules from srx ruleset
# 2. filter: process dmz rules only
# 3. check for duplicates and unusable rules (e.g. any any deny)
# 4. store satinized rules in separate list
# 5. process list to create fortigate commands

# get complete policy (list of policies)
security_policy = srx_config['rpc-reply']['configuration']['security']['policies']['policy']

# extract dmz policy rules
mig_policy_rules = []
for policy in security_policy:
    if policy['from-zone-name'] == mig_zone or policy['to-zone-name'] == mig_zone:
        if not policy['from-zone-name'] == policy['to-zone-name']:
            mig_policy_rules.append(policy)

# list containing sanitized rules
fg_policy = []
srx_policy = []
skipped_rules = []

# part one: ruleset scrubbing
for ruleset in mig_policy_rules:
    src_if = fg_topo[ruleset['from-zone-name']]
    dst_if = fg_topo[ruleset['to-zone-name']]
    policy = ruleset['policy']
    for rules in policy:
        skip_rule = False
        rule_check = {}
        rule_check['name'] = rules['name']
        rule_check['src_if'] = src_if
        rule_check['dst_if'] = dst_if
        if 'permit' in rules['then']:
            rule_check['action'] = 'accept'
        else:
            rule_check['action'] = 'deny'
        rule_check['src'] = srcdst(rules['match']['source-address'])
        rule_check['dst'] = srcdst(rules['match']['destination-address'])
        rule_check['services'] = app2svc(rules['match']['application'])
        if rule_check['src'] == 'all':
            if rule_check['dst'] == 'all':
                if rule_check['services'] == 'ALL':
                    rule_check['skip_reason'] = 'Any rule'
                    skipped_rules.append(rule_check)
                    continue
        if len(srx_policy) > 1:
            for dup_check in srx_policy:
                if dup_check['src'] == rule_check['src']:
                    if dup_check['dst'] == rule_check['dst']:
                       if dup_check['services'] == rule_check['services']:
                            dup_rule = dup_check['name']
                            skip_rule = True
                            rule_check['skip_reason'] = 'Duplicate of ' + dup_rule
        if skip_rule:
            skipped_rules.append(rule_check)
        else:
            srx_policy.append(rule_check)

# write skipped rules to file for further checks
with open('skipped_rules.json', 'w') as outfile:
    json.dump(skipped_rules, outfile)

# process remaining rules
for policy in srx_policy:
    src_list = policy['src'].split()
    for src in src_list:
        for entry in address_book:
            if entry['name'] == src:
                if entry['type'] == 'ip':
                    addr = entry['ipaddress']
                    if ipaddress.ip_address(addr.split('/')[0]) in mig_net:
                        fg_policy.append(policy)
    dst_list = policy['dst'].split()
    for dst in dst_list:
        for entry in address_book:
            if entry['name'] == dst:
                if entry['type'] == 'ip':
                    addr = entry['ipaddress']
                    if ipaddress.ip_address(addr.split('/')[0]) in mig_net:
                        fg_policy.append(policy)

# loop through filtered policy and add nat if needed
unique_rules = []
duplicate_rules = []
for policy in fg_policy:
    if not policy['name'] in unique_rules:
        unique_rules.append(policy['name'])
    else:
        duplicate_rules.append(policy)

# duplicate rules output
with open('duplicate_rules.json', 'w') as outfile:
    json.dump(duplicate_rules, outfile)

# create firewall rules import file
counter = rules_index
with open('firewall_rules.txt', 'w') as outfile:
    outfile.write('config vdom\n')
    outfile.write('edit ' + str(vdom) + '\n')
    outfile.write('config firewall policy\n')
    for rule_name in unique_rules:
        policy = [ pol for pol in fg_policy if pol['name'] == rule_name ][0]
        #json.dump(policy, outfile)
        outfile.write('    edit ' + str(counter) + '\n')
        outfile.write('        set name ' + policy['name'] + '\n')
        outfile.write('        set srcintf ' + policy['src_if'] + '\n')
        outfile.write('        set dstintf ' + policy['dst_if'] + '\n')
        outfile.write('        set action ' + policy['action'] + '\n')
        outfile.write('        set srcaddr ' + policy['src'] + '\n')
        outfile.write('        set dstaddr ' + policy['dst'] + '\n')
        outfile.write('        set service ')
        service_list = policy['services'].split()
        for service in service_list:
            if service in service_map:
                converted = service_map[service]
                outfile.write('"' + converted + '" ')
            else:
                outfile.write('"' + service + '" ')
        outfile.write('\n')
        outfile.write('        set schedule "always"\n')
        outfile.write('        set logtraffic all\n')
        outfile.write('    next' + '\n')
        counter += 1
    outfile.write('end' + '\n')
