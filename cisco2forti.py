#!/usr/bin/python3

# Convert Cisco Router ACL to Fortinet firewall rules and objects
# Creates output files that can be copy-pasted to Fortinet firewall
#
# Thanks to Fortinet for not providing a usable API documentation *stinkefinger-smiley*
#
# dj0Nz Mar 2023

import re
import ipaddress

# Input file containing Cisco ACL export
infile = 'cisco-acl.txt'
objectsfile = 'network-objects.txt'
rulesfile = 'rules.txt'

# Lists for network objects and rules
netobjects = []
rules = []

# Network topology - Routes and interfaces on Fortigate
topology = {
    "0.0.0.0/0":"bond3",
    "192.168.3.0/24":"bond0.203",
    "10.10.0.0/16":"eth7",
}

# Start-ID for new rules
rule_id = 2

# Regex pattern to filter unneeded rules
established_pattern = re.compile('established')
ospf_pattern = re.compile('ospf')

# Regex pattern to identify wildcard masks
wildcard_pattern = re.compile('^0\\.')

# Function to convert wildcard mask to either prefix length (default) or netmask 
def convert_wildcard (wildcardmask):
    prefixlen=str(ipaddress.IPv4Address._prefix_from_ip_int(int(ipaddress.IPv4Address(wildcardmask))^(2**32-1)))
    return(prefixlen)

# Find source or destination if for packet
def if_lookup_net (addr):
    if addr == 'any':
        interface = topology['0.0.0.0/0']
    else:
        for net in topology:
            input_network = ipaddress.ip_network(addr)
            topo_network = ipaddress.ip_network(net)
            check = input_network.subnet_of(topo_network)
            if check:
                interface = topology[net]
    return(interface)

# Convert Cisco ip acl to "any" rule
def create_ip_rule (testacl):
    rule = []
    # Set action based on acl[0]
    if testacl[0] == 'permit':
        action = 'accept'
    else:
        action = 'deny'

    # This is an "ip any" ACL
    service = 'ALL'

    # Get source from netobjects or any
    source = ''
    if testacl[2] == 'any':
        source = 'any'
    else:
        num=len(netobjects)
        for index in range(0, num):
            found = re.search(rf'^{testacl[2]}',netobjects[index])
            if found:
                source = netobjects[index]
    
    # Determine source interface
    srcif = if_lookup_net(source)

    # Get destination from netobjects list
    destination = ''
    if testacl[2] == 'any':
        if testacl[3] == 'host':
            num=len(netobjects)
            for index in range(0, num):
                found = re.search(rf'^{testacl[4]}',netobjects[index])
                if found:
                    destination = netobjects[index]
        else:
            num=len(netobjects)
            for index in range(0, num):
                found = re.search(rf'^{testacl[3]}',netobjects[index])
                if found:
                    destination = netobjects[index]
    else:
        if not testacl[4] == 'any':
            num=len(netobjects)
            for index in range(0, num):
                found = re.search(rf'^{testacl[4]}',netobjects[index])
                if found:
                    destination = netobjects[index]
        else:
            destination = 'any'
        
    # Determine destination interface
    dstif = if_lookup_net(destination)

    # Firewall rule objects - needs to be transformed to "write command to file" and "use defined object format"
    rule=[action,service,source,srcif,destination,dstif]
    # Output for troubleshooting
    print(rule)
    rules.append(rule)

    
# Open ACL file and read contents into list
with open(infile) as aclfile:
    ciscoacls = aclfile.readlines()

num = 0

# Loop through file containing cisco acls, collect network objects and 
for line in ciscoacls:
    # Transform line to list
    acl = line.split()
    # Delete acl number
    del acl[0]
    # Delete log keyword
    last = acl[-1]
    if last == 'log':
        del acl[-1]
    # Filter "established" acls
    established = re.search(established_pattern, line)
    if established:
        continue
    # Filter ospf rules
    ospf = re.search(ospf_pattern, line)
    if ospf:
        continue
    # Filter source port rules with source address any
    if acl[2] == 'any':
        if acl[3] == 'eq':
            continue
        if acl[3] == 'range':
            continue
    # Filter source port rules to specific hosts
    if acl[2] == 'host':
        if acl[4] == 'eq':
            continue
    num = len(acl)
    # Loop through complete line
    for index in range(0, num):
        # If host keyword found, next field is ip address
        if acl[index] == 'host':
            nextindex = index + 1
            # Check if hostobject already in list and add, if not
            hostcheck = netobjects.count(acl[nextindex])
            if not hostcheck:
                hostobject = acl[nextindex] + '/32'
                netobjects.append(hostobject)
        # Check if field is wildcard mask
        wildcard = re.search(wildcard_pattern, acl[index])
        # If yes, then previous filed contains network address
        if wildcard:
            netobject = acl[index-1] + '/' + convert_wildcard (acl[index]) 
            netobjects.append(netobject)
        # Content checking: Output with space delimiter
        # print(acl[index], end = ' ')
    # Content checking: Linefeed after complete line
    # print()
    # Rules section
    rules.append(acl)
    #if acl[1] == 'ip':
    #    create_ip_rule(acl)


# Write objects to file in copy-paste-to-fortinet format
with open(objectsfile, 'w') as file:
    file.write('config firewall address\n')
    for x in range(len(netobjects)):
        netname,netmask = netobjects[x].split('/')
        if netmask == '32':
            file.write('edit host_' + netname + '\n')
            file.write('  set subnet ' + netobjects[x] + '\n')
            file.write('next\n')
        else:    
            file.write('edit net_' + netname + '_' + netmask + '\n')
            file.write('  set subnet ' + netobjects[x] + '\n' )
            file.write('next\n')
    file.write('end\n')

# Checking list contents
print(*netobjects, sep = '\n')
print(*rules, sep = '\n')