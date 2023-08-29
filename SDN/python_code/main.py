# /*-------------------------------------------------------------------------------\
# | SDN (Intrusion Prevention)                                                     |
# +--------------------------------------------------------------------------------+
# |  Programmed by Vivek BG			                   |
# +--------------------------------------------------------------------------------|
# | Version 1.0                                                                    |
# +--------------------------------------------------------------------------------+
# | CODE DESCRIPTION:                                                              |
# |     SDN Based Intrusion Prevention, a simple simulation of access controls     |
# |     filterations.                                                              |
# +--------------------------------------------------------------------------------+ 

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.link import Intf
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from threading import Thread
from subprocess import call
import mysql.connector
import time
import requests
import json
import subprocess
import multiprocessing

SNMP_START_CMD = '/usr/sbin/snmpd -Lsd -Lf /dev/null -u root -I -smux -p /var/run/snmpd.pid -c /etc/snmp/snmpd.conf'
SNMP_WALK_CMD = 'snmpwalk -v 1 -c public -O e '
SNMP_WALK_OUT = 'dump.out'


def init_ips():

	cmd = subprocess.Popen(['gnome-terminal','--', 'python3','ips.py'])
	cmd.wait()

def myNetwork():

	# establish a connection to the MySQL server
	cnx = mysql.connector.connect(user='vk', password='vk',
	                              host='localhost', database='sdn')

	# create a cursor object to execute SQL queries
	cursor = cnx.cursor()

	# execute an SQL query
	query = "SELECT * FROM checkhere"
	cursor.execute(query)

	# fetch the results of the query
	results = cursor.fetchall()
	items = ''
	acl_dict = {'SSH': {'id':1, 'status':0, 'port':22, 'layer4':'TCP', 'flow_name': {} }, 
				'SNMP': {'id':2, 'status':0, 'port':161, 'layer4':'UDP', 'flow_name': {} }, 
				'TELNET': {'id':3, 'status':0, 'port':23, 'layer4':'TCP', 'flow_name': {} }}
	for row in results:
	    name = row[1].upper()
	    val = row[2]
	    if(val==1):
	        items += '   -> '+ name + '\n'
	        acl_dict[name]['status']=1
    
	print("[+] Protocols for the watch list:\n\n"+ items + "\n Rules will be checked and activated accordingly...") 

	# Topology
	net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')
	# Add remote ODL controller
	c0 = net.addController(name='c0', controller=RemoteController, ip='10.0.2.15', port=6633)

	# Add switches
	s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
	s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
	#Intf( 'enp0s3', node=s1 )


	# Add hosts to switches
	h1 = net.addHost('h1', cls=Node, ip='10.0.2.1/24')
	h2 = net.addHost('h2', cls=Node, ip='10.0.2.2/24')
	h3 = net.addHost('h3', cls=Node, ip='10.0.2.3/24')
	h4 = net.addHost('h4', cls=Node, ip='10.0.2.4/24')


	# Add host-switch links in the same subnet
	net.addLink(h1, s1)
	net.addLink(h2, s1)
	net.addLink(h3, s2)
	net.addLink(h4, s2)

	# Add switch-switch link
	net.addLink(s1, s2)

	# Start network
	net.build()
	#net.start()
	c0.start()
	s1.start([c0])
	s2.start([c0])

	# Wait for switches to connect to controller
	time.sleep(3)

	# Set the data for the flow entry	
	
	ssh_flow = {
	    "flow-node-inventory:flow": [
		{
		    "id": "1",
		    "table_id": "0",
		    "priority": "100",
		    "flow-name": "SSH BLOCK",
		    "match": {
		        "ethernet-match": {
		            "ethernet-type": {
		                "type": "0x0800"
		            }		             
		        },
		        "ip-match": {
	                    "ip-proto": "ipv4"
	                },
		        "tcp-destination-port": "22"
		    },
		    "instructions": {
		        "instruction": [
		            {
		                "order": "0",
		                "apply-actions": {
		                    "action": [
		                        {
		                            "order": "0",
		                            "drop-action": {}
		                        }
		                    ]
		                }
		            }
		        ]
		    }
		}
	    ]
	}
	snmp_flow = {
	    "flow-node-inventory:flow": [
		{
		    "id": "2",
		    "table_id": "0",
		    "priority": "100",
		    "flow-name": "SNMP BLOCK",
		    "match": {
		        "ethernet-match": {
		            "ethernet-type": {
		                "type": "0x0800"
		            }		             
		        },
		        "ip-match": {
	                    "ip-proto": "ipv4"
	                },
		        "udp-destination-port": "161"
		    },
		    "instructions": {
		        "instruction": [
		            {
		                "order": "0",
		                "apply-actions": {
		                    "action": [
		                        {
		                            "order": "0",
		                            "drop-action": {}
		                        }
		                    ]
		                }
		            }
		        ]
		    }
		}
	    ]
	}
	telnet_flow = {
	    "flow-node-inventory:flow": [
		{
		    "id": "3",
		    "table_id": "0",
		    "priority": "100",
		    "flow-name": "TELNET BLOCK",
		    "match": {
		        "ethernet-match": {
		            "ethernet-type": {
		                "type": "0x0800"
		            }		             
		        },
		        "ip-match": {
	                    "ip-proto": "ipv4"
	                },
		        "tcp-destination-port": "23"
		    },
		    "instructions": {
		        "instruction": [
		            {
		                "order": "0",
		                "apply-actions": {
		                    "action": [
		                        {
		                            "order": "0",
		                            "drop-action": {}
		                        }
		                    ]
		                }
		            }
		        ]
		    }
		}
	    ]
	}
	acl_dict['SSH']['flow_name']=ssh_flow
	acl_dict['SNMP']['flow_name']=snmp_flow
	acl_dict['TELNET']['flow_name']=telnet_flow


	# Set the headers for the RESTCONF API request
	headers = {
	    'Content-Type': 'application/json',
	    'Accept': 'application/json'
	}

	for protocol, values in acl_dict.items():
		if(values['status']==1):
			print(f"\n[*]-----> UPDATING WATCHLIST FOR {protocol}\n")
			if(values['layer4']=='TCP'):
				layer4=6
			else:
				layer4=17
			flow_id= values['id']
			url= f"http://10.0.2.15:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/{flow_id}"
			# DELETE req0uest to remove flow entry to update next 
			response = requests.delete(url, auth=('admin', 'admin'), headers=headers)
			
			if response.status_code == 200 or response.status_code == 204:
				print("\t[+] Removing any obsolete entries associated with this rule...\n\t[+] Preparing to update...")

			# GET request to check if the flow entry exists or not
			response = requests.get(url, auth=('admin', 'admin'), headers=headers)

			if response.status_code != 200:
				# PUT request to install blocking flows on switches
				response = requests.put(url, auth=('admin', 'admin'), headers=headers, json=values['flow_name'])		
				s1_ovs = net.get('s1')

				s1_ovs.cmd(f"ovs-ofctl add-flow s1 \"table=0, priority=100, dl_type=0x0800, nw_proto={layer4}, tp_dst={values['port']}, actions=drop\"")
				# Check if the request was successful
				if response.status_code == 200 or response.status_code == 201:
					print("\t[+] Flow entry added successfully\n\n")
				else:
			  		print("\t[+] Error adding flow entry: response code:{1} || {0}".format(response.content,response.status_code))
			  		exit(0)
			else:
				print(f"[+] Flow entry for {protocol} exists in the controller. Previous configurations used instead.")
		elif(values['status']==0):
			print(f"[*]-----> Checking the status of {protocol} and clearing any unwanted rules...")
			if(values['layer4']=='TCP'):
				layer4=6
			else:
				layer4=17
			flow_id= values['id']
			url= f"http://10.0.2.15:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:1/table/0/flow/{flow_id}"
			response = requests.delete(url, auth=('admin', 'admin'), headers=headers)			
			if response.status_code == 200 or response.status_code == 204:
				print(f"\t[+] Entry for the {protocol} removed from the watchllist.\n")
			else:
				print(f"\t[+] Nothing to clean here.\n")
			s1_ovs = net.get('s1')
			s1_ovs.cmd(f"ovs-ofctl del-flows s1 \"table=0, priority=100, dl_type=0x0800, nw_proto={layer4}, tp_dst={values['port']}\"")
	print("\n===================================================\n")
	print("\n[+] Entering the Mininet realm to experiment the traffic...")	


	# Start CLI
	CLI(net)

	# Stop network
	net.stop()
	

if __name__ == '__main__':
    setLogLevel( 'info' ) 
    # proc = multiprocessing.Process(target=init_ips)
    # proc.start()  
    myNetwork()
