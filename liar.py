#!/usr/bin/python -u

# liar.py -i <interface> -f <blacklist file> [-d]
#
# Reads a list of domains from a text file and sends back spoofed DNS
# responses for requests to them.  Designed for an environment in which
# an intrusion detection system sees DNS traffic via a passive tap and
# cannot block packets directly.
#
# Runs in the foreground unless -d is specified.
#
# Each line of the block list should consists of a domain, an IP, and an
# optional TTL separated by whitespace.  For example:
#
# badguymalwaredownload.com	127.0.0.1	86400

import os
import sys
import time
import getopt
import signal
from scapy.all import *

# TODO
#
# Add wildcarding.  Switch from blocklist["abc123.com."] to 
#	blocklist["com"]["abc123"]
# Add a whitelist to go with the wildcarding so we can block *.dynwhatever.com
# 	but still allow goodguy.dynwhatever.com.

# Pcap filter.  Adjust as needed for your environment.
filter = "src net 10.0.0.0/8 and udp and dst port 53"

# Default TTL to return in spoofed responses
default_ttl = 300

# Note: interface name will be appended to the pid file
pidfile = "/var/run/liar-"

blocklist = {}

def usage():
	print "Usage: %s -i <interface> -f <blacklist file> [-d]" % os.path.basename(__file__)
	sys.exit(2)

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "i:f:d")
	except getopt.GetoptError as err:
		# Print error and usage and exit
		print str(err)
		usage()
	interface = None
	blockfile = None
	daemon = False
	for opt, arg in opts:
		if opt == "-i":
			interface = arg
		elif opt == "-f":
			blockfile = arg
		elif opt == "-d":
			daemon = True
		else:
			assert False, "unhandled option"

	if not interface or not blockfile:
		usage()

	# It would be nice if we could reload the block list via SIGHUP,
	# but this crashes scapy, and I haven't figured out how to fix it.
	#signal.signal(signal.SIGHUP, lambda signum, frame : load_list(blockfile))

	# Load the block list
	load_list(blockfile)

	# Get the length of the first part of each hostname.  We'll use
	# that to narrow down our pcap filter so we don't have to look 
	# at every DNS packet.  This is particularly effective for DGAs
	# that generate unusually long domain names.
	#
	# E.g. "udp and dst port 53 and udp[20] == 12" matches
	# 0123456789abc.com but not abc.com
	token_len = {}
	for hostname in blocklist.keys():
		first_token_len = len(re.split('\.', hostname)[0])
		token_len[first_token_len] = 1
	
	additional_filter = " or ".join(["udp[20] == %s" % length for length in token_len.keys()])
	complete_filter = "%s and (%s)" % (filter, additional_filter)
	print "filter: %s" % complete_filter

	# Write our PID file
	pid = str(os.getpid())
	file(pidfile + interface, 'w').write(pid)

	# Fork into the background if running with -d
	if daemon and os.fork():
		sys.exit()

	# Sniff for packets
	sniff(filter=complete_filter, prn=packet_handler, iface=interface, store=0)

# Load the block list.  The block list consists of a hostname, ip, and
# optional TTL, separated by whitespace.  Any line beginning with a non
# alpha numeric character will be ignored.  Hostnames will be normalized
# to lower case.
def load_list(blockfile):
	f = open(blockfile, 'r')
	for line in f:
		if re.match('^[a-zA-Z0-9]', line):
			# Extract the hostname, dest ip, and optional TTL from each line
			element  = []
			element  = re.split('\s+', line.strip())
			hostname = element[0].lower()
			block_ip = element[1]
			if len(element) > 2:
				ttl = int(element[2])
			else:
				ttl = default_ttl
			blocklist[hostname + '.'] = [block_ip, ttl]

	f.close()
	print "Loaded %d blocklist entries" % len(blocklist)

def packet_handler(pkt):
	# Is this a DNS packet that isn't a response?
	if (DNSQR in pkt and pkt[DNS].qr == 0L):
		# Is the query name in our block list?
		hostname = pkt[DNSQR].qname.lower()
		(block_ip, block_ttl) = blocklist.get(hostname, [0, 0])

		if not block_ip:
			# Hostname is not in our block list
			return

		# Hostname is in our block list
		print "%s Spoofing %s %d -> %s %d, %s = %s, ttl %d" % (
			time.strftime('%Y-%m-%d %H:%M:%S %z'),
			pkt[IP].dst, pkt[UDP].dport,
			pkt[IP].src, pkt[UDP].sport,
			hostname, block_ip, block_ttl
		)

		# Send a spoofed response
		spoofed_response = IP(dst=pkt[IP].src, src=pkt[IP].dst)\
                    /UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)\
                    /DNS(id=pkt[DNS].id, rd=pkt[DNS].rd, ra=pkt[DNS].rd, qr=1L,\
			ancount=1, qdcount=1, qd=pkt[DNSQR],\
			an=DNSRR(rrname=pkt[DNSQR].qname, ttl=block_ttl, rdata=block_ip)\
                    /DNSRR(rrname=pkt[DNSQR].qname, rdata=block_ip))
                send(spoofed_response, verbose=0)

if __name__ == '__main__':
    main()
