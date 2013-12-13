liar
====

Liar is a python/scapy script that listens for DNS requests, checks them against a block list, and spoofs back a fake response.  Its intended purpose is blocking malicious domains.

It depends on the scapy packet manipulation library.  http://www.secdev.org/projects/scapy/

Usage: liar.py -i <interface> -f <blacklist file> [-d]

Reads a list of domains from a text file and sends back spoofed DNS responses for requests to them.  Designed for an environment in which an intrusion detection system sees DNS traffic via a passive tap and cannot block packets directly.  Runs in the foreground unless -d is specified.

Each line of the block list should consists of a domain, an IP, and an optional TTL separated by whitespace.  For example:

badguymalwaredownload.com     127.0.0.1       86400
