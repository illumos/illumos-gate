#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

# Copyright 2011, Richard Lowe

include ../../Makefile.master

MANSECT = 	7p

MANFILES = 	arp.7p		\
	 	dlpi.7p		\
	 	icmp.7p		\
	 	icmp6.7p	\
	 	if_tcp.7p	\
	 	inet.7p		\
	 	inet6.7p	\
	 	ip.7p		\
	 	ip6.7p		\
	 	ipsec.7p	\
	 	ipsecah.7p	\
	 	ipsecesp.7p	\
	 	pf_key.7p	\
	 	rarp.7p		\
	 	route.7p	\
	 	routing.7p	\
	 	sctp.7p		\
	 	sip.7p		\
	 	slp.7p		\
	 	tcp.7p		\
	 	udp.7p

MANSOFILES =	AH.7p	\
	 	ARP.7p	\
	 	ESP.7p	\
	 	ICMP.7p	\
	 	IP.7p	\
	 	RARP.7p	\
	 	SCTP.7p	\
	 	TCP.7p	\
	 	UDP.7p	\
	 	if.7p

MANFILES +=	$(MANSOFILES)

ARP.7p	:= SOSRC = man7p/arp.7p

ICMP.7p := SOSRC = man7p/icmp.7p

if.7p	:= SOSRC = man7p/if_tcp.7p

IP.7p	:= SOSRC = man7p/ip.7p

AH.7p	:= SOSRC = man7p/ipsecah.7p

ESP.7p	:= SOSRC = man7p/ipsecesp.7p

RARP.7p := SOSRC = man7p/rarp.7p

SCTP.7p := SOSRC = man7p/sctp.7p

TCP.7p	:= SOSRC = man7p/tcp.7p

UDP.7p	:= SOSRC = man7p/udp.7p

.KEEP_STATE:

include ../Makefile.man

install: $(ROOTMANFILES)
