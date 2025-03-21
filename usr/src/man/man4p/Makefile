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

#
# Copyright 2011, Richard Lowe
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT=	4p

MANFILES=	arp.4p		\
		dlpi.4p		\
		icmp.4p		\
		icmp6.4p	\
		if_tcp.4p	\
		inet.4p		\
		inet6.4p	\
		ip.4p		\
		ip6.4p		\
		ipsec.4p	\
		ipsecah.4p	\
		ipsecesp.4p	\
		ndp.4p		\
		pf_key.4p	\
		rarp.4p		\
		route.4p	\
		routing.4p	\
		sctp.4p		\
		sip.4p		\
		slp.4p		\
		tcp.4p		\
		udp.4p		\
		vxlan.4p

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
