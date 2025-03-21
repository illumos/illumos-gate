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
# Copyright 2018 Nexenta Systems, Inc.
# Copyright 2013, OmniTI Computer Consulting, Inc.
#

include		$(SRC)/Makefile.master

MANSECT=	3socket

MANFILES=	accept.3socket		\
		bind.3socket		\
		connect.3socket		\
		ethers.3socket		\
		getaddrinfo.3socket	\
		getifaddrs.3socket	\
		getipnodebyname.3socket \
		getnetbyname.3socket	\
		getpeername.3socket	\
		getprotobyname.3socket	\
		getservbyname.3socket	\
		getsockname.3socket	\
		getsockopt.3socket	\
		getsourcefilter.3socket \
		icmp6_filter.3socket	\
		if_nametoindex.3socket	\
		inet6_opt.3socket	\
		inet6_rth.3socket	\
		listen.3socket		\
		rcmd.3socket		\
		recv.3socket		\
		rexec.3socket		\
		sctp_bindx.3socket	\
		sctp_getladdrs.3socket	\
		sctp_getpaddrs.3socket	\
		sctp_opt_info.3socket	\
		sctp_peeloff.3socket	\
		sctp_recvmsg.3socket	\
		sctp_send.3socket	\
		sctp_sendmsg.3socket	\
		send.3socket		\
		sockaddr.3socket	\
		shutdown.3socket	\
		socket.3socket		\
		socketpair.3socket	\
		spray.3socket

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
