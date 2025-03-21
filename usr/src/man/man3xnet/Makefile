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

MANSECT=	3xnet

MANFILES=	accept.3xnet		\
		bind.3xnet		\
		connect.3xnet		\
		endhostent.3xnet	\
		endnetent.3xnet		\
		endprotoent.3xnet	\
		endservent.3xnet	\
		freeaddrinfo.3xnet	\
		gai_strerror.3xnet	\
		gethostname.3xnet	\
		getnameinfo.3xnet	\
		getpeername.3xnet	\
		getsockname.3xnet	\
		getsockopt.3xnet	\
		htonl.3xnet		\
		if_nametoindex.3xnet	\
		inet_addr.3xnet		\
		inet_ntop.3xnet		\
		listen.3xnet		\
		recv.3xnet		\
		recvfrom.3xnet		\
		recvmsg.3xnet		\
		send.3xnet		\
		sendmsg.3xnet		\
		sendto.3xnet		\
		setsockopt.3xnet	\
		shutdown.3xnet		\
		sockatmark.3xnet	\
		socket.3xnet		\
		socketpair.3xnet

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
