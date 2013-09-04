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

MANSECT= 	1c

MANFILES= 	ct.1c		\
		cu.1c		\
		rup.1c		\
		uucp.1c		\
		uuencode.1c	\
		uuglist.1c	\
		uustat.1c	\
		uuto.1c		\
		uux.1c

MANLINKS=	uudecode.1c	\
		uulog.1c	\
		uuname.1c	\
		uupick.1c

uulog.1c	:= LINKSRC = uucp.1c
uuname.1c	:= LINKSRC = uucp.1c

uudecode.1c	:= LINKSRC = uuencode.1c

uupick.1c	:= LINKSRC = uuto.1c

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
