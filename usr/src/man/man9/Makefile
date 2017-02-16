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
# Copyright 2017, Richard Lowe
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT= 	9
MANFILES=	Intro.9	\
		vmem.9


MANLINKS=	intro.9

intro.9		:= LINKSRC = Intro.9

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install: 	$(ROOTMANFILES) $(ROOTMANLINKS)
