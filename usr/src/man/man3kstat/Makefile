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

MANSECT= 	3kstat

MANFILES= 	kstat.3kstat			\
		kstat_chain_update.3kstat	\
		kstat_lookup.3kstat		\
		kstat_open.3kstat		\
		kstat_read.3kstat

MANLINKS=	kstat_close.3kstat		\
		kstat_data_lookup.3kstat	\
		kstat_write.3kstat

kstat_data_lookup.3kstat	:= LINKSRC = kstat_lookup.3kstat

kstat_close.3kstat		:= LINKSRC = kstat_open.3kstat

kstat_write.3kstat		:= LINKSRC = kstat_read.3kstat

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
