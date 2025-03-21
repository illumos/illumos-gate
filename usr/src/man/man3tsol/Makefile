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
# Copyright 2017 Peter Tribble
#

include		$(SRC)/Makefile.master

MANSECT=	3tsol

MANFILES=	blcompare.3tsol		\
		blminmax.3tsol		\
		bltocolor.3tsol		\
		bltos.3tsol		\
		btohex.3tsol		\
		getdevicerange.3tsol	\
		getlabel.3tsol		\
		getpathbylabel.3tsol	\
		getplabel.3tsol		\
		getuserrange.3tsol	\
		getzonelabelbyid.3tsol	\
		getzonerootbyid.3tsol	\
		hextob.3tsol		\
		label_to_str.3tsol	\
		m_label.3tsol		\
		sbltos.3tsol		\
		setflabel.3tsol		\
		stobl.3tsol		\
		str_to_label.3tsol	\
		tsol_getrhtype.3tsol

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
