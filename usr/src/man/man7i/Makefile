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

MANSECT= 	7i

_MANFILES=	audio.7i	\
		cdio.7i		\
		dkio.7i		\
		dsp.7i		\
		fbio.7i		\
		fdio.7i		\
		hdio.7i		\
		iec61883.7i	\
		ipnat.7i	\
		mhd.7i		\
		mixer.7i	\
		mtio.7i		\
		prnio.7i	\
		quotactl.7i	\
		sesio.7i	\
		sockio.7i	\
		streamio.7i	\
		termio.7i	\
		termiox.7i	\
		uscsi.7i	\
		visual_io.7i	\
		vt.7i

i386_MANFILES=	agpgart_io.7i

MANFILES=	$(_MANFILES) $($(MACH)_MANFILES)

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
