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

MANSECT= 	7m

_MANFILES = 	bufmod.7m	\
		connld.7m	\
		ldterm.7m	\
		pckt.7m		\
		pfmod.7m	\
		pipemod.7m	\
		ptem.7m		\
		sppptun.7m	\
		timod.7m	\
		tirdwr.7m	\
		ttcompat.7m	\
		usb_ah.7m	\
		usbkbm.7m	\
		usbms.7m	\
		vuidmice.7m

sparc_MANFILES=	kb.7m

MANLINKS=	vuid2ps2.7m	\
		vuid3ps2.7m	\
		vuidm3p.7m	\
		vuidm4p.7m	\
		vuidm5p.7m

MANFILES=	$(_MANFILES) $($(MACH)_MANFILES)

vuid2ps2.7m	:= LINKSRC = vuidmice.7m
vuid3ps2.7m	:= LINKSRC = vuidmice.7m
vuidm3p.7m	:= LINKSRC = vuidmice.7m
vuidm4p.7m	:= LINKSRC = vuidmice.7m
vuidm5p.7m	:= LINKSRC = vuidmice.7m

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
