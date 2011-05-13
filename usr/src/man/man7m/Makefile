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

MANSECT = 	7m

COMMON_MANFILES = 	bufmod.7m	\
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

MANSOFILES =	vuid2ps2.7m	\
		vuid3ps2.7m	\
		vuidm3p.7m	\
		vuidm4p.7m	\
		vuidm5p.7m

MANFILES =	$(COMMON_MANFILES) $($(MACH)_MANFILES) $(MANSOFILES)

vuid2ps2.7m	:= SOSRC = man7m/vuidmice.7m
vuid3ps2.7m	:= SOSRC = man7m/vuidmice.7m
vuidm3p.7m	:= SOSRC = man7m/vuidmice.7m
vuidm4p.7m	:= SOSRC = man7m/vuidmice.7m
vuidm5p.7m	:= SOSRC = man7m/vuidmice.7m

.KEEP_STATE:

include ../Makefile.man

install: $(ROOTMANFILES)
