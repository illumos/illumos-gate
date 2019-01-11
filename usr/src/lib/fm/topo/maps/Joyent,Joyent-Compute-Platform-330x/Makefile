#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2018, Joyent, Inc.
#

ARCH = i86pc
CLASS = arch
DTDFILE = topology.dtd.1
OTHER_VARIANTS = \
	Joyent-Compute-Platform-3302-hc-topology.xml

ROOTJOYENTMAPS = $(OTHER_VARIANTS:%=$(arch_ROOTTOPOROOT)/%)

TOPOFILE = \
	Joyent-Compute-Platform-3301-hc-topology.xml \
	Joyent-Compute-Platform-330x-chassis-hc-topology.xml \
	Joyent-Compute-Platform-330x-fan-hc-topology.xml

SRCDIR = ../Joyent,Joyent-Compute-Platform-330x

PLATFORM = Joyent-Compute-Platform-330x

CLOBBERFILES +=	$(ROOTJOYENTMAPS)

include ../Makefile.map

install: $(ROOTJOYENTMAPS)

#
# The JCP-3301 and JCP-3302 are essentially the same underlying hardware.  The
# only significant difference is the JCP-3302 uses SSDs internally instead of
# traditional disks.  As such, the same platform topo map should work for
# both platforms so we simply create a symlink from the JCP 3301 map for the
# JCP 3302.
#
$(ROOTJOYENTMAPS): Joyent-Compute-Platform-3301-hc-topology.xml
	$(RM) $@
	$(SYMLINK) ./$? $@

