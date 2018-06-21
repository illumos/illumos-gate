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

# NOTE: The name of the xml file we are building is 'platform'
# specific, but its build is structured as 'arch' specific since
# 'uname -i' on all x86 platforms returns i86pc.

ARCH = i86pc
CLASS = arch
DTDFILE = topology.dtd.1
JOYENT_PLATFORMS = \
	Joyent-M12G5-hc-topology.xml

ROOTJOYENTMAPS = $(JOYENT_PLATFORMS:%=$(arch_ROOTTOPOROOT)/%)

TOPOFILE = \
	SSG-2029P-ACR24L-hc-topology.xml \
	SSG-2029P-ACR24L-chassis-hc-topology.xml \
	SSG-2029P-ACR24L-disk-hc-topology.xml \
	SSG-2029P-ACR24L-slot-hc-topology.xml

SRCDIR = ../SMCI,SSG-2029P-ACR24L

PLATFORM = SSG-2029P-ACR24L

CLOBBERFILES +=	SSG-2029P-ACR24L-disk-hc-topology.xml

include ../Makefile.map

install: $(ROOTJOYENTMAPS)

#
# Note, the Joyent M12G5 is based on the SuperMicro SSG-2029P-ACR24L.
# Because of that, the topo map used here will work for all such
# systems.
#
$(ROOTJOYENTMAPS): SSG-2029P-ACR24L-hc-topology.xml
	$(RM) $@
	$(SYMLINK) ./$? $@
