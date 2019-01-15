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
	Joyent-S10G5-hc-topology.xml

JOYENT_USBMAPS = \
	Joyent-S10G5-usb.usbtopo

ROOTJOYENTMAPS = $(JOYENT_PLATFORMS:%=$(arch_ROOTTOPOROOT)/%)
ROOTJOYENTUSB = $(JOYENT_USBMAPS:%=$(arch_ROOTTOPOROOT)/%)

TOPOFILE = \
	SSG-6049P-E1CR36L-hc-topology.xml \
	SSG-6049P-E1CR36L-chassis-hc-topology.xml \
	SSG-6049P-E1CR36L-slot-hc-topology.xml \
	SSG-6049P-E1CR36L-usb.usbtopo

SRCDIR = ../SMCI,SSG-6049P-E1CR36L

PLATFORM = SSG-6049P-E1CR36L

include ../Makefile.map

install: $(ROOTJOYENTMAPS) $(ROOTJOYENTUSB)
#
# Note, the Joyent S10G5 is based on the SuperMicro SSG-6049P-E1CR36L.
# Because of that, the topo map used here will work for all such
# systems.
#
$(ROOTJOYENTMAPS): SSG-6049P-E1CR36L-hc-topology.xml
	$(RM) $@
	$(SYMLINK) ./$? $@

$(ROOTJOYENTUSB): SSG-6049P-E1CR36L-usb.usbtopo
	$(RM) $@
	$(SYMLINK) ./$? $@
