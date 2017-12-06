#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright (c) 2017, Joyent, Inc.
#

# NOTE: The name of the xml file we are building is 'platform'
# specific, but its build is structured as 'arch' specific since
# 'uname -i' on all x86 platforms returns i86pc.

ARCH = i86pc
CLASS = arch
DTDFILE = topology.dtd.1
JOYENT_PLATFORMS = \
	Joyent-Compute-Platform-3101-hc-topology.xml \
	Joyent-Compute-Platform-3102-hc-topology.xml

ROOTJOYENTMAPS = $(JOYENT_PLATFORMS:%=$(arch_ROOTTOPOROOT)/%)

TOPOFILE = \
	SSG-2028R-ACR24L-hc-topology.xml \
	SSG-2028R-ACR24L-chassis-hc-topology.xml \
	SSG-2028R-ACR24L-disk-hc-topology.xml

SRCDIR = ../SMCI,SSG-2028R-ACR24L

PLATFORM = SSG-2028R-ACR24L

CLOBBERFILES +=	$(ROOTJOYENTMAPS) SSG-2028R-ACR24L-disk-hc-topology.xml

include ../Makefile.map

install: $(ROOTJOYENTMAPS)

#
# Note, the Joyent Compute Platform 310x is based on the SuperMicro
# SSG-2028R-ACR24L. Because of that, the topo map used here will work for all
# such systems.
#
$(ROOTJOYENTMAPS): SSG-2028R-ACR24L-hc-topology.xml
	$(RM) $@
	$(SYMLINK) ./$? $@

