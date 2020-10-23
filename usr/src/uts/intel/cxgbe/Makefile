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
# Copyright (c) 2013 by Chelsio Communications, Inc. All rights reserved.
#

#
# This makefile drives the production of the Chelsio Terminator 4 10G Ethernet
# (CXGBE) driver modules on x86 systems.
#

UTSBASE = ../..

include $(UTSBASE)/intel/Makefile.intel

.KEEP_STATE:

SUBDIRS= t4nex cxgbe

all def clean clobber install: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ
