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
# Copyright 2024 Oxide Computer Company
#

#
# This makefile drives the production of the Chelsio Terminator 4 10G Ethernet
# (CXGBE) driver modules on x86 systems.
#

#
# Paths to the base of the uts directory trees
#
UTSBASE = ../../..

#
# Define the module and object file sets.
#
MODULE		= cxgbe
OBJECTS		= $(CXGBE_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)

#
# Include common rules
#
include $(UTSBASE)/intel/Makefile.intel

#
# Define targets
#
ALL_TARGET = $(BINARY)
INSTALL_TARGET = $(BINARY) $(ROOTMODULE)

CFLAGS += -I$(UTSBASE)/common/io/cxgbe/t4nex \
	-I$(UTSBASE)/common/io/cxgbe/shared

#
# Driver depends
#
LDFLAGS += -N misc/mac -N drv/ip -N drv/t4nex

#
# Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

#
# Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ
