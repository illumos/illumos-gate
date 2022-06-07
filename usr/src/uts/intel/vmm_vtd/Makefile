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
# Copyright 2019 Joyent, Inc.
# Copyright 2022 Oxide Computer Company
#

UTSBASE	= ../..

MODULE		= vmm_vtd
OBJECTS		= $(VMM_VTD_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(USR_MISC_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/intel/io/vmm
MAPFILE		= $(UTSBASE)/intel/io/vmm/vmm_vtd.mapfile

PRE_INC_PATH	= \
	-I$(COMPAT)/bhyve \
	-I$(COMPAT)/bhyve/amd64 \
	-I$(CONTRIB)/bhyve \
	-I$(CONTRIB)/bhyve/amd64

INC_PATH	+= -I$(UTSBASE)/intel/io/vmm -I$(UTSBASE)/intel/io/vmm/io
AS_INC_PATH	+= -I$(UTSBASE)/intel/io/vmm -I$(OBJS_DIR)

LDFLAGS		+= -N drv/vmm -N misc/acpica -N misc/pcie
LDFLAGS		+= -M $(MAPFILE)

include $(UTSBASE)/intel/Makefile.intel

ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)

.PARALLEL:	$(OBJECTS)

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

include $(UTSBASE)/intel/Makefile.targ
include $(UTSBASE)/intel/io/vmm/Makefile.rules
