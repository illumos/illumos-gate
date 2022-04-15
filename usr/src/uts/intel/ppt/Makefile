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
# Copyright 2013 Pluribus Networks Inc.
# Copyright 2019 Joyent, Inc.
# Copyright 2022 Oxide Computer Company
#

UTSBASE	= ../..

MODULE		= ppt
OBJECTS		= $(PPT_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(USR_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/intel/io/vmm/io
MAPFILE		= $(UTSBASE)/intel/io/vmm/io/ppt.mapfile

include $(UTSBASE)/intel/Makefile.intel

ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)
ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)

PRE_INC_PATH	= \
	-I$(COMPAT)/bhyve \
	-I$(COMPAT)/bhyve/amd64 \
	-I$(CONTRIB)/bhyve \
	-I$(CONTRIB)/bhyve/amd64

INC_PATH	+= -I$(UTSBASE)/intel/io/vmm -I$(UTSBASE)/intel/io/vmm/io
AS_INC_PATH	+= -I$(UTSBASE)/intel/io/vmm -I$(OBJS_DIR)

LDFLAGS		+= -N drv/vmm -N misc/pcie
LDFLAGS		+= -M $(MAPFILE)

$(OBJS_DIR)/ppt.o := CERRWARN	+= -_gcc=-Wno-unused-variable

# needs work
SMOFF += all_func_returns

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

include $(UTSBASE)/intel/Makefile.targ
include $(UTSBASE)/intel/io/vmm/Makefile.rules
