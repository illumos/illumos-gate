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
#

UTSBASE	= ../..

LX_CMN		= $(SRC)/common/brand/lx

MODULE		= lx_devfs
OBJECTS		= $(LX_DEVFS_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(LX_DEVFS_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(USR_FS_DIR)/$(MODULE)

INC_PATH	+= -I$(UTSBASE)/common/brand/lx -I$(LX_CMN)

include $(UTSBASE)/intel/Makefile.intel

ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

CFLAGS		+= $(CCVERBOSE)

LDFLAGS		+= -dy -Nbrand/lx_brand

# needs work
$(OBJS_DIR)/lxd_vnops.o := SMOFF += signed

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

include $(UTSBASE)/intel/Makefile.targ

include $(UTSBASE)/intel/lx_devfs/Makefile.rules
