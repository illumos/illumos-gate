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
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= ppt
OBJECTS		= $(PPT_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(PPT_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(USR_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/i86pc/io/vmm/io
MAPFILE		= $(UTSBASE)/i86pc/io/vmm/io/ppt.mapfile

#
#	Include common rules.
#
include $(UTSBASE)/i86pc/Makefile.i86pc

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Overrides and additions
#
ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)
PRE_INC_PATH	= -I$(COMPAT)/freebsd -I$(COMPAT)/freebsd/amd64 \
	-I$(CONTRIB)/freebsd -I$(CONTRIB)/freebsd/amd64
INC_PATH	+= -I$(UTSBASE)/i86pc/io/vmm -I$(UTSBASE)/i86pc/io/vmm/io
AS_INC_PATH	+= -I$(UTSBASE)/i86pc/io/vmm -I$(OBJS_DIR)

LDFLAGS         += -dy -N drv/vmm -N misc/pcie
LDFLAGS         += -M $(MAPFILE)

$(OBJS_DIR)/ppt.o := CERRWARN	+= -_gcc=-Wno-unused-variable

# needs work
SMOFF += all_func_returns

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/i86pc/Makefile.targ
