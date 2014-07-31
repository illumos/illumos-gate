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
# Copyright (c) 2014 Joyent, Inc.  All rights reserved.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= lx_netlink
OBJECTS		= $(LX_NETLINK_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(LX_NETLINK_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_SOCK_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

CPPFLAGS	+= -I$(UTSBASE)/common/brand/lx
LDFLAGS		+= -dy -Ndrv/ip -Nfs/sockfs

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
include $(UTSBASE)/intel/Makefile.targ

$(OBJS_DIR)/%.o:	$(UTSBASE)/common/brand/lx/io/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

$(LINTS_DIR)/%.ln:	$(UTSBASE)/common/brand/lx/io/%.c
	@($(LHEAD) $(LINT.c) $< $(LTAIL))
