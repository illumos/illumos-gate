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
# Copyright 2013 Nexenta Inc.  All rights reserved.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE		= ../..

#
#	Define the module and object file sets.
#
MODULE		= vioif
OBJECTS		= $(VIOIF_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(VIOIF_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#	Overrides
#

INC_PATH += -I$(UTSBASE)/common/io/virtio

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE)
#
# Driver depends on virtio and blkdev
#
LDFLAGS		+= -dy -N misc/virtio -N misc/mac

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
