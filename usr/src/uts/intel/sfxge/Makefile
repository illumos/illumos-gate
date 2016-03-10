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
# Copyright 2016 Garrett D'Amore <garrett@damore.org>
#

UTSBASE		= ../..

MODULE		= sfxge
OBJECTS		= $(SFXGE_OBJS:%=$(OBJS_DIR)/%)
OBJECS		+= $(SFXGE_SF_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(SFXGE_OBJS:%.o=$(LINTS_DIR)/%.ln)
LINTS		+= $(SFXGE_SF_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)

include $(UTSBASE)/intel/Makefile.intel

#
# Targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
# Overrides
#

INC_PATH += -I$(UTSBASE)/common/io/sfxge -I$(UTSBASE)/common/io/sfxge/common

#
# TODO:
# These are specific to this driver.  We will unidef these out later.
# Some of them need further cleanup as well (e.g. we shouldn't bother with
# supporting NDD directly.)
#
CPPFLAGS += -U_USE_MTU_UPDATE

CFLAGS += $(CCVERBOSE)

#
# Driver depends on GLDv3 (mac)
#
LDFLAGS		+= -dy -N misc/mac

#
# Default build targets.
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
