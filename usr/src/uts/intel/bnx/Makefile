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
# Copyright (c) 2018, Joyent, Inc.
#

#
# uts/intel/bnx/Makefile
#
#	This makefile drives the production of the bnx
#	driver kernel module.
#
#	intel architecture dependent
#

#
#	Paths to the base of the uts directory trees
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= bnx
OBJECTS		= $(BNX_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(LINTS_DIR)/bnx_lint.ln
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
SRCDIR		= $(UTSBASE)/common/io/bnx
CONF_SRCDIR	= $(SRCDIR)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(CONFMOD)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

#
#	Driver-specific flags
#
CPPFLAGS += \
	-D_USE_FRIENDLY_NAME \
	-DEXCLUDE_RSS_SUPPORT \
	-DEXCLUDE_KQE_SUPPORT \
	-DL2_ONLY \
	-DSOLARIS \
	-D_ANSI_C_ \
	-DLM_MAX_MC_TABLE_SIZE=256 \
	-DBRCMVERSION="\"7.10.4\"" \
	-DLITTLE_ENDIAN \
	-DLITTLE_ENDIAN_HOST \
	-D__LITTLE_ENDIAN

CPPFLAGS += \
	-I$(SRCDIR) \
	-I$(SRCDIR)/include \
	-I$(SRCDIR)/570x/common/include \
	-I$(SRCDIR)/570x/driver/common/lmdev


LDFLAGS		+= -dy -r -Ndrv/ip -Nmisc/mac

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
