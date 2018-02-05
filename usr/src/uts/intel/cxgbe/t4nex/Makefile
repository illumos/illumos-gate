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
# (CXGBE) driver nexus modules on x86 systems.
#

#
# Paths to the base of the uts directory trees
#
UTSBASE = ../../..

#
# Define the module and object file sets.
#
MODULE		= t4nex
OBJECTS		= $(CXGBE_COM_OBJS:%=$(OBJS_DIR)/%) \
		  $(CXGBE_FW_OBJS:%=$(OBJS_DIR)/%) \
		  $(CXGBE_NEX_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(CXGBE_COM_OBJS:%.o=$(LINTS_DIR)/%.ln) \
		  $(CXGBE_FW_OBJS:%.o=$(LINTS_DIR)/%.ln) \
		  $(CXGBE_NEX_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)

#
# Include common rules
#
include $(UTSBASE)/intel/Makefile.intel

#
# Define targets
#
ALL_TARGET = $(BINARY)
LINT_TARGET = $(MODULE).lint
INSTALL_TARGET = $(BINARY) $(ROOTMODULE)

CFLAGS += -g -I$(UTSBASE)/common/io/cxgbe -I$(UTSBASE)/common/io/cxgbe/common \
	-I$(UTSBASE)/common/io/cxgbe/t4nex -I$(UTSBASE)/common/io/cxgbe/shared \
	-I$(UTSBASE)/common/io/cxgbe/firmware

#
# Driver depends
#
LDFLAGS += -dy -N misc/mac -N drv/ip

#
# Lint
#
LINTFLAGS += -I$(UTSBASE)/common/io/cxgbe -I$(UTSBASE)/common/io/cxgbe/common \
	-I$(UTSBASE)/common/io/cxgbe/t4nex -I$(UTSBASE)/common/io/cxgbe/shared \
	-I$(UTSBASE)/common/io/cxgbe/firmware
LINTFLAGS += -Xc99=%all

#
# A lot of these come from the fact that there are static inlines and
# that this driver leverages various C99 and some GNU C extensions.
#
LINTTAGS += -erroff=E_STATIC_UNUSED
LINTTAGS += -erroff=E_FUNC_ARG_UNUSED
LINTTAGS += -erroff=E_ZERO_OR_NEGATIVE_SUBSCRIPT
LINTTAGS += -erroff=E_ZERO_SIZED_STRUCT_UNION
LINTTAGS += -erroff=E_ANONYMOUS_UNION_DECL
LINTTAGS += -erroff=E_CONSTANT_CONDITION

#
# These have been manually verified at the moment. When updating this
# driver, please manually check the following lint warnings. Note some
# of these are due to limitations in Sun Studio.
#
LINTTAGS += -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS += -erroff=E_ENUM_VAL_OVERFLOWS_INT_MAX
LINTTAGS += -erroff=E_FUNC_NO_RET_VAL
LINTTAGS += -erroff=E_NOP_IF_STMT
LINTTAGS += -erroff=E_FUNC_SET_NOT_USED
LINTTAGS += -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTTAGS += -erroff=E_FUNC_RET_MAYBE_IGNORED2
LINTTAGS += -erroff=E_CASE_FALLTHRU
LINTTAGS += -erroff=E_ASSIGN_NARROW_CONV

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
# Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ
