#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# This file may contain confidential information of Nvidia
# and should not be distributed in source form without approval
# from Sun Legal.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of the nvidia toe/ge
#	driver.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE   = ../..

#
#	Define the module and object file sets.
#
MODULE		= nge
OBJECTS		= $(NGE_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(NGE_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR     = $(UTSBASE)/common/io/nge

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Override defaults
#
INC_PATH	+= -I$(CONF_SRCDIR)

# CFLAGS += $(CINLINEFLAGS)

#
# Driver depends on GLD & IP
#
LDFLAGS		+= -dy -N misc/mac -N drv/ip

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV
LINTTAGS	+= -erroff=E_STATIC_UNUSED

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
