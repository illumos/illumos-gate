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
# Copyright (c) 2014, Joyent, Inc
#

#
# uts/intel/nfp/Makefile
#
#	This makefile drives the production of the nfp
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
MODULE		= nfp
OBJECTS		= $(NFP_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(NFP_OBJS:%.o=$(LINTS_DIR)/%.ln)
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
# 	Driver-specific flags
#
CPPFLAGS	+= -DCH_KERNELVER=270
LDFLAGS		+= -dy
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-function

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
