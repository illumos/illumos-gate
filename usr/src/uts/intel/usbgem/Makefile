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
MODULE		= usbgem
OBJECTS		= $(USBGEM_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(USBGEM_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_MISC_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	The USBGEM has support for various different features. We use
#	these pre-processor macros to define the set we care about.
#
CPPFLAGS	+= \
		-DUSBGEM_CONFIG_GLDv3 \
		-DMODULE \
		-DGEN_CONFIG_FMA \
		-DUSBGEM_CONFIG_MAC_PROP \
		-DVERSION=\"1.6\"

CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-unused-function

LINTTAGS	+= -erroff=E_FUNC_VAR_UNUSED
LINTTAGS	+= -erroff=E_FUNC_ARG_UNUSED
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_FUNC_SET_NOT_USED
LINTTAGS	+= -erroff=E_FUNC_RET_MAYBE_IGNORED2
LINTTAGS	+= -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTTAGS	+= -erroff=E_BAD_FORMAT_ARG_TYPE2
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV

LDFLAGS		+= -dy -N misc/mac -N drv/ip -N misc/usba

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

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

#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ
