#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# uts/sun4u/boston/platmod/Makefile
#
# This makefile drives the production of the sun4u boston platform module.
#
# sun4u implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
MODULE		= platmod
OBJECTS		= $(BOSTON_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(BOSTON_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_BOSTON_MISC_DIR)/$(MODULE)

PLAT_DIR	= .
HERE		= ../boston/platmod

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/boston/Makefile.boston

#
#	Override defaults
#
CLEANFILES	+= $(PLATLIB) $(SYM_MOD)

#
#	Define targets
#
ALL_TARGET	= $(SYM_MOD)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE)

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

check:

LINT_LIB_DIR	= $(BOSTON_LINT_LIB_DIR)

$(PLATLIB):	$(BINARY)
	$(BUILD.SO) $(BINARY)

$(SYM_MOD):	$(UNIX_O) $(PLATLIB)
	@echo "resolving symbols against unix.o"
	@(cd $(UNIX_DIR); pwd; \
	    PLAT_DIR=$(HERE) SYM_MOD=$(HERE)/$(SYM_MOD) $(MAKE) symcheck)

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/boston/Makefile.targ
