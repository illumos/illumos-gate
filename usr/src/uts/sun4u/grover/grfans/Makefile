#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

# This makefile drives the production of the grover_fans driver.
#
# Path to the base of the uts directory tree (usually /usr/src/uts).

UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
MODULE		= grfans
OBJECTS		= $(GRFANS_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(GRFANS_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_GROVER_DRV_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/grover/Makefile.grover

# 
# lint pass one enforcement 
# 
CFLAGS += $(CCVERBOSE)

CPPFLAGS += -I$(UTSBASE)/sun4u/grover

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

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
#	Include common targets
#
include $(UTSBASE)/sun4u/grover/Makefile.targ
