#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of the ACPI CA services
#	kernel module.
#
#	i86pc implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE		= ../..

#
#	Define the module and object file sets.
#
MODULE		= acpica
OBJECTS		= $(ACPICA_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(ACPICA_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_MISC_DIR)/$(MODULE)
INC_PATH        += -I$(UTSBASE)/intel/sys/acpi

#
#	Include common rules.
#
include $(UTSBASE)/i86pc/Makefile.i86pc

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(CONFMOD) $(ITUMOD)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_ITUFILE)

#
#	Overrides.
#
DEBUG_FLGS	= 
DEBUG_DEFS	+= $(DEBUG_FLGS)

#
# depends on low-level PCI functions
#
LDFLAGS		+= -dy -Nmisc/pci_autoconfig

#
# lint pass one non-enforcement
#
CFLAGS += $(CCVERBOSE) -DPWRDMN -DACPI_USE_LOCAL_CACHE

LINTFLAGS += -errchk=%none
LINTFLAGS += -errhdr=%none
LINTFLAGS += -erroff=%all
LINTFLAGS += -errwarn=%none

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
include $(UTSBASE)/i86pc/Makefile.targ
