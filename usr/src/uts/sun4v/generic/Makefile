#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	This makefile drives the production of the Generic sun4v cpu module.
#
#	sun4v implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= generic
OBJECTS		= $(GENERIC_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(GENERIC_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_PSM_CPU_DIR)/$(MODULE)
SOFTLINKS	= sun4v
ROOTSOFTLINKS	= $(SOFTLINKS:%=$(ROOT_PSM_CPU_DIR)/%)

CPU_DIR		= .
HERE		= ../generic

#
#	Include common rules.
#
include $(UTSBASE)/sun4v/Makefile.sun4v

#
#	Override defaults
#
CLEANFILES	+= $(CPULIB) $(SYM_MOD)

#
#	Define targets
#
ALL_TARGET	= $(SYM_MOD)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= def $(BINARY) $(ROOTMODULE) $(ROOTSOFTLINKS)

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses

#
# cpu-module-specific flags
#
CPPFLAGS += -DCPU_MODULE
AS_CPPFLAGS += -DCPU_MODULE

#
# The ATOMIC_BO_ENABLE_SHIFT enables backoff in atomic routines.
# It is also used to scale final limit value w.r.t. number of
# online cpus.
#
# In case of generic cpu module, the backoff will be using spin
# loop as the CPU specific delay routine for atomic backoff will
# not be available. The ATOMIC_BO_ENABLE_SHIFT value below takes
# this into account.
#
ATOMIC_BO_FLAG = -DATOMIC_BO_ENABLE_SHIFT=7
CFLAGS += $(ATOMIC_BO_FLAG)
CPPFLAGS +=$(ATOMIC_BO_FLAG)
AS_CPPFLAGS += $(ATOMIC_BO_FLAG)

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:		$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:		$(INSTALL_DEPS)

$(CPULIB):	$(OBJECTS)
	$(BUILD.SO) $(OBJECTS)

$(SYM_MOD):	$(UNIX_O) $(CPULIB)
	@echo "resolving symbols against unix.o"
	@(cd $(UNIX_DIR); pwd; \
	    CPU_DIR=$(HERE) SYM_MOD=$(HERE)/$(SYM_MOD) $(MAKE) symcheck)

$(ROOTSOFTLINKS): $(ROOTMODULE)
	$(RM) $@; $(SYMLINK) $(MODULE) $@

#	Include common targets.
#
include $(UTSBASE)/$(PLATFORM)/Makefile.targ
