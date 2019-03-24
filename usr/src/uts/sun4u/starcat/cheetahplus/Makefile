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
#	This makefile drives the production of the Starcat specific
#	UltraSPARC-III+ driver module.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
MODULE		= SUNW,UltraSPARC-III+
OBJECTS		= $(CHEETAHPLUS_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(CHEETAHPLUS_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_STARCAT_CPU_DIR)/$(MODULE)
SOFTLINKS	= SUNW,UltraSPARC-IV SUNW,UltraSPARC-IV+
ROOTSOFTLINKS	= $(SOFTLINKS:%=$(ROOT_STARCAT_CPU_DIR)/%)

CPU_DIR		= .
HERE		= ../cheetahplus

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/starcat/Makefile.starcat

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
#       Overrides
#
ALL_BUILDS      = $(ALL_BUILDSONLY64)
DEF_BUILDS      = $(DEF_BUILDSONLY64)
CLEANLINTFILES  += $(LINT32_FILES)

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE) -DCHEETAH -DCHEETAH_PLUS -DCPU_IMP_L1_CACHE_PARITY \
	     -DCPU_IMP_ECACHE_ASSOC -DCPU_IMP_DUAL_PAGESIZE -DCPU_IMP_AFSR_EXT
ASFLAGS +=  -DCHEETAH -DCHEETAH_PLUS -DCPU_IMP_L1_CACHE_PARITY \
	    -DCPU_IMP_ECACHE_ASSOC -DCPU_IMP_DUAL_PAGESIZE -DCPU_IMP_AFSR_EXT

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-clobbered

#
# cpu-module-specific flags
#
CPPFLAGS += -DCPU_MODULE -DCHEETAH -DCHEETAH_PLUS -DCPU_IMP_L1_CACHE_PARITY \
	    -DCPU_IMP_ECACHE_ASSOC -DCPU_IMP_DUAL_PAGESIZE -DCPU_IMP_AFSR_EXT
AS_CPPFLAGS += -DCPU_MODULE -DCHEETAH -DCHEETAH_PLUS -DCPU_IMP_L1_CACHE_PARITY \
	       -DCPU_IMP_ECACHE_ASSOC -DCPU_IMP_DUAL_PAGESIZE -DCPU_IMP_AFSR_EXT

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS) lint32

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

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
include $(UTSBASE)/sun4u/starcat/Makefile.targ
