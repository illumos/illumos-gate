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
# uts/sparc/spppcomp/Makefile
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright (c) 2011 Bayard G. Bell. All rights reserved.
#
#	This makefile drives the production of the spppcomp STREAMS 
#	kernel module.
#
#	sparc architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= spppcomp
OBJECTS		= $(SPPPCOMP_OBJS:%=$(OBJS_DIR)/%)
LINTS           = $(SPPPCOMP_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(USR_STRMOD_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET     = $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#	Internal build definitions
#
CPPFLAGS	+= -DINTERNAL_BUILD -DSOL2 -DMUX_FRAME

# 
#	Additional compiler definitions
# 
INC_PATH	+= -I$(UTSBASE)/common/io/ppp/common
CFLAGS		+= $(CCVERBOSE)

#
# Define dependency on sppp
#
LDFLAGS += -dy -N drv/sppp

CLEANLINTFILES  += $(LINT64_FILES)

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= $(CNOWARN_UNINIT)

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS) lint64

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

$(LINTS_DIR)/%.ln:		$(UTSBASE)/common/io/ppp/spppcomp/%.c
	@($(LHEAD) $(LINT.c) $< $(LTAIL))

$(OBJS_DIR)/%.o:		$(UTSBASE)/common/io/ppp/spppcomp/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

#
#	Include common targets.
#
include $(UTSBASE)/sparc/Makefile.targ
