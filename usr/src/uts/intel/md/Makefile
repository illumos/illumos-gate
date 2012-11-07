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
# uts/intel/md/Makefile
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright (c) 2011 Bayard G. Bell. All rights reserved.
#
#	This makefile drives the production of the md driver
#
#	architecture independent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= md
OBJECTS		= $(MD_OBJS:%=$(OBJS_DIR)/%)
OBJECTS		+= $(MD_COMMON_OBJS:%=$(OBJS_DIR)/%)
OBJECTS		+= $(MD_DERIVED_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(MD_OBJS:%.o=$(LINTS_DIR)/%.ln)
LINTS		+= $(MD_COMMON_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/lvm/md

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_SUSPICIOUS_COMPARISON
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV

CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-parentheses

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
# Depends on rpcmod
#
LDFLAGS         += -dy -N strmod/rpcmod

#
#	Default build targets.
#
.KEEP_STATE:

def:		derived_h .WAIT $(DEF_DEPS)

all:		derived_h .WAIT $(ALL_DEPS)

clean:		derived_h .WAIT $(CLEAN_DEPS)

clobber:	derived_h .WAIT $(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	derived_h .WAIT $(MODLINTLIB_DEPS)

clean.lint:	derived_h .WAIT $(CLEAN_LINT_DEPS)

install:	derived_h .WAIT $(INSTALL_DEPS)

derived_h:
	cd $(UTSBASE)/common/sys/lvm; pwd; $(MAKE) $(TARGET)

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ
