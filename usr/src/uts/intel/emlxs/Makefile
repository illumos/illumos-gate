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
# Copyright (c) 2011 Bayard G. Bell. All rights reserved.
# Copyright (c) 2018, Joyent, Inc.
#
# This makefile drives the production of the emlxs driver kernel module.
#
# Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE		= ../../
COMMON_BASE	= ../../../common

#
#	Define the module and object file sets.
#
MODULE		= emlxs
OBJECTS		= $(EMLXS_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(EMLXS_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/fibre-channel/fca/emlxs

#
#	Include common rules.
#
ARCHDIR		= intel
include ../Makefile.$(ARCHDIR)

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

EMLXS_FLAGS             = -DEMLXS_I386
EMLXS_FLAGS             += -DS11
EMLXS_FLAGS             += -DVERSION=\"11\"
EMLXS_FLAGS             += -DMACH=\"$(MACH)\"
EMLXS_CFLAGS            = $(EMLXS_FLAGS)
EMLXS_LFLAGS            = $(EMLXS_FLAGS)
CFLAGS	                += $(EMLXS_CFLAGS) -DEMLXS_ARCH=\"$(CLASS)\"
LINTTAGS                += $(EMLXS_LFLAGS) -DEMLXS_ARCH=\"$(CLASS)\"


#
#	Overrides and depends_on
#
INC_PATH	+= -I$(ROOT)/usr/include
INC_PATH	+= -I$(UTSBASE)/common/sys
INC_PATH	+= -I$(COMMON_BASE)/bignum
INC_PATH	+= -I$(UTSBASE)/common/sys/fibre-channel
INC_PATH	+= -I$(UTSBASE)/common/sys/fibre-channel/fca
INC_PATH	+= -I$(UTSBASE)/common/sys/fibre-channel/fca/emlxs
INC_PATH	+= -I$(UTSBASE)/common/sys/fibre-channel/impl
INC_PATH	+= -I$(UTSBASE)/common/sys/fibre-channel/ulp

#
#	misc/fctl required because #ifdef MODSYM_LOAD code
#	triggered by -DS11; uses DDI calls to load FCA symbols
#
LDFLAGS		+= -dy -Nmisc/md5 -Nmisc/sha1
LDFLAGS		+= -Nmisc/bignum -Nmisc/fctl

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV
LINTTAGS	+= -erroff=E_SUSPICIOUS_COMPARISON
LINTTAGS	+= -erroff=E_INCONS_VAL_TYPE_DECL2

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-uninitialized

SMOFF += indenting,deref_check,all_func_returns

# seems definitely wrong
$(OBJS_DIR)/emlxs_fcf.o := SMOFF += logical_instead_of_bitwise

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
include ../Makefile.targ
