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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= rdsv3
OBJECTS		= $(RDSV3_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(RDSV3_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CFLAGS 		+= $(CCVERBOSE) $(_XPG4_2)
LDFLAGS		+= -dy -Nfs/sockfs -Nmisc/ksocket -Ndrv/ip -Nmisc/ibtl -Nmisc/ibcm -Nmisc/sol_ofs
CONF_SRCDIR	= $(UTSBASE)/common/io/ib/clients/rdsv3
#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

# CFLAGS 		+= -DOFA_SOLARIS

#
# Disable these lint checks since some errors suppressed here are
# in the OFED code, but we'd like to keep it as is as much as possible.
# Note. maintainers should endeavor to investigate and remove these for
# maximum lint coverage, but please do not carry these forward to new 
# Makefiles blindly.
#
LINTTAGS        += -erroff=E_STATIC_UNUSED
LINTTAGS        += -erroff=E_CONSTANT_CONDITION 
LINTTAGS        += -erroff=E_FUNC_VAR_UNUSED
LINTTAGS        += -erroff=E_SUSPICIOUS_COMPARISON 
LINTTAGS        += -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS        += -erroff=E_ASSIGN_NARROW_CONV 
LINTTAGS        += -erroff=E_FUNC_SET_NOT_USED

CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-parentheses

# needs work
SMATCH=off

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

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

