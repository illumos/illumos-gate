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

#
# This makefile drives the production of the EoIB Nexus driver
#
# sparc architecture dependent
#

#
# Path to the base of the uts directory tree (usually /usr/src/uts)
#
UTSBASE	= ../..

#
# Define the module and object file sets
#
MODULE		= eibnx
OBJECTS		= $(EIBNX_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(EIBNX_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/ib/clients/eoib

#
# Include common rules
#
include $(UTSBASE)/sparc/Makefile.sparc

#
# Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
# Overrides.
#
ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)

# Module specific debug flag
#
CPPFLAGS += -DENX_DEBUG

#
# Lint pass one enforcement
#
CFLAGS += $(CCVERBOSE)

#
# Depends on misc/ibtl
#
LDFLAGS	+= -dy -Nmisc/ibcm -Nmisc/ibtl

#
# The only lint flag we should need
#
LINTTAGS += -erroff=E_BAD_PTR_CAST_ALIGN

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized

#
# Default build targets
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

#
# Include common targets
#
include $(UTSBASE)/sparc/Makefile.targ
