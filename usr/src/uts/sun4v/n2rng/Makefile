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
# uts/sun4v/n2rng/Makefile
#
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
#
#
#
#	This makefile drives the production of the n2rng driver kernel module.
#
#	sun4v implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..
COM_DIR   = $(COMMONBASE)/crypto

#
#	Define the module and object file sets.
#
MODULE		= n2rng
OBJECTS		= $(N2RNG_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(N2RNG_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_PSM_DRV_DIR)/$(MODULE)
CONF_SRCDIR     = $(UTSBASE)/sun4v/io/n2rng

#
#	Include common rules.
#
include $(UTSBASE)/sun4v/Makefile.sun4v

#
#	Override defaults to build a unique, local modstubs.o.
#
MODSTUBS_DIR	= $(OBJS_DIR)

CLEANFILES	+= $(MODSTUBS_O)

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE) -DN2 -I$(COM_DIR)
LINTFLAGS += -DN2 -I$(COM_DIR)
CERRWARN += $(CNOWARN_UNINIT)

#
# module dependencies
#
LDFLAGS += -dy -Nmisc/kcf

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
include $(UTSBASE)/sun4v/Makefile.targ
