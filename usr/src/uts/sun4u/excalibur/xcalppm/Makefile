#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# uts/sun4u/excalibur/xcalppm/Makefile
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
#	This makefile drives the production of the platform power
#	management driver in the sun4u excalibur system.
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../../..

#
#	Define the module and object file sets.
#
MODULE		= xcalppm
OBJECTS		= $(XCALPPM_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(XCALPPM_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_EXCALIBUR_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/sun4u/excalibur/io

#
#	Include common rules.
#
include $(UTSBASE)/sun4u/excalibur/Makefile.excalibur

CLEANLINTFILES	= $(LINTS) $(PPM_LINT_LIBS)
CLEANFILES	= $(OBJECTS) $(CLEANLINTFILES)
CLOBBERFILES	= $(OBJS_DIR)/$(MODULE) $(CLEANFILES)

#
# Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-switch

#
# Turn on doubleword alignment for 64 bit registers
#
CFLAGS += -dalign

#
# dependency
#
LDFLAGS += -dy -Ndrv/schppm

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

lint:		$(LINT_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:           $(LINT_DEPS)

modlintlib:     $(MODLINTLIB_DEPS)

clean.lint:     $(CLEAN_LINT_DEPS)

install:        $(INSTALL_DEPS)

LINT_LIB_DIR    = $(EXCALIBUR_LINT_LIB_DIR)

#
#	Include common targets.
#
include $(UTSBASE)/sun4u/excalibur/Makefile.targ
