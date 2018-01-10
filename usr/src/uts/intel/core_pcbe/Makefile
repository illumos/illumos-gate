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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright 2018, Joyent, Inc.
#
# This Makefile builds
# the Intel Core Architecture Performance Counter BackEnd (PCBE).
#

UTSBASE = ../..

#
#	Define module and object file sets.
#
MODULE		= pcbe.GenuineIntel.6.15
OBJECTS		= $(CORE_PCBE_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(CORE_PCBE_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_PSM_PCBE_DIR)/$(MODULE)
SOFTLINKS	= pcbe.GenuineIntel.6.23 \
			pcbe.GenuineIntel.6.26 \
			pcbe.GenuineIntel.6.28 \
			pcbe.GenuineIntel.6.29 \
			pcbe.GenuineIntel.6.30 \
			pcbe.GenuineIntel.6.31 \
			pcbe.GenuineIntel.6.37 \
			pcbe.GenuineIntel.6.42 \
			pcbe.GenuineIntel.6.44 \
			pcbe.GenuineIntel.6.45 \
			pcbe.GenuineIntel.6.46 \
			pcbe.GenuineIntel.6.47 \
			pcbe.GenuineIntel.6.58 \
			pcbe.GenuineIntel.6.60 \
			pcbe.GenuineIntel.6.61 \
			pcbe.GenuineIntel.6.62 \
			pcbe.GenuineIntel.6.63 \
			pcbe.GenuineIntel.6.69 \
			pcbe.GenuineIntel.6.70 \
			pcbe.GenuineIntel.6.71 \
			pcbe.GenuineIntel.6.78 \
			pcbe.GenuineIntel.6.79 \
			pcbe.GenuineIntel.6.85
ROOTSOFTLINKS	= $(SOFTLINKS:%=$(ROOT_PSM_PCBE_DIR)/%)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-unused-variable

#
#	Define targets.
#
ALL_TARGET	= $(BINARY)
LINT_MODULE	= core_pcbe
LINT_TARGET	= $(LINT_MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTSOFTLINKS)

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

$(ROOTSOFTLINKS):	$(ROOTMODULE)
	-$(RM) $@; $(SYMLINK) $(MODULE) $@

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ
