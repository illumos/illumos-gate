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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the kernel component of
#	the N-1 Solaris brand
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE =	../..
SN1_BASE =	$(UTSBASE)/common/brand/sn1

#
#	Define the module and object file sets.
#
MODULE =	sn1_brand
OFFSETS_H =	$(OBJS_DIR)/sn1_offsets.h
OFFSETS_SRC =	$(SN1_BASE)/sn1_offsets.in
OBJECTS =	$(SN1_BRAND_OBJS:%=$(OBJS_DIR)/%)
LINTS =		$(SN1_BRAND_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE =	$(ROOT_PSM_BRAND_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/sun4v/Makefile.sun4v

#
#	Define targets
#
ALL_TARGET =		$(OFFSETS_H) $(BINARY)
LINT_TARGET =		$(MODULE).lint
INSTALL_TARGET =	$(OFFSETS_H) $(BINARY) $(ROOTMODULE)

#
#	Update compiler variables.
#
INC_PATH +=	-I$(SN1_BASE) -I$(OBJS_DIR)
LDFLAGS +=	-dy -Nexec/elfexec

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
# Create genassym.h
#
$(OFFSETS_H): $(OFFSETS_SRC)
	$(OFFSETS_CREATE) <$(OFFSETS_SRC) >$@

#
#	Include common targets.
#
include $(UTSBASE)/sun4v/Makefile.targ
