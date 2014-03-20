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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of genassym.h through
#	compile time intialized data.
#
#	intel architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

GENASSYM_H	= $(GENASSYM_DIR)/$(OBJS_DIR)/genassym.h
OFFSETS_SRC	= $(GENASSYM_DIR)/offsets.in

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(GENASSYM_H)

INC_PATH	+= -I$(UTSBASE)/common/brand/lx

#
#	Overrides
#
CLEANFILES	= Nothing_to_remove
CLOBBERFILES	= $(GENASSYM_H) Nothing_to_remove

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

clean.lint:

install:	def

#
# Create genassym.h
#
$(GENASSYM_H): $(OFFSETS_SRC)
	$(OFFSETS_CREATE) <$(OFFSETS_SRC) >$@

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ
