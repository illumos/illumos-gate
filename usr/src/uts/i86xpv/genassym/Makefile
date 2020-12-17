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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
#	This makefile drives the production of assym.h through
#	compile time intialized data.
#
#	i86xpv implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

ASSYM_H		= $(DSF_DIR)/$(OBJS_DIR)/assym.h
KDI_ASSYM_H	= $(DSF_DIR)/$(OBJS_DIR)/kdi_assym.h
GENASSYM	= $(DSF_DIR)/$(OBJS_DIR)/genassym

#
#	Include common rules.
#
include $(UTSBASE)/i86xpv/Makefile.i86xpv

#
#	Define targets
#
ALL_TARGET	= $(ASSYM_H) $(KDI_ASSYM_H)

#
# This is DSF_DIR.  Use a short path.
#
DSF_DIR		= .


#
#	Overrides
#
CLEANFILES	= $(GENASSYM) Nothing_to_remove
CLOBBERFILES	= $(ASSYM_H) $(KDI_ASSYM_H) $(CLEANFILES) Nothing_to_remove

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	def

#
# Create assym.h
#
$(GENASSYM): $(GENASSYM_SRC)
	$(NATIVECC) $(NATIVE_CFLAGS) $(ALWAYS_DEFS) $(GENASSYM_DEFS) \
	    $(NATIVE_INC_PATH) -o $@ $(GENASSYM_SRC)

$(ASSYM_H): $(OFFSETS_SRC) $(PLATFORM_OFFSETS_SRC) $(GENASSYM)
	$(OFFSETS_CREATE) <$(OFFSETS_SRC) >$@
	$(OFFSETS_CREATE) <$(PLATFORM_OFFSETS_SRC) >>$@
	$(GENASSYM) >>$@

$(KDI_ASSYM_H): $(KDI_OFFSETS_SRC) $(GENASSYM)
	$(OFFSETS_CREATE) <$(KDI_OFFSETS_SRC) >$@
	$(GENASSYM) >>$@

#
#	Include common targets.
#
include $(UTSBASE)/i86xpv/Makefile.targ
