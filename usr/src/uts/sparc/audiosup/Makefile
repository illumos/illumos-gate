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
# uts/sparc/audiosup/Makefile
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the audio support (audiosup)
#	module.
#
#ident	"%Z%%M%	%I%	%E% SMI"

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= audiosup
OBJECTS		= $(AUDIO_SUP_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(AUDIO_SUP_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_MISC_DIR)/$(MODULE)
WARLOCK_OUT = $(AUDIO_SUP_OBJS:%.o=%.ll)
WARLOCK_OK	= $(MODULE).ok
WLCMD_DIR       = $(UTSBASE)/common/io/warlock


#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

#
#	Turn off -xspace so we get all optimizations.
#
SPACEFLAG	=

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

# 
#	Overrides, lint pass one enforcement 
# 
CFLAGS		+= $(CCVERBOSE)

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK)

clobber:	$(CLOBBER_DEPS)
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/sparc/Makefile.targ

#
#	Defines for local commands.
#
TEST		= test
WLCC		= wlcc
TOUCH		= touch
WARLOCK 	= warlock

#
#	Warlock targets
#
warlock:	$(WARLOCK_OK)

$(WARLOCK_OK):	$(WARLOCK_OUT) warlock_ddi.files $(WLCMD_DIR)/audiosup.wlcmd
	$(WARLOCK) -c $(WLCMD_DIR)/audiosup.wlcmd $(WARLOCK_OUT) \
	-l ../warlock/ddi_dki_impl.ll
	$(TOUCH) $(WARLOCK_OK)

%.ll: $(UTSBASE)/common/io/audio/sada/framework/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock
