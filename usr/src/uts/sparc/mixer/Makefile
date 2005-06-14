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
# uts/sparc/mixer/Makefile
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the audio mixer (mixer)
#	Audio Personality Module.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= mixer
OBJECTS		= $(MIXER_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(MIXER_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_MISC_DIR)/$(MODULE)
WARLOCK_OBJECTS = $(MIXER_OBJS:%.o=%.ll)
WARLOCK_OK	= $(MODULE).ok

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
#	Depends on misc/audiosup
#
LDFLAGS		+= -dy -Nmisc/audiosup

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS); \
		$(RM) $(WARLOCK_OBJECTS) $(WARLOCK_OK)

clobber:	$(CLOBBER_DEPS); \
		$(RM) $(WARLOCK_OBJECTS) $(WARLOCK_OK)

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
SCCS		= sccs
TEST		= test
WLCC		= wlcc
TOUCH		= touch
WARLOCK 	= warlock

#
#	Warlock targets
#
%.wlcmd:
	$(TEST) -f $@ || $(SCCS) get $@

warlock:	$(WARLOCK_OK)

$(WARLOCK_OK):	$(WARLOCK_OBJECTS) warlock_ddi.files \
	warlock_audiosup.files warlock_amsrc1.files \
	warlock_amsrc2.files \
	warlock_standalone mixer_with_audiosup.wlcmd 
	$(WARLOCK) -c mixer_with_audiosup.wlcmd $(WARLOCK_OBJECTS) \
	../audiosup/audio_support.ll ../amsrc1/am_src1.ll \
	-l ../warlock/ddi_dki_impl.ll
	$(WARLOCK) -c mixer_with_audiosup.wlcmd $(WARLOCK_OBJECTS) \
	../audiosup/audio_support.ll ../amsrc2/am_src2.ll \
	-l ../warlock/ddi_dki_impl.ll
	$(TOUCH) $(WARLOCK_OK)

%.ll: $(UTSBASE)/common/io/audio/sada/mixer/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

warlock_standalone:  $(WARLOCK_OBJECTS) warlock_ddi.files \
	mixer.wlcmd
	$(WARLOCK) -c mixer.wlcmd $(WARLOCK_OBJECTS) \
	-l ../warlock/ddi_dki_impl.ll

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock

warlock_audiosup.files:
	@cd ../audiosup; pwd; $(MAKE) warlock

warlock_amsrc1.files:
	@cd ../amsrc1; pwd; $(MAKE) warlock

warlock_amsrc2.files:
	@cd ../amsrc2; pwd; $(MAKE) warlock
