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
# uts/intel/mixer/Makefile
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the audio mixer (mixer)
#	Audio Personality Module.
#
#ident	"%Z%%M%	%I%	%E% SMI"

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
WARLOCK_OUT	= $(MIXER_OBJS:%.o=%.ll)
WARLOCK_OK	= $(MODULE).ok
WLCMD_DIR	= $(UTSBASE)/common/io/warlock

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#	Depends on misc/audiosup
#
LDFLAGS		+= -dy -Nmisc/audiosup

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV
LINTTAGS	+= -erroff=E_SUSPICIOUS_COMPARISON

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
include $(UTSBASE)/intel/Makefile.targ

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
AUDIO_SUP_FILES = $(AUDIO_SUP_OBJS:%.o=$(UTSBASE)/intel/audiosup/%.ll)
AMSRC1_FILES = $(AMSRC1_OBJS:%.o=$(CLOSED)/uts/intel/amsrc1/%.ll)
AMSRC2_FILES = $(AMSRC2_OBJS:%.o=$(UTSBASE)/intel/amsrc2/%.ll)

WARLOCK_TARGETS = $(WARLOCK_OUT) warlock_ddi.files warlock_audiosup.files \
	warlock_standalone $(WLCMD_DIR)/mixer_with_audiosup.wlcmd

$(CLOSED_BUILD)WARLOCK_CLOSED = warlock_closed

warlock: warlock_open $(WARLOCK_CLOSED)
	$(TOUCH) $(WARLOCK_OK)

warlock_open: $(WARLOCK_TARGETS) warlock_amsrc2.files
	$(WARLOCK) -c $(WLCMD_DIR)/mixer_with_audiosup.wlcmd $(WARLOCK_OUT) \
	$(AUDIO_SUP_FILES) $(AMSRC2_FILES) \
	-l ../warlock/ddi_dki_impl.ll

warlock_closed: $(WARLOCK_TARGETS) warlock_amsrc1.files
	$(WARLOCK) -c $(WLCMD_DIR)/mixer_with_audiosup.wlcmd \
	$(WARLOCK_OUT) $(AUDIO_SUP_FILES) $(AMSRC1_FILES) \
	-l ../warlock/ddi_dki_impl.ll

%.ll: $(UTSBASE)/common/io/audio/sada/mixer/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

warlock_standalone:  $(WARLOCK_OUT) warlock_ddi.files \
	$(WLCMD_DIR)/mixer.wlcmd
	$(WARLOCK) -c $(WLCMD_DIR)/mixer.wlcmd $(WARLOCK_OUT) \
	-l ../warlock/ddi_dki_impl.ll

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock

warlock_audiosup.files:
	@cd ../audiosup; pwd; $(MAKE) warlock

warlock_amsrc1.files:
	@cd $(CLOSED)/uts/intel/amsrc1; pwd; $(MAKE) warlock

warlock_amsrc2.files:
	@cd ../amsrc2; pwd; $(MAKE) warlock
