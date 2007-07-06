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
# uts/intel/audio810/Makefile
#
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of Metropolis audio driver
#	(audio810) kernel module.
#
#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= audio810
OBJECTS		= $(AUDIO810_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(AUDIO810_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/audio/sada/drv/audio810
WARLOCK_OUT	= $(AUDIO810_OBJS:%.o=%.ll)
WARLOCK_OK	= $(MODULE).ok
WLCMD_DIR       = $(UTSBASE)/common/io/warlock

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

# 
#	Overrides, lint pass one enforcement 
# 
CFLAGS		+= $(CCVERBOSE)
DEBUG_FLGS	=
$(NOT_RELEASE_BUILD)DEBUG_DEFS	+= $(DEBUG_FLGS)

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN

#
#	Depends on misc/audiosup
#
LDFLAGS		+= -dy -Nmisc/amsrc2 -Nmisc/audiosup -Nmisc/mixer

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

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
MIXER_FILES = $(MIXER_OBJS:%.o=$(UTSBASE)/intel/mixer/%.ll)
AUDIO_SUP_FILES = $(AUDIO_SUP_OBJS:%.o=$(UTSBASE)/intel/audiosup/%.ll)
AMSRC2_FILES = $(AMSRC2_OBJS:%.o=$(UTSBASE)/intel/amsrc2/%.ll)

warlock:	$(WARLOCK_OK)

$(WARLOCK_OK):	$(WARLOCK_OUT) warlock_ddi.files warlock_standalone \
	warlock_audiosup.files warlock_mixer.files warlock_amsrc2.files \
	$(WLCMD_DIR)/audio810_with_sada.wlcmd
	$(WARLOCK) -c $(WLCMD_DIR)/audio810_with_sada.wlcmd $(WARLOCK_OUT) \
	$(MIXER_FILES) $(AUDIO_SUP_FILES) $(AMSRC2_FILES) \
	-l ../../intel/warlock/ddi_dki_impl.ll
	$(TOUCH) $(WARLOCK_OK)

%.ll: $(UTSBASE)/common/io/audio/sada/drv/audio810/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

warlock_standalone: $(WARLOCK_OUT) warlock_ddi.files $(WLCMD_DIR)/audio810.wlcmd
	$(WARLOCK) -c $(WLCMD_DIR)/audio810.wlcmd $(WARLOCK_OUT) \
	-l ../../intel/warlock/ddi_dki_impl.ll

warlock_ddi.files:
	@cd ../../intel/warlock; pwd; $(MAKE) warlock

warlock_audiosup.files:
	@cd ../../intel/audiosup; pwd; $(MAKE) warlock

warlock_amsrc2.files:
	@cd ../../intel/amsrc2; pwd; $(MAKE) warlock

warlock_mixer.files:
	@cd ../../intel/mixer; pwd; $(MAKE) warlock
