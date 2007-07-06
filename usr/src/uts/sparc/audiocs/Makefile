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
# uts/sparc/audiocs/Makefile
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of the Crystal 4231
#	audio driver (audiocs) kernel module.
#
#	sparc architecture dependent
#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= audiocs
OBJECTS		= $(AUDIOCS_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(AUDIOCS_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/sun/io/audio/sada/drv/audiocs
WARLOCK_OUT 	= $(AUDIOCS_OBJS:%.o=%.ll)
WARLOCK_OK	= $(MODULE).ok
WLCMD_DIR       = $(UTSBASE)/common/io/warlock

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Overrides
#
CFLAGS		+= $(CCVERBOSE)

#
#	Depends on misc/audiosup and misc/mixer
#
LDFLAGS		+= -dy -Nmisc/amsrc2 -Nmisc/audiosup -Nmisc/mixer

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
MIXER_FILES = $(MIXER_OBJS:%.o=$(UTSBASE)/sparc/mixer/%.ll)
AUDIO_SUP_FILES = $(AUDIO_SUP_OBJS:%.o=$(UTSBASE)/sparc/audiosup/%.ll)
AMSRC2_FILES = $(AMSRC2_OBJS:%.o=$(UTSBASE)/sparc/amsrc2/%.ll)

warlock:	$(WARLOCK_OK)

$(WARLOCK_OK):	$(WARLOCK_OUT) warlock_ddi.files \
	warlock_audiosup.files warlock_mixer.files warlock_amsrc2.files \
	warlock_standalone $(WLCMD_DIR)/audiocs_with_sada.wlcmd
	$(WARLOCK) -c $(WLCMD_DIR)/audiocs_with_sada.wlcmd $(WARLOCK_OUT) \
	$(MIXER_FILES) $(AUDIO_SUP_FILES) $(AMSRC2_FILES) \
	-l ../warlock/ddi_dki_impl.ll
	$(TOUCH) $(WARLOCK_OK)

%.ll: $(UTSBASE)/sun/io/audio/sada/drv/audiocs/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

warlock_standalone: $(WARLOCK_OUT) warlock_ddi.files $(WLCMD_DIR)/audiocs.wlcmd
	$(WARLOCK) -c $(WLCMD_DIR)/audiocs.wlcmd $(WARLOCK_OUT) \
	-l ../warlock/ddi_dki_impl.ll

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock

warlock_audiosup.files:
	@cd ../audiosup; pwd; $(MAKE) warlock

warlock_amsrc2.files:
	@cd ../amsrc2; pwd; $(MAKE) warlock

warlock_mixer.files:
	@cd ../mixer; pwd; $(MAKE) warlock
