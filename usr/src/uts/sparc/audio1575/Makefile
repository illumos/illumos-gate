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
# uts/sparc/audio1575/Makefile
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#	This makefile drives the production of the M1575 audio driver
#	(audio1575) kernel module.
#
#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= audio1575
OBJECTS		= $(AUDIO1575_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(AUDIO1575_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/sun/io/audio/sada/drv/audio1575

WARLOCK_OBJECTS = $(AUDIO1575_OBJS:%.o=%.ll)
WARLOCK_OK	= $(MODULE).ok

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

# 
#	Overrides, lint pass one enforcement 
# 
CFLAGS		+= $(CCVERBOSE)

#
#	Depends on misc/audiosup
#
LDFLAGS		+= -dy -Nmisc/amsrc2 -Nmisc/mixer -Nmisc/audiosup

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE_64)

#
#       Overrides
#
ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)
CLEANLINTFILES	+= $(LINT32_FILES)

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
	
clean:		$(CLEAN_DEPS); \
		$(RM) $(WARLOCK_OBJECTS) $(WARLOCK_OK)

clobber:	$(CLOBBER_DEPS); \
		$(RM) $(WARLOCK_OBJECTS) $(WARLOCK_OK)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS) lint32

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
#	Mapfile target
#
mapfile:
	$(TEST) -f $@ || $(SCCS) get $@

#
#	Warlock targets
#
# NOTE: there will be warnings about q_lock which is the simulated
# rwlock of the taskq framework
#

%.wlcmd:
	$(TEST) -f $@ || $(SCCS) get $@

warlock:	$(WARLOCK_OK)

$(WARLOCK_OK):	$(WARLOCK_OBJECTS) warlock_ddi.files \
	warlock_audiosup.files warlock_mixer.files warlock_amsrc2.files
	$(WARLOCK) -c audio1575_with_sada.wlcmd $(WARLOCK_OBJECTS) \
	../audiosup/audio_support.ll ../amsrc2/am_src2.ll \
	../mixer/am_main.ll ../mixer/am_ad.ll ../mixer/am_ioctl.ll \
	-l ../warlock/ddi_dki_impl.ll
	$(TOUCH) $(WARLOCK_OK)

%.ll: $(UTSBASE)/sun/io/audio/sada/drv/audio1575/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

warlock_standalone: $(WARLOCK_OBJECTS) warlock_ddi.files audio1575.wlcmd
	$(WARLOCK) -c audio1575.wlcmd $(WARLOCK_OBJECTS) \
	-l ../warlock/ddi_dki_impl.ll

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock

warlock_audiosup.files:
	@cd ../audiosup; pwd; $(MAKE) warlock

warlock_amsrc2.files:
	@cd ../amsrc2; pwd; $(MAKE) warlock

warlock_mixer.files:
	@cd ../mixer; pwd; $(MAKE) warlock
