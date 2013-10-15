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
# uts/sparc/ses/Makefile
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright (c) 2011 Bayard G. Bell. All rights reserved.
#
# This makefile drives the production of the ses driver kernel module.
#
# sparc architecture dependent
#

#
# Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
# Define the module and object file sets.
#
MODULE		= ses
OBJECTS		= $(SES_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(SES_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/sun/io/scsi/targets
WARLOCK_OUT     = $(SES_OBJS:%.o=%.ll)
WARLOCK_OK      = $(MODULE).ok
WLCMD_DIR	= $(UTSBASE)/common/io/warlock

#
# Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

#
# Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)
CLEANFILES	+= $(WARLOCK_TARGETS)

#
# Define dependency on scsi
#
LDFLAGS += -dy -N misc/scsi

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV
LINTTAGS	+= -erroff=E_SUSPICIOUS_COMPARISON

#
# Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK)

clobber:	$(CLOBBER_DEPS)
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK)

modlintlib:	$(MODLINTLIB_DEPS) lint64

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/sparc/Makefile.targ


#
# Defines for local commands.
#
WARLOCK		= warlock
WLCC		= wlcc
TOUCH		= touch
TEST		= test

#
# Warlock targets
#
# XXX FIX ME.  this can be improved quite a bit

SES_FILES	= $(MODULE).ll
SCSI_FILES	= $(SCSI_OBJS:%.o=-l ../scsi/%.ll)

WARLOCK_TARGETS	= $(WARLOCK_OK) warlock_with_esp.ok warlock_with_fas.ok

warlock: $(WARLOCK_TARGETS)

$(WARLOCK_OK): $(WLCMD_DIR)/$(MODULE).wlcmd $(SES_FILES)
	@cd ../warlock; $(MAKE) warlock
	@cd ../scsi; $(MAKE) warlock
	$(WARLOCK) -c $(WLCMD_DIR)/$(MODULE).wlcmd $(SES_FILES) ../warlock/scsi.ll \
	        -l ../warlock/ddi_dki_impl.ll  \
	        $(SCSI_FILES)
	@ $(TOUCH) $@

warlock_with_esp.ok: $(WLCMD_DIR)/ses_with_esp.wlcmd $(SES_FILES)
	@cd ../warlock; $(MAKE) warlock
	@cd ../scsi; $(MAKE) warlock
	@cd ../esp; $(MAKE) warlock;
	$(WARLOCK) -c $(WLCMD_DIR)/ses_with_esp.wlcmd $(SES_FILES) ../esp/esp  \
	        ../warlock/scsi.ll \
	        -l ../warlock/ddi_dki_impl.ll \
	        $(SCSI_FILES)
	@ $(TOUCH) $@

warlock_with_fas.ok: $(WLCMD_DIR)/ses_with_fas.wlcmd $(SES_FILES)
	@cd ../warlock; $(MAKE) warlock
	@cd ../scsi; $(MAKE) warlock
	@cd ../fas; $(MAKE) warlock;
	$(WARLOCK) -c $(WLCMD_DIR)/ses_with_fas.wlcmd $(SES_FILES) \
	        ../fas/fas ../fas/fas_callbacks \
	        ../warlock/scsi.ll \
	        -l ../warlock/ddi_dki_impl.ll \
	        $(SCSI_FILES)
	@ $(TOUCH) $@

%.ll: $(UTSBASE)/common/io/scsi/targets/%.c
	$(WLCC) $(CPPFLAGS) -o $@ $<


