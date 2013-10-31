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
# uts/sparc/sd/Makefile
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright (c) 2011 Bayard G. Bell. All rights reserved.
#
#	This makefile drives the production of the sd driver kernel module.
#
#	sparc architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= sd
OBJECTS		= $(SD_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(SD_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/sun/io/scsi/targets
WARLOCK_OUT     = $(SD_OBJS:%.o=%.ll)
WARLOCK_OK      = $(MODULE).ok
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
# lint pass one enforcement 
# 
CFLAGS += $(CCVERBOSE)

#
# Define dependencies on scsi and cmlb
#
LDFLAGS += -dy -N misc/scsi -N misc/cmlb

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_SUSPICIOUS_COMPARISON

CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-uninitialized

#
#	Default build targets.
#
.KEEP_STATE:

all:		$(ALL_DEPS)

def:		$(DEF_DEPS)

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
include	$(UTSBASE)/sparc/Makefile.targ


#
#	Defines for local commands.
#
WARLOCK		= warlock
WLCC		= wlcc
TOUCH		= touch
TEST		= test

#
# Warlock targets
#
# Note that in warlock_with_{esp,isp} it is important to load sd.ll
# before {isp,esp}.ll; the reason is that both have _init/_info/_fini
# and warlock can only handle one extern function by a given name;
# any loaded after the first are ignored.

SCSI_FILES = $(SCSI_OBJS:%.o=-l ../scsi/%.ll)
CMLB_FILES = $(CMLB_OBJS:%.o=-l ../cmlb/%.ll)

WARLOCK_TARGETS = warlock_alone warlock_with_esp warlock_with_fas

warlock: $(WARLOCK_TARGETS)

warlock_alone: $(WARLOCK_OK)

$(WARLOCK_OK): $(WLCMD_DIR)/sd.wlcmd $(WARLOCK_OUT) scsi_files \
	warlock_ddi.files cmlb_files
	$(WARLOCK) -c $(WLCMD_DIR)/sd.wlcmd $(WARLOCK_OUT) $(SCSI_FILES) \
		$(CMLB_FILES) \
		-l ../warlock/ddi_dki_impl.ll
	$(TOUCH) $@

%.ll: $(UTSBASE)/common/io/scsi/targets/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

warlock_with_esp: $(WLCMD_DIR)/sd_with_esp.wlcmd $(WARLOCK_OUT) scsi_files \
	esp_files warlock_ddi.files cmlb_files
	$(WARLOCK) -c $(WLCMD_DIR)/sd_with_esp.wlcmd \
		$(WARLOCK_OUT) ../esp/esp $(SCSI_FILES) $(CMLB_FILES) \
		-l ../warlock/ddi_dki_impl.ll

warlock_with_fas: $(WLCMD_DIR)/sd_with_fas.wlcmd $(WARLOCK_OUT) scsi_files \
	fas_files warlock_ddi.files cmlb_files
	$(WARLOCK) -c $(WLCMD_DIR)/sd_with_fas.wlcmd \
		$(WARLOCK_OUT) ../fas/fas \
		../fas/fas_callbacks \
		$(SCSI_FILES) $(CMLB_FILES) \
		-l ../warlock/ddi_dki_impl.ll

cmlb_files:
	@cd ../cmlb; pwd; $(MAKE) warlock


scsi_files:
	@cd ../scsi; pwd; $(MAKE) warlock

esp_files:
	@cd ../esp; pwd; $(MAKE) warlock

fas_files:
	@cd ../fas; pwd; $(MAKE) warlock

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock
