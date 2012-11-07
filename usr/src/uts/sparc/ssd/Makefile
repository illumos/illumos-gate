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
# uts/sparc/ssd/Makefile
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright (c) 2011 Bayard G. Bell. All rights reserved.
#

#
#	This makefile drives the production of the ssd driver kernel module.
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
MODULE		= ssd
OBJECTS		= $(SSD_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(SSD_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/sun/io/scsi/targets
WARLOCK_OUT     = ssd.ll 
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
CFLAGS += $(CCVERBOSE) -D__fibre -dalign
LINTFLAGS += -D__fibre
WLCCFLAGS = -D__fibre

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_SUSPICIOUS_COMPARISON

CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-type-limits

#
# Depends on scsi and cmlb
# fcp included for fibre support
#
LDFLAGS         += -dy -N misc/scsi -N misc/cmlb -N drv/fcp

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

browser:	$(BINARY)

browser		:= CFLAGS += -xsb

#
#	Defines for local commands.
#
WARLOCK		= warlock
WLCC		= wlcc
TOUCH		= touch
TEST		= test

#
# Warlock targets

SCSI_FILES = $(SCSI_OBJS:%.o=-l ../scsi/%.ll)
CMLB_FILES = $(CMLB_OBJS:%.o=-l ../cmlb/%.ll)

warlock: warlock_alone

warlock_alone: $(WARLOCK_OK)

scsi_files:
	@cd ../scsi; pwd; $(MAKE) warlock

cmlb_files:
	 @cd ../cmlb; pwd; $(MAKE) warlock

$(WARLOCK_OK): $(WLCMD_DIR)/ssd.wlcmd $(WARLOCK_OUT) scsi.files cmlb_files
	$(WARLOCK) -c $(WLCMD_DIR)/ssd.wlcmd $(WARLOCK_OUT) \
	$(SCSI_FILES) $(CMLB_FILES) \
	-l ../warlock/ddi_dki_impl.ll
	$(TOUCH) $@

ssd.ll: $(UTSBASE)/common/io/scsi/targets/sd.c
	$(WLCC) $(CPPFLAGS) $(WLCCFLAGS) -DDEBUG -o $@ $(UTSBASE)/common/io/scsi/targets/sd.c 

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock

scsi.files:
	@cd ../scsi; pwd; $(MAKE) warlock
