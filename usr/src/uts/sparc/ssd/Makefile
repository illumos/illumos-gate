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
# uts/sparc/ssd/Makefile
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

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

WARLOCK_OUT     = $(SSD_OBJS:%.o=%.ll)
WARLOCK_OK      = $(MODULE).ok

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
#	Default build targets.
#
.KEEP_STATE:

all:		$(ALL_DEPS)

def:		$(DEF_DEPS)

clean:		$(CLEAN_DEPS); \
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK)

clobber:	$(CLOBBER_DEPS); \
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
SCCS		= sccs
TEST		= test

#
# Warlock targets

SSD_FILES   = $(MODULE).ll
SCSI_FILES = $(SCSI_OBJS:%.o=-l ../scsi/%.ll)

warlock: warlock_alone

warlock_alone: $(MODULE).ok

%.wlcmd:
	$(TEST) -f $@ || $(SCCS) get $@

scsi_files:
	@cd ../scsi; pwd; $(MAKE) warlock

ssd.ok: ssd.wlcmd $(SSD_FILES) scsi_files
	$(WARLOCK) -c ./ssd.wlcmd $(SSD_FILES) \
	$(SCSI_FILES) \
	-l ../warlock/ddi_dki_impl.ll
	$(TOUCH) $@

ssd.ll: $(UTSBASE)/common/io/scsi/targets/sd.c
	$(WLCC) $(CPPFLAGS) $(WLCCFLAGS) -DDEBUG -o $@ $(UTSBASE)/common/io/scsi/targets/sd.c 

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock

scsi.files:
	@cd ../scsi; pwd; $(MAKE) warlock
