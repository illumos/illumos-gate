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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# uts/sparc/wbsd/Makefile
#
#	This makefile drives the production of the wbsd driver
#	kernel module.
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
MODULE		= wbsd
OBJECTS		= $(WBSD_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(WBSD_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
WARLOCK_OUT	= $(WBSD_OBJS:%.o=%.ll)
WARLOCK_OK	= $(MODULE).ok
WLCMD_DIR	= $(UTSBASE)/common/io/warlock

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#	Overrides.
#
DEBUG_FLGS	=
DEBUG_DEFS	+= $(DEBUG_FLGS)

#
# lint pass one enforcement
#  
CFLAGS += $(CCVERBOSE)

#
# dependency on scsi module
#
LDFLAGS += -dy -Nmisc/sda

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/sparc/Makefile.targ

WARLOCK		= warlock
WLCC		= wlcc
TOUCH		= touch
SDA_LLS 	= $(SDA_OBJS:%.o= -l ../sda/%.ll)
BLK2SCSA_LLS	= $(BLK2SCSA_OBJS:%.o= -l ../blk2scsa/%.ll)

warlock:	$(WARLOCK_OK)

blk2scsa.wl:
	@cd ../blk2scsa; pwd; $(MAKE) warlock

sda.wl:
	@cd ../sda; pwd; $(MAKE) warlock

$(WARLOCK_OK):	$(WARLOCK_OUT) $(WLCMD_DIR)/wbsd.wlcmd blk2scsa.wl sda.wl
	$(WARLOCK) -c $(WLCMD_DIR)/wbsd.wlcmd $(WARLOCK_OUT) \
		$(SDA_LLS) $(BLK2SCSA_LLS) \
		-l ../warlock/ddi_dki_impl.ll
	$(TOUCH) $@

%.ll:	$(UTSBASE)/common/io/sdcard/adapters/wbsd/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<
