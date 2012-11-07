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
#	This makefile drives the production of the wc driver 
#	kernel module.
#
#	intel implementation architecture independent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= wc
OBJECTS		= $(WC_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(WC_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io
WARLOCK_OUT	= $(WC_OBJS:%.o=%.ll)
WARLOCK_OK	= $(MODULE).ok
WLCMD_DIR	= $(UTSBASE)/common/io/warlock

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
#	Overrides.
#
LDFLAGS		+= -dy -Nmisc/tem -Ndacf/consconfig_dacf

CERRWARN	+= -_gcc=-Wno-uninitialized

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
include $(UTSBASE)/intel/Makefile.targ

#
#	Defines for local commands
#
TEST		= test
WLCC		= wlcc
TOUCH		= touch
WARLOCK		= warlock

#
#	warlock targets
#

#
# vcons_conf.c is compile to genunix, add it to WARLOCK_OUT
#
WARLOCK_OUT	+= vcons_conf.ll

warlock:	$(WARLOCK_OUT) sdev_vtops.file  warlock_ddi.files
	$(WARLOCK) -c $(WLCMD_DIR)/wc.wlcmd $(WARLOCK_OUT) \
	-l ../../intel/warlock/ddi_dki_impl.ll
	$(WARLOCK) -c $(WLCMD_DIR)/wc_devfs.wlcmd sdev_vtops.ll vcons_conf.ll \
	-l ../../intel/warlock/ddi_dki_impl.ll
	$(TOUCH) $(WARLOCK_OK)

%.ll:	$(UTSBASE)/common/io/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

sdev_vtops.file:
	$(WLCC) $(CPPFLAGS) -DDEBUG -o sdev_vtops.ll -c \
	../../common/fs/dev/sdev_vtops.c

warlock_ddi.files:
	@cd ../../intel/warlock; pwd; $(MAKE) warlock
