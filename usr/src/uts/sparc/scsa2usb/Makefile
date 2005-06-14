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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# uts/sparc/scsa2usb/Makefile
#
#	This makefile drives the production of the scsa2usb driver
#	kernel module. sparc architecture dependent
#

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= scsa2usb
OBJECTS		= $(SCSA2USB_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(SCSA2USB_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/usb/scsa2usb
WARLOCK_OUT	= $(SCSA2USB_OBJS:%.o=%.ll)
WARLOCK_OK	= $(MODULE).ok

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

# 
# lint pass one enforcement 
# 
CFLAGS += $(CCVERBOSE)

# depends on misc/usba misc/scsi
#
LDFLAGS		+= -dy -Nmisc/usba -Nmisc/scsi

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

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
include $(UTSBASE)/sparc/Makefile.targ

#
#	Defines for local commands.
#
WARLOCK		= warlock
WLCC		= wlcc
TOUCH		= touch
SCCS		= sccs
TEST		= test

#
#	lock_lint rules
#
WARLOCK_OBJECTS = $(SCSA2USB_OBJS:%.o=%.ll)
USBA_FILES = $(USBA_OBJS:%.o=../usba/%.ll)
UHCI_FILES = $(UHCI_OBJS:%.o=../uhci/%.ll)
OHCI_FILES = $(OHCI_OBJS:%.o=../ohci/%.ll)
EHCI_FILES = $(EHCI_OBJS:%.o=../ehci/%.ll)
SCSI_FILES = $(SCSI_OBJS:%.o= -l ../scsi/%.ll)

warlock: $(MODULE).ok $(WARLOCK_OBJECTS) warlock_with_usba

%.wlcmd:
	$(TEST) -f $@ || $(SCCS) get $@

scsa2usb.ok: $(WARLOCK_OBJECTS) scsa2usb.wlcmd warlock_ddi.files \
	scsi.files
	$(WARLOCK) -c scsa2usb.wlcmd $(WARLOCK_OBJECTS)  \
		../warlock/scsi.ll \
		-l ../warlock/ddi_dki_impl.ll \
		$(SCSI_FILES)
	$(TOUCH) $@

%.ll: $(UTSBASE)/common/io/usb/scsa2usb/%.c \
		$(UTSBASE)/common/sys/usb/clients/mass_storage/usb_bulkonly.h \
		$(UTSBASE)/common/sys/usb/clients/mass_storage/usb_cbi.h \
		$(UTSBASE)/common/sys/usb/scsa2usb/scsa2usb.h
	$(WLCC)  $(CPPFLAGS) -DDEBUG -o $@ $<

warlock_with_usba: scsa2usb.wlcmd  $(WARLOCK_OBJECTS) usba_files \
	ohci_files ehci_files uhci_files warlock_ddi.files
	$(WARLOCK) -c ./scsa2usb_with_usba.wlcmd \
		$(USBA_FILES) $(OHCI_FILES) $(EHCI_FILES) $(UHCI_FILES) \
		$(WARLOCK_OBJECTS) \
		-l ../warlock/ddi_dki_impl.ll

usba_files:
	@cd ../usba;pwd; $(MAKE) warlock

uhci_files:
	@cd ../uhci;pwd; $(MAKE) warlock

ohci_files:
	@cd ../ohci;pwd; $(MAKE) warlock

ehci_files:
	@cd ../ehci;pwd; $(MAKE) warlock

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock

scsi.files:
	@cd ../scsi; pwd; $(MAKE) warlock
