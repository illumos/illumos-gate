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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
#
# uts/intel/usb_ac/Makefile
#
#	This makefile drives the production of the usb_ac driver
#	kernel module. Intel architecture dependent
#


#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= usb_ac
OBJECTS		= $(USB_AC_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(USB_AC_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/usb/clients/audio/usb_ac
WARLOCK_OUT	= $(USB_AC_OBJS:%.o=%.ll)
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
#	Override defaults to build a unique, local modstubs.o.
#
MODSTUBS_DIR	 = $(OBJS_DIR)
CLEANFILES	+= $(MODSTUBS_O)

CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-uninitialized

#
# depends on misc/usba
#
LDFLAGS += -dy -Nmisc/usba -Ndrv/audio

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
WARLOCK		= warlock
WLCC		= wlcc
TOUCH		= touch
TEST		= test

#
#	lock_lint rules
#
USBA_FILES	= $(USBA_OBJS:%.o=../usba/%.ll)
UHCI_FILES	= $(UHCI_OBJS:%.o=../uhci/%.ll)
OHCI_FILES	= $(OHCI_OBJS:%.o=../ohci/%.ll)
EHCI_FILES	= $(EHCI_OBJS:%.o=../ehci/%.ll)


#
#	Warlock targets
#
warlock: $(WARLOCK_OK)

$(WARLOCK_OK):	$(WARLOCK_OUT) warlock_ddi.files \
	warlock_standalone warlock_usba.files warlock_with_usba
	$(TOUCH) $(WARLOCK_OK)

warlock_with_usba: $(WLCMD_DIR)/usb_ac_with_usba.wlcmd  $(WARLOCK_OUT) \
	warlock_ddi.files warlock_usba.files warlock_ohci.files \
	warlock_ehci.files warlock_uhci.files
	$(WARLOCK) -c $(WLCMD_DIR)/usb_ac_with_usba.wlcmd \
	$(USBA_FILES) $(OHCI_FILES) $(EHCI_FILES) $(UHCI_FILES) \
	$(WARLOCK_OUT)  -l ../warlock/ddi_dki_impl.ll

warlock_standalone: $(WARLOCK_OUT) warlock_ddi.files $(WLCMD_DIR)/usb_ac.wlcmd
	$(WARLOCK) -c $(WLCMD_DIR)/usb_ac.wlcmd $(WARLOCK_OUT) \
	-l ../warlock/ddi_dki_impl.ll

%.ll: $(UTSBASE)/common/io/usb/clients/audio/usb_ac/%.c
	$(WLCC) $(CPPFLAGS) -DDEBUG -o $@ $<

warlock_usba.files:
	@cd ../usba;pwd; $(MAKE) warlock

warlock_ohci.files:
	@cd ../ohci;pwd; $(MAKE) warlock

warlock_uhci.files:
	@cd ../uhci;pwd; $(MAKE) warlock

warlock_ehci.files:
	@cd ../ehci;pwd; $(MAKE) warlock

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock
