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
# uts/sparc/usb_ac/Makefile
#
#	This makefile drives the production of the usb_ac driver
#	kernel module. sparc architecture dependent
#
#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= usb_ac
OBJECTS		= $(USB_AC_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(USB_AC_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/usb/clients/audio/usb_ac
WARLOCK_OUT	= $(USB_AC_OBJS:%.o=%.ll) usb_ac_dacf.ll
WARLOCK_OK	= $(MODULE).ok
WLCMD_DIR       = $(UTSBASE)/common/io/warlock

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE)

#
LDFLAGS	+= -dy -Nmisc/usba -Nmisc/audiosup -Nmisc/mixer

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN

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
include $(UTSBASE)/sparc/Makefile.targ

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
MIXER_FILES = $(MIXER_OBJS:%.o=$(UTSBASE)/sparc/mixer/%.ll)
AUDIO_SUP_FILES = $(AUDIO_SUP_OBJS:%.o=$(UTSBASE)/sparc/audiosup/%.ll)
AMSRC2_FILES = $(AMSRC2_OBJS:%.o=$(UTSBASE)/sparc/amsrc2/%.ll)


#
#	Warlock targets
#
warlock: $(WARLOCK_OK)

$(WARLOCK_OK):	$(WARLOCK_OUT) warlock_ddi.files \
	warlock_audiosup.files warlock_mixer.files warlock_amsrc2.files \
	warlock_standalone warlock_with_usba  warlock_with_sada
	$(TOUCH) $(WARLOCK_OK)

warlock_with_sada: $(WLCMD_DIR)/usb_ac_with_sada.wlcmd \
	$(WARLOCK_OUT) \
	warlock_audiosup.files warlock_amsrc2.files warlock_mixer.files
	$(WARLOCK) -c $(WLCMD_DIR)/usb_ac_with_sada.wlcmd $(WARLOCK_OUT) \
	$(MIXER_FILES) $(AUDIO_SUP_FILES) $(AMSRC2_FILES) \
	-l ../warlock/ddi_dki_impl.ll

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

warlock_audiosup.files:
	@cd ../audiosup; pwd; $(MAKE) warlock

warlock_amsrc2.files:
	@cd ../amsrc2; pwd; $(MAKE) warlock

warlock_mixer.files:
	@cd ../mixer; pwd; $(MAKE) warlock
