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
# uts/sparc/usb_as/Makefile
#
#	This makefile drives the production of the usb_audio driver
#	kernel module. sparc architecture dependent
#

#ident	"%Z%%M%	%I%	%E% SMI"

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= usb_as
OBJECTS		= $(USB_AS_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(USB_AS_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
WARLOCK_OUT	= $(USB_AS_OBJS:%.o=%.ll)
WARLOCK_OK	= $(MODULE).ok

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

# 
# lint pass one enforcement 
# 
CFLAGS += $(CCVERBOSE)

#
# do not remove depends on amsrc2. If removed, amsrc2 gets unloaded when
# usb_ac_dacf gets unloaded
LDFLAGS		+= -dy -Nmisc/usba -Nmisc/audiosup -Nmisc/mixer -Nmisc/amsrc2

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW

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
USB_AS_FILES	= $(MODULE).ll
USBA_FILES	= $(USBA_OBJS:%.o=../usba/%.ll)
UHCI_FILES	= $(UHCI_OBJS:%.o=../uhci/%.ll)
OHCI_FILES	= $(OHCI_OBJS:%.o=../ohci/%.ll)
EHCI_FILES	= $(EHCI_OBJS:%.o=../ehci/%.ll)
MIXER_FILES	= $(MIXER_OBJS:%.o=../mixer/%.ll)
AUDIOSUP_FILES	= $(AUDIO_SUP_OBJS:%.o=../audiosup/%.ll)
# AMSRC1_OBJS is only defined in the closed tree.
AMSRC1_FILES	= $(CLOSED)/uts/sparc/amsrc1/am_src1.ll

#
#	Warlock targets
#
%.wlcmd:
	$(TEST) -f $@ || $(SCCS) get $@

warlock: $(MODULE).ok

$(WARLOCK_OK):	$(WARLOCK_OUT) warlock_ddi.files \
	warlock_audiosup.files warlock_mixer.files warlock_amsrc1.files \
	warlock_standalone warlock_with_usba  warlock_with_sada
	$(TOUCH) $(WARLOCK_OK)

warlock_with_sada: usb_as_with_sada.wlcmd \
	$(WARLOCK_OUT) \
	warlock_audiosup.files warlock_amsrc1.files warlock_mixer.files
	$(WARLOCK) -c usb_as_with_sada.wlcmd $(WARLOCK_OUT) \
	$(MIXER_FILES) $(AUDIOSUP_FILES) $(AMSRC1_FILES) \
	-l ../warlock/ddi_dki_impl.ll

warlock_with_usba: usb_as.wlcmd  $(WARLOCK_OUT) \
	warlock_ddi.files warlock_ohci.files warlock_usba.files \
	warlock_ehci.files warlock_uhci.files 
	$(WARLOCK) -c ./usb_as_with_usba.wlcmd \
	$(USBA_FILES) $(OHCI_FILES) $(EHCI_FILES) $(UHCI_FILES) \
	$(WARLOCK_OUT)  -l ../warlock/ddi_dki_impl.ll

warlock_standalone: $(WARLOCK_OUT) warlock_ddi.files usb_as.wlcmd
	$(WARLOCK) -c usb_as.wlcmd $(WARLOCK_OUT) \
	-l ../warlock/ddi_dki_impl.ll

%.ll: $(UTSBASE)/common/io/usb/clients/audio/usb_as/%.c
	$(WLCC)  $(CPPFLAGS) -DDEBUG -o $@ $<


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

warlock_amsrc1.files:
	@cd $(CLOSED)/uts/sparc/amsrc1; pwd; $(MAKE) warlock

warlock_mixer.files:
	@cd ../mixer; pwd; $(MAKE) warlock
