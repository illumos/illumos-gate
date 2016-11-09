#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2016 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
#

#
# This makefile drives the production of the iwn driver kernel module.
#
# intel architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define firmware location & files
#
FWDIR	= $(UTSBASE)/common/io/iwn/fw-iw
FWFILES	= iwlwifi-100-5.ucode iwlwifi-1000-3.ucode iwlwifi-105-6.ucode \
	iwlwifi-135-6.ucode iwlwifi-2000-6.ucode iwlwifi-2030-6.ucode \
	iwlwifi-4965-2.ucode iwlwifi-5000-2.ucode iwlwifi-5150-2.ucode \
	iwlwifi-6000-4.ucode iwlwifi-6000g2a-5.ucode iwlwifi-6000g2b-6.ucode \
	iwlwifi-6050-5.ucode

#
#	Define the module and object file sets.
#
MODULE		= iwn
OBJECTS		= $(IWN_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(IWN_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
ROOTFIRMWARE	= $(FWFILES:%=$(ROOT_FIRMWARE_DIR)/$(MODULE)/%)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(CONFMOD) $(ITUMOD)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTFIRMWARE)

#
#	Overrides
#
LINTTAGS	+= -erroff=E_FUNC_RET_MAYBE_IGNORED2
LINTTAGS	+= -erroff=E_FUNC_RET_ALWAYS_IGNOR2
LINTTAGS	+= -erroff=E_INTEGER_OVERFLOW_DETECTED

LDFLAGS         += -dy -Nmisc/mac -Nmisc/net80211 -Ndrv/random -Ndrv/ip

CERRWARN	+= -erroff=E_INTEGER_OVERFLOW_DETECTED

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
