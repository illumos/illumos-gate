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
# Copyright 2024 Oxide Computer Company
#

UTSBASE = ../..

MODULE		= igc
OBJECTS		= $(IGC_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)

include $(UTSBASE)/intel/Makefile.intel

ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)
CPPFLAGS	+= -I$(UTSBASE)/common/io/igc
LDFLAGS		+= -N misc/mac

#
# Smatch gags for the core code. We should consider fixing these and
# understanding the implications of these as part of figuring out how much
# divergence here is okay. For the moment we are opting for no divergence.
#
$(OBJS_DIR)/igc_api.o := SMOFF += all_func_returns
$(OBJS_DIR)/igc_base.o := SMOFF += all_func_returns
$(OBJS_DIR)/igc_i225.o := SMOFF += all_func_returns
$(OBJS_DIR)/igc_mac.o := SMOFF += all_func_returns
$(OBJS_DIR)/igc_nvm.o := SMOFF += all_func_returns
$(OBJS_DIR)/igc_phy.o := SMOFF += all_func_returns

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

include $(UTSBASE)/intel/Makefile.targ
