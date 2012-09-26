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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# This makefile drives the production of the EoIB Nexus driver
#
# sparc architecture dependent
#

#
# Path to the base of the uts directory tree (usually /usr/src/uts)
#
UTSBASE	= ../..

#
# Define the module and object file sets
#
MODULE		= eoib
OBJECTS		= $(EOIB_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(EOIB_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
WARLOCK_OUT	= $(EOIB_OBJS:%.o=%.ll)
WARLOCK_OK	= $(MODULE).ok
WLCMD_DIR	= $(UTSBASE)/common/io/warlock

#
# Include common rules
#
include $(UTSBASE)/sparc/Makefile.sparc

#
# Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
# Overrides
#
ALL_BUILDS	= $(ALL_BUILDSONLY64)
DEF_BUILDS	= $(DEF_BUILDSONLY64)

# Module specific debug flag
#
CPPFLAGS += -DEIB_DEBUG

# 
# Lint pass one enforcement 
# 
CFLAGS += $(CCVERBOSE)

CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-uninitialized

#
# Depends on misc/ibtl
#
LDFLAGS	+= -dy -Nmisc/mac -Nmisc/ibtl -Nmisc/ibcm -Nmisc/ibmf

#
# Default build targets
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK)

clobber:	$(CLOBBER_DEPS)
		$(RM) $(WARLOCK_OUT) $(WARLOCK_OK)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS) lint32

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
# Include common targets
#
include $(UTSBASE)/sparc/Makefile.targ

#
# Defines for local commands
#
WARLOCK		= warlock
WLCC		= wlcc
TOUCH		= touch
TEST		= test

warlock: $(WARLOCK_OK)

$(WARLOCK_OK): $(WARLOCK_OUT) $(WLCMD_DIR)/eoib.wlcmd warlock_ddi.files
	$(WARLOCK) -c $(WLCMD_DIR)/eoib.wlcmd $(WARLOCK_OUT)  \
		-l ../warlock/ddi_dki_impl.ll
	$(TOUCH) $@

%.ll: $(UTSBASE)/common/io/ib/clients/eoib/eib_adm.c \
	    $(UTSBASE)/common/io/ib/clients/eoib/eib_chan.c \
	    $(UTSBASE)/common/io/ib/clients/eoib/eib_cmn.c \
	    $(UTSBASE)/common/io/ib/clients/eoib/eib_ctl.c \
	    $(UTSBASE)/common/io/ib/clients/eoib/eib_data.c \
	    $(UTSBASE)/common/io/ib/clients/eoib/eib_fip.c \
	    $(UTSBASE)/common/io/ib/clients/eoib/eib_ibt.c \
	    $(UTSBASE)/common/io/ib/clients/eoib/eib_log.c \
	    $(UTSBASE)/common/io/ib/clients/eoib/eib_mac.c \
	    $(UTSBASE)/common/io/ib/clients/eoib/eib_main.c \
	    $(UTSBASE)/common/io/ib/clients/eoib/eib_rsrc.c \
	    $(UTSBASE)/common/io/ib/clients/eoib/eib_svc.c \
	    $(UTSBASE)/common/io/ib/clients/eoib/eib_vnic.c \
	    $(UTSBASE)/common/sys/ib/clients/eoib/fip.h \
	    $(UTSBASE)/common/sys/ib/clients/eoib/eib.h \
	    $(UTSBASE)/common/sys/ib/clients/eoib/eib_impl.h
	$(WLCC)  $(CPPFLAGS) -DDEBUG -o $@ $<

warlock_ddi.files:
	@cd ../warlock; pwd; $(MAKE) warlock
