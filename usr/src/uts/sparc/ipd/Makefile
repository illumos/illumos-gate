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
# Copyright 2012 Joyent, Inc.  All rights reserved.
# Copyright (c) 2014 Igor Kozhukhov <ikozhukhov@gmail.com>
# Use is subject to license terms.
# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
#

UTSBASE	= ../..

MODULE		= ipd
OBJECTS		= $(IPD_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/inet/ipd

include $(UTSBASE)/sparc/Makefile.sparc

ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

LDFLAGS += -Nmisc/neti -Nmisc/hook

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

include $(UTSBASE)/sparc/Makefile.targ
