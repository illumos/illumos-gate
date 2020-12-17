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

UTSBASE	= ../..

MODULE		= dcpc
OBJECTS		= $(DCPC_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
ROOTLINK	= $(ROOT_DTRACE_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/dtrace

ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTLINK) $(ROOT_CONFFILE)

include $(UTSBASE)/sparc/Makefile.sparc

LDFLAGS		+= -dy -Ndrv/dtrace -Ndrv/cpc

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

$(ROOTLINK):	$(ROOT_DTRACE_DIR) $(ROOTMODULE)
	-$(RM) $@; ln $(ROOTMODULE) $@

include $(UTSBASE)/sparc/Makefile.targ
