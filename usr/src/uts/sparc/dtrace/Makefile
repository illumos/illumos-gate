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

UTSBASE	= ../..

PLATFORM	= sun4u
MODULE		= dtrace
OBJECTS		= $(DTRACE_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/dtrace

include $(UTSBASE)/sparc/Makefile.sparc

#
#	Redefine	DSF_DIR
#
DSF_DIR		= $(UTSBASE)/$(PLATFORM)/genassym

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-type-limits
CERRWARN	+= $(CNOWARN_UNINIT)

ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

DTRACE_INC_32	= -I$(UTSBASE)/sparc/v7
DTRACE_INC_64	= -I$(UTSBASE)/sparc/v9

CFLAGS		+= $(CCVERBOSE)
CPPFLAGS += $(DTRACE_INC_$(CLASS))
CPPFLAGS += -I$(SRC)/common/util

DTRACE_XAS_32	= -xarch=v8plus
DTRACE_XAS_64	= -xarch=v9

AS_CPPFLAGS	+= $(DTRACE_INC_64)
ASFLAGS		+= $(DTRACE_XAS_$(CLASS))
AS_INC_PATH	+= -I$(DSF_DIR)/$(OBJS_DIR)

ASSYM_H		= $(DSF_DIR)/$(OBJS_DIR)/assym.h

#
# For now, disable these warnings; maintainers should endeavor
# to investigate and remove these for maximum coverage.
# Please do not carry these forward to new Makefiles.
#

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

$(BINARY):	$(ASSYM_H)

include $(UTSBASE)/sparc/Makefile.targ
