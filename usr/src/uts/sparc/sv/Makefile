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
# uts/sparc/sv/Makefile
#
#       This makefile drives the production of the sv kernel module
#
#       sparc implementation architecture dependent
#

#
#       Path to the base of the uts directory tree (usually /usr/src/uts).
#
#
UTSBASE = ../..

ARCHDIR:sh = cd ..; basename `pwd`

#
#       Define the module and object file sets.
#
MODULE		= sv
OBJECTS		= $(SV_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(SV_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE      = $(USR_DRV_DIR)/$(MODULE)
INC_PATH	+= -I$(ROOT)/usr/include
CONF_SRCDIR	= $(UTSBASE)/common/avs/ns/sv

#
#       Include common rules.
#
include ../Makefile.$(ARCHDIR)
include $(UTSBASE)/common/avs/Makefile.com

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE)
LDFLAGS += -dy -N"drv/nsctl" -N"drv/nskern" -N"misc/spuni"

CERRWARN += -_gcc=-Wno-uninitialized

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
include ../Makefile.targ
