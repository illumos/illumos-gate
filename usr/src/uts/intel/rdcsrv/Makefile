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
# uts/intel/rdcsrv/Makefile
#
#       This makefile drives the production of the rdcsrv kernel module
#
#       intel implementation architecture dependent
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
MODULE		= rdcsrv
OBJECTS		= $(RDCSRV_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(RDCSRV_OBJS:%.o=$(LINTS_DIR)/%.ln)
INC_PATH	+= -I$(ROOT)/usr/include
ROOTMODULE      = $(USR_DRV_DIR)/$(MODULE)
ROOTLINK        = $(USR_MISC_DIR)/$(MODULE)

#
#       Include common rules.
#
include ../Makefile.$(ARCHDIR)
include $(UTSBASE)/common/avs/Makefile.com

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTLINK)

#
# lint pass one enforcement
#
CFLAGS		+= $(CCVERBOSE) -D_SD_8K_BLKSIZE -D_SYSCALL32
LINT_DEFS	+= -D_SD_8K_BLKSIZE -D_SYSCALL32
LDFLAGS		+= -dy -N"strmod/rpcmod" -N"misc/rdcstub"

CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-unused-variable

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

$(ROOTLINK):	$(USR_MISC_DIR) $(ROOTMODULE)
		-$(RM) $@; $(LN) $(ROOTMODULE) $@

#
#	Include common targets.
#
include ../Makefile.targ
