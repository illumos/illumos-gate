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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the TPM driver kernel
#	module.
#

UTSBASE	= $(SRC)/uts

#
#	Define the module and object file sets.
#
MODULE		= tpm
OBJECTS		= $(TPM_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(TPM_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)

#
#	Include common rules.
#
# For now, TPM only delivers on x86/64 platforms, so only build
# with the Intel rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#	Dependency
#
LDFLAGS		+= -dy

CFLAGS		+= -xCC

# This is for everything except /usr/include/tss/
CPPFLAGS	+= -I$(ROOT)/usr/include

# This is for /usr/include/tss/, which is not built in the ON consolidation
CPPFLAGS	+= -I$(ADJUNCT_PROTO)/usr/include

CERRWARN	+= -_gcc=-Wno-parentheses

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

include $(UTSBASE)/intel/Makefile.targ

$(OBJECTS): $(OBJS_DIR)
