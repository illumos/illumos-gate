#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.


UTSBASE	= ../..

MODULE = smbios
OBJECTS	= $(OBJS_DIR)/smbios.o
LINTS = $(LINTS_DIR)/smbios.ln
ROOTMODULE = $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR = $(UTSBASE)/common/io

include $(UTSBASE)/intel/Makefile.intel

ALL_TARGET = $(BINARY) $(SRC_CONFILE)
LINT_TARGET = $(MODULE).lint
INSTALL_TARGET = $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

# needs work
SMOFF += signed_integer_overflow_check

.KEEP_STATE:

def: $(DEF_DEPS)

all: $(ALL_DEPS)

clean: $(CLEAN_DEPS)

clobber: $(CLOBBER_DEPS)

lint: $(LINT_DEPS)

modlintlib: $(MODLINTLIB_DEPS)

clean.lint: $(CLEAN_LINT_DEPS)

install: $(INSTALL_DEPS)

include $(UTSBASE)/intel/Makefile.targ
