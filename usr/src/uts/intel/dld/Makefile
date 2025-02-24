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
# Copyright (c) 2018, Joyent, Inc.

#
# Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
# Define the module and object file sets.
#
MODULE		= dld
OBJECTS		= $(DLD_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/dld
ROOTDEVLINK	= $(ROOT)/dev/$(MODULE)

#
# Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
# Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
# Overrides
#
CFLAGS		+= $(CCVERBOSE)
LDFLAGS		+= -N misc/dls -N misc/mac

#
# For now, disable these warnings; maintainers should endeavor
# to investigate and remove these for maximum coverage.
# Please do not carry these forward to new Makefiles.
#

CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-parentheses

# needs work
$(OBJS_DIR)/dld_drv.o := SMOFF += cast_assign

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS) $(ROOTDEVLINK)

$(ROOTDEVLINK):
	-$(RM) $@; $(SYMLINK) ../devices/pseudo/$(@F)@0:ctl $@

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ
