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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# uts/sparc/devfs/Makefile
#	This makefile drives the production of the Cache file system
#	kernel module.
#
#	sparc implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= devfs
OBJECTS		= $(DEVFS_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_FS_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

CERRWARN	+= -_gcc=-Wno-parentheses

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#	Overrides.
#
MODSTUBS_DIR	 = $(OBJS_DIR)
$(MODSTUBS_O)	:= AS_CPPFLAGS += -DDEVFS_MODULE
CLEANFILES	+= $(MODSTUBS_O)
CFLAGS		+= $(CCVERBOSE)

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/sparc/Makefile.targ
