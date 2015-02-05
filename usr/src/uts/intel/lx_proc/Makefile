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
# uts/intel/lx_proc/Makefile
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2015 Joyent, Inc.
#
#	This makefile drives the production of the lxproc file system
#	kernel module.
#
#	i86 architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Path to where brand common sources live
#
LX_CMN		= $(SRC)/common/brand/lx

#
#	Define the module and object file sets.
#
MODULE		= lx_proc
OBJECTS		= $(LX_PROC_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(LX_PROC_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(USR_FS_DIR)/$(MODULE)

INC_PATH	+= -I$(UTSBASE)/common/brand/lx -I$(LX_CMN)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#	Overrides.
#
CFLAGS		+= $(CCVERBOSE)

#
#	Depends on procfs and lx_brand
#
LDFLAGS		+= -dy -Nfs/procfs -Nbrand/lx_brand -Ndrv/inotify -Ndrv/ip
LDFLAGS		+= -Nfs/sockfs

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV

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

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

#
#	Include brand-specific rules
#

include $(UTSBASE)/intel/lx_proc/Makefile.rules
