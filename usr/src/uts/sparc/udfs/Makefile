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
# Copyright (c) 2011 Bayard G. Bell. All rights reserved.
#
#	This makefile drives the production of the udfs file system
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
MODULE		= udfs
OBJECTS		= $(UDFS_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(UDFS_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_FS_DIR)/$(MODULE)

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#	Overrides.
#
MODSTUBS_DIR	 = $(OBJS_DIR)
$(MODSTUBS_O)	:= AS_CPPFLAGS += -DUDFS_MODULE
CLEANFILES	+= $(MODSTUBS_O)
CFLAGS		+= $(CCVERBOSE)

#
# Define dependency on specfs
#
LDFLAGS         += -dy -N fs/specfs

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_SUSPICIOUS_COMPARISON
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-type-limits

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

putback:
	-cstyle -p ../../common/fs/udfs/udf_alloc.c
	-cstyle -p ../../common/fs/udfs/udf_bmap.c
	-cstyle -p ../../common/fs/udfs/udf_dir.c
	-cstyle -p ../../common/fs/udfs/udf_inode.c
	-cstyle -p ../../common/fs/udfs/udf_subr.c
	-cstyle -p ../../common/fs/udfs/udf_vfsops.c
	-cstyle -p ../../common/fs/udfs/udf_vnops.c
	-keywords ../../common/fs/udfs/udf_alloc.c
	-keywords ../../common/fs/udfs/udf_bmap.c
	-keywords ../../common/fs/udfs/udf_dir.c
	-keywords ../../common/fs/udfs/udf_inode.c
	-keywords ../../common/fs/udfs/udf_subr.c
	-keywords ../../common/fs/udfs/udf_vfsops.c
	-keywords ../../common/fs/udfs/udf_vnops.c
	-keywords Makefile
	-keywords ../../common/sys/fs/udf_inode.h
	-keywords ../../common/sys/fs/udf_volume.h
	-hdrchk ../../common/sys/fs/udf_inode.h
	-hdrchk ../../common/sys/fs/udf_volume.h



#
#	Include common targets.
#
include $(UTSBASE)/sparc/Makefile.targ
