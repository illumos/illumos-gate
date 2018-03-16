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
# Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
#

LIBRARY =	libfksmbfs.a
VERS =		.1

OBJS_LOCAL = \
	fksmbfs_rwlock.o \
	fake_fssub.o \
	fake_getdents.o \
	fake_lookup.o \
	fake_misc.o \
	fake_modconf.o \
	fake_nbmlock.o \
	fake_open.o \
	fake_rename.o \
	fake_rw.o \
	fake_stat.o \
	fake_unlink.o \
	fake_vfs.o \
	fake_vnode.o \
	fake_zone.o

# See also: $SRC/uts/common/Makefile.files
# NB: Intentionally ommitted, compared w/ the above:
#  smbfs_rwlock.o
#
OBJS_FS_SMBFS = \
	smbfs_vfsops.o \
	smbfs_vnops.o \
	smbfs_client.o \
	smbfs_node.o \
	smbfs_smb.o \
	smbfs_smb1.o \
	smbfs_smb2.o \
	smbfs_subr.o \
	smbfs_subr2.o \
	smbfs_acl.o \
	smbfs_xattr.o

OBJS_CMN_SMBFS = \
	smbfs_ntacl.o

OBJS_MISC = \
	acl_common.o \
	pathname.o \
	refstr.o

OBJECTS = \
	$(OBJS_LOCAL) \
	$(OBJS_FS_SMBFS) \
	$(OBJS_CMN_SMBFS) \
	$(OBJS_MISC)

include ../../../Makefile.lib
include ../../Makefile.lib

# Force SOURCEDEBUG
CSOURCEDEBUGFLAGS	= -g
CCSOURCEDEBUGFLAGS	= -g
STRIP_STABS 	= :

# Note: need our sys includes _before_ ENVCPPFLAGS, proto etc.
# Also, like Makefile.uts, reset CPPFLAGS
CPPFLAGS.first += -I../../../libfakekernel/common
CPPFLAGS.first += -I../../libfknsmb/common
CPPFLAGS.first += -I../common
CPPFLAGS= $(CPPFLAGS.first)

INCS += -I$(SRC)/uts/common/fs/smbclnt
INCS += -I$(SRC)/uts/common
INCS += -I$(SRC)/common/smbclnt
INCS += -I$(SRC)/common

CPPFLAGS += $(INCS) -D_REENTRANT -D_FAKE_KERNEL
CPPFLAGS += -D_FILE_OFFSET_BITS=64
# Always want DEBUG here
CPPFLAGS += -DDEBUG

CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-parentheses

LDLIBS +=	$(MACH_LDLIBS)
LDLIBS +=	-lfknsmb -lfakekernel -lidmap -lcmdutils -lavl -lc

FS_SMBFS_DIR=$(SRC)/uts/common/fs/smbclnt/smbfs
CMN_SMBFS_DIR=$(SRC)/common/smbclnt
SRCS=   $(OBJS_LOCAL:%.o=$(SRCDIR)/%.c) \
	$(OBJS_FS_SMBFS:%.o=$(FS_SMBFS_DIR)/%.c) \
	$(OBJS_CMN_SMBFS:%.o=$(CMN_SMBFS_DIR)/%.c)

all:

pics/%.o:	$(FS_SMBFS_DIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

# pathname.o
pics/%.o:	$(SRC)/uts/common/fs/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

# refstr.o
pics/%.o:	$(SRC)/uts/common/os/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/acl_common.o:	   $(SRC)/common/acl/acl_common.c
	$(COMPILE.c) -o $@ $(SRC)/common/acl/acl_common.c
	$(POST_PROCESS_O)

.KEEP_STATE:

include ../../Makefile.targ
include ../../../Makefile.targ
