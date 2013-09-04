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

LIBRARY =	libfsmgt.a
VERS =		.1
NFSLIB_DIR =	$(SRC)/cmd/fs.d/nfs/lib

OBJECTS =	fs_mounts.o fs_mount_defaults.o \
		sys_info.o sharetab.o nfs_sec.o \
		replica.o nfs_mntinfo.o fs_shares.o \
		cmd.o fileutil.o fs_dfstab.o \
		nfs_netcfg.o nfs_nfssec.o

include ../../Makefile.lib

ROOTDIRS= $(ROOT)/usr/include

ROOTHDRS= $(HDRS:%=$(ROOTDIRS)/%)

CHECKHDRS= $(HDRS:%.h=%.check)

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc -lnsl -lkstat

SRCDIR =	../common
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I$(SRC)/lib/libfsmgt/common \
		-I$(SRC)/cmd/fs.d/nfs/lib

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-uninitialized

CLOBBERFILES	+= $(SRCDIR)/nfs_sec.c
CLOBBERFILES	+= $(SRCDIR)/replica.c
CLOBBERFILES	+= $(SRCDIR)/sharetab.c

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

$(SRCDIR)/sharetab.c: $(NFSLIB_DIR)/sharetab.c
	rm -f $(SRCDIR)/sharetab.c
	$(CP) -p $(NFSLIB_DIR)/sharetab.c $(SRCDIR)

$(SRCDIR)/nfs_sec.c: $(NFSLIB_DIR)/nfs_sec.c
	rm -f $(SRCDIR)/nfs_sec.c
	$(CP) -p $(NFSLIB_DIR)/nfs_sec.c $(SRCDIR)

$(SRCDIR)/replica.c: $(NFSLIB_DIR)/replica.c
	rm -f $(SRCDIR)/replica.c
	$(CP) -p $(NFSLIB_DIR)/replica.c $(SRCDIR)

include ../../Makefile.targ
