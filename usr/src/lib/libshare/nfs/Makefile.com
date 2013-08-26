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
#
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
#

LIBRARY =	libshare_nfs.a
VERS =		.1
NFSLIB_DIR	= $(SRC)/cmd/fs.d/nfs/lib

LIBOBJS =	libshare_nfs.o
OTHOBJS =	nfs_sec.o nfslog_config.o nfslogtab.o smfcfg.o
OBJECTS =	$(LIBOBJS) $(OTHOBJS)

include ../../../Makefile.lib

ROOTLIBDIR =	$(ROOT)/usr/lib/fs/nfs
ROOTLIBDIR64 =	$(ROOT)/usr/lib/fs/nfs/$(MACH64)

LIBSRCS = $(LIBOBJS:%.o=$(SRCDIR)/%.c)
# we don't want to lint the sources for OTHOBJS since they are pre-existing files
# that are not lint free.
lintcheck := SRCS = $(LIBSRCS)

LIBS =		$(DYNLIB)
LDLIBS +=	-lshare -lnsl -lscf -lumem -lc -lxml2

#add nfs/lib directory as part of the include path
CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized
CPPFLAGS +=	-D_REENTRANT -I$(NFSLIB_DIR) \
		-I$(ADJUNCT_PROTO)/usr/include/libxml2 -I$(SRCDIR)/../common

.KEEP_STATE:

all: $(LIBS)

install: all

lint: lintcheck

pics/%.o:  $(NFSLIB_DIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../../Makefile.targ
