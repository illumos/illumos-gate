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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
LIBRARY =	libshare.a
VERS =		.1
NFSLIB_DIR =	$(SRC)/cmd/fs.d/nfs/lib
NFSSECSRC  =	$(NFSLIB_DIR)/nfs_sec.c
NFSSHARETAB =	$(NFSLIB_DIR)/sharetab.c

LIBOBJS =	libshare.o libsharecore.o scfutil.o libshare_zfs.o \
		plugin.o parser.o issubdir.o
OTHOBJS =	sharetab.o nfs_sec.o
OBJECTS =	$(LIBOBJS) $(OTHOBJS)
COMMON =	../common

SRCS =		$(OBJECTS:%.o=../%.c)
LIBSRCS =	$(LIBOBJS:%.o=$(COMMON)/%.c)
POFILES	=	$(OBJECTS:%.o=%.po)
POFILE  =	libshare.po

include ../../Makefile.lib

ROOTDIRS= $(ROOT)/usr/include

ROOTHDRS= $(HDRS:%=$(ROOTDIRS)/%)

CHECKHDRS= $(HDRS:%.h=%.check)

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc -lnsl -lscf -lzfs -luuid -lfsmgt
all install := LDLIBS += -lxml2
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

SRCDIR =	../common
MAPDIR =	../spec/$(TRANSMACH)
SPECMAPFILE =	$(MAPDIR)/mapfile

#add nfs/lib directory as part of the include path
CFLAGS +=	$(CCVERBOSE) -g
CPPFLAGS +=	-D_REENTRANT -I$(SRC)/lib/libfsmgt/common \
		-I$(SRC)/cmd/fs.d/nfs/lib -I/usr/include/libxml2 \
		-I../common

.KEEP_STATE:

all: $(LIBS)

# we don't want to lint the sharetab and nfs_sec files
lint: $$(LIBSRCS)
	$(LINT.c) $(LINTCHECKFLAGS) $(LIBSRCS) $(LDLIBS)

pics/%.o:	$(NFSLIB_DIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ

$(POFILE):      $(POFILES)
	$(RM) $@; cat $(POFILES) > $@
