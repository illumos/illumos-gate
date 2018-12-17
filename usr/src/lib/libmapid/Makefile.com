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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =	libmapid.a
VERS	=	.1
SMF_DIR	=	$(SRC)/cmd/fs.d/nfs/lib

LIBOBJS	=	mapid.o
OTHOBJS	=	smfcfg.o
OBJECTS =	$(LIBOBJS) $(OTHOBJS)

include $(SRC)/lib/Makefile.lib

LIBS	=	$(DYNLIB) $(LINTLIB)

#
# This library will be installed w/all other nfs
# binaries in /usr/lib/nfs, so define it as such.
#
ROOTLIBDIR   =	$(ROOT)/usr/lib/nfs

#
# SRCS is defined to be $(OBJECTS:%.o=$(SRCDIR)/%.c)
#
SRCDIR	=	../common
LIBSRCS	= $(LIBOBJS:%.o=$(SRCDIR)/%.c)
$(LINTLIB) := SRCS = $(LINTSRC:%=$(SRCDIR)/%)
lintcheck  :=	SRCS = $(LIBSRCS)

LDLIBS	+=	-lresolv -lc -lscf

CFLAGS	+=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR) -I$(SMF_DIR) -D_REENTRANT

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized

SMOFF += all_func_returns

.KEEP_STATE:

all:  $(LIBS)

install: $(ROOTLIBDIR) all

lint:	$(LINTLIB) lintcheck

pics/%.o:	$(SMF_DIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(ROOTLIBDIR):
	$(INS.dir)

include ../../Makefile.targ
