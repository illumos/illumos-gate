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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY =	libnfs_basic.a
VERS =		.1

LIBOBJS =	libnfs_basic.o
COMMON =	ref_subr.o
OBJECTS =	$(LIBOBJS) $(COMMON)

include $(SRC)/lib/Makefile.lib

lintcheck := SRCS = ../libnfs_basic.c ../../lib/ref_subr.c

ROOTLIBDIR =	$(ROOT)/usr/lib/reparse
ROOTLIBDIR64 =	$(ROOT)/usr/lib/reparse/$(MACH64)

LIBSRCS = $(LIBOBJS:%.o=$(SRCDIR)/%.c)

LIBS =		$(DYNLIB)
LDLIBS +=	-lc -lnsl

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I$(SRC)/cmd/fs.d/nfs/lib

# not linted
SMATCH=off

.KEEP_STATE:

all: $(LIBS)

install: $(ROOTLIBDIR) $(ROOTLIBDIR64) all

lint: lintcheck

pics/ref_subr.o:     ../../lib/ref_subr.c
	$(COMPILE.c) -o pics/ref_subr.o ../../lib/ref_subr.c
	$(POST_PROCESS_O)

$(ROOTLIBDIR):
	$(INS.dir)

$(ROOTLIBDIR64):
	$(INS.dir)

include $(SRC)/lib/Makefile.targ
