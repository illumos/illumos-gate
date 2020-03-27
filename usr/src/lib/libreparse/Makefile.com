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

LIBRARY=	libreparse.a
VERS=		.1

LOCOBJS =	fs_reparse_lib.o
COMOBJS =	fs_reparse.o
OBJECTS =	$(LOCOBJS) $(COMOBJS)
COMDIR =	$(SRC)/common/fsreparse

include ../../Makefile.lib

SRCDIR =	../common
SRCS =		$(LOCOBJS:%.o=$(SRCDIR)/%.c) $(COMOBJS:%.o=$(COMDIR)/%.c)

LIBS =		$(DYNLIB)
LDLIBS +=	-lc -lnvpair

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(COMDIR) -D_FILE_OFFSET_BITS=64


.KEEP_STATE:

all: $(LIBS)


include ../../Makefile.targ

pics/%.o: $(COMDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
