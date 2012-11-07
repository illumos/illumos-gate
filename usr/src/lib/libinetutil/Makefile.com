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

LIBRARY = libinetutil.a
VERS = 	  .1
OBJECTS = octet.o inetutil.o ifspec.o ifaddrlist.o ifaddrlistx.o eh.o tq.o \
	    ofmt.o

include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

LIBS =		$(DYNLIB) $(LINTLIB)

SRCDIR =	../common
COMDIR =	$(SRC)/common/net/dhcp
SRCS = 		$(COMDIR)/octet.c $(SRCDIR)/inetutil.c \
		$(SRCDIR)/ifspec.c $(SRCDIR)/eh.c $(SRCDIR)/tq.c \
		$(SRCDIR)/ifaddrlist.c $(SRCDIR)/ifaddrlistx.c \
		$(SRCDIR)/ofmt.c

$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)
LDLIBS +=	-lsocket -lc

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR)

CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-parentheses

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: $(COMDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ
