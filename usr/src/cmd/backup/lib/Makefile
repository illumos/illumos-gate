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

LIBRARY=	libdump.a

# Has to be before include of Makefile.backup
# This should be POFILE=libdump.po, but that causes make to
# fall over due to some seriously weird interactions in the
# various indirectly-included makefiles.  So, since this works
# and is otherwise harmless, we fake it.
PROG=		libdump

# Include library definitions, then backup definitions, as in general
# we want the flags and such from our tree.

include ../../../lib/Makefile.lib
include ../Makefile.backup

SRCDIR =	.

# Specifically request the construction of a static library.
# This library is not installed in the proto area.
LIBS=	$(LIBRARY)

HDRS=		../include/byteorder.h \
	../include/memutils.h ../include/myrcmd.h \
	../../../head/protocols/dumprestore.h \
	../include/rmt.h

YFILE=		getdate.y
YSRC=		getdate.c

CLOBBERFILES +=	$(LIBS) $(GLIB)

LOBJS=		rmtlib.o myrcmd.o \
		$(YSRC:%.c=%.o) \
		byteorder.o memutils.o $(RPC_CLNT:%.c=%.o) $(RPC_XDR:%.c=%.o)

OBJECTS=	$(LOBJS)
POFILES=	$(OBJECTS:.o=.po)
GENERAL=	../include
GLOBAL=		../../../head
CPPFLAGS=	-I$(GENERAL) -I$(GLOBAL) $(CPPFLAGS.master)
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-unused-variable
LINTOUT=	lint.out
CLEANFILES=	$(OBJECTS) $(LINTOUT) $(LINTLIB) $(DEBUGS) *.ln \
		$(YSRC) $(LIBRARY)
LINTFLAGS +=	-y

# support for -g library
GLIB=		libdump_g.a
DEBUGS=		$(OBJECTS:%=.debug/%)
$(GLIB):=	AROBJS = $(DEBUGS)
$(GLIB):=	DIR = .debug
$(GLIB):=	CFLAGS= -g $(XESS) -DDEBUG -DYYDEBUG ${SBFLAGS}

.KEEP_STATE:

all:	$(LIBS)

debug:	$(LIBS) $(GLIB)

.debug:
	-@mkdir -p $@

.debug/%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(GLIB): .debug $$(DEBUGS)
	$(BUILD.AR)
	$(POST_PROCESS_A)

$(OBJECTS):	$(HDRS)

install:	all

$(POFILE):	$(POFILES)
	$(RM) $@; cat $(POFILES) > $@

# rpcgen produces unused local variables that we can't easily suppress.
# It is also stupid about 32/64 bit integers.  Since we don't support
# the RPC subsystem any more, just ignore complaints about it all.
# We have no control over yaccpar, and it has lots of 32/64 complaints.
# Assumes lint run with -s argument
lint:		lint.out
	sed -f lint.sed lint.out

lint.out:	$(LINTLIB)

check:	$(HDRS)
	$(CSTYLE) $(CSTYLEFLAGS) `echo $(SRCS) | sed -e s/getdate.c//` $(HDRS)
	$(HDRCHK) $(HDRCHKFLAGS) $(HDRS)

# include library targets
include ../../../lib/Makefile.targ

_msg: 		$(POFILE)
