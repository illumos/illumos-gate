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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		elfsign
SHFILES=	elfsigncmp

LIBOBJS=	elfcertlib.o elfsignlib.o
OBJS=		$(PROG).o $(LIBOBJS)

.PARALLEL:	$(OBJS)

CMDDIR=	$(SRC)/cmd/cmd-crypto/elfsign
LIBDIR=	$(SRC)/lib/libelfsign/common
SRCS=	$(CMDDIR)/$(PROG).c $(LIBOBJS:%.o=$(LIBDIR)/%.c)
CLEANFILES=	$(PROG) $(OBJS) $(SHFILES)

include ../../../src/tools/Makefile.tools

OWNER=	root
GROUP=	bin
CFLAGS += $(CCVERBOSE)
CFLAGS += -_gcc=-fasm

CPPFLAGS += -D_POSIX_PTHREAD_SEMANTICS
CPPFLAGS +=	-I$(SRC)/lib/libelfsign/common
CPPFLAGS +=	-I$(SRC)/uts/common
CPPFLAGS +=	-I$(SRC)/lib/libkmf/include
CPPFLAGS +=	-I$(SRC)/lib/libcryptoutil/common
LDFLAGS +=	-lmd -lelf -lkmf -lcryptoutil -lc

#
# While the gate builds a libelfsign.so linked staticly against
# pksc11_softtoken, the tools version of libelfsign is dynamically linked
# against the build machines pkcs11_softtoken.so.
#
SOFTTOKENDIR =	/usr/lib/security
SOFTTOKENLIB =	pkcs11_softtoken.so
LDFLAGS +=	-R $(SOFTTOKENDIR) $(SOFTTOKENDIR)/$(SOFTTOKENLIB)

MKDIR=	mkdir

.KEEP_STATE:

all:	$(PROG) $(SHFILES)

install: all .WAIT $(ROOTONBLDMACHPROG) $(ROOTONBLDSHFILES)

$(PROG):	$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o:	$(CMDDIR)/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(LIBDIR)/%.c
	$(COMPILE.c) -o $@ $<

lint:	lint_SRCS

clean:
	$(RM) $(CLEANFILES)

include ../../../src/tools/Makefile.targ
