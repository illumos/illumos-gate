#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.
# All rights reserved.  Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

FSTYPE=		nfs

TYPEPROG=	nfsmapid
TESTPROG=	nfsmapid_test
ATTMK=          $(TYPEPROG)

POFILE= nfsmapid.po

catalog: $(POFILE)

$(POFILE): $(SRCS)
	$(RM) $@
	$(COMPILE.cpp) $(SRCS)	> $(POFILE).i
	$(XGETTEXT) $(XGETFLAGS)	$(POFILE).i
	sed "/^domain/d"	messages.po     > $@
	$(RM) $(POFILE).i messages.po

include		../../Makefile.fstype

LDLIBS +=	-lresolv -lnsl -lcmd -lrt -ldtrace

SRCS=		nfsmapid.c nfsmapid_server.c nfsmapid_resolv.c
DSRC=		nfsmapid_dt.d
DOBJ=		$(DSRC:%.d=%.o)
HDRS+=		nfsmapid_resolv.h
OBJS=		$(SRCS:%.c=%.o)
CPPFLAGS +=	-I../lib -D_POSIX_PTHREAD_SEMANTICS

$(TYPEPROG):	$(OBJS) $(DSRC)
		$(COMPILE.d) -s $(DSRC) -o $(DOBJ) $(OBJS)
		$(LINK.c) -zignore -o $@ $(DOBJ) $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

$(OBJS):	$(HDRS)

#
# Test program
#
TESTSRCS=	nfsmapid_test.c
TESTOBJS=	$(TESTSRCS:%.c=%.o)
TEST_OBJS=	$(TESTOBJS)

$(TESTPROG):	$(TEST_OBJS)
		$(LINK.c) -o $@ $(TEST_OBJS) $(LDLIBS)
		$(POST_PROCESS)

all:		$(TYPEPROG) $(TESTPROG)

clean:
		$(RM) $(OBJS) $(TESTOBJS) $(DOBJ)

lint:		$(SRCS) lint_SRCS
