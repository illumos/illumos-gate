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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

FSTYPE	  =	nfs
TYPEPROG  =	nfsmapid
TESTPROG  =	nfsmapid_test
ATTMK	  =	$(TYPEPROG)

include		../../Makefile.fstype

LDLIBS   +=	-L$(ROOT)/usr/lib/nfs -R/usr/lib/nfs
LDLIBS   +=	-lnsl -lmapid -ldoor -ldtrace -lidmap
SRCS	  =	nfsmapid.c nfsmapid_server.c
DSRC	  =	nfsmapid_dt.d
DOBJ	  =	$(DSRC:%.d=%.o)
OBJS	  =	$(SRCS:%.c=%.o)
CPPFLAGS +=	-I../lib -D_POSIX_PTHREAD_SEMANTICS

all:		$(TYPEPROG) $(TESTPROG)

$(TYPEPROG):	$(OBJS) $(DSRC)
		$(COMPILE.d) -s $(DSRC) -o $(DOBJ) $(OBJS)
		$(LINK.c) $(ZIGNORE) -o $@ $(DOBJ) $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

TESTSRCS  =	nfsmapid_test.c
TESTOBJS  =	$(TESTSRCS:%.c=%.o)
TEST_OBJS =	$(TESTOBJS)

$(TESTPROG):	$(TEST_OBJS)
		$(LINK.c) -o $@ $(TEST_OBJS) $(LDLIBS)
		$(POST_PROCESS)

POFILE	  =	nfsmapid.po
catalog:	$(POFILE)

$(POFILE):	$(SRCS)
		$(RM) $@
		$(COMPILE.cpp) $(SRCS) > $@.i
		$(XGETTEXT) $(XGETFLAGS) $@.i
		sed "/^domain/d" messages.po > $@
		$(RM) $@.i messages.po

clean:
		$(RM) $(OBJS) $(TESTPROG) $(TESTOBJS) $(DOBJ) $(POFILE)

lint:		$(SRCS) lint_SRCS
