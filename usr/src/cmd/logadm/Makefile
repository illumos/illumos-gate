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

PROG= logadm
TESTS= conftest globtest kwtest luttest optstest
OBJS= conf.o err.o fn.o glob.o kw.o lut.o main.o opts.o
TESTOBJS= $(TESTS:%=%.o)
SRCS= $(OBJS:%.o=%.c)
POFILES= $(OBJS:%.o=%.po)
CONFIGFILE= logadm.conf

include ../Makefile.cmd

CPPFLAGS += -D_FILE_OFFSET_BITS=64
XGETFLAGS += -a -x logadm.xcl

$(ROOTETC)/$(CONFIGFILE):= FILEMODE= 644

CLOBBERFILES += $(TESTS)

.KEEP_STATE:

all: $(PROG)

test: $(TESTS) $(PROG)
	./tester `pwd`

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG) $(ROOTETC)/$(CONFIGFILE)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

clean:
	$(RM) $(OBJS) $(TESTOBJS)

lint: lint_SRCS

include ../Makefile.targ

#
# dependencies for various test programs built from same source
#
%test.o: %.c
	$(COMPILE.c) -DTESTMODULE -o $@ $<
	$(POST_PROCESS_O)

conftest: conftest.o err.o fn.o lut.o opts.o
	$(LINK.c) -o conftest conftest.o err.o fn.o lut.o opts.o $(LDLIBS)
	$(POST_PROCESS)

globtest: globtest.o lut.o err.o fn.o
	$(LINK.c) -o globtest globtest.o lut.o err.o fn.o $(LDLIBS)
	$(POST_PROCESS)

kwtest: kwtest.o err.o fn.o lut.o
	$(LINK.c) -o kwtest kwtest.o err.o fn.o lut.o $(LDLIBS)
	$(POST_PROCESS)

luttest: luttest.o err.o
	$(LINK.c) -o luttest luttest.o err.o $(LDLIBS)
	$(POST_PROCESS)

optstest: optstest.o err.o fn.o lut.o
	$(LINK.c) -o optstest optstest.o err.o fn.o lut.o $(LDLIBS)
	$(POST_PROCESS)
