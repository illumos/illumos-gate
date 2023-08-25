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
# Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
#

PROGS=		pcom acom dcom tpcom dispsyms
LDLIBS=		-lelf

OBJS=	$(PROGS:%=%.o)

.KEEP_STATE:

all:	libobj.a .WAIT $(PROGS)

libobj.a: $(OBJS)
	ar -r $@ $(OBJS)

%.o:	%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<
	mcs -d -a "ELF demo: object comment: $@" $@

%:	%.o
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)
	mcs -d -a "ELF demo: executable comment: $@" $@

test: test1 test2 test3 test4 test5 test6

test1: pcom FRC
	@ echo ""
	@ echo "<<< Test 1 >>>"
	@ echo "Print comments of pcom"
	pcom pcom
	@ echo
	@ echo "Print comments from archive libobj.a"
	pcom libobj.a

test2: dcom pcom FRC
	@ echo ""
	@ echo "<<< Test 2 >>>"
	@ echo "Delete the comment section from pcom"
	TMPDIR= dcom pcom
	pcom pcom

test3: pcom acom test2 FRC
	@ echo ""
	@ echo "<<< Test 3 >>>"
	@ echo "update comments from pcom and then print them out."
	acom "Newly Updated Comments" pcom
	pcom pcom

test4: acom pcom test3 FRC
	@ echo ""
	@ echo "<<< Test 4 >>>"
	@ echo "Append to the comment section of pcom."
	acom "This comment has been appended" pcom
	pcom pcom

test5: $(PROGS) FRC
	@ echo ""
	@ echo "<<< Test 5 >>>"
	@ echo "Relabel the new utilities using the new utilities."
	TMPDIR= dcom $(PROGS)
	cp acom acom.safe
	acom.safe "libelf Demonstration Tools" $(PROGS)
	pcom $(PROGS)
	$(RM) acom.safe

test6: dispsyms FRC
	@ echo ""
	@ echo "<<< Test 6 >>>"
	@ echo "Display symbols in dispsyms itself."
	dispsyms dispsyms | egrep -v "LOCL|ABS|SECT|UNDEF"

test-extra: tpcom FRC
	@ echo ""
	@ echo "<<< Test-extra >>>"
	@ echo "Using the threaded tpcom, go through and examine all"
	@ echo "libraries in /lib.  This is an output intensive test."
	tpcom /lib/lib*.so.?

clean: FRC
	$(RM) $(OBJS) $(PROGS) libobj.a core

FRC:
