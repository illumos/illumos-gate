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
#ident	"%Z%%M%	%I%	%E% SMI"

include ../Makefile.com

fasttrap/tst.fasttrap.exe := LIBS += -ldtrace
fasttrap/tst.stack.exe := LIBS += -ldtrace

proc/tst.sigwait.exe := LIBS += -lrt

GCC = /usr/sfw/bin/gcc
GCCFLAGS_sparc = -mcpu=ultrasparc
GCCFLAGS = $(GCCFLAGS_$(MACH))

pid/tst.gcc.exe: pid/tst.gcc.c
	$(GCC) $(GCCFLAGS) -o pid/tst.gcc.exe pid/tst.gcc.c

usdt/tst.args.exe: usdt/tst.args.o usdt/args.o
	$(CC) -o usdt/tst.args.exe usdt/tst.args.o usdt/args.o

usdt/args.o: usdt/args.d usdt/tst.args.o
	/usr/sbin/dtrace -G -32 -o usdt/args.o -s usdt/args.d usdt/tst.args.o

usdt/tst.argmap.exe: usdt/tst.argmap.o usdt/argmap.o
	$(CC) -o usdt/tst.argmap.exe usdt/tst.argmap.o usdt/argmap.o

usdt/argmap.o: usdt/argmap.d usdt/tst.argmap.o
	/usr/sbin/dtrace -G -32 -o usdt/argmap.o -s usdt/argmap.d \
		usdt/tst.argmap.o
