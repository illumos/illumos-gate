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

include $(SRC)/Makefile.master
include ../Makefile.com

fasttrap/tst.fasttrap.exe := LDLIBS += -ldtrace
fasttrap/tst.stack.exe := LDLIBS += -ldtrace

proc/tst.sigwait.exe := LDLIBS += -lrt

sysevent/tst.post.exe := LDLIBS += -lsysevent
sysevent/tst.post_chan.exe := LDLIBS += -lsysevent

ustack/tst.bigstack.exe := COPTFLAG += -xO1

GCC = $(ONBLD_TOOLS)/bin/$(MACH)/cw -_gcc

pid/tst.gcc.exe: pid/tst.gcc.c
	$(GCC) -o pid/tst.gcc.exe pid/tst.gcc.c $(LDFLAGS)
	$(POST_PROCESS) ; $(STRIP_STABS)

usdt/tst.args.exe: usdt/tst.args.o usdt/args.o
	$(LINK.c) -o usdt/tst.args.exe usdt/tst.args.o usdt/args.o $(LDLIBS)
	$(POST_PROCESS) ; $(STRIP_STABS)

usdt/args.o: usdt/args.d usdt/tst.args.o
	$(COMPILE.d) -o usdt/args.o -s usdt/args.d usdt/tst.args.o

usdt/tst.argmap.exe: usdt/tst.argmap.o usdt/argmap.o
	$(LINK.c) -o usdt/tst.argmap.exe usdt/tst.argmap.o usdt/argmap.o \
		$(LDLIBS)
	$(POST_PROCESS) ; $(STRIP_STABS)

usdt/argmap.o: usdt/argmap.d usdt/tst.argmap.o
	$(COMPILE.d) -o usdt/argmap.o -s usdt/argmap.d usdt/tst.argmap.o

SUBDIRS = java_api
include ../../Makefile.subdirs
