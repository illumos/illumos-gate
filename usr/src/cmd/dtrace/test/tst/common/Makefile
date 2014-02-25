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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright (c) 2013, Joyent, Inc. All rights reserved.
#

#
# WARNING: Do not include Makefile.ctf here. That will cause tests to
# break.
#

include $(SRC)/Makefile.master
include ../Makefile.com

SNOOPDIR = $(SRC)/cmd/cmd-inet/usr.sbin/snoop
SNOOPOBJS = nfs4_xdr.o
SNOOPSRCS = ${SNOOPOBJS:%.o=%.c}
CLOBBERFILES += nfs/$(SNOOPOBJS)

RPCSVCDIR = $(SRC)/head/rpcsvc
RPCSVCOBJS = nfs_prot.o
RPCSVCSRCS = ${RPCSVCOBJS:%o=%c}
CLOBBERFILES += nfs/$(RPCSVCOBJS) $(RPCSVCDIR)/$(RPCSVCSRCS)
CLOBBERFILES += usdt/forker.h usdt/lazyprobe.h

fasttrap/tst.fasttrap.exe := LDLIBS += -ldtrace
fasttrap/tst.stack.exe := LDLIBS += -ldtrace

sysevent/tst.post.exe := LDLIBS += -lsysevent
sysevent/tst.post_chan.exe := LDLIBS += -lsysevent

ustack/tst.bigstack.exe := COPTFLAG += -xO1

GCC = $(ONBLD_TOOLS)/bin/$(MACH)/cw -_gcc

nfs/%.o: $(SNOOPDIR)/%.c
	$(COMPILE.c) -o $@ $< -I$(SNOOPDIR)
	$(POST_PROCESS_O)
nfs/tst.call.exe: nfs/tst.call.o nfs/$(SNOOPOBJS)
	$(LINK.c) -o $@ nfs/tst.call.o nfs/$(SNOOPOBJS) $(LDLIBS) -lnsl
	$(POST_PROCESS) ; $(STRIP_STABS)
$(RPCSVCDIR)/%.c: $(RPCSVCDIR)/%.x
	$(RPCGEN) -Cc $< > $@
nfs/$(RPCSVCOBJS): $(RPCSVCDIR)/$(RPCSVCSRCS)
	$(COMPILE.c) -o $@ $(RPCSVCDIR)/$(RPCSVCSRCS)
	$(POST_PROCESS_O)
nfs/tst.call3.exe: nfs/tst.call3.o nfs/$(RPCSVCOBJS)
	$(LINK.c) -o $@ nfs/tst.call3.o nfs/$(RPCSVCOBJS) \
	$(LDLIBS) -lnsl -lrpcsvc
	$(POST_PROCESS) ; $(STRIP_STABS)

pid/tst.gcc.exe: pid/tst.gcc.c
	$(GCC) -o pid/tst.gcc.exe pid/tst.gcc.c $(LDFLAGS)
	$(POST_PROCESS) ; $(STRIP_STABS)

json/tst.usdt.o: json/usdt.h

json/usdt.h: json/usdt.d
	$(DTRACE) -h -s json/usdt.d -o json/usdt.h

json/usdt.o: json/usdt.d json/tst.usdt.o
	$(COMPILE.d) -o json/usdt.o -s json/usdt.d json/tst.usdt.o

json/tst.usdt.exe: json/tst.usdt.o json/usdt.o
	$(LINK.c) -o json/tst.usdt.exe json/tst.usdt.o json/usdt.o $(LDLIBS)
	$(POST_PROCESS) ; $(STRIP_STABS)

#
# Tests that use the next three programs rely on the binaries having
# valid CTF data.
#
uctf/tst.aouttype.exe: uctf/tst.aouttype.c
	$(COMPILE.c) $(CTF_FLAGS) -o uctf/tst.aouttype.o uctf/tst.aouttype.c
	$(CTFCONVERT) -i -L VERSION uctf/tst.aouttype.o
	$(LINK.c) -o uctf/tst.aouttype.exe uctf/tst.aouttype.o $(LDLIBS)
	$(CTFMERGE) -L VERSION -o $@ uctf/tst.aouttype.o
	$(POST_PROCESS) ; $(STRIP_STABS)

uctf/tst.chasestrings.exe: uctf/tst.chasestrings.c
	$(COMPILE.c) $(CTF_FLAGS) -o uctf/tst.chasestrings.o uctf/tst.chasestrings.c
	$(CTFCONVERT) -i -L VERSION uctf/tst.chasestrings.o
	$(LINK.c) -o uctf/tst.chasestrings.exe uctf/tst.chasestrings.o $(LDLIBS)
	$(CTFMERGE) -L VERSION -o $@ uctf/tst.chasestrings.o
	$(POST_PROCESS) ; $(STRIP_STABS)

uctf/tst.printtype.exe: uctf/tst.printtype.c
	$(COMPILE.c) $(CTF_FLAGS) -o uctf/tst.printtype.o uctf/tst.printtype.c
	$(CTFCONVERT) -i -L VERSION uctf/tst.printtype.o
	$(LINK.c) -o uctf/tst.printtype.exe uctf/tst.printtype.o $(LDLIBS)
	$(CTFMERGE) -L VERSION -o $@ uctf/tst.printtype.o
	$(POST_PROCESS) ; $(STRIP_STABS)

#
# This program should never have any ctf data in it.
#
uctf/tst.libtype.exe:
	$(LINK.c) -o uctf/tst.libtype.exe uctf/tst.libtype.c $(LDLIBS)
	$(POST_PROCESS) ; $(STRIP_STABS)

usdt/tst.args.exe: usdt/tst.args.o usdt/args.o
	$(LINK.c) -o usdt/tst.args.exe usdt/tst.args.o usdt/args.o $(LDLIBS)
	$(POST_PROCESS) ; $(STRIP_STABS)

usdt/args.o: usdt/args.d usdt/tst.args.o
	$(COMPILE.d) -o usdt/args.o -s usdt/args.d usdt/tst.args.o

usdt/tst.argmap.exe: usdt/tst.argmap.o usdt/argmap.o
	$(LINK.c) -o usdt/tst.argmap.exe \
	    usdt/tst.argmap.o usdt/argmap.o $(LDLIBS)
	$(POST_PROCESS) ; $(STRIP_STABS)

usdt/argmap.o: usdt/argmap.d usdt/tst.argmap.o
	$(COMPILE.d) -o usdt/argmap.o -s usdt/argmap.d usdt/tst.argmap.o

usdt/tst.forker.exe: usdt/tst.forker.o usdt/forker.o
	$(LINK.c) -o usdt/tst.forker.exe \
	    usdt/tst.forker.o usdt/forker.o $(LDLIBS)
	$(POST_PROCESS) ; $(STRIP_STABS)

usdt/forker.o: usdt/forker.d usdt/tst.forker.o
	$(COMPILE.d) -o usdt/forker.o -s usdt/forker.d usdt/tst.forker.o

usdt/tst.forker.o: usdt/forker.h

usdt/forker.h: usdt/forker.d
	$(DTRACE) -h -s usdt/forker.d -o usdt/forker.h

usdt/tst.lazyprobe.exe: usdt/tst.lazyprobe.o usdt/lazyprobe.o
	$(LINK.c) -o usdt/tst.lazyprobe.exe \
	    usdt/tst.lazyprobe.o usdt/lazyprobe.o $(LDLIBS)
	$(POST_PROCESS) ; $(STRIP_STABS)

usdt/lazyprobe.o: usdt/lazyprobe.d usdt/tst.lazyprobe.o
	$(COMPILE.d) -xlazyload -o usdt/lazyprobe.o \
	    -s usdt/lazyprobe.d usdt/tst.lazyprobe.o

usdt/tst.lazyprobe.o: usdt/lazyprobe.h

usdt/lazyprobe.h: usdt/lazyprobe.d
	$(DTRACE) -h -s usdt/lazyprobe.d -o usdt/lazyprobe.h

SUBDIRS = java_api
include ../../Makefile.subdirs
