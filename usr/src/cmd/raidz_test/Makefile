#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2020 Joyent, Inc.
#

include ../Makefile.cmd
include ../Makefile.cmd.64

PROG= raidz_test
OBJS= raidz_test.o raidz_bench.o
SRCS= $(OBJS:%.o=%.c)
POFILES= $(PROG:%=%.po)

# No msg catalog here.
POFILE=

LDLIBS += -lzpool -lfakekernel -lumem

INCS += -I../../lib/libzpool/common
INCS += -I../../uts/common/fs/zfs

CPPFLAGS.first = -I$(SRC)/lib/libfakekernel/common -D_FAKE_KERNEL
CPPFLAGS += -D_LARGEFILE64_SOURCE=1
CPPFLAGS += $(INCS)

CSTD =   $(CSTD_GNU99)

CERRWARN += -_gcc=-Wno-type-limits

SMATCH=off

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

_msg: $(MSGDOMAIN) $(POFILES)
	$(CP) $(POFILES) $(MSGDOMAIN)

$(MSGDOMAIN):
	$(INS.dir)

include ../Makefile.targ
