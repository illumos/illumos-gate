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
# Copyright 2019 Toomas Soome <tsoome@me.com>
#
# Copyright (c) 2018, Joyent, Inc.

include		../Makefile.tools

SOFTCORE=	$(SRC)/common/ficl/softcore
LZ4=		$(SRC)/common/lz4
PROG=		makesoftcore

CSTD=		$(CSTD_GNU99)
CPPFLAGS +=	-I$(SRC)/lib/libficl -I$(SRC)/common/ficl -I$(LZ4)
CPPFLAGS +=	-I../../uts/common
OBJS=		makesoftcore.o lz4.o
SRCS=		makesoftcore.c $(LZ4)/lz4.c
LDLIBS=		-lumem

# not linted
SMOFF += all_func_returns

.KEEP_STATE:

all:		$(PROG)

install:	all .WAIT $(ROOTONBLDMACHPROG)

clean:
		$(RM) $(PROG) $(OBJS)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

%.o:		$(SOFTCORE)/%.c
		$(COMPILE.c) -o $@ $<

%.o:		$(LZ4)/%.c
		$(COMPILE.c) -o $@ $<

include		../Makefile.targ
