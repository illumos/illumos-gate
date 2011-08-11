#
# Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2011 Nexenta Systems, Inc. All rights reserved.
#

PROG=		pppdump
OBJS=		bsd-comp.o deflate.o pppdump.o zlib.o
SRCS=		$(OBJS:%.o=%.c)

include		../../../Makefile.cmd

CPPFLAGS +=	-DPPP_DEFS_IN_NET

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

install:	 all $(ROOTPROG)

clean:
		$(RM) $(OBJS)

lint:

include		../../../Makefile.targ
