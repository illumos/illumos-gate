#
# Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2011 Nexenta Systems, Inc. All rights reserved.
# Copyright (c) 2018, Joyent, Inc.
#

PROG=		pppdump
OBJS=		bsd-comp.o deflate.o pppdump.o zlib.o
SRCS=		$(OBJS:%.o=%.c)

include		../../../Makefile.cmd

CPPFLAGS +=	-DPPP_DEFS_IN_NET

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	$(CNOWARN_UNINIT)

# not linted
SMATCH=off

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
