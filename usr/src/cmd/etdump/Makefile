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
# Copyright (c) 2019, Joyent, Inc.
#

PROG=	etdump
OBJS=	etdump.o output_shell.o output_text.o
SRCS=	$(OBJS:%.o=%.c)

include ../Makefile.cmd

# comes from FreeBSD upstream
SMOFF += all_func_returns

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

lint:

include ../Makefile.targ
