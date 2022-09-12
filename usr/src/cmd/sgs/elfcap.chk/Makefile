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
# Copyright 2022 Oxide Computer Company
#

PROG	= elfcap.chk
OBJS	= elfcap_chk.o elfcap.o

include	$(SRC)/Makefile.master
include	$(SRC)/Makefile.master.64
include ../Makefile.com

CSTD =		$(GNU_C99)
NATIVE_LIBS +=	libc.so
CPPFLAGS =	$(CPPFLAGS.native)
CFLAGS =	$(NATIVE_CFLAGS)
CC =		$(NATIVECC)
LDCHECKS =

CPPFLAGS += -I$(ELFCAP)

all: $(PROG)

install:

check: $(PROG)
	./$(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<

%.o: $(ELFCAP)/%.c
	$(COMPILE.c) $<

clean:
	$(RM) $(OBJS)

clobber: clean
	$(RM) $(PROG)
