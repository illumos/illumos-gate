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
# Copyright (c) 2018, Joyent, Inc.
#

PROG	= cpcgen
OBJS	= cpcgen.o json_nvlist.o custr.o

include ../Makefile.tools

LDLIBS	+= -lnvpair
CPPFLAGS += -I$(SRC)/lib/json_nvlist/

all: $(PROG)

install: all .WAIT $(ROOTONBLDMACHPROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<

%.o: $(SRC)/lib/json_nvlist/%.c
	$(COMPILE.c) $<

%.o: $(SRC)/lib/libcustr/common/%.c
	$(COMPILE.c) $<

clean:
	$(RM) $(OBJS)

include ../Makefile.targ
