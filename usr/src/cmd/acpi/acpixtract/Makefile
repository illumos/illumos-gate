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
# Copyright 2016 Joyent, Inc.
# Copyright 2016 RackTop Systems.
#

PROG=		acpixtract

include ../../Makefile.cmd
include ../../Makefile.ctf

OBJS= axmain.o acpixtract.o axutils.o
SRCS = $(OBJS:.o=.c)

CERRWARN += -_gcc=-Wno-unused-function

CPPFLAGS += -I$(SRC)/uts/intel/sys/acpi -DACPI_XTRACT_APP

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) ../common/acpi.a $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../../Makefile.targ
