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
# Copyright 2022 Jason King
#

PROG = find_elf
MAN1ONBLDFILES = find_elf.1onbld

#
# Since libcustr is private, we just build and link in the code directly
# into the binary. If more build utilities require it in the future, we
# can transition to building a tools version of the library and link
# against it.
CUSTRDIR = $(SRC)/lib/libcustr/common

OBJS = find_elf.o custr.o

include $(SRC)/tools/Makefile.tools
include $(SRC)/cmd/Makefile.ctf

$(ROOTONBLDMAN1ONBLDFILES) := FILEMODE=	644

LDLIBS = -lelf -lavl
NATIVE_LIBS += libelf.so libc.so libavl.so

CPPFLAGS += -I$(CUSTRDIR)
LDFLAGS = \
	-L$(ROOTONBLDLIBMACH) \
	'-R$$ORIGIN/../../lib/$(MACH)' \
	$(BDIRECT) $(ZLAZYLOAD)

CSTD = $(CSTD_GNU99)

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:	$(PROG)

install: all .WAIT $(ROOTONBLDMACHPROG) $(ROOTONBLDDATAFILES) \
	$(ROOTONBLDMAN1ONBLDFILES)

clean:
	$(RM) -f $(OBJS)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o: $(CUSTRDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/tools/Makefile.targ
