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
# Copyright 2025 Hans Rosenfeld
#

SCRIPTS = printf-intmax

PROG = printf-intmax

PROG32 = $(PROG:%=%.32)
PROG64 = $(PROG:%=%.64)
PROGC89 = $(PROG:%=%.c89)

OBJS = printf-intmax.o

OBJS32 = $(OBJS:%.o=%.32.o)
OBJS64 = $(OBJS:%.o=%.64.o)
OBJSC89 = $(OBJS:%.o=%.c89.o)

ROOTOPTDIR = $(ROOT)/opt/libc-tests/tests
ROOTOPTPROGS =	$(PROG32:%=$(ROOTOPTDIR)/%) \
		$(PROG64:%=$(ROOTOPTDIR)/%) \
		$(PROGC89:%=$(ROOTOPTDIR)/%)
ROOTOPTSCRIPTS = $(SCRIPTS:%=$(ROOTOPTDIR)/%)

$(ROOTOPTSCRIPTS) := FILEMODE = 0555

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

# We decidedly want to build the C89 test using the C89 standard, but for the
# other cases the only requirement is to have something newer than C89. We'll
# use C99 for being next newer C standard.
#
# For the lack of CSTD_C{8,9}9 we'll use GNU variants of these C standards,
# the difference shouldn't matter at all.
$(PROGC89) := CSTD = $(CSTD_GNU89)
CSTD = $(CSTD_GNU99)

.KEEP_STATE:

all: $(PROG32) $(PROG64) $(PROGC89)

install: $(ROOTOPTPROGS) $(ROOTOPTSCRIPTS) $(ROOTOPTDIR)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTDIR)/%: %
	$(INS.file)

$(ROOTOPTDIR)/%: %.ksh
	$(INS.rename)

%.c89.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.c89: $(OBJSC89)
	$(LINK.c) -o $@ $(OBJSC89) $(LDLIBS)
	$(POST_PROCESS)

%.32.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.32: $(OBJS32)
	$(LINK.c) -o $@ $(OBJS32) $(LDLIBS)
	$(POST_PROCESS)

%.64.o: %.c
	$(COMPILE64.c) -o $@ $<
	$(POST_PROCESS_O)

%.64: $(OBJS64)
	$(LINK64.c) -o $@ $(OBJS64) $(LDLIBS64)
	$(POST_PROCESS)

clean:
	-$(RM) $(OBJS32) $(OBJS64) $(OBJSC89)

clobber: clean
	-$(RM) $(PROG32) $(PROG64) $(PROGC89)


