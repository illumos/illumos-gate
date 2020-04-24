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

include $(SRC)/Makefile.master

PROG = sysevent

SCRIPTS = cleanup \
	resilver_restart_001 \
	setup

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

ROOTOPTPKG = $(ROOT)/opt/zfs-tests
TARGETDIR = $(ROOTOPTPKG)/tests/functional/resilver

OBJS = $(PROG:%=%.o)
SRCS = $(OBJS:%.o=%.c)
SRCFILES = resilver.cfg

CMDS = $(PROG:%=$(TARGETDIR)/%) $(SCRIPTS:%=$(TARGETDIR)/%)
$(CMDS) := FILEMODE = 0555

FILES = $(SRCFILES:%=$(TARGETDIR)/%)
$(FILES) := FILEMODE = 0444

CPPFLAGS += -D__EXTENSIONS__
LDLIBS += -lsysevent

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<

install: all $(CMDS) $(FILES)

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) $(OBJS)

$(CMDS): $(TARGETDIR) $(PROG)

$(FILES): $(SRCFILES)

$(TARGETDIR):
	$(INS.dir)

$(TARGETDIR)/%: %
	$(INS.file)

$(TARGETDIR)/%: %.ksh
	$(INS.rename)
