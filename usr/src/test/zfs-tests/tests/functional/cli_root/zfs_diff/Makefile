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
# Copyright 2019 Joyent, Inc.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/zfs-tests
TARGETDIR = $(ROOTOPTPKG)/tests/functional/cli_root/zfs_diff

PROG = socket
OBJS = $(PROG:%=%.o)
SRCS = $(OBJS:%.o=%.c)

include $(SRC)/cmd/Makefile.cmd

$(TARGETDIR)/$(PROG) :=	FILEMODE = 0555

CPPFLAGS = -D__EXTENSIONS__
LDLIBS += -lsocket

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: $(TARGETDIR)/$(PROG)

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) $(OBJS)

$(TARGETDIR)/$(PROG): $(TARGETDIR)

include $(SRC)/test/zfs-tests/Makefile.com
