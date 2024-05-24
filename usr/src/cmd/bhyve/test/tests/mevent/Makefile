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
# Copyright 2018 Joyent, Inc.
# Copyright 2022 Oxide Computer Company
# Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
#

TESTSUBDIR =	mevent
PROG = \
		lists_delete \
		mevent_test \
		read_disable \
		read_pause \
		read_requeue \
		vnode_file \
		vnode_zvol

SUPOBJS =	mevent.o testlib.o

include ../../Makefile.com

CMDS =		$(PROG:%=$(TESTDIR)/%)
$(CMDS) :=	FILEMODE = 0555

all: $(PROG)

install: $(TESTDIR) $(CMDS)

$(CMDS): $(PROG)

vnode_zvol :=	LDLIBS += -lzfs -lnvpair
mevent_test :=	LDLIBS += -lsocket

include ../../Makefile.targ

%: %.o $(SUPOBJS)
	$(LINK.c) -o $@ $< $(SUPOBJS) $(LDLIBS)
	$(POST_PROCESS)

mevent.o: ../../../common/mevent.c
