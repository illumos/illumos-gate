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
#

PROG= varpd
OBJS = varpd.o
SRCS = $(OBJS:%.o=../%.c)
SVCMETHOD = svc-varpd
MANIFEST = varpd.xml
ROOTLIBVARPD = $(ROOTLIB)/varpd
ROOTLIBVARPDPROG=	$(PROG:%=$(ROOTLIBVARPD)/%)


include ../Makefile.cmd
include ../Makefile.ctf

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)

CLEANFILES += $(OBJS)
CPPFLAGS += -D_REENTRANT
CFLAGS += $(CCVERBOSE)
LDLIBS += -lvarpd -lumem -lscf
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

#
# Our debug only umem related functions cause lint to get confused.
#
LINTFLAGS += -erroff=E_NAME_DEF_NOT_USED2

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	-$(RM) $(CLEANFILES)

lint: lint_PROG

%.o: ../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

check: $(CHKMANIFEST)

clobber: clean
	$(RM) $(PROG)

install: $(PROG) $(ROOTLIBVARPDPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

$(ROOTLIBVARPD):
	$(INS.dir)

$(ROOTLIBVARPD)/%: % $(ROOTLIBVARPD)
	$(INS.file)

FRC:

include ../Makefile.targ
