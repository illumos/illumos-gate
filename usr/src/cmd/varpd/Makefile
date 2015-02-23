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

CSTD=		$(CSTD_GNU99)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	-$(RM) $(CLEANFILES)

%.o: ../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

check: $(CHKMANIFEST)

install: $(PROG) $(ROOTLIBVARPDPROG) $(ROOTMANIFEST)

$(ROOTLIBVARPD):
	$(INS.dir)

$(ROOTLIBVARPD)/%: % $(ROOTLIBVARPD)
	$(INS.file)

FRC:

include ../Makefile.targ
