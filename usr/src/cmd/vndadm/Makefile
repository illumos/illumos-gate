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
# Copyright (c) 2018 Joyent, Inc.  All rights reserved.
#

PROG= vndadm
OBJS = vndadm.o
SRCS = $(OBJS:%.o=../%.c)


include ../Makefile.cmd
include ../Makefile.ctf

CLEANFILES += $(OBJS)
CFLAGS += $(CCVERBOSE)
LDLIBS += -lvnd
LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2
C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

all	:= TARGET += all
clean	:= TARGET += clean
clobber	:= TARGET += clobber
install	:= TARGET += install
lint	:= TARGET += lint

SUBDIRS = test

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean: $(SUBDIRS)
	-$(RM) $(CLEANFILES)

lint: lint_PROG $(SUBDIRS)

%.o: ../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

clobber: clean $(SUBDIRS)
	$(RM) $(PROG)

install: $(PROG) $(ROOTUSRSBINPROG) $(SUBDIRS)


$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
