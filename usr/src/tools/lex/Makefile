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
# Copyright 2024 MNX Cloud, Inc.
#

PROG =		lex

SGSDIR =	../../cmd/sgs
SRCDIR =	$(SGSDIR)/lex/common

OBJS =		main.o sub1.o sub2.o sub3.o header.o parser.o

include ../Makefile.tools

CPPFLAGS =	-I$(SGSDIR)/include
CSTD=		$(CSTD_GNU99)

# unused labels in yaccpar
CERRWARN +=	-_gnu=-Wno-unused-label

FORMS =		nceucform ncform nrform
ROOTFORMS =	$(FORMS:%=$(ROOTONBLDSHLIBCCS)/%)

.KEEP_STATE:

all:	$(PROG)

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o:	$(SRCDIR)/%.c
	$(COMPILE.c) -o $@ $<

install: all $(ROOTONBLDMACHPROG) $(ROOTFORMS)

clean:
	$(RM) $(PROG) $(OBJS)

$(ROOTONBLDSHLIBCCS)/%: $(SRCDIR)/%
	$(INS.file)

include	../Makefile.targ
