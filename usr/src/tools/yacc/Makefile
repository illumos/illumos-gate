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
# Copyright 2024 Toomas Soome <tsoome@me.com>
#

PROG =		yacc

SGSDIR =	../../cmd/sgs
SRCDIR =	$(SGSDIR)/yacc/common

OBJS =		y1.o y2.o y3.o y4.o

include ../Makefile.tools

CPPFLAGS =	-I$(SGSDIR)/include

.KEEP_STATE:

all:	$(PROG)

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o:	$(SRCDIR)/%.c
	$(COMPILE.c) -o $@ $<

install: all $(ROOTONBLDMACHPROG) $(ROOTONBLDLIB)/yaccpar

$(ROOTONBLDLIB)/%: $(SGSDIR)/yacc/common/%
	$(INS.file)

clean:
	$(RM) $(PROG) $(OBJS)

include	../Makefile.targ
