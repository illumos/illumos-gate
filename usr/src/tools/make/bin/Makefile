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

# Copyright 2015, Richard Lowe.

PROG=	make
CMDDIR=	$(SRC)/cmd/make/bin
OBJS=	ar.o		\
	depvar.o	\
	doname.o	\
	dosys.o		\
	files.o		\
	globals.o	\
	implicit.o	\
	macro.o		\
	main.o		\
	misc.o		\
	nse_printdep.o	\
	parallel.o	\
	pmake.o		\
	read.o		\
	read2.o		\
	rep.o		\
	state.o
SRCS=$(OBJS:%.o:$(CMDDIR)/%.cc)

include ../../Makefile.tools
include ../Makefile.com

LDLIBS += ../lib/mksh/libmksh.a ../lib/vroot/libvroot.a
LDLIBS += ../lib/bsd/libbsd.a -lc -lnsl -lumem

CPPFLAGS += -D_FILE_OFFSET_BITS=64

ROOTLINKS = $(ROOTONBLDBINMACH)/dmake
ROOTRULES = $(ROOTONBLDSHARE)/make.rules

all:	$(PROG)

install: all $(ROOTONBLDMACHPROG) $(ROOTLINKS) $(ROOTRULES)

$(PROG):	$(OBJS)
	$(LINK.cc) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o:	$(CMDDIR)/%.cc
	$(COMPILE.cc) -o $@ $<

$(ROOTONBLDBINMACH)/dmake:
	-$(RM) $@; $(SYMLINK) ./make $@

$(ROOTRULES) := FILEMODE = 0444

$(ROOTONBLDSHARE)/%: $(CMDDIR)/%.file
	$(INS.rename)


lint:

clean:
	$(RM) $(OBJS)

include $(SRC)/tools/Makefile.targ

