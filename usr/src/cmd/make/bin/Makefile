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
POFILE=	make.po
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
POFILES= $(OBJS:%.o=%.po)

include ../../Makefile.cmd
include ../Makefile.com

LDLIBS += ../lib/mksh/libmksh.a ../lib/vroot/libvroot.a
LDLIBS += ../lib/bsd/libbsd.a -lc -lnsl -lumem

CPPFLAGS += -D_FILE_OFFSET_BITS=64

ROOTLINKS = $(ROOTCCSBIN)/make $(ROOTXPG4BIN)/make $(ROOTBIN)/dmake $(ROOTCCSLIB)/svr4.make \
	$(ROOTLIB)/svr4.make

ROOTRULES = $(ROOTSHLIB)/make/make.rules $(ROOTSHLIB)/make/svr4.make.rules

all:	$(PROG)

install: all $(ROOTPROG) $(ROOTLINKS) $(ROOTRULES)

$(PROG):	$(OBJS)
	$(LINK.cc) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(ROOTCCSBIN)/make:
	-$(RM) $@; $(SYMLINK) ../../bin/make $@

$(ROOTCCSLIB)/svr4.make:
	-$(RM) $@; $(SYMLINK) ../../bin/make $@

$(ROOTLIB)/svr4.make:
	-$(RM) $@; $(SYMLINK) ../bin/make $@

$(ROOTXPG4BIN)/make:
	-$(RM) $@; $(SYMLINK) ../../bin/make $@

$(ROOTBIN)/dmake:
	-$(RM) $@; $(SYMLINK) ./make $@

$(ROOTRULES) := FILEMODE = 0444

$(ROOTRULES): $(ROOTSHLIB)/make

$(ROOTSHLIB)/make: FRC
	$(INS.dir)

$(ROOTSHLIB)/make/%: %.file
	$(INS.rename)

lint:

clean:
	$(RM) $(OBJS)

FRC:

include ../../Makefile.targ

