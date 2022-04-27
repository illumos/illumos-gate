# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

#	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved

# Copyright (c) 1980 Regents of the University of California.
# All rights reserved.  The Berkeley Software License Agreement
# specifies the terms and conditions for redistribution.

#
# C Shell with process control; VM/UNIX VAX Makefile
# Bill Joy UC Berkeley; Jim Kulp IIASA, Austria
#

include ../Makefile.cmd

#
# For message catalogue files
#
POFILE= csh.po
CLOBBERFILES += sh.tconst.h
CLEANFILES += sh.tconst.h

all :=          TARGET = all
install :=      TARGET = install
clean :=        TARGET = clean
clobber :=      TARGET = clobber
lint :=         TARGET = lint

POBJS = \
sh.o sh.char.o \
sh.dir.o sh.dol.o sh.err.o sh.exec.o sh.exp.o\
sh.file.o sh.func.o sh.glob.o sh.hist.o\
sh.init.o sh.lex.o sh.misc.o sh.parse.o\
sh.print.o sh.proc.o sh.sem.o sh.set.o\
sh.tchar.o sh.time.o wait3.o printf.o

CPPFLAGS +=	-D_FILE_OFFSET_BITS=64
CPPFLAGS +=	-I ../sh

.KEEP_STATE:

all install clean clobber lint:	$(MACH)

POFILES= $(POBJS:%.o=%.po)

XGETFLAGS += -a -x csh.xcl

#
# For message catalogue files
#
_msg: $(MSGDOMAIN) sh.tconst.h .WAIT $(POFILE)
	$(RM) $(POFILE)
	$(CAT) $(POFILES) > $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(MSGDOMAIN):
	$(INS.dir)

$(POFILE):	$(POFILES)
	$(RM) $@; cat $(POFILES) > $@

sh.tconst.h: sh.tconst.c make.sh.tconst.h.ed
	$(RM) $@; $(ED) sh.tconst.c < make.sh.tconst.h.ed

clobber: local_clobber $(MACH)

local_clobber:
	$(RM) $(CLOBBERFILES)

clean: local_clean

local_clean:
	$(RM) $(CLEANFILES)

$(MACH): sh.tconst.h .WAIT FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
