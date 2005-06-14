# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

#	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved

# Copyright (c) 1980 Regents of the University of California.
# All rights reserved.  The Berkeley Software License Agreement
# specifies the terms and conditions for redistribution.

# ident	"%Z%%M%	%I%	%E% SMI"

#
# C Shell with process control; VM/UNIX VAX Makefile
# Bill Joy UC Berkeley; Jim Kulp IIASA, Austria
#

include ../Makefile.cmd

ED= ed
#
# For message catalogue files
#
GREP= egrep
SED= sed
POFILE= csh.po
CLOBBERFILES += sh.tconst.h

all :=          TARGET = all
install :=      TARGET = install
clean :=        TARGET = clean
clobber :=      TARGET = clobber
lint :=         TARGET = lint

PFOBJS = sh_policy.o

POBJS = \
sh.o sh.char.o sh.debug.o\
sh.dir.o sh.dol.o sh.err.o sh.exec.o sh.exp.o\
sh.file.o sh.func.o sh.glob.o sh.hist.o\
sh.init.o sh.lex.o sh.misc.o sh.parse.o\
sh.print.o sh.proc.o sh.sem.o sh.set.o\
sh.tchar.o sh.time.o stubs.o wait3.o printf.o

CPPFLAGS +=	-D_FILE_OFFSET_BITS=64
CPPFLAGS +=	-I ../sh

.KEEP_STATE:

all install clean clobber lint:	$(MACH)

PFPOFILES= $(PFOBJS:%.o=%.po)

POFILES= \
sh.po sh.char.po sh.debug.po\
sh.dir.po sh.dol.po sh.err.po sh.exec.po sh.exp.po\
sh.file.po sh.func.po sh.glob.po sh.hist.po\
sh.init.po sh.lex.po sh.misc.po sh.parse.po\
sh.print.po sh.proc.po sh.sem.po sh.set.po\
sh.tchar.po sh.time.po stubs.po wait3.po\
$(PFPOFILES)

XGETFLAGS= -a -x csh.xcl


#
# For message catalogue files
#
_msg: $(MSGDOMAIN) sh.tconst.h .WAIT $(POFILE)
	$(RM) $(POFILE)
	cat $(POFILES) > $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)


$(POFILE):	$(POFILES)
	$(RM) $@; cat $(POFILES) > $@

# based on .c.po, BUILD.po from Makefile.master
%.po:	../sh/%.c
	$(COMPILE.cpp) $<  > $(<F).i
	$(XGETTEXT) $(XGETFLAGS) $(<F).i ;\
	$(RM)   $@ ;\
	sed "/^domain/d" < messages.po  > $@ ;\
	$(RM) messages.po $(<F).i

$(PROG):	$$(POBJS)
		$(LINK.c) $(POBJS) -o $@

sh.tconst.h:
	$(RM) $@; $(ED) sh.tconst.c < make.sh.tconst.h.ed

clobber: local_clobber $(MACH)

local_clobber:
	$(RM) $(CLOBBERFILES)

$(MACH): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
