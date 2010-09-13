#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
#
# Copyright (c) 1994  
# Open Software Foundation, Inc. 
#  
# Permission is hereby granted to use, copy, modify and freely distribute 
# the software in this file and its documentation for any purpose without 
# fee, provided that the above copyright notice appears in all copies and 
# that both the copyright notice and this permission notice appear in 
# supporting documentation.  Further, provided that the name of Open 
# Software Foundation, Inc. ("OSF") not be used in advertising or 
# publicity pertaining to distribution of the software without prior 
# written permission from OSF.  OSF makes no representations about the 
# suitability of this software for any purpose.  It is provided "as is" 
# without express or implied warranty. 
#
#
# Copyright (c) 1995
# Dalrymple Consulting
#
#
#  $Header: /usr/src/docbook-to-man/Instant/tptregexp/RCS/Makefile,v 1.2 1996/06/15 22:55:56 fld Exp $
#
include ../../../../../Makefile.cmd

ROOT	= /usr/lib/sgml

MAKE	= make
SHELL	= /bin/sh

LIBDIR	= $(ROOT)/lib
#CC	= gcc

# Things you might want to put in ENV and LENV:
# -Dvoid=int		compilers that don't do void
# -DCHARBITS=0377	compilers that don't do unsigned char
# -DSTATIC=extern	compilers that don't like "static foo();" as forward decl
# -DSTRCSPN		library does not have strcspn()
# -Dstrchr=index	library does not have strchr()
# -DERRAVAIL		have utzoo-compatible error() function and friends
#ENV=-Dvoid=int -DCHARBITS=0377 -DSTATIC=extern
#LENV=-Dvoid=int -DCHARBITS=0377

# Things you might want to put in TEST:
# -DDEBUG		debugging hooks
# -I.			tptregexp.h from current directory, not /usr/include
TEST=	-I.

# Things you might want to put in PROF:
# -Dstatic='/* */'	make everything global so profiler can see it.
# -p			profiler
PROF=

OPT=

CFLAGS += $(OPT) $(ENV) $(TEST) $(PROF)
LINTFLAGS = $(LENV) $(TEST) -ha
LDFLAGS =

OBJ=regexp.o regsub.o regerror.o strerror.o
LSRC=regexp.c regsub.c regerror.c strerror.c
DTR=README dMakefile regexp.3 tptregexp.h regexp.c regsub.c regerror.c \
	regmagic.h try.c timer.c tests

all: libtptregexp.a
install: libtptregexp.a
#	@echo "No install of regex lib - install in a lib directory by hand if desired."
	cp libtptregexp.a $(LIBDIR)

try:	try.o $(OBJ)
	$(CC) $(LDFLAGS) try.o $(OBJ) -o try

# Making timer will probably require putting stuff in $(PROF) and then
# recompiling everything; the following is just the final stage.
timer:	timer.o $(OBJ)
	$(CC) $(LDFLAGS) $(PROF) timer.o $(OBJ) -o timer

timer.o:	timer.c timer.t.h

timer.t.h:	tests
	sed 's/	/","/g;s/\\/&&/g;s/.*/{"&"},/' tests >timer.t.h

# Regression test.
r:	try tests
	@echo 'No news is good news...'
	try <tests

lint:	timer.t.h
	@echo 'Complaints about multiply-declared regerror() are legit.'
	lint $(LINTFLAGS) $(LSRC) try.c
	lint $(LINTFLAGS) $(LSRC) timer.c

regexp.o:	regexp.c tptregexp.h regmagic.h
regsub.o:	regsub.c tptregexp.h regmagic.h

clean:
	rm -f *.o core mon.out timer.t.h dMakefile dtr try timer

clobber:	clean
	rm -f libtptregexp.a

dtr:	r makedtr $(DTR)
	makedtr $(DTR) >dtr

dMakefile:	Makefile
	sed '/^L*ENV=/s/ *-DERRAVAIL//' Makefile >dMakefile


lib:	libtptregexp.a
libtptregexp.a: $(OBJ)
	ar rcv $@ $(OBJ)
	if [ -f /usr/bin/ranlib ] ; then ranlib $@ ; else true ; fi

.PARALLEL:	$(OBJ)

