#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# ucblib/libcurses/Makefile.com
#

LIBRARY=	libcurses.a
VERS=		.1

OBJECTS= 		\
	addch.o		\
	addstr.o	\
	box.o		\
	clear.o		\
	clrtobot.o	\
	clrtoeol.o	\
	cr_put.o	\
	cr_tty.o	\
	curses.o	\
	delch.o		\
	deleteln.o	\
	delwin.o	\
	endwin.o	\
	erase.o		\
	fullname.o	\
	getch.o		\
	getstr.o	\
	id_subwins.o	\
	idlok.o		\
	initscr.o	\
	insch.o		\
	insertln.o	\
	longname.o	\
	move.o		\
	mvprintw.o	\
	mvscanw.o	\
	mvwin.o		\
	newwin.o	\
	overlay.o	\
	overwrite.o	\
	printw.o	\
	putchar.o	\
	refresh.o	\
	scanw.o		\
	scroll.o	\
	standout.o	\
	toucholap.o	\
	touchwin.o	\
	tstp.o		\
	unctrl.o

# include library definitions
include $(SRC)/lib/Makefile.lib

ROOTLIBDIR=	$(ROOT)/usr/ucblib
ROOTLIBDIR64=	$(ROOT)/usr/ucblib/$(MACH64)

MAPFILE=	$(MAPDIR)/mapfile
SRCS=		$(OBJECTS:%.o=../%.c)

LIBS = $(DYNLIB) $(LINTLIB)

LINTSRC= $(LINTLIB:%.ln=%)
ROOTLINTDIR= $(ROOTLIBDIR)
ROOTLINTDIR64= $(ROOTLIBDIR)/$(MACH64)
ROOTLINT= $(LINTSRC:%=$(ROOTLINTDIR)/%)
ROOTLINT64= $(LINTSRC:%=$(ROOTLINTDIR64)/%)

# install rule for lint source file target
$(ROOTLINTDIR)/%: ../%
	$(INS.file)
$(ROOTLINTDIR64)/%: ../%
	$(INS.file)

$(LINTLIB):= SRCS=../llib-lcurses

CFLAGS	+=	$(CCVERBOSE)
CFLAGS64 +=	$(CCVERBOSE)
DYNFLAGS +=	
DYNFLAGS32 =	-M$(MAPFILE) -R/usr/ucblib
DYNFLAGS64 =	-M$(MAPFILE) -R/usr/ucblib/$(MACH64)
LDLIBS +=	-ltermcap -lucb -lc

CPPFLAGS = -I$(ROOT)/usr/ucbinclude -I../../../lib/libc/inc $(CPPFLAGS.master)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

$(DYNLIB): 	$(MAPFILE)

$(MAPFILE):
	@cd $(MAPDIR); $(MAKE) mapfile

#
# Include library targets
#
include $(SRC)/lib/Makefile.targ

objs/%.o pics/%.o: ../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
