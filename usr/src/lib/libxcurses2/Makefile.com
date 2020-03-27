#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY=	libcurses.a
VERS=	.2

# objects are grouped by source directory
# all of the libxcurses source files are in src/libc
OBJECTS= $(XCURSES)	$(MKS)	$(WIDE)

# XCURSES source files are in src/libc/xcurses
XCURSES= \
add_wch.o	dupwin.o	longname.o	strname.o	wbrdr.o \
addch.o		echo_wch.o	m_cc.o		termattr.o	wbrdr_st.o \
addchn.o	echochar.o	meta.o		tgetent.o	wchgat.o \
addnstr.o	endwin.o	move.o		tgetflag.o	wclear.o \
addnws.o	flushinp.o	mvcur.o		tgetnum.o	wclrbot.o \
addwchn.o	get_wch.o	mvwin.o		tgetstr.o	wclreol.o \
attr_on.o	getcchar.o	napms.o		tgoto.o		wdelch.o \
attron.o	getch.o		newpad.o	tigetfla.o	wget_wch.o \
baudrate.o	getn_ws.o	newterm.o	tigetnum.o	wgetch.o \
beep.o		getnstr.o	newwin.o	tigetstr.o	wgetn_ws.o \
bkgd.o		getwin.o	noecho.o	timeout.o	whln.o \
bkgdset.o	has.o		nonl.o		touched.o	whln_st.o \
bkgrnd.o	hln.o		numcode.o	touchwin.o	win_wch.o \
bkgrndst.o	hln_st.o	numfnam.o	tparm.o		win_wchn.o \
boolcode.o	in_wch.o	numname.o	tputs.o		winch.o \
boolfnam.o	in_wchn.o	overlay.o	winchn.o \
boolname.o	inch.o		pecho_wc.o	unctrl.o	winnstr.o \
box.o		inchn.o		pechoch.o	vid_attr.o	winnwstr.o \
box_set.o	initscr.o	prefresh.o	vid_puts.o	wins_nws.o \
brdr.o		innstr.o	printw.o	vidattr.o	wins_wch.o \
brdr_st.o	innwstr.o	ptrmove.o	vw_print.o	winsch.o \
cbreak.o	ins_nws.o	qiflush.o	vw_scanw.o	winsdel.o \
chgat.o		ins_wch.o	redraw.o	vwprintw.o	winsnstr.o \
clear.o		insch.o		refresh.o	vwscanw.o	wmove.o \
clearok.o	insnstr.o	savetty.o	wacs.o		wredraw.o \
clrbot.o	intrflsh.o	scanw.o		wadd_wch.o	wrefresh.o \
clreol.o	scr_dump.o	waddch.o	wscrl.o \
color.o		isendwin.o	scrl.o		waddchn.o	wscrreg.o \
copywin.o	key_name.o	scrreg.o	waddnstr.o	wsyncdn.o \
curs_set.o	keyindex.o	setcchar.o	waddnws.o	wsyncup.o \
delay.o		keyname.o	setup.o		waddwchn.o	wtimeout.o \
delch.o		keypad.o	slk.o		wattr_on.o	wtouchln.o \
deleteln.o	killchar.o	strcode.o	wattron.o	wunctrl.o \
doupdate.o	killwch.o	strfnam.o	wbkgrnd.o

# MKS source files are in src/libc/mks
MKS= m_crcpos.o

# WIDE source files are in src/libc/wide
WIDE= wio_get.o	wio_put.o

# include library definitions
include ../../Makefile.lib

SRCDIR =	../src

SRCS=		$(XCURSES:%.o=../src/libc/xcurses/%.c) \
		$(MKS:%.o=../src/libc/mks/%.c) \
		$(WIDE:%.o=../src/libc/wide/%.c)

LIBS =		$(DYNLIB)

# definitions for install target
ROOTLIBDIR=	$(ROOT)/usr/xpg4/lib
ROOTLIBDIR64=	$(ROOT)/usr/xpg4/lib/$(MACH64)
ROOTLIBS=	$(LIBS:%=$(ROOTLIBDIR)/%)

LDLIBS += -lc

CPPFLAGS = -I../h -I../src/libc/xcurses $(CPPFLAGS.master)
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-unused-value

# not linted
SMATCH=off

#
# If and when somebody gets around to messaging this, CLOBBERFILE should not
# be cleared (so that any .po file will be clobbered.
#
CLOBBERFILES=	libcurses.so libcurses.so$(VERS)

.KEEP_STATE:

all: $(LIBS)


#
# Include library targets
#
include ../../Makefile.targ

objs/%.o pics/%.o:	../src/libc/xcurses/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o:	../src/libc/mks/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o:	../src/libc/wide/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
