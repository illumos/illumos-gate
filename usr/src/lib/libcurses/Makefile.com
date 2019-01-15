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
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY=	libcurses.a
VERS=	.1

OBJECTS=	$(OBJS1) $(OBJS2) $(OBJS3) $(OBJS4) $(OBJS5) $(OBJS6)

OBJS1=	_addch.o _addchnstr.o _addchstr.o _addnstr.o _addstr.o \
	_attroff.o _attron.o _attrset.o _beep.o _bkgd.o \
	_bkgdset.o _border.o _box.o _clear.o _clrtobot.o \
	_clrtoeol.o _crmode.o _del_curterm.o _delch.o _deleteln.o \
	_echo.o _echochar.o _erase.o _fixterm.o _flash.o \
	_garbagdlins.o _garbagedwin.o _getch.o _getstr.o \
	_halfdelay.o _hline.o _inch.o _inchnstr.o _inchstr.o \
	_innstr.o _insch.o _insdelln.o _insertln.o _insnstr.o \
	_insstr.o _instr.o _intrflush.o _meta.o _move.o \
	_mvaddch.o _mvaddchnstr.o _mvaddchstr.o _mvaddnstr.o \
	_mvaddstr.o _mvdelch.o _mvgetch.o _mvgetstr.o _mvhline.o \
	_mvinch.o _mvinchnstr.o _mvinchstr.o _mvinnstr.o \
	_mvinsch.o _mvinsnstr.o _mvinsstr.o _mvinstr.o _mvvline.o \
	_mvwaddch.o _mvwaddchnst.o _mvwaddchstr.o _mvwaddnstr.o \
	_mvwaddstr.o _mvwdelch.o _mvwgetch.o _mvwgetstr.o \
	_mvwhline.o _mvwinch.o _mvwinchnst.o _mvwinchstr.o \
	_mvwinnstr.o _mvwinsch.o _mvwinsnstr.o _mvwinsstr.o \
	_mvwinstr.o _mvwvline.o _newterm.o _nl.o _nocrmode.o \
	_noecho.o _nonl.o _noqiflush.o _overlay.o _overwrite.o \
	_qiflush.o _refresh.o _resetterm.o _saveterm.o \
	_scr_init.o _scr_restore.o _scr_set.o _scrl.o _scroll.o \
	_set_curterm.o _set_term.o _setscrreg.o _slk_init.o \
	_standend.o _standout.o _subpad.o _timeout.o _touchline.o \
	_unctrl.o _vline.o _waddchstr.o _waddstr.o _wclear.o \
	_wdeleteln.o _werase.o _winsertln.o _winsstr.o \
	_wstandend.o _wstandout.o V2.__sscans.o V2._sprintw.o \
	V2.makenew.o V3.box.o V3.initscr.o V3.m_addch.o V3.m_addstr.o \
	V3.m_clear.o V3.m_erase.o V3.m_initscr.o V3.m_move.o V3.m_newterm.o \
	V3.m_refresh.o V3.newterm.o V3.pechochar.o V3.upd_old_y.o \
	V3.vidattr.o V3.vidputs.o V3.waddch.o V3.wattroff.o V3.wattron.o \
	V3.wattrset.o V3.wechochar.o V3.winsch.o baudrate.o can_change.o \
	color_cont.o cbreak.o chkinput.o clearok.o copywin.o curs_set.o \
	curserr.o curses.o def_prog.o delay.o delay_out.o \
	delkey.o delkeymap.o delscreen.o delterm.o delwin.o \
	derwin.o doupdate.o draino.o dupwin.o endwin.o erasechar.o \
	flushinp.o getattrs.o getbegyx.o getbkgd.o getmaxyx.o \
	getparyx.o getsyx.o gettmode.o getwin.o getyx.o has_colors.o \
	has_ic.o has_il.o idcok.o idlok.o immedok.o init_acs.o init_color.o \
	init_costs.o init_pair.o initscr.o is_linetou.o is_wintou.o \
	keyname.o keypad.o killchar.o leaveok.o

OBJS2=	longname.o makenew.o memSset.o meta.o mvcur.o \
	mvderwin.o mvprintw.o mvscanw.o mvwin.o mvwprintw.o \
	mvwscanw.o napms.o newkey.o newpad.o newscreen.o \
	newwin.o nocbreak.o nodelay.o noraw.o \
	notimeout.o outch.o overlap.o pechochar.o pnoutref.o \
	prefresh.o printw.o putp.o putwin.o quick_echo.o \
	raw.o redrawwin.o reset_sh.o resetty.o restart.o \
	ring.o ripoffline.o savetty.o scanw.o scr_all.o \
	scr_dump.o scr_ll_dump.o scr_reset.o scrollok.o setcurscreen.o \
	setcurterm.o setecho.o setkeymap.o setnonl.o setqiflush.o \
	setsyx.o setterm.o setupterm.o slk_atroff.o slk_atron.o \
	slk_atrset.o slk_clear.o slk_label.o \
	slk_noutref.o slk_refresh.o slk_restore.o slk_set.o slk_start.o \
	slk_touch.o subwin.o syncok.o tcsearch.o termattrs.o \
	termcap.o termerr.o termname.o tgetch.o tgoto.o \
	tifget.o tifnames.o tiget.o tinames.o tinputfd.o \
	tnames.o touchwin.o tparm.o tputs.o trace.o \
	tstp.o ttimeout.o typeahead.o unctrl.o ungetch.o \
	untouchwin.o vidputs.o vidupdate.o vwprintw.o \
	vwscanw.o waddch.o waddchnstr.o waddnstr.o wattroff.o \
	wattron.o wattrset.o wbkgd.o wbkgdset.o wborder.o \
	wclrtobot.o wclrtoeol.o wdelch.o wechochar.o wgetch.o \
	wgetstr.o whline.o winch.o winchnstr.o winchstr.o \
	winnstr.o winsch.o winsdelln.o winsnstr.o winstr.o \
	wmove.o wnoutref.o wprintw.o wredrawln.o wrefresh.o \
	wscanw.o wscrl.o wsetscrreg.o wsyncdown.o wsyncup.o \
	wtimeout.o wtouchln.o wvline.o pair_cont.o start_col.o \
	mouse.o

OBJS3=	mbaddch.o mbcharlen.o mbdisplen.o mbgetwidth.o \
	mbinch.o mbinsshift.o mbmove.o mbtranslate.o \
	pechowchar.o tgetwch.o ungetwch.o waddnwstr.o \
	waddwch.o waddwchnstr.o wechowchar.o wgetwstr.o \
	wgetwch.o winnwstr.o winsnwstr.o winswch.o \
	winwch.o winwchnstr.o winwstr.o \
	use_env.o

OBJS4=	_addnwstr.o _addwch.o _addwchnstr.o _addwchstr.o \
	_addwstr.o _echowchar.o _getnwstr.o _getwch.o \
	_getwstr.o _innwstr.o _insnwstr.o _inswch.o \
	_inswstr.o _inwch.o _inwchnstr.o _inwchstr.o \
	_inwstr.o _mvaddnwstr.o _mvaddwch.o _mvaddwchnstr.o \
	_mvaddwchstr.o _mvaddwstr.o _mvgetnwstr.o _mvgetwch.o \
	_mvgetwstr.o _mvinnwstr.o _mvinsnwstr.o _mvinswch.o \
	_mvinswstr.o _mvinwch.o _mvinwchnstr.o _mvinwchstr.o \
	_mvinwstr.o _mvwaddnwstr.o _mvwaddwch.o _mvwaddwchnstr.o \
	_mvwaddwchstr.o _mvwaddwstr.o _mvwgetnwstr.o _mvwgetwch.o \
	_mvwgetwstr.o _mvwinnwstr.o _mvwinsnwstr.o _mvwinswch.o \
	_mvwinswstr.o _mvwinwch.o _mvwinwchnstr.o _mvwinwchstr.o \
	_mvwinwstr.o _waddwchstr.o _waddwstr.o _winswstr.o \
	_winwchstr.o

OBJS5=	mbstowcs.o mbtowc.o wcstombs.o wctomb.o

OBJS6=	wmovenextch.o wmoveprevch.o wadjcurspos.o print.o iexpand.o \
	cexpand.o infotocap.o

# include library definitions
include ../../Makefile.lib

# install this library in the root filesystem
include ../../Makefile.rootfs

SRCDIR =	../screen

LIBS =		$(DYNLIB) $(LINTLIB)

# definitions for lint

$(LINTLIB):= SRCS=../screen/llib-lcurses

LINTOUT=	lint.out
LINTSRC=	$(LINTLIB:%.ln=%)

CLEANFILES +=	$(LINTOUT) $(LINTLIB)

CFLAGS	+=	$(CCVERBOSE)

CERRWARN +=	-_gcc=-Wno-char-subscripts
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-parentheses

# not linted
SMATCH=off

LDLIBS += -lc

CPPFLAGS += -I../screen -I../../common/inc

ED = ed
RM = rm -f

#
# If and when somebody gets around to messaging this, CLOBBERFILE should not
# be cleared (so that any .po file will be clobbered.
#
CLOBBERFILES=	libcurses.so libcurses.so$(VERS)

all: $(LIBS)

lint: lintcheck

#
# Install rules for libtermlib.so links.
# Augments the rule in Makefile.targ
#
$(ROOTLIBDIR)/$(LIBLINKS) := INS.liblink= \
	$(RM) $@; $(SYMLINK) $(LIBLINKPATH)$(LIBLINKS)$(VERS) $@; \
	cd $(ROOTLIBDIR); \
		$(RM) libtermlib.so libtermlib.so$(VERS); \
		$(SYMLINK) libcurses.so$(VERS) libtermlib.so$(VERS); \
		$(SYMLINK) libtermlib.so$(VERS) libtermlib.so;

$(ROOTLIBDIR64)/$(LIBLINKS) := INS.liblink64= \
	$(RM) $@; $(SYMLINK) $(LIBLINKPATH)$(LIBLINKS)$(VERS) $@; \
	cd $(ROOTLIBDIR64); \
		$(RM) libtermlib.so libtermlib.so$(VERS);\
		$(SYMLINK) libcurses.so$(VERS) libtermlib.so$(VERS); \
		$(SYMLINK) libtermlib.so$(VERS) libtermlib.so;

#
# Install rules for libtermlib.ln links.
# Augments a pattern rule in Makefile.targ
#
$(ROOTLIBDIR)/$(LINTLIB) := INS.file= \
	-$(RM) $@; $(INS) -s -m $(FILEMODE) -f $(@D) $(LINTLIB); \
	cd $(ROOTLIBDIR); \
		$(RM) llib-ltermlib.ln ; \
		$(SYMLINK) ./llib-lcurses.ln llib-ltermlib.ln;

$(ROOTLIBDIR64)/$(LINTLIB) := INS.file= \
	-$(RM) $@; $(INS) -s -m $(FILEMODE) -f $(@D) $(LINTLIB); \
	cd $(ROOTLIBDIR64); \
		$(RM) llib-ltermlib.ln ; \
		$(SYMLINK) ./llib-lcurses.ln llib-ltermlib.ln;

#
# Install rule for the lint source, which is installed only in
# the default library dir, not MACH64 etc.
#
$(ROOTLINTDIR)/%: ../screen/%
	$(INS.file)
	cd $(ROOTLINTDIR); \
		$(RM) llib-ltermlib ; \
		$(SYMLINK) ./llib-lcurses llib-ltermlib;

#
# Include library targets
#
include ../../Makefile.targ
