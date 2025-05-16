#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT=	3xcurses

MANFILES=	COLS.3xcurses			\
		LINES.3xcurses			\
		add_wch.3xcurses		\
		add_wchnstr.3xcurses		\
		addch.3xcurses			\
		addchstr.3xcurses		\
		addnstr.3xcurses		\
		addnwstr.3xcurses		\
		attr_get.3xcurses		\
		attroff.3xcurses		\
		baudrate.3xcurses		\
		beep.3xcurses			\
		bkgd.3xcurses			\
		bkgrnd.3xcurses			\
		border.3xcurses			\
		border_set.3xcurses		\
		can_change_color.3xcurses	\
		cbreak.3xcurses			\
		chgat.3xcurses			\
		clear.3xcurses			\
		clearok.3xcurses		\
		clrtobot.3xcurses		\
		clrtoeol.3xcurses		\
		copywin.3xcurses		\
		cur_term.3xcurses		\
		curs_set.3xcurses		\
		curscr.3xcurses			\
		curses.3xcurses			\
		def_prog_mode.3xcurses		\
		del_curterm.3xcurses		\
		delay_output.3xcurses		\
		delch.3xcurses			\
		deleteln.3xcurses		\
		delscreen.3xcurses		\
		delwin.3xcurses			\
		derwin.3xcurses			\
		doupdate.3xcurses		\
		dupwin.3xcurses			\
		echo.3xcurses			\
		echo_wchar.3xcurses		\
		echochar.3xcurses		\
		endwin.3xcurses			\
		erasechar.3xcurses		\
		filter.3xcurses			\
		flushinp.3xcurses		\
		get_wch.3xcurses		\
		getbegyx.3xcurses		\
		getcchar.3xcurses		\
		getch.3xcurses			\
		getn_wstr.3xcurses		\
		getnstr.3xcurses		\
		getwin.3xcurses			\
		halfdelay.3xcurses		\
		has_ic.3xcurses			\
		hline.3xcurses			\
		hline_set.3xcurses		\
		idcok.3xcurses			\
		immedok.3xcurses		\
		in_wch.3xcurses			\
		in_wchnstr.3xcurses		\
		inch.3xcurses			\
		inchnstr.3xcurses		\
		initscr.3xcurses		\
		innstr.3xcurses			\
		innwstr.3xcurses		\
		ins_nwstr.3xcurses		\
		ins_wch.3xcurses		\
		insch.3xcurses			\
		insdelln.3xcurses		\
		insertln.3xcurses		\
		insnstr.3xcurses		\
		intrflush.3xcurses		\
		is_linetouched.3xcurses		\
		keyname.3xcurses		\
		keypad.3xcurses			\
		libcurses.3xcurses		\
		longname.3xcurses		\
		meta.3xcurses			\
		move.3xcurses			\
		mvcur.3xcurses			\
		mvderwin.3xcurses		\
		mvprintw.3xcurses		\
		mvscanw.3xcurses		\
		mvwin.3xcurses			\
		napms.3xcurses			\
		newpad.3xcurses			\
		nl.3xcurses			\
		nodelay.3xcurses		\
		noqiflush.3xcurses		\
		notimeout.3xcurses		\
		overlay.3xcurses		\
		pechochar.3xcurses		\
		putp.3xcurses			\
		redrawwin.3xcurses		\
		resetty.3xcurses		\
		ripoffline.3xcurses		\
		scr_dump.3xcurses		\
		scrl.3xcurses			\
		set_term.3xcurses		\
		setcchar.3xcurses		\
		slk_attroff.3xcurses		\
		standend.3xcurses		\
		stdscr.3xcurses			\
		syncok.3xcurses			\
		termattrs.3xcurses		\
		termname.3xcurses		\
		tgetent.3xcurses		\
		tigetflag.3xcurses		\
		typeahead.3xcurses		\
		unctrl.3xcurses			\
		ungetch.3xcurses		\
		use_env.3xcurses		\
		vidattr.3xcurses		\
		vw_printw.3xcurses		\
		vw_scanw.3xcurses		\
		vwprintw.3xcurses		\
		vwscanw.3xcurses		\
		wunctrl.3xcurses

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
