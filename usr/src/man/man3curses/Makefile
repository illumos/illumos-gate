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

MANSECT= 	3curses

MANFILES= 	curs_addch.3curses		\
		curs_addchstr.3curses		\
		curs_addstr.3curses		\
		curs_addwch.3curses		\
		curs_addwchstr.3curses		\
		curs_addwstr.3curses		\
		curs_alecompat.3curses		\
		curs_attr.3curses		\
		curs_beep.3curses		\
		curs_bkgd.3curses		\
		curs_border.3curses		\
		curs_clear.3curses		\
		curs_color.3curses		\
		curs_delch.3curses		\
		curs_deleteln.3curses		\
		curs_getch.3curses		\
		curs_getstr.3curses		\
		curs_getwch.3curses		\
		curs_getwstr.3curses		\
		curs_getyx.3curses		\
		curs_inch.3curses		\
		curs_inchstr.3curses		\
		curs_initscr.3curses		\
		curs_inopts.3curses		\
		curs_insch.3curses		\
		curs_insstr.3curses		\
		curs_instr.3curses		\
		curs_inswch.3curses		\
		curs_inswstr.3curses		\
		curs_inwch.3curses		\
		curs_inwchstr.3curses		\
		curs_inwstr.3curses		\
		curs_kernel.3curses		\
		curs_move.3curses		\
		curs_outopts.3curses		\
		curs_overlay.3curses		\
		curs_pad.3curses		\
		curs_printw.3curses		\
		curs_refresh.3curses		\
		curs_scanw.3curses		\
		curs_scr_dump.3curses		\
		curs_scroll.3curses		\
		curs_slk.3curses		\
		curs_termattrs.3curses		\
		curs_termcap.3curses		\
		curs_terminfo.3curses		\
		curs_touch.3curses		\
		curs_util.3curses		\
		curs_window.3curses		\
		curses.3curses			\
		form_cursor.3curses		\
		form_data.3curses		\
		form_driver.3curses		\
		form_field.3curses		\
		form_field_attributes.3curses	\
		form_field_buffer.3curses	\
		form_field_info.3curses		\
		form_field_just.3curses		\
		form_field_new.3curses		\
		form_field_opts.3curses		\
		form_field_userptr.3curses	\
		form_field_validation.3curses	\
		form_fieldtype.3curses		\
		form_hook.3curses		\
		form_new.3curses		\
		form_new_page.3curses		\
		form_opts.3curses		\
		form_page.3curses		\
		form_post.3curses		\
		form_userptr.3curses		\
		form_win.3curses		\
		forms.3curses			\
		menu_attributes.3curses		\
		menu_cursor.3curses		\
		menu_driver.3curses		\
		menu_format.3curses		\
		menu_hook.3curses		\
		menu_item_current.3curses	\
		menu_item_name.3curses		\
		menu_item_new.3curses		\
		menu_item_opts.3curses		\
		menu_item_userptr.3curses	\
		menu_item_value.3curses		\
		menu_item_visible.3curses	\
		menu_items.3curses		\
		menu_mark.3curses		\
		menu_new.3curses		\
		menu_opts.3curses		\
		menu_pattern.3curses		\
		menu_post.3curses		\
		menu_userptr.3curses		\
		menu_win.3curses		\
		menus.3curses			\
		panel_above.3curses		\
		panel_move.3curses		\
		panel_new.3curses		\
		panel_show.3curses		\
		panel_top.3curses		\
		panel_update.3curses		\
		panel_userptr.3curses		\
		panel_window.3curses		\
		panels.3curses

MANLINKS=	addch.3curses			\
		addchnstr.3curses		\
		addchstr.3curses		\
		addnstr.3curses			\
		addnwstr.3curses		\
		addstr.3curses			\
		addwch.3curses			\
		addwchnstr.3curses		\
		addwchstr.3curses		\
		addwstr.3curses			\
		adjcurspos.3curses		\
		attroff.3curses			\
		attron.3curses			\
		attrset.3curses			\
		baudrate.3curses		\
		beep.3curses			\
		bkgd.3curses			\
		bkgdset.3curses			\
		border.3curses			\
		bottom_panel.3curses		\
		box.3curses			\
		can_change_color.3curses	\
		cbreak.3curses			\
		clear.3curses			\
		clearok.3curses			\
		clrtobot.3curses		\
		clrtoeol.3curses		\
		color_content.3curses		\
		copywin.3curses			\
		current_field.3curses		\
		current_item.3curses		\
		curs_set.3curses		\
		data_ahead.3curses		\
		data_behind.3curses		\
		def_prog_mode.3curses		\
		def_shell_mode.3curses		\
		del_curterm.3curses		\
		del_panel.3curses		\
		delay_output.3curses		\
		delch.3curses			\
		deleteln.3curses		\
		delscreen.3curses		\
		delwin.3curses			\
		derwin.3curses			\
		doupdate.3curses		\
		dup_field.3curses		\
		dupwin.3curses			\
		dynamic_field_info.3curses	\
		echo.3curses			\
		echochar.3curses		\
		echowchar.3curses		\
		endwin.3curses			\
		erase.3curses			\
		erasechar.3curses		\
		field_arg.3curses		\
		field_back.3curses		\
		field_buffer.3curses		\
		field_count.3curses		\
		field_fore.3curses		\
		field_index.3curses		\
		field_info.3curses		\
		field_init.3curses		\
		field_just.3curses		\
		field_opts.3curses		\
		field_opts_off.3curses		\
		field_opts_on.3curses		\
		field_pad.3curses		\
		field_status.3curses		\
		field_term.3curses		\
		field_type.3curses		\
		field_userptr.3curses		\
		filter.3curses			\
		flash.3curses			\
		flushinp.3curses		\
		form_fields.3curses		\
		form_init.3curses		\
		form_opts_off.3curses		\
		form_opts_on.3curses		\
		form_sub.3curses		\
		form_term.3curses		\
		free_field.3curses		\
		free_fieldtype.3curses		\
		free_form.3curses		\
		free_item.3curses		\
		free_menu.3curses		\
		getbegyx.3curses		\
		getch.3curses			\
		getmaxyx.3curses		\
		getnwstr.3curses		\
		getparyx.3curses		\
		getstr.3curses			\
		getsyx.3curses			\
		getwch.3curses			\
		getwin.3curses			\
		getwstr.3curses			\
		getyx.3curses			\
		halfdelay.3curses		\
		has_colors.3curses		\
		has_ic.3curses			\
		has_il.3curses			\
		hide_panel.3curses		\
		idcok.3curses			\
		idlok.3curses			\
		immedok.3curses			\
		inch.3curses			\
		inchnstr.3curses		\
		inchstr.3curses			\
		init_color.3curses		\
		init_pair.3curses		\
		initscr.3curses			\
		innstr.3curses			\
		innwstr.3curses			\
		insch.3curses			\
		insdelln.3curses		\
		insertln.3curses		\
		insnstr.3curses			\
		insnwstr.3curses		\
		insstr.3curses			\
		instr.3curses			\
		inswch.3curses			\
		inswstr.3curses			\
		intrflush.3curses		\
		inwch.3curses			\
		inwchnstr.3curses		\
		inwchstr.3curses		\
		inwstr.3curses			\
		is_linetouched.3curses		\
		is_wintouched.3curses		\
		isendwin.3curses		\
		item_count.3curses		\
		item_description.3curses	\
		item_index.3curses		\
		item_init.3curses		\
		item_name.3curses		\
		item_opts.3curses		\
		item_opts_off.3curses		\
		item_opts_on.3curses		\
		item_term.3curses		\
		item_userptr.3curses		\
		item_value.3curses		\
		item_visible.3curses		\
		keyname.3curses			\
		keypad.3curses			\
		killchar.3curses		\
		leaveok.3curses			\
		link_field.3curses		\
		link_fieldtype.3curses		\
		longname.3curses		\
		menu_back.3curses		\
		menu_fore.3curses		\
		menu_grey.3curses		\
		menu_init.3curses		\
		menu_opts_off.3curses		\
		menu_opts_on.3curses		\
		menu_pad.3curses		\
		menu_sub.3curses		\
		menu_term.3curses		\
		meta.3curses			\
		move.3curses			\
		move_field.3curses		\
		move_panel.3curses		\
		movenextch.3curses		\
		moveprevch.3curses		\
		mvaddch.3curses			\
		mvaddchnstr.3curses		\
		mvaddchstr.3curses		\
		mvaddnstr.3curses		\
		mvaddnwstr.3curses		\
		mvaddstr.3curses		\
		mvaddwch.3curses		\
		mvaddwchnstr.3curses		\
		mvaddwchstr.3curses		\
		mvaddwstr.3curses		\
		mvcur.3curses			\
		mvdelch.3curses			\
		mvderwin.3curses		\
		mvgetch.3curses			\
		mvgetnwstr.3curses		\
		mvgetstr.3curses		\
		mvgetwch.3curses		\
		mvgetwstr.3curses		\
		mvinch.3curses			\
		mvinchnstr.3curses		\
		mvinchstr.3curses		\
		mvinnstr.3curses		\
		mvinnwstr.3curses		\
		mvinsch.3curses			\
		mvinsnstr.3curses		\
		mvinsnwstr.3curses		\
		mvinsstr.3curses		\
		mvinstr.3curses			\
		mvinswch.3curses		\
		mvinswstr.3curses		\
		mvinwch.3curses			\
		mvinwchnstr.3curses		\
		mvinwchstr.3curses		\
		mvinwstr.3curses		\
		mvprintw.3curses		\
		mvscanw.3curses			\
		mvwaddch.3curses		\
		mvwaddchnstr.3curses		\
		mvwaddchstr.3curses		\
		mvwaddnstr.3curses		\
		mvwaddnwstr.3curses		\
		mvwaddstr.3curses		\
		mvwaddwch.3curses		\
		mvwaddwchnstr.3curses		\
		mvwaddwchstr.3curses		\
		mvwaddwstr.3curses		\
		mvwdelch.3curses		\
		mvwgetch.3curses		\
		mvwgetnwstr.3curses		\
		mvwgetstr.3curses		\
		mvwgetwch.3curses		\
		mvwgetwstr.3curses		\
		mvwin.3curses			\
		mvwinch.3curses			\
		mvwinchnstr.3curses		\
		mvwinchstr.3curses		\
		mvwinnstr.3curses		\
		mvwinnwstr.3curses		\
		mvwinsch.3curses		\
		mvwinsnstr.3curses		\
		mvwinsnwstr.3curses		\
		mvwinsstr.3curses		\
		mvwinstr.3curses		\
		mvwinswch.3curses		\
		mvwinswstr.3curses		\
		mvwinwch.3curses		\
		mvwinwchnstr.3curses		\
		mvwinwchstr.3curses		\
		mvwinwstr.3curses		\
		mvwprintw.3curses		\
		mvwscanw.3curses		\
		napms.3curses			\
		new_field.3curses		\
		new_fieldtype.3curses		\
		new_form.3curses		\
		new_item.3curses		\
		new_menu.3curses		\
		new_page.3curses		\
		new_panel.3curses		\
		newpad.3curses			\
		newterm.3curses			\
		newwin.3curses			\
		nl.3curses			\
		nocbreak.3curses		\
		nodelay.3curses			\
		noecho.3curses			\
		nonl.3curses			\
		noqiflush.3curses		\
		noraw.3curses			\
		notimeout.3curses		\
		overlay.3curses			\
		overwrite.3curses		\
		pair_content.3curses		\
		panel_below.3curses		\
		panel_hidden.3curses		\
		pechochar.3curses		\
		pechowchar.3curses		\
		pnoutrefresh.3curses		\
		pos_form_cursor.3curses		\
		pos_menu_cursor.3curses		\
		post_form.3curses		\
		post_menu.3curses		\
		prefresh.3curses		\
		printw.3curses			\
		putp.3curses			\
		putwin.3curses			\
		qiflush.3curses			\
		raw.3curses			\
		redrawwin.3curses		\
		refresh.3curses			\
		replace_panel.3curses		\
		reset_prog_mode.3curses		\
		reset_shell_mode.3curses	\
		resetty.3curses			\
		restartterm.3curses		\
		ripoffline.3curses		\
		savetty.3curses			\
		scale_form.3curses		\
		scale_menu.3curses		\
		scanw.3curses			\
		scr_dump.3curses		\
		scr_init.3curses		\
		scr_restore.3curses		\
		scr_set.3curses			\
		scrl.3curses			\
		scroll.3curses			\
		scrollok.3curses		\
		set_current_field.3curses	\
		set_current_item.3curses	\
		set_curterm.3curses		\
		set_field_back.3curses		\
		set_field_buffer.3curses	\
		set_field_fore.3curses		\
		set_field_init.3curses		\
		set_field_just.3curses		\
		set_field_opts.3curses		\
		set_field_pad.3curses		\
		set_field_status.3curses	\
		set_field_term.3curses		\
		set_field_type.3curses		\
		set_field_userptr.3curses	\
		set_fieldtype_arg.3curses	\
		set_fieldtype_choice.3curses	\
		set_form_fields.3curses		\
		set_form_init.3curses		\
		set_form_opts.3curses		\
		set_form_page.3curses		\
		set_form_sub.3curses		\
		set_form_term.3curses		\
		set_form_userptr.3curses	\
		set_form_win.3curses		\
		set_item_init.3curses		\
		set_item_opts.3curses		\
		set_item_term.3curses		\
		set_item_userptr.3curses	\
		set_item_value.3curses		\
		set_max_field.3curses		\
		set_menu_back.3curses		\
		set_menu_fore.3curses		\
		set_menu_format.3curses		\
		set_menu_grey.3curses		\
		set_menu_init.3curses		\
		set_menu_items.3curses		\
		set_menu_mark.3curses		\
		set_menu_opts.3curses		\
		set_menu_pad.3curses		\
		set_menu_pattern.3curses	\
		set_menu_sub.3curses		\
		set_menu_term.3curses		\
		set_menu_userptr.3curses	\
		set_menu_win.3curses		\
		set_new_page.3curses		\
		set_panel_userptr.3curses	\
		set_term.3curses		\
		set_top_row.3curses		\
		setscrreg.3curses		\
		setsyx.3curses			\
		setterm.3curses			\
		setupterm.3curses		\
		show_panel.3curses		\
		slk_attroff.3curses		\
		slk_attron.3curses		\
		slk_attrset.3curses		\
		slk_clear.3curses		\
		slk_init.3curses		\
		slk_label.3curses		\
		slk_noutrefresh.3curses		\
		slk_refresh.3curses		\
		slk_restore.3curses		\
		slk_set.3curses			\
		slk_touch.3curses		\
		standend.3curses		\
		standout.3curses		\
		start_color.3curses		\
		subpad.3curses			\
		subwin.3curses			\
		syncok.3curses			\
		termattrs.3curses		\
		termname.3curses		\
		tgetent.3curses			\
		tgetflag.3curses		\
		tgetnum.3curses			\
		tgetstr.3curses			\
		tgoto.3curses			\
		tigetflag.3curses		\
		tigetnum.3curses		\
		tigetstr.3curses		\
		timeout.3curses			\
		top_panel.3curses		\
		top_row.3curses			\
		touchline.3curses		\
		touchwin.3curses		\
		tparm.3curses			\
		tputs.3curses			\
		typeahead.3curses		\
		unctrl.3curses			\
		ungetch.3curses			\
		ungetwch.3curses		\
		unpost_form.3curses		\
		unpost_menu.3curses		\
		untouchwin.3curses		\
		update_panels.3curses		\
		use_env.3curses			\
		vidattr.3curses			\
		vidputs.3curses			\
		vwprintw.3curses		\
		vwscanw.3curses			\
		waddch.3curses			\
		waddchnstr.3curses		\
		waddchstr.3curses		\
		waddnstr.3curses		\
		waddnwstr.3curses		\
		waddstr.3curses			\
		waddwch.3curses			\
		waddwchnstr.3curses		\
		waddwchstr.3curses		\
		waddwstr.3curses		\
		wadjcurspos.3curses		\
		wattroff.3curses		\
		wattron.3curses			\
		wattrset.3curses		\
		wbkgd.3curses			\
		wbkgdset.3curses		\
		wborder.3curses			\
		wclear.3curses			\
		wclrtobot.3curses		\
		wclrtoeol.3curses		\
		wcursyncup.3curses		\
		wdelch.3curses			\
		wdeleteln.3curses		\
		wechochar.3curses		\
		wechowchar.3curses		\
		werase.3curses			\
		wgetch.3curses			\
		wgetnstr.3curses		\
		wgetnwstr.3curses		\
		wgetstr.3curses			\
		wgetwch.3curses			\
		wgetwstr.3curses		\
		whline.3curses			\
		winch.3curses			\
		winchnstr.3curses		\
		winchstr.3curses		\
		winnstr.3curses			\
		winnwstr.3curses		\
		winsch.3curses			\
		winsdelln.3curses		\
		winsertln.3curses		\
		winsnstr.3curses		\
		winsnwstr.3curses		\
		winsstr.3curses			\
		winstr.3curses			\
		winswch.3curses			\
		winswstr.3curses		\
		winwch.3curses			\
		winwchnstr.3curses		\
		winwchstr.3curses		\
		winwstr.3curses			\
		wmove.3curses			\
		wmovenextch.3curses		\
		wmoveprevch.3curses		\
		wnoutrefresh.3curses		\
		wprintw.3curses			\
		wredrawln.3curses		\
		wrefresh.3curses		\
		wscanw.3curses			\
		wscrl.3curses			\
		wsetscrreg.3curses		\
		wstandend.3curses		\
		wstandout.3curses		\
		wsyncdown.3curses		\
		wsyncup.3curses			\
		wtimeout.3curses		\
		wtouchln.3curses		\
		wvline.3curses

addch.3curses			:= LINKSRC = curs_addch.3curses
echochar.3curses		:= LINKSRC = curs_addch.3curses
mvaddch.3curses			:= LINKSRC = curs_addch.3curses
mvwaddch.3curses		:= LINKSRC = curs_addch.3curses
waddch.3curses			:= LINKSRC = curs_addch.3curses
wechochar.3curses		:= LINKSRC = curs_addch.3curses

addchnstr.3curses		:= LINKSRC = curs_addchstr.3curses
addchstr.3curses		:= LINKSRC = curs_addchstr.3curses
mvaddchnstr.3curses		:= LINKSRC = curs_addchstr.3curses
mvaddchstr.3curses		:= LINKSRC = curs_addchstr.3curses
mvwaddchnstr.3curses		:= LINKSRC = curs_addchstr.3curses
mvwaddchstr.3curses		:= LINKSRC = curs_addchstr.3curses
waddchnstr.3curses		:= LINKSRC = curs_addchstr.3curses
waddchstr.3curses		:= LINKSRC = curs_addchstr.3curses

addnstr.3curses			:= LINKSRC = curs_addstr.3curses
addstr.3curses			:= LINKSRC = curs_addstr.3curses
mvaddnstr.3curses		:= LINKSRC = curs_addstr.3curses
mvaddstr.3curses		:= LINKSRC = curs_addstr.3curses
mvwaddnstr.3curses		:= LINKSRC = curs_addstr.3curses
mvwaddstr.3curses		:= LINKSRC = curs_addstr.3curses
waddnstr.3curses		:= LINKSRC = curs_addstr.3curses
waddstr.3curses			:= LINKSRC = curs_addstr.3curses

addwch.3curses			:= LINKSRC = curs_addwch.3curses
echowchar.3curses		:= LINKSRC = curs_addwch.3curses
mvaddwch.3curses		:= LINKSRC = curs_addwch.3curses
mvwaddwch.3curses		:= LINKSRC = curs_addwch.3curses
waddwch.3curses			:= LINKSRC = curs_addwch.3curses
wechowchar.3curses		:= LINKSRC = curs_addwch.3curses

addwchnstr.3curses		:= LINKSRC = curs_addwchstr.3curses
addwchstr.3curses		:= LINKSRC = curs_addwchstr.3curses
mvaddwchnstr.3curses		:= LINKSRC = curs_addwchstr.3curses
mvaddwchstr.3curses		:= LINKSRC = curs_addwchstr.3curses
mvwaddwchnstr.3curses		:= LINKSRC = curs_addwchstr.3curses
mvwaddwchstr.3curses		:= LINKSRC = curs_addwchstr.3curses
waddwchnstr.3curses		:= LINKSRC = curs_addwchstr.3curses
waddwchstr.3curses		:= LINKSRC = curs_addwchstr.3curses

addnwstr.3curses		:= LINKSRC = curs_addwstr.3curses
addwstr.3curses			:= LINKSRC = curs_addwstr.3curses
mvaddnwstr.3curses		:= LINKSRC = curs_addwstr.3curses
mvaddwstr.3curses		:= LINKSRC = curs_addwstr.3curses
mvwaddnwstr.3curses		:= LINKSRC = curs_addwstr.3curses
mvwaddwstr.3curses		:= LINKSRC = curs_addwstr.3curses
waddnwstr.3curses		:= LINKSRC = curs_addwstr.3curses
waddwstr.3curses		:= LINKSRC = curs_addwstr.3curses

adjcurspos.3curses		:= LINKSRC = curs_alecompat.3curses
movenextch.3curses		:= LINKSRC = curs_alecompat.3curses
moveprevch.3curses		:= LINKSRC = curs_alecompat.3curses
wadjcurspos.3curses		:= LINKSRC = curs_alecompat.3curses
wmovenextch.3curses		:= LINKSRC = curs_alecompat.3curses
wmoveprevch.3curses		:= LINKSRC = curs_alecompat.3curses

attroff.3curses			:= LINKSRC = curs_attr.3curses
attron.3curses			:= LINKSRC = curs_attr.3curses
attrset.3curses			:= LINKSRC = curs_attr.3curses
standend.3curses		:= LINKSRC = curs_attr.3curses
standout.3curses		:= LINKSRC = curs_attr.3curses
wattroff.3curses		:= LINKSRC = curs_attr.3curses
wattron.3curses			:= LINKSRC = curs_attr.3curses
wattrset.3curses		:= LINKSRC = curs_attr.3curses
wstandend.3curses		:= LINKSRC = curs_attr.3curses
wstandout.3curses		:= LINKSRC = curs_attr.3curses

beep.3curses			:= LINKSRC = curs_beep.3curses
flash.3curses			:= LINKSRC = curs_beep.3curses

bkgd.3curses			:= LINKSRC = curs_bkgd.3curses
bkgdset.3curses			:= LINKSRC = curs_bkgd.3curses
wbkgd.3curses			:= LINKSRC = curs_bkgd.3curses
wbkgdset.3curses		:= LINKSRC = curs_bkgd.3curses

border.3curses			:= LINKSRC = curs_border.3curses
box.3curses			:= LINKSRC = curs_border.3curses
wborder.3curses			:= LINKSRC = curs_border.3curses
whline.3curses			:= LINKSRC = curs_border.3curses
wvline.3curses			:= LINKSRC = curs_border.3curses

clear.3curses			:= LINKSRC = curs_clear.3curses
clrtobot.3curses		:= LINKSRC = curs_clear.3curses
clrtoeol.3curses		:= LINKSRC = curs_clear.3curses
erase.3curses			:= LINKSRC = curs_clear.3curses
wclear.3curses			:= LINKSRC = curs_clear.3curses
wclrtobot.3curses		:= LINKSRC = curs_clear.3curses
wclrtoeol.3curses		:= LINKSRC = curs_clear.3curses
werase.3curses			:= LINKSRC = curs_clear.3curses

can_change_color.3curses	:= LINKSRC = curs_color.3curses
color_content.3curses		:= LINKSRC = curs_color.3curses
has_colors.3curses		:= LINKSRC = curs_color.3curses
init_color.3curses		:= LINKSRC = curs_color.3curses
init_pair.3curses		:= LINKSRC = curs_color.3curses
pair_content.3curses		:= LINKSRC = curs_color.3curses
start_color.3curses		:= LINKSRC = curs_color.3curses

delch.3curses			:= LINKSRC = curs_delch.3curses
mvdelch.3curses			:= LINKSRC = curs_delch.3curses
mvwdelch.3curses		:= LINKSRC = curs_delch.3curses
wdelch.3curses			:= LINKSRC = curs_delch.3curses

deleteln.3curses		:= LINKSRC = curs_deleteln.3curses
insdelln.3curses		:= LINKSRC = curs_deleteln.3curses
insertln.3curses		:= LINKSRC = curs_deleteln.3curses
wdeleteln.3curses		:= LINKSRC = curs_deleteln.3curses
winsdelln.3curses		:= LINKSRC = curs_deleteln.3curses
winsertln.3curses		:= LINKSRC = curs_deleteln.3curses

getch.3curses			:= LINKSRC = curs_getch.3curses
mvgetch.3curses			:= LINKSRC = curs_getch.3curses
mvwgetch.3curses		:= LINKSRC = curs_getch.3curses
ungetch.3curses			:= LINKSRC = curs_getch.3curses
wgetch.3curses			:= LINKSRC = curs_getch.3curses

getstr.3curses			:= LINKSRC = curs_getstr.3curses
mvgetstr.3curses		:= LINKSRC = curs_getstr.3curses
mvwgetstr.3curses		:= LINKSRC = curs_getstr.3curses
wgetnstr.3curses		:= LINKSRC = curs_getstr.3curses
wgetstr.3curses			:= LINKSRC = curs_getstr.3curses

getwch.3curses			:= LINKSRC = curs_getwch.3curses
mvgetwch.3curses		:= LINKSRC = curs_getwch.3curses
mvwgetwch.3curses		:= LINKSRC = curs_getwch.3curses
ungetwch.3curses		:= LINKSRC = curs_getwch.3curses
wgetwch.3curses			:= LINKSRC = curs_getwch.3curses

getnwstr.3curses		:= LINKSRC = curs_getwstr.3curses
getwstr.3curses			:= LINKSRC = curs_getwstr.3curses
mvgetnwstr.3curses		:= LINKSRC = curs_getwstr.3curses
mvgetwstr.3curses		:= LINKSRC = curs_getwstr.3curses
mvwgetnwstr.3curses		:= LINKSRC = curs_getwstr.3curses
mvwgetwstr.3curses		:= LINKSRC = curs_getwstr.3curses
wgetnwstr.3curses		:= LINKSRC = curs_getwstr.3curses
wgetwstr.3curses		:= LINKSRC = curs_getwstr.3curses

getbegyx.3curses		:= LINKSRC = curs_getyx.3curses
getmaxyx.3curses		:= LINKSRC = curs_getyx.3curses
getparyx.3curses		:= LINKSRC = curs_getyx.3curses
getyx.3curses			:= LINKSRC = curs_getyx.3curses

inch.3curses			:= LINKSRC = curs_inch.3curses
mvinch.3curses			:= LINKSRC = curs_inch.3curses
mvwinch.3curses			:= LINKSRC = curs_inch.3curses
winch.3curses			:= LINKSRC = curs_inch.3curses

inchnstr.3curses		:= LINKSRC = curs_inchstr.3curses
inchstr.3curses			:= LINKSRC = curs_inchstr.3curses
mvinchnstr.3curses		:= LINKSRC = curs_inchstr.3curses
mvinchstr.3curses		:= LINKSRC = curs_inchstr.3curses
mvwinchnstr.3curses		:= LINKSRC = curs_inchstr.3curses
mvwinchstr.3curses		:= LINKSRC = curs_inchstr.3curses
winchnstr.3curses		:= LINKSRC = curs_inchstr.3curses
winchstr.3curses		:= LINKSRC = curs_inchstr.3curses

delscreen.3curses		:= LINKSRC = curs_initscr.3curses
endwin.3curses			:= LINKSRC = curs_initscr.3curses
initscr.3curses			:= LINKSRC = curs_initscr.3curses
isendwin.3curses		:= LINKSRC = curs_initscr.3curses
newterm.3curses			:= LINKSRC = curs_initscr.3curses
set_term.3curses		:= LINKSRC = curs_initscr.3curses

cbreak.3curses			:= LINKSRC = curs_inopts.3curses
echo.3curses			:= LINKSRC = curs_inopts.3curses
halfdelay.3curses		:= LINKSRC = curs_inopts.3curses
intrflush.3curses		:= LINKSRC = curs_inopts.3curses
keypad.3curses			:= LINKSRC = curs_inopts.3curses
meta.3curses			:= LINKSRC = curs_inopts.3curses
nocbreak.3curses		:= LINKSRC = curs_inopts.3curses
nodelay.3curses			:= LINKSRC = curs_inopts.3curses
noecho.3curses			:= LINKSRC = curs_inopts.3curses
noqiflush.3curses		:= LINKSRC = curs_inopts.3curses
noraw.3curses			:= LINKSRC = curs_inopts.3curses
notimeout.3curses		:= LINKSRC = curs_inopts.3curses
qiflush.3curses			:= LINKSRC = curs_inopts.3curses
raw.3curses			:= LINKSRC = curs_inopts.3curses
timeout.3curses			:= LINKSRC = curs_inopts.3curses
typeahead.3curses		:= LINKSRC = curs_inopts.3curses
wtimeout.3curses		:= LINKSRC = curs_inopts.3curses

insch.3curses			:= LINKSRC = curs_insch.3curses
mvinsch.3curses			:= LINKSRC = curs_insch.3curses
mvwinsch.3curses		:= LINKSRC = curs_insch.3curses
winsch.3curses			:= LINKSRC = curs_insch.3curses

insnstr.3curses			:= LINKSRC = curs_insstr.3curses
insstr.3curses			:= LINKSRC = curs_insstr.3curses
mvinsnstr.3curses		:= LINKSRC = curs_insstr.3curses
mvinsstr.3curses		:= LINKSRC = curs_insstr.3curses
mvwinsnstr.3curses		:= LINKSRC = curs_insstr.3curses
mvwinsstr.3curses		:= LINKSRC = curs_insstr.3curses
winsnstr.3curses		:= LINKSRC = curs_insstr.3curses
winsstr.3curses			:= LINKSRC = curs_insstr.3curses

innstr.3curses			:= LINKSRC = curs_instr.3curses
instr.3curses			:= LINKSRC = curs_instr.3curses
mvinnstr.3curses		:= LINKSRC = curs_instr.3curses
mvinstr.3curses			:= LINKSRC = curs_instr.3curses
mvwinnstr.3curses		:= LINKSRC = curs_instr.3curses
mvwinstr.3curses		:= LINKSRC = curs_instr.3curses
winnstr.3curses			:= LINKSRC = curs_instr.3curses
winstr.3curses			:= LINKSRC = curs_instr.3curses

inswch.3curses			:= LINKSRC = curs_inswch.3curses
mvinswch.3curses		:= LINKSRC = curs_inswch.3curses
mvwinswch.3curses		:= LINKSRC = curs_inswch.3curses
winswch.3curses			:= LINKSRC = curs_inswch.3curses

insnwstr.3curses		:= LINKSRC = curs_inswstr.3curses
inswstr.3curses			:= LINKSRC = curs_inswstr.3curses
mvinsnwstr.3curses		:= LINKSRC = curs_inswstr.3curses
mvinswstr.3curses		:= LINKSRC = curs_inswstr.3curses
mvwinsnwstr.3curses		:= LINKSRC = curs_inswstr.3curses
mvwinswstr.3curses		:= LINKSRC = curs_inswstr.3curses
winsnwstr.3curses		:= LINKSRC = curs_inswstr.3curses
winswstr.3curses		:= LINKSRC = curs_inswstr.3curses

inwch.3curses			:= LINKSRC = curs_inwch.3curses
mvinwch.3curses			:= LINKSRC = curs_inwch.3curses
mvwinwch.3curses		:= LINKSRC = curs_inwch.3curses
winwch.3curses			:= LINKSRC = curs_inwch.3curses

inwchnstr.3curses		:= LINKSRC = curs_inwchstr.3curses
inwchstr.3curses		:= LINKSRC = curs_inwchstr.3curses
mvinwchnstr.3curses		:= LINKSRC = curs_inwchstr.3curses
mvinwchstr.3curses		:= LINKSRC = curs_inwchstr.3curses
mvwinwchnstr.3curses		:= LINKSRC = curs_inwchstr.3curses
mvwinwchstr.3curses		:= LINKSRC = curs_inwchstr.3curses
winwchnstr.3curses		:= LINKSRC = curs_inwchstr.3curses
winwchstr.3curses		:= LINKSRC = curs_inwchstr.3curses

innwstr.3curses			:= LINKSRC = curs_inwstr.3curses
inwstr.3curses			:= LINKSRC = curs_inwstr.3curses
mvinnwstr.3curses		:= LINKSRC = curs_inwstr.3curses
mvinwstr.3curses		:= LINKSRC = curs_inwstr.3curses
mvwinnwstr.3curses		:= LINKSRC = curs_inwstr.3curses
mvwinwstr.3curses		:= LINKSRC = curs_inwstr.3curses
winnwstr.3curses		:= LINKSRC = curs_inwstr.3curses
winwstr.3curses			:= LINKSRC = curs_inwstr.3curses

curs_set.3curses		:= LINKSRC = curs_kernel.3curses
def_prog_mode.3curses		:= LINKSRC = curs_kernel.3curses
def_shell_mode.3curses		:= LINKSRC = curs_kernel.3curses
getsyx.3curses			:= LINKSRC = curs_kernel.3curses
napms.3curses			:= LINKSRC = curs_kernel.3curses
reset_prog_mode.3curses		:= LINKSRC = curs_kernel.3curses
reset_shell_mode.3curses	:= LINKSRC = curs_kernel.3curses
resetty.3curses			:= LINKSRC = curs_kernel.3curses
ripoffline.3curses		:= LINKSRC = curs_kernel.3curses
savetty.3curses			:= LINKSRC = curs_kernel.3curses
setsyx.3curses			:= LINKSRC = curs_kernel.3curses

move.3curses			:= LINKSRC = curs_move.3curses
wmove.3curses			:= LINKSRC = curs_move.3curses

clearok.3curses			:= LINKSRC = curs_outopts.3curses
idcok.3curses			:= LINKSRC = curs_outopts.3curses
idlok.3curses			:= LINKSRC = curs_outopts.3curses
immedok.3curses			:= LINKSRC = curs_outopts.3curses
leaveok.3curses			:= LINKSRC = curs_outopts.3curses
nl.3curses			:= LINKSRC = curs_outopts.3curses
nonl.3curses			:= LINKSRC = curs_outopts.3curses
scrollok.3curses		:= LINKSRC = curs_outopts.3curses
setscrreg.3curses		:= LINKSRC = curs_outopts.3curses
wsetscrreg.3curses		:= LINKSRC = curs_outopts.3curses

copywin.3curses			:= LINKSRC = curs_overlay.3curses
overlay.3curses			:= LINKSRC = curs_overlay.3curses
overwrite.3curses		:= LINKSRC = curs_overlay.3curses

newpad.3curses			:= LINKSRC = curs_pad.3curses
pechochar.3curses		:= LINKSRC = curs_pad.3curses
pechowchar.3curses		:= LINKSRC = curs_pad.3curses
pnoutrefresh.3curses		:= LINKSRC = curs_pad.3curses
prefresh.3curses		:= LINKSRC = curs_pad.3curses
subpad.3curses			:= LINKSRC = curs_pad.3curses

mvprintw.3curses		:= LINKSRC = curs_printw.3curses
mvwprintw.3curses		:= LINKSRC = curs_printw.3curses
printw.3curses			:= LINKSRC = curs_printw.3curses
vwprintw.3curses		:= LINKSRC = curs_printw.3curses
wprintw.3curses			:= LINKSRC = curs_printw.3curses

doupdate.3curses		:= LINKSRC = curs_refresh.3curses
redrawwin.3curses		:= LINKSRC = curs_refresh.3curses
refresh.3curses			:= LINKSRC = curs_refresh.3curses
wnoutrefresh.3curses		:= LINKSRC = curs_refresh.3curses
wredrawln.3curses		:= LINKSRC = curs_refresh.3curses
wrefresh.3curses		:= LINKSRC = curs_refresh.3curses

mvscanw.3curses			:= LINKSRC = curs_scanw.3curses
mvwscanw.3curses		:= LINKSRC = curs_scanw.3curses
scanw.3curses			:= LINKSRC = curs_scanw.3curses
vwscanw.3curses			:= LINKSRC = curs_scanw.3curses
wscanw.3curses			:= LINKSRC = curs_scanw.3curses

scr_dump.3curses		:= LINKSRC = curs_scr_dump.3curses
scr_init.3curses		:= LINKSRC = curs_scr_dump.3curses
scr_restore.3curses		:= LINKSRC = curs_scr_dump.3curses
scr_set.3curses			:= LINKSRC = curs_scr_dump.3curses

scrl.3curses			:= LINKSRC = curs_scroll.3curses
scroll.3curses			:= LINKSRC = curs_scroll.3curses
wscrl.3curses			:= LINKSRC = curs_scroll.3curses

slk_attroff.3curses		:= LINKSRC = curs_slk.3curses
slk_attron.3curses		:= LINKSRC = curs_slk.3curses
slk_attrset.3curses		:= LINKSRC = curs_slk.3curses
slk_clear.3curses		:= LINKSRC = curs_slk.3curses
slk_init.3curses		:= LINKSRC = curs_slk.3curses
slk_label.3curses		:= LINKSRC = curs_slk.3curses
slk_noutrefresh.3curses		:= LINKSRC = curs_slk.3curses
slk_refresh.3curses		:= LINKSRC = curs_slk.3curses
slk_restore.3curses		:= LINKSRC = curs_slk.3curses
slk_set.3curses			:= LINKSRC = curs_slk.3curses
slk_touch.3curses		:= LINKSRC = curs_slk.3curses

baudrate.3curses		:= LINKSRC = curs_termattrs.3curses
erasechar.3curses		:= LINKSRC = curs_termattrs.3curses
has_ic.3curses			:= LINKSRC = curs_termattrs.3curses
has_il.3curses			:= LINKSRC = curs_termattrs.3curses
killchar.3curses		:= LINKSRC = curs_termattrs.3curses
longname.3curses		:= LINKSRC = curs_termattrs.3curses
termattrs.3curses		:= LINKSRC = curs_termattrs.3curses
termname.3curses		:= LINKSRC = curs_termattrs.3curses

tgetent.3curses			:= LINKSRC = curs_termcap.3curses
tgetflag.3curses		:= LINKSRC = curs_termcap.3curses
tgetnum.3curses			:= LINKSRC = curs_termcap.3curses
tgetstr.3curses			:= LINKSRC = curs_termcap.3curses
tgoto.3curses			:= LINKSRC = curs_termcap.3curses

del_curterm.3curses		:= LINKSRC = curs_terminfo.3curses
mvcur.3curses			:= LINKSRC = curs_terminfo.3curses
putp.3curses			:= LINKSRC = curs_terminfo.3curses
restartterm.3curses		:= LINKSRC = curs_terminfo.3curses
set_curterm.3curses		:= LINKSRC = curs_terminfo.3curses
setterm.3curses			:= LINKSRC = curs_terminfo.3curses
setupterm.3curses		:= LINKSRC = curs_terminfo.3curses
tigetflag.3curses		:= LINKSRC = curs_terminfo.3curses
tigetnum.3curses		:= LINKSRC = curs_terminfo.3curses
tigetstr.3curses		:= LINKSRC = curs_terminfo.3curses
tparm.3curses			:= LINKSRC = curs_terminfo.3curses
tputs.3curses			:= LINKSRC = curs_terminfo.3curses
vidattr.3curses			:= LINKSRC = curs_terminfo.3curses
vidputs.3curses			:= LINKSRC = curs_terminfo.3curses

is_linetouched.3curses		:= LINKSRC = curs_touch.3curses
is_wintouched.3curses		:= LINKSRC = curs_touch.3curses
touchline.3curses		:= LINKSRC = curs_touch.3curses
touchwin.3curses		:= LINKSRC = curs_touch.3curses
untouchwin.3curses		:= LINKSRC = curs_touch.3curses
wtouchln.3curses		:= LINKSRC = curs_touch.3curses

delay_output.3curses		:= LINKSRC = curs_util.3curses
filter.3curses			:= LINKSRC = curs_util.3curses
flushinp.3curses		:= LINKSRC = curs_util.3curses
getwin.3curses			:= LINKSRC = curs_util.3curses
keyname.3curses			:= LINKSRC = curs_util.3curses
putwin.3curses			:= LINKSRC = curs_util.3curses
unctrl.3curses			:= LINKSRC = curs_util.3curses
use_env.3curses			:= LINKSRC = curs_util.3curses

delwin.3curses			:= LINKSRC = curs_window.3curses
derwin.3curses			:= LINKSRC = curs_window.3curses
dupwin.3curses			:= LINKSRC = curs_window.3curses
mvderwin.3curses		:= LINKSRC = curs_window.3curses
mvwin.3curses			:= LINKSRC = curs_window.3curses
newwin.3curses			:= LINKSRC = curs_window.3curses
subwin.3curses			:= LINKSRC = curs_window.3curses
syncok.3curses			:= LINKSRC = curs_window.3curses
wcursyncup.3curses		:= LINKSRC = curs_window.3curses
wsyncdown.3curses		:= LINKSRC = curs_window.3curses
wsyncup.3curses			:= LINKSRC = curs_window.3curses

pos_form_cursor.3curses		:= LINKSRC = form_cursor.3curses

data_ahead.3curses		:= LINKSRC = form_data.3curses
data_behind.3curses		:= LINKSRC = form_data.3curses

field_count.3curses		:= LINKSRC = form_field.3curses
form_fields.3curses		:= LINKSRC = form_field.3curses
move_field.3curses		:= LINKSRC = form_field.3curses
set_form_fields.3curses		:= LINKSRC = form_field.3curses

field_back.3curses		:= LINKSRC = form_field_attributes.3curses
field_fore.3curses		:= LINKSRC = form_field_attributes.3curses
field_pad.3curses		:= LINKSRC = form_field_attributes.3curses
set_field_back.3curses		:= LINKSRC = form_field_attributes.3curses
set_field_fore.3curses		:= LINKSRC = form_field_attributes.3curses
set_field_pad.3curses		:= LINKSRC = form_field_attributes.3curses

field_buffer.3curses		:= LINKSRC = form_field_buffer.3curses
field_status.3curses		:= LINKSRC = form_field_buffer.3curses
set_field_buffer.3curses	:= LINKSRC = form_field_buffer.3curses
set_field_status.3curses	:= LINKSRC = form_field_buffer.3curses
set_max_field.3curses		:= LINKSRC = form_field_buffer.3curses

dynamic_field_info.3curses	:= LINKSRC = form_field_info.3curses
field_info.3curses		:= LINKSRC = form_field_info.3curses
field_just.3curses		:= LINKSRC = form_field_just.3curses
set_field_just.3curses		:= LINKSRC = form_field_just.3curses

dup_field.3curses		:= LINKSRC = form_field_new.3curses
free_field.3curses		:= LINKSRC = form_field_new.3curses
link_field.3curses		:= LINKSRC = form_field_new.3curses
new_field.3curses		:= LINKSRC = form_field_new.3curses

field_opts.3curses		:= LINKSRC = form_field_opts.3curses
field_opts_off.3curses		:= LINKSRC = form_field_opts.3curses
field_opts_on.3curses		:= LINKSRC = form_field_opts.3curses
set_field_opts.3curses		:= LINKSRC = form_field_opts.3curses

field_userptr.3curses		:= LINKSRC = form_field_userptr.3curses
set_field_userptr.3curses	:= LINKSRC = form_field_userptr.3curses

field_arg.3curses		:= LINKSRC = form_field_validation.3curses
field_type.3curses		:= LINKSRC = form_field_validation.3curses
set_field_type.3curses		:= LINKSRC = form_field_validation.3curses

free_fieldtype.3curses		:= LINKSRC = form_fieldtype.3curses
link_fieldtype.3curses		:= LINKSRC = form_fieldtype.3curses
new_fieldtype.3curses		:= LINKSRC = form_fieldtype.3curses
set_fieldtype_arg.3curses	:= LINKSRC = form_fieldtype.3curses
set_fieldtype_choice.3curses	:= LINKSRC = form_fieldtype.3curses

field_init.3curses		:= LINKSRC = form_hook.3curses
field_term.3curses		:= LINKSRC = form_hook.3curses
form_init.3curses		:= LINKSRC = form_hook.3curses
form_term.3curses		:= LINKSRC = form_hook.3curses
set_field_init.3curses		:= LINKSRC = form_hook.3curses
set_field_term.3curses		:= LINKSRC = form_hook.3curses
set_form_init.3curses		:= LINKSRC = form_hook.3curses
set_form_term.3curses		:= LINKSRC = form_hook.3curses

free_form.3curses		:= LINKSRC = form_new.3curses
new_form.3curses		:= LINKSRC = form_new.3curses

new_page.3curses		:= LINKSRC = form_new_page.3curses
set_new_page.3curses		:= LINKSRC = form_new_page.3curses

form_opts_off.3curses		:= LINKSRC = form_opts.3curses
form_opts_on.3curses		:= LINKSRC = form_opts.3curses
set_form_opts.3curses		:= LINKSRC = form_opts.3curses

current_field.3curses		:= LINKSRC = form_page.3curses
field_index.3curses		:= LINKSRC = form_page.3curses
set_current_field.3curses	:= LINKSRC = form_page.3curses
set_form_page.3curses		:= LINKSRC = form_page.3curses

post_form.3curses		:= LINKSRC = form_post.3curses
unpost_form.3curses		:= LINKSRC = form_post.3curses

set_form_userptr.3curses	:= LINKSRC = form_userptr.3curses

form_sub.3curses		:= LINKSRC = form_win.3curses
scale_form.3curses		:= LINKSRC = form_win.3curses
set_form_sub.3curses		:= LINKSRC = form_win.3curses
set_form_win.3curses		:= LINKSRC = form_win.3curses

menu_back.3curses		:= LINKSRC = menu_attributes.3curses
menu_fore.3curses		:= LINKSRC = menu_attributes.3curses
menu_grey.3curses		:= LINKSRC = menu_attributes.3curses
menu_pad.3curses		:= LINKSRC = menu_attributes.3curses
set_menu_back.3curses		:= LINKSRC = menu_attributes.3curses
set_menu_fore.3curses		:= LINKSRC = menu_attributes.3curses
set_menu_grey.3curses		:= LINKSRC = menu_attributes.3curses
set_menu_pad.3curses		:= LINKSRC = menu_attributes.3curses

pos_menu_cursor.3curses		:= LINKSRC = menu_cursor.3curses
set_menu_format.3curses		:= LINKSRC = menu_format.3curses

item_init.3curses		:= LINKSRC = menu_hook.3curses
item_term.3curses		:= LINKSRC = menu_hook.3curses
menu_init.3curses		:= LINKSRC = menu_hook.3curses
menu_term.3curses		:= LINKSRC = menu_hook.3curses
set_item_init.3curses		:= LINKSRC = menu_hook.3curses
set_item_term.3curses		:= LINKSRC = menu_hook.3curses
set_menu_init.3curses		:= LINKSRC = menu_hook.3curses
set_menu_term.3curses		:= LINKSRC = menu_hook.3curses

current_item.3curses		:= LINKSRC = menu_item_current.3curses
item_index.3curses		:= LINKSRC = menu_item_current.3curses
set_current_item.3curses	:= LINKSRC = menu_item_current.3curses
set_top_row.3curses		:= LINKSRC = menu_item_current.3curses
top_row.3curses			:= LINKSRC = menu_item_current.3curses

item_description.3curses	:= LINKSRC = menu_item_name.3curses
item_name.3curses		:= LINKSRC = menu_item_name.3curses

free_item.3curses		:= LINKSRC = menu_item_new.3curses
new_item.3curses		:= LINKSRC = menu_item_new.3curses

item_opts.3curses		:= LINKSRC = menu_item_opts.3curses
item_opts_off.3curses		:= LINKSRC = menu_item_opts.3curses
item_opts_on.3curses		:= LINKSRC = menu_item_opts.3curses
set_item_opts.3curses		:= LINKSRC = menu_item_opts.3curses

item_userptr.3curses		:= LINKSRC = menu_item_userptr.3curses
set_item_userptr.3curses	:= LINKSRC = menu_item_userptr.3curses

item_value.3curses		:= LINKSRC = menu_item_value.3curses
set_item_value.3curses		:= LINKSRC = menu_item_value.3curses

item_visible.3curses		:= LINKSRC = menu_item_visible.3curses

item_count.3curses		:= LINKSRC = menu_items.3curses
set_menu_items.3curses		:= LINKSRC = menu_items.3curses

set_menu_mark.3curses		:= LINKSRC = menu_mark.3curses

free_menu.3curses		:= LINKSRC = menu_new.3curses
new_menu.3curses		:= LINKSRC = menu_new.3curses

menu_opts_off.3curses		:= LINKSRC = menu_opts.3curses
menu_opts_on.3curses		:= LINKSRC = menu_opts.3curses
set_menu_opts.3curses		:= LINKSRC = menu_opts.3curses

set_menu_pattern.3curses	:= LINKSRC = menu_pattern.3curses

post_menu.3curses		:= LINKSRC = menu_post.3curses
unpost_menu.3curses		:= LINKSRC = menu_post.3curses

set_menu_userptr.3curses	:= LINKSRC = menu_userptr.3curses

menu_sub.3curses		:= LINKSRC = menu_win.3curses
scale_menu.3curses		:= LINKSRC = menu_win.3curses
set_menu_sub.3curses		:= LINKSRC = menu_win.3curses
set_menu_win.3curses		:= LINKSRC = menu_win.3curses

panel_below.3curses		:= LINKSRC = panel_above.3curses

move_panel.3curses		:= LINKSRC = panel_move.3curses

del_panel.3curses		:= LINKSRC = panel_new.3curses
new_panel.3curses		:= LINKSRC = panel_new.3curses

hide_panel.3curses		:= LINKSRC = panel_show.3curses
panel_hidden.3curses		:= LINKSRC = panel_show.3curses
show_panel.3curses		:= LINKSRC = panel_show.3curses

bottom_panel.3curses		:= LINKSRC = panel_top.3curses
top_panel.3curses		:= LINKSRC = panel_top.3curses

update_panels.3curses		:= LINKSRC = panel_update.3curses

set_panel_userptr.3curses	:= LINKSRC = panel_userptr.3curses

replace_panel.3curses		:= LINKSRC = panel_window.3curses

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
