#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libeti/menu/spec/menu.spec

function	current_item
include		<menu.h>
declaration	ITEM *current_item(MENU *menu)
version		SUNW_1.1
end		

function	free_item
include		<menu.h>
declaration	int free_item(ITEM *item)
version		SUNW_1.1
end		

function	free_menu
include		<menu.h>
declaration	int free_menu(MENU *menu)
version		SUNW_1.1
end		

function	item_count
include		<menu.h>
declaration	int item_count(MENU *menu)
version		SUNW_1.1
end		

function	item_description
include		<menu.h>
declaration	char *item_description(ITEM *item)
version		SUNW_1.1
end		

function	item_index
include		<menu.h>
declaration	int item_index(ITEM *item)
version		SUNW_1.1
end		

function	item_init
include		<menu.h>
declaration	PTF_void item_init(MENU *menu)
version		SUNW_1.1
end		

function	item_name
include		<menu.h>
declaration	char *item_name(ITEM *item)
version		SUNW_1.1
end		

function	item_opts
include		<menu.h>
declaration	OPTIONS item_opts(ITEM *item)
version		SUNW_1.1
end		

function	item_opts_off
include		<menu.h>
declaration	int item_opts_off(ITEM *item, OPTIONS opts)
version		SUNW_1.1
end		

function	item_opts_on
include		<menu.h>
declaration	int item_opts_on(ITEM *item, OPTIONS opts)
version		SUNW_1.1
end		

function	item_term
include		<menu.h>
declaration	PTF_void item_term(MENU *menu)
version		SUNW_1.1
end		

function	item_userptr
include		<menu.h>
declaration	char *item_userptr(ITEM *item)
version		SUNW_1.1
end		

function	item_value
include		<menu.h>
declaration	int item_value(ITEM *item)
version		SUNW_1.1
end		

function	item_visible
include		<menu.h>
declaration	int item_visible(ITEM *item)
version		SUNW_1.1
end		

function	menu_back
include		<menu.h>
declaration	chtype menu_back(MENU *menu)
version		SUNW_1.1
end		

function	menu_driver
include		<menu.h>
declaration	int menu_driver(MENU *menu, int c)	
version		SUNW_1.1
end		

function	menu_fore
include		<menu.h>
declaration	chtype menu_fore(MENU *menu)
version		SUNW_1.1
end		

function	menu_format
include		<menu.h>
declaration	void menu_format(MENU *menu, int *rows, int *cols)
version		SUNW_1.1
end		

function	menu_grey
include		<menu.h>
declaration	chtype menu_grey(MENU *menu)
version		SUNW_1.1
end		

function	menu_init
include		<menu.h>
declaration	PTF_void menu_init(MENU *menu)
version		SUNW_1.1
end		

function	menu_items
include		<menu.h>
declaration	ITEM **menu_items(MENU *menu)
version		SUNW_1.1
end		

function	menu_mark
include		<menu.h>
declaration	char *menu_mark(MENU *menu)
version		SUNW_1.1
end		

function	menu_opts
include		<menu.h>
declaration	OPTIONS menu_opts(MENU *menu)
version		SUNW_1.1
end		

function	menu_opts_off
include		<menu.h>
declaration	int menu_opts_off(MENU *menu, OPTIONS opts)
version		SUNW_1.1
end		

function	menu_opts_on
include		<menu.h>
declaration	int menu_opts_on(MENU *menu, OPTIONS opts)
version		SUNW_1.1
end		

function	menu_pad
include		<menu.h>
declaration	int menu_pad(MENU *menu)
version		SUNW_1.1
end		

function	menu_pattern
include		<menu.h>
declaration	char *menu_pattern(MENU *menu)
version		SUNW_1.1
end		

function	menu_sub
include		<menu.h>
declaration	WINDOW *menu_sub(MENU *menu)
version		SUNW_1.1
end		

function	menu_term
include		<menu.h>
declaration	PTF_void menu_term(MENU *menu)
version		SUNW_1.1
end		

function	menu_userptr
include		<menu.h>
declaration	char *menu_userptr(MENU *menu)
version		SUNW_1.1
end		

function	menu_win
include		<menu.h>
declaration	WINDOW *menu_win(MENU *menu)
version		SUNW_1.1
end		

function	new_item
include		<menu.h>
declaration	ITEM *new_item(char *name, char *desc)
version		SUNW_1.1
end		

function	new_menu
include		<menu.h>
declaration	MENU *new_menu(ITEM **items)
version		SUNW_1.1
end		

function	pos_menu_cursor
include		<menu.h>
declaration	int pos_menu_cursor(MENU *menu)	
version		SUNW_1.1
end		

function	post_menu
include		<menu.h>
declaration	int post_menu(MENU *menu)
version		SUNW_1.1
end		

function	scale_menu
include		<menu.h>
declaration	int scale_menu(MENU *menu, int *rows, int *cols)
version		SUNW_1.1
end		

function	set_current_item
include		<menu.h>
declaration	int set_current_item(MENU *menu, ITEM *item)
version		SUNW_1.1
end		

function	set_item_init
include		<menu.h>
declaration	int set_item_init(MENU *menu, void (*func)(MENU *))
version		SUNW_1.1
end		

function	set_item_opts
include		<menu.h>
declaration	int set_item_opts(ITEM *item, OPTIONS opts)
version		SUNW_1.1
end		

function	set_item_term
include		<menu.h>
declaration	int set_item_term(MENU *menu, void (*func)(MENU *))
version		SUNW_1.1
end		

function	set_item_userptr
include		<menu.h>
declaration	int set_item_userptr(ITEM *item, char *userptr)
version		SUNW_1.1
end		

function	set_item_value
include		<menu.h>
declaration	int set_item_value(ITEM *item, int bool)
version		SUNW_1.1
end		

function	set_menu_back
include		<menu.h>
declaration	int set_menu_back(MENU *menu, chtype attr)
version		SUNW_1.1
end		

function	set_menu_fore
include		<menu.h>
declaration	int set_menu_fore(MENU *menu, chtype attr)
version		SUNW_1.1
end		

function	set_menu_format
include		<menu.h>
declaration	int set_menu_format(MENU *menu, int rows, int cols)
version		SUNW_1.1
end		

function	set_menu_grey
include		<menu.h>
declaration	int set_menu_grey(MENU*menu, chtype attr)
version		SUNW_1.1
end		

function	set_menu_init
include		<menu.h>
declaration	int set_menu_init(MENU  *menu,  void  (*func)(MENU  *))
version		SUNW_1.1
end		

function	set_menu_items
include		<menu.h>
declaration	int set_menu_items(MENU *menu, ITEM **items)
version		SUNW_1.1
end		

function	set_menu_mark
include		<menu.h>
declaration	int set_menu_mark(MENU *menu, char *mark)
version		SUNW_1.1
end		

function	set_menu_opts
include		<menu.h>
declaration	int set_menu_opts(MENU *menu, OPTIONS opts)
version		SUNW_1.1
end		

function	set_menu_pad
include		<menu.h>
declaration	int set_menu_pad(MENU *menu, int pad)
version		SUNW_1.1
end		

function	set_menu_pattern
include		<menu.h>
declaration	int set_menu_pattern(MENU *menu, char *pat)
version		SUNW_1.1
end		

function	set_menu_sub
include		<menu.h>
declaration	int set_menu_sub(MENU *menu, WINDOW *sub)
version		SUNW_1.1
end		

function	set_menu_term
include		<menu.h>
declaration	int set_menu_term(MENU  *menu,  void  (*func)(MENU  *))
version		SUNW_1.1
end		

function	set_menu_userptr
include		<menu.h>
declaration	int set_menu_userptr(MENU *menu, char *userptr)
version		SUNW_1.1
end		

function	set_menu_win
include		<menu.h>
declaration	int set_menu_win(MENU *menu, WINDOW *win)
version		SUNW_1.1
end		

function	set_top_row
include		<menu.h>
declaration	int set_top_row(MENU *menu, int row)
version		SUNW_1.1
end		

function	top_row
include		<menu.h>
declaration	int top_row(MENU *menu)
version		SUNW_1.1
end		

function	unpost_menu
include		<menu.h>
declaration	int unpost_menu(MENU *menu)
version		SUNW_1.1
end		

function	_affect_change
version		SUNWprivate_1.1
end		

function	_chk_current
version		SUNWprivate_1.1
end		

function	_chk_top
version		SUNWprivate_1.1
end		

function	_connect
version		SUNWprivate_1.1
end		

function	_Default_Item
version		SUNWprivate_1.1
end		

function	_Default_Menu
version		SUNWprivate_1.1
end		

function	_disconnect
version		SUNWprivate_1.1
end		

function	_draw
version		SUNWprivate_1.1
end		

function	_lib_version
version		SUNWprivate_1.1
end		

function	_link_items
version		SUNWprivate_1.1
end		

function	_match
version		SUNWprivate_1.1
end		

function	_move_post_item
version		SUNWprivate_1.1
end		

function	_movecurrent
version		SUNWprivate_1.1
end		

function	_position_cursor
version		SUNWprivate_1.1
end		

function	_post_item
version		SUNWprivate_1.1
end		

function	_scale
version		SUNWprivate_1.1
end		

function	_show
version		SUNWprivate_1.1
end		

