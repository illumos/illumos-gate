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
# lib/libeti/form/spec/form.spec

function	current_field
include		<form.h>
declaration	FIELD *current_field(FORM*form)
version		SUNW_1.1
end		

function	data_ahead
include		<form.h>
declaration	int data_ahead(FORM *form)
version		SUNW_1.1
end		

function	data_behind
include		<form.h>
declaration	int data_behind(FORM *form)
version		SUNW_1.1
end		

function	dup_field
include		<form.h>
declaration	FIELD *dup_field(FIELD *field, int frow, int fcol)
version		SUNW_1.1
end		

function	dynamic_field_info
include		<form.h>
declaration	int dynamic_field_info(FIELD *field, int *drows, \
		    int *dcols, int *max)
version		SUNW_1.1
end		

function	field_arg
include		<form.h>
declaration	char *field_arg(FIELD *field)
version		SUNW_1.1
end		

function	field_back
include		<form.h>
declaration	chtype field_back(FIELD *field)
version		SUNW_1.1
end		

function	field_buffer
include		<form.h>
declaration	char *field_buffer(FIELD *field, int buf)
version		SUNW_1.1
end		

function	field_count
include		<form.h>
declaration	int field_count(FORM *form)
version		SUNW_1.1
end		

function	field_fore
include		<form.h>
declaration	chtype field_fore(FIELD *field)
version		SUNW_1.1
end		

function	field_index
include		<form.h>
declaration	int field_index(FIELD *field)
version		SUNW_1.1
end		

function	field_info
include		<form.h>
declaration	int field_info(FIELD  *field,  int  *rows,  int  *cols, \
		    int *frow, int *fcol, int *nrow, int *nbuf)
version		SUNW_1.1
end		

function	field_init
include		<form.h>
declaration	PTF_void field_init(FORM *form)
version		SUNW_1.1
end		

function	field_just
include		<form.h>
declaration	int field_just(FIELD *field);
version		SUNW_1.1
end		

function	field_opts
include		<form.h>
declaration	OPTIONS field_opts(FIELD *field)
version		SUNW_1.1
end		

function	field_opts_off
include		<form.h>
declaration	int field_opts_off(FIELD *field, OPTIONS opts)
version		SUNW_1.1
end		

function	field_opts_on
include		<form.h>
declaration	int field_opts_on(FIELD *field, OPTIONS opts)
version		SUNW_1.1
end		

function	field_pad
include		<form.h>
declaration	int field_pad(FIELD *field)
version		SUNW_1.1
end		

function	field_status
include		<form.h>
declaration	int field_status(FIELD *field)
version		SUNW_1.1
end		

function	field_term
include		<form.h>
declaration	PTF_void field_term(FORM *form)
version		SUNW_1.1
end		

function	field_type
include		<form.h>
declaration	FIELDTYPE *field_type(FIELD *field)
version		SUNW_1.1
end		

function	field_userptr
include		<form.h>
declaration	char *field_userptr(FIELD *field)
version		SUNW_1.1
end		

function	form_driver
include		<form.h>
declaration	int form_driver(FORM *form, int c)
version		SUNW_1.1
end		

function	form_fields
include		<form.h>
declaration	FIELD **form_fields(FORM *form)
version		SUNW_1.1
end		

function	form_init
include		<form.h>
declaration	PTF_void	form_init(FORM *form)
version		SUNW_1.1
end		

function	form_opts
include		<form.h>
declaration	OPTIONS form_opts(FORM *form)
version		SUNW_1.1
end		

function	form_opts_off
include		<form.h>
declaration	int form_opts_off(FORM *form, OPTIONS opts)
version		SUNW_1.1
end		

function	form_opts_on
include		<form.h>
declaration	int form_opts_on(FORM *form, OPTIONS opts)
version		SUNW_1.1
end		

function	form_page
include		<form.h>
declaration	int form_page(FORM *form)
version		SUNW_1.1
end		

function	form_sub
include		<form.h>
declaration	WINDOW *form_sub(FORM *form)
version		SUNW_1.1
end		

function	form_term
include		<form.h>
declaration	PTF_void form_term(FORM *form)
version		SUNW_1.1
end		

function	form_userptr
include		<form.h>
declaration	char *form_userptr(FORM *form)
version		SUNW_1.1
end		

function	form_win
include		<form.h>
declaration	WINDOW *form_win(FORM *form)
version		SUNW_1.1
end		

function	free_field
include		<form.h>
declaration	int free_field(FIELD *field)
version		SUNW_1.1
end		

function	free_fieldtype
include		<form.h>
declaration	int free_fieldtype(FIELDTYPE *fieldtype)
version		SUNW_1.1
end		

function	free_form
include		<form.h>
declaration	int free_form(FORM *form)
version		SUNW_1.1
end		

function	link_field
include		<form.h>
declaration	FIELD *link_field(FIELD *field, int frow, int fcol)
version		SUNW_1.1
end		

function	link_fieldtype
include		<form.h>
declaration	FIELDTYPE *link_fieldtype(FIELDTYPE *type1, FIELDTYPE *type2)
version		SUNW_1.1
end		

function	move_field
include		<form.h>
declaration	int move_field(FIELD *field, int frow, int fcol)
version		SUNW_1.1
end		

function	new_field
include		<form.h>
declaration	FIELD *new_field(int r, int c, int frow, int fcol, \
		    int nrow, int ncol)
version		SUNW_1.1
end		

function	new_fieldtype
include		<form.h>
declaration	FIELDTYPE *new_fieldtype(int (* field_check)(FIELD *, \
		    char *), int (* char_check)(int, char *))
version		SUNW_1.1
end		

function	new_form
include		<form.h>
declaration	FORM *new_form(FIELD **fields)
version		SUNW_1.1
end		

function	new_page
include		<form.h>
declaration	int new_page(FIELD *field)
version		SUNW_1.1
end		

function	pos_form_cursor
include		<form.h>
declaration	int pos_form_cursor(FORM *form)
version		SUNW_1.1
end		

function	post_form
include		<form.h>
declaration	int post_form(FORM *form)
version		SUNW_1.1
end		

function	scale_form
include		<form.h>
declaration	int scale_form(FORM *form, int *rows, int *cols)
version		SUNW_1.1
end		

function	set_current_field
include		<form.h>
declaration	int set_current_field(FORM *form, FIELD *field)
version		SUNW_1.1
end		

function	set_field_back
include		<form.h>
declaration	int set_field_back(FIELD *field, chtype attr)
version		SUNW_1.1
end		

function	set_field_buffer
include		<form.h>
declaration	int set_field_buffer(FIELD *field, int buf, char *value)
version		SUNW_1.1
end		

function	set_field_fore
include		<form.h>
declaration	int set_field_fore(FIELD *field, chtype attr)
version		SUNW_1.1
end		

function	set_field_init
include		<form.h>
declaration	int set_field_init(FORM *form, void (*func)(FORM*))
version		SUNW_1.1
end		

function	set_field_just
include		<form.h>
declaration	int set_field_just(FIELD *field, int justification)
version		SUNW_1.1
end		

function	set_field_opts
include		<form.h>
declaration	int set_field_opts(FIELD *field, OPTIONS opts)
version		SUNW_1.1
end		

function	set_field_pad
include		<form.h>
declaration	int set_field_pad(FIELD *field, int pad)
version		SUNW_1.1
end		

function	set_field_status
include		<form.h>
declaration	int set_field_status(FIELD *field, int status)
version		SUNW_1.1
end		

function	set_field_term
include		<form.h>
declaration	int set_field_term(FORM *form, void (*func)(FORM*))
version		SUNW_1.1
end		

function	set_field_type
include		<form.h>
declaration	int set_field_type(FIELD *field, FIELDTYPE *type, ...)
version		SUNW_1.1
end		

function	set_field_userptr
include		<form.h>
declaration	int set_field_userptr(FIELD *field, char *ptr)
version		SUNW_1.1
end		

function	set_fieldtype_arg
include		<form.h>
declaration	int set_fieldtype_arg(FIELDTYPE *fieldtype, \
		    char *(* mak_arg)(va_list  *), \
		    char  *(*  copy_arg)(char *), \
		    void (* free_arg)(char *))
version		SUNW_1.1
end		

function	set_fieldtype_choice
include		<form.h>
declaration	int set_fieldtype_choice(FIELDTYPE *fieldtype, \
		    int (* next_choice)(FIELD  *, char *), \
		    int (* prev_choice)(FIELD *, char *))
version		SUNW_1.1
end		

function	set_form_fields
include		<form.h>
declaration	int set_form_fields(FORM *form, FIELD **field)
version		SUNW_1.1
end		

function	set_form_init
include		<form.h>
declaration	int set_form_init(FORM *form, void (*func)(FORM*))
version		SUNW_1.1
end		

function	set_form_opts
include		<form.h>
declaration	int set_form_opts(FORM *form, OPTIONS opts)
version		SUNW_1.1
end		

function	set_form_page
include		<form.h>
declaration	int set_form_page(FORM *form, int page)
version		SUNW_1.1
end		

function	set_form_sub
include		<form.h>
declaration	int set_form_sub(FORM *form, WINDOW *sub)
version		SUNW_1.1
end		

function	set_form_term
include		<form.h>
declaration	int set_form_term(FORM *form, void (*func)(FORM*))
version		SUNW_1.1
end		

function	set_form_userptr
include		<form.h>
declaration	int set_form_userptr(FORM *form, char *ptr)
version		SUNW_1.1
end		

function	set_form_win
include		<form.h>
declaration	int set_form_win(FORM *form, WINDOW *win)
version		SUNW_1.1
end		

function	set_max_field
include		<form.h>
declaration	int set_max_field(FIELD *field, int max)
version		SUNW_1.1
end		

function	set_new_page
include		<form.h>
declaration	int set_new_page(FIELD *field, int bool)
version		SUNW_1.1
end		

function	unpost_form
include		<form.h>
declaration	int unpost_form(FORM *form)
version		SUNW_1.1
end		

function	__advance
version		SUNWprivate_1.1
end		

function	__braelist
version		SUNWprivate_1.1
end		

function	__braslist
version		SUNWprivate_1.1
end		

function	__bravar
version		SUNWprivate_1.1
end		

function	__cclass
version		SUNWprivate_1.1
end		

function	__cflg
version		SUNWprivate_1.1
end		

function	__eptr_
version		SUNWprivate_1.1
end		

function	__execute
version		SUNWprivate_1.1
end		

function	__getrnge
version		SUNWprivate_1.1
end		

function	__i_size
version		SUNWprivate_1.1
end		

function	__loc1
version		SUNWprivate_1.1
end		

function	__lptr_
version		SUNWprivate_1.1
end		

function	__rpop
version		SUNWprivate_1.1
end		

function	__rpush
version		SUNWprivate_1.1
end		

function	__size
version		SUNWprivate_1.1
end		

function	__sp_
version		SUNWprivate_1.1
end		

function	__st
version		SUNWprivate_1.1
end		

function	__stmax
version		SUNWprivate_1.1
end		

function	__xpop
version		SUNWprivate_1.1
end		

function	__xpush
version		SUNWprivate_1.1
end		

function	_adjust_cursor
version		SUNWprivate_1.1
end		

function	_beg_field
version		SUNWprivate_1.1
end		

function	_beg_line
version		SUNWprivate_1.1
end		

function	_buf_to_win
version		SUNWprivate_1.1
end		

function	_checkchar
version		SUNWprivate_1.1
end		

function	_checkfield
version		SUNWprivate_1.1
end		

function	_clr_eof
version		SUNWprivate_1.1
end		

function	_clr_eol
version		SUNWprivate_1.1
end		

function	_clr_field
version		SUNWprivate_1.1
end		

function	_copyarg
version		SUNWprivate_1.1
end		

function	_data_beg
version		SUNWprivate_1.1
end		

function	_data_end
version		SUNWprivate_1.1
end		

function	_data_entry
version		SUNWprivate_1.1
end		

function	_data_manipulation
version		SUNWprivate_1.1
end		

function	_data_navigation
version		SUNWprivate_1.1
end		

function	_DEFAULT_FIELD
version		SUNWprivate_1.1
end		

function	_DEFAULT_FIELDTYPE
version		SUNWprivate_1.1
end		

function	_DEFAULT_FORM
version		SUNWprivate_1.1
end		

function	_del_char
version		SUNWprivate_1.1
end		

function	_del_line
version		SUNWprivate_1.1
end		

function	_del_prev
version		SUNWprivate_1.1
end		

function	_del_word
version		SUNWprivate_1.1
end		

function	_down_char
version		SUNWprivate_1.1
end		

function	_down_field
version		SUNWprivate_1.1
end		

function	_end_field
version		SUNWprivate_1.1
end		

function	_end_line
version		SUNWprivate_1.1
end		

function	_field_navigation
version		SUNWprivate_1.1
end		

function	_first_active
version		SUNWprivate_1.1
end		

function	_first_field
version		SUNWprivate_1.1
end		

function	_first_page
version		SUNWprivate_1.1
end		

function	_freearg
version		SUNWprivate_1.1
end		

function	_grow_field
version		SUNWprivate_1.1
end		

function	_ins_char
version		SUNWprivate_1.1
end		

function	_ins_line
version		SUNWprivate_1.1
end		

function	_ins_mode
version		SUNWprivate_1.1
end		

function	_last_field
version		SUNWprivate_1.1
end		

function	_last_page
version		SUNWprivate_1.1
end		

function	_left_char
version		SUNWprivate_1.1
end		

function	_left_field
version		SUNWprivate_1.1
end		

function	_lib_version
version		SUNWprivate_1.1
end		

function	_makearg
version		SUNWprivate_1.1
end		

function	_misc_request
version		SUNWprivate_1.1
end		

function	_new_line
version		SUNWprivate_1.1
end		

function	_next_char
version		SUNWprivate_1.1
end		

function	_next_choice
version		SUNWprivate_1.1
end		

function	_next_field
version		SUNWprivate_1.1
end		

function	_next_line
version		SUNWprivate_1.1
end		

function	_next_page
version		SUNWprivate_1.1
end		

function	_next_word
version		SUNWprivate_1.1
end		

function	_nextchoice
version		SUNWprivate_1.1
end		

function	_ovl_mode
version		SUNWprivate_1.1
end		

function	_page_navigation
version		SUNWprivate_1.1
end		

function	_pos_form_cursor
version		SUNWprivate_1.1
end		

function	_prev_char
version		SUNWprivate_1.1
end		

function	_prev_choice
version		SUNWprivate_1.1
end		

function	_prev_field
version		SUNWprivate_1.1
end		

function	_prev_line
version		SUNWprivate_1.1
end		

function	_prev_page
version		SUNWprivate_1.1
end		

function	_prev_word
version		SUNWprivate_1.1
end		

function	_prevchoice
version		SUNWprivate_1.1
end		

function	_right_char
version		SUNWprivate_1.1
end		

function	_right_field
version		SUNWprivate_1.1
end		

function	_scr_bchar
version		SUNWprivate_1.1
end		

function	_scr_bhpage
version		SUNWprivate_1.1
end		

function	_scr_bline
version		SUNWprivate_1.1
end		

function	_scr_bpage
version		SUNWprivate_1.1
end		

function	_scr_fchar
version		SUNWprivate_1.1
end		

function	_scr_fhpage
version		SUNWprivate_1.1
end		

function	_scr_fline
version		SUNWprivate_1.1
end		

function	_scr_fpage
version		SUNWprivate_1.1
end		

function	_scr_hbhalf
version		SUNWprivate_1.1
end		

function	_scr_hbline
version		SUNWprivate_1.1
end		

function	_scr_hfhalf
version		SUNWprivate_1.1
end		

function	_scr_hfline
version		SUNWprivate_1.1
end		

function	_set_current_field
version		SUNWprivate_1.1
end		

function	_set_form_page
version		SUNWprivate_1.1
end		

function	_sfirst_field
version		SUNWprivate_1.1
end		

function	_slast_field
version		SUNWprivate_1.1
end		

function	_snext_field
version		SUNWprivate_1.1
end		

function	_sprev_field
version		SUNWprivate_1.1
end		

function	_sync_attrs
version		SUNWprivate_1.1
end		

function	_sync_buffer
version		SUNWprivate_1.1
end		

function	_sync_field
version		SUNWprivate_1.1
end		

function	_sync_linked
version		SUNWprivate_1.1
end		

function	_sync_opts
version		SUNWprivate_1.1
end		

function	_up_char
version		SUNWprivate_1.1
end		

function	_up_field
version		SUNWprivate_1.1
end		

function	_update_current
version		SUNWprivate_1.1
end		

function	_validate
version		SUNWprivate_1.1
end		

function	_validation
version		SUNWprivate_1.1
end		

function	_whsp_beg
version		SUNWprivate_1.1
end		

function	_whsp_end
version		SUNWprivate_1.1
end		

function	_win_to_buf
version		SUNWprivate_1.1
end		

function	TYPE_ALNUM
version		SUNWprivate_1.1
end		

function	TYPE_ALPHA
version		SUNWprivate_1.1
end		

function	TYPE_ENUM
version		SUNWprivate_1.1
end		

function	TYPE_INTEGER
version		SUNWprivate_1.1
end		

function	TYPE_NUMERIC
version		SUNWprivate_1.1
end		

function	TYPE_REGEXP
version		SUNWprivate_1.1
end		

