/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _FORM_H
#define	_FORM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.10	*/

#include <curses.h>
#include <eti.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * FIELDTYPE
 */

typedef struct typenode {

	int			status;		/* flags		*/
	int			ref;		/* reference count	*/
	struct typenode *	left;		/* ptr to operand for |	*/
	struct typenode *	right;		/* ptr to operand for |	*/
	PTF_charP		makearg;	/* make fieldtype arg	*/
	PTF_charP		copyarg;	/* copy fieldtype arg	*/
	PTF_void		freearg;	/* free fieldtype arg	*/
	PTF_int			fcheck;		/* field validation	*/
	PTF_int			ccheck;		/* character validation	*/
	PTF_int			next;		/* enumerate next value	*/
	PTF_int			prev;		/* enumerate prev value	*/
}
	FIELDTYPE;

/*
 * _PAGE
 */

typedef struct {

	int			pmin;		/* first field on page	*/
	int			pmax;		/* last field on page	*/
	int			smin;		/* top leftmost field	*/
	int			smax;		/* bottom rightmost	*/
}
	_PAGE;

/*
 * FIELD
 */

typedef struct fieldnode {

	int			status;		/* flags		*/
	int			rows;		/* size in rows		*/
	int			cols;		/* size in cols		*/
	int			frow;		/* first row		*/
	int			fcol;		/* first col		*/
	int			drows;		/* dynamic rows		*/
	int			dcols;		/* dynamic cols		*/
	int			maxgrow;	/* maximum field growth */
	int			nrow;		/* offscreen rows	*/
	int			nbuf;		/* additional buffers	*/
	int			just;		/* justification	*/
	int			page;		/* page on form		*/
	int			index;		/* into form -> field	*/
	int			pad;		/* pad character	*/
	chtype			fore;		/* foreground attribute	*/
	chtype			back;		/* background attribute	*/
	OPTIONS			opts;		/* options		*/
	struct fieldnode *	snext;		/* sorted order pointer	*/
	struct fieldnode *	sprev;		/* sorted order pointer	*/
	struct fieldnode *	link;		/* linked field chain	*/
	struct formnode *	form;		/* containing form	*/
	FIELDTYPE *		type;		/* field type		*/
	char *			arg;		/* argument for type	*/
	char *			buf;		/* field buffers	*/
	char *			usrptr;		/* user pointer		*/
}
	FIELD;

/*
 * FORM
 */

typedef struct formnode {

	int			status;		/* flags		*/
	int			rows;		/* size in rows		*/
	int			cols;		/* size in cols		*/
	int			currow;		/* current row		*/
	int			curcol;		/* current col		*/
	int			toprow;		/* in vertically	*/
						/* scrollable field	*/
	int			begincol;	/* in horizontally	*/
						/* scrollable field	*/
	int			maxfield;	/* number of fields	*/
	int			maxpage;	/* number of pages	*/
	int			curpage;	/* index into page	*/
	OPTIONS			opts;		/* options		*/
	WINDOW *		win;		/* window		*/
	WINDOW *		sub;		/* subwindow		*/
	WINDOW *		w;		/* window		*/
	FIELD **		field;		/* field [maxfield]	*/
	FIELD *			current;	/* current field	*/
	_PAGE *			page;		/* page [maxpage]	*/
	char *			usrptr;		/* user pointer		*/
	PTF_void		forminit;	/* user function	*/
	PTF_void		formterm;	/* user function	*/
	PTF_void		fieldinit;	/* user function	*/
	PTF_void		fieldterm;	/* user function	*/
}
	FORM;

/*
 * miscellaneous #defines
 */

/*
 *	field justification
 */
#define	NO_JUSTIFICATION	0
#define	JUSTIFY_LEFT		1
#define	JUSTIFY_CENTER		2
#define	JUSTIFY_RIGHT		3
/*
 *	field options
 */
#define	O_VISIBLE		0x0001
#define	O_ACTIVE		0x0002
#define	O_PUBLIC		0x0004
#define	O_EDIT			0x0008
#define	O_WRAP			0x0010
#define	O_BLANK			0x0020
#define	O_AUTOSKIP		0x0040
#define	O_NULLOK		0x0080
#define	O_PASSOK		0x0100
#define	O_STATIC		0x0200
/*
 *	form options
 */
#define	O_NL_OVERLOAD		0x0001
#define	O_BS_OVERLOAD		0x0002
/*
 *	form driver commands
 */
#define	REQ_NEXT_PAGE	(KEY_MAX + 1)	/* move to next page		*/
#define	REQ_PREV_PAGE	(KEY_MAX + 2)	/* move to previous page	*/
#define	REQ_FIRST_PAGE	(KEY_MAX + 3)	/* move to first page		*/
#define	REQ_LAST_PAGE	(KEY_MAX + 4)	/* move to last page		*/

#define	REQ_NEXT_FIELD	(KEY_MAX + 5)	/* move to next field		*/
#define	REQ_PREV_FIELD	(KEY_MAX + 6)	/* move to previous field	*/
#define	REQ_FIRST_FIELD	(KEY_MAX + 7)	/* move to first field		*/
#define	REQ_LAST_FIELD	(KEY_MAX + 8)	/* move to last field		*/
#define	REQ_SNEXT_FIELD	(KEY_MAX + 9)	/* move to sorted next field	*/
#define	REQ_SPREV_FIELD	(KEY_MAX + 10)	/* move to sorted prev field	*/
#define	REQ_SFIRST_FIELD (KEY_MAX + 11)	/* move to sorted first field	*/
#define	REQ_SLAST_FIELD	(KEY_MAX + 12)	/* move to sorted last field	*/
#define	REQ_LEFT_FIELD	(KEY_MAX + 13)	/* move to left to field	*/
#define	REQ_RIGHT_FIELD	(KEY_MAX + 14)	/* move to right to field	*/
#define	REQ_UP_FIELD	(KEY_MAX + 15)	/* move to up to field		*/
#define	REQ_DOWN_FIELD	(KEY_MAX + 16)	/* move to down to field	*/

#define	REQ_NEXT_CHAR	(KEY_MAX + 17)	/* move to next char in field	*/
#define	REQ_PREV_CHAR	(KEY_MAX + 18)	/* move to prev char in field	*/
#define	REQ_NEXT_LINE	(KEY_MAX + 19)	/* move to next line in field	*/
#define	REQ_PREV_LINE	(KEY_MAX + 20)	/* move to prev line in field	*/
#define	REQ_NEXT_WORD	(KEY_MAX + 21)	/* move to next word in field	*/
#define	REQ_PREV_WORD	(KEY_MAX + 22)	/* move to prev word in field	*/
#define	REQ_BEG_FIELD	(KEY_MAX + 23)	/* move to first char in field	*/
#define	REQ_END_FIELD	(KEY_MAX + 24)	/* move after last char in fld	*/
#define	REQ_BEG_LINE	(KEY_MAX + 25)	/* move to beginning of line	*/
#define	REQ_END_LINE	(KEY_MAX + 26)	/* move after last char in line	*/
#define	REQ_LEFT_CHAR	(KEY_MAX + 27)	/* move left in field		*/
#define	REQ_RIGHT_CHAR	(KEY_MAX + 28)	/* move right in field		*/
#define	REQ_UP_CHAR	(KEY_MAX + 29)	/* move up in field		*/
#define	REQ_DOWN_CHAR	(KEY_MAX + 30)	/* move down in field		*/

#define	REQ_NEW_LINE	(KEY_MAX + 31)	/* insert/overlay new line	*/
#define	REQ_INS_CHAR	(KEY_MAX + 32)	/* insert blank char at cursor	*/
#define	REQ_INS_LINE	(KEY_MAX + 33)	/* insert blank line at cursor	*/
#define	REQ_DEL_CHAR	(KEY_MAX + 34)	/* delete char at cursor	*/
#define	REQ_DEL_PREV	(KEY_MAX + 35)	/* delete char before cursor	*/
#define	REQ_DEL_LINE	(KEY_MAX + 36)	/* delete line at cursor	*/
#define	REQ_DEL_WORD	(KEY_MAX + 37)	/* delete line at cursor	*/
#define	REQ_CLR_EOL	(KEY_MAX + 38)	/* clear to end of line		*/
#define	REQ_CLR_EOF	(KEY_MAX + 39)	/* clear to end of field	*/
#define	REQ_CLR_FIELD	(KEY_MAX + 40)	/* clear entire field		*/
#define	REQ_OVL_MODE	(KEY_MAX + 41)	/* begin overlay mode		*/
#define	REQ_INS_MODE	(KEY_MAX + 42)	/* begin insert mode		*/

#define	REQ_SCR_FLINE	(KEY_MAX + 43)	/* scroll field forward a line	*/
#define	REQ_SCR_BLINE	(KEY_MAX + 44)	/* scroll field backward a line	*/
#define	REQ_SCR_FPAGE	(KEY_MAX + 45)	/* scroll field forward a page	*/
#define	REQ_SCR_BPAGE	(KEY_MAX + 46)	/* scroll field backward a page	*/
#define	REQ_SCR_FHPAGE	(KEY_MAX + 47)	/* scroll field forward half page */
#define	REQ_SCR_BHPAGE	(KEY_MAX + 48)	/* scroll field backward half page */

#define	REQ_SCR_FCHAR	(KEY_MAX + 49)	/* horizontal scroll char */
#define	REQ_SCR_BCHAR	(KEY_MAX + 50)	/* horizontal scroll char */
#define	REQ_SCR_HFLINE	(KEY_MAX + 51)	/* horizontal scroll line */
#define	REQ_SCR_HBLINE	(KEY_MAX + 52)	/* horizontal scroll line */
#define	REQ_SCR_HFHALF	(KEY_MAX + 53)	/* horizontal scroll half line */
#define	REQ_SCR_HBHALF	(KEY_MAX + 54)	/* horizontal scroll half line */

#define	REQ_VALIDATION	(KEY_MAX + 55)	/* validate field		*/
#define	REQ_NEXT_CHOICE	(KEY_MAX + 56)	/* display next field choice	*/
#define	REQ_PREV_CHOICE	(KEY_MAX + 57)	/* display prev field choice	*/

#define	MIN_FORM_COMMAND (KEY_MAX + 1)	/* used by form_driver		*/
#define	MAX_FORM_COMMAND (KEY_MAX + 57)	/* used by form_driver		*/

/*
 *  standard field types
 */

extern FIELDTYPE *	TYPE_ALPHA;
extern FIELDTYPE *	TYPE_ALNUM;
extern FIELDTYPE *	TYPE_ENUM;
extern FIELDTYPE *	TYPE_INTEGER;
extern FIELDTYPE *	TYPE_NUMERIC;
extern FIELDTYPE *	TYPE_REGEXP;

/*
 *  default objects
 */

extern FORM *		_DEFAULT_FORM;
extern FIELD *		_DEFAULT_FIELD;

#ifdef __STDC__

/*
 *  FIELDTYPE routines
 */

extern FIELDTYPE *	new_fieldtype(PTF_int, PTF_int);
extern FIELDTYPE *	link_fieldtype(FIELDTYPE *, FIELDTYPE *);
extern int		free_fieldtype(FIELDTYPE *);
extern int		set_fieldtype_arg(FIELDTYPE *, PTF_charP,
					    PTF_charP, PTF_void);
extern int		set_fieldtype_choice(FIELDTYPE *, PTF_int, PTF_int);

/*
 *  FIELD routines
 */

extern FIELD *		new_field(int, int, int, int, int, int);
extern FIELD *		dup_field(FIELD *, int, int);
extern FIELD *		link_field(FIELD *, int, int);
extern int		free_field(FIELD *);
extern int		field_info(FIELD *, int *, int *, int *, int *,
			    int *, int *);
extern int		dynamic_field_info(FIELD *, int *, int *, int *);
extern int		set_max_field(FIELD *, int);
extern int		move_field(FIELD *, int, int);
extern int		set_field_type(FIELD *, FIELDTYPE *, ...);
extern FIELDTYPE *	field_type(FIELD *);
extern char *		field_arg(FIELD *);
extern int		set_new_page(FIELD *, int);
extern int		new_page(FIELD *);
extern int		set_field_just(FIELD *, int);
extern int		field_just(FIELD *);
extern int		set_field_fore(FIELD *, chtype);
extern chtype		field_fore(FIELD *);
extern int		set_field_back(FIELD *, chtype);
extern chtype		field_back(FIELD *);
extern int		set_field_pad(FIELD *, int);
extern int		field_pad(FIELD *);
extern int		set_field_buffer(FIELD *, int, char *);
extern char *		field_buffer(FIELD *, int);
extern int		set_field_status(FIELD *, int);
extern int		field_status(FIELD *);
extern int		set_field_userptr(FIELD *, char *);
extern char *		field_userptr(FIELD *);
extern int		set_field_opts(FIELD *, OPTIONS);
extern OPTIONS		field_opts(FIELD *);
extern int		field_opts_on(FIELD *, OPTIONS);
extern int		field_opts_off(FIELD *, OPTIONS);
extern int		field_index(FIELD *);

/*
 *  FORM routines
 */

extern FORM *		new_form(FIELD **);
extern int		free_form(FORM *);
extern int		set_form_fields(FORM *, FIELD **);
extern FIELD **		form_fields(FORM *);
extern int		field_count(FORM *);
extern int		set_form_win(FORM *, WINDOW *);
extern WINDOW *		form_win(FORM *);
extern int		set_form_sub(FORM *, WINDOW *);
extern WINDOW *		form_sub(FORM *);
extern int		set_current_field(FORM *, FIELD *);
extern FIELD *		current_field(FORM *);
extern int		set_form_page(FORM *, int);
extern int		form_page(FORM *);
extern int		scale_form(FORM *, int *, int *);
extern int		set_form_init(FORM *, PTF_void);
extern PTF_void		form_init(FORM *);
extern int		set_form_term(FORM *, PTF_void);
extern PTF_void		form_term(FORM *);
extern int		set_field_init(FORM *, PTF_void);
extern PTF_void		field_init(FORM *);
extern int		set_field_term(FORM *, PTF_void);
extern PTF_void		field_term(FORM *);
extern int		post_form(FORM *);
extern int		unpost_form(FORM *);
extern int		pos_form_cursor(FORM *);
extern int		form_driver(FORM *, int);
extern int		set_form_userptr(FORM *, char *);
extern char *		form_userptr(FORM *);
extern int		set_form_opts(FORM *, OPTIONS);
extern OPTIONS		form_opts(FORM *);
extern int		form_opts_on(FORM *, OPTIONS);
extern int		form_opts_off(FORM *, OPTIONS);
extern int		data_ahead(FORM *);
extern int		data_behind(FORM *);

#else	/* old style extern's */

/*
 *  FIELDTYPE routines
 */

extern FIELDTYPE *	new_fieldtype();
extern FIELDTYPE *	link_fieldtype();
extern int		free_fieldtype();
extern int		set_fieldtype_arg();
extern int		set_fieldtype_choice();

/*
 *  FIELD routines
 */

extern FIELD *		new_field();
extern FIELD *		dup_field();
extern FIELD *		link_field();
extern int		free_field();
extern int		field_info();
extern int		dynamic_field_info();
extern int		set_max_field();
extern int		move_field();
extern int		set_field_type();
extern FIELDTYPE *	field_type();
extern char *		field_arg();
extern int		set_new_page();
extern int		new_page();
extern int		set_field_just();
extern int		field_just();
extern int		set_field_fore();
extern chtype		field_fore();
extern int		set_field_back();
extern chtype		field_back();
extern int		set_field_pad();
extern int		field_pad();
extern int		set_field_buffer();
extern char *		field_buffer();
extern int		set_field_status();
extern int		field_status();
extern int		set_field_userptr();
extern char *		field_userptr();
extern int		set_field_opts();
extern OPTIONS		field_opts();
extern int		field_opts_on();
extern int		field_opts_off();
extern int		field_index();

/*
 *  FORM routines
 */

extern FORM *		new_form();
extern int		free_form();
extern int		set_form_fields();
extern FIELD **		form_fields();
extern int		field_count();
extern int		set_form_win();
extern WINDOW *		form_win();
extern int		set_form_sub();
extern WINDOW *		form_sub();
extern int		set_current_field();
extern FIELD *		current_field();
extern int		set_form_page();
extern int		form_page();
extern int		scale_form();
extern int		set_form_init();
extern PTF_void		form_init();
extern int		set_form_term();
extern PTF_void		form_term();
extern int		set_field_init();
extern PTF_void		field_init();
extern int		set_field_term();
extern PTF_void		field_term();
extern int		post_form();
extern int		unpost_form();
extern int		pos_form_cursor();
extern int		form_driver();
extern int		set_form_userptr();
extern char *		form_userptr();
extern int		set_form_opts();
extern OPTIONS		form_opts();
extern int		form_opts_on();
extern int		form_opts_off();
extern int		data_ahead();
extern int		data_behind();

#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _FORM_H */
