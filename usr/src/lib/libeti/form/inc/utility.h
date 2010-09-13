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


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_UTILITY_H
#define	_UTILITY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/

#include <form.h>
#include <memory.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* miscellaneous #defines */
typedef	int		BOOLEAN;

#define	MIN(x, y)		((x) < (y) ? (x) : (y))

/* form status flags */
#define	POSTED			0x0001	/* posted flag			*/
#define	DRIVER			0x0002	/* inside init/term routine	*/
#define	OVERLAY			0x0004	/* insert/overlay mode		*/
#define	WIN_CHG			0x0010	/* window change (system flag)	*/
#define	BUF_CHG			0x0020	/* buffer change (system flag)	*/
/* field status flags */
#define	USR_CHG			0x0001	/* buffer change (user's flag)	*/
#define	TOP_CHG			0x0002	/* toprow change (system flag)	*/
#define	NEW_PAGE		0x0004	/* new page (system flag)	*/
#define	GROWABLE		0x0008	/* growable page (system flag)	*/
/* field type status flags */
#define	LINKED			0x0001	/* conjunctive field type	*/
#define	ARGS			0x0002	/* has additional arguments	*/
#define	CHOICE			0x0004	/* has choice functions		*/
/* form/field/fieldtype status manipulation macros */
#define	Status(f, s)		((f) -> status & (s))
#define	Set(f, s)		((f) -> status |= (s))
#define	Clr(f, s)		((f) -> status &= ~(s))
/* form/field option manipulation macros */
#define	Opt(f, x)		((f) -> opts & (x))
/* alloc/free with check */
#define	Alloc(x, t)		((x = (t *) malloc(sizeof (t))) != (t *)0)
#define	arrayAlloc(x, n, t)	((x = (t *) malloc((n) * sizeof (t))) != \
				(t *)0)
#define	Free(x)			{ if (x) free(x); }
/* field type macros */
#define	MakeArg(f, p, err)	(_makearg((f) -> type, p, err))
#define	CopyArg(f, err)		(_copyarg((f) -> type, (f) -> arg, err))
#define	FreeArg(f)		(_freearg((f) -> type, (f) -> arg))
#define	CheckField(f)		(_checkfield((f) -> type, (f), (f) -> arg))
#define	CheckChar(f, c)		(_checkchar((f) -> type, (c), (f) -> arg))
#define	NextChoice(f)		(_nextchoice((f) -> type, (f), (f) -> arg))
#define	PrevChoice(f)		(_prevchoice((f) -> type, (f), (f) -> arg))
#define	IncrType(type)		{ if (type) ++(type -> ref); }
#define	DecrType(type)		{ if (type) --(type -> ref); }
/* form/field init/term calls */
#define	init_field(f)		{					\
					if ((f) -> fieldinit)		\
					{				\
						Set(f, DRIVER);	\
						(*(f) -> fieldinit)(f);	\
						Clr(f, DRIVER);	\
					}				\
				}
#define	term_field(f)		{					\
					if ((f) -> fieldterm)		\
					{				\
						Set(f, DRIVER);	\
						(*(f) -> fieldterm)(f);	\
						Clr(f, DRIVER);	\
					}				\
				}
#define	init_form(f)		{					\
					if ((f) -> forminit)		\
					{				\
						Set(f, DRIVER);	\
						(*(f) -> forminit)(f);	\
						Clr(f, DRIVER);	\
					}				\
				}
#define	term_form(f)		{					\
					if ((f) -> formterm)		\
					{				\
						Set(f, DRIVER);	\
						(*(f) -> formterm)(f);	\
						Clr(f, DRIVER);	\
					}				\
				}
/* page macros */
#define	P(f)			((f) -> curpage)
#define	Pmin(f, p)		((f) -> page [p].pmin)
#define	Pmax(f, p)		((f) -> page [p].pmax)
#define	Smin(f,	p)		((f) -> page [p].smin)
#define	Smax(f, p)		((f) -> page [p].smax)
/* form macros */
#define	Form(f)			((f) ? (f) : _DEFAULT_FORM)
#define	ValidIndex(f, i)	((i) >= 0 && (i) < (f) -> maxfield)
#define	ValidPage(f, i)		((i) >= 0 && (i) < (f) -> maxpage)
#define	C(f)			((f) -> current)
#define	W(f)			((f) -> w)
#define	X(f)			((f) -> curcol)
#define	Y(f)			((f) -> currow)
#define	T(f)			((f) -> toprow)
#define	B(f)			((f) -> begincol)
#define	Xmax(f)			(C(f) -> dcols)
#define	Ymax(f)			(C(f) -> drows)
#define	Win(f)			((f) -> win ? (f) -> win : stdscr)
#define	Sub(f)			((f) -> sub ? (f) -> sub : Win(f))
/* field macros */
#define	Field(f)		((f) ? (f) : _DEFAULT_FIELD)
#define	Buf(f)			((f) -> buf)
#define	OneRow(f)		((f)->rows + (f)->nrow == 1)
#define	GrowSize(f)		(((f) -> rows + (f) -> nrow) * (f) -> cols)
#define	BufSize(f)		((f) -> drows  * (f) -> dcols)
#define	Buffer(f, n)		(Buf(f) + (n) * (BufSize(f) + 1))
#define	LineBuf(f, n)		(Buf(f) + (n) * (f) -> dcols)
#define	TotalBuf(f)		((BufSize(f) + 1) * ((f) -> nbuf + 1))
#define	Just(f)			((f) -> just)
#define	Fore(f)			((f) -> fore)
#define	Back(f)			((f) -> back)
#define	Pad(f)			((f) -> pad)
/* system externs */
extern int	_next_page(FORM *);		/* REQ_NEXT_PAGE	*/
extern int	_prev_page(FORM *);		/* REQ_PREV_PAGE	*/
extern int	_first_page(FORM *);		/* REQ_FIRST_PAGE	*/
extern int	_last_page(FORM *);		/* REQ_LAST_PAGE	*/

extern int	_next_field(FORM *);		/* REQ_NEXT_FIELD	*/
extern int	_prev_field(FORM *);		/* REQ_PREV_FIELD	*/
extern int	_first_field(FORM *);		/* REQ_FIRST_FIELD	*/
extern int	_last_field(FORM *);		/* REQ_LAST_FIELD	*/
extern int	_snext_field(FORM *);		/* REQ_SNEXT_FIELD	*/
extern int	_sprev_field(FORM *);		/* REQ_SPREV_FIELD	*/
extern int	_sfirst_field(FORM *);		/* REQ_SFIRST_FIELD	*/
extern int	_slast_field(FORM *);		/* REQ_SLAST_FIELD	*/
extern int	_left_field(FORM *);		/* REQ_LEFT_FIELD	*/
extern int	_right_field(FORM *);		/* REQ_RIGHT_FIELD	*/
extern int	_up_field(FORM *);		/* REQ_UP_FIELD		*/
extern int	_down_field(FORM *);		/* REQ_DOWN_FIELD	*/

extern int	_next_char(FORM *);		/* REQ_NEXT_CHAR	*/
extern int	_prev_char(FORM *);		/* REQ_PREV_CHAR	*/
extern int	_next_line(FORM *);		/* REQ_NEXT_LINE	*/
extern int	_prev_line(FORM *);		/* REQ_PREV_LINE	*/
extern int	_next_word(FORM *);		/* REQ_NEXT_WORD	*/
extern int	_prev_word(FORM *);		/* REQ_PREV_WORD	*/
extern int	_beg_field(FORM *);		/* REQ_BEG_FIELD	*/
extern int	_end_field(FORM *);		/* REQ_END_FIELD	*/
extern int	_beg_line(FORM *);		/* REQ_BEG_LINE		*/
extern int	_end_line(FORM *);		/* REQ_END_LINE		*/
extern int	_left_char(FORM *);		/* REQ_LEFT_CHAR	*/
extern int	_right_char(FORM *);		/* REQ_RIGHT_CHAR	*/
extern int	_up_char(FORM *);		/* REQ_UP_CHAR		*/
extern int	_down_char(FORM *);		/* REQ_DOWN_CHAR	*/

extern int	_new_line(FORM *);		/* REQ_NEW_LINE		*/
extern int	_ins_char(FORM *);		/* REQ_INS_CHAR		*/
extern int	_ins_line(FORM *);		/* REQ_INS_LINE		*/
extern int	_del_char(FORM *);		/* REQ_DEL_CHAR		*/
extern int	_del_prev(FORM *);		/* REQ_DEL_PREV		*/
extern int	_del_line(FORM *);		/* REQ_DEL_LINE		*/
extern int	_del_word(FORM *);		/* REQ_DEL_WORD		*/
extern int	_clr_eol(FORM *);		/* REQ_CLR_EOL		*/
extern int	_clr_eof(FORM *);		/* REQ_CLR_EOF		*/
extern int	_clr_field(FORM *);		/* REQ_CLR_FIELD	*/
extern int	_ovl_mode(FORM *);		/* REQ_OVL_MODE		*/
extern int	_ins_mode(FORM *);		/* REQ_INS_MODE		*/
extern int	_scr_fline(FORM *);		/* REQ_SCR_FLINE	*/
extern int	_scr_bline(FORM *);		/* REQ_SCR_BLINE	*/
extern int	_scr_fpage(FORM *);		/* REQ_SCR_FPAGE	*/
extern int	_scr_fhpage(FORM *);		/* REQ_SCR_FHPAGE	*/
extern int	_scr_bpage(FORM *);		/* REQ_SCR_BPAGE	*/
extern int	_scr_bhpage(FORM *);		/* REQ_SCR_BHPAGE	*/

extern int	_scr_fchar(FORM *);		/* REQ_SCR_FCHAR	*/
extern int	_scr_bchar(FORM *);		/* REQ_SCR_BCHAR	*/
extern int	_scr_hfline(FORM *);		/* REQ_SCR_HFLINE	*/
extern int	_scr_hbline(FORM *);		/* REQ_SCR_HBLINE	*/
extern int	_scr_hfhalf(FORM *);		/* REQ_SCR_HFHALF	*/
extern int	_scr_hbhalf(FORM *);		/* REQ_SCR_HBHALF	*/

extern int	_validation(FORM *);		/* REQ_VALIDATION	*/
extern int	_next_choice(FORM *);		/* REQ_NEXT_CHOICE	*/
extern int	_prev_choice(FORM *);		/* REQ_PREV_CHOICE	*/

extern char *	_makearg(FIELDTYPE *, va_list *, int *);
extern char *	_copyarg(FIELDTYPE *, char *, int *);
extern void	_freearg(FIELDTYPE *,  char *);
extern int	_checkfield(FIELDTYPE *, FIELD *, char *);
extern int	_checkchar(FIELDTYPE *, int, char *);
extern int	_nextchoice(FIELDTYPE *, FIELD *, char *);
extern int	_prevchoice(FIELDTYPE *, FIELD *, char *);

extern BOOLEAN	_grow_field(FIELD *, int);
extern FIELD *	_first_active(FORM *);
extern char *	_data_beg(char *, int);
extern char *	_data_end(char *, int);
extern char *	_whsp_beg(char *, int);
extern char *	_whsp_end(char *, int);
extern void	_buf_to_win(FIELD *, WINDOW *);
extern void	_win_to_buf(WINDOW *, FIELD *);
extern void	_adjust_cursor(FORM *, char *);
extern void	_sync_buffer(FORM *);
extern int	_sync_linked(FIELD *);
extern int	_sync_field(FIELD *);
extern int	_sync_attrs(FIELD *);
extern int	_sync_opts(FIELD *, OPTIONS);
extern int	_validate(FORM *);
extern int	_set_current_field(FORM *, FIELD *);
extern int	_set_form_page(FORM *, int, FIELD *);
extern int	_pos_form_cursor(FORM *);
extern int	_update_current(FORM *);
extern int	_data_entry(FORM *, int);
extern int	_page_navigation(PTF_int, FORM *);
extern int	_field_navigation(PTF_int, FORM *);
extern int	_data_navigation(PTF_int, FORM *);
extern int	_data_manipulation(PTF_int, FORM *);
extern int	_misc_request(PTF_int, FORM *);

extern intptr_t	__execute(char *, char *);
extern intptr_t	__advance(char *, char *);
extern intptr_t	__xpop(intptr_t);
extern intptr_t	__xpush(intptr_t, char *);
extern intptr_t	__getrnge(intptr_t *, intptr_t *, char *);
extern intptr_t	__cclass(char *, char, intptr_t);
extern int	__size(char *);
extern int	__rpush(char *);
extern intptr_t	__rpop(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _UTILITY_H */
