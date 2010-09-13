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
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* SVr4.0 1.4 */

/*LINTLIBRARY*/

#include <sys/types.h>
#include "utility.h"

typedef struct {
	PTF_int		class;
	PTF_int		act;
} REQUEST;

static REQUEST parse(int);

#define	COMMAND(x)	(x.class)
#define	CALL(x, f)	(x.class ? (*x.class) (x.act, f) : E_SYSTEM_ERROR)

/* command array(carray) order is significant(see form.h REQ_*) */
static REQUEST carray [MAX_FORM_COMMAND - MIN_FORM_COMMAND + 1] =
{
	_page_navigation,	_next_page,	/* REQ_NEXT_PAGE	*/
	_page_navigation,	_prev_page,	/* REQ_PREV_PAGE	*/
	_page_navigation,	_first_page,	/* REQ_FIRST_PAGE	*/
	_page_navigation,	_last_page,	/* REQ_LAST_PAGE	*/

	_field_navigation,	_next_field,	/* REQ_NEXT_FIELD	*/
	_field_navigation,	_prev_field,	/* REQ_PREV_FIELD	*/
	_field_navigation,	_first_field,	/* REQ_FIRST_FIELD	*/
	_field_navigation,	_last_field,	/* REQ_LAST_FIELD	*/
	_field_navigation,	_snext_field,	/* REQ_SNEXT_FIELD	*/
	_field_navigation,	_sprev_field,	/* REQ_SPREV_FIELD	*/
	_field_navigation,	_sfirst_field,	/* REQ_SFIRST_FIELD	*/
	_field_navigation,	_slast_field,	/* REQ_SLAST_FIELD	*/
	_field_navigation,	_left_field,	/* REQ_LEFT_FIELD	*/
	_field_navigation,	_right_field,	/* REQ_RIGHT_FIELD	*/
	_field_navigation,	_up_field,	/* REQ_UP_FIELD		*/
	_field_navigation,	_down_field,	/* REQ_DOWN_FIELD	*/

	_data_navigation,	_next_char,	/* REQ_NEXT_CHAR	*/
	_data_navigation,	_prev_char,	/* REQ_PREV_CHAR	*/
	_data_navigation,	_next_line,	/* REQ_NEXT_LINE	*/
	_data_navigation,	_prev_line,	/* REQ_PREV_LINE	*/
	_data_navigation,	_next_word,	/* REQ_NEXT_WORD	*/
	_data_navigation,	_prev_word,	/* REQ_PREV_WORD	*/
	_data_navigation,	_beg_field,	/* REQ_BEG_FIELD	*/
	_data_navigation,	_end_field,	/* REQ_END_FIELD	*/
	_data_navigation,	_beg_line,	/* REQ_BEG_LINE		*/
	_data_navigation,	_end_line,	/* REQ_END_LINE		*/
	_data_navigation,	_left_char,	/* REQ_LEFT_CHAR	*/
	_data_navigation,	_right_char,	/* REQ_RIGHT_CHAR	*/
	_data_navigation,	_up_char,	/* REQ_UP_CHAR		*/
	_data_navigation,	_down_char,	/* REQ_DOWN_CHAR	*/

	_misc_request,		_new_line,	/* REQ_NEW_LINE		*/
	_data_manipulation,	_ins_char,	/* REQ_INS_CHAR		*/
	_data_manipulation,	_ins_line,	/* REQ_INS_LINE		*/
	_data_manipulation,	_del_char,	/* REQ_DEL_CHAR		*/
	_misc_request,		_del_prev,	/* REQ_DEL_PREV		*/
	_data_manipulation,	_del_line,	/* REQ_DEL_LINE		*/
	_data_manipulation,	_del_word,	/* REQ_DEL_WORD		*/
	_data_manipulation,	_clr_eol,	/* REQ_CLR_EOL		*/
	_data_manipulation,	_clr_eof,	/* REQ_CLR_EOF		*/
	_data_manipulation,	_clr_field,	/* REQ_CLR_FIELD	*/

	_misc_request,		_ovl_mode,	/* REQ_OVL_MODE		*/
	_misc_request,		_ins_mode,	/* REQ_INS_MODE		*/

	_data_navigation,	_scr_fline,	/* REQ_SCR_FLINE	*/
	_data_navigation,	_scr_bline,	/* REQ_SCR_BLINE	*/
	_data_navigation,	_scr_fpage,	/* REQ_SCR_FPAGE	*/
	_data_navigation,	_scr_bpage,	/* REQ_SCR_BPAGE	*/
	_data_navigation,	_scr_fhpage,	/* REQ_SCR_FHPAGE	*/
	_data_navigation,	_scr_bhpage,	/* REQ_SCR_BHPAGE	*/

	_data_navigation,	_scr_fchar,	/* REQ_SCR_FCHAR	*/
	_data_navigation,	_scr_bchar,	/* REQ_SCR_BCHAR	*/
	_data_navigation,	_scr_hfline,	/* REQ_SCR_HFLINE	*/
	_data_navigation,	_scr_hbline,	/* REQ_SCR_HBLINE	*/
	_data_navigation,	_scr_hfhalf,	/* REQ_SCR_HFHALF	*/
	_data_navigation,	_scr_hbhalf,	/* REQ_SCR_HBHALF	*/

	_misc_request,		_validation,	/* REQ_VALIDATION	*/
	_misc_request,		_next_choice,	/* REQ_NEXT_CHOICE	*/
	_misc_request,		_prev_choice,	/* REQ_PREV_CHOICE	*/
};

static REQUEST FAIL = { (PTF_int) 0, (PTF_int) 0 };

/* _page_navigation - service page navigation request */
int
_page_navigation(PTF_int act, FORM *f)
{
	int v;

	if (_validate(f)) {
		term_field(f);
		term_form(f);
		v = (*act) (f);
		init_form(f);
		init_field(f);
	} else
		v = E_INVALID_FIELD;

	return (v);
}

/* _field_navigation - service inter-field navigation request */
int
_field_navigation(PTF_int act, FORM *f)
{
	int v;

	if (_validate(f)) {
		term_field(f);
		v = (*act) (f);
		init_field(f);
	} else
		v = E_INVALID_FIELD;

	return (v);
}

/* _data_navigation - service intra-field navagation request */
int
_data_navigation(PTF_int act, FORM *f)
{
	return ((*act) (f));
}

/* _data_manipulation - service data modification request */
int
_data_manipulation(PTF_int act, FORM *f)
{
	int		v = E_REQUEST_DENIED;
	FIELD *		c = C(f);

	if (Opt(c, O_EDIT))
		if ((v = (*act) (f)) == E_OK)
			Set(f, WIN_CHG);
	return (v);
}

int
_misc_request(PTF_int act, FORM *f)
{
	return ((*act) (f));
}

int
form_driver(FORM *f, int c)
{
	int		v;
	REQUEST		x;

	if (f) {
		if (Status(f, DRIVER))

			v = E_BAD_STATE;

		else if (Status(f, POSTED)) {
			x = parse(c);

			if (COMMAND(x))
				v = CALL(x, f);
			else {
				if (isascii(c) && isprint(c) &&
				    CheckChar(C(f), c))
					v = _data_entry(f, c);
				else
					v = E_UNKNOWN_COMMAND;
			}
			(void) _update_current(f);
		} else
			v = E_NOT_POSTED;
	} else
		v = E_BAD_ARGUMENT;

	return (v);
}

static REQUEST
parse(int c)
{
	if (c < MIN_FORM_COMMAND || c > MAX_FORM_COMMAND)
		return (FAIL);

	return (carray[c - MIN_FORM_COMMAND]);
}
