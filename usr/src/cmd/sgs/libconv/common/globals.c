/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<strings.h>
#include	<_machelf.h>
#include	"_conv.h"
#include	"globals_msg.h"


/*
 * Given an integer value, generate an ASCII representation of it.
 *
 * entry:
 *	inv_buf - Buffer into which the resulting string is generated.
 *	value - Value to be formatted.
 *	fmt_flags - CONV_FMT_* values, used to specify formatting details.
 *
 * exit:
 *	The formatted string is placed into inv_buf. The pointer
 *	to the string is returned.
 */
const char *
conv_invalid_val(Conv_inv_buf_t *inv_buf, Xword value,
    Conv_fmt_flags_t fmt_flags)
{
	const char	*fmt;

	if (fmt_flags & CONV_FMT_DECIMAL) {
		if (fmt_flags & CONV_FMT_SPACE)
			fmt = MSG_ORIG(MSG_GBL_FMT_DECS);
		else
			fmt = MSG_ORIG(MSG_GBL_FMT_DEC);
	} else {
		if (fmt_flags & CONV_FMT_SPACE)
			fmt = MSG_ORIG(MSG_GBL_FMT_HEXS);
		else
			fmt = MSG_ORIG(MSG_GBL_FMT_HEX);
	}
	(void) snprintf(inv_buf->buf, sizeof (inv_buf->buf), fmt, value);
	return ((const char *)inv_buf->buf);
}



/*
 * cef_cp() is used by conv_expn_field() to fill in the output buffer.
 * A CONV_EXPN_FIELD_STATE variable is used to maintain the buffer state
 * as the operation progresses.
 *
 * entry:
 *	arg - As passed to conv_expn_field().
 *	state - Variable used to maintain buffer state between calls.
 *	list_item - TRUE(1) if this is a list item, and FALSE(0)
 *		if it is something else.
 *	str - String to be added to the buffer.
 *
 * exit:
 *	On Success:
 *		buffer contains the output string, including a list
 *		separator if appropriate. state has been updated.
 *		TRUE(1) is returned.
 *	On Failure:
 *		Buffer contains the numeric representation for the flags,
 *		and FALSE(0) is returned.
 */
typedef struct {
	char *cur;		/* Current output position in buf */
	size_t room;		/* # of bytes left in buf */
	int list_cnt;		/* # of list items output into buf  */
	const char *sep_str;	/* String used as list separator */
	int sep_str_len;	/* strlen(sep_str) */
} CONV_EXPN_FIELD_STATE;

static int
cef_cp(CONV_EXPN_FIELD_ARG *arg, CONV_EXPN_FIELD_STATE *state,
	int list_item, const char *str)
{
	Conv_inv_buf_t inv_buf;
	int n;

	if (list_item) {	/* This is a list item */
		/*
		 * If list is non-empty, and the buffer has room,
		 * then insert the separator.
		 */
		if (state->list_cnt != 0) {
			if (state->sep_str_len < state->room) {
				(void) memcpy(state->cur, state->sep_str,
				    state->sep_str_len);
				state->cur += state->sep_str_len;
				state->room -= state->sep_str_len;
			} else {
				/* Ensure code below will catch lack of room */
				state->room = 0;
			}
		}
		state->list_cnt++;
	}

	n = strlen(str);
	if (n < state->room) {
		(void) memcpy(state->cur, str, n);
		state->cur += n;
		state->room -= n;
		return (TRUE);
	}

	/* Buffer too small. Fill in the numeric value and report failure */
	(void) conv_invalid_val(&inv_buf, arg->oflags, 0);
	(void) strlcpy(arg->buf, inv_buf.buf, arg->bufsize);
	return (FALSE);
}



/*
 * Provide a focal point for expanding bit-fields values into
 * their corresponding strings.
 *
 * entry:
 *	arg - Specifies the operation to be carried out. See the
 *		definition of CONV_EXPN_FIELD_ARG in conv.h for details.
 *
 * exit:
 *	arg->buf contains the formatted result. True (1) is returned if there
 *	was no error, and False (0) if the buffer was too small. In the failure
 *	case, arg->buf contains a numeric representation of the value.
 */
int
conv_expn_field(CONV_EXPN_FIELD_ARG *arg, Conv_fmt_flags_t fmt_flags)
{
	const Val_desc *vde;
	CONV_EXPN_FIELD_STATE state;
	Xword rflags = arg->rflags;
	const char **lead_str;


	/* Initialize buffer state */
	state.cur = arg->buf;
	state.room = arg->bufsize;
	state.list_cnt = 0;
	state.sep_str = arg->sep ? arg->sep : MSG_ORIG(MSG_GBL_SEP);
	state.sep_str_len = strlen(state.sep_str);

	/* Prefix string */
	if ((fmt_flags & CONV_FMT_NOBKT) == 0)
		if (!cef_cp(arg, &state, FALSE,
		    (arg->prefix ? arg->prefix : MSG_ORIG(MSG_GBL_OSQBRKT))))
			return (FALSE);

	/* Any strings in the lead_str array go at the head of the list */
	lead_str = arg->lead_str;
	if (lead_str) {
		while (*lead_str) {
			if (!cef_cp(arg, &state, TRUE, *lead_str++))
				return (FALSE);
		}
	}

	/*
	 * Traverse the callers Val_desc array and determine if the value
	 * corresponds to any array item and add those that are to the list.
	 */
	for (vde = arg->vdp; vde->v_msg; vde++) {
		if (arg->oflags & vde->v_val) {
			if (!cef_cp(arg, &state, TRUE, vde->v_msg))
				return (FALSE);

			/* Indicate this item has been collected */
			rflags &= ~(vde->v_val);
		}
	}

	/*
	 * If any flags remain, then they are unidentified.  Add the numeric
	 * representation of these flags to the users output buffer.
	 */
	if (rflags) {
		Conv_inv_buf_t inv_buf;

		(void) conv_invalid_val(&inv_buf, rflags, fmt_flags);
		if (!cef_cp(arg, &state, TRUE, inv_buf.buf))
			return (FALSE);
	}

	/* Suffix string */
	if ((fmt_flags & CONV_FMT_NOBKT) == 0)
		if (!cef_cp(arg, &state, FALSE,
		    (arg->suffix ? arg->suffix : MSG_ORIG(MSG_GBL_CSQBRKT))))
			return (FALSE);

	/* Terminate the buffer */
	*state.cur = '\0';

	return (TRUE);
}
