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
/*
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * vid_puts.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/vid_puts.c 1.6 1998/05/28 14:22:43 "
"cbates Exp $";
#endif
#endif

#include <private.h>

static attr_t	turn_off(int (*)(int), attr_t);
static attr_t	turn_on(int (*)(int), attr_t);

/*
 * Return true if attribute X a member of the attribute set A.
 * no_color_video is the set of attributes that cannot be combined
 * with colours.
 */
#define	ISATTR(a, x)	(((a) & ~no_color_video & (x)) == (x))

/*
 * Set the desired attribute state for a terminal screen.
 *
 * Using set_attributes is the prefered method but requires some care
 * in writing the proper terminfo string.  Using exit_attribute_mode and
 * the assorted enter_ attribute mode capabilities is the next best method.
 * Finally using the assorted exit_ and enter_ attribute mode capabilities
 * is the last method available and is not necessarily efficent (or smart
 * because of the needs of ceol_standout_glitch support).
 */
/* ARGSUSED */
int
vid_puts(attr_t attr, short pair, void *opts, int (*putout)(int))
{
	long	p1, p2, p3, p4, p5, p6, p7, p8, p9;

	if (set_attributes != NULL && ATTR_STATE != attr) {
		/*
		 * Assume that <set_attributes> disables attributes
		 * then re-enables attributes that are to be on.
		 */
		p1 = (long) ISATTR(attr, WA_STANDOUT);
		p2 = (long) ISATTR(attr, WA_UNDERLINE);
		p3 = (long) ISATTR(attr, WA_REVERSE);
		p4 = (long) ISATTR(attr, WA_BLINK);
		p5 = (long) ISATTR(attr, WA_DIM);
		p6 = (long) ISATTR(attr, WA_BOLD);
		p7 = (long) ISATTR(attr, WA_INVIS);
		p8 = (long) ISATTR(attr, WA_PROTECT);
		p9 = (long) ISATTR(attr, WA_ALTCHARSET);

		(void) TPUTS(tparm(set_attributes,
			p1, p2, p3, p4, p5, p6, p7, p8, p9),
			1, putout);

		ATTR_STATE &= ~WA_SGR_MASK;
		ATTR_STATE |= attr & WA_SGR_MASK;

		/*
		 * Only use <set_a_attributes> when <set_attributes>
		 * is defined.  <set_a_attributes> should not disable
		 * attributes, as this will have been handled by
		 * <set_attributes>.
		 * NOT TRUE - C. Bates
		 */
		if (set_a_attributes != NULL) {
			p1 = (long) ISATTR(attr, WA_HORIZONTAL);
			p2 = (long) ISATTR(attr, WA_LEFT);
			p3 = (long) ISATTR(attr, WA_LOW);
			p4 = (long) ISATTR(attr, WA_RIGHT);
			p5 = (long) ISATTR(attr, WA_TOP);
			p6 = (long) ISATTR(attr, WA_VERTICAL);

			(void) TPUTS(tparm(set_a_attributes,
				p1, p2, p3, p4, p5, p6, 0L, 0L, 0L),
				1, putout);

			ATTR_STATE &= ~WA_SGR1_MASK;
			ATTR_STATE |= attr & WA_SGR1_MASK;
		}
	} else if (ATTR_STATE != attr) {
		/* Turn off only those attributes that are on. */
		(void) turn_off(putout, ATTR_STATE);

		/*
		 * Turn on attributes regardless if they are already
		 * on, because terminals with ceol_standout_glitch, like
		 * HP terminals, will have to re-enforce the current
		 * attributes in order to change existing attribute
		 * cookies on the screen.
		 */
		ATTR_STATE = turn_on(putout, attr);
	}

	/*
	 * A_NORMAL equals 0, which is all attributes off and
	 * COLOR_PAIR(0).  This implies that colour pair 0 is
	 * the orig_pair.
	 */
	if (pair == 0) {
		if (orig_pair != NULL) {
			(void) TPUTS(orig_pair, 1, putout);
		}

		pair = 0;
	} else if (pair != cur_term->_co && 0 < max_colors) {
		short	fg, bg;

		if (set_color_pair != NULL) {
			(void) TPUTS(tparm(set_color_pair, (long) pair,
				0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L),
				1, putout);
		} else if (pair_content(pair, &fg, &bg) == OK) {
			if (set_a_foreground != NULL) {
				(void) TPUTS(tparm(set_a_foreground, (long) fg,
					0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L),
					1, putout);
			} else if (set_foreground != NULL) {
				(void) TPUTS(tparm(set_foreground, (long) fg,
					0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L),
					1, putout);
			}

			if (set_a_background != NULL) {
				(void) TPUTS(tparm(set_a_background, (long) bg,
					0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L),
					1, putout);
			} else if (set_background != NULL) {
				(void) TPUTS(tparm(set_background, (long) bg,
					0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L),
					1, putout);
			}
		}
	}

	/* Remember the current attribute state for the terminal. */
	ATTR_STATE = attr;
	cur_term->_co = pair;

	return (OK);
}

static attr_t
turn_off(int (*putout)(int), attr_t attr)
{
	attr_t	new = attr;

	if (exit_attribute_mode != NULL) {
		(void) TPUTS(exit_attribute_mode, 1, putout);
		new = WA_NORMAL;
	} else {
		if (ISATTR(attr, WA_UNDERLINE) &&
			exit_underline_mode != NULL) {
			(void) TPUTS(exit_underline_mode, 1, putout);
			new &= ~WA_UNDERLINE;
		}

		if (ISATTR(attr, WA_STANDOUT) &&
			exit_standout_mode != NULL) {
			(void) TPUTS(exit_standout_mode, 1, putout);
			new &= ~WA_STANDOUT;
		}

		if (ISATTR(attr, WA_ALTCHARSET) &&
			exit_alt_charset_mode != NULL) {
			(void) TPUTS(exit_alt_charset_mode, 1, putout);
			new &= ~WA_ALTCHARSET;
		}
	}

	return (new);
}

static attr_t
turn_on(int (*putout)(int), attr_t attr)
{
	attr_t	new = attr;

	if (ISATTR(attr, WA_ALTCHARSET) &&
		enter_alt_charset_mode != NULL) {
		(void) TPUTS(enter_alt_charset_mode, 1, putout);
		new |= WA_ALTCHARSET;
	}

	if (ISATTR(attr, WA_BLINK) &&
		enter_blink_mode != NULL) {
		(void) TPUTS(enter_blink_mode, 1, putout);
		new |= WA_BLINK;
	}

	if (ISATTR(attr, WA_BOLD) &&
		enter_bold_mode != NULL) {
		(void) TPUTS(enter_bold_mode, 1, putout);
		new |= WA_BOLD;
	}

	if (ISATTR(attr, WA_INVIS) &&
		enter_secure_mode != NULL) {
		(void) TPUTS(enter_secure_mode, 1, putout);
		new |= WA_INVIS;
	}

	if (ISATTR(attr, WA_DIM) &&
		enter_dim_mode != NULL) {
		(void) TPUTS(enter_dim_mode, 1, putout);
		new |= WA_DIM;
	}

	if (ISATTR(attr, WA_PROTECT) &&
		enter_protected_mode != NULL) {
		(void) TPUTS(enter_protected_mode, 1, putout);
		new |= WA_PROTECT;
	}

	if (ISATTR(attr, WA_REVERSE) &&
		enter_reverse_mode != NULL) {
		(void) TPUTS(enter_reverse_mode, 1, putout);
		new |= WA_REVERSE;
	}

	if (ISATTR(attr, WA_STANDOUT) &&
		enter_standout_mode != NULL) {
		(void) TPUTS(enter_standout_mode, 1, putout);
		new |= WA_STANDOUT;
	}

	if (ISATTR(attr, WA_UNDERLINE) &&
		enter_underline_mode != NULL) {
		(void) TPUTS(enter_underline_mode, 1, putout);
		new |= WA_UNDERLINE;
	}

	if (ISATTR(attr, WA_HORIZONTAL) &&
		enter_horizontal_hl_mode != NULL) {
		(void) TPUTS(enter_horizontal_hl_mode, 1, putout);
		new |= WA_HORIZONTAL;
	}

	if (ISATTR(attr, WA_LEFT) &&
		enter_left_hl_mode != NULL) {
		(void) TPUTS(enter_left_hl_mode, 1, putout);
		new |= WA_LEFT;
	}

	if (ISATTR(attr, WA_LOW) &&
		enter_low_hl_mode != NULL) {
		(void) TPUTS(enter_low_hl_mode, 1, putout);
		new |= WA_LOW;
	}

	if (ISATTR(attr, WA_RIGHT) &&
		enter_right_hl_mode != NULL) {
		(void) TPUTS(enter_right_hl_mode, 1, putout);
		new |= WA_RIGHT;
	}

	if (ISATTR(attr, WA_TOP) &&
		enter_top_hl_mode != NULL) {
		(void) TPUTS(enter_top_hl_mode, 1, putout);
		new |= WA_TOP;
	}

	if (ISATTR(attr, WA_VERTICAL) &&
		enter_vertical_hl_mode != NULL) {
		(void) TPUTS(enter_vertical_hl_mode, 1, putout);
		new |= WA_VERTICAL;
	}

	return (new);
}
