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
/*	  All Rights Reserved	*/


/*
 * Copyright (c) 1997, by Sun Mircrosystems, Inc.
 * All rights reserved.
 */

/*LINTLIBRARY*/

#include <sys/types.h>
#include "private.h"

int
menu_driver(MENU *m, int c)
{
	int i, n;
	int top;
	ITEM *current;
	int ret;

	if (!m) {
		return (E_BAD_ARGUMENT);
	}
	ret = E_OK;
	if (Indriver(m)) {
		return (E_BAD_STATE);
	}
	if (!Posted(m)) {
		return (E_NOT_POSTED);
	}
	top = Top(m);
	current = Current(m);

	if (c > KEY_MAX && c < MAX_COMMAND) {

		/* Clear the pattern buffer if not one of these requests */
		if (c != REQ_BACK_PATTERN &&
		    c != REQ_NEXT_MATCH &&
		    c != REQ_PREV_MATCH) {
			Pindex(m) = 0;
			IthPattern(m, 0) = '\0';
		}

		switch (c) {

		case REQ_RIGHT_ITEM: {
			if (Right(current) == (ITEM *)0) {
					ret = E_REQUEST_DENIED;
					break;
			}
			current = Right(current);
			break;
		}
		case REQ_LEFT_ITEM: {
			if (Left(current) == (ITEM *)0) {
				ret = E_REQUEST_DENIED;
				break;
			}
			current = Left(current);
			break;
		}
		case REQ_UP_ITEM: {
			if (Up(current) == (ITEM *)0) {
				ret = E_REQUEST_DENIED;
				break;
			}
			current = Up(current);
			break;
		}
		case REQ_DOWN_ITEM: {
			if (Down(current) == (ITEM *)0) {
				ret = E_REQUEST_DENIED;
				break;
			}
			current = Down(current);
			break;
		}
		case REQ_SCR_ULINE: {
			if (--top < 0) {
				++top;
				ret = E_REQUEST_DENIED;
				break;
			}
			current = Up(current);
			break;
		}
		case REQ_SCR_DLINE: {
			if (++top > Rows(m) - Height(m)) {
				--top;
				ret = E_REQUEST_DENIED;
				break;
			}
			current = Down(current);
			break;
		}
		case REQ_SCR_UPAGE: {
			n = min(Height(m), top);
			if (n) {
				top -= n;
				for (i = n; i--; ) {
					current = Up(current);
				}
			} else {
				ret = E_REQUEST_DENIED;
				break;
			}
			break;
		}
		case REQ_SCR_DPAGE: {
			n = min(Height(m), Rows(m) - Height(m) - top);
			if (n) {
				top += n;
				for (i = n; i--; ) {
					current = Down(current);
				}
			} else {
				ret = E_REQUEST_DENIED;
				break;
			}
			break;
		}
		case REQ_FIRST_ITEM: {
			current = IthItem(m, 0);
			break;
		}
		case REQ_LAST_ITEM: {
			current = IthItem(m, Nitems(m)-1);
			break;
		}
		case REQ_NEXT_MATCH: {
			if (IthPattern(m, 0) != '\0') {
				ret = _match(m, '\0', &current);
			} else {
				if (Index(current)+1 >= Nitems(m)) {
					current = IthItem(m, 0);
				} else {
					current = IthItem(m, Index(current)+1);
				}
			}
			break;
		}
		case REQ_NEXT_ITEM: {
			if (Index(current)+1 >= Nitems(m)) {
				if (Cyclic(m)) {
					current = IthItem(m, 0);
				} else {
					ret = E_REQUEST_DENIED;
				}
			} else {
				current = IthItem(m, Index(current)+1);
			}
			break;
		}
		case REQ_PREV_MATCH: {
			if (IthPattern(m, 0) != '\0') {
				ret = _match(m, '\b', &current);
			} else {
				/* This differs from PREV_ITEM in that */
				/* it is cyclic */
				if (Index(current)-1 < 0) {
					current = IthItem(m, Nitems(m)-1);
				} else {
					current = IthItem(m, Index(current)-1);
				}
			}
			break;
		}
		case REQ_PREV_ITEM: {
			if (Index(current)-1 < 0) {
				if (Cyclic(m)) {
					current = IthItem(m, Nitems(m)-1);
				} else {
					ret = E_REQUEST_DENIED;
				}
			} else {
				current = IthItem(m, Index(current)-1);
			}
			break;
		}
		case REQ_TOGGLE_ITEM: {
			if (!OneValue(m)) {
				if (Selectable(Current(m))) {
					Value(Current(m)) ^= TRUE;
					_move_post_item(m, Current(m));
					_show(m);
				} else {
					ret = E_NOT_SELECTABLE;
				}
			} else {
				ret = E_REQUEST_DENIED;
			}
			break;
		}
		case REQ_BACK_PATTERN: {
			if (Pindex(m) > 0) {
				Pindex(m) -= 1;
				IthPattern(m, Pindex(m)) = '\0';
				_position_cursor(m);
			} else {
				ret = E_REQUEST_DENIED;
			}
			break;
		}
		case REQ_CLEAR_PATTERN: {
			/* This was already done at the top */
			break;
		}
		default: {
			ret = E_UNKNOWN_COMMAND;
		}
		}
	} else {
		if (c > 037 && c < 0177) {
			/*LINTED [E_PASS_INT_TO_SMALL_INT]*/
			ret = _match(m, c, &current);
		} else {
			ret = E_UNKNOWN_COMMAND;
		}
	}

	/* Verify the location of the top row */

	_chk_top(m, &top, current);

	/* Go change the actual values of Top and Current and do init/term */

	_affect_change(m, top, current);

	return (ret);
}
