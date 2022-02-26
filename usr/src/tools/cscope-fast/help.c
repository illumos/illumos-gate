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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *	cscope - interactive C symbol cross-reference
 *
 *	display help
 */

#include "global.h"
#include <curses.h>	/* LINES */

#define	MAXHELP	50	/* maximum number of help strings */

void
help(void)
{
	char	**ep, *s, **tp, *text[MAXHELP];
	int	line;

	tp = text;
	if (changing == NO) {
		if (mouse) {
			*tp++ = "Point with the mouse and click button 1 to "
			    "move to the desired input field,\n";
			*tp++ = "type the pattern to search for, and then "
			    "press the RETURN key.  For the first 5\n";
			*tp++ = "and last 2 input fields, the pattern can be "
			    "a regcmp(3C) regular expression.\n";
			*tp++ = "If the search is successful, you can edit "
			    "the file containing a displayed line\n";
			*tp++ = "by pointing with the mouse and clicking "
			    "button 1.\n";
			*tp++ = "\nYou can either use the button 2 menu or "
			    "these command characters:\n\n";
		} else {
			*tp++ = "Press the TAB key repeatedly to move to the "
			    "desired input field, type the\n";
			*tp++ = "pattern to search for, and then press the "
			    "RETURN key.  For the first 4 and\n";
			*tp++ = "last 2 input fields, the pattern can be a "
			    "regcmp(3C) regular expression.\n";
			*tp++ = "If the search is successful, you can use "
			    "these command characters:\n\n";
			*tp++ = "1-9\tEdit the file containing the displayed "
			    "line.\n";
		}
		*tp++ = "space\tDisplay next lines.\n";
		*tp++ = "+\tDisplay next lines.\n";
		*tp++ = "-\tDisplay previous lines.\n";
		*tp++ = "^E\tEdit all lines.\n";
		*tp++ = ">\tWrite all lines to a file.\n";
		*tp++ = ">>\tAppend all lines to a file.\n";
		*tp++ = "<\tRead lines from a file.\n";
		*tp++ = "^\tFilter all lines through a shell command.\n";
		*tp++ = "|\tPipe all lines to a shell command.\n";
		*tp++ = "\nAt any time you can use these command "
		    "characters:\n\n";
		if (!mouse) {
			*tp++ = "^P\tMove to the previous input field.\n";
		}
		*tp++ = "^A\tSearch again with the last pattern typed.\n";
		*tp++ = "^B\tRecall previous input field and search pattern.\n";
		*tp++ = "^F\tRecall next input field and search pattern.\n";
		*tp++ = "^C\tToggle ignore/use letter case when searching.\n";
		*tp++ = "^R\tRebuild the symbol database.\n";
		*tp++ = "!\tStart an interactive shell (type ^D to return "
		    "to cscope).\n";
		*tp++ = "^L\tRedraw the screen.\n";
		*tp++ = "?\tDisplay this list of commands.\n";
		*tp++ = "^D\tExit cscope.\n";
		*tp++ = "\nNote: If the first character of the pattern you "
		    "want to search for matches\n";
		*tp++ = "a command, type a \\ character first.\n";
	} else {
		if (mouse) {
			*tp++ = "Point with the mouse and click button 1 "
			    "to mark or unmark the line to be\n";
			*tp++ = "changed.  You can also use the button 2 "
			    "menu or these command characters:\n\n";
		} else {
			*tp++ = "When changing text, you can use these "
			    "command characters:\n\n";
			*tp++ = "1-9\tMark or unmark the line to be changed.\n";
		}
		*tp++ = "*\tMark or unmark all displayed lines to be "
		    "changed.\n";
		*tp++ = "space\tDisplay next lines.\n";
		*tp++ = "+\tDisplay next lines.\n";
		*tp++ = "-\tDisplay previous lines.\n";
		*tp++ = "a\tMark or unmark all lines to be changed.\n";
		*tp++ = "^D\tChange the marked lines and exit.\n";
		*tp++ = "RETURN\tExit without changing the marked lines.\n";
		*tp++ = "!\tStart an interactive shell (type ^D to return "
		    "to cscope).\n";
		*tp++ = "^L\tRedraw the screen.\n";
		*tp++ = "?\tDisplay this list of commands.\n";
	}
	/* print help, a screen at a time */
	ep = tp;
	line = 0;
	for (tp = text; tp < ep; ) {
		if (line < LINES - 1) {
			for (s = *tp; *s != '\0'; ++s) {
				if (*s == '\n') {
					++line;
				}
			}
			(void) addstr(*tp++);
		} else {
			(void) addstr("\n");
			askforchar();
			(void) clear();
			line = 0;
		}
	}
	if (line) {
		(void) addstr("\n");
		askforchar();
	}
}
