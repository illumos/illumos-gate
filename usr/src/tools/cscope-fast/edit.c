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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	cscope - interactive C symbol cross-reference
 *
 *	file editing functions
 */

#include <curses.h>	/* KEY_BREAK and refresh */
#include <libgen.h>
#include <stdio.h>
#include "global.h"


/* edit this displayed reference */

void
editref(int i)
{
	char	file[PATHLEN + 1];	/* file name */
	char	linenum[NUMLEN + 1];	/* line number */

	/* verify that there is a references found file */
	if (refsfound == NULL) {
		return;
	}
	/* get the selected line */
	seekline(i + topline);

	/* get the file name and line number */
	if (fscanf(refsfound, "%s%*s%s", file, linenum) == 2) {
		edit(file, linenum);	/* edit it */
	}
	seekline(topline);	/* restore the line pointer */
}

/* edit all references */

void
editall(void)
{
	char	file[PATHLEN + 1];	/* file name */
	char	linenum[NUMLEN + 1];	/* line number */
	int	c;

	/* verify that there is a references found file */
	if (refsfound == NULL) {
		return;
	}
	/* get the first line */
	seekline(1);

	/* get each file name and line number */
	while (fscanf(refsfound, "%s%*s%s%*[^\n]", file, linenum) == 2) {
		edit(file, linenum);	/* edit it */
		if (editallprompt == YES) {
			putmsg("Type ^D to stop editing all lines, "
			    "or any other character to continue: ");
			if ((c = mygetch()) == EOF || c == ctrl('D') ||
			    c == ctrl('Z') || c == KEY_BREAK) {
				/* needed for interrupt on first time */
				(void) refresh();
				break;
			}
		}
	}
	seekline(topline);
}

/* call the editor */

void
edit(char *file, char *linenum)
{
	char	msg[MSGLEN + 1];	/* message */
	char	plusnum[NUMLEN + 2];	/* line number option */
	char	*s;

	(void) sprintf(msg, "%s +%s %s", editor, linenum, file);
	putmsg(msg);
	(void) sprintf(plusnum, "+%s", linenum);

	/* if this is the more or page commands */
	if (strcmp(s = basename(editor), "more") == 0 ||
	    strcmp(s, "page") == 0) {
		/*
		 * get it to pause after displaying a file smaller
		 * than the screen length
		 */
		(void) execute(editor, editor, plusnum, file, "/dev/null",
		    (char *)NULL);
	} else {
		(void) execute(editor, editor, plusnum, file, (char *)NULL);
	}
}
