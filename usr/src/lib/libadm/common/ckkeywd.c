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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1 */
/*LINTLIBRARY*/

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include "libadm.h"

static int
match(char *strval, char *set[])
{
	char *found;
	int i, len;

	len = (int)strlen(strval);

	found = NULL;
	for (i = 0; set[i]; i++) {
		if (strncmp(set[i], strval, len) == 0) {
			if (found)
				return (-1); /* not unique */
			found = set[i];
		}
	}

	if (found) {
		(void) strcpy(strval, found);
		return (0);
	}
	return (1);
}

int
ckkeywd(char *strval, char *keyword[], char *defstr, char *error, char *help,
	char *prompt)
{
	int valid, i, n;
	char input[MAX_INPUT];
	char defmesg[512];
	char *ept;

	(void) sprintf(defmesg, "Please enter one of the following keywords: ");
	ept = defmesg + strlen(defmesg);
	for (i = 0; keyword[i]; ) {
		if (i)
			(void) strcat(ept, ", ");
		(void) strcat(ept, keyword[i++]);
	}
	(void) strcat(ept, ckquit ? ", q." : ".");

	if (!prompt)
		prompt = "Enter appropriate value";

start:
	putprmpt(stderr, prompt, keyword, defstr);
	if (getinput(input))
		return (1);

	n = (int)strlen(input);
	if (n == 0) {
		if (defstr) {
			(void) strcpy(strval, defstr);
			return (0);
		}
		puterror(stderr, defmesg, error);
		goto start;
	}
	if (strcmp(input, "?") == 0) {
		puthelp(stderr, defmesg, help);
		goto start;
	}
	if (ckquit && (strcmp(input, "q") == 0)) {
		(void) strcpy(strval, input);
		return (3);
	}

	valid = 1;
	if (keyword)
		valid = !match(input, keyword);

	if (!valid) {
		puterror(stderr, defmesg, error);
		goto start;
	}
	(void) strcpy(strval, input);
	return (0);
}
