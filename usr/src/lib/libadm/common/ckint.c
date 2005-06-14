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

/*LINTLIBRARY*/
#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include "libadm.h"

static void
setmsg(char *msg, short base)
{
	if ((base == 0) || (base == 10))
		(void) sprintf(msg, "Please enter an integer.");
	else
		(void) sprintf(msg, "Please enter a base %d integer.", base);
}

static void
setprmpt(char *prmpt, short base)
{
	if ((base == 0) || (base == 10))
		(void) sprintf(prmpt, "Enter an integer.");
	else
		(void) sprintf(prmpt, "Enter a base %d integer.", base);
}

int
ckint_val(char *value, short base)
{
	char	*ptr;

	(void) strtol(value, &ptr, (int)base);
	if (*ptr == '\0')
		return (0);
	return (1);
}

void
ckint_err(short base, char *error)
{
	char	defmesg[64];

	setmsg(defmesg, base);
	puterror(stdout, defmesg, error);
}

void
ckint_hlp(short base, char *help)
{
	char	defmesg[64];

	setmsg(defmesg, base);
	puthelp(stdout, defmesg, help);
}

int
ckint(long *intval, short base, char *defstr, char *error, char *help,
	char *prompt)
{
	long	value;
	char	*ptr,
		input[MAX_INPUT],
		defmesg[64],
		temp[64];

	if (!prompt) {
		setprmpt(temp, base);
		prompt = temp;
	}
	setmsg(defmesg, base);

start:
	putprmpt(stderr, prompt, NULL, defstr);
	if (getinput(input))
		return (1);

	if (strlen(input) == 0) {
		if (defstr) {
			*intval = strtol(defstr, NULL, (int)base);
			return (0);
		}
		puterror(stderr, defmesg, error);
		goto start;
	} else if (strcmp(input, "?") == 0) {
		puthelp(stderr, defmesg, help);
		goto start;
	} else if (ckquit && (strcmp(input, "q") == 0))
		return (3);

	value = strtol(input, &ptr, (int)base);
	if (*ptr != '\0') {
		puterror(stderr, defmesg, error);
		goto start;
	}
	*intval = value;
	return (0);
}
