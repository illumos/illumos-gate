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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include "libadm.h"

/*
 * This file is the only one anywhere to need these functions,
 * so we declare them here, not in libadm.h
 */
extern char *__compile(char *, char *, const char *, int);
extern int __step(const char *, const char *);

#define	ESIZE	1024

#define	ERRMSG0 "Input is required."
#define	ERRMSG1	"Please enter a string containing no more than %d characters."
#define	ERRMSG2	\
	"Pattern matching has failed."
#define	ERRMSG3 \
	"Please enter a string which contains no imbedded, \
	leading or trailing spaces or tabs."

#define	HLPMSG0	"Please enter a string"
#define	HLPMSG1 "Please enter a string containing no more than %d characters"
#define	HLPMSG2 "matches one of the following patterns:"
#define	HLPMSG3 "matches the following pattern:"
#define	HLPMSG4 "contains no imbedded, leading or trailing spaces or tabs."

static char	*errstr;

static char *
sethlp(char *msg, char *regexp[], int length)
{
	int	i;

	if (length)
		(void) sprintf(msg, HLPMSG1, length);
	else
		(void) strcpy(msg, HLPMSG0);

	(void) strcat(msg, length ? " and " : " which ");

	if (regexp && regexp[0]) {
		(void) strcat(msg, regexp[1] ? HLPMSG2 : HLPMSG3);
		for (i = 0; regexp[i]; i++) {
			(void) strcat(msg, "\\n\\t");
			(void) strcat(msg, regexp[i]);
		}
	} else
		(void) strcat(msg, HLPMSG4);
	return (msg);
}

int
ckstr_val(char *regexp[], int length, char *input)
{
	char	expbuf[ESIZE];
	int	i, valid;

	valid = 1;
	if (length && (strlen(input) > (size_t)length)) {
		errstr = ERRMSG1;
		return (1);
	}
	if (regexp && regexp[0]) {
		valid = 0;
		for (i = 0; !valid && regexp[i]; ++i) {
			if (!__compile(regexp[i], expbuf, &expbuf[ESIZE], '\0'))
				return (2);
			valid = __step(input, expbuf);
		}
		if (!valid)
			errstr = ERRMSG2;
	} else if (strpbrk(input, " \t")) {
		errstr = ERRMSG3;
		valid = 0;
	}
	return (valid == 0);
}

void
ckstr_err(char *regexp[], int length, char *error, char *input)
{
	char	*defhlp;
	char	temp[1024];

	if (input) {
		if (ckstr_val(regexp, length, input)) {
			(void) sprintf(temp, errstr, length);
			puterror(stdout, temp, error);
			return;
		}
	}

	defhlp = sethlp(temp, regexp, length);
	puterror(stdout, defhlp, error);
}

void
ckstr_hlp(char *regexp[], int length, char *help)
{
	char	*defhlp;
	char	hlpbuf[1024];

	defhlp = sethlp(hlpbuf, regexp, length);
	puthelp(stdout, defhlp, help);
}

int
ckstr(char *strval, char *regexp[], int length, char *defstr, char *error,
	char *help, char *prompt)
{
	int	n;
	char	*defhlp;
	char	input[MAX_INPUT],
		hlpbuf[1024],
		errbuf[1024];

	defhlp = NULL;
	if (!prompt)
		prompt = "Enter an appropriate value";

start:
	putprmpt(stderr, prompt, NULL, defstr);
	if (getinput(input))
		return (1);

	n = (int)strlen(input);
	if (n == 0) {
		if (defstr) {
			(void) strcpy(strval, defstr);
			return (0);
		}
		puterror(stderr, ERRMSG0, error);
		goto start;
	}
	if (strcmp(input, "?") == 0) {
		if (defhlp == NULL)
			defhlp = sethlp(hlpbuf, regexp, length);
		puthelp(stderr, defhlp, help);
		goto start;
	}
	if (ckquit && (strcmp(input, "q") == 0)) {
		(void) strcpy(strval, input);
		return (3);
	}
	if (ckstr_val(regexp, length, input)) {
		(void) sprintf(errbuf, errstr, length);
		puterror(stderr, errbuf, error);
		goto start;
	}
	(void) strcpy(strval, input);
	return (0);
}
