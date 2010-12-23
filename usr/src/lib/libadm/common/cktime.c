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
 * Copyright (c) 1997,1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*LINTLIBRARY*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <stdlib.h>
#include "libadm.h"

static int	fmtcheck(char *);

#define	PROMPT	"Enter the time of day"
#define	ERRMSG	"Please enter the time of day. Format is"
#define	DEFAULT	"%H:%M"

#define	TLEN 3
#define	LH 00
#define	UH 23
#define	USH 12
#define	LM 00
#define	UM 59
#define	LS 00
#define	US 59
#define	DELIM1 ':'
#define	BLANK ' '
#define	TAB '	'

static void
setmsg(char *msg, char *fmt)
{
	if (fmt == NULL)
		fmt = DEFAULT;
	(void) sprintf(msg, "%s <%s>.", ERRMSG, fmt);
}

static char *
p_ndig(char *string, int *value)
{
	char *ptr;
	int accum = 0;
	int n = 2;

	if (!string)
		return (0);
	for (ptr = string; *ptr && n > 0; n--, ptr++) {
		if (! isdigit((unsigned char)*ptr))
			return (NULL);
		accum = (10 * accum) + (*ptr - '0');
		}
	if (n)
		return (NULL);
	*value = accum;
	return (ptr);
}

static char *
p_time(char *string, int llim, int ulim)
{
	char *ptr;
	int begin = -1;
	if (!(ptr = p_ndig(string, &begin)))
		return (NULL);
	if (begin >= llim && begin <= ulim)
		return (ptr);
	else return (NULL);
}

/* p_meridian will parse the string for the meridian - AM/PM or am/pm */

static char *
p_meridian(char *string)
{
	static char *middle[] = { "AM", "PM", "am", "pm" };
	int legit, n;
	char mid[TLEN];

	legit = 0;
	n = 0;
	mid[2] = '\0';
	(void) sscanf(string, "%2s", mid);
	while (!(legit) && (n < 4)) {
		if ((strncmp(mid, middle[n], 2)) == 0)
			legit = 1;	/* found legitimate string */
		n++;
	}
	if (legit)
		return (string+2);
	return (NULL);
}

static char *
p_delim(char *string, char dchoice)
{
	char dlm;

	if (! string)
		return (NULL);
	(void) sscanf(string, "%1c", &dlm);
	return ((dlm == dchoice) ? string + 1 : NULL);
}

int
cktime_val(char *fmt, char *input)
{
	char ltrl, dfl;
	int valid = 1; 	/* time of day string is valid for format */

	if ((fmt != NULL) && (fmtcheck(fmt) == 1))
		return (4);

	if (fmt == NULL)
		fmt = DEFAULT;
	ltrl = '\0';
	while (*fmt && valid) {
		if ((*fmt) == '%') {
			switch (*++fmt) {
			    case 'H':
				input = p_time(input, LH, UH);
				if (!input)
					valid = 0;
				break;

			    case 'M':
				input = p_time(input, LM, UM);
				if (!input)
					valid = 0;
				break;

			    case 'S':
				input = p_time(input, LS, US);
				if (!input)
					valid = 0;
				break;

			    case 'T':
				input = p_time(input, LH, UH);
				if (!input) {
					valid = 0;
					break;
				}

				input = p_delim(input, DELIM1);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_time(input, LM, UM);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_delim(input, DELIM1);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_time(input, LS, US);
				if (!input)
					valid = 0;
				break;

			    case 'R':
				input = p_time(input, LH, UH);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_delim(input, DELIM1);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_time(input, LM, UM);
				if (!input) {
					valid = 0;
					break;
				}
				break;

			    case 'r':
				input = p_time(input, LH, USH);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_delim(input, DELIM1);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_time(input, LM, UM);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_delim(input, DELIM1);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_time(input, LS, US);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_delim(input, BLANK);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_meridian(input);
				if (!input)
					valid = 0;
				break;

			    case 'I':
				input = p_time(input, LH, USH);
				if (!input)
					valid = 0;
				break;

			    case 'p':
				input = p_meridian(input);
				if (!input)
					valid = 0;
				break;

			    default:
				(void) sscanf(input++, "%1c", &ltrl);
			}
		} else {
			dfl = '\0';
			(void) sscanf(input, "%1c", &dfl);
			input++;
		}
		fmt++;
	}

	if (!(*fmt) && (input) && (*input))
		valid = 0;

	return ((valid == 0));
}

int
cktime_err(char *fmt, char *error)
{
	char	defmesg[128];

	if ((fmt != NULL) && (fmtcheck(fmt) == 1))
		return (4);
	setmsg(defmesg, fmt);
	puterror(stdout, defmesg, error);
	return (0);
}

int
cktime_hlp(char *fmt, char *help)
{
	char	defmesg[128];

	if ((fmt != NULL) && (fmtcheck(fmt) == 1))
		return (4);
	setmsg(defmesg, fmt);
	puthelp(stdout, defmesg, help);
	return (0);
}

/*
 *	A little state machine that checks out the format to
 *	make sure it is acceptable.
 *		return value 1: NG
 *		return value 0: OK
 */
int
fmtcheck(char *fmt)
{
	int	percent = 0;

	while (*fmt) {
		switch (*fmt++) {
			case '%': /* previous state must be start or letter */
				if (percent == 0)
					percent = 1;
				else
					return (1);
				break;
			case 'H': /* previous state must be "%" */
			case 'M':
			case 'S':
			case 'T':
			case 'R':
			case 'r':
			case 'I':
			case 'p':
				if (percent == 1)
					percent = 0;
				else
					return (1);
				break;
			case TAB: /* previous state must be start or letter */
			case BLANK:
			case DELIM1:
				if (percent == 1)
					return (1);
				break;
			default:
				return (1);
		}
	}
	return (percent);
}

int
cktime(char *tod, char *fmt, char *defstr, char *error, char *help,
	char *prompt)
{
	char	input[MAX_INPUT],
		defmesg[128];

	if ((fmt != NULL) && (fmtcheck(fmt) == 1))
		return (4);

	if (fmt == NULL)
		fmt = DEFAULT;
	setmsg(defmesg, fmt);
	if (!prompt)
		prompt = "Enter a time of day";

start:
	putprmpt(stderr, prompt, NULL, defstr);
	if (getinput(input))
		return (1);

	if (!strlen(input)) {
		if (defstr) {
			(void) strcpy(tod, defstr);
			return (0);
		}
		puterror(stderr, defmesg, error);
		goto start;
	}
	if (strcmp(input, "?") == 0) {
		puthelp(stderr, defmesg, help);
		goto start;
	}
	if (ckquit && (strcmp(input, "q") == 0))
		return (3);

	if (cktime_val(fmt, input)) {
		puterror(stderr, defmesg, error);
		goto start;
	}
	(void) strcpy(tod, input);
	return (0);
}
