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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*LINTLIBRARY*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <stdlib.h>
#include <limits.h>
#include "libadm.h"

static int	fmtcheck(char *);

#define	MSGSIZ	64
#define	PROMPT	"Enter the date"
#define	MESG	"Please enter a date"
#define	DEFAULT	"%m/%d/%y"

static char	*p_ndigit(char *, int *, int);
static char	*p_date(char *, int, int, int);
static char	*p_eday(char *, int, int);
static char	*p_dlm(char *, char);

#define	MLIM 10
#define	STDIG 2
#define	LD2 10
#define	LD 01
#define	UD 31
#define	LM 01
#define	UM 12
/*
 * All digits are valid for a YY year format
 * 70-99 refer to the 20th Century
 * 00-69 refer to the 21st Century
 */
#define	LY 00
#define	UY 99
#define	LCY 1970
#define	UCY 9999
#define	CCYY 4
#define	DELIM1 '/'
#define	DELIM2 '-'
#define	BLANK ' '
#define	TAB '	'

static void
setmsg(char *msg, char *fmt, size_t sz)
{
	if ((fmt == NULL) || strcmp(fmt, "%D") == 0)
		fmt = "%m/%d/%y";
	(void) snprintf(msg, sz, "%s. Format is <%s>.", MESG, fmt);
}

static char *
p_ndigit(char *string, int *value, int n)
{
	char *ptr;
	int accum = 0;

	if (!string)
		return (NULL);
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
p_date(char *string, int llim, int ulim, int ndig)
{
	char *ptr;
	int begin = -1;

	if (!(ptr = p_ndigit(string, &begin, ndig)))
		return (NULL);
	if (begin >= llim && begin <= ulim)
		return (ptr);
	else
		return (NULL);
}

static char *
p_eday(char *string, int llim, int ulim)
{
	char *ptr, *copy;
	int begin = -1;
	int iday = 0;
	int idaymax = 2;

	if (*string == BLANK) {
		string++;
		idaymax--;
	}
	copy = string;
	while (isdigit((unsigned char)*copy) && (iday < idaymax)) {
		copy++;
		iday++;
	}
	if (iday == 1) {
		llim = 1;
		ulim = 9;
	} else if (iday == 2) {
		llim = 10;
		ulim = 31;
	}
	if (iday == 0)
		return (NULL);

	if (!(ptr = p_ndigit(string, &begin, iday)))
		return (NULL);

	if (begin >= llim && begin <= ulim)
		return (ptr);
	else
		return (NULL);
}

/* p_month will parse the string for the month - abbr. form i.e. JAN - DEC */

static char *
p_month(char *string, char mnabr)
{
	static char *fmonth[] = {
		    "JANUARY", "FEBRUARY", "MARCH", "APRIL",
		    "MAY", "JUNE", "JULY", "AUGUST",
		    "SEPTEMBER", "OCTOBER", "NOVEMBER", "DECEMBER"
	};
	static char *amonth[] = {
		    "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
		    "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"
	};
	int ichng, icnt;
	char *mnth[12];
	char *copy;
	char mletter[MLIM];
	int mlen;
	int imnth = 0;
	int legit = 0;
	int n = 0;

	if (mnabr == 'a') {
		mlen = 3;
		for (icnt = 0; icnt < 12; icnt++)
			mnth[icnt] = amonth[icnt];
	} else {
		mlen = 9;
		for (icnt = 0; icnt < 12; icnt++)
			mnth[icnt] = fmonth[icnt];
	}

	copy = string;

	while (((islower((unsigned char)*copy)) ||
	    (isupper((unsigned char)*copy))) && (imnth < mlen)) {
		mletter[imnth] = toupper((unsigned char)*copy++);
		imnth++;
	}
	mletter[imnth] = '\0';
	while (!(legit) && (n < 12)) {
		if (strncmp(mletter, mnth[n],
		    (imnth = (int)strlen(mnth[n]))) == 0)
			legit = 1;	/* found legitimate string */
		n++;
	}
	if (legit) {
		for (ichng = 0; ichng < imnth; ichng++) {
			*string = toupper((unsigned char)*string);
			string++;
		}

		return (string);
		/*
		 * I know this causes side effects, but it's less
		 * code  than adding in a copy for string and using that
		 */
	} else
		return (NULL);
}

static char *
p_dlm(char *string, char dchoice)
{
	char dlm;


	if (! string)
		return (NULL);
	(void) sscanf(string, "%1c", &dlm);
	if (dchoice == '/')
		return (((dlm == DELIM1) || (dlm == DELIM2)) ? string+1 : NULL);
	else
		return ((dlm == dchoice) ? string + 1 : NULL);
}

int
ckdate_err(char	*fmt, char *error)
{
	char	defmesg[MSGSIZ];

	if ((fmt != NULL) && (fmtcheck(fmt) == 1))
		return (4);
	setmsg(defmesg, fmt, MSGSIZ);
	puterror(stdout, defmesg, error);
	return (0);
}

int
ckdate_hlp(char *fmt, char *help)
{
	char	defmesg[MSGSIZ];

	if ((fmt != NULL) && (fmtcheck(fmt) == 1))
		return (4);
	setmsg(defmesg, fmt, MSGSIZ);
	puthelp(stdout, defmesg, help);
	return (0);
}

/*
 *	A little state machine that checks out the format to
 *	make sure it is acceptable.
 *		return value 1: NG
 *		return value 0: OK
 */
static int
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
			case 'd': /* previous state must be "%" */
			case 'e':
			case 'm':
			case 'y':
			case 'Y':
			case 'D':
			case 'h':
			case 'b':
			case 'B':
				if (percent == 1)
					percent = 0;
				else
					return (1);
				break;
			case TAB: /* previous state must be start or letter */
			case BLANK:
			case DELIM1:
			case DELIM2:
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
ckdate_val(char *fmt, char *input)
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
			fmt++;
			switch (*fmt) {
				case 'd':
					input = p_date(input, LD, UD, STDIG);
					if (!input)
						valid = 0;
					break;

				case 'e':
					input = p_eday(input, LD2, UD);
					if (!input)
						valid = 0;
					break;

				case 'm':
					input = p_date(input, LM, UM, STDIG);
					if (!input)
						valid = 0;
					break;

				case 'y':
					input = p_date(input, LY, UY, STDIG);
					if (!input)
						valid = 0;
					break;

				case 'Y':
					input = p_date(input, LCY, UCY, CCYY);
					if (!input)
						valid = 0;
					break;

				case 'D':
					input = p_date(input, LM, UM, STDIG);
					if (!input) {
						valid = 0;
					break;
				}
				input = p_dlm(input, DELIM1);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_date(input, LD, UD, STDIG);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_dlm(input, DELIM1);
				if (!input) {
					valid = 0;
					break;
				}
				input = p_date(input, LY, UY, STDIG);
				if (!input)
					valid = 0;
				break;

				case 'h':
				case 'b':
					input = p_month(input, 'a');
					if (!input)
						valid = 0;
					break;

				case 'B':
					input = p_month(input, 'f');
					if (!input)
						valid = 0;
					break;

				default:
					(void) sscanf(input, "%1c", &ltrl);
					input++;
			}
		} else {
			dfl = '\0';
			(void) sscanf(input, "%1c", &dfl);
			input++;
		}
		fmt++;
	}	 /* end of while fmt and valid */

	if ((*fmt == NULL) && ((input != NULL) && *input != 0)) {
		if (*input != NULL)
			valid = 0;
	}
	return ((valid == 0));
}

int
ckdate(char *date, char *fmt, char *defstr, char *error, char *help,
    char *prompt)
{
	char	defmesg[MSGSIZ];
	char	input[MAX_INPUT];
	char	*ept, end[128];

	ept = end;
	*ept = '\0';

	if ((fmt != NULL) && (fmtcheck(fmt) == 1))
		return (4);

	setmsg(defmesg, fmt, MSGSIZ);
	(void) sprintf(ept, "[?,q]");

	if (!prompt)
		prompt = PROMPT;

start:
	putprmpt(stderr, prompt, NULL, defstr);
	if (getinput(input))
		return (1);

	if (!strlen(input)) {
		if (defstr) {
			(void) strcpy(date, defstr);
			return (0);
		}
		puterror(stderr, defmesg, error);
		goto start;
	} else if (strcmp(input, "?") == 0) {
		puthelp(stderr, defmesg, help);
		goto start;
	} else if (ckquit && strcmp(input, "q") == 0) {
		return (3);
	} else if (ckdate_val(fmt, input)) {
		puterror(stderr, defmesg, error);
		goto start;
	}
	(void) strcpy(date, input);
	return (0);
}
