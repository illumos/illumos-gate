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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4 */
/*LINTLIBRARY*/

#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include "valtools.h"
#include <sys/types.h>
#include <stdlib.h>
#include <strings.h>
#include "libadm.h"

static int	insert(struct _choice_ *, CKMENU *);
static char	*strtoki(char *, char *);
static char	**match(CKMENU *, char *, int);
static int	getstr(char *, char *, char *, char *, char *);
static int	getnum(char *, int, int *, int *);
static struct _choice_ *next(struct _choice_ *);

static char	*deferr;
static char	*errmsg;
static char	*defhlp;

#define	PROMPT	"Enter selection"
#define	MESG0	"Entry does not match available menu selection. "
#define	MESG1	"the number of the menu item you wish to select, or "
#define	MESG2	"the token which is associated with the menu item,\
		or a partial string which uniquely identifies the \
		token for the menu item. Enter ?? to reprint the menu."

#define	TOOMANY	"Too many items selected from menu"
#define	NOTUNIQ	"The entered text does not uniquely identify a menu choice."
#define	BADNUM	"Bad numeric choice specification"

static char *
setmsg(CKMENU *menup, short flag)
{
	int	n;
	char	*msg;

	n = (int)(6 + sizeof (MESG2));
	if (flag)
		n += (int)(sizeof (MESG0));

	if (menup->attr & CKUNNUM) {
		msg = calloc((size_t)n, sizeof (char));
		if (flag)
			(void) strcpy(msg, MESG0);
		else
			msg[0] = '\0';
		(void) strcat(msg, "Enter ");
		(void) strcat(msg, MESG2);
	} else {
		msg = calloc(n+sizeof (MESG1), sizeof (char));
		if (flag)
			(void) strcpy(msg, MESG0);
		else
			msg[0] = '\0';
		(void) strcat(msg, "Enter ");
		(void) strcat(msg, MESG1);
		(void) strcat(msg, MESG2);
	}
	return (msg);
}

CKMENU *
allocmenu(char *label, int attr)
{
	CKMENU *pt;

	if (pt = calloc(1, sizeof (CKMENU))) {
		pt->attr = attr;
		pt->label = label;
	}
	return (pt);
}

void
ckitem_err(CKMENU *menup, char *error)
{
	deferr = setmsg(menup, 1);
	puterror(stdout, deferr, error);
	free(deferr);
}

void
ckitem_hlp(CKMENU *menup, char *help)
{
	defhlp = setmsg(menup, 0);
	puthelp(stdout, defhlp, help);
	free(defhlp);
}

int
ckitem(CKMENU *menup, char *item[], short max, char *defstr, char *error,
	char *help, char *prompt)
{
	int	n, i;
	char	strval[MAX_INPUT];
	char	**list;

	if ((menup->nchoices <= 0) && !menup->invis)
		return (4); /* nothing to choose from */

	if (menup->attr & CKONEFLAG) {
		if (((n = menup->nchoices) <= 1) && menup->invis) {
			for (i = 0; menup->invis[i]; ++i)
				n++;
		}
		if (n <= 1) {
			if (menup->choice)
				item[0] = menup->choice->token;
			else if (menup->invis)
				item[0] = menup->invis[0];
			item[1] = NULL;
			return (0);
		}
	}

	if (max < 1)
		max = menup->nchoices;

	if (!prompt)
		prompt = PROMPT;
	defhlp = setmsg(menup, 0);
	deferr = setmsg(menup, 1);

reprint:
	printmenu(menup);

start:
	if (n = getstr(strval, defstr, error, help, prompt)) {
		free(defhlp);
		free(deferr);
		return (n);
	}
	if (strcmp(strval, "??") == 0) {
		goto reprint;
	}
	if ((defstr) && (strcmp(strval, defstr) == 0)) {
		item[0] = defstr;
		item[1] = NULL;
	} else {
		list = match(menup, strval, (int)max);
		if (!list) {
			puterror(stderr, deferr, (errmsg ? errmsg : error));
			goto start;
		}
		for (i = 0; (i < max); i++)
			item[i] = list[i];
		free(list);
	}
	free(defhlp);
	free(deferr);
	return (0);
}

static int
getnum(char *strval, int max, int *begin, int *end)
{
	int n;
	char *pt;

	*begin = *end = 0;
	pt = strval;
	for (;;) {
		if (*pt == '$') {
			n = max;
			pt++;
		} else {
			n = (int)strtol(pt, &pt, 10);
			if ((n <= 0) || (n > max))
				return (1);
		}
		while (isspace((unsigned char)*pt))
			pt++;

		if (!*begin && (*pt == '-')) {
			*begin = n;
			pt++;
			while (isspace((unsigned char)*pt))
				pt++;
			continue;
		} else if (*pt) {
			return (1); /* wasn't a number, or an invalid one */
		} else if (*begin) {
			*end = n;
			break;
		} else {
			*begin = n;
			break;
		}
	}
	if (!*end)
		*end = *begin;
	return ((*begin <= *end) ? 0 : 1);
}

static char **
match(CKMENU *menup, char *strval, int max)
{
	struct _choice_ *chp;
	char **choice;
	int begin, end;
	char *pt, *found;
	int i, len, nchoice;

	nchoice = 0;
	choice = calloc((size_t)max, sizeof (char *));

	do {
		if (pt = strpbrk(strval, " \t,")) {
			do {
				*pt++ = '\0';
			} while (strchr(" \t,", *pt));
		}

		if (nchoice >= max) {
			errmsg = TOOMANY;
			return (NULL);
		}
		if (!(menup->attr & CKUNNUM) &&
			isdigit((unsigned char)*strval)) {
			if (getnum(strval, (int)menup->nchoices, &begin,
			    &end)) {
				errmsg = BADNUM;
				return (NULL);
			}
			chp = menup->choice;
			for (i = 1; chp; i++) {
				if ((i >= begin) && (i <= end)) {
					if (nchoice >= max) {
						errmsg = TOOMANY;
						return (NULL);
					}
					choice[nchoice++] = chp->token;
				}
				chp = chp->next;
			}
			continue;
		}

		found = NULL;
		chp = menup->choice;
		for (i = 0; chp; i++) {
			len = (int)strlen(strval);
			if (strncmp(chp->token, strval, (size_t)len) == 0) {
				if (chp->token[len] == '\0') {
					found = chp->token;
					break;
				} else if (found) {
					errmsg = NOTUNIQ;
					return (NULL); /* not unique */
				}
				found = chp->token;
			}
			chp = chp->next;
		}

		if (menup->invis) {
			for (i = 0; menup->invis[i]; ++i) {
				len = (int)strlen(strval);
				if (strncmp(menup->invis[i], strval,
				    (size_t)len) == 0) {
#if _3b2
					if (chp->token[len] == '\0') {
#else
					if (menup->invis[i][len] == '\0') {
#endif
						found = menup->invis[i];
						break;
					} else if (found) {
						errmsg = NOTUNIQ;
						return (NULL);
					}
					found = menup->invis[i];
				}
			}
		}
		if (found) {
			choice[nchoice++] = found;
			continue;
		}
		errmsg = NULL;
		return (NULL);
	} while (((strval = pt) != NULL) && *pt);
	return (choice);
}

int
setitem(CKMENU *menup, char *choice)
{
	struct _choice_ *chp;
	int n;
	char *pt;

	if (choice == NULL) {
		/* request to clear memory usage */
		chp = menup->choice;
		while (chp) {
			struct _choice_	*_chp = chp;

			chp = chp->next;
			menup->longest = menup->nchoices = 0;

			(void) free(_chp->token); /* free token and text */
			(void) free(_chp);
		}
		return (1);
	}

	if ((chp = calloc(1, sizeof (struct _choice_))) == NULL)
		return (1);

	if ((pt = strdup(choice)) == NULL) {
		free(chp);
		return (1);
	}
	if (!*pt || isspace((unsigned char)*pt)) {
		free(chp);
		return (2);
	}

	chp->token = strtoki(pt, " \t\n");
	chp->text = strtoki(NULL, "");

	if (chp->text) {
	    while (isspace((unsigned char)*chp->text))
		chp->text++;
	}
	n = (int)strlen(chp->token);
	if (n > menup->longest)
		menup->longest = (short)n;

	if (insert(chp, menup))
		menup->nchoices++;
	else
		free(chp); /* duplicate entry */
	return (0);
}

int
setinvis(CKMENU *menup, char *choice)
{
	int	index;

	index = 0;
	if (choice == NULL) {
		if (menup->invis == NULL)
			return (0);
		while (menup->invis[index])
			free(menup->invis[index]);
		free(menup->invis);
		return (0);
	}

	if (menup->invis == NULL)
		menup->invis = calloc(2, sizeof (char *));
	else {
		while (menup->invis[index])
			index++; /* count invisible choices */
		menup->invis = realloc(menup->invis,
			(index+2)* sizeof (char *));
		menup->invis[index+1] = NULL;
	}
	if (!menup->invis)
		return (-1);
	menup->invis[index] = strdup(choice);
	return (0);
}

static int
insert(struct _choice_ *chp, CKMENU *menup)
{
	struct _choice_ *last, *base;
	int n;

	base = menup->choice;
	last = NULL;

	if (!(menup->attr & CKALPHA)) {
		while (base) {
			if (strcmp(base->token, chp->token) == 0)
				return (0);
			last = base;
			base = base->next;
		}
		if (last)
			last->next = chp;
		else
			menup->choice = chp;
		return (1);
	}

	while (base) {
		if ((n = strcmp(base->token, chp->token)) == 0)
			return (0);
		if (n > 0) {
			/* should come before this one */
			break;
		}
		last = base;
		base = base->next;
	}
	if (last) {
		chp->next = last->next;
		last->next = chp;
	} else {
		chp->next = menup->choice;
		menup->choice = chp;
	}
	return (1);
}

void
printmenu(CKMENU *menup)
{
	int i;
	struct _choice_ *chp;
	char *pt;
	char format[16];
	int c;

	(void) fputc('\n', stderr);
	if (menup->label) {
		(void) puttext(stderr, menup->label, 0, 0);
		(void) fputc('\n', stderr);
	}
	(void) sprintf(format, "%%-%ds", menup->longest+5);

	(void) next(NULL);
	chp = ((menup->attr & CKALPHA) ? next(menup->choice) : menup->choice);
	for (i = 1; chp; ++i) {
		if (!(menup->attr & CKUNNUM))
			(void) fprintf(stderr, "%3d  ", i);
		(void) fprintf(stderr, format, chp->token);
		if (chp->text) {
			/* there is text associated with the token */
			pt = chp->text;
			while (*pt) {
				(void) fputc(*pt, stderr);
				if (*pt++ == '\n') {
					if (!(menup->attr & CKUNNUM))
						(void) fprintf(stderr,
						    "%5s", "");
					(void) fprintf(stderr, format, "");
					while (isspace((unsigned char)*pt))
						++pt;
				}
			}
		}
		(void) fputc('\n', stderr);
		chp = ((menup->attr & CKALPHA) ?
			next(menup->choice) : chp->next);
		if (chp && ((i % 10) == 0)) {
			/* page the choices */
			(void) fprintf(stderr,
			    "\n... %d more menu choices to follow;",
			    menup->nchoices - i);
			(void) fprintf(stderr,
			    /* CSTYLED */
			    "\n<RETURN> for more choices, <CTRL-D> to stop \
display:");
			/* ignore other chars */
			while (((c = getc(stdin)) != EOF) && (c != '\n'))
				;
			(void) fputc('\n', stderr);
			if (c == EOF)
				break; /* stop printing menu */
		}
	}
}

static int
getstr(char *strval, char *defstr, char *error, char *help, char *prompt)
{
	char input[MAX_INPUT];
	char *ept, end[MAX_INPUT];

	*(ept = end) = '\0';
	if (defstr) {
		(void) sprintf(ept, "(default: %s) ", defstr);
		ept += strlen(ept);
	}
	if (ckquit) {
		(void) strcat(ept, "[?,??,q]");
	} else {
		(void) strcat(ept, "[?,??]");
	}

start:
	(void) fputc('\n', stderr);
	(void) puttext(stderr, prompt, 0, 0);
	(void) fprintf(stderr, " %s: ", end);

	if (getinput(input))
		return (1);

	if (strlen(input) == 0) {
		if (defstr) {
			(void) strcpy(strval, defstr);
			return (0);
		}
		puterror(stderr, deferr, (errmsg ? errmsg : error));
		goto start;
	} else if (strcmp(input, "?") == 0) {
		puthelp(stderr, defhlp, help);
		goto start;
	} else if (ckquit && (strcmp(input, "q") == 0)) {
		/* (void) strcpy(strval, input); */
		return (3);
	}
	(void) strcpy(strval, input);
	return (0);
}

static struct _choice_ *
next(struct _choice_ *chp)
{
	static char *last;
	static char *first;
	struct _choice_ *found;

	if (!chp) {
		last = NULL;
		return (NULL);
	}

	found = NULL;
	for (first = NULL; chp; chp = chp->next) {
		if (last && strcmp(last, chp->token) >= 0)
			continue; /* lower than the last one we found */

		if (!first || strcmp(first, chp->token) > 0) {
			first = chp->token;
			found = chp;
		}
	}
	last = first;
	return (found);
}

static char *
strtoki(char *string, char *sepset)
{
	char	*p, *q, *r;
	static char	*savept;

	/* first or subsequent call */
	p = (string == NULL)? savept: string;

	if (p == NULL)		/* return if no tokens remaining */
		return (NULL);

	q = p + strspn(p, sepset);	/* skip leading separators */

	if (*q == '\0')		/* return if no tokens remaining */
		return (NULL);

	if ((r = strpbrk(q, sepset)) == NULL)	/* move past token */
		savept = 0;	/* indicate this is last token */
	else {
		*r = '\0';
		savept = ++r;
	}
	return (q);
}
