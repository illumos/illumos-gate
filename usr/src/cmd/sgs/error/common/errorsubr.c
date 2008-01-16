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

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include "error.h"

/*
 *	Arrayify a list of rules
 */
void
arrayify(int *e_length, Eptr **e_array, Eptr header)
{
	Eptr	errorp;
	Eptr	*array;
	int	listlength;
	int	listindex;

	for (errorp = header, listlength = 0;
	    errorp; errorp = errorp->error_next, listlength++)
		continue;
	array = Calloc(listlength+1, sizeof (Eptr));
	for (listindex = 0, errorp = header;
	    listindex < listlength;
	    listindex++, errorp = errorp->error_next) {
		array[listindex] = errorp;
		errorp->error_position = listindex;
	}
	array[listindex] = (Eptr)0;
	*e_length = listlength;
	*e_array = array;
}

/*PRINTFLIKE1*/
static void
error(char *format, ...)
{
	va_list	args;

	va_start(args, format);
	(void) fprintf(stderr, "Error: ");
	(void) vfprintf(stderr, format, args);
	(void) fprintf(stderr, "\n");
	(void) fflush(stdout);
	(void) fflush(stderr);
	va_end(args);
	exit(6);
}

void *
Calloc(int nelements, int size)
{
	void	*back;
	if ((back = calloc(nelements, size)) == NULL) {
		error("Ran out of memory.\n");
		exit(1);
	}
	return (back);
}

char *
strsave(char *instring)
{
	char	*outstring;
	(void) strcpy(outstring = Calloc(1, strlen(instring) + 1),
	    instring);
	return (outstring);
}
/*
 *	find the position of a given character in a string
 *		(one based)
 */
int
position(char *string, char ch)
{
	int	i;
	if (string)
	for (i = 1; *string; string++, i++) {
		if (*string == ch)
			return (i);
	}
	return (-1);
}
/*
 *	clobber the first occurance of ch in string by the new character
 */
char *
substitute(char *string, char chold, char chnew)
{
	char	*cp = string;

	if (cp)
	while (*cp) {
		if (*cp == chold) {
			*cp = chnew;
			break;
		}
		cp++;
	}
	return (string);
}

char
lastchar(char *string)
{
	int	length;

	if (string == NULL)
		return ('\0');
	length = strlen(string);
	if (length >= 1)
		return (string[length-1]);
	else
		return ('\0');
}

char
firstchar(char *string)
{
	if (string)
		return (string[0]);
	else
		return ('\0');
}

char
next_lastchar(char *string)
{
	int	length;

	if (string == NULL)
		return ('\0');
	length = strlen(string);
	if (length >= 2)
		return (string[length - 2]);
	else
		return ('\0');
}

void
clob_last(char *string, char newstuff)
{
	int	length = 0;
	if (string)
		length = strlen(string);
	if (length >= 1)
		string[length - 1] = newstuff;
}

/*
 *	parse a string that is the result of a format %s(%d)
 *	return TRUE if this is of the proper format
 */
boolean
persperdexplode(char *string, char **r_perd, char **r_pers)
{
	char	*cp;
	int	length = 0;

	if (string)
		length = strlen(string);
	if ((length >= 4) && (string[length - 1] == ')')) {
		for (cp = &string[length - 2];
		    (isdigit(*cp)) && (*cp != '('); --cp)
			continue;
		if (*cp == '(') {
			string[length - 1] = '\0';	/* clobber the ) */
			*r_perd = strsave(cp+1);
			string[length - 1] = ')';
			*cp = '\0';			/* clobber the ( */
			*r_pers = strsave(string);
			*cp = '(';
			return (TRUE);
		}
	}
	return (FALSE);
}

static	char	cincomment[] = CINCOMMENT;
static	char	coutcomment[] = COUTCOMMENT;
static	char	fincomment[] = FINCOMMENT;
static	char	foutcomment[] = FOUTCOMMENT;
static	char	newline[] = NEWLINE;
static	char	piincomment[] = PIINCOMMENT;
static	char	pioutcomment[] = PIOUTCOMMENT;
static	char	lispincomment[] = LISPINCOMMENT;
static	char	riincomment[] = RIINCOMMENT;
static	char	rioutcomment[] = RIOUTCOMMENT;
static	char	troffincomment[] = TROFFINCOMMENT;
static	char	troffoutcomment[] = TROFFOUTCOMMENT;
static	char	mod2incomment[] = MOD2INCOMMENT;
static	char	mod2outcomment[] = MOD2OUTCOMMENT;

struct lang_desc lang_table[] = {
	/* INUNKNOWN	0 */	"unknown", cincomment,	coutcomment,
	/* INCPP	1 */	"cpp",	cincomment,    coutcomment,
	/* INCC		2 */	"cc",	cincomment,    coutcomment,
	/* INAS		3 */	"as",	ASINCOMMENT,   newline,
	/* INLD		4 */	"ld",	cincomment,    coutcomment,
	/* INLINT	5 */	"lint",	cincomment,    coutcomment,
	/* INF77	6 */	"f77",	fincomment,    foutcomment,
	/* INPI		7 */	"pi",	piincomment,   pioutcomment,
	/* INPC		8 */	"pc",	piincomment,   pioutcomment,
	/* INFRANZ	9 */	"franz", lispincomment, newline,
	/* INLISP	10 */	"lisp",	lispincomment, newline,
	/* INVAXIMA	11 */	"vaxima", lispincomment, newline,
	/* INRATFOR	12 */	"ratfor", fincomment,   foutcomment,
	/* INLEX	13 */	"lex",	cincomment,    coutcomment,
	/* INYACC	14 */	"yacc",	cincomment,    coutcomment,
	/* INAPL	15 */	"apl",	".lm", newline,
	/* INMAKE	16 */	"make",	ASINCOMMENT,   newline,
	/* INRI		17 */	"ri",	riincomment,   rioutcomment,
	/* INTROFF	18 */	"troff", troffincomment, troffoutcomment,
	/* INMOD2	19 */	"mod2",	mod2incomment, mod2outcomment,
	/* INSUNF77	20 */	"Sunf77", fincomment,   foutcomment,
	0,	0,	0
};

void
printerrors(boolean look_at_subclass, int errorc, Eptr errorv[])
{
	int	i;
	Eptr	errorp;

	for (errorp = errorv[i = 0]; i < errorc; errorp = errorv[++i]) {
		if (errorp->error_e_class == C_IGNORE)
			continue;
		if (look_at_subclass && errorp->error_s_class == C_DUPL)
			continue;
		(void) printf("Error %d, (%s error) [%s], text = \"",
		    i,
		    class_table[errorp->error_e_class],
		    lang_table[errorp->error_language].lang_name);
		wordvprint(stdout, errorp->error_lgtext, errorp->error_text);
		(void) printf("\"\n");
	}
}

void
wordvprint(FILE *fyle, int wordc, char *wordv[])
{
	int	i;
	char *sep = "";

	for (i = 0; i < wordc; i++)
		if (wordv[i]) {
			(void) fprintf(fyle, "%s%s", sep, wordv[i]);
			sep = " ";
		}
}

/*
 *	Given a string, parse it into a number of words, and build
 *	a wordc wordv combination pointing into it.
 */
void
wordvbuild(char *string, int *r_wordc, char ***r_wordv)
{
	char 	*cp;
	char	*saltedbuffer;
	char	**wordv;
	int	wordcount;
	int	wordindex;

	saltedbuffer = strsave(string);
	for (wordcount = 0, cp = saltedbuffer; *cp; wordcount++) {
		while (*cp && isspace(*cp))
			cp++;
		while (*cp && !isspace(*cp))
			cp++;
	}
	wordv = Calloc(wordcount + 1, sizeof (char *));
	for (cp = saltedbuffer, wordindex = 0; wordcount;
	    wordindex++, --wordcount) {
		while (*cp && isspace(*cp))
			cp++;
		if (*cp == 0)
			break;
		wordv[wordindex] = cp;
		while (*cp && !isspace(*cp))
			cp++;
		*cp++ = '\0';
	}
	if (wordcount != 0)
		error("Initial miscount of the number of words in a line\n");
	wordv[wordindex] = NULL;
#ifdef FULLDEBUG
	for (wordcount = 0; wordcount < wordindex; wordcount++)
		(void) printf("Word %d = \"%s\"\n", wordcount,
		    wordv[wordcount]);
	(void) printf("\n");
#endif
	*r_wordc = wordindex;
	*r_wordv = wordv;
}
/*
 *	Compare two 0 based wordvectors
 */
int
wordvcmp(char **wordv1, int wordc, char **wordv2)
{
	int i;
	int	back;

	for (i = 0; i < wordc; i++) {
		if (wordv1[i] == 0 || wordv2[i] == 0)
				return (-1);
		if (back = strcmp(wordv1[i], wordv2[i])) {
			return (back);
		}
	}
	return (0);	/* they are equal */
}

/*
 *	splice a 0 basedword vector onto the tail of a
 *	new wordv, allowing the first emptyhead slots to be empty
 */
char **
wordvsplice(int emptyhead, int wordc, char **wordv)
{
	char	**nwordv;
	int	nwordc = emptyhead + wordc;
	int	i;

	nwordv = Calloc(nwordc, sizeof (char *));
	for (i = 0; i < emptyhead; i++)
		nwordv[i] = 0;
	for (i = emptyhead; i < nwordc; i++) {
		nwordv[i] = wordv[i-emptyhead];
	}
	return (nwordv);
}

/*
 *	plural'ize and verb forms
 */
static	char	*S = "s";
static	char	*N = "";

char *
plural(int n)
{
	return (n > 1 ? S : N);
}

char *
verbform(int n)
{
	return (n > 1 ? N : S);
}
