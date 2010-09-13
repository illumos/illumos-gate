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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * 	cscope - interactive C symbol or text cross-reference
 *
 *	searching functions
 */

#include <unistd.h>
#include <stdio.h>
#include <libgen.h>
#include "global.h"
#include "vp.h"

/*
 * most of these functions have been optimized so their innermost loops have
 * only one test for the desired character by putting the char and
 * an end-of-block marker (\0) at the end of the disk block buffer.
 * When the inner loop exits on the char, an outer loop will see if
 * the char is followed by a \0.  If so, it will read the next block
 * and restart the inner loop.
 */

char	block[BUFSIZ + 2];		/* leave room for end-of-block mark */
int	blocklen;			/* length of disk block read */
char	blockmark;			/* mark character to be searched for */
long	blocknumber;			/* block number */
char	*blockp;			/* pointer to current char in block */
char	lastfilepath[PATHLEN + 1];	/* last file that full path was */
					/* computed for */

static	char	cpattern[PATLEN + 1];	/* compressed pattern */
static	long	lastfcnoffset;		/* last function name offset */
static	long	postingsfound;		/* retrieved number of postings */
static	char	*regexp;		/* regular expression */
static	POSTING	*postingp;		/* retrieved posting set pointer */
static	long	searchcount;		/* count of files searched */
static	long	starttime;		/* start time for progress messages */

static POSTING *getposting(void);
static void putsource(FILE *output);
static void putref(char *file, char *function);
static void findcalledbysub(char *file);
static void findterm(void);
static void fileprogress(void);
static void putpostingref(POSTING *p);
static void putline(FILE *output);
static char *strtolower(char *s);
static char *filepath(char *file);

/* find the symbol in the cross-reference */

void
findsymbol(void)
{
	char	file[PATHLEN + 1];	/* source file name */
	char	function[PATLEN + 1];	/* function name */
	char	macro[PATLEN + 1];	/* macro name */
	char	symbol[PATLEN + 1];	/* symbol name */
	char	*cp;
	char	c;
	char	*s;

	if (invertedindex == YES) {
		long	lastline = 0;
		POSTING	*p;

		findterm();
		while ((p = getposting()) != NULL) {
			if (p->type != INCLUDE && p->lineoffset != lastline) {
				putpostingref(p);
				lastline = p->lineoffset;
			}
		}
		return;
	}
	(void) scanpast('\t');		/* find the end of the header */
	skiprefchar();			/* skip the file marker */
	getstring(file);		/* save the file name */
	*function = '\0';
	/* a macro can be inside a function, but not vice versa */
	*macro = '\0';

	/* find the next symbol */
	/* note: this code was expanded in-line for speed */
	/* while (scanpast('\n') != NULL) { */
	/* other macros were replaced by code using cp instead of blockp */
	cp = blockp;
	for (;;) {
		setmark('\n');
		do {	/* innermost loop optimized to only one test */
			while (*cp != '\n') {
				++cp;
			}
		} while (*(cp + 1) == '\0' && (cp = readblock()) != NULL);

		/* skip the found character */
		if (cp != NULL && *(++cp + 1) == '\0') {
			cp = readblock();
		}
		if (cp == NULL) {
			break;
		}
		/* look for a source file or function name */
		if (*cp == '\t') {
			blockp = cp;
			switch (getrefchar()) {

			case NEWFILE:		/* file name */

				/* save the name */
				skiprefchar();
				getstring(file);

				/* check for the end of the symbols */
				if (*file == '\0') {
					return;
				}
				fileprogress();
				/* FALLTHROUGH */

			case FCNEND:		/* function end */
				*function = '\0';
				goto notmatched;	/* don't match name */

			case FCNDEF:		/* function name */
				s = function;
				break;

			case DEFINE:		/* could be a macro */
				if (fileversion >= 10) {
					s = macro;
				} else {
					s = symbol;
				}
				break;

			case DEFINEEND:
				*macro = '\0';
				goto notmatched;	/* don't match name */

			case INCLUDE:		/* #include file */
				goto notmatched;	/* don't match name */
			default:		/* other symbol */
				s = symbol;
			}
			/* save the name */
			skiprefchar();
			getstring(s);

			/* see if this is a regular expression pattern */
			if (regexp != NULL) {
				if (caseless == YES) {
					s = strtolower(s);
				}
				if (*s != '\0' && regex(regexp, s) != NULL) {
					goto matched;
				}
			}
			/* match the symbol to the text pattern */
			else if (strequal(pattern, s)) {
				goto matched;
			}
			goto notmatched;
		}
		/* if this is a regular expression pattern */
		if (regexp != NULL) {
			c = *cp;
			if (c & 0200) {	/* digraph char? */
				c = dichar1[(c & 0177) / 8];
			}
			/* if this is a symbol */
			if (isalpha(c) || c == '_') {
				blockp = cp;
				getstring(symbol);
				s = symbol;
				if (caseless == YES) {
					s = strtolower(s);
				}
				/* match the symbol to the regular expression */
				if (regex(regexp, s) != NULL) {
					goto matched;
				}
				goto notmatched;
			}
		}
		/* match the character to the text pattern */
		else if (*cp == cpattern[0]) {
			blockp = cp;

			/* match the rest of the symbol to the text pattern */
			if (matchrest()) {
				s = NULL;
matched:
				/*
				 * output the file, calling function or macro,
				 * and source line
				 */
				if (*macro != '\0' && s != macro) {
					putref(file, macro);
				} else if (s != function) {
					putref(file, function);
				} else {
					putref(file, "");
				}
				if (blockp == NULL) {
					return;
				}
			}
notmatched:
			cp = blockp;
		}
	}
	blockp = cp;
}

/* find the function definition or #define */

void
finddef(void)
{
	char	file[PATHLEN + 1];	/* source file name */
	char	function[PATLEN + 1];	/* function name */
	char	macro[PATLEN + 1];	/* macro name */
	char	symbol[PATLEN + 1];	/* symbol name */
	char	*s;

	if (invertedindex == YES) {
		POSTING	*p;

		findterm();
		while ((p = getposting()) != NULL) {
			switch (p->type) {
			case DEFINE:		/* could be a macro */
			case FCNDEF:
			case CLASSDEF:
			case ENUMDEF:
			case MEMBERDEF:
			case STRUCTDEF:
			case TYPEDEF:
			case UNIONDEF:
			case GLOBALDEF:		/* other global definition */
			case LOCALDEF:		/* other local definition */
			case PARAMETER:
				putpostingref(p);
			}
		}
		return;
	}
	/* find the next file name or definition */
	*function = '\0';
	/* a macro can be inside a function, but not vice versa */
	*macro = '\0';

	while (scanpast('\t') != NULL) {
		switch (*blockp) {

		case NEWFILE:
			skiprefchar();	/* save file name */
			getstring(file);
			if (*file == '\0') {	/* if end of symbols */
				return;
			}
			fileprogress();
			/* FALLTHROUGH */

		case FCNEND:		/* function end */
			*function = '\0';
			break;

		case FCNDEF:		/* function name */
			s = function;
			goto def;

		case DEFINE:		/* could be a macro */
			if (fileversion >= 10) {
				s = macro;
			} else {
				s = symbol;
			}
			goto def;

		case DEFINEEND:
			*macro = '\0';
			break;

		case CLASSDEF:
		case ENUMDEF:
		case MEMBERDEF:
		case STRUCTDEF:
		case TYPEDEF:
		case UNIONDEF:
		case GLOBALDEF:		/* other global definition */
		case LOCALDEF:		/* other local definition */
		case PARAMETER:
			s = symbol;
		def:
			/* save the name */
			skiprefchar();
			getstring(s);

			/* see if this is a regular expression pattern */
			if (regexp != NULL) {
				if (caseless == YES) {
					s = strtolower(s);
				}
				if (*s != '\0' && regex(regexp, s) != NULL) {
					goto matched;
				}
			} else if (strequal(pattern, s)) {
				/* match the symbol to the text pattern */
matched:
				/*
				 * output the file, calling function or macro,
				 * and source line
				 */
				if (*macro != '\0' && s != macro) {
					putref(file, macro);
				} else if (s != function) {
					putref(file, function);
				} else {
					putref(file, "");
				}
			}
		}
	}
}

/* find all function definitions (used by samuel only) */

void
findallfcns(void)
{
	char	file[PATHLEN + 1];	/* source file name */
	char	function[PATLEN + 1];	/* function name */

	/* find the next file name or definition */
	while (scanpast('\t') != NULL) {
		switch (*blockp) {
		case NEWFILE:
			skiprefchar();	/* save file name */
			getstring(file);
			if (*file == '\0') {	/* if end of symbols */
				return;
			}
			fileprogress();
			break;

		case FCNDEF:
		case CLASSDEF:
			skiprefchar();	/* save function name */
			getstring(function);

			/* output the file, function and source line */
			putref(file, function);
			break;
		}
	}
}

/* find the functions called by this function */

void
findcalledby(void)
{
	char	file[PATHLEN + 1];	/* source file name */

	if (invertedindex == YES) {
		POSTING	*p;

		findterm();
		while ((p = getposting()) != NULL) {
			switch (p->type) {
			case DEFINE:		/* could be a macro */
			case FCNDEF:
				if (dbseek(p->lineoffset) != -1 &&
				    scanpast('\t') != NULL) {	/* skip def */
					findcalledbysub(srcfiles[p->fileindex]);
				}
			}
		}
		return;
	}
	/* find the function definition(s) */
	while (scanpast('\t') != NULL) {
		switch (*blockp) {
		case NEWFILE:
			skiprefchar();	/* save file name */
			getstring(file);
			if (*file == '\0') {	/* if end of symbols */
				return;
			}
			fileprogress();
			break;

		case DEFINE:		/* could be a macro */
			if (fileversion < 10) {
				break;
			}
			/* FALLTHROUGH */

		case FCNDEF:
			skiprefchar();	/* match name to pattern */
			if (match()) {
				findcalledbysub(file);
			}
			break;
		}
	}
}

static void
findcalledbysub(char *file)
{
	/* find the next function call or the end of this function */
	while (scanpast('\t') != NULL) {
		switch (*blockp) {
		case DEFINE:		/* #define inside a function */
			if (fileversion >= 10) {	/* skip it */
				while (scanpast('\t') != NULL &&
				    *blockp != DEFINEEND)
					;
			}
			break;
		case FCNCALL:		/* function call */

			/* output the file name */
			(void) fprintf(refsfound, "%s ", filepath(file));

			/* output the function name */
			skiprefchar();
			putline(refsfound);
			(void) putc(' ', refsfound);

			/* output the source line */
			putsource(refsfound);
			break;

		case DEFINEEND:		/* #define end */
		case FCNEND:		/* function end */
		case FCNDEF:		/* function end (pre 9.5) */
		case NEWFILE:		/* file end */
			return;
		}
	}
}

/* find the functions calling this function */

void
findcalling(void)
{
	char	file[PATHLEN + 1];	/* source file name */
	char	function[PATLEN + 1];	/* function name */
	char	macro[PATLEN + 1];	/* macro name */

	if (invertedindex == YES) {
		POSTING	*p;

		findterm();
		while ((p = getposting()) != NULL) {
			if (p->type == FCNCALL) {
				putpostingref(p);
			}
		}
		return;
	}
	/* find the next file name or function definition */
	/* a macro can be inside a function, but not vice versa */
	*macro = '\0';

	while (scanpast('\t') != NULL) {
		switch (*blockp) {
		case NEWFILE:		/* save file name */
			skiprefchar();
			getstring(file);
			if (*file == '\0') {	/* if end of symbols */
				return;
			}
			fileprogress();
			/* FALLTHROUGH */
		case FCNEND:		/* function end */
			*function = '\0';
			break;
		case DEFINE:		/* could be a macro */
			if (fileversion >= 10) {
				skiprefchar();
				getstring(macro);
			}
			break;

		case DEFINEEND:
			*macro = '\0';
			break;

		case FCNDEF:		/* save calling function name */
			skiprefchar();
			getstring(function);
			break;
		case FCNCALL:		/* match function called to pattern */
			skiprefchar();
			if (match()) {
				/* output the file, calling function or */
				/* macro, and source */
				if (*macro != '\0') {
					putref(file, macro);
				} else {
					putref(file, function);
				}
			}
		}
	}
}

/* find direct assignment to, and increment and decrement of, this variable */

void
findassignments(void)
{
	char	file[PATHLEN + 1];	/* source file name */
	char	function[PATLEN + 1];	/* function name */
	char	macro[PATLEN + 1];	/* macro name */

	if (fileversion < 13) {
		putmsg("Database built with cscope version < 13 does not "
		    "have assignment information");
		(void) sleep(3);
		return;
	}
#if CTRACE
	ctroff();
#endif
	if (invertedindex == YES) {
		POSTING	*p;

		findterm();
		while ((p = getposting()) != NULL) {
			switch (p->type) {
			case ASSIGNMENT:
			case GLOBALDEF:		/* can have initializer */
			case LOCALDEF:		/* can have initializer */
			case PARAMETER:		/* initial value */
				putpostingref(p);
			}
		}
		return;
	}
	/* find the next file name or function definition */
	/* a macro can be inside a function, but not vice versa */
	*macro = '\0';

	while (scanpast('\t') != NULL) {
		switch (*blockp) {
		case NEWFILE:		/* save file name */
			skiprefchar();
			getstring(file);
			if (*file == '\0') {	/* if end of symbols */
				return;
			}
			fileprogress();
			/* FALLTHROUGH */
		case FCNEND:		/* function end */
			*function = '\0';
			break;
		case DEFINE:		/* could be a macro */
			if (fileversion >= 10) {
				skiprefchar();
				getstring(macro);
			}
			break;

		case DEFINEEND:
			*macro = '\0';
			break;

		case FCNDEF:		/* save calling function name */
			skiprefchar();
			getstring(function);
			break;
		case ASSIGNMENT:	/* match assignment to pattern */
		case GLOBALDEF:		/* can have initializer */
		case LOCALDEF:		/* can have initializer */
		case PARAMETER:		/* initial value */
			skiprefchar();
			if (match()) {
				/* output the file, calling function or */
				/* macro, and source */
				if (*macro != '\0') {
					putref(file, macro);
				} else {
					putref(file, function);
				}
			}
		}
	}
}

/* find the grep pattern in the source files */

char *
findgreppat(void)
{
	char	egreppat[2 * PATLEN];
	char	*cp, *pp;

	/* translate egrep special characters in the regular expression */
	cp = egreppat;
	for (pp = pattern; *pp != '\0'; ++pp) {
		if (strchr("+?|()", *pp) != NULL) {
			*cp++ = '\\';
		}
		*cp++ = *pp;
	}
	*cp = '\0';

	/* search the source files */
	return (findegreppat(egreppat));
}

/* find this regular expression in the source files */

char *
findegreppat(char *egreppat)
{
	int	i;
	char	*egreperror;
	char	msg[MSGLEN + 1];

	/* compile the pattern */
	if ((egreperror = egrepinit(egreppat)) == NULL) {

		/* search the files */
		for (i = 0; i < nsrcfiles; ++i) {
			char *file = filepath(srcfiles[i]);
			fileprogress();
			if (egrep(file, refsfound, "%s <unknown> %ld ") < 0) {
				(void) sprintf(msg, "Cannot open file %s",
				    file);
				putmsg2(msg);
			}
		}
	}
	return (egreperror);
}

/* find matching file names */

void
findfile(void)
{
	int	i;
	char	*s;

	for (i = 0; i < nsrcfiles; ++i) {
		s = srcfiles[i];
		if (caseless == YES) {
			s = strtolower(s);
		}
		if (regex(regexp, s) != NULL) {
			(void) fprintf(refsfound, "%s <unknown> 1 <unknown>\n",
				filepath(srcfiles[i]));
		}
	}
}

/* find files #including this file */

void
findinclude(void)
{
	char	file[PATHLEN + 1];	/* source file name */

	if (invertedindex == YES) {
		POSTING	*p;

		findterm();
		while ((p = getposting()) != NULL) {
			if (p->type == INCLUDE) {
				putpostingref(p);
			}
		}
		return;
	}
	/* find the next file name or function definition */
	while (scanpast('\t') != NULL) {
		switch (*blockp) {

		case NEWFILE:		/* save file name */
			skiprefchar();
			getstring(file);
			if (*file == '\0') {	/* if end of symbols */
				return;
			}
			fileprogress();
			break;

		case INCLUDE:		/* match function called to pattern */
			skiprefchar();
			/* skip global or local #include marker */
			skiprefchar();
			if (match()) {
				/* output the file and source line */
				putref(file, "");
			}
		}
	}
}

/* initialize */

FINDINIT
findinit(void)
{
	char	buf[PATLEN + 3];
	BOOL	isregexp = NO;
	int	i;
	char	*s;
	unsigned c;

	/* remove trailing white space */
	for (s = pattern + strlen(pattern) - 1; isspace(*s); --s) {
		*s = '\0';
	}
	/* allow a partial match for a file name */
	if (field == FILENAME || field == INCLUDES) {
		/* allow types.h to match #include <sys/types.h> */
		if (invertedindex == YES && field == INCLUDES &&
		    strncmp(pattern, ".*", 2) != 0) {
			(void) sprintf(pattern, ".*%s", strcpy(buf, pattern));
		}
		if ((regexp = regcmp(pattern, (char *)NULL)) == NULL) {
			return (REGCMPERROR);
		}
		return (NOERROR);
	}
	/* see if the pattern is a regular expression */
	if (strpbrk(pattern, "^.[{*+$") != NULL) {
		isregexp = YES;
	} else {
		/* check for a valid C symbol */
		s = pattern;
		if (!isalpha(*s) && *s != '_') {
			return (NOTSYMBOL);
		}
		while (*++s != '\0') {
			if (!isalnum(*s) && *s != '_') {
				return (NOTSYMBOL);
			}
		}
		/*
		 * look for use of the -T option (truncate symbol to 8
		 * characters) on a database not built with -T
		 */
		if (truncatesyms == YES && isuptodate == YES &&
		    dbtruncated == NO && s - pattern >= 8) {
			(void) strcpy(pattern + 8, ".*");
			isregexp = YES;
		}
	}
	/* if this is a regular expression or letter case is to be ignored */
	/* or there is an inverted index */
	if (isregexp == YES || caseless == YES || invertedindex == YES) {

		/* remove a leading ^ */
		s = pattern;
		if (*s == '^') {
			(void) strcpy(newpat, s + 1);
			(void) strcpy(s, newpat);
		}
		/* remove a trailing $ */
		i = strlen(s) - 1;
		if (s[i] == '$') {
			s[i] = '\0';
		}
		/* if requested, try to truncate a C symbol pattern */
		if (truncatesyms == YES && strpbrk(s, "[{*+") == NULL) {
			s[8] = '\0';
		}
		/* must be an exact match */
		/*
		 * note: regcmp doesn't recognize ^*keypad$ as an syntax error
		 * unless it is given as a single arg
		 */
		(void) sprintf(buf, "^%s$", s);
		if ((regexp = regcmp(buf, (char *)NULL)) == NULL) {
			return (REGCMPERROR);
		}
	} else {
		/* if requested, truncate a C symbol pattern */
		if (truncatesyms == YES && field <= CALLING) {
			pattern[8] = '\0';
		}
		/* compress the string pattern for matching */
		s = cpattern;
		for (i = 0; (c = pattern[i]) != '\0'; ++i) {
			if (dicode1[c] && dicode2[(unsigned)pattern[i + 1]]) {
				c = (0200 - 2) + dicode1[c] +
				    dicode2[(unsigned)pattern[i + 1]];
				++i;
			}
			*s++ = (char)c;
		}
		*s = '\0';
	}
	return (NOERROR);
}

void
findcleanup(void)
{
	/* discard any regular expression */
	if (regexp != NULL) {
		free(regexp);
		regexp = NULL;
	}
}

/* find this term, which can be a regular expression */

static void
findterm(void)
{
	char	*s;
	int	len;
	char	prefix[PATLEN + 1];
	char	term[PATLEN + 1];

	npostings = 0;		/* will be non-zero after database built */
	lastfcnoffset = 0;	/* clear the last function name found */
	boolclear();		/* clear the posting set */

	/* get the string prefix (if any) of the regular expression */
	(void) strcpy(prefix, pattern);
	if ((s = strpbrk(prefix, ".[{*+")) != NULL) {
		*s = '\0';
	}
	/* if letter case is to be ignored */
	if (caseless == YES) {

		/*
		 * convert the prefix to upper case because it is lexically
		 * less than lower case
		 */
		s = prefix;
		while (*s != '\0') {
			*s = toupper(*s);
			++s;
		}
	}
	/* find the term lexically >= the prefix */
	(void) invfind(&invcontrol, prefix);
	if (caseless == YES) {	/* restore lower case */
		(void) strcpy(prefix, strtolower(prefix));
	}
	/*
	 * a null prefix matches the null term in the inverted index,
	 * so move to the first real term
	 */
	if (*prefix == '\0') {
		(void) invforward(&invcontrol);
	}
	len = strlen(prefix);
	do {
		(void) invterm(&invcontrol, term);	/* get the term */
		s = term;
		if (caseless == YES) {
			s = strtolower(s);	/* make it lower case */
		}
		/* if it matches */
		if (regex(regexp, s) != NULL) {
			/* add it's postings to the set */
			if ((postingp = boolfile(&invcontrol,
			    &npostings, OR)) == NULL) {
				break;
			}
		} else if (len > 0) {
			/* if there is a prefix */

			/*
			 * if ignoring letter case and the term is out of the
			 * range of possible matches
			 */
			if (caseless == YES) {
				if (strncmp(term, prefix, len) > 0) {
					break;	/* stop searching */
				}
			}
			/* if using letter case and the prefix doesn't match */
			else if (strncmp(term, prefix, len) != 0) {
				break;	/* stop searching */
			}
		}
		/* display progress about every three seconds */
		if (++searchcount % 50 == 0) {
			progress("%ld of %ld symbols matched",
			    searchcount, totalterms);
		}
	} while (invforward(&invcontrol));	/* while didn't wrap around */

	/* initialize the progress message for retrieving the references */
	initprogress();
	postingsfound = npostings;
}

/* display the file search progress about every three seconds */

static void
fileprogress(void)
{
	if (++searchcount % 10 == 0) {
		progress("%ld of %ld files searched", searchcount,
		    (long)nsrcfiles);
	}
}

/* initialize the progress message */

void
initprogress(void)
{
	searchcount = 0;
	starttime = time((long *)NULL);
}

/* display the progress every three seconds */

void
progress(char *format, long n1, long n2)
{
	char	msg[MSGLEN + 1];
	long	now;

	/* print after 2 seconds so the average is nearer 3 seconds */
	if (linemode == NO && (now = time((long *)NULL)) - starttime >= 2) {
		starttime = now;
		(void) sprintf(msg, format, n1, n2);
		putmsg(msg);
	}
}

/* match the pattern to the string */

BOOL
match(void)
{
	char	string[PATLEN + 1];
	char	*s;

	/* see if this is a regular expression pattern */
	if (regexp != NULL) {
		getstring(string);
		if (*string == '\0') {
			return (NO);
		}
		s = string;
		if (caseless == YES) {
			s = strtolower(s);
		}
		return (regex(regexp, s) ? YES : NO);
	}
	/* it is a string pattern */
	return ((BOOL)(*blockp == cpattern[0] && matchrest()));
}

/* match the rest of the pattern to the name */

BOOL
matchrest(void)
{
	int	i = 1;

	skiprefchar();
	do {
		while (*blockp == cpattern[i]) {
			++blockp;
			++i;
		}
	} while (*(blockp + 1) == '\0' && readblock() != NULL);

	if (*blockp == '\n' && cpattern[i] == '\0') {
		return (YES);
	}
	return (NO);
}

/* get the next posting for this term */

static POSTING *
getposting(void)
{
	if (npostings-- <= 0) {
		return (NULL);
	}
	/* display progress about every three seconds */
	if (++searchcount % 100 == 0) {
		progress("%ld of %ld possible references retrieved",
		    searchcount, postingsfound);
	}
	return (postingp++);
}

/* put the posting reference into the file */

static void
putpostingref(POSTING *p)
{
	static	char	function[PATLEN + 1];	/* function name */

	if (p->fcnoffset == 0) {
		*function = '\0';
	} else if (p->fcnoffset != lastfcnoffset) {
		if (dbseek(p->fcnoffset) != -1) {
			getstring(function);
			lastfcnoffset = p->fcnoffset;
		}
	}
	if (dbseek(p->lineoffset) != -1) {
		putref(srcfiles[p->fileindex], function);
	}
}

/* put the reference into the file */

static void
putref(char *file, char *function)
{
	FILE	*output;

	/* put global references first */
	if (*function == '\0') {
		function = "<global>";
		output = refsfound;
	} else {
		output = nonglobalrefs;
	}
	if (fprintf(output, "%s %s ", filepath(file), function) == EOF) {
		cannotwrite(temp1);
		/* NOTREACHED */
	}
	putsource(output);
}

/* put the source line into the file */

static void
putsource(FILE *output)
{
	char	*cp, nextc = '\0';

	if (fileversion <= 5) {
		(void) scanpast(' ');
		putline(output);
		(void) putc('\n', output);
		return;
	}
	/* scan back to the beginning of the source line */
	cp = blockp;
	while (*cp != '\n' || nextc != '\n') {
		nextc = *cp;
		if (--cp < block) {
			/* read the previous block */
			(void) dbseek((blocknumber - 1) * BUFSIZ);
			cp = &block[BUFSIZ - 1];
		}
	}
	/* there must be a double newline followed by a line number */
	blockp = cp;
	setmark(' ');	/* so getrefchar doesn't skip the last block char */
	if (*blockp != '\n' || getrefchar() != '\n' ||
	    !isdigit(getrefchar()) && fileversion >= 12) {
		putmsg("Internal error: cannot get source line from database");
		myexit(1);
	}
	/* until a double newline is found */
	do {
		/* skip a symbol type */
		if (*blockp == '\t') {
			skiprefchar();
			skiprefchar();
		}
		/* output a piece of the source line */
		putline(output);
	} while (blockp != NULL && getrefchar() != '\n');
	(void) putc('\n', output);
}

/* put the rest of the cross-reference line into the file */

static void
putline(FILE *output)
{
	char	*cp;
	unsigned c;

	setmark('\n');
	cp = blockp;
	do {
		while ((c = *cp) != '\n') {
			/* check for a compressed digraph */
			if (c & 0200) {
				c &= 0177;
				(void) putc(dichar1[c / 8], output);
				(void) putc(dichar2[c & 7], output);
			} else if (c < ' ') {
				/* a compressed keyword */
				(void) fputs(keyword[c].text, output);
				if (keyword[c].delim != '\0') {
					(void) putc(' ', output);
				}
				if (keyword[c].delim == '(') {
					(void) putc('(', output);
				}
			} else {
				(void) putc((int)c, output);
			}
			++cp;
		}
	} while (*(cp + 1) == '\0' && (cp = readblock()) != NULL);
	blockp = cp;
}

/* put the rest of the cross-reference line into the string */

void
getstring(char *s)
{
	char	*cp;
	unsigned c;

	setmark('\n');
	cp = blockp;
	do {
		while ((c = *cp) != '\n') {
			if (c & 0200) {
				c &= 0177;
				*s++ = dichar1[c / 8];
				*s++ = dichar2[c & 7];
			} else {
				*s++ = (char)c;
			}
			++cp;
		}
	} while (*(cp + 1) == '\0' && (cp = readblock()) != NULL);
	blockp = cp;
	*s = '\0';
}

/* scan past the next occurence of this character in the cross-reference */

char *
scanpast(int c)
{
	char	*cp;

	setmark(c);
	cp = blockp;
	do {	/* innermost loop optimized to only one test */
		while (*cp != c) {
			++cp;
		}
	} while (*(cp + 1) == '\0' && (cp = readblock()) != NULL);
	blockp = cp;
	if (cp != NULL) {
		skiprefchar();	/* skip the found character */
	}
	return (blockp);
}

/* read a block of the cross-reference */

char *
readblock(void)
{
	/* read the next block */
	blocklen = read(symrefs, block, BUFSIZ);
	blockp = block;

	/* add the search character and end-of-block mark */
	block[blocklen] = blockmark;
	block[blocklen + 1] = '\0';

	/* return NULL on end-of-file */
	if (blocklen == 0) {
		blockp = NULL;
	} else {
		++blocknumber;
	}
	return (blockp);
}

/* seek to the database offset */

long
dbseek(long offset)
{
	long	n;
	int	rc = 0;

	if ((n = offset / BUFSIZ) != blocknumber) {
		if ((rc = lseek(symrefs, n * BUFSIZ, 0)) == -1) {
			myperror("Lseek failed");
			(void) sleep(3);
			return (rc);
		}
		(void) readblock();
		blocknumber = n;
	}
	blockp = block + offset % BUFSIZ;
	return (rc);
}

/* convert the string to lower case */

static char *
strtolower(char *s)
{
	static char buf[PATLEN + 1];
	char *lp = buf;

	while (*s != '\0') {
		/*
		 * note: s in not incremented in this line because the BSD
		 * compatibility tolower macro evaluates its argument twice
		 */
		*lp++ = tolower(*s);
		++s;
	}
	*lp = '\0';
	return (buf);
}

/* if needed, convert a relative path to a full path */

static char *
filepath(char *file)
{
	static	char	path[PATHLEN + 1];
	int	i;

	if (*file != '/') {

		/* if same file as last time, return the same path */
		if (strequal(file, lastfilepath)) {
			return (path);
		}
		(void) strcpy(lastfilepath, file);

		/* if requested, prepend a path to a relative file path */
		if (prependpath != NULL) {
			(void) sprintf(path, "%s/%s", prependpath, file);
			return (path);
		}
		/*
		 * if the database was built with a view path, return a
		 * full path so "cscope -d -f" does not have to be called
		 * from the build directory with the same view path
		 */
		if (dbvpndirs > 1) {
			for (i = 0; i < dbvpndirs; i++) {
				(void) sprintf(path,
				    "%s/%s", dbvpdirs[i], file);
				if (access(path, READ) != -1) {
					return (path);
				}
			}
		}
		(void) strcpy(path, file);	/* for lastfilepath check */
	}
	return (file);
}
