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
 *	cscope - interactive C symbol cross-reference
 *
 *	build cross-reference file
 */

#include "global.h"

/* convert long to a string */
#define	ltobase(value)	n = value; \
			s = buf + (sizeof (buf) - 1); \
			*s = '\0'; \
			digits = 1; \
			while (n >= BASE) { \
				++digits; \
				i = n; \
				n /= BASE; \
				*--s = i - n * BASE + '!'; \
			} \
			*--s = n + '!';

#define	SYMBOLINC	20	/* symbol list size increment */
#define	FREAD	"r"		/* fopen for reading */

long	dboffset;		/* new database offset */
BOOL	errorsfound;		/* prompt before clearing messages */
long	fileindex;		/* source file name index */
long	lineoffset;		/* source line database offset */
long	npostings;		/* number of postings */
int	nsrcoffset;		/* number of file name database offsets */
long	*srcoffset;		/* source file name database offsets */
int	symbols;		/* number of symbols */

static	char	*filename;	/* file name for warning messages */
static	long	fcnoffset;	/* function name database offset */
static	long	macrooffset;	/* macro name database offset */
static	int	msymbols = SYMBOLINC;	/* maximum number of symbols */
static	struct	symbol {	/* symbol data */
	int	type;		/* type */
	int	first;		/* index of first character in text */
	int	last;		/* index of last+1 character in text */
	int	length;		/* symbol length */
} *symbol;

static void putcrossref(void);

void
crossref(char *srcfile)
{
	int	i;
	int	length;		/* symbol length */
	int	token;			/* current token */

	/* open the source file */
	if ((yyin = vpfopen(srcfile, FREAD)) == NULL) {
		cannotopen(srcfile);
		errorsfound = YES;
		return;
	}
	filename = srcfile;	/* save the file name for warning messages */
	putfilename(srcfile);	/* output the file name */
	dbputc('\n');
	dbputc('\n');

	/* read the source file */
	initscanner(srcfile);
	fcnoffset = macrooffset = 0;
	symbols = 0;
	if (symbol == NULL) {
		symbol = mymalloc(msymbols * sizeof (struct symbol));
	}
	for (;;) {

		/* get the next token */
		switch (token = yylex()) {
		default:
			/* if requested, truncate C symbols */
			length = last - first;
			if (truncatesyms && length > 8 &&
			    token != INCLUDE && token != NEWFILE) {
				length = 8;
				last = first + 8;
			}
			/* see if the token has a symbol */
			if (length == 0) {
				savesymbol(token);
				break;
			}
			/* see if the symbol is already in the list */
			for (i = 0; i < symbols; ++i) {
				if (length == symbol[i].length &&
				    strncmp(yytext + first, yytext +
					symbol[i].first, length) == 0 &&
				    (token == IDENT ||
					token == symbol[i].type)) {
					first = yyleng;
					break;
				}
			}
			if (i == symbols) {	/* if not already in list */
				savesymbol(token);
			}
			break;

		case NEWLINE:	/* end of line containing symbols */
			--yyleng;	/* remove the newline */
			putcrossref();	/* output the symbols and source line */
			lineno = yylineno; /* save the symbol line number */
			break;

		case LEXEOF:	/* end of file; last line may not have \n */

			/*
			 * if there were symbols, output them and the
			 * source line
			 */
			if (symbols > 0) {
				putcrossref();
			}
			(void) fclose(yyin);	/* close the source file */

			/* output the leading tab expected by the next call */
			dbputc('\t');
			return;
		}
	}
}

/* save the symbol in the list */

void
savesymbol(int token)
{
	/* make sure there is room for the symbol */
	if (symbols == msymbols) {
		msymbols += SYMBOLINC;
		symbol = (struct symbol *)myrealloc(symbol,
		    msymbols * sizeof (struct symbol));
	}
	/* save the symbol */
	symbol[symbols].type = token;
	symbol[symbols].first = first;
	symbol[symbols].last = last;
	symbol[symbols].length = last - first;
	++symbols;
	first = yyleng;
}

/* output the file name */

void
putfilename(char *srcfile)
{
	/* check for file system out of space */
	/* note: dbputc is not used to avoid lint complaint */
	if (putc(NEWFILE, newrefs) == EOF) {
		cannotwrite(newreffile);
		/* NOTREACHED */
	}
	++dboffset;
	if (invertedindex) {
		srcoffset[nsrcoffset++] = dboffset;
	}
	dbfputs(srcfile);
	fcnoffset = macrooffset = 0;
}

/* output the symbols and source line */

static void
putcrossref(void)
{
	int	i, j;
	unsigned c;
	BOOL	blank = NO;	/* output blank */
	BOOL	newline = NO;	/* output newline */
	int	symput = 0;	/* symbols output */
	int	type;

	/* output the source line */
	lineoffset = dboffset;
	dbfprintf(newrefs, "%d ", lineno);
	for (i = 0; i < yyleng; ++i) {

		/* change a tab to a blank and compress blanks */
		if ((c = yytext[i]) == ' ' || c == '\t') {
			blank = YES;
		}
		/* look for the start of a symbol */
		else if (symput < symbols && i == symbol[symput].first) {

			/* check for compressed blanks */
			if (blank) {
				blank = NO;
				if (newline) {
					dbputc('\n');
				}
				dbputc(' ');
			}
			dbputc('\n');	/* symbols start on a new line */

			/* output any symbol type */
			if ((type = symbol[symput].type) != IDENT) {
				dbputc('\t');
				dbputc(type);
			} else {
				type = ' ';
			}
			/* output the symbol */
			j = symbol[symput].last;
			c = yytext[j];
			yytext[j] = '\0';
			if (invertedindex) {
				putposting(yytext + i, type);
			}
			putstring(yytext + i);
			newline = YES;
			yytext[j] = (char)c;
			i = j - 1;
			++symput;
		} else {
			if (newline) {
				newline = NO;
				dbputc('\n');
			}
			/* check for compressed blanks */
			if (blank) {
				if (dicode2[c]) {
					c = (0200 - 2) + dicode1[' '] +
					    dicode2[c];
				} else {
					dbputc(' ');
				}
			} else if (dicode1[c] &&
			    (j = dicode2[(unsigned)yytext[i + 1]]) != 0 &&
			    symput < symbols && i + 1 != symbol[symput].first) {
				/* compress digraphs */
				c = (0200 - 2) + dicode1[c] + j;
				++i;
			}
			/*
			 * if the last line of the file is a '}' without a
			 * newline, the lex EOF code overwrites it with a 0
			 */
			if (c) {
				dbputc((int)c);
			} else {
				dbputc(' ');
			}
			blank = NO;

			/* skip compressed characters */
			if (c < ' ') {
				++i;

				/* skip blanks before a preprocesor keyword */
				/*
				 * note: don't use isspace() because \f and \v
				 * are used for keywords
				 */
				while ((j = yytext[i]) == ' ' || j == '\t') {
					++i;
				}
				/* skip the rest of the keyword */
				while (isalpha(yytext[i])) {
					++i;
				}
				/* skip space after certain keywords */
				if (keyword[c].delim != '\0') {
					while ((j = yytext[i]) == ' ' ||
					    j == '\t') {
						++i;
					}
				}
				/* skip a '(' after certain keywords */
				if (keyword[c].delim == '(' &&
				    yytext[i] == '(') {
					++i;
				}
				--i;	/* compensate for ++i in for() */
			}
		}
	}
	/* ignore trailing blanks */
	dbputc('\n');
	dbputc('\n');

	/* output any #define end marker */
	/*
	 * note: must not be part of #define so putsource() doesn't discard it
	 * so findcalledbysub() can find it and return
	 */
	if (symput < symbols && symbol[symput].type == DEFINEEND) {
		dbputc('\t');
		dbputc(DEFINEEND);
		dbputc('\n');
		dbputc('\n');	/* mark beginning of next source line */
		macrooffset = 0;
	}
	symbols = 0;
}

/* output the inverted index posting */

void
putposting(char *term, int type)
{
	long	i, n;
	char	*s;
	int	digits;		/* digits output */
	long	offset;		/* function/macro database offset */
	char	buf[11];		/* number buffer */

	/* get the function or macro name offset */
	offset = fcnoffset;
	if (macrooffset != 0) {
		offset = macrooffset;
	}
	/* then update them to avoid negative relative name offset */
	switch (type) {
	case DEFINE:
		macrooffset = dboffset;
		break;
	case DEFINEEND:
		macrooffset = 0;
		return;		/* null term */
	case FCNDEF:
		fcnoffset = dboffset;
		break;
	case FCNEND:
		fcnoffset = 0;
		return;		/* null term */
	}
	/* ignore a null term caused by a enum/struct/union without a tag */
	if (*term == '\0') {
		return;
	}
	/* skip any #include secondary type char (< or ") */
	if (type == INCLUDE) {
		++term;
	}
	/*
	 * output the posting, which should be as small as possible to reduce
	 * the temp file size and sort time
	 */
	(void) fputs(term, postings);
	(void) putc(' ', postings);

	/*
	 * the line offset is padded so postings for the same term will sort
	 * in ascending line offset order to order the references as they
	 * appear withing a source file
	 */
	ltobase(lineoffset);
	for (i = PRECISION - digits; i > 0; --i) {
		(void) putc('!', postings);
	}
	do {
		(void) putc(*s, postings);
	} while (*++s != '\0');

	/* postings are also sorted by type */
	(void) putc(type, postings);

	/* function or macro name offset */
	if (offset > 0) {
		(void) putc(' ', postings);
		ltobase(offset);
		do {
			(void) putc(*s, postings);
		} while (*++s != '\0');
	}
	if (putc('\n', postings) == EOF) {
		cannotwrite(temp1);
		/* NOTREACHED */
	}
	++npostings;
}

/* put the string into the new database */

void
putstring(char *s)
{
	unsigned c;
	int	i;

	/* compress digraphs */
	for (i = 0; (c = s[i]) != '\0'; ++i) {
		if (dicode1[c] && dicode2[(unsigned)s[i + 1]]) {
			c = (0200 - 2) + dicode1[c] +
			    dicode2[(unsigned)s[i + 1]];
			++i;
		}
		dbputc((int)c);
	}
}

/* print a warning message with the file name and line number */

void
warning(text)
char	*text;
{
	extern	int	yylineno;

	(void) fprintf(stderr, "cscope: \"%s\", line %d: warning: %s\n",
	    filename, yylineno, text);
	errorsfound = YES;
}
