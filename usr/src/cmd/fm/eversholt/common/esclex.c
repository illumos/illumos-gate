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
 *
 * esclex.c -- lexer for esc
 *
 * this module provides lexical analysis and error handling routine
 * expected by the yacc-generated parser (i.e. yylex() and yyerror()).
 * it also does lots of tracking of things like filenames, line numbers,
 * and what tokens are seen on a line up to the point where a syntax error
 * was found.  this module also arranges for the input source files to
 * be run through cpp.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "out.h"
#include "alloc.h"
#include "stats.h"
#include "stable.h"
#include "lut.h"
#include "literals.h"
#include "tree.h"
#include "esclex.h"
#include "eftread.h"
#include "check.h"
#include "y.tab.h"

/* ridiculously long token buffer -- disallow any token longer than this */
#define	MAXTOK	8192
static char Tok[MAXTOK];

/* some misc stats we keep on the lexer & parser */
static struct stats *Tokcount;
static struct stats *Lexelapse;
struct stats *Filecount;
struct filestats {
	struct filestats *next;
	struct stats *stats;
	struct stats *idstats;
} *Fstats;

static int Errcount;

/* input file state */
static char **Files;
static const char *Fileopened;
static FILE *Fp;
static int Line;
static const char *File;
static const char *Cpp = "/usr/lib/cpp";
#ifdef	ESC
static const char *Cppargs;
static const char *Cppstdargs = "-undef -Y.";
#endif	/* ESC */

/* for debugging */
static int Lexecho;	/* echo tokens as we read them */

/* forward declarations of our internal routines */
static int record(int tok, const char *s);
static void dumpline(int flags);
static void doident();
static void dopragma(const char *tok);

/*
 * table of reserved words.  this table is only used by lex_init()
 * to intialize the Rwords lookup table.
 */
static const struct {
	const char *word;
	const int val;
} Rwords[] = {
	{ "asru", ASRU },
	{ "count", COUNT },
	{ "div", DIV },
	{ "engine", ENGINE },
	{ "event", EVENT },
	{ "fru", FRU },
	{ "if", IF },
	{ "mask", MASK },
	{ "prop", PROP },
	{ "config", CONFIG },
	/*
	 * PATHFUNC indicates functions that operate only on paths
	 * and quotes
	 */
	{ "is_connected", PATHFUNC },
	{ "is_under", PATHFUNC },
	{ "is_on", PATHFUNC },
	{ "is_present", PATHFUNC },
	{ "is_type", PATHFUNC },
	{ "has_fault", PATHFUNC },
	{ "confprop", PATHFUNC },
	{ "confprop_defined", PATHFUNC },
};

/*
 * Rwordslut is a lookup table of reserved words.  lhs is the word
 * (in the string table) and the rhs is the token value returned
 * by the yylex() for that word.
 */
static struct lut *Rwordslut;

static const struct {
	const char *suffix;
	const unsigned long long nsec;
} Timesuffix[] = {
	{ "nanosecond",		1ULL },
	{ "nanoseconds",	1ULL },
	{ "nsec",		1ULL },
	{ "nsecs",		1ULL },
	{ "ns",			1ULL },
	{ "microsecond",	1000ULL },
	{ "microseconds",	1000ULL },
	{ "usec",		1000ULL },
	{ "usecs",		1000ULL },
	{ "us",			1000ULL },
	{ "millisecond",	1000000ULL },
	{ "milliseconds",	1000000ULL },
	{ "msec",		1000000ULL },
	{ "msecs",		1000000ULL },
	{ "ms",			1000000ULL },
	{ "second",		1000000000ULL },
	{ "seconds",		1000000000ULL },
	{ "s",			1000000000ULL },
	{ "minute",		1000000000ULL * 60 },
	{ "minutes",		1000000000ULL * 60 },
	{ "min",		1000000000ULL * 60 },
	{ "mins",		1000000000ULL * 60 },
	{ "m",			1000000000ULL * 60 },
	{ "hour",		1000000000ULL * 60 * 60 },
	{ "hours",		1000000000ULL * 60 * 60 },
	{ "hr",			1000000000ULL * 60 * 60 },
	{ "hrs",		1000000000ULL * 60 * 60 },
	{ "h",			1000000000ULL * 60 * 60 },
	{ "day",		1000000000ULL * 60 * 60 * 24 },
	{ "days",		1000000000ULL * 60 * 60 * 24 },
	{ "d",			1000000000ULL * 60 * 60 * 24 },
	{ "week",		1000000000ULL * 60 * 60 * 24 * 7 },
	{ "weeks",		1000000000ULL * 60 * 60 * 24 * 7 },
	{ "wk",			1000000000ULL * 60 * 60 * 24 * 7 },
	{ "wks",		1000000000ULL * 60 * 60 * 24 * 7 },
	{ "month",		1000000000ULL * 60 * 60 * 24 * 30 },
	{ "months",		1000000000ULL * 60 * 60 * 24 * 30 },
	{ "year",		1000000000ULL * 60 * 60 * 24 * 365 },
	{ "years",		1000000000ULL * 60 * 60 * 24 * 365 },
	{ "yr",			1000000000ULL * 60 * 60 * 24 * 365 },
	{ "yrs",		1000000000ULL * 60 * 60 * 24 * 365 },
};

/*
 * some wrappers around the general lut functions to provide type checking...
 */

static struct lut *
lex_s2i_lut_add(struct lut *root, const char *s, intptr_t i)
{
	return (lut_add(root, (void *)s, (void *)i, NULL));
}

static int
lex_s2i_lut_lookup(struct lut *root, const char *s)
{
	return ((intptr_t)lut_lookup(root, (void *)s, NULL));
}

static struct lut *
lex_s2ullp_lut_add(struct lut *root, const char *s,
    const unsigned long long *ullp)
{
	return (lut_add(root, (void *)s, (void *)ullp, NULL));
}

const unsigned long long *
lex_s2ullp_lut_lookup(struct lut *root, const char *s)
{
	return ((unsigned long long *)lut_lookup(root, (void *)s, NULL));
}

/*
 * lex_init -- initialize the lexer with appropriate filenames & debug flags
 */

/*ARGSUSED*/
void
lex_init(char **av, const char *cppargs, int lexecho)
{
	int i;
#ifdef	ESC
	const char *ptr;
#endif	/* ESC */

	Lexecho = lexecho;
	Tokcount = stats_new_counter("lex.tokens", "total tokens in", 1);
	Filecount = stats_new_counter("lex.files", "total files read", 0);
	Lexelapse = stats_new_elapse("lex.time", "elapsed lex/parse time", 1);

#ifdef	ESC
	Cppargs = cppargs;

	/* allow user to tell us where cpp is if it is some weird place */
	if (ptr = getenv("_ESC_CPP"))
		Cpp = ptr;

	/* and in case it takes some special stdargs */
	if (ptr = getenv("_ESC_CPP_STDARGS"))
		Cppstdargs = ptr;

	/* verify we can find cpp */
	if (access(Cpp, X_OK) < 0) {
		Cpp = "/usr/lib/cpp";
		if (access(Cpp, X_OK) < 0)
			out(O_DIE, "can't locate cpp");
	}
#endif	/* ESC */

	Files = av;

	/* verify we can find all the input files */
	while (*av) {
		if (strlen(*av) >= MAXTOK - strlen(Cpp) - 3)
			out(O_DIE, "filename too long: %.100s...", *av);
		if (access(*av, R_OK) < 0)
			out(O_DIE|O_SYS, "%s", *av);
		av++;
		stats_counter_bump(Filecount);
	}

	/* put reserved words into the string table & a lookup table */
	for (i = 0; i < sizeof (Rwords) / sizeof (*Rwords); i++)
		Rwordslut = lex_s2i_lut_add(Rwordslut,
		    stable(Rwords[i].word), Rwords[i].val);

	/* initialize table of timeval suffixes */
	for (i = 0; i < sizeof (Timesuffix) / sizeof (*Timesuffix); i++) {
		Timesuffixlut = lex_s2ullp_lut_add(Timesuffixlut,
		    stable(Timesuffix[i].suffix), &Timesuffix[i].nsec);
	}

	/* record start time */
	stats_elapse_start(Lexelapse);
}

void
closefile(void)
{
	if (Fp != NULL) {
#ifdef	ESC
		if (pclose(Fp) > 0)
			out(O_DIE, "cpp errors while reading \"%s\", "
			    "bailing out.", Fileopened);
#else
		(void) fclose(Fp);
#endif	/* ESC */
	}
	Fp = NULL;
}

/*
 * yylex -- the lexer, called yylex() because that's what yacc wants
 */

int
yylex()
{
	int c;
	int nextc;
	char *ptr = Tok;
	char *eptr = &Tok[MAXTOK];
	const char *cptr;
	int startline;
	int val;
	static int bol = 1;	/* true if we're at beginning of line */

	for (;;) {
		while (Fp == NULL) {
			char ibuf[80];

			if (*Files == NULL)
				return (record(EOF, NULL));
			Fileopened = stable(*Files++);
#ifdef	ESC
			sprintf(Tok, "%s %s %s %s",
			    Cpp, Cppstdargs, Cppargs, Fileopened);
			if ((Fp = popen(Tok, "r")) == NULL)
				out(O_DIE|O_SYS, "%s", Tok);
#else
			Fp = eftread_fopen(Fileopened, ibuf, sizeof (ibuf));
#endif	/* ESC */
			Line = 1;
			bol = 1;

			/* add name to stats for visibility */
			if (Fp != NULL) {
				static int fnum;
				char nbuf[100];
				struct filestats *nfs = MALLOC(sizeof (*nfs));

				(void) sprintf(nbuf, "lex.file%d", fnum);
				nfs->stats = stats_new_string(nbuf, "", 0);
				stats_string_set(nfs->stats, Fileopened);

				if (ibuf[0] != '\0') {
					(void) sprintf(nbuf, "lex.file%d-ident",
					    fnum);
					nfs->idstats =
					    stats_new_string(nbuf, "", 0);
					stats_string_set(nfs->idstats, ibuf);
				} else {
					nfs->idstats = NULL;
				}

				nfs->next = Fstats;
				Fstats = nfs;
				fnum++;
			}
		}

		switch (c = getc(Fp)) {
		case '#':
			/* enforce that we're at beginning of line */
			if (!bol)
				return (record(c, NULL));

			while ((c = getc(Fp)) != EOF &&
			    (c == ' ' || c == '\t'))
				;
			if (!isdigit(c)) {
				/*
				 * three cases here:
				 *	#pragma
				 *	#ident
				 *	#something-we-don't-understand
				 * anything we don't expect we just ignore.
				 */
				*ptr++ = c;
				while ((c = getc(Fp)) != EOF && isalnum(c))
					if (ptr < eptr - 1)
						*ptr++ = c;
				*ptr++ = '\0';
				if (strcmp(Tok, "pragma") == 0) {
					/* skip white space */
					while ((c = getc(Fp)) != EOF &&
					    (c == ' ' || c == '\t'))
						;

					if (c == EOF || c == '\n')
						outfl(O_DIE, File, Line,
						    "bad #pragma");

					/* pull in next token */
					ptr = Tok;
					*ptr++ = c;
					while ((c = getc(Fp)) != EOF &&
					    !isspace(c))
						if (ptr < eptr - 1)
							*ptr++ = c;
					*ptr++ = '\0';
					(void) ungetc(c, Fp);

					dopragma(Tok);
				} else if (strcmp(Tok, "ident") == 0)
					doident();
			} else {
				/* handle file & line info from cpp */
				Line = 0;
				do {
					if (!isdigit(c))
						break;
					Line = Line * 10 + c - '0';
				} while ((c = getc(Fp)) != EOF);
				Line--;		/* newline will increment it */
				while (c != EOF && isspace(c))
					c = getc(Fp);
				if (c != '"')
					outfl(O_DIE, File, Line,
					    "bad # statement (file name)");
				while ((c = getc(Fp)) != EOF && c != '"')
					if (ptr < eptr - 1)
						*ptr++ = c;
				*ptr++ = '\0';
				if (c != '"')
					outfl(O_DIE, File, Line,
					    "bad # statement (quotes)");
				File = stable(Tok);
			}
			/* skip the rest of the cpp line */
			while ((c = getc(Fp)) != EOF && c != '\n' && c != '\r')
				;
			if (c == EOF)
				return (record(c, NULL));
			else
				(void) ungetc(c, Fp);
			ptr = Tok;
			break;

		case EOF:
			closefile();
			continue;

		case '\n':
			Line++;
			bol = 1;
			break;

		case '\r':
		case ' ':
		case '\t':
			bol = 0;
			break;

		case '/':
			bol = 0;
			/* comment handling */
			if ((nextc = getc(Fp)) == EOF)
				outfl(O_DIE, File, Line, "unexpected EOF");
			else if (nextc == '*') {
				startline = Line;
				while ((c = getc(Fp)) != EOF) {
					if (c == '\n')
						Line++;
					else if (c == '*' &&
					    (((c = getc(Fp)) == EOF) ||
					    (c == '/')))
						break;
				}
				if (c == EOF) {
					outfl(O_DIE, File, Line,
					    "end of comment not seen "
					    "(started on line %d)",
					    startline);
				}
			} else {
				/* wasn't a comment, return the '/' token */
				(void) ungetc(nextc, Fp);
				return (record(c, NULL));
			}
			break;

		case '"': {
			int prevc;

			bol = 0;
			prevc = '\0';
			/* quoted string handling */
			startline = Line;
			for (;;) {
				c = getc(Fp);
				if (c == EOF)
					outfl(O_DIE, File, Line,
					    "end of string not seen "
					    "(started on line %d)",
					    startline);
				else if (c == '\n')
					Line++;
				else if (c == '"' && prevc != '\\')
					break;
				else if (ptr < eptr)
					*ptr++ = c;
				prevc = c;
			}
			if (ptr >= eptr)
				out(O_DIE, File, Line, "string too long");
			*ptr++ = '\0';
			return (record(QUOTE, stable(Tok)));
		}
		case '&':
			bol = 0;
			/* && */
			if ((nextc = getc(Fp)) == '&')
				return (record(AND, NULL));
			else {
				(void) ungetc(nextc, Fp);
				return (record(c, NULL));
			}
			/*NOTREACHED*/
			break;

		case '|':
			bol = 0;
			/* || */
			if ((nextc = getc(Fp)) == '|')
				return (record(OR, NULL));
			else {
				(void) ungetc(nextc, Fp);
				return (record(c, NULL));
			}
			/*NOTREACHED*/
			break;

		case '!':
			bol = 0;
			/* ! or != */
			if ((nextc = getc(Fp)) == '=')
				return (record(NE, NULL));
			else {
				(void) ungetc(nextc, Fp);
				return (record(c, NULL));
			}
			/*NOTREACHED*/
			break;

		case '=':
			bol = 0;
			/* == */
			if ((nextc = getc(Fp)) == '=')
				return (record(EQ, NULL));
			else {
				(void) ungetc(nextc, Fp);
				return (record(c, NULL));
			}
			/*NOTREACHED*/
			break;

		case '-':
			bol = 0;
			/* -> */
			if ((nextc = getc(Fp)) == '>')
				return (record(ARROW, stable(Tok)));
			else {
				(void) ungetc(nextc, Fp);
				return (record(c, NULL));
			}
			/*NOTREACHED*/
			break;

		case '<':
			bol = 0;
			if ((nextc = getc(Fp)) == '=')
				/* <= */
				return (record(LE, NULL));
			else if (nextc == '<')
				/* << */
				return (record(LSHIFT, NULL));
			else {
				(void) ungetc(nextc, Fp);
				return (record(c, NULL));
			}
			/*NOTREACHED*/
			break;

		case '>':
			bol = 0;
			if ((nextc = getc(Fp)) == '=')
				/* >= */
				return (record(GE, NULL));
			else if (nextc == '>')
				/* >> */
				return (record(RSHIFT, NULL));
			else {
				(void) ungetc(nextc, Fp);
				return (record(c, NULL));
			}
			/*NOTREACHED*/
			break;

		default:
			bol = 0;
			if (isdigit(c)) {
				int base;

				/* collect rest of number */
				if (c == '0') {
					*ptr++ = c;
					if ((c = getc(Fp)) == EOF) {
						*ptr++ = '\0';
						return (record(NUMBER,
						    stable(Tok)));
					} else if (c == 'x' || c == 'X') {
						*ptr++ = c;
						base = 16;
					} else {
						(void) ungetc(c, Fp);
						base = 8;
					}
				} else {
					*ptr++ = c;
					base = 10;
				}
				while ((c = getc(Fp)) != EOF) {
					if (ptr >= eptr)
						out(O_DIE, File, Line,
						    "number too long");

					switch (base) {
					case 16:
						if (c >= 'a' && c <= 'f' ||
						    c >= 'A' && c <= 'F') {
							*ptr++ = c;
							continue;
						}
						/*FALLTHRU*/
					case 10:
						if (c >= '8' && c <= '9') {
							*ptr++ = c;
							continue;
						}
						/*FALLTHRU*/
					case 8:
						if (c >= '0' && c <= '7') {
							*ptr++ = c;
							continue;
						}
						/* not valid for this base */
						*ptr++ = '\0';
						(void) ungetc(c, Fp);
						return (record(NUMBER,
						    stable(Tok)));
					}
				}
				*ptr++ = '\0';
				return (record(NUMBER, stable(Tok)));
			} else if (isalpha(c)) {
				/* collect identifier */
				*ptr++ = c;
				for (;;) {
					c = getc(Fp);
					if ((isalnum(c) || c == '_') &&
					    ptr < eptr)
						*ptr++ = c;
					else {
						(void) ungetc(c, Fp);
						break;
					}
				}
				if (ptr >= eptr)
					out(O_DIE, File, Line,
					    "identifier too long");
				*ptr++ = '\0';
				cptr = stable(Tok);
				if (val = lex_s2i_lut_lookup(Rwordslut, cptr)) {
					return (record(val, cptr));
				}
				return (record(ID, cptr));
			} else
				return (record(c, NULL));
		}
		/*NOTREACHED*/
	}
}

/*
 * the record()/dumpline() routines are used to track & report
 * the list of tokens seen on a given line.  this is used in two ways.
 * first, syntax errors found by the parser are reported by us (via
 * yyerror()) and we tack on the tokens processed so far on the current
 * line to help indicate exactly where the error is.  second, if "lexecho"
 * debugging is turned on, these routines provide it.
 */
#define	MAXRECORD 1000
static int Recordedline;
static struct {
	int tok;
	const char *s;
} Recorded[MAXRECORD];
static int Recordnext;

static int
record(int tok, const char *s)
{
	stats_counter_bump(Tokcount);
	if (Line != Recordedline) {
		/* starting new line, dump out the previous line */
		if (Lexecho && Recordedline) {
			outfl(O_NONL, File, Recordedline, "lex: ");
			dumpline(O_OK);
		}
		Recordedline = Line;
		Recordnext = 0;
	}
	if (Recordnext >= MAXRECORD)
		outfl(O_DIE, File, Line, "line too long, bailing out");
	Recorded[Recordnext].tok = tok;
	Recorded[Recordnext++].s = s;

	yylval.tok.s = s;
	yylval.tok.file = File;
	yylval.tok.line = Line;
	return (tok);
}

/*ARGSUSED*/
static void
dumpline(int flags)
{
	int i;

	for (i = 0; i < Recordnext; i++)
		if (Recorded[i].s && Recorded[i].tok != ARROW)
			switch (Recorded[i].tok) {
			case T_QUOTE:
				out(flags|O_NONL, " \"%s\"",
				    Recorded[i].s);
				break;

			default:
				out(flags|O_NONL, " %s",
				    Recorded[i].s);
				break;
			}
		else
			switch (Recorded[i].tok) {
			case EOF:
				out(flags|O_NONL, " EOF");
				break;
			case ARROW:
				out(flags|O_NONL, " ->%s",
				    Recorded[i].s);
				break;
			case EQ:
				out(flags|O_NONL, " ==");
				break;
			case NE:
				out(flags|O_NONL, " !=");
				break;
			case OR:
				out(flags|O_NONL, " ||");
				break;
			case AND:
				out(flags|O_NONL, " &&");
				break;
			case LE:
				out(flags|O_NONL, " <=");
				break;
			case GE:
				out(flags|O_NONL, " >=");
				break;
			case LSHIFT:
				out(flags|O_NONL, " <<");
				break;
			case RSHIFT:
				out(flags|O_NONL, " >>");
				break;
			default:
				if (isprint(Recorded[i].tok))
					out(flags|O_NONL, " %c",
					    Recorded[i].tok);
				else
					out(flags|O_NONL, " '\\%03o'",
					    Recorded[i].tok);
				break;
			}
	out(flags, NULL);
}

/*
 * yyerror -- report a pareser error, called yyerror because yacc wants it
 */

void
yyerror(const char *s)
{
	Errcount++;
	outfl(O_ERR|O_NONL, File, Line, "%s, tokens: ", s);
	dumpline(O_ERR);
}

/*
 * doident -- handle "#pragma ident" directives
 */
static void
doident()
{
	int c;
	char *ptr = Tok;
	char *eptr = &Tok[MAXTOK];

	/* skip white space and quotes */
	while ((c = getc(Fp)) != EOF &&
	    (c == ' ' || c == '\t' || c == '"'))
		;

	if (c == EOF || c == '\n')
		outfl(O_DIE, File, Line, "bad ident");

	/* pull in next token */
	ptr = Tok;
	*ptr++ = c;
	while ((c = getc(Fp)) != EOF && c != '"' && c != '\n')
		if (ptr < eptr - 1)
			*ptr++ = c;
	*ptr++ = '\0';
	if (c != '\n') {
		/* skip to end of line (including close quote, if any) */
		while ((c = getc(Fp)) != EOF && c != '\n')
			;
	}
	(void) ungetc(c, Fp);
	Ident = lut_add(Ident, (void *)stable(Tok), (void *)0, NULL);

	outfl(O_VERB, File, Line, "pragma set: ident \"%s\"", Tok);
}

/*
 * dodictionary -- handle "#pragma dictionary" directives
 */
static void
dodictionary()
{
	int c;
	char *ptr = Tok;
	char *eptr = &Tok[MAXTOK];

	/* skip white space and quotes */
	while ((c = getc(Fp)) != EOF &&
	    (c == ' ' || c == '\t' || c == '"'))
		;

	if (c == EOF || c == '\n')
		outfl(O_DIE, File, Line, "bad dictionary");

	/* pull in next token */
	ptr = Tok;
	*ptr++ = c;
	while ((c = getc(Fp)) != EOF && c != '"' && c != '\n')
		if (ptr < eptr - 1)
			*ptr++ = c;
	*ptr++ = '\0';
	if (c != '\n') {
		/* skip to end of line (including close quote, if any) */
		while ((c = getc(Fp)) != EOF && c != '\n')
			;
	}
	(void) ungetc(c, Fp);
	Dicts = lut_add(Dicts, (void *)stable(Tok), (void *)0, NULL);

	outfl(O_VERB, File, Line, "pragma set: dictionary \"%s\"", Tok);
}

/*
 * doallow_cycles -- handle "#pragma allow_cycles" directives
 */
static void
doallow_cycles()
{
	int c;
	char *ptr = Tok;
	char *eptr = &Tok[MAXTOK];
	unsigned long long newlevel;

	/*
	 * by default the compiler does not allow cycles or loops
	 * in propagations.  when cycles are encountered, the
	 * compiler prints out an error message.
	 *
	 *   "#pragma allow_cycles" and
	 *   "#pragma allow_cycles 0"
	 * allow cycles, but any such cycle will produce a warning
	 * message.
	 *
	 *   "#pragma allow_cycles N"
	 * with N > 0 will allow cycles and not produce any
	 * warning messages.
	 */

	/* skip white space and quotes */
	while ((c = getc(Fp)) != EOF &&
	    (c == ' ' || c == '\t' || c == '"'))
		;

	if (c == EOF || c == '\n')
		newlevel = 0ULL;
	else {

		/* pull in next token */
		ptr = Tok;
		*ptr++ = c;
		while ((c = getc(Fp)) != EOF && c != '"' && c != '\n')
			if (ptr < eptr - 1)
				*ptr++ = c;
		*ptr++ = '\0';
		if (c != '\n') {
			/* skip to end of line */
			while ((c = getc(Fp)) != EOF && c != '\n')
				;
		}
		newlevel = strtoll(Tok, NULL, 0);
	}
	(void) ungetc(c, Fp);

	(void) check_cycle_level(newlevel);
	outfl(O_VERB, File, Line,
	    "pragma set: allow_cycles (%s)",
	    newlevel ? "no warnings" : "with warnings");
}

/*
 * dopragma -- handle #pragma directives
 */
static void
dopragma(const char *tok)
{
	if (strcmp(tok, "ident") == 0)
		doident();
	else if (strcmp(tok, "dictionary") == 0)
		dodictionary();
	else if (strcmp(tok, "new_errors_only") == 0) {
		if (Pragma_new_errors_only++ == 0)
			outfl(O_VERB, File, Line,
			    "pragma set: new_errors_only");
	} else if (strcmp(tok, "trust_ereports") == 0) {
		if (Pragma_trust_ereports++ == 0)
			outfl(O_VERB, File, Line,
			    "pragma set: trust_ereports");
	} else if (strcmp(tok, "allow_cycles") == 0)
		doallow_cycles();
	else
		outfl(O_VERB, File, Line,
		    "unknown pragma ignored: \"%s\"", tok);
}

/*
 * lex_fini -- finalize the lexer
 */

int
lex_fini(void)
{
	stats_elapse_stop(Lexelapse);
	closefile();
	if (Lexecho) {
		outfl(O_OK, File, Line, "lex: ");
		dumpline(O_OK);
	}
	return (Errcount);
}

void
lex_free(void)
{
	struct filestats *nfstats = Fstats;

	/*
	 * Free up memory consumed by the lexer
	 */
	stats_delete(Tokcount);
	stats_delete(Filecount);
	stats_delete(Lexelapse);
	while (nfstats != NULL) {
		Fstats = nfstats->next;
		stats_delete(nfstats->stats);
		if (nfstats->idstats != NULL)
			stats_delete(nfstats->idstats);
		FREE(nfstats);
		nfstats = Fstats;
	}
	lut_free(Timesuffixlut, NULL, NULL);
	lut_free(Rwordslut, NULL, NULL);
	lut_free(Ident, NULL, NULL);
	lut_free(Dicts, NULL, NULL);
}
