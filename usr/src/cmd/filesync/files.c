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
/*
 * Copyright (c) 1995 Sun Microsystems, Inc.  All Rights Reserved
 *
 * module:
 *	files.c
 *
 * purpose:
 *	routines to examine and manipulate file names
 *
 * contents:
 *	qualify ... ensure that a name is fully qualified
 *	expand  ... expand env variables within a string or file name
 *	noblanks .. ensure that a name contains no embdded unescaped blanks
 *	lex ....... a lexer that can handle escaped/embedded blanks
 *	wildcards . see whether or not a name contains wild cards
 *	prefix .... does one string begin with another
 *	suffix .... does one string end with another
 *	contains .. does one string contain another
 *
 *	cannonize (static) ...	compress redundant "." and ".." out of name
 *
 * notes:
 *	we are interested in embedded blanks because international
 *	character sets and non-unix file systems can both contain
 *	the byte 0x20.  Thus, whenever we record a filename in
 *	file, we must be careful to escape any embedded blanks that
 *	cause trouble when we re-lex that file later.
 */
#ident	"%W%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "filesync.h"
#include "messages.h"

static void cannonize(char *name);

/*
 * routine:
 *	qualify
 *
 * purpose:
 *	to fully qualify a name
 *
 * parameters:
 *	name to be qualified
 *
 * returns:
 *	either original pointer or copy to a new (malloced) buffer
 *
 * notes:
 *	someday I may conclude that I should always make a copy
 *	so that the caller can know that it is safe to free the parm
 *
 *	I thought about this and concluded that there is never a need
 *	to fully qualify a string containing variables.  If the string
 *	came from the command line, the variables were already expanded
 *	and if it came from the rules data base it is required to already
 *	be fully qualified.
 */
char *
qualify(char *name)
{
	char namebuf[ MAX_PATH ];

	/* in the simple case, the parameter is already there */
	if (*name == '/') {
		cannonize(name);
		return (name);
	}

	/* things that begin with variables get the benefit of the doubt */
	if (*name == '$') {
		cannonize(name);
		return (name);
	}

	/* start with the current working directory	*/
	if (getcwd(namebuf, sizeof (namebuf)) == 0) {
		fprintf(stderr, gettext(ERR_nocwd), name);
		exit(ERR_OTHER);
	}

	/* make sure we have room for our file name	*/
	if ((strlen(namebuf) + strlen(name) + 2) >= sizeof (namebuf)) {
		fprintf(stderr, gettext(ERR_longname), name);
		exit(ERR_OTHER);
	}

	/* append the specified file name to it	*/
	strcat(namebuf, "/");
	strcat(namebuf, name);

	/* filter out redundant dots	*/
	cannonize(namebuf);

	if (opt_debug & DBG_VARS)
		fprintf(stderr, "VARS: QUALIFY %s to %s\n", name, namebuf);

	/* and return a newly malloc'd copy	*/
	return (strdup(namebuf));
}

/*
 * routine:
 *	expand
 *
 * purpose:
 *	to expand variable names within a string
 *
 * parameters:
 *	string to be expanded.  Variable references always begin
 *	with a $ and are delimited by parens or curleys.
 *
 * returns:
 *	either original pointer or a copy to a new (malloced) buffer
 *
 * notes:
 *	someday I may conclude that I should always make a copy
 *	so that the caller can know that it is safe to free the parm
 *
 *	someday I may decide to support escape conventions for embedding
 *	$(){} in file names, but I suspec that day will never come.
 *
 *	I thought about this and concluded there was no reason to
 *	fully qualify these names, because the only names that should
 *	need qualification are src/dst lines from the command line,
 *	and the shell should have handled those for me.  Once something
 *	makes it into the database, it is expected to be fully qualified
 *	already.
 *
 *	We are limited to producing strings of length MAX_PATH or less
 *	and variable names of length MAX_NAME or less.  In practice,
 *	these limitations should not be a problem.
 */
char *
expand(char *name)
{	const char *s;
	char *p, *v;
	char delim;
	char namebuf[ MAX_PATH ];
	char varbuf[ MAX_NAME ];

	/* first see if there are no variables to be bound */
	for (s = name; *s && *s != '$'; s++);
	if (*s == 0)
		return (name);

	/* move through the string, copying and expanding	*/
	for (s = name, p = namebuf; *s; s++) {

		/* check for overflow	*/
		if (p >= &namebuf[ MAX_PATH ]) {
			fprintf(stderr, gettext(ERR_longname), name);
			exit(ERR_OTHER);
		}

		/* normal characters, we just copy		*/
		if (*s != '$') {
			*p++ = *s;
			continue;
		}

		/* figure out how the variable name is delimited */
		delim = *++s;
		if (delim == '(') {
			delim = ')';
			s++;
		} else if (delim == '{') {
			delim = '}';
			s++;
		} else
			delim = 0;

		/* copy the variable name up to the closing delimiter */
		for (v = varbuf; *s; s++) {
			if (isalnum(*s) || (*s == '_') ||
				(delim && *s != delim))
				*v++ = *s;
			else
				break;

			/* make sure we don't overflow var name buffer	*/
			if (v >= &varbuf[MAX_NAME - 1]) {
				*v = 0;
				fprintf(stderr, gettext(ERR_longname), varbuf);
				exit(ERR_OTHER);
			}
		}

		*v = 0;

		/* FIX THIS ... there must be a more elegant way */
		/* we may have to back up because s will be bumped */
		if (delim == 0 || *s != delim)
			s--;

		/* look up the variable 			*/
		v = getenv(varbuf);
		if (v == 0 || *v == 0) {
			fprintf(stderr, gettext(ERR_undef), varbuf);
			return (0);
		}

		/* copy the variable into the buffer		*/
		while (*v)
			*p++ = *v++;
	}

	/* null terminate the copy	*/
	*p = 0;

	/* compress out any redundant dots and dot-dots	*/
	cannonize(namebuf);

	if (opt_debug & DBG_VARS)
		fprintf(stderr, "VARS: EXPAND %s to %s\n", name, namebuf);

	/* and return a newly malloc'd copy	*/
	return (strdup(namebuf));
}

/*
 * routine:
 *	noblanks
 *
 * purpose:
 *	to ensure that a name contains no unescaped embedded blanks
 *
 * parameters:
 *	pointer to name
 *
 * returns:
 *	pointer to name or pointer to buffer containing escaped version of name
 *
 * notes:
 *	this routine can be called on full file names, and so can
 *	conceivably require an arbitrarily large buffer.
 */
const char *
noblanks(const char *name)
{
	const char *s;
	char *p;
	static char *namebuf = 0;
	static int buflen = 0;
	int l;

	/* first see if there are no embedded blanks	*/
	for (s = name; *s && *s != ' '; s++);
	if (*s == 0)
		return (name);

	/* make sure we have a buffer large enough for the worst case	*/
	l = 4 + (2*strlen(name));
	for (buflen = MAX_PATH; buflen < l; buflen += MAX_NAME);
	namebuf = (char *) realloc(namebuf, buflen);

	/* quote the name, and copy it, escaping quotes	*/
	p = namebuf;
	*p++ = '"';

	for (s = name; *s; s++) {
		if (*s == '"' || *s == '\\')
			*p++ = '\\';
		*p++ = *s;
	}

	*p++ = '"';
	*p = 0;

	return (namebuf);
}

/*
 * routine:
 *	lex
 *
 * purpose:
 *	my own version of strtok that handles quoting and escaping
 *
 * parameters:
 *	FILE structure for file to read (0 for same string, same file)
 *
 * returns:
 *	pointer to next token
 *
 * notes:
 *	this routine makes no changes to the string it is passed,
 *	copying tokens into a static buffer.
 *
 *	this routine handles continuation lines after reading and
 *	before the lexing even starts.  This limits continued lines
 *	to a length of MAX_LINE, but keeps everything else very simple.
 *	We also, therefore, limit tokens to a maximum length of MAX_LINE.
 */
int lex_linenum;		/* line number in current input file	*/

char *
lex(FILE *file)
{	char c, delim;
	char *p;
	char *s;
	static char *savep;
	static char namebuf[ MAX_LINE ];
	static char inbuf[ MAX_LINE ];

	if (file) {			/* read a new line		*/
		p = inbuf + sizeof (inbuf);

		/* read the next input line, with all continuations	*/
		for (s = inbuf; savep = fgets(s, p - s, file); ) {
			lex_linenum++;

			/* go find the last character of the input line	*/
			while (*s && s[1])
				s++;
			if (*s == '\n')
				s--;

			/* see whether or not we need a continuation	*/
			if (s < inbuf || *s != '\\')
				break;

			continue;
		}

		if (savep == 0)
			return (0);

		s = inbuf;
	} else {			/* continue with old line	*/
		if (savep == 0)
			return (0);
		s = savep;
	}
	savep = 0;

	/* skip over leading white space	*/
	while (isspace(*s))
		s++;
	if (*s == 0)
		return (0);

	/* see if this is a quoted string	*/
	c = *s;
	if (c == '\'' || c == '"') {
		delim = c;
		s++;
	} else
		delim = 0;

	/* copy the token into the buffer	*/
	for (p = namebuf; (c = *s) != 0; s++) {
		/* literal escape		*/
		if (c == '\\') {
			s++;
			*p++ = *s;
			continue;
		}

		/* closing delimiter		*/
		if (c == delim) {
			s++;
			break;
		}

		/* delimiting white space	*/
		if (delim == 0 && isspace(c))
			break;

		/* ordinary characters		*/
		*p++ = *s;
	}


	/* remember where we left off		*/
	savep = *s ? s : 0;

	/* null terminate and return the buffer	*/
	*p = 0;
	return (namebuf);
}

/*
 * routine:
 *	wildcards
 *
 * purpose:
 *	determine whether or not there are any wild cards in a name
 *
 * parameters:
 *	name to be checked
 *
 * returns:
 *	true/false
 *
 * notes:
 *	we use this to take shortcuts
 */
bool_t
wildcards(const char *name)
{	const char *s;
	int literal = 0;

	for (s = name; *s; s++)
		if (literal)
			switch (*s) {
				case '\'':	/* end of literal string */
					literal = 0;
					continue;
				case '\\':	/* escape next character */
					s++;
					continue;
			}
		else
			switch (*s) {
				case '\'':	/* literal string	*/
					literal = 1;
					continue;
				case '\\':	/* escape next character */
					s++;
					continue;
				case '*':
				case '[':
				case '{':
				case '?':
					/* any of these is a wild card	*/
					return (TRUE);
			}

	return (FALSE);
}

/*
 * routine:
 *	cannonize
 *
 * purpose:
 *	to compress redundant dots out of a path
 *
 * parameters:
 *	file name in an editable buffer
 *
 * returns:
 *	void
 *
 * notes:
 *	because we compress the string in place, there is no danger
 *	of our overflowing any fixed sized buffer.
 */
static void
cannonize(char *name)
{	char *s, *p;

	/* leading dot-slashes	*/
	for (s = name; *s == '.' && s[1] == '/'; strcpy(s, &s[2]));

	for (s = name; *s; s++) {
		/* interesting things happen after slashes	*/
		if (*s != '/')
			continue;

		/* embedded dot-slashes */
		while (s[1] == '.' && s[2] == '/')
			strcpy(&s[1], &s[3]);

		/* embedded slash-dot-dot-slash	*/
		if (strncmp(s, "/../", 4) == 0) {
			/* scan backwards to eliminate last directory */
			for (p = s-1; p > name && *p != '/'; p--);

			if (p < name)
				p = name;
			strcpy(p, &s[3]);
		}

		continue;
	}
}

/*
 * routine:
 *	prefix
 *
 * purpose:
 *	determine whether or not one string begins with another
 *
 * parameters:
 *	string to be tested
 *	suspected prefix
 *
 * returns:
 *	no	0
 *	yes	pointer character after prefix
 */
const char *
prefix(const char *s, const char *p)
{
	while (*p)
		if (*p++ != *s++)
			return (0);

	return (s);
}

/*
 * routine:
 *	suffix
 *
 * purpose:
 *	determine whether or not one string ends with another
 *
 * parameters:
 *	string to be tested
 *	suspected suffix
 *
 * returns:
 *	true/false
 */
bool_t
suffix(const char *str, const char *suf)
{	const char *s;

	/* go to where the alleged suffix would start */
	for (s = str; *s; s++);
	s -= strlen(suf);
	if (s < str)
		return (FALSE);

	/* see if the string ends with the suffix */
	while (*suf)
		if (*suf++ != *s++)
			return (FALSE);

	return (TRUE);
}

/*
 * routine:
 *	contains
 *
 * purpose:
 *	determine whether or not one string contains another
 *
 * parameters:
 *	string to be checked
 *	pattern we are seeking
 *
 * returns:
 *	true/false
 */
bool_t
contains(const char *str, const char *pat)
{	const char *s, *p;

	while (*str) {
		if (*str++ == *pat) {
			for (s = str, p = &pat[1]; *s == *p; s++, p++)
				if (p[1] == 0)
					return (TRUE);
		}
	}

	return (FALSE);
}
