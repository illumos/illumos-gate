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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include "s_string.h"
#include <stdlib.h>

/* global to this file */
#define	STRLEN 128UL
#define	STRALLOC 128UL
#define	MAXINCR 250000UL

/* buffer pool for allocating string structures */
typedef struct {
	string s[STRALLOC];
	size_t o;
} stralloc;
static stralloc *freep = NULL;

/* pool of freed strings */
static string *freed = NULL;
static string *s_alloc(void);
static void s_simplegrow(string *, size_t);

void
s_free(string *sp)
{
	if (sp != NULL) {
		sp->ptr = (char *)freed;
		freed = sp;
	}
}

/* allocate a string head */
static string *
s_alloc(void)
{
	if (freep == NULL || freep->o >= STRALLOC) {
		freep = (stralloc *)malloc(sizeof (stralloc));
		if (freep == NULL) {
			perror("allocating string");
			exit(1);
		}
		freep->o = (size_t)0;
	}
	return (&(freep->s[freep->o++]));
}

/* create a new `short' string */
string *
s_new(void)
{
	string *sp;

	if (freed != NULL) {
		sp = freed;
		/*LINTED*/
		freed = (string *)(freed->ptr);
		sp->ptr = sp->base;
		return (sp);
	}
	sp = s_alloc();
	sp->base = sp->ptr = malloc(STRLEN);
	if (sp->base == NULL) {
		perror("allocating string");
		exit(1);
	}
	sp->end = sp->base + STRLEN;
	s_terminate(sp);
	return (sp);
}

/* grow a string's allocation by at least `incr' bytes */
static void
s_simplegrow(string *sp, size_t incr)
{
	char *cp;
	size_t size;

	/*
	 *  take a larger increment to avoid mallocing too often
	 */
	if (((sp->end - sp->base) < incr) && (MAXINCR < incr))
		size = (sp->end - sp->base) + incr;
	else if ((sp->end - sp->base) > MAXINCR)
		size = (sp->end - sp->base) + MAXINCR;
	else
		size = (size_t)2 * (sp->end - sp->base);

	cp = realloc(sp->base, size);
	if (cp == NULL) {
		perror("string:");
		exit(1);
	}
	sp->ptr = (sp->ptr - sp->base) + cp;
	sp->end = cp + size;
	sp->base = cp;
}

/* grow a string's allocation */
int
s_grow(string *sp, int c)
{
	s_simplegrow(sp, (size_t)2);
	s_putc(sp, c);
	return (c);
}

/* return a string containing a character array (this had better not grow) */
string *
s_array(char *cp, size_t len)
{
	string *sp = s_alloc();

	sp->base = sp->ptr = cp;
	sp->end = sp->base + len;
	return (sp);
}

/* return a string containing a copy of the passed char array */
string*
s_copy(char *cp)
{
	string *sp;
	size_t len;

	sp = s_alloc();
	len = strlen(cp)+1;
	sp->base = malloc(len);
	if (sp->base == NULL) {
		perror("string:");
		exit(1);
	}
	sp->end = sp->base + len;	/* point past end of allocation */
	(void) strcpy(sp->base, cp);
	sp->ptr = sp->end - (size_t)1;	/* point to NULL terminator */
	return (sp);
}

/* convert string to lower case */
void
s_tolower(string *sp)
{
	char *cp;

	for (cp = sp->ptr; *cp; cp++)
		*cp = tolower(*cp);
}

void
s_skipwhite(string *sp)
{
	while (isspace(*sp->ptr))
		s_skipc(sp);
}

/* append a char array to a string */
string *
s_append(string *to, char *from)
{
	if (to == NULL)
		to = s_new();
	if (from == NULL)
		return (to);
	for (; *from; from++)
		s_putc(to, (int)(unsigned int)*from);
	s_terminate(to);
	return (to);
}

/*
 * Append a logical input sequence into a string.  Ignore blank and
 * comment lines.  Backslash preceding newline indicates continuation.
 * The `lineortoken' variable indicates whether the sequence to beinput
 * is a whitespace delimited token or a whole line.
 *
 *	FILE *fp;		stream to read from
 *	string *to;		where to put token
 *	int lineortoken;	how the sequence terminates
 *
 * Returns a pointer to the string or NULL. Trailing newline is stripped off.
 */
string *
s_seq_read(FILE *fp, string *to, int lineortoken)
{
	int c;
	int done = 0;

	if (feof(fp))
		return (NULL);

	/* get rid of leading goo */
	do {
		c = getc(fp);
		switch (c) {
		case EOF:
			if (to != NULL)
				s_terminate(to);
			return (NULL);
		case '#':
			/*LINTED*/
			while ((c = getc(fp)) != '\n' && c != EOF)
				continue;
			break;
		case ' ':
		case '\t':
		case '\n':
		case '\r':
		case '\f':
			break;
		default:
			done = 1;
			break;
		}
	} while (!done);

	if (to == NULL)
		to = s_new();

	/* gather up a sequence */
	for (;;) {
		switch (c) {
		case '\\':
			c = getc(fp);
			if (c != '\n') {
				s_putc(to, (int)(unsigned int)'\\');
				s_putc(to, c);
			}
			break;
		case EOF:
		case '\r':
		case '\f':
		case '\n':
			s_terminate(to);
			return (to);
		case ' ':
		case '\t':
			if (lineortoken == TOKEN) {
				s_terminate(to);
				return (to);
			}
			/* fall through */
		default:
			s_putc(to, c);
			break;
		}
		c = getc(fp);
	}
}

string *
s_tok(string *from, char *split)
{
	char *splitend = strpbrk(from->ptr, split);

	if (splitend) {
		string *to = s_new();
		for (; from->ptr < splitend; ) {
			s_putc(to, (int)(unsigned int)*from->ptr);
			from->ptr++;
		}
		s_terminate(to);
		s_restart(to);
		/* LINT: warning due to lint bug */
		from->ptr += strspn(from->ptr, split);
		return (to);
	}

	else if (from->ptr[0]) {
		string *to = s_clone(from);
		while (*from->ptr)
			from->ptr++;
		return (to);
	}

	else
		return (NULL);
}

/*
 * Append an input line to a string.
 *
 * Returns a pointer to the string (or NULL).
 * Trailing newline is left on.
 */
char *
s_read_line(FILE *fp, string *to)
{
	int c;
	size_t len = 0;

	s_terminate(to);

	/* end of input */
	if (feof(fp) || (c = getc(fp)) == EOF)
		return (NULL);

	/* gather up a line */
	for (; ; ) {
		len++;
		switch (c) {
		case EOF:
			s_terminate(to);
			return (to->ptr - len);
		case '\n':
			s_putc(to, (int)(unsigned int)'\n');
			s_terminate(to);
			return (to->ptr - len);
		default:
			s_putc(to, c);
			break;
		}
		c = getc(fp);
	}
}

/*
 * Read till eof
 */
size_t
s_read_to_eof(FILE *fp, string *to)
{
	size_t got;
	size_t have;

	s_terminate(to);

	for (; ; ) {
		if (feof(fp))
			break;
		/* allocate room for a full buffer */
		have = to->end - to->ptr;
		if (have < 4096UL)
			s_simplegrow(to, (size_t)4096);

		/* get a buffers worth */
		have = to->end - to->ptr;
		got = fread(to->ptr, (size_t)1, have, fp);
		if (got == (size_t)0)
			break;
		/* LINT: warning due to lint bug */
		to->ptr += got;
	}

	/* null terminate the line */
	s_terminate(to);
	return (to->ptr - to->base);
}

/*
 * Get the next field from a string.  The field is delimited by white space,
 * single or double quotes.
 *
 *	string *from;	string to parse
 *	string *to;	where to put parsed token
 */
string *
s_parse(string *from, string *to)
{
	while (isspace(*from->ptr))
		from->ptr++;
	if (*from->ptr == '\0')
		return (NULL);
	if (to == NULL)
		to = s_new();
	if (*from->ptr == '\'') {
		from->ptr++;
		for (; *from->ptr != '\'' && *from->ptr != '\0'; from->ptr++)
			s_putc(to, (int)(unsigned int)*from->ptr);
		if (*from->ptr == '\'')
			from->ptr++;
	} else if (*from->ptr == '"') {
		from->ptr++;
		for (; *from->ptr != '"' && *from->ptr != '\0'; from->ptr++)
			s_putc(to, (int)(unsigned int)*from->ptr);
		if (*from->ptr == '"')
			from->ptr++;
	} else {
		for (; !isspace(*from->ptr) && *from->ptr != '\0'; from->ptr++)
			s_putc(to, (int)(unsigned int)*from->ptr);
	}
	s_terminate(to);

	return (to);
}
