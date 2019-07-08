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
 * Copyright 1997-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "parser.h"
#include "trace.h"
#include "util.h"
#include "errlog.h"

#define	TABLE_INITIAL	50
#define	TABLE_INCREMENT	50

/*
 * String processing
 */

/*
 * strnormalize -- combined tab-to-space and strtrim, plus removal
 *	of leading and trailing *$%$^@!!! semicolons.
 *  Not internationalized: TBD.
 */
char *
strnormalize(char *str)
{
	char	*p;

	if (str == NULL || *str == '\0')
		return (str);
	for (p = str; *p != '\0'; p++) {
		if (isspace(*p)) {
			*p = ' ';
		}
	}
	p--;
	while (p >= str && (isspace(*p) || *p == ';'))
		*p-- = '\0';

	/* ERA - remove leading spaces */
	while (isspace(*str))
		str++;

	return (str);
}

char *
strtrim(char *str)
{
	char	*p;

	for (p = str; *p != '\0'; p++)
		continue;
	p--;
	while (p >= str && isspace(*p))
		*p-- = '\0';
	return (str);
}

/*
 * strlower -- make a string lower-case, destructively.
 *	Not internationalized: TBD.
 */
char *
strlower(char *str)
{
	char	*p;

	for (p = str; *p != '\0'; p++) {
		*p = tolower(*p);
	}
	return (str);
}

/*
 * strset -- update a dynamically-allocated string or die trying.
 */
char *
strset(char *string, char *value)
{
	size_t	vlen;

	assert(value != NULL, "passed a NULL value to strset");
	vlen = strlen(value);
	if (string == NULL) {
		/* It was never allocated, so allocate it. */
		if ((string = malloc(vlen+1)) == NULL) {
			errlog(FATAL, "malloc ran out of space");
		}
	} else if (strlen(string) < vlen) {

		/* Reallocate bigger. */
		if ((string = realloc(string, vlen+1)) == NULL) {
			errlog(FATAL, "realloc ran out of space", "", 0);
		}
	}
	(void) strcpy(string, value);
	return (string);
}

/*
 * in_string_set --see if string matches any member of a space-separated
 *	set of strings.
 */
int
in_string_set(char *p, char *set)
{
	char	*q;
	char save;

	errlog(BEGIN, "in_string_set( p = \"%s\", set = \"%s\") {", p, set);

	for (;;) {
		set = skipb(set);
		q = nextsep(set);
		if (q == set) {
			/* We've hit the end */
			break;
		}
		save = *q;
		*q = '\0';
		if (strcmp(p, set) == 0) {
			*q = save;
			errlog(VERBOSE, "return YES");
			errlog(END, "}");
			return (YES);
		}
		*q = save;
		set = q;
	}
	errlog(VERBOSE, "return NO");
	errlog(END, "}");
	return (NO);

}

char *
strend(char *p)
{

	while (*p)
		p++;
	return (p);
}

char *
lastspace(char *p)
{
	char	*q;

	q = strend(p);
	q--;
	while (q >= p && isspace(*q))
		q--;
	return (++q);
}

/*
 * skipb -- skip over blanks (whitespace, actually), stopping
 *	on first non-blank.
 */
char *
skipb(char *p)
{
	while (*p && isspace(*p))
		p++;
	return (p);
}

/*
 * nextb -- skip over non-blanks (including operators!)
 *	stopping on first blank.
 */
char *
nextb(char *p)
{
	while (*p && !isspace(*p))
		p++;
	return (p);
}

/*
 * skipsep -- skip over separators (all but alnum and _),
 *	stopping on first non-separator.
 */
char *
skipsep(char *p)
{
	errlog(BEGIN, "skipsep() {");
	errlog(VERBOSE, "p (in) = %s", p);
	while (*p && !(isalnum(*p) || *p == '_' || *p == '$'))
		p++;
	errlog(VERBOSE, "p (out) = %s", p);
	errlog(END, "}");
	return (p);
}

/*
 * nextsep -- skip over non-separators (alnum and _, actually),
 *	stopping on first separator.
 */
char *
nextsep(char *p)
{
	errlog(BEGIN, "nextsep() {");
	errlog(VERBOSE, "p (in) = %s", p);
	while (*p && isalnum(*p) || *p == '_' || *p == '$')
		p++;
	errlog(VERBOSE, "p (out) = %s", p);
	errlog(END, "}");
	return (p);
}

/*
 * nextsep2 -- same as nextsep but also skips '.'
 */
char *
nextsep2(char *p)
{
	errlog(BEGIN, "nextsep() {");
	errlog(VERBOSE, "p (in) = %s", p);
	while (*p && isalnum(*p) || *p == '_' || *p == '$' || *p == '.')
		p++;
	errlog(VERBOSE, "p (out) = %s", p);
	errlog(END, "}");
	return (p);
}

/*
 * objectname -- basename was taken (in man3c), so...
 */
char *
objectname(char *name)
{
	char    *p;
	static char basename[MAXLINE];

	p = strrchr(name, '/');
	while (p != NULL && *(p+1) == '\0') {
		/* The / was at the end of the name. */
		*p = '\0';
		p = strrchr(name, '/');
	}
	(void) strlcpy(basename, p? p+1: name, MAXLINE);
	if ((p = strstr(basename, ".c")) != NULL) {
		*p = '\0';
	}
	return (strcat(basename, ".o"));
}

/*
 * String tables
 */

table_t *
create_string_table(int size)
{
	table_t	*t;

	errlog(BEGIN, "create_string_table() {");
	if ((t = (table_t *)calloc((size_t)1,
	    (size_t)(sizeof (table_t) + (sizeof (char *)*size)))) == NULL) {
		errlog(FATAL, "out of memory creating a string table");
	}
	t->nelem = size;
	t->used = -1;
	errlog(END, "}");
	return (t);
}

table_t *
add_string_table(table_t *t, char *value)
{
	table_t *t2;
	int	i;

	if (t == NULL) {
		errlog(FATAL, "programmer error: tried to add to "
			"a NULL table");
	}
	if (in_string_table(t, value)) {
		return (t);
	}
	t->used++;
	if (t->used >= t->nelem) {
		if ((t2 = realloc(t, (size_t)(sizeof (table_t)+(sizeof
				(char *)*(t->nelem+TABLE_INCREMENT)))))
								== NULL) {
			errlog(FATAL, "out of memory extending string table");
		}
		t = t2;
		t->nelem += TABLE_INCREMENT;
		for (i = t->used; i < t->nelem; i++) {
			t->elements[i] = NULL;
		}
	}

	t->elements[t->used] = strset(t->elements[t->used], value);
	return (t);
}

/*
 * free_string_table -- really only mark it empty for reuse.
 */
table_t *
free_string_table(table_t *t)
{
	errlog(BEGIN, "free_string_table() {");
	if (t != NULL) {
		t->used = -1;
	}
	errlog(END, "}");
	return (t);
}

char *
get_string_table(table_t *t, int index)
{
	if (t == NULL) {
		return (NULL);
	} else if (index > t->used) {
		return (NULL);
	} else {
		return (t->elements[index]);
	}
}

int
in_string_table(table_t *t, char *value)
{
	int	i;
	size_t	len = strlen(value);

	if (t == NULL) {
		return (0);
	}
	for (i = 0; i <= t->used; i++) {
		if (strncmp(value, t->elements[i], len) == 0 &&
		    (t->elements[i][len] == '\0' ||
			t->elements[i][len] == ','))
			return (1);
	}
	return (0);
}

static int
compare(const void *p, const void *q)
{
	return (strcmp((char *)(*(char **)p), (char *)(*(char **)q)));
}

void
sort_string_table(table_t *t)
{
	if (t) {
		qsort((char *)t->elements, (size_t)t->used,
			sizeof (char *), compare);
	}
}
