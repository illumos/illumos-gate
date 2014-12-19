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
 * Copyright 2014 Joyent, Inc.
 */

/*
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <err.h>

#include "rcv.h"

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Routines for processing and detecting headlines.
 */

static int nextword(const char *, custr_t *, const char **);

/*
 * See if the passed line buffer is a mail header.
 * Return true if yes.
 */
boolean_t
is_headline(const char *linebuf)
{
	headline_t *hl;
	boolean_t ret;

	if (strncmp("From ", linebuf, 5) != 0) {
		return (B_FALSE);
	}

	if (headline_alloc(&hl) != 0 || parse_headline(linebuf, hl) != 0) {
		err(1, "could not parse headline");
	}

	ret = custr_len(hl->hl_from) > 0 ? B_TRUE : B_FALSE;

	headline_free(hl);
	return (ret);
}

/*
 * Manage headline_t objects:
 */
void
headline_free(headline_t *hl)
{
	custr_free(hl->hl_from);
	custr_free(hl->hl_tty);
	custr_free(hl->hl_date);
	free(hl);
}

int
headline_alloc(headline_t **hl)
{
	int en;
	headline_t *t;

	if ((t = calloc(1, sizeof (*t))) == NULL) {
		return (-1);
	}

	if (custr_alloc(&t->hl_from) != 0 || custr_alloc(&t->hl_tty) != 0 ||
	    custr_alloc(&t->hl_date) != 0) {
		en = errno;

		headline_free(t);

		errno = en;
		return (-1);
	}

	*hl = t;
	return (0);
}

/*
 * Clear all of the strings in a headline_t:
 */
void
headline_reset(headline_t *hl)
{
	custr_reset(hl->hl_from);
	custr_reset(hl->hl_tty);
	custr_reset(hl->hl_date);
}

int
parse_headline(const char *line, headline_t *hl)
{
	const char *c = line;

	headline_reset(hl);

	/*
	 * Load the first word from the line and ensure that it is "From".
	 */
	if (nextword(c, hl->hl_from, &c) != 0) {
		return (-1);
	}
	if (strcmp(custr_cstr(hl->hl_from), "From") != 0) {
		errno = EINVAL;
		return (-1);
	}
	custr_reset(hl->hl_from);

	/*
	 * The next word will be the From address.
	 */
	if (nextword(c, hl->hl_from, &c) != 0) {
		return (-1);
	}

	/*
	 * If there is a next word, the rest of the string is the Date.
	 */
	if (c != NULL) {
		if (custr_append(hl->hl_date, c) != 0) {
			return (-1);
		}
	}

	errno = 0;
	return (0);
}

/*
 * Collect a space- or tab-delimited word into the word buffer, if one is
 * passed.  The double quote character (") can be used to include whitespace
 * within a word.  Set "nextword" to the location of the first character of the
 * _next_ word, or NULL if there were no more words.  Returns 0 on success or
 * -1 otherwise.
 */
static int
nextword(const char *input, custr_t *word, const char **nextword)
{
	boolean_t in_quotes = B_FALSE;
	const char *c = input != NULL ? input : "";

	/*
	 * Collect the first word into the word buffer, if one is provided.
	 */
	for (;;) {
		if (*c == '\0') {
			/*
			 * We have reached the end of the string.
			 */
			*nextword = NULL;
			return (0);
		}

		if (*c == '"') {
			/*
			 * Either beginning or ending a quoted string.
			 */
			in_quotes = in_quotes ? B_FALSE : B_TRUE;
		}

		if (!in_quotes && (*c == ' ' || *c == '\t')) {
			/*
			 * We have reached a whitespace region.
			 */
			break;
		}

		/*
		 * Copy this character into the word buffer.
		 */
		if (word != NULL) {
			if (custr_appendc(word, *c) != 0) {
				return (-1);
			}
		}
		c++;
	}

	/*
	 * Find the beginning of the next word, if there is one.
	 */
	for (;;) {
		if (*c == '\0') {
			/*
			 * We have reached the end of the string.
			 */
			*nextword = NULL;
			return (0);

		} else if (*c != ' ' && *c != '\t') {
			/*
			 * We have located the next word.
			 */
			*nextword = c;
			return (0);
		}
		c++;
	}
}

/*
 * Copy str1 to str2, return pointer to null in str2.
 */

char *
copy(char *str1, char *str2)
{
	register char *s1, *s2;

	s1 = str1;
	s2 = str2;
	while (*s1)
		*s2++ = *s1++;
	*s2 = 0;
	return(s2);
}

/*
 * Is ch any of the characters in str?
 */

int 
any(int ch, char *str)
{
	register char *f;
	int c;

	f = str;
	c = ch;
	while (*f)
		if (c == *f++)
			return(1);
	return(0);
}
