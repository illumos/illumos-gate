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
 *	ignore.c
 *
 * purpose:
 *	routines to manage the ignore lists and test names against them,
 *
 * contents:
 *	ignore_check ... is a particular file covered by an ignore rule
 *	ignore_file .... add a specific file name to be ignored
 *	ignore_expr .... add a regular expression for files to be ignored
 *	ignore_pgm ..... add a rule to run a program to generate a list
 *	ignore_reset ... flush the internal optimization data structures
 *
 *	static
 *	    ign_hash ... maintain a hash table of ignored names
 *	    cheap_check. build up a table of safe suffixes
 *
 * notes:
 *	a much simpler implementation could have been provided, but
 *	this test (every file tested against every rule) has the
 *	potential to be EXTREMELY expensive.  This module implements
 *	an engine that attempts to optimize the process of determining
 *	that a file has not been ignored.
 *
 *	the usage scenario is
 *	    per base
 *		call ignore_{file,expr,pgm} for each ignore rule
 *		call ignore_check for every file under the base
 *		call ignore_reset when you are done
 */
#ident	"%W%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include "filesync.h"
#include "messages.h"

/*
 * routines:
 */
static struct list *ign_hash(const char *, int);
static void cheap_check(const char *);

/*
 * globals
 */
struct list {
	char *l_value;			/* the actual string		*/
	struct list *l_next;		/* pointer to next element	*/
};

static struct list *expr_list;		/* list of regular expressions	*/
static struct list *file_list[ HASH_SIZE ]; /* hash table of literal names */

static char cheap_last[256];		/* cheap test: last char	*/
static char cheap_penu[256];		/* cheap test: penultimate char	*/

/*
 * routine:
 *	ignore_check
 *
 * purpose:
 *	determine whether or not a particular name matches an ignore pattern.
 *
 * parameters:
 *	file name
 *
 * returns:
 *	true/false
 *
 * note:
 *	becuse this routine is called on every single file in
 *	every single sub-directory, it is critical that we make
 *	it fail quickly for most files.  The purpose of the cheap_last
 *	and cheap_penu arrays is to quickly determine there is no chance
 *	that a name will match any expression.  Most expressions have
 *	wildcards near the front and constant suffixes, so our cheap
 *	test is to look at the last two bytes.
 */
bool_t
ignore_check(const char *name)
{	struct list *lp;
	const char *s;

	/*
	 * start with the cheap test
	 */
	for (s = name; *s; s++);
	if (cheap_last[ (unsigned char) s[-1] ] == 0 ||
	    cheap_penu[ (unsigned char) s[-2] ] == 0)
		return (FALSE);

	/* check the literal names in the hash table		*/
	if (ign_hash(name, 0)) {
		if (opt_debug & DBG_IGNORE)
			fprintf(stderr, "IGNO: match %s\n", name);
		return (TRUE);
	}

	/* check all the regular expressions			*/
	for (lp = expr_list; lp; lp = lp->l_next) {
		if (gmatch(name, lp->l_value) == 0)
			continue;

		if (opt_debug & DBG_IGNORE)
			fprintf(stderr, "IGNO: regex %s : %s\n",
				lp->l_value, name);
		return (TRUE);
	}

	return (FALSE);
}

/*
 * routine:
 *	ignore_file
 *
 * purpose:
 *	to add a specific file to an ignore list
 *
 * parameters:
 *	command to run
 */
void
ignore_file(const char *name)
{
	cheap_check(name);

	(void) ign_hash(name, 1);

	if (opt_debug & DBG_IGNORE)
		fprintf(stderr, "IGNO: add file %s\n", name);
}

/*
 * routine:
 *	ignore_expr
 *
 * purpose:
 *	to add a regular expression to an ignore list
 *
 * parameters:
 *	command to run
 */
void
ignore_expr(const char *expr)
{	struct list *lp;

	cheap_check(expr);

	/* allocate a new node and stick it on the front of the list	*/
	lp = malloc(sizeof (*lp));
	if (lp == 0)
		nomem("ignore list");
	lp->l_value = strdup(expr);
	lp->l_next = expr_list;
	expr_list = lp;

	if (opt_debug & DBG_IGNORE)
		fprintf(stderr, "IGNO: add expr %s\n", expr);
}

/*
 * routine:
 *	ignore_pgm
 *
 * purpose:
 *	to run a program and gather up the ignore list it produces
 *
 * parameters:
 *	command to run
 */
void
ignore_pgm(const char *cmd)
{	char *s;
	FILE *fp;
	char inbuf[ MAX_LINE ];

	if (opt_debug & DBG_IGNORE)
		fprintf(stderr, "IGNO: add pgm %s\n", cmd);

	/* run the command and collect its ouput	*/
	fp = popen(cmd, "r");
	if (fp == NULL) {
		fprintf(stderr, gettext(ERR_badrun), cmd);
		return;
	}

	/*
	 * read each line, strip off the newline and add it to the list
	 */
	while (fgets(inbuf, sizeof (inbuf), fp) != 0) {
		/* strip off any trailing newline	*/
		for (s = inbuf; *s && *s != '\n'; s++);
		*s = 0;

		/* skip any leading white space		*/
		for (s = inbuf; *s == ' ' || *s == '\t'; s++);

		/* add this file to the list		*/
		if (*s) {
			cheap_check(s);
			(void) ign_hash(s, 1);

			if (opt_debug & DBG_IGNORE)
				fprintf(stderr, "IGNO: ... %s\n", s);
		}
	}

	pclose(fp);
}

/*
 * routine:
 *	ign_hash
 *
 * purpose:
 *	to find an entry in the hash list
 *
 * parameters:
 *	name
 *	allocate flag
 *
 * returns:
 *	pointer to new list entry or 0
 */
static struct list *
ign_hash(const char *name, int alloc)
{	const unsigned char *s;
	int i;
	struct list *lp;
	struct list **pp;

	/* perform the hash and find the chain	*/
	for (s = (const unsigned char *) name, i = 0; *s; s++)
		i += *s;
	pp = &file_list[i % HASH_SIZE ];

	/* search for the specified entry	*/
	for (lp = *pp; lp; lp = *pp) {
		if (strcmp(name, lp->l_value) == 0)
			return (lp);
		pp = &(lp->l_next);
	}

	/* if caller said alloc, buy a new node and chain it in	*/
	if (alloc) {
		lp = malloc(sizeof (*lp));
		if (lp == 0)
			nomem("ignore list");
		lp->l_value = strdup(name);
		lp->l_next = 0;
		*pp = lp;
	}

	return (lp);
}

/*
 * routine:
 *	cheap_check
 *
 * purpose:
 *	to update the cheap-check arrays for an ignore expression
 *
 * parameters:
 *	name/expression
 */
static void
cheap_check(const char *name)
{	const char *s;
	unsigned char c;
	int i;

	for (s = name; *s; s++);
	s--;

	/* if expr ends in a wild card, we are undone		*/
	c = *s;
	if (c == '*' || c == '?' || c == ']' || c == '}') {
		for (i = 0; i < 256; i++) {
			cheap_last[i] = 1;
			cheap_penu[i] = 1;
		}
		return;
	} else
		cheap_last[c] = 1;

	if (s <= name)
		return;

	/* check the next to last character too		*/
	c = s[-1];
	if (c == '*' || c == '?' || c == ']' || c == '}') {
		for (i = 0; i < 256; i++)
			cheap_penu[i] = 1;
	} else
		cheap_penu[c] = 1;
}

/*
 * routine:
 *	ignore_reset
 *
 * purpose:
 *	to free up all the ignore entries so we can start anew
 */
void
ignore_reset(void)
{	int i;
	struct list *np = 0;	/* for LINT */
	struct list *lp;

	/* clear the cheap check arrays */
	for (i = 0; i < 255; i++) {
		cheap_last[i] = 0;
		cheap_penu[i] = 0;
	}

	/* free all of the literal hash chains	*/
	for (i = 0; i < HASH_SIZE; i++) {
		for (lp = file_list[i]; lp; lp = np) {
			np = lp->l_next;
			free(lp->l_value);
			free(lp);
		}
		file_list[i] = 0;
	}

	/* free all of the expressions on the chain	*/
	for (lp = expr_list; lp; lp = np) {
		np = lp->l_next;
		free(lp->l_value);
		free(lp);
	}
	expr_list = 0;
}
