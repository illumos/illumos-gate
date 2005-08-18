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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	topological sort
 *	input is sequence of pairs of items (blank-free strings)
 *	nonidentical pair is a directed edge in graph
 *	identical pair merely indicates presence of node
 *	output is ordered list of items consistent with
 *	the partial ordering specified by the graph
 */
#include "errmsg.h"
#include "stdio.h"
#include "string.h"
#include <locale.h>

/*
 *	the nodelist always has an empty element at the end to
 *	make it easy to grow in natural order
 *	states of the "live" field:
 */
#define	DEAD 0	/* already printed */
#define	LIVE 1	/* not yet printed */
#define	VISITED 2	/* used only in findloop() */

#define	STR(X) #X
#define	XSTR(X) STR(X)
#define	FORMAT "%" XSTR(FILENAME_MAX) "s%" XSTR(FILENAME_MAX) "s"
/* These should make FORMAT "%1024s%1024s", if FILENAME_MAX is 1024. */

static
struct nodelist {
	struct nodelist *nextnode;
	struct predlist *inedges;
	char *name;
	int live;
} firstnode = {NULL, NULL, NULL, DEAD};

/*
 *	a predecessor list tells all the immediate
 *	predecessors of a given node
 */
struct predlist {
	struct predlist *nextpred;
	struct nodelist *pred;
};

static struct nodelist *index(char *s);
static struct nodelist *findloop(void);
static struct nodelist *mark(struct nodelist *i);
static int present(struct nodelist *i, struct nodelist *j);
static int anypred(struct nodelist *i);

/*
 *	the first for loop reads in the graph,
 *	the second prints out the ordering
 */
int
main(int argc, char **argv)
{
	struct predlist *t;
	FILE *input = stdin;
	struct nodelist *i, *j;
	int x;
	char precedes[FILENAME_MAX+1], follows[FILENAME_MAX+1];

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if not previously defined */
#endif
	(void) textdomain(TEXT_DOMAIN);

	errprefix("UX");
	errsource(*argv);
	errverb("notag,notofix");
	switch (argc) {
	case 1:
		break;
	case 2:
		if (strcmp(argv[1], "-") == 0)
			break;
		if (strcmp(argv[1], "--") == 0)
			break;
		input = zfopen(EERROR, argv[1], "r");
		break;
	case 3:
		if (strcmp(argv[1], "--") != 0)
			errusage(gettext("[ file ]"));
		input = zfopen(EERROR, argv[2], "r");
		break;
	default:
		errusage("[ file ]");
	}
	for (;;) {
		x = fscanf(input, FORMAT, precedes, follows);
		if (x == EOF)
			break;
		if (x != 2)
			errmsg(EERROR, gettext("odd data"));
		i = index(precedes);
		j = index(follows);
		if (i == j || present(i, j))
			continue;
		t = (struct predlist *)
			zmalloc(EERROR, sizeof (struct predlist));
		t->nextpred = j->inedges;
		t->pred = i;
		j->inedges = t;
	}
	for (;;) {
		x = 0;	/* anything LIVE on this sweep? */
		for (i = &firstnode; i->nextnode != NULL; i = i->nextnode) {
			if (i->live == LIVE) {
				x = 1;
				if (!anypred(i))
					break;
			}
		}
		if (x == 0)
			break;
		if (i->nextnode == NULL)
			i = findloop();
		(void) puts(i->name);
		i->live = DEAD;
	}
	return (0);	/* Ensure zero return on normal termination */
}

/*
 *	is i present on j's predecessor list?
 */
static int
present(struct nodelist *i, struct nodelist *j)
{
	struct predlist *t;
	for (t = j->inedges; t != NULL; t = t->nextpred)
		if (t->pred == i)
			return (1);
	return (0);
}

/*
 *	is there any live predecessor for i?
 */
static int
anypred(struct nodelist *i)
{
	struct predlist *t;
	for (t = i->inedges; t != NULL; t = t->nextpred)
		if (t->pred->live == LIVE)
			return (1);
	return (0);
}

/*
 *	turn a string into a node pointer
 */
static struct nodelist *
index(char *s)
{
	struct nodelist *i;
	char *t;
	for (i = &firstnode; i->nextnode != NULL; i = i->nextnode)
		if (strcmp(s, i->name) == 0)
			return (i);
	for (t = s; *t; t++);
	t = zmalloc(EERROR, (unsigned)(t + 1 - s));
	i->nextnode = (struct nodelist *)
		zmalloc(EERROR, sizeof (struct nodelist));
	i->name = t;
	i->live = LIVE;
	i->nextnode->nextnode = NULL;
	i->nextnode->inedges = NULL;
	i->nextnode->live = DEAD;
	while (*t++ = *s++);
	return (i);
}

/*
 *	given that there is a cycle, find some
 *	node in it
 */
static struct nodelist *
findloop(void)
{
	struct nodelist *i, *j;

	for (i = &firstnode; i->nextnode != NULL; i = i->nextnode)
		if (i->live == LIVE)
			break;
	errmsg(EINFO, "cycle in data");
	i = mark(i);
	if (i == NULL)
		errmsg(EHALT, gettext("program error"));
	for (j = &firstnode; j->nextnode != NULL; j = j->nextnode)
		if (j->live == VISITED)
			j->live = LIVE;
	return (i);
}

/*
 *	depth-first search of LIVE predecessors
 *	to find some element of a cycle;
 *	VISITED is a temporary state recording the
 *	visits of the search
 */
static struct nodelist *
mark(struct nodelist *i)
{
	struct nodelist *j;
	struct predlist *t;

	if (i->live == DEAD)
		return (NULL);
	if (i->live == VISITED)
		return (i);
	i->live = VISITED;
	for (t = i->inedges; t != NULL; t = t->nextpred) {
		j = mark(t->pred);
		if (j != NULL) {
			(void) fprintf(stderr, "\t%s\n", i->name);
			return (j);
		}
	}
	return (NULL);
}
