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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "queue.h"
#include "set.h"
#include "new.h"


/*
 * Globals
 */

static queue_node_t g_setlist = {
	&g_setlist,
&g_setlist};


/*
 * Forward Declarations
 */

static void			set_destroy(set_t * set_p);
static void			set_print(FILE * stream, set_t * set_p);


/*
 * set() - creates a set
 */

set_t		  *
set(char *setname_p, expr_t * exprlist_p)
{
	set_t		  *new_p;
	set_t		  *old_p;

	/* does this setname exist already? */
	old_p = set_find(setname_p);
	if (old_p)
		set_destroy(old_p);

	/* create a new set */
	new_p = new(set_t);
	queue_init(&new_p->qn);
	new_p->setname_p = setname_p;
	new_p->exprlist_p = exprlist_p;

	/* append the new set to the global list */
	(void) queue_append(&g_setlist, &new_p->qn);

	return (new_p);

}				/* end set */


/*
 * set_destroy() - destroys a set and related resources
 */

static void
set_destroy(set_t * set_p)
{
	if (!set_p)
		return;

	/* remove ourselves from any list */
	if (!queue_isempty(&set_p->qn))
		(void) queue_remove(&set_p->qn);

	if (set_p->setname_p)
		free(set_p->setname_p);

	/* destroy the exprlist */
	expr_destroy(set_p->exprlist_p);

	free(set_p);

}				/* end set_destroy */


/*
 * set_list() - pretty prints the global setlist
 */

void
set_list(void)
{
	set_t		  *set_p;

	set_p = (set_t *) & g_setlist;
	while ((set_p = (set_t *) queue_next(&g_setlist, &set_p->qn))) {
		(void) printf("$%-8s ", set_p->setname_p);
		set_print(stdout, set_p);
		(void) printf("\n");
	}

}				/* end set_list */


/*
 * set_print() - pretty prints a set
 */

static void
set_print(FILE * stream, set_t * set_p)
{
	if (!set_p)
		return;

	expr_print(stream, set_p->exprlist_p);

}				/* end set_print */


#ifdef OLD
/*
 * set_match() - discerns whether a probe is in a set
 */

boolean_t
set_match(set_t * set_p, const char *name, const char *keys)
{
	if (!set_p)
		return (B_FALSE);

	return (expr_match(set_p->exprlist_p, name, keys));

}				/* end set_match */
#endif


/*
 * set_find() - finds a set by name
 */

set_t		  *
set_find(char *setname_p)
{
	set_t		  *set_p;

	if (!setname_p)
		return (NULL);

	set_p = (set_t *) & g_setlist;
	while ((set_p = (set_t *) queue_next(&g_setlist, &set_p->qn)))
		if (strcmp(setname_p, set_p->setname_p) == 0)
			return (set_p);

	return (NULL);

}				/* end set_find */
