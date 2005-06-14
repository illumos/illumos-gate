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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_list.h>
#include <mdb/mdb_debug.h>
#include <unistd.h>

/*
 * Simple doubly-linked list implementation.  This implementation assumes that
 * each list element contains an embedded mdb_list_t (previous and next
 * pointers), which is typically the first member of the element struct.
 * An additional mdb_list_t is used to store the head (ml_next) and tail
 * (ml_prev) pointers.  The current head and tail list elements have their
 * previous and next pointers set to NULL, respectively.
 */

void
mdb_list_append(mdb_list_t *mlp, void *new)
{
	mdb_list_t *p = mlp->ml_prev;	/* p = tail list element */
	mdb_list_t *q = new;		/* q = new list element */

	mlp->ml_prev = q;
	q->ml_prev = p;
	q->ml_next = NULL;

	if (p != NULL) {
		ASSERT(p->ml_next == NULL);
		p->ml_next = q;
	} else {
		ASSERT(mlp->ml_next == NULL);
		mlp->ml_next = q;
	}
}

void
mdb_list_prepend(mdb_list_t *mlp, void *new)
{
	mdb_list_t *p = new;		/* p = new list element */
	mdb_list_t *q = mlp->ml_next;	/* q = head list element */

	mlp->ml_next = p;
	p->ml_prev = NULL;
	p->ml_next = q;

	if (q != NULL) {
		ASSERT(q->ml_prev == NULL);
		q->ml_prev = p;
	} else {
		ASSERT(mlp->ml_prev == NULL);
		mlp->ml_prev = p;
	}
}

void
mdb_list_insert(mdb_list_t *mlp, void *after_me, void *new)
{
	mdb_list_t *p = after_me;
	mdb_list_t *q = new;

	if (p == NULL || p->ml_next == NULL) {
		mdb_list_append(mlp, new);
		return;
	}

	q->ml_next = p->ml_next;
	q->ml_prev = p;
	p->ml_next = q;
	q->ml_next->ml_prev = q;
}

void
mdb_list_delete(mdb_list_t *mlp, void *existing)
{
	mdb_list_t *p = existing;

	if (p->ml_prev != NULL)
		p->ml_prev->ml_next = p->ml_next;
	else
		mlp->ml_next = p->ml_next;

	if (p->ml_next != NULL)
		p->ml_next->ml_prev = p->ml_prev;
	else
		mlp->ml_prev = p->ml_prev;
}

void
mdb_list_move(mdb_list_t *src, mdb_list_t *dst)
{
	dst->ml_prev = src->ml_prev;
	dst->ml_next = src->ml_next;
	src->ml_prev = NULL;
	src->ml_next = NULL;
}
