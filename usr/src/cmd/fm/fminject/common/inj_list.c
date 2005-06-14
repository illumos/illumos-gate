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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <inj_err.h>
#include <inj_list.h>

#include <assert.h>
#include <unistd.h>

void
inj_list_append(inj_list_t *mlp, void *new)
{
	inj_list_t *p = mlp->ml_prev;	/* p = tail list element */
	inj_list_t *q = new;		/* q = new list element */

	mlp->ml_prev = q;
	q->ml_prev = p;
	q->ml_next = NULL;

	if (p != NULL) {
		assert(p->ml_next == NULL);
		p->ml_next = q;
	} else {
		assert(mlp->ml_next == NULL);
		mlp->ml_next = q;
	}
}

void
inj_list_prepend(inj_list_t *mlp, void *new)
{
	inj_list_t *p = new;		/* p = new list element */
	inj_list_t *q = mlp->ml_next;	/* q = head list element */

	mlp->ml_next = p;
	p->ml_prev = NULL;
	p->ml_next = q;

	if (q != NULL) {
		assert(q->ml_prev == NULL);
		q->ml_prev = p;
	} else {
		assert(mlp->ml_prev == NULL);
		mlp->ml_prev = p;
	}
}
