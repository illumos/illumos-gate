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
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <math.h>
#include "stabs.h"

void squander_do_sou(struct tdesc *tdp, struct node *np);
void squander_do_enum(struct tdesc *tdp, struct node *np);
void squander_do_intrinsic(struct tdesc *tdp, struct node *np);

void
squander_do_intrinsic(struct tdesc *tdp, struct node *np)
{
}

void
squander_do_sou(struct tdesc *tdp, struct node *np)
{
	struct mlist *mlp;
	size_t msize = 0;
	unsigned long offset;

	if (np->name == NULL)
		return;
	if (tdp->type == UNION)
		return;

	offset = 0;
	for (mlp = tdp->data.members.forw; mlp != NULL; mlp = mlp->next) {
		if (offset != (mlp->offset / 8)) {
			printf("%lu wasted bytes before %s.%s (%lu, %lu)\n",
			    (mlp->offset / 8) - offset,
			    np->name,
			    mlp->name == NULL ? "(null)" : mlp->name,
			    offset, mlp->offset / 8);
		}
		msize += (mlp->size / 8);
		offset = (mlp->offset / 8) + (mlp->size / 8);
	}

	printf("%s: sizeof: %lu  total: %lu  wasted: %lu\n", np->name,
	    tdp->size, msize, tdp->size - msize);
}

void
squander_do_enum(struct tdesc *tdp, struct node *np)
{
}
