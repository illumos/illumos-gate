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
 * Copyright(c) 1996-1999, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_LLT_H
#define	_LLT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

typedef struct ll {
	struct ll *n;
} ll_t;

typedef struct llh {
	ll_t *front;
	ll_t **back;
} llh_t;

void   ll_init(llh_t *head);
void   ll_enqueue(llh_t *head, ll_t *data);
void   ll_mapf(llh_t *head, void (*func)(void *));
ll_t * ll_peek(llh_t *head);
ll_t * ll_dequeue(llh_t *head);
ll_t * ll_traverse(llh_t *ptr, int (*func)(void *, void *), void *user);
int    ll_check(llh_t *head);

#endif /* _LLT_H */
