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

/*
 * Generic lists
 * Lists are circular, doubly-linked, with headers.
 * When a list is empty, both pointers in the header
 * point to the header itself.
 */

#include "nsc_list.h"
/*
 * void
 * ls_remove(ls_elt_t *)
 *	Unlink donated element for list.
 *
 * Calling/Exit State:
 *	Resets elements pointers to empty list state.
 */
void
ls_remove(ls_elt_t *p)
{
	p->ls_prev->ls_next = p->ls_next;
	p->ls_next->ls_prev = p->ls_prev;
	LS_INIT(p);
}
/*
 * void
 * ls_ins_after(ls_elt_t *, ls_elt_t *)
 *
 *	Link new into list after old.
 *
 * Calling/Exit State:
 *
 *	None.
 */
void
ls_ins_after(ls_elt_t *old, ls_elt_t *new)
{
	new->ls_next = old->ls_next;
	new->ls_prev = old;
	new->ls_next->ls_prev = new;
	new->ls_prev->ls_next = new;
}


/*
 * void
 * ls_ins_before(ls_elt_t *, ls_elt_t *)
 *	Link new into list after old.
 *
 * Calling/Exit State:
 *
 *	None.
 */
void
ls_ins_before(ls_elt_t *old, ls_elt_t *new)
{
	new->ls_prev = old->ls_prev;
	new->ls_next = old;
	new->ls_prev->ls_next = new;
	new->ls_next->ls_prev = new;
}
