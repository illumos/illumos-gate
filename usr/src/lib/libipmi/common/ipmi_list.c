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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Embedded Linked Lists
 *
 * Simple doubly-linked list implementation.  This implementation assumes that
 * each list element contains an embedded ipmi_list_t (previous and next
 * pointers), which is typically the first member of the element struct.
 * An additional ipmi_list_t is used to store the head (l_next) and tail
 * (l_prev) pointers.  The current head and tail list elements have their
 * previous and next pointers set to NULL, respectively.
 */

#include <assert.h>
#include <ipmi_impl.h>

void
ipmi_list_append(ipmi_list_t *lp, void *new)
{
	ipmi_list_t *p = lp->l_prev;	/* p = tail list element */
	ipmi_list_t *q = new;		/* q = new list element */

	lp->l_prev = q;
	q->l_prev = p;
	q->l_next = NULL;

	if (p != NULL) {
		assert(p->l_next == NULL);
		p->l_next = q;
	} else {
		assert(lp->l_next == NULL);
		lp->l_next = q;
	}
}

void
ipmi_list_prepend(ipmi_list_t *lp, void *new)
{
	ipmi_list_t *p = new;		/* p = new list element */
	ipmi_list_t *q = lp->l_next;	/* q = head list element */

	lp->l_next = p;
	p->l_prev = NULL;
	p->l_next = q;

	if (q != NULL) {
		assert(q->l_prev == NULL);
		q->l_prev = p;
	} else {
		assert(lp->l_prev == NULL);
		lp->l_prev = p;
	}
}

void
ipmi_list_insert_before(ipmi_list_t *lp, void *before_me, void *new)
{
	ipmi_list_t *p = before_me;
	ipmi_list_t *q = new;

	if (p == NULL || p->l_prev == NULL) {
		ipmi_list_prepend(lp, new);
		return;
	}

	q->l_prev = p->l_prev;
	q->l_next = p;
	p->l_prev = q;
	q->l_prev->l_next = q;
}

void
ipmi_list_insert_after(ipmi_list_t *lp, void *after_me, void *new)
{
	ipmi_list_t *p = after_me;
	ipmi_list_t *q = new;

	if (p == NULL || p->l_next == NULL) {
		ipmi_list_append(lp, new);
		return;
	}

	q->l_next = p->l_next;
	q->l_prev = p;
	p->l_next = q;
	q->l_next->l_prev = q;
}

void
ipmi_list_delete(ipmi_list_t *lp, void *existing)
{
	ipmi_list_t *p = existing;

	if (p->l_prev != NULL)
		p->l_prev->l_next = p->l_next;
	else
		lp->l_next = p->l_next;

	if (p->l_next != NULL)
		p->l_next->l_prev = p->l_prev;
	else
		lp->l_prev = p->l_prev;
}
