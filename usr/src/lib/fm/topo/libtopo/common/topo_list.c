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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Joyent, Inc.
 */

#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <topo_error.h>
#include <topo_list.h>
#include <topo_tree.h>

/*
 * Embedded Linked Lists
 *
 * Simple doubly-linked list implementation.  This implementation assumes that
 * each list element contains an embedded topo_list_t (previous and next
 * pointers), which is typically the first member of the element struct.
 * An additional topo_list_t is used to store the head (l_next) and tail
 * (l_prev) pointers.  The current head and tail list elements have their
 * previous and next pointers set to NULL, respectively.
 *
 * NOTE: The embeddable list code in this file intentionally provides no
 * locking of any kind.  The implementation of any list in topo must provide
 * an appropriate locking strategy to protect the list or to protect access
 * to the embedded topo_list_t inside of each list element to avoid corruption.
 * Refer to comments in the source files that use topo_list_t for lock details.
 */


void
topo_list_append(topo_list_t *lp, void *new)
{
	topo_list_t *p = lp->l_prev;	/* p = tail list element */
	topo_list_t *q = new;		/* q = new list element */

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
topo_list_prepend(topo_list_t *lp, void *new)
{
	topo_list_t *p = new;		/* p = new list element */
	topo_list_t *q = lp->l_next;	/* q = head list element */

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
topo_list_insert_before(topo_list_t *lp, void *before_me, void *new)
{
	topo_list_t *p = before_me;
	topo_list_t *q = new;

	if (p == NULL || p->l_prev == NULL) {
		topo_list_prepend(lp, new);
		return;
	}

	q->l_prev = p->l_prev;
	q->l_next = p;
	p->l_prev = q;
	q->l_prev->l_next = q;
}

void
topo_list_insert_after(topo_list_t *lp, void *after_me, void *new)
{
	topo_list_t *p = after_me;
	topo_list_t *q = new;

	if (p == NULL || p->l_next == NULL) {
		topo_list_append(lp, new);
		return;
	}

	q->l_next = p->l_next;
	q->l_prev = p;
	p->l_next = q;
	q->l_next->l_prev = q;
}

void
topo_list_delete(topo_list_t *lp, void *existing)
{
	topo_list_t *p = existing;

	if (p->l_prev != NULL)
		p->l_prev->l_next = p->l_next;
	else
		lp->l_next = p->l_next;

	if (p->l_next != NULL)
		p->l_next->l_prev = p->l_prev;
	else
		lp->l_prev = p->l_prev;
}

tnode_t *
topo_child_first(tnode_t *pnode)
{
	int i;
	topo_nodehash_t *nhp;

	for (nhp = topo_list_next(&pnode->tn_children); nhp != NULL;
	    nhp = topo_list_next(nhp)) {
		for (i = 0; i < nhp->th_arrlen; ++i) {
			if (nhp->th_nodearr[i] != NULL)
				return (nhp->th_nodearr[i]);
		}
	}

	return (NULL);
}

tnode_t *
topo_child_next(tnode_t *pnode, tnode_t *node)
{
	int i;
	int index;
	topo_nodehash_t *nhp;

	if (node == NULL) {
		return (topo_child_first(pnode));
	}

	/*
	 * Begin search for next child in the current hash array
	 * If none found or we are at the end of the array, move
	 * on to the next array
	 */
	index = topo_node_hash(node->tn_phash, node->tn_instance) + 1;
	for (nhp = node->tn_phash; nhp != NULL; nhp = topo_list_next(nhp)) {
		for (i = index; i < nhp->th_arrlen; ++i) {
			if (nhp->th_nodearr[i] != NULL) {
				return (nhp->th_nodearr[i]);
			}
		}
		index = 0;
	}

	return (NULL);
}

int
topo_list_deepcopy(topo_hdl_t *thp, topo_list_t *dest, topo_list_t *src,
    size_t elem_sz)
{
	void *elem;

	/* if the destination list is not empty - bail out */
	if (topo_list_next(dest) != NULL)
		return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

	for (elem = topo_list_next(src); elem != NULL;
	    elem = topo_list_next(elem)) {
		void *elem_copy;

		if ((elem_copy = topo_hdl_alloc(thp, elem_sz)) == NULL) {
			goto err;
		}
		(void) memcpy(elem_copy, elem, elem_sz);
		topo_list_append(dest, elem_copy);
	}
	return (0);

err:
	/*
	 * If we hit an error, cleanup any partially copied list elements
	 * before we return.
	 */
	elem = topo_list_next(dest);
	while (elem != NULL) {
		void *tmp = elem;

		elem = topo_list_next(elem);
		topo_list_delete(dest, tmp);
		topo_hdl_free(thp, tmp, elem_sz);
	}
	return (topo_hdl_seterrno(thp, ETOPO_NOMEM));
}
