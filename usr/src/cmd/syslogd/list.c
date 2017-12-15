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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <pthread.h>
#include <malloc.h>
#include <memory.h>
#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include "llt.h"

void
ll_init(llh_t *head)
{
	head->back = &head->front;
	head->front = NULL;
}

void
ll_enqueue(llh_t *head, ll_t *data)
{
	data->n = NULL;
	*head->back = data;
	head->back = &data->n;
}

/*
 * apply the function func to every element of the ll in sequence.  Can
 * be used to free up the element, so "n" is computed before func is
 * called on it.
 */
void
ll_mapf(llh_t *head, void (*func)(void *))
{
	ll_t *t = head->front;
	ll_t *n;

	while (t) {
		n = t->n;
		func(t);
		t = n;
	}
}

ll_t *
ll_peek(llh_t *head)
{
	return (head->front);
}

ll_t *
ll_dequeue(llh_t *head)
{
	ll_t *ptr;
	ptr = head->front;
	if (ptr && ((head->front = ptr->n) == NULL))
		head->back = &head->front;
	return (ptr);
}

ll_t *
ll_traverse(llh_t *ptr, int (*func)(void *, void *), void *user)
{
	ll_t *t;
	ll_t **prev = &ptr->front;

	t = ptr->front;
	while (t) {
		switch (func(t, user)) {
		case 1:
			return (NULL);
		case 0:
			prev = &(t->n);
			t = t->n;
			break;
		case -1:
			if ((*prev = t->n) == NULL)
				ptr->back = prev;
			return (t);
		}
	}
	return (NULL);
}

/* Make sure the list isn't corrupt and returns number of list items */
int
ll_check(llh_t *head)
{
	int i = 0;
	ll_t *ptr = head->front;
#ifndef NDEBUG
	ll_t **prev = &head->front;
#endif

	while (ptr) {
		i++;
#ifndef NDEBUG
		prev = &ptr->n;
#endif
		ptr = ptr->n;
	}
	assert(head->back == prev);
	return (i);
}
