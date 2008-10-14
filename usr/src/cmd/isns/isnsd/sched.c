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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "isns_server.h"
#include "isns_protocol.h"
#include "isns_log.h"
#include "isns_sched.h"
#include "isns_scn.h"
#include "isns_esi.h"

/*
 * extern variables.
 */

/*
 * global variables.
 */
pthread_mutex_t el_mtx = PTHREAD_MUTEX_INITIALIZER;

/*
 * local variables.
 */
static el_key_t **il;
static int icurr = 0;
static el_notice_t *curr = NULL;

static uint32_t DU;
static uint32_t DT;
static uint32_t LB;
static uint32_t NLIM;

/*
 * external variables.
 */

/*
 * local functions.
 */

/*
 * ****************************************************************************
 *
 * il_shift:
 *	Shift the indexed-list to the most current time.
 *
 * t	- most current time.
 *
 * ****************************************************************************
 */
static void
il_shift(
	uint32_t t
)
{
	el_notice_t *fn, *n;
	el_key_t *fk, *k;
	uint32_t nt;
	int c;

	k = il[icurr];
	while (k->time < t) {
		fk = k;
		fn = k->notice;
		/* remove the dummy key and dummy notice */
		fk->left->right = fk->right;
		fk->right->left = fk->left;
		fn->pred->sucd = fn->sucd;
		fn->sucd->pred = fn->pred;

		/* find the place where the dummy goes to */
		k = il[(icurr + DU - 1) % DU];
		if (k->time < INFINITY - DT) {
			nt = k->time + DT; /* next key time */
		} else {
			nt = INFINITY - 1; /* the last second */
		}
		while (k->time < nt) {
			k = k->right;
		}
		n = k->notice->pred;
		c = 1;
		while (n->time >= nt) {
			c ++;
			n = n->pred;
		}
		n = n->sucd;

		/* update lower bound */
		LB = fk->time;

		/* insert the dummy key */
		fk->time = nt;
		fk->count = k->count - c + 1;
		fk->left = k->left;
		fk->right = k;
		k->left->right = fk;
		k->left = fk;
		k->count = c;
		/* insert the dummy notice */
		fn->time = nt;
		fn->pred = n->pred;
		fn->sucd = n;
		n->pred->sucd = fn;
		n->pred = fn;

		/* shift the current index */
		icurr = (icurr + 1) % DU;
		k = il[icurr];
	}
}

/*
 * global functions.
 */

/*
 * ****************************************************************************
 *
 * el_init:
 *	Initialize the element list.
 *
 * du	- Number of uint in the indexed-list.
 * dt	- Time interval of the indexed-list.
 * nlim	- Limit number of each notice.
 * return - 0: successful, otherwise failed.
 *
 * ****************************************************************************
 */
int
el_init(
	uint32_t du,
	uint32_t dt,
	uint32_t nlim
)
{
	el_key_t *k, *kleft;
	el_notice_t *n, *npred;

	uint32_t t = 0;

	int i;

	if (du < 1 || dt < 1 || nlim < 1) {
		return (1);
	}

	DU = du;
	DT = dt;
	LB = 0;
	NLIM = nlim;

	/*
	 * initialize the event set
	 */

	/* first dummy notice */
	n = (el_notice_t *)malloc(sizeof (el_notice_t));
	if (n == NULL) {
		return (1);
	}
	n->time = LB;
	n->event = NULL;
	n->isdummy = 1;
	n->pred = NULL;
	npred = n;

	/* first dummy key */
	k = (el_key_t *)malloc(sizeof (el_key_t));
	if (k == NULL) {
		return (1);
	}
	k->time = LB;
	k->count = 1;
	k->notice = n;
	k->left = NULL;
	kleft = k;

	n->key = k;

	/* index list */
	il = (el_key_t **)malloc((DU + 1) * sizeof (el_key_t *));
	if (il == NULL) {
		return (1);
	}

	/* create notice list, key list & index list */
	for (i = 0; i < DU; i++) {
		t += DT;

		n = (el_notice_t *)malloc(sizeof (el_notice_t));
		if (n == NULL) {
			return (1);
		}
		n->time = t;
		n->event = NULL;
		n->isdummy = 1;
		n->pred = npred;
		npred->sucd = n;
		npred = n;

		k = (el_key_t *)malloc(sizeof (el_key_t));
		if (k == NULL) {
			return (1);
		}
		k->time = t;
		k->count = 1;
		k->notice = n;
		k->left = kleft;
		kleft->right = k;
		kleft = k;

		n->key = k;

		il[i] = k;
	}

	/* last dummy notice */
	n = (el_notice_t *)malloc(sizeof (el_notice_t));
	if (n == NULL) {
		return (1);
	}
	n->time = INFINITY; /* the end of the world */
	n->event = NULL;
	n->isdummy = 1;
	n->pred = npred;
	n->sucd = NULL;
	npred->sucd = n;

	/* last dummy key */
	k = (el_key_t *)malloc(sizeof (el_key_t));
	if (k == NULL) {
		return (1);
	}
	k->time = INFINITY; /* the end of the world */
	k->count = 1;
	k->notice = n;
	k->left = kleft;
	k->right = NULL;
	kleft->right = k;

	n->key = k;

	/* last index */
	il[DU] = k;

	return (0);
}

/*
 * ****************************************************************************
 *
 * el_add:
 *	Add an event to the element list with it's execution time.
 *	It might not actually put the event to the list if the event
 *	is the most current one for execution.
 *
 * ev	- The Event.
 * t	- The time when the event is scheduled at.
 * evp	- Pointer of event for returning.
 * return - Error code.
 *
 * ****************************************************************************
 */
int
el_add(
	void *ev,
	uint32_t t,
	void **evp
)
{
	int ec = 0;

	uint32_t t1 = 0;

	int i, j;
	el_key_t *k;
	el_notice_t *n;

	el_key_t *y;
	el_notice_t *x;

	/* lock the event set */
	(void) pthread_mutex_lock(&el_mtx);

	/* strip it off from the event list which is being handled */
	if (evf_again(ev) != 0) {
		/* if it is rescheduling an event and the event */
		/* was waiting for execution after idle finishes */
		if (evf_rem(ev) == 0 &&
		    evp != NULL &&
		    (curr == NULL || t <= curr->time)) {
			/* no need to reschedule it */
			*evp = ev;
			goto add_done;
		}
		evl_strip(ev);
		/* if it is marked as a removed event, do not add it */
		if (evf_rem(ev) != 0) {
			ev_free(ev);
			goto add_done;
		}
	}

	/* get the index in the il */
	if (t == 0) {
		t = ev_intval(ev);
		/* not initialization time */
		if (evf_init(ev) || evf_again(ev)) {
			t1 = get_stopwatch(evf_wakeup(ev));
			/* make il up to date */
			il_shift(t1);
			/* avoid overflow */
			if (t1 >= INFINITY - t) {
				/* the last second */
				t1 = INFINITY - t1 - 1;
			}
		}
		t += t1;
	}
	i = (t - LB) / DT;
	if (i >= DU) {
		i = DU;
	} else {
		i = (i + icurr) % DU;
	}

	/* find the right key */
	k = (il[i])->left;
	while (k->time > t) {
		k = k->left;
	}
	k = k->right;

	/* need to split */
	if (k->count == NLIM) {
		/* insert a new key */
		y = (el_key_t *)malloc(sizeof (el_key_t));
		if (y == NULL) {
			ec = ISNS_RSP_INTERNAL_ERROR;
			goto add_done;
		}
		k->count = NLIM / 2;
		x = k->notice;
		for (j = 1; j <= NLIM / 2; j++) {
			x = x->pred;
		}
		y->time = x->time;
		y->count = NLIM - NLIM / 2;
		y->notice = x;
		y->right = k;
		y->left = k->left;
		k->left->right = y;
		k->left = y;

		/* update the key */
		x->key = y;

		/* shift */
		if (y->time > t) {
			k = y;
		}
	}

	/* make a new notice */
	x = (el_notice_t *)malloc(sizeof (el_notice_t));
	if (x == NULL) {
		ec = ISNS_RSP_INTERNAL_ERROR;
		goto add_done;
	}
	x->time = t;
	x->event = ev;
	x->isdummy = 0;
	x->key = NULL;

	/* insert it */
	n = k->notice;
	while (n->time > t) {
		n = n->pred;
	}
	x->pred = n;
	x->sucd = n->sucd;
	n->sucd->pred = x;
	n->sucd = x;

	/* increase number of notice */
	k->count ++;

	/* reset current notice and wake up idle */
	if (curr == NULL || curr->time > t) {
		curr = x;
	}

	/* clear event flags */
	evf_zero(ev);

	isnslog(LOG_DEBUG, "el_add", "%s [%d] is scheduled at %d.",
	    ((ev_t *)ev)->type == EV_ESI ? "ESI" : "REG_EXP",
	    ((ev_t *)ev)->uid,
	    t);

add_done:
	/* unlock the event set */
	(void) pthread_mutex_unlock(&el_mtx);

	/* failed, free it */
	if (ec != 0) {
		ev_free(ev);
		isnslog(LOG_DEBUG, "el_add", "failed, no memory.");
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * el_remove:
 *	Remove or update an event from the element list. If the event is
 *	currently not in the element list, it must be in a queue which
 *	contains all of event which are being executing at the moment.
 *	So it seeks the event from the list prior to the element list.
 *
 * id1	- The event ID.
 * id2	- The second ID for the event update.
 * pending - Do not actually remove, mark it for removal pending.
 * return - Error code.
 *
 * ****************************************************************************
 */
int
el_remove(
	uint32_t id1,
	uint32_t id2,
	int pending
)
{
	el_key_t *k, *kl, *kr;
	el_notice_t *n, *n2;

	(void) pthread_mutex_lock(&el_mtx);

	/* search the event from the event list which is being handled */
	if (evl_remove(id1, id2, pending) != 0) {
		(void) pthread_mutex_unlock(&el_mtx);
		return (0);
	}

	/* search the notice starting from current */
	n = curr;
	while (n != NULL) {
		/* found the match notice */
		if (!n->isdummy && ev_match(n->event, id1) != 0) {
			if (ev_remove(n->event, id2, 1, pending) == 0) {
				/* update the key of the match notice */
				k = n->key;
				if (k != NULL && k->count == 1) {
					/* no more notice */
					k->left->right = k->right;
					k->right->left = k->left;
					free(k);
				} else {
					if (k != NULL) {
						k->notice = n->pred;
						k->notice->key = k;
						k->time = k->notice->time;
					}
					n2 = n;
					k = n2->key;
					while (k == NULL) {
						n2 = n2->sucd;
						k = n2->key;
					}
					/* decrease the count by one */
					k->count --;
					/* merge the keys */
					kl = k->left;
					kr = k->right;
					if (!kl->notice->isdummy &&
					    (kl->count + k->count) <= NLIM) {
						/* delete the left key */
						k->count += kl->count;
						k->left = kl->left;
						k->left->right = k;
						kl->notice->key = NULL;
						free(kl);
					} else if (!k->notice->isdummy &&
					    (kr->count + k->count) <= NLIM) {
						/* delete this key */
						kr->count += k->count;
						kr->left = k->left;
						kr->left->right = kr;
						k->notice->key = NULL;
						free(k);
					}
				}
				/* delete the match notice */
				n->pred->sucd = n->sucd;
				n->sucd->pred = n->pred;
				/* update current */
				if (n == curr) {
					n2 = n->sucd;
					while (n2 != NULL && n2->isdummy) {
						n2 = n2->sucd;
					}
					curr = n2;
				}
				free(n);
			}
			break; /* exit while loop */
		}
		n = n->sucd;
	}

	(void) pthread_mutex_unlock(&el_mtx);

	return (0);
}

/*
 * ****************************************************************************
 *
 * el_first:
 *	Fetch the first event from the element list.
 *
 * t	- Pointer of time of the event for returning.
 * return - The event.
 *
 * ****************************************************************************
 */
void *
el_first(
	uint32_t *t
)
{
	void *p = NULL;

	el_notice_t *n;
	el_key_t *k;

	(void) pthread_mutex_lock(&el_mtx);

	if (curr != NULL) {
		/* remove current from the event set */
		curr->pred->sucd = curr->sucd;
		curr->sucd->pred = curr->pred;

		/* decrease number of notice */
		n = curr;
		while (n->key == NULL) {
			n = n->sucd;
		}
		k = n->key;
		k->count --;

		/* empty not-dummy key */
		if (k->count == 0) {
			k->left->right = k->right;
			k->right->left = k->left;
			free(k);
		}

		/* get next notice */
		n = curr->sucd;
		while (n != NULL && n->isdummy) {
			n = n->sucd;
		}

		/* return the time */
		*t = curr->time;
		/* reset current notice */
		p = curr->event;
		free(curr);
		curr = n;
	}

	/* the one that is being handled by esi_proc */
	if (p) {
		evl_append(p);
	}

	(void) pthread_mutex_unlock(&el_mtx);

	if (p) {
		isnslog(LOG_DEBUG, "el_first", "%s [%d] is fetched.",
		    ((ev_t *)p)->type == EV_ESI ? "ESI" : "REG_EXP",
		    ((ev_t *)p)->uid);
	}

	return (p);
}
