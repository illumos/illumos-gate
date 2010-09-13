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
#include <sys/types.h>
#include <pthread.h>
#include <libelf.h>
#include <libelf.h>

#include "isns_server.h"
#include "isns_cache.h"
#include "isns_htab.h"
#include "isns_log.h"

#define	UID_REUSABLE(T, X)	((T) - (X)->t >= ONE_DAY)

/*
 * external variables.
 */
extern int cache_flag;

/*
 * ****************************************************************************
 * avl_search:
 *	search a node from an AVL tree.
 *
 * tab	- the hash table.
 * uid	- the object UID.
 * return - the node which matches the object UID.
 *
 * ****************************************************************************
 */
static htab_itemx_t *
avl_search(
	const htab_t *tab,
	const uint32_t uid
)
{
	htab_itemx_t *x = tab->avlt;

	while (x != NULL) {
		if (x->uid > uid) {
			x = x->l;
		} else if (x->uid < uid) {
			x = x->r;
		} else {
			break;
		}
	}

	return (x);
}

/*
 * ****************************************************************************
 * avl_search_next:
 *	search a node from an AVL tree, the object UID of the node
 *	is next to the previous object UID.
 *
 * tab	- the hash table.
 * uid	- the previous object UID.
 * return - the next node.
 *
 * ****************************************************************************
 */
static htab_itemx_t *
avl_search_next(
	const htab_t *tab,
	const uint32_t uid
)
{
	htab_itemx_t *p = NULL;
	htab_itemx_t *x = tab->avlt;

	while (x != NULL) {
		if (x->uid > uid) {
			p = x;
			x = x->l;
		} else if (x->uid <= uid) {
			x = x->r;
		}
	}

	return (p);
}

/*
 * ****************************************************************************
 * avl_ll:
 *	perform LL balance rotation on an AVL tree (or the subtree).
 *
 * a	- the left child.
 * b	- the right child.
 * return - the new root.
 *
 * ****************************************************************************
 */
static htab_itemx_t *
avl_ll(
	htab_itemx_t *a,
	htab_itemx_t *b
)
{
	/* rotate right */
	a->l = b->r;
	a->bf = 0;
	b->r = a;
	b->bf = 0;

	return (b);
}

/*
 * ****************************************************************************
 * avl_rr:
 *	perform RR balance rotation on an AVL tree (or the subtree).
 *
 * a	- the left child.
 * b	- the right child.
 * return - the new root.
 *
 * ****************************************************************************
 */
static htab_itemx_t *
avl_rr(
	htab_itemx_t *a,
	htab_itemx_t *b
)
{
	/* rotate left */
	a->r = b->l;
	a->bf = 0;
	b->l = a;
	b->bf = 0;

	return (b);
}

/*
 * ****************************************************************************
 * avl_lr:
 *	perform LR balance rotation on an AVL tree (or the subtree).
 *
 * a	- the left child.
 * b	- the right child.
 * return - the new root.
 *
 * ****************************************************************************
 */
static htab_itemx_t *
avl_lr(
	htab_itemx_t *a,
	htab_itemx_t *b
)
{
	htab_itemx_t *c;

	c = b->r;

	/* rotate left and then right */
	a->l = c->r;
	c->r = a;
	b->r = c->l;
	c->l = b;

	/* update balance factor */
	switch (c->bf) {
	case -1:
		/* on c's right */
		a->bf = 0;
		b->bf = 1;
		break;
	case 0:
		/* on c itself */
		a->bf = 0;
		b->bf = 0;
		break;
	case 1:
		/* on c's left */
		a->bf = -1;
		b->bf = 0;
		break;
	}
	c->bf = 0;

	return (c);
}

/*
 * ****************************************************************************
 * avl_rl:
 *	perform RL balance rotation on an AVL tree (or the subtree).
 *
 * a	- the left child.
 * b	- the right child.
 * return - the new root.
 *
 * ****************************************************************************
 */
static htab_itemx_t *
avl_rl(
	htab_itemx_t *a,
	htab_itemx_t *b
)
{
	htab_itemx_t *c;

	c = b->l;

	/* rotate right and then left */
	a->r = c->l;
	c->l = a;
	b->l = c->r;
	c->r = b;

	/* update balance factor */
	switch (c->bf) {
	case -1:
		/* on c's right */
		a->bf = 1;
		b->bf = 0;
		break;
	case 0:
		/* on c itself */
		a->bf = 0;
		b->bf = 0;
		break;
	case 1:
		/* on c's left */
		a->bf = 0;
		b->bf = -1;
		break;
	}
	c->bf = 0;

	return (c);
}

/*
 * ****************************************************************************
 * avl_insert:
 *	insert a node into an AVL tree.
 *
 * tab	- the hash table.
 * x	- the node being added.
 *
 * ****************************************************************************
 */
static void
avl_insert(
	htab_t *tab,
	htab_itemx_t *x
)
{
	htab_itemx_t *f, *a, *p, *q, *b, *c;
	int d;

	/* initialize the new one */
	x->bf = 0;
	x->l = NULL;
	x->r = NULL;

	if (tab->avlt == NULL) {
		tab->avlt = x;
	} else {
		/* locate the position */
		f = NULL;
		a = tab->avlt;
		p = tab->avlt;
		q = NULL;
		while (p != NULL) {
			if (p->bf != 0) {
				a = p;
				f = q;
			}
			q = p;
			if (x->uid < q->uid) {
				p = p->l;
			} else {
				p = p->r;
			}
		}
		/* insert it */
		if (x->uid < q->uid) {
			q->l = x;
		} else {
			q->r = x;
		}
		/* update the balance factor between a to x */
		if (x->uid < a->uid) {
			p = a->l;
			d = 1;
		} else {
			p = a->r;
			d = -1;
		}
		b = p;
		while (p != x) {
			if (x->uid < p->uid) {
				p->bf = 1;
				p = p->l;
			} else {
				p->bf = -1;
				p = p->r;
			}
		}
		/* brance is not broken */
		if (a->bf == 0) {
			a->bf = d;
			goto bal_done;
		} else if (a->bf + d == 0) {
			a->bf = 0;
			goto bal_done;
		}
		/* rotate the tree */
		if (d == 1) {
			if (b->bf == 1) {
				/* LL rotate */
				c = avl_ll(a, b);
			} else if (b->bf == -1) {
				/* LR rotate */
				c = avl_lr(a, b);
			}
		} else {
			if (b->bf == -1) {
				/* RR rotate */
				c = avl_rr(a, b);
			} else if (b->bf == 1) {
				/* RL rotate */
				c = avl_rl(a, b);
			}
		}
		/* update the parent */
		if (f == NULL) {
			tab->avlt = c;
		} else if (f->l == a) {
			f->l = c;
		} else if (f->r == a) {
			f->r = c;
		}
	}

bal_done:
	if (x->uid > tab->buid) {
		tab->buid = x->uid;
	}
}

/*
 * ****************************************************************************
 * new_uid:
 *	allocate new node(s) of the avl tree.
 *
 * tab	- the hash table.
 * uid	- the UID of the node.
 * return - the newly allocated UID node.
 *
 * ****************************************************************************
 */
static htab_itemx_t *
new_uid(
	htab_t *tab,
	uint32_t uid
)
{
	htab_itemx_t *x = NULL;

	uint32_t start, end;

	/* overflow happened */
	if (uid == 0) {
		/* search for an unused one */
		uid ++;
		while (uid != 0 &&
		    avl_search(tab, uid) != NULL) {
			uid ++;
		}
		if (uid == 0) {
			/* all are used up, sigh! */
			return (NULL);
		}
	}

	/* check if there is a gap and the gap needs to be filled up */
	if (uid > tab->buid &&
	    (tab->flags & UID_FLAGS_SEQ) != 0) {
		start = tab->buid + 1;
	} else {
		start = uid;
	}
	end = uid;

	/* make new UID(s) */
	do {
		if (x != NULL) {
			x->hval = BAD_HVAL_MASK;
			x->t = 0;
			/* put it to the start of the fifo list */
			x->n = tab->list;
			tab->list = x;
			if (tab->tail == NULL) {
				tab->tail = x;
			}
		}
		x = (htab_itemx_t *)malloc(sizeof (htab_itemx_t));
		if (x != NULL) {
			x->uid = start;
			x->n = NULL;
			/* insert it to the tree */
			avl_insert(tab, x);
		}
		start ++;
	} while (x != NULL && start <= end && start != 0);

	return (x);
}

/*
 * ****************************************************************************
 * uid_insert:
 *	insert a new UID node to the avl tree.
 *
 * tab	- the hash table.
 * uid_p- the pointer of the UID.
 * hval	- the hash value of the new node.
 * return -	0: no UID value assigned;
 *		1: assigned an UID.
 *		-1: no memory.
 *		-2: invalid UID.
 *
 * ****************************************************************************
 */
static int
uid_insert(
	htab_t *tab,
	uint32_t *const uid_p,
	const uint32_t hval
)
{
	int assignx = 0;

	uint32_t uid = *uid_p;

	htab_itemx_t *x, *n;

	if (uid != 0) {
		/* search the existing one from the tree */
		x = avl_search(tab, uid);
		if (x == NULL) {
			x = new_uid(tab, uid);
		} else if (!BAD_HVAL(x->hval) &&
		    x->hval != hval) {
			/* the item with this uid will override an */
			/* existing item, we treat this as an error */
			return (-2);
		}
	} else {
		/* assign a value */
		x = tab->list;
		/* strip off the used ones */
		while (x != NULL &&
		    !BAD_HVAL(x->hval)) {
			n = x->n;
			x->n = NULL;
			x = n;
		}

		if (x == NULL ||
		    UID_REUSABLE(tab->c->timestamp(), x) == 0) {
			/* none is available, make a new one */
			tab->list = x;
			x = new_uid(tab, tab->buid + 1);
		} else {
			n = x->n;
			x->n = NULL;
			tab->list = n;
		}
		/* update the available list */
		if (tab->list == NULL) {
			tab->tail = NULL;
		}
		assignx = 1;
		if (x != NULL) {
			*uid_p = x->uid;
		}
	}

	if (x == NULL) {
		return (-1); /* no memory */
	}

	x->hval = hval;
	x->t = 0; /* registration initial time */

	return (assignx);
}

/*
 * ****************************************************************************
 * enlarge_htab:
 *	enlarge the hash table when it gets too full.
 *
 * tab	- the hash table.
 *
 * ****************************************************************************
 */
static void
enlarge_htab(
	htab_t *tab
)
{
	htab_item_t **items;
	uint16_t logsize;
	uint32_t oldsz, newsz, mask;
	htab_item_t *item, *tmp, **itemp;
	uint16_t i;
	uint32_t j;

	uint32_t uid;

	/* enlarge the logsize by one */
	logsize = tab->logsize + 1;
	newsz = (1 << logsize);
	items = (htab_item_t **)calloc(
	    newsz * tab->chunks, sizeof (htab_item_t *));
	/* re-hash all items to the new table */
	if (items != NULL) {
		mask = newsz - 1;
		oldsz = (1 << tab->logsize);
		i = 0;
		while (i < tab->chunks) {
			j = 0;
			while (j < oldsz) {
				item = tab->items[(i * oldsz) + j];
				while (item != NULL) {
					tmp = item->next;
					itemp = &items[(i * newsz) +
					    (item->hval & mask)];
					uid = tab->c->get_uid(item->p);
					while (*itemp != NULL &&
					    tab->c->get_uid((*itemp)->p) >
					    uid) {
						itemp = &(*itemp)->next;
					}
					item->next = *itemp;
					*itemp = item;
					item = tmp;
				}
				j ++;
			}
			i ++;
		}
		free(tab->items);
		tab->items = items;
		tab->logsize = logsize;
		tab->mask = mask;
	} else {
		isnslog(LOG_DEBUG, "enlarge_htab", "calloc() failed.");
	}
}

/*
 * ****************************************************************************
 * htab_init:
 *	some generic initialization for the hash table.
 *
 * ****************************************************************************
 */
void
htab_init(
)
{
	/* do nothing */
}

/*
 * ****************************************************************************
 * htab_create:
 *	create a new hash table.
 *
 * flags - UID_FLAGS_SEQ: the UID in the table needs to be sequential.
 * logsize - the hash table logsize.
 * chunks  - the number of seperated chunks of the table.
 * return  - the newly created hash table.
 *
 * ****************************************************************************
 */
htab_t *
htab_create(
	int flags,
	uint16_t logsize,
	uint16_t chunks
)
{
	htab_t *tab = NULL;
	htab_item_t **items = NULL;
	uint32_t count;

	/* do not enlarge it if the logsize reaches the maximum */
	if (logsize <= MAX_LOGSIZE &&
	    chunks > 0) {
		tab = (htab_t *)calloc(1, sizeof (htab_t));
		if (tab != NULL) {
			count = (1 << logsize);
			items = (htab_item_t **)calloc(
			    count * chunks, sizeof (htab_item_t *));
			if (items != NULL) {
				tab->flags = flags;
				tab->items = items;
				tab->logsize = logsize;
				tab->chunks = chunks;
				tab->mask = count - 1;
				tab->count = 1; /* reserve one */
				tab->avlt = NULL;
				tab->buid = 0;
				tab->list = NULL;
				tab->tail = NULL;
			} else {
				free(tab);
				tab = NULL;
			}
		}
	}

	return (tab);
}

/*
 * ****************************************************************************
 * htab_compute_hval:
 *	compute a hash value for the specified key.
 *
 * key - the key of the hash.
 * return - the hash value.
 *
 * ****************************************************************************
 */
uint32_t
htab_compute_hval(
	const uchar_t *key
)
{
	/* use classic Dan Bernstein hash alorigthm */
	uint32_t hash = 5381;
	int c;

	while ((c = *key++) != 0) {
		hash = ((hash << 5) + hash) + c;
	}

	return (hash);
}

/*
 * ****************************************************************************
 * htab_add:
 *	add an object to the hash table.
 *
 * tab	- the hash table.
 * p	- the object.
 * flag	- 0: not an association object; otherwise association object.
 * uid_p- pointer of UID for returning.
 * update_p - pointer of update flag for returning.
 * return - error code.
 *
 * ****************************************************************************
 */
int
htab_add(
	htab_t *tab,
	void *p,
	int flag,
	uint32_t *uid_p,
	int *update_p
)
{
	int ec = 0;

	htab_item_t *items = NULL, **itemp;
	uint32_t chunksz;
	uint32_t flags = 0;
	uint32_t hval;
	uint32_t uid = 0;
	int i;

	/* compute the hash value */
	hval = VALID_HVAL(tab->c->get_hval(p, 0, &flags));

	/* check for duplicate */
	items = tab->items[hval & tab->mask];
	while (items != NULL) {
		if (tab->c->cmp(items->p, p, 0) == 0) {
			if (flag == 0) {
				ec = tab->c->replace_hook(items->p, p, uid_p,
				    update_p == NULL ? 1 : 0);
			}
			if (update_p != NULL) {
				*update_p = 1;
			}
			items = NULL;
			goto add_done;
		}
		items = items->next;
	}

	/* add new object */
	if (update_p != NULL) {
		*update_p = 0;
	}

	/* make new items for the object */
	items = (htab_item_t *)calloc(tab->chunks, sizeof (htab_item_t));

	if (items == NULL ||
	    tab->count == 0 ||
	    (++tab->count) == 0) {
		/* no memory or table is full */
		ec = ISNS_RSP_INTERNAL_ERROR;
		goto add_done;
	}

	/* check if the table needs is too full */
	chunksz = (1 << tab->logsize);
	if (tab->count >= (chunksz * HASH_RATIO) &&
	    tab->logsize < MAX_LOGSIZE) {
		enlarge_htab(tab);
		chunksz = (1 << tab->logsize);
	}

	/* put the UID of the object to the avl tree */
	uid = tab->c->get_uid(p);
	switch (uid_insert(tab, &uid, hval)) {
	case -2:
		ec = ISNS_RSP_INVALID_REGIS;
		goto add_done;
	case -1:
		ec = ISNS_RSP_INTERNAL_ERROR;
		goto add_done;
	case 0:
		break;
	case 1:
		tab->c->set_uid(p, uid);
		break;
	default:
		break;
	}

	/* update data store before putting to hash table */
	if (flag == 0) {
		/* not association object */
		ec = tab->c->add_hook(p);
	}

	/* put the object to the table */
	for (i = 0; ec == 0; ) {
		items[i].hval = hval;
		items[i].p = p;
		itemp = &tab->items[(i * chunksz) + (hval & tab->mask)];
		while (*itemp != NULL &&
		    tab->c->get_uid((*itemp)->p) > uid) {
			itemp = &(*itemp)->next;
		}
		items[i].next = *itemp;
		*itemp = &items[i];
		i ++;
		if (i < tab->chunks) {
			hval = VALID_HVAL(tab->c->get_hval(p, i, &flags));
		} else {
			break;
		}
	}

	/* cache has been successfully updated */
	SET_CACHE_UPDATED();

	/* successfully added */
	items = NULL;

	if (ec == 0) {
		/* perform the Default DD behavior */
		tab->c->ddd(p, '+');

		/* set the return uid */
		if (uid_p != NULL) {
			*uid_p = uid;
		}
	}
add_done:
	if (ec != 0 && items != NULL) {
		free(items);
	}

	return (ec);
}

/*
 * ****************************************************************************
 * htab_remove:
 *	remove an object from the hash table.
 *
 * tab	- the hash table.
 * p	- the lookup control for the object.
 * uid	- the UID of the object.
 * clone_flag - indicate if the removing is for an association object.
 * return - the removed object.
 *
 * ****************************************************************************
 */
isns_obj_t *
htab_remove(
	htab_t *tab,
	void *p,
	uint32_t uid,
	int clone_flag
)
{
	void *zhizi = NULL;
	void *clone = NULL;
	htab_item_t *items = NULL;
	htab_item_t *item, **itemp;
	htab_itemx_t *x = NULL;
	uint32_t chunksz;
	uint32_t flags;
	uint32_t hval;
	int i;

	/* get the object hash value */
	if (uid != 0) {
		x = avl_search(tab, uid);
		if (x != NULL && !BAD_HVAL(x->hval)) {
			hval = x->hval;
		} else {
			goto remove_done;
		}
	} else {
		flags = 0 | FLAGS_CTRL_MASK;
		hval = VALID_HVAL(tab->c->get_hval(p, 0, &flags));
	}

	/* search the object from the table */
	flags = 0;
	chunksz = (1 << tab->logsize);
	for (i = 0; ; ) {
		itemp = &tab->items[(i * chunksz) + (hval & tab->mask)];
		item = *itemp;
		while (item != NULL) {
			/* found it */
			if (tab->c->cmp(item->p, p, 1) == 0) {
				/* make an association object if the object */
				/* has membership in user-defined DD(s). */
				if (i == 0) {
					if ((clone = tab->c->clone(item->p,
					    clone_flag)) == NULL) {
						tab->c->ddd(item->p, '-');
						tab->count --;
						items = item;
						zhizi = item->p;
					}
				}
				if (clone == NULL) {
					/* remove it */
					*itemp = item->next;
				} else if (clone == item->p) {
					/* itself is an association object */
					goto remove_done;
				} else {
					/* replace it with association */
					zhizi = item->p;
					item->p = clone;
				}
				if (i == 0) {
					/* obj has been removed or updated */
					SET_CACHE_UPDATED();
				}
				break;
			}
			itemp = &item->next;
			item = *itemp;
		}
		i ++;
		if (zhizi != NULL && i < tab->chunks) {
			hval = VALID_HVAL(tab->c->get_hval(
			    zhizi, i, &flags));
		} else {
			break;
		}
	}

	/* update the node in the avl tree */
	if (items != NULL) {
		if (x == NULL) {
			uid = tab->c->get_uid(zhizi);
			ASSERT(uid != 0);
			x = avl_search(tab, uid);
		}
		ASSERT(x != NULL && !BAD_HVAL(x->hval));
		/* mark the uid item as invalid */
		x->hval |= BAD_HVAL_MASK;
		/* update the timestamp */
		x->t = tab->c->timestamp();
		/* put it to the end of fifo list */
		if (tab->list != NULL) {
			tab->tail->n = x;
		} else {
			tab->list = x;
		}
		tab->tail = x;
	}

remove_done:
	if (items != NULL) {
		free(items);
	}

	return (zhizi);
}

/*
 * ****************************************************************************
 * htab_lookup:
 *	lookup an object from the hash table.
 *
 * tab	- the hash table.
 * p	- the lookup control for the item.
 * uid	- the UID of the object.
 * uid_p- the pointer of UID for returning.
 * callback - callback function if the object is found.
 * rekey - flag that indicates if the callback function will update
 *		the key of the object.
 * return - error code.
 *
 * ****************************************************************************
 */
int
htab_lookup(
	htab_t *tab,
	void *p,
	uint32_t uid,
	uint32_t *uid_p,
	int (*callback)(void *, void *),
	int rekey
)
{
	uint32_t ret = 0;
	void *zhizi = NULL;
	htab_item_t *item, **itemp;
	htab_itemx_t *x = NULL;
	uint32_t chunksz;
	uint32_t flags = 0 | FLAGS_CTRL_MASK;
	uint32_t hval;
	int i;

	/* compute the hash value */
	if (uid != 0) {
		x = avl_search(tab, uid);
		if (x != NULL) {
			hval = x->hval;
		} else {
			hval = BAD_HVAL_MASK;
		}
	} else {
		hval = VALID_HVAL(tab->c->get_hval(p, 0, &flags));
	}

	/* find the object */
	if (!BAD_HVAL(hval)) {
		i = flags & FLAGS_CHUNK_MASK;
		chunksz = (1 << tab->logsize);
		itemp = &tab->items[(i * chunksz) + (hval & tab->mask)];
		item = *itemp;
		while (item != NULL) {
			if (tab->c->cmp(item->p, p, 1) == 0) {
				zhizi = item->p;
				break;
			}
			itemp = &item->next;
			item = *itemp;
		}
	}

	/* found it */
	if (zhizi != NULL) {
		/* set the return uid */
		if (uid_p != NULL) {
			*uid_p = tab->c->get_uid(zhizi);
		}
		/* invoke callback */
		if (callback != NULL) {
			ret = callback(zhizi, p);
		}
		if (rekey != 0 && ret == 0) {
			/* Rekey works for one-chunk hash table only. */
			ASSERT(tab->chunks == 1 && x != NULL);
			/* remove from previous slot */
			*itemp = item->next;
			/* add it to the new slot */
			flags = 0;
			hval = VALID_HVAL(tab->c->get_hval(zhizi, 0, &flags));
			x->hval = hval;
			item->hval = hval;
			itemp = &tab->items[(hval & tab->mask)];
			while (*itemp != NULL &&
			    (tab->c->get_uid((*itemp)->p) >
			    tab->c->get_uid(zhizi))) {
				itemp = &(*itemp)->next;
			}
			item->next = *itemp;
			*itemp = item;
		}
	} else if (uid_p != NULL) {
		/* set the return uid to 0 */
		*uid_p = 0;
	}

	return (ret);
}

/*
 * ****************************************************************************
 * htab_get_next:
 *	get the next object UID from the hash table.
 *
 * tab	- the hash table.
 * uid	- the previous objet UID.
 * return - the next object UID.
 *
 * ****************************************************************************
 */
uint32_t
htab_get_next(
	htab_t *tab,
	uint32_t uid
)
{
	htab_itemx_t *x;

	do {
		/* search the next node from the avl tree */
		x = avl_search_next(tab, uid);
		if (x != NULL) {
			uid = x->uid;
			/* validate the node */
			if (!BAD_HVAL(x->hval)) {
				return (uid);
			}
		}
	} while (x != NULL);

	/* no more node is available */
	return (0);
}

/*
 * ****************************************************************************
 * htab_dump:
 *	dump all objects stored in the hash table for debug purpose.
 *
 * tab	- the hash table.
 *
 * ****************************************************************************
 */
#ifdef DEBUG
void
htab_dump(
	htab_t *tab
)
{
	uint32_t chunksz;
	htab_item_t *items;

	uint32_t i;

	chunksz = (1 << tab->logsize);

	for (i = 0; i < chunksz; i++) {
		items = tab->items[i];
		while (items != NULL) {
			tab->c->dump(items->p);
			items = items->next;
		}
	}
}
#endif
