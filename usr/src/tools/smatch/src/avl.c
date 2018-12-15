/*
 * Copyright (C) 2010 Joseph Adams <joeyadams3.14159@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <assert.h>
#include <stdlib.h>

#include "smatch.h"
#include "smatch_slist.h"

static AvlNode *mkNode(const struct sm_state *sm);
static void freeNode(AvlNode *node);

static AvlNode *lookup(const struct stree *avl, AvlNode *node, const struct sm_state *sm);

static bool insert_sm(struct stree *avl, AvlNode **p, const struct sm_state *sm);
static bool remove_sm(struct stree *avl, AvlNode **p, const struct sm_state *sm, AvlNode **ret);
static bool removeExtremum(AvlNode **p, int side, AvlNode **ret);

static int sway(AvlNode **p, int sway);
static void balance(AvlNode **p, int side);

static bool checkBalances(AvlNode *node, int *height);
static bool checkOrder(struct stree *avl);
static size_t countNode(AvlNode *node);

int unfree_stree;

/*
 * Utility macros for converting between
 * "balance" values (-1 or 1) and "side" values (0 or 1).
 *
 * bal(0)   == -1
 * bal(1)   == +1
 * side(-1) == 0
 * side(+1) == 1
 */
#define bal(side) ((side) == 0 ? -1 : 1)
#define side(bal) ((bal)  == 1 ?  1 : 0)

static struct stree *avl_new(void)
{
	struct stree *avl = malloc(sizeof(*avl));

	unfree_stree++;
	assert(avl != NULL);

	avl->root = NULL;
	avl->base_stree = NULL;
	avl->has_states = calloc(num_checks + 1, sizeof(char));
	avl->count = 0;
	avl->stree_id = 0;
	avl->references = 1;
	return avl;
}

void free_stree(struct stree **avl)
{
	if (!*avl)
		return;

	assert((*avl)->references > 0);

	(*avl)->references--;
	if ((*avl)->references != 0) {
		*avl = NULL;
		return;
	}

	unfree_stree--;

	freeNode((*avl)->root);
	free(*avl);
	*avl = NULL;
}

struct sm_state *avl_lookup(const struct stree *avl, const struct sm_state *sm)
{
	AvlNode *found;

	if (!avl)
		return NULL;
	if (sm->owner != USHRT_MAX &&
	    !avl->has_states[sm->owner])
		return NULL;
	found = lookup(avl, avl->root, sm);
	if (!found)
		return NULL;
	return (struct sm_state *)found->sm;
}

AvlNode *avl_lookup_node(const struct stree *avl, const struct sm_state *sm)
{
	return lookup(avl, avl->root, sm);
}

size_t stree_count(const struct stree *avl)
{
	if (!avl)
		return 0;
	return avl->count;
}

static struct stree *clone_stree_real(struct stree *orig)
{
	struct stree *new = avl_new();
	AvlIter i;

	avl_foreach(i, orig)
		avl_insert(&new, i.sm);

	new->base_stree = orig->base_stree;
	return new;
}

bool avl_insert(struct stree **avl, const struct sm_state *sm)
{
	size_t old_count;

	if (!*avl)
		*avl = avl_new();
	if ((*avl)->references > 1) {
		(*avl)->references--;
		*avl = clone_stree_real(*avl);
	}
	old_count = (*avl)->count;
	/* fortunately we never call get_state() on "unnull_path" */
	if (sm->owner != USHRT_MAX)
		(*avl)->has_states[sm->owner] = 1;
	insert_sm(*avl, &(*avl)->root, sm);
	return (*avl)->count != old_count;
}

bool avl_remove(struct stree **avl, const struct sm_state *sm)
{
	AvlNode *node = NULL;

	if (!*avl)
		return false;
	/* it's fairly rare for smatch to call avl_remove */
	if ((*avl)->references > 1) {
		(*avl)->references--;
		*avl = clone_stree_real(*avl);
	}

	remove_sm(*avl, &(*avl)->root, sm, &node);

	if ((*avl)->count == 0)
		free_stree(avl);

	if (node == NULL) {
		return false;
	} else {
		free(node);
		return true;
	}
}

static AvlNode *mkNode(const struct sm_state *sm)
{
	AvlNode *node = malloc(sizeof(*node));

	assert(node != NULL);

	node->sm = sm;
	node->lr[0] = NULL;
	node->lr[1] = NULL;
	node->balance = 0;
	return node;
}

static void freeNode(AvlNode *node)
{
	if (node) {
		freeNode(node->lr[0]);
		freeNode(node->lr[1]);
		free(node);
	}
}

static AvlNode *lookup(const struct stree *avl, AvlNode *node, const struct sm_state *sm)
{
	int cmp;

	if (node == NULL)
		return NULL;

	cmp = cmp_tracker(sm, node->sm);

	if (cmp < 0)
		return lookup(avl, node->lr[0], sm);
	if (cmp > 0)
		return lookup(avl, node->lr[1], sm);
	return node;
}

/*
 * Insert an sm into a subtree, rebalancing if necessary.
 *
 * Return true if the subtree's height increased.
 */
static bool insert_sm(struct stree *avl, AvlNode **p, const struct sm_state *sm)
{
	if (*p == NULL) {
		*p = mkNode(sm);
		avl->count++;
		return true;
	} else {
		AvlNode *node = *p;
		int      cmp  = cmp_tracker(sm, node->sm);

		if (cmp == 0) {
			node->sm = sm;
			return false;
		}

		if (!insert_sm(avl, &node->lr[side(cmp)], sm))
			return false;

		/* If tree's balance became -1 or 1, it means the tree's height grew due to insertion. */
		return sway(p, cmp) != 0;
	}
}

/*
 * Remove the node matching the given sm.
 * If present, return the removed node through *ret .
 * The returned node's lr and balance are meaningless.
 *
 * Return true if the subtree's height decreased.
 */
static bool remove_sm(struct stree *avl, AvlNode **p, const struct sm_state *sm, AvlNode **ret)
{
	if (p == NULL || *p == NULL) {
		return false;
	} else {
		AvlNode *node = *p;
		int      cmp  = cmp_tracker(sm, node->sm);

		if (cmp == 0) {
			*ret = node;
			avl->count--;

			if (node->lr[0] != NULL && node->lr[1] != NULL) {
				AvlNode *replacement;
				int      side;
				bool     shrunk;

				/* Pick a subtree to pull the replacement from such that
				 * this node doesn't have to be rebalanced. */
				side = node->balance <= 0 ? 0 : 1;

				shrunk = removeExtremum(&node->lr[side], 1 - side, &replacement);

				replacement->lr[0]   = node->lr[0];
				replacement->lr[1]   = node->lr[1];
				replacement->balance = node->balance;
				*p = replacement;

				if (!shrunk)
					return false;

				replacement->balance -= bal(side);

				/* If tree's balance became 0, it means the tree's height shrank due to removal. */
				return replacement->balance == 0;
			}

			if (node->lr[0] != NULL)
				*p = node->lr[0];
			else
				*p = node->lr[1];

			return true;

		} else {
			if (!remove_sm(avl, &node->lr[side(cmp)], sm, ret))
				return false;

			/* If tree's balance became 0, it means the tree's height shrank due to removal. */
			return sway(p, -cmp) == 0;
		}
	}
}

/*
 * Remove either the left-most (if side == 0) or right-most (if side == 1)
 * node in a subtree, returning the removed node through *ret .
 * The returned node's lr and balance are meaningless.
 *
 * The subtree must not be empty (i.e. *p must not be NULL).
 *
 * Return true if the subtree's height decreased.
 */
static bool removeExtremum(AvlNode **p, int side, AvlNode **ret)
{
	AvlNode *node = *p;

	if (node->lr[side] == NULL) {
		*ret = node;
		*p = node->lr[1 - side];
		return true;
	}

	if (!removeExtremum(&node->lr[side], side, ret))
		return false;

	/* If tree's balance became 0, it means the tree's height shrank due to removal. */
	return sway(p, -bal(side)) == 0;
}

/*
 * Rebalance a node if necessary.  Think of this function
 * as a higher-level interface to balance().
 *
 * sway must be either -1 or 1, and indicates what was added to
 * the balance of this node by a prior operation.
 *
 * Return the new balance of the subtree.
 */
static int sway(AvlNode **p, int sway)
{
	if ((*p)->balance != sway)
		(*p)->balance += sway;
	else
		balance(p, side(sway));

	return (*p)->balance;
}

/*
 * Perform tree rotations on an unbalanced node.
 *
 * side == 0 means the node's balance is -2 .
 * side == 1 means the node's balance is +2 .
 */
static void balance(AvlNode **p, int side)
{
	AvlNode  *node  = *p,
	         *child = node->lr[side];
	int opposite    = 1 - side;
	int bal         = bal(side);

	if (child->balance != -bal) {
		/* Left-left (side == 0) or right-right (side == 1) */
		node->lr[side]      = child->lr[opposite];
		child->lr[opposite] = node;
		*p = child;

		child->balance -= bal;
		node->balance = -child->balance;

	} else {
		/* Left-right (side == 0) or right-left (side == 1) */
		AvlNode *grandchild = child->lr[opposite];

		node->lr[side]           = grandchild->lr[opposite];
		child->lr[opposite]      = grandchild->lr[side];
		grandchild->lr[side]     = child;
		grandchild->lr[opposite] = node;
		*p = grandchild;

		node->balance       = 0;
		child->balance      = 0;

		if (grandchild->balance == bal)
			node->balance  = -bal;
		else if (grandchild->balance == -bal)
			child->balance = bal;

		grandchild->balance = 0;
	}
}


/************************* avl_check_invariants() *************************/

bool avl_check_invariants(struct stree *avl)
{
	int    dummy;

	return checkBalances(avl->root, &dummy)
	    && checkOrder(avl)
	    && countNode(avl->root) == avl->count;
}

static bool checkBalances(AvlNode *node, int *height)
{
	if (node) {
		int h0, h1;

		if (!checkBalances(node->lr[0], &h0))
			return false;
		if (!checkBalances(node->lr[1], &h1))
			return false;

		if (node->balance != h1 - h0 || node->balance < -1 || node->balance > 1)
			return false;

		*height = (h0 > h1 ? h0 : h1) + 1;
		return true;
	} else {
		*height = 0;
		return true;
	}
}

static bool checkOrder(struct stree *avl)
{
	AvlIter     i;
	const struct sm_state *last = NULL;
	bool        last_set = false;

	avl_foreach(i, avl) {
		if (last_set && cmp_tracker(last, i.sm) >= 0)
			return false;
		last     = i.sm;
		last_set = true;
	}

	return true;
}

static size_t countNode(AvlNode *node)
{
	if (node)
		return 1 + countNode(node->lr[0]) + countNode(node->lr[1]);
	else
		return 0;
}


/************************* Traversal *************************/

void avl_iter_begin(AvlIter *iter, struct stree *avl, AvlDirection dir)
{
	AvlNode *node;

	iter->stack_index = 0;
	iter->direction   = dir;

	if (!avl || !avl->root) {
		iter->sm      = NULL;
		iter->node     = NULL;
		return;
	}
	node = avl->root;

	while (node->lr[dir] != NULL) {
		iter->stack[iter->stack_index++] = node;
		node = node->lr[dir];
	}

	iter->sm   = (struct sm_state *) node->sm;
	iter->node  = node;
}

void avl_iter_next(AvlIter *iter)
{
	AvlNode     *node = iter->node;
	AvlDirection dir  = iter->direction;

	if (node == NULL)
		return;

	node = node->lr[1 - dir];
	if (node != NULL) {
		while (node->lr[dir] != NULL) {
			iter->stack[iter->stack_index++] = node;
			node = node->lr[dir];
		}
	} else if (iter->stack_index > 0) {
		node = iter->stack[--iter->stack_index];
	} else {
		iter->sm      = NULL;
		iter->node     = NULL;
		return;
	}

	iter->node  = node;
	iter->sm   = (struct sm_state *) node->sm;
}

struct stree *clone_stree(struct stree *orig)
{
	if (!orig)
		return NULL;

	orig->references++;
	return orig;
}

void set_stree_id(struct stree **stree, int stree_id)
{
	if ((*stree)->stree_id != 0)
		*stree = clone_stree_real(*stree);

	(*stree)->stree_id = stree_id;
}

int get_stree_id(struct stree *stree)
{
	if (!stree)
		return -1;
	return stree->stree_id;
}
