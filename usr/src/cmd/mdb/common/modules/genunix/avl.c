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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <sys/avl.h>

#include <mdb/mdb_modapi.h>

struct aw_info {
	void *aw_buff;		/* buffer to hold tree element */
	avl_tree_t aw_tree;	/* copy of avl_tree_t being walked */
	uintptr_t aw_end;	/* last node in specified range */
	const char *aw_elem_name;
	int (*aw_elem_check)(void *, uintptr_t, void *);
	void *aw_elem_check_arg;
};

/*
 * common code used to find the addr of the the leftmost child below
 * an AVL node
 */
static uintptr_t
avl_leftmostchild(uintptr_t addr, void *buff, size_t offset, size_t size,
    const char *elem_name)
{
	avl_node_t *node = (avl_node_t *)((uintptr_t)buff + offset);

	for (;;) {
		addr -= offset;
		if (mdb_vread(buff, size, addr) == -1) {
			mdb_warn("failed to read %s at %#lx", elem_name, addr);
			return ((uintptr_t)-1L);
		}
		if (node->avl_child[0] == NULL)
			break;
		addr = (uintptr_t)node->avl_child[0];
	}
	return (addr);
}

/*
 * initialize a forward walk thru an avl tree.
 *
 * begin and end optionally specify objects other than the first and last
 * objects in the tree; either or both may be NULL (defaulting to first and
 * last).
 *
 * avl_name and element_name specify command-specific labels other than
 * "avl_tree_t" and "tree element" for use in error messages.
 *
 * element_check() returns -1, 1, or 0: abort the walk with an error, stop
 * without an error, or allow the normal callback; arg is an optional user
 * argument to element_check().
 */
int
avl_walk_init_range(mdb_walk_state_t *wsp, uintptr_t begin, uintptr_t end,
    const char *avl_name, const char *element_name,
    int (*element_check)(void *, uintptr_t, void *), void *arg)
{
	struct aw_info *aw;
	avl_tree_t *tree;
	uintptr_t addr;

	if (avl_name == NULL)
		avl_name = "avl_tree_t";
	if (element_name == NULL)
		element_name = "tree element";

	/*
	 * allocate the AVL walk data
	 */
	wsp->walk_data = aw = mdb_zalloc(sizeof (struct aw_info), UM_SLEEP);

	/*
	 * get an mdb copy of the avl_tree_t being walked
	 */
	tree = &aw->aw_tree;
	if (mdb_vread(tree, sizeof (avl_tree_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read %s at %#lx", avl_name, wsp->walk_addr);
		goto error;
	}
	if (tree->avl_size < tree->avl_offset + sizeof (avl_node_t)) {
		mdb_warn("invalid avl_tree_t at %p, avl_size:%d, avl_offset:%d",
		    wsp->walk_addr, tree->avl_size, tree->avl_offset);
		goto error;
	}

	/*
	 * allocate a buffer to hold the mdb copy of tree's structs
	 * "node" always points at the avl_node_t field inside the struct
	 */
	aw->aw_buff = mdb_zalloc(tree->avl_size, UM_SLEEP);
	aw->aw_end = (end == NULL ? NULL : end + tree->avl_offset);
	aw->aw_elem_name = element_name;
	aw->aw_elem_check = element_check;
	aw->aw_elem_check_arg = arg;

	/*
	 * get the first avl_node_t address, use same algorithm
	 * as avl_start() -- leftmost child in tree from root
	 */
	if (begin == NULL) {
		addr = (uintptr_t)tree->avl_root;
		if (addr == NULL) {
			wsp->walk_addr = NULL;
			return (WALK_NEXT);
		}
		addr = avl_leftmostchild(addr, aw->aw_buff, tree->avl_offset,
		    tree->avl_size, aw->aw_elem_name);
		if (addr == (uintptr_t)-1L)
			goto error;
		wsp->walk_addr = addr;
	} else {
		wsp->walk_addr = begin + tree->avl_offset;
	}

	return (WALK_NEXT);

error:
	if (aw->aw_buff != NULL)
		mdb_free(aw->aw_buff, sizeof (tree->avl_size));
	mdb_free(aw, sizeof (struct aw_info));
	return (WALK_ERR);
}

int
avl_walk_init(mdb_walk_state_t *wsp)
{
	return (avl_walk_init_range(wsp, NULL, NULL, NULL, NULL, NULL, NULL));
}

int
avl_walk_init_named(mdb_walk_state_t *wsp,
    const char *avl_name, const char *element_name)
{
	return (avl_walk_init_range(wsp, NULL, NULL, avl_name, element_name,
	    NULL, NULL));
}

int
avl_walk_init_checked(mdb_walk_state_t *wsp,
    const char *avl_name, const char *element_name,
    int (*element_check)(void *, uintptr_t, void *), void *arg)
{
	return (avl_walk_init_range(wsp, NULL, NULL, avl_name, element_name,
	    element_check, arg));
}

/*
 * At each step, visit (callback) the current node, then move to the next
 * in the AVL tree.  Uses the same algorithm as avl_walk().
 */
int
avl_walk_step(mdb_walk_state_t *wsp)
{
	struct aw_info *aw;
	size_t offset;
	size_t size;
	uintptr_t addr;
	avl_node_t *node;
	int status;
	int was_child;

	/*
	 * don't walk past the end of the tree!
	 */
	addr = wsp->walk_addr;
	if (addr == NULL)
		return (WALK_DONE);

	aw = (struct aw_info *)wsp->walk_data;

	if (aw->aw_end != NULL && wsp->walk_addr == aw->aw_end)
		return (WALK_DONE);

	size = aw->aw_tree.avl_size;
	offset = aw->aw_tree.avl_offset;
	node = (avl_node_t *)((uintptr_t)aw->aw_buff + offset);

	/*
	 * must read the current node for the call back to use
	 */
	if (mdb_vread(aw->aw_buff, size, addr) == -1) {
		mdb_warn("failed to read %s at %#lx", aw->aw_elem_name, addr);
		return (WALK_ERR);
	}

	if (aw->aw_elem_check != NULL) {
		int rc = aw->aw_elem_check(aw->aw_buff, addr,
		    aw->aw_elem_check_arg);
		if (rc == -1)
			return (WALK_ERR);
		else if (rc == 1)
			return (WALK_DONE);
	}

	/*
	 * do the call back
	 */
	status = wsp->walk_callback(addr, aw->aw_buff, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	/*
	 * move to the next node....
	 * note we read in new nodes, so the pointer to the buffer is fixed
	 */

	/*
	 * if the node has a right child then go to it and then all the way
	 * thru as many left children as possible
	 */
	addr = (uintptr_t)node->avl_child[1];
	if (addr != NULL) {
		addr = avl_leftmostchild(addr, aw->aw_buff, offset, size,
		    aw->aw_elem_name);
		if (addr == (uintptr_t)-1L)
			return (WALK_ERR);

	/*
	 * othewise return to parent nodes, stopping if we ever return from
	 * a left child
	 */
	} else {
		for (;;) {
			was_child = AVL_XCHILD(node);
			addr = (uintptr_t)AVL_XPARENT(node);
			if (addr == NULL)
				break;
			addr -= offset;
			if (was_child == 0) /* stop on return from left child */
				break;
			if (mdb_vread(aw->aw_buff, size, addr) == -1) {
				mdb_warn("failed to read %s at %#lx",
				    aw->aw_elem_name, addr);
				return (WALK_ERR);
			}
		}
	}

	wsp->walk_addr = addr;
	return (WALK_NEXT);
}

/*
 * Release the memory allocated for the walk
 */
void
avl_walk_fini(mdb_walk_state_t *wsp)
{
	struct aw_info *aw;

	aw = (struct aw_info *)wsp->walk_data;

	if (aw == NULL)
		return;

	if (aw->aw_buff != NULL)
		mdb_free(aw->aw_buff, aw->aw_tree.avl_size);

	mdb_free(aw, sizeof (struct aw_info));
}

/*
 * This function is named avl_walk_mdb to avoid a naming conflict with the
 * existing avl_walk function.
 */
int
avl_walk_mdb(uintptr_t addr, mdb_walk_cb_t callback, void *cbdata)
{
	mdb_walk_state_t ws;
	int ret;

	ws.walk_addr = addr;
	ws.walk_callback = callback;
	ws.walk_cbdata = cbdata;

	avl_walk_init(&ws);
	while ((ret = avl_walk_step(&ws)) == WALK_NEXT)
		continue;
	avl_walk_fini(&ws);

	return (ret);
}
