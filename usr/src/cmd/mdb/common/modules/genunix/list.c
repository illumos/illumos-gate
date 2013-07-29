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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <sys/list.h>

typedef struct list_walk_data {
	uintptr_t lw_head;	/* address of list head */
	size_t	lw_size;	/* size of list element */
	size_t	lw_offset;	/* list element linkage offset */
	void	*lw_obj;	/* buffer of lw_size to hold list element */
	uintptr_t lw_end;	/* last node in specified range */
	const char *lw_elem_name;
	int	(*lw_elem_check)(void *, uintptr_t, void *);
	void	*lw_elem_check_arg;
} list_walk_data_t;

/*
 * Initialize a forward walk through a list.
 *
 * begin and end optionally specify objects other than the first and last
 * objects in the list; either or both may be NULL (defaulting to first and
 * last).
 *
 * list_name and element_name specify command-specific labels other than
 * "list_t" and "list element" for use in error messages.
 *
 * element_check() returns -1, 1, or 0: abort the walk with an error, stop
 * without an error, or allow the normal callback; arg is an optional user
 * argument to element_check().
 */
int
list_walk_init_range(mdb_walk_state_t *wsp, uintptr_t begin, uintptr_t end,
    const char *list_name, const char *element_name,
    int (*element_check)(void *, uintptr_t, void *), void *arg)
{
	list_walk_data_t *lwd;
	list_t list;

	if (list_name == NULL)
		list_name = "list_t";
	if (element_name == NULL)
		element_name = "list element";

	if (mdb_vread(&list, sizeof (list_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read %s at %#lx", list_name,
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (list.list_size < list.list_offset + sizeof (list_node_t)) {
		mdb_warn("invalid or uninitialized %s at %#lx\n", list_name,
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	lwd = mdb_alloc(sizeof (list_walk_data_t), UM_SLEEP);

	lwd->lw_size = list.list_size;
	lwd->lw_offset = list.list_offset;
	lwd->lw_obj = mdb_alloc(list.list_size, UM_SLEEP);
	lwd->lw_head = (uintptr_t)&((list_t *)wsp->walk_addr)->list_head;
	lwd->lw_end = (end == NULL ? NULL : end + lwd->lw_offset);
	lwd->lw_elem_name = element_name;
	lwd->lw_elem_check = element_check;
	lwd->lw_elem_check_arg = arg;

	wsp->walk_addr = (begin == NULL
	    ? (uintptr_t)list.list_head.list_next
	    : begin + lwd->lw_offset);
	wsp->walk_data = lwd;

	return (WALK_NEXT);
}

int
list_walk_init(mdb_walk_state_t *wsp)
{
	return (list_walk_init_range(wsp, NULL, NULL, NULL, NULL, NULL, NULL));
}

int
list_walk_init_named(mdb_walk_state_t *wsp,
    const char *list_name, const char *element_name)
{
	return (list_walk_init_range(wsp, NULL, NULL, list_name, element_name,
	    NULL, NULL));
}

int
list_walk_init_checked(mdb_walk_state_t *wsp,
    const char *list_name, const char *element_name,
    int (*element_check)(void *, uintptr_t, void *), void *arg)
{
	return (list_walk_init_range(wsp, NULL, NULL, list_name, element_name,
	    element_check, arg));
}

int
list_walk_step(mdb_walk_state_t *wsp)
{
	list_walk_data_t *lwd = wsp->walk_data;
	uintptr_t addr = wsp->walk_addr - lwd->lw_offset;
	list_node_t *node;
	int status;

	if (wsp->walk_addr == lwd->lw_head)
		return (WALK_DONE);

	if (lwd->lw_end != NULL && wsp->walk_addr == lwd->lw_end)
		return (WALK_DONE);

	if (mdb_vread(lwd->lw_obj, lwd->lw_size, addr) == -1) {
		mdb_warn("failed to read %s at %#lx", lwd->lw_elem_name, addr);
		return (WALK_ERR);
	}

	if (lwd->lw_elem_check != NULL) {
		int rc = lwd->lw_elem_check(lwd->lw_obj, addr,
		    lwd->lw_elem_check_arg);
		if (rc == -1)
			return (WALK_ERR);
		else if (rc == 1)
			return (WALK_DONE);
	}

	status = wsp->walk_callback(addr, lwd->lw_obj, wsp->walk_cbdata);
	node = (list_node_t *)((uintptr_t)lwd->lw_obj + lwd->lw_offset);
	wsp->walk_addr = (uintptr_t)node->list_next;

	return (status);
}

void
list_walk_fini(mdb_walk_state_t *wsp)
{
	list_walk_data_t *lwd = wsp->walk_data;

	mdb_free(lwd->lw_obj, lwd->lw_size);
	mdb_free(lwd, sizeof (list_walk_data_t));
}
