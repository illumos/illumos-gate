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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "dis_target.h"
#include "dis_list.h"
#include "dis_util.h"

/*
 * List support functions.
 *
 * Support routines for managing lists of sections and functions.  We first
 * process the command line arguments into lists of strings.  For each target,
 * we resolve these strings against the set of available sections and/or
 * functions to arrive at the set of objects to disassemble.
 *
 * We export two types of lists, namelists and resolvelists.  The first is used
 * to record names given as command line options.  The latter is used to
 * maintain the data objects specific to a given target.
 */

typedef struct unresolved_name {
	const char	*un_name;	/* name of function or object */
	int		un_value;	/* user-supplied data */
	int		un_mark;	/* internal counter */
	uu_list_node_t	un_node;	/* uulist node */
} unresolved_name_t;

typedef struct resolved_name {
	void		*rn_data;	/* section or function data */
	int		rn_value;	/* user-supplied data */
	uu_list_node_t	rn_node;	/* uulist node */
} resolved_name_t;

static uu_list_pool_t *unresolved_pool;
static uu_list_pool_t *resolved_pool;
static int current_mark = 0;

static void
initialize_pools(void)
{
	unresolved_pool = uu_list_pool_create(
	    "unresolved_pool", sizeof (unresolved_name_t),
	    offsetof(unresolved_name_t, un_node), NULL, 0);
	resolved_pool = uu_list_pool_create(
	    "resolved_pool", sizeof (resolved_name_t),
	    offsetof(resolved_name_t, rn_node), NULL, 0);

	if (unresolved_pool == NULL ||
	    resolved_pool == NULL)
		die("out of memory");
}

/*
 * Returns an empty list of unresolved names.
 */
dis_namelist_t *
dis_namelist_create(void)
{
	uu_list_t *listp;

	/*
	 * If this is the first request to create a list, initialize the list
	 * pools.
	 */
	if (unresolved_pool == NULL)
		initialize_pools();

	if ((listp = uu_list_create(unresolved_pool, NULL, 0)) == NULL)
		die("out of memory");

	return (listp);
}

/*
 * Adds the given name to the unresolved list.  'value' is an arbitrary value
 * which is preserved for this entry, even when resolved against a target.  This
 * allows the caller to associate similar behavior (such as the difference
 * between -d, -D, and -s) without having to create multiple lists.
 */
void
dis_namelist_add(dis_namelist_t *list, const char *name, int value)
{
	unresolved_name_t *node;

	node = safe_malloc(sizeof (unresolved_name_t));

	node->un_name = name;
	node->un_value = value;
	node->un_mark = 0;

	(void) uu_list_insert_before(list, NULL, node);
}

/*
 * Internal callback structure used
 */
typedef struct cb_data {
	int		cb_mark;
	uu_list_t	*cb_source;
	uu_list_t	*cb_resolved;
} cb_data_t;

/*
 * For each section, walk the list of unresolved names and resolve those that
 * correspond to real functions.  We mark functions as we see them, and re-walk
 * the list a second time to warn about functions we didn't find.
 *
 * This is an O(n * m) algorithm, but we typically search for only a single
 * function.
 */
/* ARGSUSED */
static void
walk_sections(dis_tgt_t *tgt, dis_scn_t *scn, void *data)
{
	cb_data_t *cb = data;
	unresolved_name_t *unp;
	uu_list_walk_t *walk;

	if ((walk = uu_list_walk_start(cb->cb_source, UU_DEFAULT)) == NULL)
		die("out of memory");

	while ((unp = uu_list_walk_next(walk)) != NULL) {
		if (strcmp(unp->un_name, dis_section_name(scn)) == 0) {
			resolved_name_t *resolved;

			/*
			 * Mark the current node as seen
			 */
			unp->un_mark = cb->cb_mark;

			/*
			 * Add the data to the resolved list
			 */
			resolved = safe_malloc(sizeof (resolved_name_t));

			resolved->rn_data = dis_section_copy(scn);
			resolved->rn_value = unp->un_value;

			(void) uu_list_insert_before(cb->cb_resolved, NULL,
			    resolved);
		}
	}

	uu_list_walk_end(walk);
}

/*
 * Take a list of unresolved names and create a resolved list of sections.  We
 * rely on walk_sections() to do the dirty work.  After resolving the sections,
 * we check for any unmarked names and warn the user about missing sections.
 */
dis_scnlist_t *
dis_namelist_resolve_sections(dis_namelist_t *namelist, dis_tgt_t *tgt)
{
	uu_list_t *listp;
	cb_data_t cb;
	unresolved_name_t *unp;
	uu_list_walk_t *walk;

	/*
	 * Walk all sections in the target, calling walk_sections() for each
	 * one.
	 */
	if ((listp = uu_list_create(resolved_pool, NULL, UU_DEFAULT)) == NULL)
		die("out of memory");

	cb.cb_mark = ++current_mark;
	cb.cb_source = namelist;
	cb.cb_resolved = listp;

	dis_tgt_section_iter(tgt, walk_sections, &cb);

	/*
	 * Walk all elements of the unresolved list, and report any that we
	 * didn't mark in the process.
	 */
	if ((walk = uu_list_walk_start(namelist, UU_DEFAULT)) == NULL)
		die("out of memory");

	while ((unp = uu_list_walk_next(walk)) != NULL) {
		if (unp->un_mark != current_mark)
			warn("failed to find section '%s' in '%s'",
			    unp->un_name, dis_tgt_name(tgt));
	}

	uu_list_walk_end(walk);

	return (listp);
}

/*
 * Similar to walk_sections(), but for functions.
 */
/* ARGSUSED */
static void
walk_functions(dis_tgt_t *tgt, dis_func_t *func, void *data)
{
	cb_data_t *cb = data;
	unresolved_name_t *unp;
	uu_list_walk_t *walk;

	if ((walk = uu_list_walk_start(cb->cb_source, UU_DEFAULT)) == NULL)
		die("out of memory");

	while ((unp = uu_list_walk_next(walk)) != NULL) {
		if (strcmp(unp->un_name, dis_function_name(func)) == 0) {
			resolved_name_t *resolved;

			unp->un_mark = cb->cb_mark;

			resolved = safe_malloc(sizeof (resolved_name_t));

			resolved->rn_data = dis_function_copy(func);
			resolved->rn_value = unp->un_value;

			(void) uu_list_insert_before(cb->cb_resolved, NULL,
			    resolved);
		}
	}

	uu_list_walk_end(walk);
}

/*
 * Take a list of unresolved names and create a resolved list of functions.  We
 * rely on walk_functions() to do the dirty work.  After resolving the
 * functions, * we check for any unmarked names and warn the user about missing
 * functions.
 */
dis_funclist_t *
dis_namelist_resolve_functions(dis_namelist_t *namelist, dis_tgt_t *tgt)
{
	uu_list_t *listp;
	uu_list_walk_t *walk;
	unresolved_name_t *unp;
	cb_data_t cb;

	if ((listp = uu_list_create(resolved_pool, NULL, UU_DEFAULT)) == NULL)
		die("out of memory");

	cb.cb_mark = ++current_mark;
	cb.cb_source = namelist;
	cb.cb_resolved = listp;

	dis_tgt_function_iter(tgt, walk_functions, &cb);

	/*
	 * Walk unresolved list and report any missing functions.
	 */
	if ((walk = uu_list_walk_start(namelist, UU_DEFAULT)) == NULL)
		die("out of memory");

	while ((unp = uu_list_walk_next(walk)) != NULL) {
		if (unp->un_mark != current_mark)
			warn("failed to find function '%s' in '%s'",
			    unp->un_name, dis_tgt_name(tgt));
	}

	uu_list_walk_end(walk);

	return (listp);
}

/*
 * Returns true if the given list is empty.
 */
int
dis_namelist_empty(dis_namelist_t *list)
{
	return (uu_list_numnodes(list) == 0);
}

static void
free_list(uu_list_t *list)
{
	uu_list_walk_t *walk;
	void *data;

	if ((walk = uu_list_walk_start(list, UU_WALK_ROBUST)) == NULL)
		die("out of memory");

	while ((data = uu_list_walk_next(walk)) != NULL) {
		uu_list_remove(list, data);
		free(data);
	}

	uu_list_walk_end(walk);

	uu_list_destroy(list);
}

/*
 * Destroy a list of sections.  First, walk the list and free the associated
 * section data.  Pass the list onto to free_list() to clean up the rest of the
 * list.
 */
void
dis_scnlist_destroy(dis_scnlist_t *list)
{
	uu_list_walk_t *walk;
	resolved_name_t *data;

	if ((walk = uu_list_walk_start(list, UU_DEFAULT)) == NULL)
		die("out of memory");

	while ((data = uu_list_walk_next(walk)) != NULL)
		dis_section_free(data->rn_data);

	uu_list_walk_end(walk);

	free_list(list);
}

/*
 * Destroy a list of functions.  First, walk the list and free the associated
 * function data.  Pass the list onto to free_list() to clean up the rest of the
 * list.
 */
void
dis_funclist_destroy(dis_funclist_t *list)
{
	uu_list_walk_t *walk;
	resolved_name_t *data;

	if ((walk = uu_list_walk_start(list, UU_DEFAULT)) == NULL)
		die("out of memory");

	while ((data = uu_list_walk_next(walk)) != NULL)
		dis_function_free(data->rn_data);

	uu_list_walk_end(walk);

	free_list(list);
}

/*
 * Destroy a lis tof unresolved names.
 */
void
dis_namelist_destroy(dis_namelist_t *list)
{
	free_list(list);
}

/*
 * Iterate over a resolved list of sections.
 */
void
dis_scnlist_iter(uu_list_t *list, void (*func)(dis_scn_t *, int, void *),
    void *arg)
{
	uu_list_walk_t *walk;
	resolved_name_t *data;

	if ((walk = uu_list_walk_start(list, UU_DEFAULT)) == NULL)
		die("out of memory");

	while ((data = uu_list_walk_next(walk)) != NULL)
		func(data->rn_data, data->rn_value, arg);

	uu_list_walk_end(walk);
}

/*
 * Iterate over a resolved list of functions.
 */
void
dis_funclist_iter(uu_list_t *list, void (*func)(dis_func_t *, int, void *),
    void *arg)
{
	uu_list_walk_t *walk;
	resolved_name_t *data;

	if ((walk = uu_list_walk_start(list, UU_DEFAULT)) == NULL)
		die("out of memory");

	while ((data = uu_list_walk_next(walk)) != NULL)
		func(data->rn_data, data->rn_value, arg);

	uu_list_walk_end(walk);
}
