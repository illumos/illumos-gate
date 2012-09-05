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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 */

#include <libintl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "prstat.h"
#include "prutil.h"
#include "prsort.h"

void
list_alloc(list_t *list, int size)
{
	list->l_size = size;
	if (size > 0)
		list->l_ptrs = Zalloc(sizeof (void *) * (size + 1));
	else
		list->l_ptrs = NULL;
}

void
list_free(list_t *list)
{
	if (list && list->l_ptrs) {
		free(list->l_ptrs);
		list->l_ptrs = NULL;
	}
}

/*
 * Sorting routines
 */
static ulong_t
get_cpu_from_psinfo(void *lwp)
{
	return ((ulong_t)
	    FRC2PCT((((lwp_info_t *)lwp)->li_info.pr_lwp.pr_pctcpu)*1000));
}

static ulong_t
get_cpu_from_usage(void *lwp)
{
	lwp_info_t *p = (lwp_info_t *)lwp;
	float cpu = 0;
	cpu += p->li_usr;
	cpu += p->li_sys;
	cpu *= 1000;
	return ((ulong_t)cpu);
}

static ulong_t
get_time(void *lwp)
{
	return ((ulong_t)TIME2SEC(((lwp_info_t *)lwp)->li_info.pr_lwp.pr_time));
}

static ulong_t
get_size(void *lwp)
{
	return ((ulong_t)((lwp_info_t *)lwp)->li_info.pr_size);
}

static ulong_t
get_rssize(void *lwp)
{
	return ((ulong_t)((lwp_info_t *)lwp)->li_info.pr_rssize);
}

static ulong_t
get_pri(void *lwp)
{
	return ((ulong_t)((lwp_info_t *)lwp)->li_info.pr_lwp.pr_pri);
}

static ulong_t
get_idkey(void *id)
{
	return (((id_info_t *)id)->id_key);
}

void
list_setkeyfunc(char *arg, optdesc_t *opt, list_t *list, int type)
{
	if (list == NULL)
		return;

	list->l_sortorder = opt->o_sortorder;
	list->l_type = type;
	if (arg == NULL) {	/* special case for id_infos */
		list->l_func = get_idkey;
		return;
	}
	if (strcmp("cpu", arg) == 0) {
		if (opt->o_outpmode & OPT_MSACCT)
			list->l_func = get_cpu_from_usage;
		else
			list->l_func = get_cpu_from_psinfo;
		return;
	}
	if (strcmp("time", arg) == 0) {
		list->l_func = get_time;
		return;
	}
	if (strcmp("size", arg) == 0) {
		list->l_func = get_size;
		return;
	}
	if (strcmp("rss", arg) == 0) {
		list->l_func = get_rssize;
		return;
	}
	if (strcmp("pri", arg) == 0) {
		list->l_func = get_pri;
		return;
	}
	Die(gettext("invalid sort key -- %s\n"), arg);
}

ulong_t
list_getkeyval(list_t *list, void *ptr)
{
	return (list->l_func(ptr));
}

static int
compare_keys(list_t *list, ulong_t key1, ulong_t key2)
{
	if (key1 == key2)
		return (0);
	if (key1 < key2)
		return (1 * list->l_sortorder);
	else
		return (-1 * list->l_sortorder);
}

static void
list_insert(list_t *list, void *ptr)
{
	int i, j;
	long k1, k2;

	for (i = 0; i < list->l_used; i++) {	/* insert in the middle */
		k1 = list_getkeyval(list, ptr);
		k2 = list_getkeyval(list, list->l_ptrs[i]);
		if (compare_keys(list, k1, k2) >= 0) {
			for (j = list->l_used - 1; j >= i; j--)
				list->l_ptrs[j+1] = list->l_ptrs[j];
			list->l_ptrs[i] = ptr;
			if (list->l_used < list->l_size)
				list->l_used++;
			return;
		}
	}
	if (i + 1 <= list->l_size) {		/* insert at the tail */
		list->l_ptrs[list->l_used] = ptr;

		list->l_used++;
	}
}

static void
list_preinsert(list_t *list, void *ptr)
{
	ulong_t	k1, k2;

	if (list->l_used < list->l_size) {	/* just add */
		list_insert(list, ptr);
		return;
	}
	k1 = list_getkeyval(list, list->l_ptrs[list->l_used - 1]);
	k2 = list_getkeyval(list, ptr);
	if (compare_keys(list, k1, k2) >= 0)	/* skip insertion */
		return;
	k1 = list_getkeyval(list, list->l_ptrs[0]);
	if (compare_keys(list, k2, k1) >= 0) {	/* add at the head */
		list_insert(list, ptr);
		return;
	}
	list_insert(list, ptr);
}

void
list_sort(list_t *list)
{
	list->l_used = 0;
	if (list->l_size == 0)
		return;

	(void) memset(list->l_ptrs, 0, sizeof (void *) * list->l_size);

	if (list->l_type == LT_LWPS) {
		lwp_info_t *lwp = list->l_head;

		while (lwp) {
			list_preinsert(list, (void *)lwp);
			lwp = lwp->li_next;
		}
	} else {
		id_info_t *id = list->l_head;

		while (id) {
			list_preinsert(list, (void *)id);
			id = id->id_next;
		}
	}
}
