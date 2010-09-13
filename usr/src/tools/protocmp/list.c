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
 * Copyright 1993-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>

#include "list.h"
#include "proto_list.h"

/* LINTLIBRARY */

int max_list_depth;

void
init_list(elem_list *list, int hsize)
{
	int	i;

	list->type = 0;
	list->list = (elem**)malloc(sizeof (elem *) * hsize);
	list->num_of_buckets = hsize;
	for (i = 0; i < list->num_of_buckets; i++)
		list->list[i] = NULL;
}

#ifdef DEBUG
void
examine_list(elem_list *list)
{
	int	i;
	elem	*cur;
	int	buck_count;

	for (i = 0; i < list->num_of_buckets; i++) {
		buck_count = 0;
		for (cur = list->list[i]; cur; cur = cur->next)
			buck_count++;
		(void) printf("bucket[%4d] contains %5d entries\n",
		    i, buck_count);
	}
}


/*
 * print all elements of a list
 *
 * Debugging routine
 */
void
print_list(elem_list *list)
{
	int	i;
	elem	*cur;

	for (i = 0; i < list->num_of_buckets; i++) {
		for (cur = list->list[i]; cur; cur = cur->next)
			print_elem(stdout, cur);
	}
}


/*
 * print all elements of a list of type 'file_type'
 *
 * Debugging routine
 */
void
print_type_list(elem_list *list, char file_type)
{
	int	i;
	elem	*cur;

	for (i = 0; i < list->num_of_buckets; i++) {
		for (cur = list->list[i]; cur; cur = cur->next) {
			if (cur->file_type == file_type)
				print_elem(stdout, cur);
		}
	}
}
#endif

unsigned int
hash(const char *str)
{
	unsigned int	i;

	for (i = 0; *str != '\0'; )
		i += *str++;
	return (i);
}


static int
name_compare(elem *i, elem *j)
{
	int	n;

	if ((n = strncmp(i->name, j->name, MAXNAME)) != 0)
		return (n);
	else
		return (j->arch - i->arch);
}


/*
 * find_elem:
 *
 * possible values for flag.
 * 			flag = FOLLOW_LINK
 *			flag = NO_FOLLOW_LINK
 */
elem *
find_elem(elem_list *list, elem *key, int flag)
{
	elem	*e;

	for (e = list->list[hash(key->name) % list->num_of_buckets]; e;
	    e = e->next) {
		if (!name_compare(e, key))
			if (e->link_parent && flag == FOLLOW_LINK)
				return (e->link_parent);
			else
				return (e);
	}

	return (NULL);
}


/*
 * find_elem_isa:
 *
 * flags - same as find_elem()
 */
elem *
find_elem_isa(elem_list *list, elem *key, int flag)
{
	short	orig_arch;
	elem	*e;

	orig_arch = key->arch;
	key->arch = P_ISA;
	e = find_elem(list, key, flag);
	key->arch = orig_arch;
	return (e);
}

/*
 * find_elem_mach:
 *
 * flags - same as find_elem()
 */
elem *
find_elem_mach(elem_list *list, elem *key, int flag)
{
	elem	*e;

	for (e = list->list[hash(key->name) % list->num_of_buckets]; e;
	    e = e->next) {
		if ((e->arch != P_ISA) && (strcmp(key->name, e->name) == 0))
			if (e->link_parent && flag == FOLLOW_LINK)
				return (e->link_parent);
			else
				return (e);
	}

	return (NULL);
}

pkg_list *
add_pkg(pkg_list *head, const char *pkgname)
{
	pkg_list	*cur, *prev = NULL;
	static pkg_list	*new = NULL;

	if (!new)
		new = (pkg_list *)malloc(sizeof (pkg_list));

	(void) strcpy(new->pkg_name, pkgname);

	for (cur = head; cur; cur = cur->next) {
		if (strcmp(cur->pkg_name, pkgname) >= 0)
			break;
		prev = cur;
	}

	if (!head) {
		new->next = head;
		head = new;
		new = NULL;
		return (head);
	}

	if (!cur) {
		prev->next = new;
		new->next = NULL;
		new = NULL;
		return (head);
	}

	if (strcmp(cur->pkg_name, pkgname) == 0)	/* a duplicate */
		return (NULL);

	if (!prev) {
		new->next = cur;
		cur = new;
		new = NULL;
		return (cur);
	}

	prev->next = new;
	new->next = cur;
	new = NULL;
	return (head);
}

void
add_elem(elem_list *list, elem *e)
{
	elem	*last = NULL;
	elem	*cur;
	int	bucket;
	int	depth = 0;

	bucket = hash(e->name) % list->num_of_buckets;
	if (list->list[bucket]) {
		for (cur = list->list[bucket]; cur; cur = cur->next) {
			depth++;
			if (strcmp(cur->name, e->name) > 0)
				break;
			last = cur;
		}

		if (last) {
			if (depth > max_list_depth)
				max_list_depth = depth;
			last->next = e;
			e->next = cur;
			return;
		}
	}

	/*
	 * insert at head of list
	 */
	e->next = list->list[bucket];
	list->list[bucket] = e;
	if (depth > max_list_depth)
		max_list_depth = depth;
}
