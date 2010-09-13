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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_GROUP_H
#define	_GROUP_H

/*
 * Group Abstraction
 */

#ifdef	__cplusplus
extern "C" {
#endif

#if (defined(_KERNEL) || defined(_KMEMUSER))
#include <sys/types.h>

#define	GRP_RESIZE	0x1	/* Resize group capacity if needed */
#define	GRP_NORESIZE	0x2	/* Do not resize group capacity; may fail */

/*
 * group structure
 */
typedef struct group {
	uint_t		grp_size;	/* # of elements */
	uint_t		grp_capacity;	/* current group capacity */
	void		**grp_set;	/* element vector */
} group_t;

typedef uint_t group_iter_t;


/*
 * Return the number of elements in the group
 */
#define	GROUP_SIZE(grp)			((grp)->grp_size)

/*
 * Access the element at the specified group index
 */
#define	GROUP_ACCESS(grp, index)	((grp)->grp_set[index])

/*
 * Group creation / destruction
 */
void		group_create(group_t *);
void		group_destroy(group_t *);

/*
 * Expand a group's holding capacity
 */
void		group_expand(group_t *, uint_t);

/*
 * Group element iteration
 */
void		group_iter_init(group_iter_t *);
void		*group_iterate(group_t *, group_iter_t *);

/*
 * Add / remove an element (or elements) from the group
 */
int		group_add(group_t *, void *, int);
int		group_remove(group_t *, void *, int);
void		group_empty(group_t *);

/*
 * Add / remove / access an element at a specified index.
 * The group must already have sufficient capacity to hold
 * an element at the specified index.
 */
int		group_add_at(group_t *, void *, uint_t);
void		group_remove_at(group_t *, uint_t);

/*
 * Search for an element in a group.
 * Returns an index that may be used with the *_at()
 * routines above to add or remove the element.
 */
uint_t		group_find(group_t *, void *);

/*
 * Convert a group to a string with list of integers.
 *
 * The consecutive integer values are represented using x-y notation.
 * The resulting string looks like "1,2-5,8"
 *
 * The convert argument is used to map group elements to integer IDs.
 * The output buffer and its length are specfied in the arguments.
 */
extern char *group2intlist(group_t *, char *, size_t, int (convert)(void*));

#endif	/* !_KERNEL && !_KMEMUSER */

#ifdef	__cplusplus
}
#endif

#endif /* _GROUP_H */
