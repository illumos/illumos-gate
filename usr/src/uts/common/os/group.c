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

#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/group.h>
#include <sys/cmn_err.h>


#define	GRP_SET_SIZE_DEFAULT 2

static void group_grow_set(group_t *);
static void group_shrink_set(group_t *);
static void group_pack_set(void **, uint_t);

/*
 * Initialize a group_t
 */
void
group_create(group_t *g)
{
	bzero(g, sizeof (group_t));
}

/*
 * Destroy a group_t
 * The group must already be empty
 */
void
group_destroy(group_t *g)
{
	ASSERT(g->grp_size == 0);

	if (g->grp_capacity > 0) {
		kmem_free(g->grp_set, g->grp_capacity * sizeof (void *));
		g->grp_capacity = 0;
	}
	g->grp_set = NULL;
}

/*
 * Empty a group_t
 * Capacity is preserved.
 */
void
group_empty(group_t *g)
{
	int	i;
	int	sz = g->grp_size;

	g->grp_size = 0;
	for (i = 0; i < sz; i++)
		g->grp_set[i] = NULL;
}

/*
 * Add element "e" to group "g"
 *
 * Returns -1 if addition would result in overcapacity, and
 * resize operations aren't allowed, and 0 otherwise
 */
int
group_add(group_t *g, void *e, int gflag)
{
	int	entry;

	if ((gflag & GRP_NORESIZE) &&
	    g->grp_size == g->grp_capacity)
		return (-1);

	ASSERT(g->grp_size != g->grp_capacity || (gflag & GRP_RESIZE));

	entry = g->grp_size++;
	if (g->grp_size > g->grp_capacity)
		group_grow_set(g);

	ASSERT(g->grp_set[entry] == NULL);
	g->grp_set[entry] = e;

	return (0);
}

/*
 * Remove element "e" from group "g"
 *
 * Returns -1 if "e" was not present in "g" and 0 otherwise
 */
int
group_remove(group_t *g, void *e, int gflag)
{
	int	i;

	if (g->grp_size == 0)
		return (-1);

	/*
	 * Find the element in the group's set
	 */
	for (i = 0; i < g->grp_size; i++)
		if (g->grp_set[i] == e)
			break;
	if (g->grp_set[i] != e)
		return (-1);

	g->grp_set[i] = NULL;
	group_pack_set(g->grp_set, g->grp_size);
	g->grp_size--;

	if ((gflag & GRP_RESIZE) &&
	    g->grp_size > GRP_SET_SIZE_DEFAULT && ISP2(g->grp_size))
		group_shrink_set(g);

	return (0);
}

/*
 * Expand the capacity of group "g" so that it may
 * contain at least "n" elements
 */
void
group_expand(group_t *g, uint_t n)
{
	while (g->grp_capacity < n)
		group_grow_set(g);
}

/*
 * Upsize a group's holding capacity
 */
static void
group_grow_set(group_t *g)
{
	uint_t		cap_old, cap_new;
	void		**set_old, **set_new;

	cap_old = g->grp_capacity;
	set_old = g->grp_set;

	/*
	 * The array size grows in powers of two
	 */
	if ((cap_new = (cap_old << 1)) == 0) {
		/*
		 * The set is unallocated.
		 * Allocate a default sized set.
		 */
		cap_new = GRP_SET_SIZE_DEFAULT;
		g->grp_set = kmem_zalloc(cap_new * sizeof (void *), KM_SLEEP);
		g->grp_capacity = cap_new;
	} else {
		/*
		 * Allocate a newly sized array,
		 * copy the data, and free the old array.
		 */
		set_new = kmem_zalloc(cap_new * sizeof (void *), KM_SLEEP);
		(void) kcopy(set_old, set_new, cap_old * sizeof (void *));
		g->grp_set = set_new;
		g->grp_capacity = cap_new;
		kmem_free(set_old, cap_old * sizeof (void *));
	}
	/*
	 * The new array size should be a power of two
	 */
	ASSERT(((cap_new - 1) & cap_new) == 0);
}

/*
 * Downsize a group's holding capacity
 */
static void
group_shrink_set(group_t *g)
{
	uint_t		cap_old, cap_new;
	void		**set_old, **set_new;

	cap_old = g->grp_capacity;
	set_old = g->grp_set;

	/*
	 * The group's existing array size must already
	 * be a power of two
	 */
	ASSERT(((cap_old - 1) & cap_old) == 0);
	cap_new = cap_old >> 1;

	/*
	 * GRP_SET_SIZE_DEFAULT is the minumum set size.
	 */
	if (cap_new < GRP_SET_SIZE_DEFAULT)
		return;

	set_new = kmem_zalloc(cap_new * sizeof (void *), KM_SLEEP);
	(void) kcopy(set_old, set_new, cap_new * sizeof (void *));
	g->grp_capacity = cap_new;
	g->grp_set = set_new;

	ASSERT(((cap_new - 1) & cap_new) == 0);
	kmem_free(set_old, cap_old * sizeof (void *));
}

/*
 * Pack a group's set
 * Element order is not preserved
 */
static void
group_pack_set(void **set, uint_t sz)
{
	uint_t	i, j, free;

	free = (uint_t)-1;

	for (i = 0; i < sz; i++) {
		if (set[i] == NULL && free == (uint_t)-1) {
			/*
			 * Found a new free slot.
			 * Start packing from here.
			 */
			free = i;
		} else if (set[i] != NULL && free != (uint_t)-1) {
			/*
			 * Found a slot to pack into
			 * an earlier free slot.
			 */
			ASSERT(set[free] == NULL);
			set[free] = set[i];
			set[i] = NULL;

			/*
			 * Find the next free slot
			 */
			for (j = free + 1; set[j] != NULL; j++) {
				ASSERT(j <= i);
				if (j == i)
					break;
			}
			if (set[j] == NULL)
				free = j;
			else
				free = (uint_t)-1;
		}
	}
}

/*
 * Initialize a group iterator cookie
 */
void
group_iter_init(group_iter_t *iter)
{
	*iter = 0;
}

/*
 * Iterate over the elements in a group
 */
void *
group_iterate(group_t *g, group_iter_t *iter)
{
	uint_t	idx = *iter;
	void	*data = NULL;

	while (idx < g->grp_size) {
		data = g->grp_set[idx++];
		if (data != NULL)
			break;
	}
	*iter = idx;

	return (data);
}

/*
 * Indexed access to a group's elements
 */
void *
group_access_at(group_t *g, uint_t idx)
{
	if (idx >= g->grp_capacity)
		return (NULL);

	return (g->grp_set[idx]);
}

/*
 * Add a new ordered group element at specified
 * index. The group must already be of sufficient
 * capacity to hold an element at the specified index.
 *
 * Returns 0 if addition was sucessful, and -1 if the
 * addition failed because the table was too small
 */
int
group_add_at(group_t *g, void *e, uint_t idx)
{
	if (idx >= g->grp_capacity)
		return (-1);

	if (idx >= g->grp_size)
		g->grp_size = idx + 1;

	ASSERT(g->grp_set[idx] == NULL);
	g->grp_set[idx] = e;
	return (0);
}

/*
 * Remove the element at the specified index
 */
void
group_remove_at(group_t *g, uint_t idx)
{
	ASSERT(idx < g->grp_capacity);
	g->grp_set[idx] = NULL;
}

/*
 * Find an element in the group, and return its index
 * Returns -1 if the element could not be found.
 */
uint_t
group_find(group_t *g, void *e)
{
	uint_t	idx;

	for (idx = 0; idx < g->grp_capacity; idx++) {
		if (g->grp_set[idx] == e)
			return (idx);
	}
	return ((uint_t)-1);
}

/*
 * Return a string in a given buffer with list of integer entries in a group.
 * The string concatenates consecutive integer ranges ax x-y.
 * The resulting string looks like "1,2-5,8"
 *
 * The convert argument is used to map group elements to integer IDs.
 */
char *
group2intlist(group_t *group, char *buffer, size_t len, int (convert)(void*))
{
	char		*ptr = buffer;
	void		*v;
	group_iter_t	iter;
	boolean_t	first_iteration = B_TRUE;
	boolean_t	first_value = B_TRUE;
	int		start = 0, end = 0;

	/*
	 * Allow for the terminating NULL-byte
	 */
	len = len -1;

	group_iter_init(&iter);
	while ((v = group_iterate(group, &iter)) != NULL && len > 0) {
		int id = convert(v);
		int nbytes = 0;

		if (first_iteration) {
			start = end = id;
			first_iteration = B_FALSE;
		} else if (end + 1 == id) {
			/*
			 * Got consecutive ID, so extend end of range without
			 * doing anything since the range may extend further
			 */
			end = id;
		} else {
			if (first_value) {
				first_value = B_FALSE;
			} else {
				*ptr++ = ',';
				len--;
			}

			if (len == 0)
				break;

			/*
			 * Next ID is not consecutive, so dump IDs gotten so
			 * far.
			 */
			if (end > start + 1) /* range */
				nbytes = snprintf(ptr, len, "%d-%d",
				    start, end);
			else if (end > start) /* different values */
				nbytes = snprintf(ptr, len, "%d,%d",
				    start, end);
			else /* same value */
				nbytes = snprintf(ptr, len, "%d", start);

			if (nbytes <= 0) {
				len = 0;
				break;
			}

			/*
			 * Advance position in the string
			 */
			ptr += nbytes;
			len -= nbytes;

			/*
			 * Try finding consecutive range starting from current
			 * ID.
			 */
			start = end = id;
		}
	}

	if (!first_value) {
		*ptr++ = ',';
		len--;
	}
	/*
	 * Print last ID(s)
	 */
	if (len > 0) {
		if (end > start + 1) {
			(void) snprintf(ptr, len, "%d-%d", start, end);
		} else if (end != start) {
			(void) snprintf(ptr, len, "%d,%d", start, end);
		} else {
			(void) snprintf(ptr, len, "%d", start);
		}
	}

	return (buffer);
}
