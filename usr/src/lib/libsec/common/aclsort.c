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
 * Copyright (c) 1993-1997 by Sun Microsystems, Inc.
 * All rights reserved
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*LINTLIBRARY*/

/*
 * aclsort():
 *	Sort an ACL by entry type according to the following order:
 *	USER_OBJ, USER, GROUP_OBJ, GROUP, CLASS_OBJ, OTHER_OBJ
 *	DEF_USER_OBJ, DEF_USER, DEF_GROUP_OBJ, DEF_GROUP, DEF_CLASS_OBJ,
 *	DEF_OTHER_OBJ.
 *	For USER, GROUP, DEF_USER, and DEF_GROUP entries, the entries
 *	are further sorted by ids.
 */

#include <stdlib.h>
#include <sys/acl.h>

#define	TOTAL_ENTRY_TYPES	12

/*
 * This maps the entry defined value to a value for sorting.
 * These values may not be the same. It is easier to add an
 * entry type with this map.
 *
 * Because the defines and sorting order are not the same,
 * the following map_to_sort table is needed.
 */
struct map {
	int	sort_order;
	int	entry_type;
};

static struct map map_to_sort[] = {
		{0, 0}, /* UNUSED */
		{1,	USER_OBJ},
		{2,	USER},
		{3, 	GROUP_OBJ},
		{4,	GROUP},
		{5,	CLASS_OBJ},
		{6, 	OTHER_OBJ},
		{7, 	DEF_USER_OBJ},
		{8, 	DEF_USER},
		{9, 	DEF_GROUP_OBJ},
		{10,	DEF_GROUP},
		{11,	DEF_CLASS_OBJ},
		{12,	DEF_OTHER_OBJ},
};

static int entrycmp(const aclent_t *, const aclent_t *);
static int idcmp(const aclent_t *, const aclent_t *);
static void sortid(aclent_t *, int, int);

int
aclsort(int nentries, int calcmask, aclent_t *aclbufp)
{
	aclent_t		*tp;
	unsigned int		newmask = 0;
	int			which;
	int			i;
	int			k;

	/* check validity first before sorting */
	if (aclcheck(aclbufp, nentries, &which) != 0)
		return (-1);

	/*
	 * Performance enhancement:
	 * We change entry type to sort order in the ACL, do the sorting.
	 * We then change sort order back to entry type.
	 * This makes entrycmp() very "light" and thus improves performance.
	 * Contrast to original implementation that had to find out
	 * the sorting order each time it is called.
	 */
	for (tp = aclbufp, i = 0; i < nentries; tp++, i++) {
		for (k = 1; k <= TOTAL_ENTRY_TYPES; k++) {
			if (tp->a_type == map_to_sort[k].entry_type) {
				tp->a_type = map_to_sort[k].sort_order;
				break;
			}
		}
	}

	/* typecast to remove incompatible type warning */
	qsort(aclbufp, nentries, sizeof (aclent_t),
	    (int (*)(const void *, const void *))entrycmp);

	for (tp = aclbufp, i = 0; i < nentries; tp++, i++) {
		for (k = 1; k <= TOTAL_ENTRY_TYPES; k++) {
			if (tp->a_type == map_to_sort[k].sort_order) {
				tp->a_type = map_to_sort[k].entry_type;
				break;
			}
		}
	}

	/*
	 * Start sorting id within USER and GROUP
	 * sortid() could return a pointer and entries left
	 * so that we dont have to search from the beginning
	 *  every time it calls
	 */
	sortid(aclbufp, nentries, USER);
	sortid(aclbufp, nentries, GROUP);
	sortid(aclbufp, nentries, DEF_USER);
	sortid(aclbufp, nentries, DEF_GROUP);

	/*
	 * Recalculate mask entry
	 */
	if (calcmask != 0) {
		/*
		 * At this point, ACL is valid and sorted. We may find a
		 * CLASS_OBJ entry and stop. Because of the case of minimum ACL,
		 * we still have to check till OTHER_OBJ entry is shown.
		 */
		for (tp = aclbufp; tp->a_type != OTHER_OBJ; tp++) {
			if (tp->a_type == USER || tp->a_type == GROUP ||
			    tp->a_type == GROUP_OBJ)
				newmask |= tp->a_perm;
			if (tp->a_type == CLASS_OBJ)
				break;
		}
		if (tp->a_type == CLASS_OBJ)
			tp->a_perm = (unsigned char)newmask;
	}
	return (0);
}

/*
 * sortid() sorts the ids with the same entry type in increasing order
 */
static void
sortid(aclent_t *ap, int cnt, int type)
{
	aclent_t	*tp;
	aclent_t	*startp; /* start of the desired entry type */
	int		howmany;

	for (tp = ap; cnt-- > 0; tp++) {
		if (tp->a_type != type)
			continue;
		startp = tp;
		howmany = 1;
		for (tp++, cnt--; cnt > 0 && tp->a_type == type; tp++, cnt--)
			howmany++;
		/* typecast to remove incompatible type warning */
		qsort(startp, howmany, sizeof (aclent_t),
		    (int (*)(const void*, const void*))idcmp);
	}
}

/*
 * compare the field a_type
 */
static int
entrycmp(const aclent_t *i, const aclent_t *j)
{
	return ((int)(i->a_type) - (int)(j->a_type));
}

/*
 * compare the field a_id
 */
static int
idcmp(const aclent_t *i, const aclent_t *j)
{
	return ((int)(i->a_id) - (int)(j->a_id));
}
