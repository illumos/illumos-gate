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
 *
 * ipath.c -- instanced pathname module
 *
 * this module provides a cache of fully instantized component paths,
 * stored in a fairly compact format.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include "alloc.h"
#include "out.h"
#include "lut.h"
#include "tree.h"
#include "ptree.h"
#include "itree.h"
#include "ipath.h"
#include "ipath_impl.h"
#include "stats.h"
#include "eval.h"
#include "config.h"

static struct stats *Nipath;
static struct stats *Nbytes;

static struct lut *Ipaths;	/* the ipath cache itself */

/*
 * ipath_init -- initialize the ipath module
 */
void
ipath_init(void)
{
	Nipath = stats_new_counter("ievent.nipath", "ipath cache entries", 1);
	Nbytes = stats_new_counter("ievent.nbytes", "total cache size", 1);
}

/*
 * ipath_cmp -- compare two ipath entries
 *
 * since two ipaths containing the same components and instance
 * numbers always point to the same cache entry, they are equal
 * if their pointers are equal, so this function is not necessary
 * to test if two ipaths are same.  but when inserting a new ipath
 * into the cache, we must use the same lut comparison logic as when
 * we're searching for it, so this function must always match the
 * itree_epnamecmp() function's logic (see below) for searching the lut.
 */
static int
ipath_cmp(struct ipath *ipp1, struct ipath *ipp2)
{
	int i;

	ASSERT(ipp1 != NULL);
	ASSERT(ipp2 != NULL);

	for (i = 0; ipp1[i].s != NULL && ipp2[i].s != NULL; i++)
		if (ipp1[i].s != ipp2[i].s)
			return (ipp2[i].s - ipp1[i].s);
		else if (ipp1[i].i != ipp2[i].i)
			return (ipp2[i].i - ipp1[i].i);

	if (ipp1[i].s == NULL && ipp2[i].s == NULL)
		return (0);
	else if (ipp1[i].s == NULL)
		return (1);
	else
		return (-1);
}

/*
 * ipath_epnamecmp -- compare an ipath with a struct node *epname list
 *
 * this function is used when searching the cache, allowing us to search
 * a lut full of ipaths by looking directly at a struct node *epname
 * (without having to convert it first).  the comparison logic here must
 * exactly match itree_cmp()'s logic (see above) so lut lookups use find
 * the same node as lut inserts.
 */
static int
ipath_epnamecmp(struct ipath *ipp, struct node *np)
{
	int i;

	ASSERT(np != NULL);
	ASSERT(ipp != NULL);

	for (i = 0; ipp[i].s != NULL && np != NULL; i++, np = np->u.name.next) {
		ASSERTinfo(np->t == T_NAME, ptree_nodetype2str(np->t));

		if (ipp[i].s != np->u.name.s)
			return (np->u.name.s - ipp[i].s);
		else {
			int inum;

			if (np->u.name.child != NULL &&
			    np->u.name.child->t == T_NUM)
				inum = (int)np->u.name.child->u.ull;
			else
				config_getcompname(np->u.name.cp, NULL, &inum);

			if (ipp[i].i != inum)
				return (inum - ipp[i].i);
		}
	}

	if (ipp[i].s == NULL && np == NULL)
		return (0);
	else if (ipp[i].s == NULL)
		return (1);
	else
		return (-1);
}

struct lut *Usednames;

void
ipath_dummy_lut(struct arrow *arrowp)
{
	const struct ipath *ipp;

	ipp = arrowp->head->myevent->ipp;
	while (ipp->s != NULL) {
		Usednames = lut_add(Usednames, (void *)ipp->s,
		    (void *)ipp->s, NULL);
		ipp++;
	}
	ipp = arrowp->tail->myevent->ipp;
	while (ipp->s != NULL) {
		Usednames = lut_add(Usednames, (void *)ipp->s,
		    (void *)ipp->s, NULL);
		ipp++;
	}
}

struct ipath *
ipath_dummy(struct node *np, struct ipath *ipp)
{
	struct ipath *ret;

	ret = ipp;
	while (ipp[1].s != NULL)
		ipp++;
	if (strcmp(ipp[0].s, np->u.name.last->u.name.s) == 0)
		return (ret);

	ret = MALLOC(sizeof (*ret) * 2);
	ret[0].s = np->u.name.last->u.name.s;
	ret[0].i = 0;
	ret[1].s = NULL;
	if ((ipp = lut_lookup(Ipaths, (void *)ret,
	    (lut_cmp)ipath_cmp)) != NULL) {
		FREE(ret);
		return (ipp);
	}
	Ipaths = lut_add(Ipaths, (void *)ret, (void *)ret, (lut_cmp)ipath_cmp);
	stats_counter_bump(Nipath);
	stats_counter_add(Nbytes, 2 * sizeof (struct ipath));
	return (ret);
}

/*
 * ipath -- find instanced path in cache, or add it if necessary
 */
const struct ipath *
ipath(struct node *np)
{
	struct ipath *ret;
	int count;
	struct node *namep;
	int i;

	if ((ret = lut_lookup(Ipaths, (void *)np,
	    (lut_cmp)ipath_epnamecmp)) != NULL)
		return (ret);	/* already in cache */

	/*
	 * not in cache, make new cache entry.
	 * start by counting the length of the name.
	 */
	count = 0;
	namep = np;
	while (namep != NULL) {
		ASSERTinfo(namep->t == T_NAME, ptree_nodetype2str(namep->t));
		count++;
		namep = namep->u.name.next;
	}

	ASSERT(count > 0);

	/* allocate array for name and last NULL entry */
	ret = MALLOC(sizeof (*ret) * (count + 1));
	ret[count].s = NULL;

	/* fill in ipath entry */
	namep = np;
	i = 0;
	while (namep != NULL) {
		ASSERT(i < count);
		ret[i].s = namep->u.name.s;
		if (namep->u.name.child != NULL &&
		    namep->u.name.child->t == T_NUM)
			ret[i].i = (int)namep->u.name.child->u.ull;
		else
			config_getcompname(namep->u.name.cp, NULL, &ret[i].i);
		i++;
		namep = namep->u.name.next;
	}

	/* add it to the cache */
	Ipaths = lut_add(Ipaths, (void *)ret, (void *)ret,
	    (lut_cmp)ipath_cmp);

	stats_counter_bump(Nipath);
	stats_counter_add(Nbytes, (count + 1) * sizeof (struct ipath));

	return (ret);
}

/*
 * ipath2str -- convert ename and ipath to class@path string
 *
 * if both ename and ipp are provided (non-NULL), the resulting string
 * will be "class@path".  otherwise, the string will just contain the
 * event class name (e.g. "ereport.io.pci.device") or just the path
 * name (e.g. "mothboard0/hostbridge0/pcibus1/pcidev0/pcifn1"), depending
 * on which argument is non-NULL.
 */
char *
ipath2str(const char *ename, const struct ipath *ipp)
{
	int i;
	size_t len = 0;
	char *ret;
	char *cp;

	/* count up length of class string */
	if (ename != NULL)
		len += strlen(ename);

	/* count up length of path string, including slash separators */
	if (ipp != NULL) {
		for (i = 0; ipp[i].s != NULL; i++) {
			/* add slash separator, but no leading slash */
			if (i != 0)
				len++;
			len += snprintf(NULL, 0, "%s%d", ipp[i].s, ipp[i].i);
		}
	}

	if (ename != NULL && ipp != NULL)
		len++;	/* room for '@' */

	len++;	/* room for final '\0' */

	cp = ret = MALLOC(len);

	if (ename != NULL) {
		/* construct class string */
		(void) strcpy(cp, ename);
		cp += strlen(cp);
	}

	/* if doing both strings, put '@' between them */
	if (ename != NULL && ipp != NULL)
		*cp++ = '@';

	if (ipp != NULL) {
		/* construct path string */
		for (i = 0; ipp[i].s != NULL; i++) {
			if (i != 0)
				*cp++ = '/';
			(void) snprintf(cp, &ret[len] - cp, "%s%d",
			    ipp[i].s, ipp[i].i);
			cp += strlen(cp);
		}
	}

	*cp++ = '\0';

	return (ret);
}

/*
 * ipath2strlen -- calculate the len of what ipath2str() would return
 */
size_t
ipath2strlen(const char *ename, const struct ipath *ipp)
{
	int i;
	size_t len = 0;

	/* count up length of class string */
	if (ename != NULL)
		len += strlen(ename);

	/* count up length of path string, including slash separators */
	if (ipp != NULL) {
		for (i = 0; ipp[i].s != NULL; i++) {
			/* add slash separator, but no leading slash */
			if (i != 0)
				len++;
			len += snprintf(NULL, 0, "%s%d", ipp[i].s, ipp[i].i);
		}
	}

	if (ename != NULL && ipp != NULL)
		len++;	/* room for '@' */

	return (len);
}

/*
 * ipath_print -- print out an ename, ipath, or both with '@' between them
 */
void
ipath_print(int flags, const char *ename, const struct ipath *ipp)
{
	if (ename != NULL) {
		out(flags|O_NONL, ename);
		if (ipp != NULL)
			out(flags|O_NONL, "@");
	}
	if (ipp != NULL) {
		char *sep = "";

		while (ipp->s != NULL) {
			out(flags|O_NONL, "%s%s%d", sep, ipp->s, ipp->i);
			ipp++;
			sep = "/";
		}
	}
}

/*ARGSUSED*/
static void
ipath_destructor(void *left, void *right, void *arg)
{
	struct ipath *ipp = (struct ipath *)right;

	FREE(ipp);
}

/*
 * ipath_fini -- free the ipath cache
 */
void
ipath_fini(void)
{
	lut_free(Ipaths, ipath_destructor, NULL);
	Ipaths = NULL;
	lut_free(Usednames, NULL, NULL);
	Usednames = NULL;

	if (Nipath) {
		stats_delete(Nipath);
		Nipath = NULL;
	}

	if (Nbytes) {
		stats_delete(Nbytes);
		Nbytes = NULL;
	}
}
