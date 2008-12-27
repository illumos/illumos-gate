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
 * Utility functions used by the dlmgmtd daemon.
 */

#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <syslog.h>
#include <stdarg.h>
#include <libdlpi.h>
#include "dlmgmt_impl.h"

/*
 * There are two datalink AVL tables. One table (dlmgmt_name_avl) is keyed by
 * the link name, and the other (dlmgmt_id_avl) is keyed by the link id.
 * Each link will be present in both tables.
 */
avl_tree_t	dlmgmt_name_avl;
avl_tree_t	dlmgmt_id_avl;

avl_tree_t	dlmgmt_dlconf_avl;

static pthread_rwlock_t	dlmgmt_avl_lock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t  dlmgmt_avl_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	dlmgmt_avl_cv = PTHREAD_COND_INITIALIZER;
static pthread_rwlock_t	dlmgmt_dlconf_lock = PTHREAD_RWLOCK_INITIALIZER;

typedef struct dlmgmt_prefix {
	struct dlmgmt_prefix	*lp_next;
	char			lp_prefix[MAXLINKNAMELEN];
	uint_t			lp_nextppa;
} dlmgmt_prefix_t;
static dlmgmt_prefix_t	*dlmgmt_prefixlist;

static datalink_id_t	dlmgmt_nextlinkid;
static datalink_id_t	dlmgmt_nextconfid = 1;

static int		linkattr_add(dlmgmt_linkattr_t **,
			    dlmgmt_linkattr_t *);
static int		linkattr_rm(dlmgmt_linkattr_t **,
			    dlmgmt_linkattr_t *);
static int		link_create(const char *, datalink_class_t, uint32_t,
			    uint32_t, dlmgmt_link_t **);

static void		dlmgmt_advance_linkid(dlmgmt_link_t *);
static void		dlmgmt_advance_ppa(dlmgmt_link_t *);

void
dlmgmt_log(int pri, const char *fmt, ...)
{
	va_list alist;

	va_start(alist, fmt);
	if (debug) {
		(void) vfprintf(stderr, fmt, alist);
		(void) fputc('\n', stderr);
	} else {
		vsyslog(pri, fmt, alist);
	}
	va_end(alist);
}

static int
cmp_link_by_name(const void *v1, const void *v2)
{
	const dlmgmt_link_t *link1 = v1;
	const dlmgmt_link_t *link2 = v2;
	int cmp;

	cmp = strcmp(link1->ll_link, link2->ll_link);
	return ((cmp == 0) ? 0 : ((cmp < 0) ? -1 : 1));
}

static int
cmp_link_by_id(const void *v1, const void *v2)
{
	const dlmgmt_link_t *link1 = v1;
	const dlmgmt_link_t *link2 = v2;

	if ((uint64_t)(link1->ll_linkid) == (uint64_t)(link2->ll_linkid))
		return (0);
	else if ((uint64_t)(link1->ll_linkid) < (uint64_t)(link2->ll_linkid))
		return (-1);
	else
		return (1);
}

static int
cmp_dlconf_by_id(const void *v1, const void *v2)
{
	const dlmgmt_dlconf_t *dlconfp1 = v1;
	const dlmgmt_dlconf_t *dlconfp2 = v2;

	if (dlconfp1->ld_id == dlconfp2->ld_id)
		return (0);
	else if (dlconfp1->ld_id < dlconfp2->ld_id)
		return (-1);
	else
		return (1);
}

int
dlmgmt_linktable_init()
{
	/*
	 * Initialize the prefix list. First add the "net" prefix to the list.
	 */
	dlmgmt_prefixlist = malloc(sizeof (dlmgmt_prefix_t));
	if (dlmgmt_prefixlist == NULL) {
		dlmgmt_log(LOG_WARNING, "dlmgmt_linktable_init() failed: %s",
		    strerror(ENOMEM));
		return (ENOMEM);
	}

	dlmgmt_prefixlist->lp_next = NULL;
	dlmgmt_prefixlist->lp_nextppa = 0;
	(void) strlcpy(dlmgmt_prefixlist->lp_prefix, "net", MAXLINKNAMELEN);

	avl_create(&dlmgmt_name_avl, cmp_link_by_name, sizeof (dlmgmt_link_t),
	    offsetof(dlmgmt_link_t, ll_node_by_name));
	avl_create(&dlmgmt_id_avl, cmp_link_by_id, sizeof (dlmgmt_link_t),
	    offsetof(dlmgmt_link_t, ll_node_by_id));
	avl_create(&dlmgmt_dlconf_avl, cmp_dlconf_by_id,
	    sizeof (dlmgmt_dlconf_t), offsetof(dlmgmt_dlconf_t, ld_node));
	dlmgmt_nextlinkid = 1;
	return (0);
}

void
dlmgmt_linktable_fini()
{
	dlmgmt_prefix_t	*lpp, *next;

	for (lpp = dlmgmt_prefixlist; lpp != NULL; lpp = next) {
		next = lpp->lp_next;
		free(lpp);
	}

	avl_destroy(&dlmgmt_dlconf_avl);
	avl_destroy(&dlmgmt_name_avl);
	avl_destroy(&dlmgmt_id_avl);
}

static int
linkattr_add(dlmgmt_linkattr_t **headp, dlmgmt_linkattr_t *attrp)
{
	if (*headp == NULL) {
		*headp = attrp;
	} else {
		(*headp)->lp_prev = attrp;
		attrp->lp_next = *headp;
		*headp = attrp;
	}
	return (0);
}

static int
linkattr_rm(dlmgmt_linkattr_t **headp, dlmgmt_linkattr_t *attrp)
{
	dlmgmt_linkattr_t *next, *prev;

	next = attrp->lp_next;
	prev = attrp->lp_prev;
	if (next != NULL)
		next->lp_prev = prev;
	if (prev != NULL)
		prev->lp_next = next;
	else
		*headp = next;

	return (0);
}

int
linkattr_set(dlmgmt_linkattr_t **headp, const char *attr, void *attrval,
    size_t attrsz, dladm_datatype_t type)
{
	dlmgmt_linkattr_t	*attrp;
	int			err;

	/*
	 * See whether the attr is already set.
	 */
	for (attrp = *headp; attrp != NULL; attrp = attrp->lp_next) {
		if (strcmp(attrp->lp_name, attr) == 0)
			break;
	}

	if (attrp != NULL) {
		/*
		 * It is already set.  If the value changed, update it.
		 */
		if (linkattr_equal(headp, attr, attrval, attrsz))
			return (0);

		free(attrp->lp_val);
	} else {
		/*
		 * It is not set yet, allocate the linkattr and prepend to the
		 * list.
		 */
		if ((attrp = calloc(1, sizeof (dlmgmt_linkattr_t))) == NULL)
			return (ENOMEM);

		if ((err = linkattr_add(headp, attrp)) != 0) {
			free(attrp);
			return (err);
		}
		(void) strlcpy(attrp->lp_name, attr, MAXLINKATTRLEN);
	}
	if ((attrp->lp_val = calloc(1, attrsz)) == NULL) {
		(void) linkattr_rm(headp, attrp);
		free(attrp);
		return (ENOMEM);
	}

	bcopy(attrval, attrp->lp_val, attrsz);
	attrp->lp_sz = attrsz;
	attrp->lp_type = type;
	attrp->lp_linkprop = dladm_attr_is_linkprop(attr);
	return (0);
}

int
linkattr_unset(dlmgmt_linkattr_t **headp, const char *attr)
{
	dlmgmt_linkattr_t	*attrp, *prev;

	/*
	 * See whether the attr exists.
	 */
	for (prev = NULL, attrp = *headp; attrp != NULL;
	    prev = attrp, attrp = attrp->lp_next) {
		if (strcmp(attrp->lp_name, attr) == 0)
			break;
	}

	/*
	 * This attribute is not set in the first place. Return success.
	 */
	if (attrp == NULL)
		return (0);

	/*
	 * Remove this attr from the list.
	 */
	if (prev == NULL)
		*headp = attrp->lp_next;
	else
		prev->lp_next = attrp->lp_next;

	free(attrp->lp_val);
	free(attrp);
	return (0);
}

int
linkattr_get(dlmgmt_linkattr_t **headp, const char *attr, void **attrvalp,
    size_t *attrszp, dladm_datatype_t *typep)
{
	dlmgmt_linkattr_t	*attrp = *headp;

	/*
	 * find the specific attr.
	 */
	for (attrp = *headp; attrp != NULL; attrp = attrp->lp_next) {
		if (strcmp(attrp->lp_name, attr) == 0)
			break;
	}

	if (attrp == NULL)
		return (ENOENT);

	*attrvalp = attrp->lp_val;
	*attrszp = attrp->lp_sz;
	if (typep != NULL)
		*typep = attrp->lp_type;
	return (0);
}

int
linkprop_getnext(dlmgmt_linkattr_t **headp, const char *lastattr,
    char **attrnamep, void **attrvalp, size_t *attrszp, dladm_datatype_t *typep)
{
	dlmgmt_linkattr_t	*attrp;

	/* skip to entry following lastattr or pick first if none specified */
	for (attrp = *headp; attrp != NULL; attrp = attrp->lp_next) {
		if (!attrp->lp_linkprop)
			continue;
		if (lastattr[0] == '\0')
			break;
		if (strcmp(attrp->lp_name, lastattr) == 0) {
			attrp = attrp->lp_next;
			break;
		}
	}
	if (attrp == NULL)
		return (ENOENT);

	*attrnamep = attrp->lp_name;
	*attrvalp = attrp->lp_val;
	*attrszp = attrp->lp_sz;
	*typep = attrp->lp_type;
	return (0);
}

boolean_t
linkattr_equal(dlmgmt_linkattr_t **headp, const char *attr, void *attrval,
    size_t attrsz)
{
	void	*saved_attrval;
	size_t	saved_attrsz;

	if (linkattr_get(headp, attr, &saved_attrval, &saved_attrsz, NULL) != 0)
		return (B_FALSE);

	return ((saved_attrsz == attrsz) &&
	    (memcmp(saved_attrval, attrval, attrsz) == 0));
}

static int
dlmgmt_table_readwritelock(boolean_t write)
{
	if (write)
		return (pthread_rwlock_trywrlock(&dlmgmt_avl_lock));
	else
		return (pthread_rwlock_tryrdlock(&dlmgmt_avl_lock));
}

void
dlmgmt_table_lock(boolean_t write)
{
	(void) pthread_mutex_lock(&dlmgmt_avl_mutex);
	while (dlmgmt_table_readwritelock(write) == EBUSY)
		(void) pthread_cond_wait(&dlmgmt_avl_cv, &dlmgmt_avl_mutex);

	(void) pthread_mutex_unlock(&dlmgmt_avl_mutex);
}

void
dlmgmt_table_unlock()
{
	(void) pthread_rwlock_unlock(&dlmgmt_avl_lock);
	(void) pthread_mutex_lock(&dlmgmt_avl_mutex);
	(void) pthread_cond_broadcast(&dlmgmt_avl_cv);
	(void) pthread_mutex_unlock(&dlmgmt_avl_mutex);
}

static int
link_create(const char *name, datalink_class_t class, uint32_t media,
    uint32_t flags, dlmgmt_link_t **linkpp)
{
	dlmgmt_link_t	*linkp = NULL;
	int		err = 0;

	if (dlmgmt_nextlinkid == DATALINK_INVALID_LINKID) {
		err = ENOSPC;
		goto done;
	}

	if ((linkp = calloc(1, sizeof (dlmgmt_link_t))) == NULL) {
		err = ENOMEM;
		goto done;
	}

	(void) strlcpy(linkp->ll_link, name, MAXLINKNAMELEN);
	linkp->ll_class = class;
	linkp->ll_media = media;
	linkp->ll_linkid = dlmgmt_nextlinkid;
	linkp->ll_flags = flags;
	linkp->ll_gen = 0;
done:
	*linkpp = linkp;
	return (err);
}

void
link_destroy(dlmgmt_link_t *linkp)
{
	dlmgmt_linkattr_t *next, *attrp;

	for (attrp = linkp->ll_head; attrp != NULL; attrp = next) {
		next = attrp->lp_next;
		free(attrp->lp_val);
		free(attrp);
	}
	free(linkp);
}

dlmgmt_link_t *
link_by_id(datalink_id_t linkid)
{
	dlmgmt_link_t	link;

	link.ll_linkid = linkid;
	return (avl_find(&dlmgmt_id_avl, &link, NULL));
}

dlmgmt_link_t *
link_by_name(const char *name)
{
	dlmgmt_link_t	link;

	(void) strlcpy(link.ll_link, name, MAXLINKNAMELEN);
	return (avl_find(&dlmgmt_name_avl, &link, NULL));
}

int
dlmgmt_create_common(const char *name, datalink_class_t class, uint32_t media,
    uint32_t flags, dlmgmt_link_t **linkpp)
{
	dlmgmt_link_t	link, *linkp, *tmp;
	avl_index_t	name_where, id_where;
	int		err;

	/*
	 * Validate the link.
	 */
	if (!dladm_valid_linkname(name))
		return (EINVAL);

	/*
	 * Check to see whether this is an existing link name.
	 */
	(void) strlcpy(link.ll_link, name, MAXLINKNAMELEN);
	if ((linkp = avl_find(&dlmgmt_name_avl, &link, &name_where)) != NULL)
		return (EEXIST);

	if ((err = link_create(name, class, media, flags, &linkp)) != 0)
		return (err);

	link.ll_linkid = linkp->ll_linkid;
	tmp = avl_find(&dlmgmt_id_avl, &link, &id_where);
	assert(tmp == NULL);
	avl_insert(&dlmgmt_name_avl, linkp, name_where);
	avl_insert(&dlmgmt_id_avl, linkp, id_where);
	dlmgmt_advance(linkp);
	*linkpp = linkp;
	return (0);
}

int
dlmgmt_destroy_common(dlmgmt_link_t *linkp, uint32_t flags)
{
	if ((linkp->ll_flags & flags) == 0) {
		/*
		 * The link does not exist in the specified space.
		 */
		return (ENOENT);
	}
	linkp->ll_flags &= ~flags;
	if (!(linkp->ll_flags & DLMGMT_PERSIST)) {
		dlmgmt_linkattr_t *next, *attrp;

		for (attrp = linkp->ll_head; attrp != NULL; attrp = next) {
			next = attrp->lp_next;
			free(attrp->lp_val);
			free(attrp);
		}
		linkp->ll_head = NULL;
	}

	if (linkp->ll_flags == 0) {
		avl_remove(&dlmgmt_id_avl, linkp);
		avl_remove(&dlmgmt_name_avl, linkp);
		link_destroy(linkp);
	}

	return (0);
}

void
dlmgmt_getattr_common(dlmgmt_linkattr_t **headp, const char *attr,
    dlmgmt_getattr_retval_t *retvalp)
{
	int			err;
	void			*attrval;
	size_t			attrsz;
	dladm_datatype_t	attrtype;

	err = linkattr_get(headp, attr, &attrval, &attrsz, &attrtype);
	if (err != 0)
		goto done;

	assert(attrsz > 0);
	if (attrsz > MAXLINKATTRVALLEN) {
		err = EINVAL;
		goto done;
	}

	retvalp->lr_type = attrtype;
	retvalp->lr_attrsz = attrsz;
	bcopy(attrval, retvalp->lr_attrval, attrsz);
done:
	retvalp->lr_err = err;
}

void
dlmgmt_dlconf_table_lock(boolean_t write)
{
	if (write)
		(void) pthread_rwlock_wrlock(&dlmgmt_dlconf_lock);
	else
		(void) pthread_rwlock_rdlock(&dlmgmt_dlconf_lock);
}

void
dlmgmt_dlconf_table_unlock()
{
	(void) pthread_rwlock_unlock(&dlmgmt_dlconf_lock);
}

int
dlconf_create(const char *name, datalink_id_t linkid, datalink_class_t class,
    uint32_t media, dlmgmt_dlconf_t **dlconfpp)
{
	dlmgmt_dlconf_t	*dlconfp = NULL;
	int		err = 0;

	if (dlmgmt_nextconfid == 0) {
		err = ENOSPC;
		goto done;
	}

	if ((dlconfp = calloc(1, sizeof (dlmgmt_dlconf_t))) == NULL) {
		err = ENOMEM;
		goto done;
	}

	(void) strlcpy(dlconfp->ld_link, name, MAXLINKNAMELEN);
	dlconfp->ld_linkid = linkid;
	dlconfp->ld_class = class;
	dlconfp->ld_media = media;
	dlconfp->ld_id = dlmgmt_nextconfid;

done:
	*dlconfpp = dlconfp;
	return (err);
}

void
dlconf_destroy(dlmgmt_dlconf_t *dlconfp)
{
	dlmgmt_linkattr_t *next, *attrp;

	for (attrp = dlconfp->ld_head; attrp != NULL; attrp = next) {
		next = attrp->lp_next;
		free(attrp->lp_val);
		free(attrp);
	}
	free(dlconfp);
}

int
dlmgmt_generate_name(const char *prefix, char *name, size_t size)
{
	dlmgmt_prefix_t	*lpp, *prev = NULL;

	/*
	 * See whether the requested prefix is already in the list.
	 */
	for (lpp = dlmgmt_prefixlist; lpp != NULL; prev = lpp,
	    lpp = lpp->lp_next) {
		if (strcmp(prefix, lpp->lp_prefix) == 0)
			break;
	}

	/*
	 * Not found.
	 */
	if (lpp == NULL) {
		dlmgmt_link_t		*linkp, link;

		assert(prev != NULL);

		/*
		 * First add this new prefix into the prefix list.
		 */
		if ((lpp = malloc(sizeof (dlmgmt_prefix_t))) == NULL)
			return (ENOMEM);

		prev->lp_next = lpp;
		lpp->lp_next = NULL;
		lpp->lp_nextppa = 0;
		(void) strlcpy(lpp->lp_prefix, prefix, MAXLINKNAMELEN);

		/*
		 * Now determine this prefix's nextppa.
		 */
		(void) snprintf(link.ll_link, MAXLINKNAMELEN, "%s%d",
		    prefix, lpp->lp_nextppa);
		linkp = avl_find(&dlmgmt_name_avl, &link, NULL);
		if (linkp != NULL)
			dlmgmt_advance_ppa(linkp);
	}

	if (lpp->lp_nextppa == (uint_t)-1)
		return (ENOSPC);

	(void) snprintf(name, size, "%s%d", prefix, lpp->lp_nextppa);
	return (0);
}

/*
 * Advance the next available ppa value if the name prefix of the current
 * link is in the prefix list.
 */
static void
dlmgmt_advance_ppa(dlmgmt_link_t *linkp)
{
	dlmgmt_prefix_t	*lpp;
	char		prefix[MAXLINKNAMELEN];
	uint_t		start, ppa;

	(void) dlpi_parselink(linkp->ll_link, prefix, &ppa);

	/*
	 * See whether the requested prefix is already in the list.
	 */
	for (lpp = dlmgmt_prefixlist; lpp != NULL; lpp = lpp->lp_next) {
		if (strcmp(prefix, lpp->lp_prefix) == 0)
			break;
	}

	/*
	 * If the link name prefix is in the list, advance the
	 * next available ppa for the <prefix>N name.
	 */
	if (lpp == NULL || lpp->lp_nextppa != ppa)
		return;

	start = lpp->lp_nextppa++;
	linkp = AVL_NEXT(&dlmgmt_name_avl, linkp);
	while (lpp->lp_nextppa != start) {
		if (lpp->lp_nextppa == (uint_t)-1) {
			dlmgmt_link_t	link;

			/*
			 * wrapped around. search from <prefix>1.
			 */
			lpp->lp_nextppa = 0;
			(void) snprintf(link.ll_link, MAXLINKNAMELEN,
			    "%s%d", lpp->lp_prefix, lpp->lp_nextppa);
			linkp = avl_find(&dlmgmt_name_avl, &link, NULL);
			if (linkp == NULL)
				return;
		} else {
			if (linkp == NULL)
				return;
			(void) dlpi_parselink(linkp->ll_link, prefix, &ppa);
			if ((strcmp(prefix, lpp->lp_prefix) != 0) ||
			    (ppa != lpp->lp_nextppa)) {
				return;
			}
		}
		linkp = AVL_NEXT(&dlmgmt_name_avl, linkp);
		lpp->lp_nextppa++;
	}
	lpp->lp_nextppa = (uint_t)-1;
}

/*
 * Advance to the next available linkid value.
 */
static void
dlmgmt_advance_linkid(dlmgmt_link_t *linkp)
{
	datalink_id_t	start;

	if (linkp->ll_linkid != dlmgmt_nextlinkid)
		return;

	start = dlmgmt_nextlinkid;
	linkp = AVL_NEXT(&dlmgmt_id_avl, linkp);

	do {
		if (dlmgmt_nextlinkid == DATALINK_MAX_LINKID) {
			dlmgmt_link_t	link;

			/*
			 * wrapped around. search from 1.
			 */
			dlmgmt_nextlinkid = 1;
			link.ll_linkid = 1;
			linkp = avl_find(&dlmgmt_id_avl, &link, NULL);
			if (linkp == NULL)
				return;
		} else {
			dlmgmt_nextlinkid++;
			if (linkp == NULL)
				return;
			if (linkp->ll_linkid != dlmgmt_nextlinkid)
				return;
		}

		linkp = AVL_NEXT(&dlmgmt_id_avl, linkp);
	} while (dlmgmt_nextlinkid != start);

	dlmgmt_nextlinkid = DATALINK_INVALID_LINKID;
}

/*
 * Advance various global values, for example, next linkid value, next ppa for
 * various prefix etc.
 */
void
dlmgmt_advance(dlmgmt_link_t *linkp)
{
	dlmgmt_advance_linkid(linkp);
	dlmgmt_advance_ppa(linkp);
}

/*
 * Advance to the next available dlconf id.
 */
void
dlmgmt_advance_dlconfid(dlmgmt_dlconf_t *dlconfp)
{
	uint_t	start;

	start = dlmgmt_nextconfid++;
	dlconfp = AVL_NEXT(&dlmgmt_dlconf_avl, dlconfp);
	while (dlmgmt_nextconfid != start) {
		if (dlmgmt_nextconfid == 0) {
			dlmgmt_dlconf_t	dlconf;

			/*
			 * wrapped around. search from 1.
			 */
			dlconf.ld_id = dlmgmt_nextconfid = 1;
			dlconfp = avl_find(&dlmgmt_name_avl, &dlconf, NULL);
			if (dlconfp == NULL)
				return;
		} else {
			if ((dlconfp == NULL) ||
			    (dlconfp->ld_id != dlmgmt_nextconfid)) {
				return;
			}
		}
		dlconfp = AVL_NEXT(&dlmgmt_name_avl, dlconfp);
		dlmgmt_nextconfid++;
	}
	dlmgmt_nextconfid = 0;
}
