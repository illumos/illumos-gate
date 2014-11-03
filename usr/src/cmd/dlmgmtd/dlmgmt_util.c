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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011, Joyent Inc. All rights reserved.
 */

/*
 * Utility functions used by the dlmgmtd daemon.
 */

#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <zone.h>
#include <errno.h>
#include <libdlpi.h>
#include "dlmgmt_impl.h"

/*
 * There are three datalink AVL tables.  The dlmgmt_name_avl tree contains all
 * datalinks and is keyed by zoneid and link name.  The dlmgmt_id_avl also
 * contains all datalinks, and it is keyed by link ID.
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
	zoneid_t		lp_zoneid;
	uint_t			lp_nextppa;
} dlmgmt_prefix_t;
static dlmgmt_prefix_t	dlmgmt_prefixlist;

datalink_id_t		dlmgmt_nextlinkid;
static datalink_id_t	dlmgmt_nextconfid = 1;

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

/*
 * Note that the zoneid associated with a link is effectively part of its
 * name.  This is essentially what results in having each zone have disjoint
 * datalink namespaces.
 */
static int
cmp_link_by_zname(const void *v1, const void *v2)
{
	const dlmgmt_link_t *link1 = v1;
	const dlmgmt_link_t *link2 = v2;

	if (link1->ll_zoneid < link2->ll_zoneid)
		return (-1);
	if (link1->ll_zoneid > link2->ll_zoneid)
		return (1);
	return (cmp_link_by_name(link1, link2));
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

void
dlmgmt_linktable_init(void)
{
	/*
	 * Initialize the prefix list. First add the "net" prefix for the
	 * global zone to the list.
	 */
	dlmgmt_prefixlist.lp_next = NULL;
	dlmgmt_prefixlist.lp_zoneid = GLOBAL_ZONEID;
	dlmgmt_prefixlist.lp_nextppa = 0;
	(void) strlcpy(dlmgmt_prefixlist.lp_prefix, "net", MAXLINKNAMELEN);

	avl_create(&dlmgmt_name_avl, cmp_link_by_zname, sizeof (dlmgmt_link_t),
	    offsetof(dlmgmt_link_t, ll_name_node));
	avl_create(&dlmgmt_id_avl, cmp_link_by_id, sizeof (dlmgmt_link_t),
	    offsetof(dlmgmt_link_t, ll_id_node));
	avl_create(&dlmgmt_dlconf_avl, cmp_dlconf_by_id,
	    sizeof (dlmgmt_dlconf_t), offsetof(dlmgmt_dlconf_t, ld_node));
	dlmgmt_nextlinkid = 1;
}

void
dlmgmt_linktable_fini(void)
{
	dlmgmt_prefix_t *lpp, *next;

	for (lpp = dlmgmt_prefixlist.lp_next; lpp != NULL; lpp = next) {
		next = lpp->lp_next;
		free(lpp);
	}

	avl_destroy(&dlmgmt_dlconf_avl);
	avl_destroy(&dlmgmt_name_avl);
	avl_destroy(&dlmgmt_id_avl);
}

static void
linkattr_add(dlmgmt_linkattr_t **headp, dlmgmt_linkattr_t *attrp)
{
	if (*headp == NULL) {
		*headp = attrp;
	} else {
		(*headp)->lp_prev = attrp;
		attrp->lp_next = *headp;
		*headp = attrp;
	}
}

static void
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
}

dlmgmt_linkattr_t *
linkattr_find(dlmgmt_linkattr_t *headp, const char *attr)
{
	dlmgmt_linkattr_t *attrp;

	for (attrp = headp; attrp != NULL; attrp = attrp->lp_next) {
		if (strcmp(attrp->lp_name, attr) == 0)
			break;
	}
	return (attrp);
}

int
linkattr_set(dlmgmt_linkattr_t **headp, const char *attr, void *attrval,
    size_t attrsz, dladm_datatype_t type)
{
	dlmgmt_linkattr_t	*attrp;
	void			*newval;
	boolean_t		new;

	attrp = linkattr_find(*headp, attr);
	if (attrp != NULL) {
		/*
		 * It is already set.  If the value changed, update it.
		 */
		if (linkattr_equal(headp, attr, attrval, attrsz))
			return (0);
		new = B_FALSE;
	} else {
		/*
		 * It is not set yet, allocate the linkattr and prepend to the
		 * list.
		 */
		if ((attrp = calloc(1, sizeof (dlmgmt_linkattr_t))) == NULL)
			return (ENOMEM);

		(void) strlcpy(attrp->lp_name, attr, MAXLINKATTRLEN);
		new = B_TRUE;
	}
	if ((newval = calloc(1, attrsz)) == NULL) {
		if (new)
			free(attrp);
		return (ENOMEM);
	}

	if (!new)
		free(attrp->lp_val);
	attrp->lp_val = newval;
	bcopy(attrval, attrp->lp_val, attrsz);
	attrp->lp_sz = attrsz;
	attrp->lp_type = type;
	attrp->lp_linkprop = dladm_attr_is_linkprop(attr);
	if (new)
		linkattr_add(headp, attrp);
	return (0);
}

void
linkattr_unset(dlmgmt_linkattr_t **headp, const char *attr)
{
	dlmgmt_linkattr_t *attrp;

	if ((attrp = linkattr_find(*headp, attr)) != NULL) {
		linkattr_rm(headp, attrp);
		free(attrp->lp_val);
		free(attrp);
	}
}

int
linkattr_get(dlmgmt_linkattr_t **headp, const char *attr, void **attrvalp,
    size_t *attrszp, dladm_datatype_t *typep)
{
	dlmgmt_linkattr_t *attrp;

	if ((attrp = linkattr_find(*headp, attr)) == NULL)
		return (ENOENT);

	*attrvalp = attrp->lp_val;
	*attrszp = attrp->lp_sz;
	if (typep != NULL)
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

void
linkattr_destroy(dlmgmt_link_t *linkp)
{
	dlmgmt_linkattr_t *next, *attrp;

	for (attrp = linkp->ll_head; attrp != NULL; attrp = next) {
		next = attrp->lp_next;
		free(attrp->lp_val);
		free(attrp);
	}
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
dlmgmt_table_unlock(void)
{
	(void) pthread_rwlock_unlock(&dlmgmt_avl_lock);
	(void) pthread_mutex_lock(&dlmgmt_avl_mutex);
	(void) pthread_cond_broadcast(&dlmgmt_avl_cv);
	(void) pthread_mutex_unlock(&dlmgmt_avl_mutex);
}

void
link_destroy(dlmgmt_link_t *linkp)
{
	linkattr_destroy(linkp);
	free(linkp);
}

/*
 * Set the DLMGMT_ACTIVE flag on the link to note that it is active.  When a
 * link becomes active and it belongs to a non-global zone, it is also added
 * to that zone.
 */
int
link_activate(dlmgmt_link_t *linkp)
{
	int		err = 0;
	zoneid_t	zoneid = ALL_ZONES;

	if (zone_check_datalink(&zoneid, linkp->ll_linkid) == 0) {
		/*
		 * This link was already added to a non-global zone.  This can
		 * happen if dlmgmtd is restarted.
		 */
		if (zoneid != linkp->ll_zoneid) {
			if (link_by_name(linkp->ll_link, zoneid) != NULL) {
				err = EEXIST;
				goto done;
			}

			if (avl_find(&dlmgmt_name_avl, linkp, NULL) != NULL)
				avl_remove(&dlmgmt_name_avl, linkp);

			linkp->ll_zoneid = zoneid;
			avl_add(&dlmgmt_name_avl, linkp);
			linkp->ll_onloan = B_TRUE;
		}
	} else if (linkp->ll_zoneid != GLOBAL_ZONEID) {
		err = zone_add_datalink(linkp->ll_zoneid, linkp->ll_linkid);
	}
done:
	if (err == 0)
		linkp->ll_flags |= DLMGMT_ACTIVE;
	return (err);
}

/*
 * Is linkp visible from the caller's zoneid?  It is if the link is in the
 * same zone as the caller, or if the caller is in the global zone and the
 * link is on loan to a non-global zone.
 */
boolean_t
link_is_visible(dlmgmt_link_t *linkp, zoneid_t zoneid)
{
	return (linkp->ll_zoneid == zoneid ||
	    (zoneid == GLOBAL_ZONEID && linkp->ll_onloan));
}

dlmgmt_link_t *
link_by_id(datalink_id_t linkid, zoneid_t zoneid)
{
	dlmgmt_link_t link, *linkp;

	link.ll_linkid = linkid;
	if ((linkp = avl_find(&dlmgmt_id_avl, &link, NULL)) == NULL)
		return (NULL);
	if (zoneid != GLOBAL_ZONEID && linkp->ll_zoneid != zoneid)
		return (NULL);
	return (linkp);
}

dlmgmt_link_t *
link_by_name(const char *name, zoneid_t zoneid)
{
	dlmgmt_link_t	link, *linkp;

	(void) strlcpy(link.ll_link, name, MAXLINKNAMELEN);
	link.ll_zoneid = zoneid;
	linkp = avl_find(&dlmgmt_name_avl, &link, NULL);
	return (linkp);
}

int
dlmgmt_create_common(const char *name, datalink_class_t class, uint32_t media,
    zoneid_t zoneid, uint32_t flags, dlmgmt_link_t **linkpp)
{
	dlmgmt_link_t	*linkp = NULL;
	avl_index_t	name_where, id_where;
	int		err = 0;

	if (!dladm_valid_linkname(name))
		return (EINVAL);
	if (dlmgmt_nextlinkid == DATALINK_INVALID_LINKID)
		return (ENOSPC);

	if ((linkp = calloc(1, sizeof (dlmgmt_link_t))) == NULL) {
		err = ENOMEM;
		goto done;
	}

	(void) strlcpy(linkp->ll_link, name, MAXLINKNAMELEN);
	linkp->ll_class = class;
	linkp->ll_media = media;
	linkp->ll_linkid = dlmgmt_nextlinkid;
	linkp->ll_zoneid = zoneid;
	linkp->ll_gen = 0;
	linkp->ll_tomb = B_FALSE;

	if (avl_find(&dlmgmt_name_avl, linkp, &name_where) != NULL ||
	    avl_find(&dlmgmt_id_avl, linkp, &id_where) != NULL) {
		err = EEXIST;
		goto done;
	}

	avl_insert(&dlmgmt_name_avl, linkp, name_where);
	avl_insert(&dlmgmt_id_avl, linkp, id_where);

	if ((flags & DLMGMT_ACTIVE) && (err = link_activate(linkp)) != 0) {
		avl_remove(&dlmgmt_name_avl, linkp);
		avl_remove(&dlmgmt_id_avl, linkp);
		goto done;
	}

	linkp->ll_flags = flags;
	dlmgmt_advance(linkp);
	*linkpp = linkp;

done:
	if (err != 0)
		free(linkp);
	return (err);
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
	if (flags & DLMGMT_PERSIST) {
		dlmgmt_linkattr_t *next, *attrp;

		for (attrp = linkp->ll_head; attrp != NULL; attrp = next) {
			next = attrp->lp_next;
			free(attrp->lp_val);
			free(attrp);
		}
		linkp->ll_head = NULL;
	}

	if ((flags & DLMGMT_ACTIVE) && linkp->ll_zoneid != GLOBAL_ZONEID) {
		(void) zone_remove_datalink(linkp->ll_zoneid, linkp->ll_linkid);
	}

	if (linkp->ll_flags == 0) {
		avl_remove(&dlmgmt_id_avl, linkp);
		avl_remove(&dlmgmt_name_avl, linkp);
		link_destroy(linkp);
	}

	return (0);
}

int
dlmgmt_getattr_common(dlmgmt_linkattr_t **headp, const char *attr,
    dlmgmt_getattr_retval_t *retvalp)
{
	int			err;
	void			*attrval;
	size_t			attrsz;
	dladm_datatype_t	attrtype;

	err = linkattr_get(headp, attr, &attrval, &attrsz, &attrtype);
	if (err != 0)
		return (err);

	assert(attrsz > 0);
	if (attrsz > MAXLINKATTRVALLEN)
		return (EINVAL);

	retvalp->lr_type = attrtype;
	retvalp->lr_attrsz = attrsz;
	bcopy(attrval, retvalp->lr_attrval, attrsz);
	return (0);
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
dlmgmt_dlconf_table_unlock(void)
{
	(void) pthread_rwlock_unlock(&dlmgmt_dlconf_lock);
}

int
dlconf_create(const char *name, datalink_id_t linkid, datalink_class_t class,
    uint32_t media, zoneid_t zoneid, dlmgmt_dlconf_t **dlconfpp)
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
	dlconfp->ld_zoneid = zoneid;

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
dlmgmt_generate_name(const char *prefix, char *name, size_t size,
    zoneid_t zoneid)
{
	dlmgmt_prefix_t	*lpp, *prev = NULL;
	dlmgmt_link_t	link, *linkp;

	/*
	 * See whether the requested prefix is already in the list.
	 */
	for (lpp = &dlmgmt_prefixlist; lpp != NULL;
	    prev = lpp, lpp = lpp->lp_next) {
		if (lpp->lp_zoneid == zoneid &&
		    strcmp(prefix, lpp->lp_prefix) == 0)
			break;
	}

	/*
	 * Not found.
	 */
	if (lpp == NULL) {
		assert(prev != NULL);

		/*
		 * First add this new prefix into the prefix list.
		 */
		if ((lpp = malloc(sizeof (dlmgmt_prefix_t))) == NULL)
			return (ENOMEM);

		prev->lp_next = lpp;
		lpp->lp_next = NULL;
		lpp->lp_zoneid = zoneid;
		lpp->lp_nextppa = 0;
		(void) strlcpy(lpp->lp_prefix, prefix, MAXLINKNAMELEN);

		/*
		 * Now determine this prefix's nextppa.
		 */
		(void) snprintf(link.ll_link, MAXLINKNAMELEN, "%s%d",
		    prefix, 0);
		link.ll_zoneid = zoneid;
		if ((linkp = avl_find(&dlmgmt_name_avl, &link, NULL)) != NULL)
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
	char		linkname[MAXLINKNAMELEN];
	uint_t		start, ppa;

	(void) dlpi_parselink(linkp->ll_link, prefix, &ppa);

	/*
	 * See whether the requested prefix is already in the list.
	 */
	for (lpp = &dlmgmt_prefixlist; lpp != NULL; lpp = lpp->lp_next) {
		if (lpp->lp_zoneid == linkp->ll_zoneid &&
		    strcmp(prefix, lpp->lp_prefix) == 0)
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
			/*
			 * wrapped around. search from <prefix>1.
			 */
			lpp->lp_nextppa = 0;
			(void) snprintf(linkname, MAXLINKNAMELEN,
			    "%s%d", lpp->lp_prefix, lpp->lp_nextppa);
			linkp = link_by_name(linkname, lpp->lp_zoneid);
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
			/*
			 * wrapped around. search from 1.
			 */
			dlmgmt_nextlinkid = 1;
			if ((linkp = link_by_id(1, GLOBAL_ZONEID)) == NULL)
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
			dlconfp = avl_find(&dlmgmt_dlconf_avl, &dlconf, NULL);
			if (dlconfp == NULL)
				return;
		} else {
			if ((dlconfp == NULL) ||
			    (dlconfp->ld_id != dlmgmt_nextconfid)) {
				return;
			}
		}
		dlconfp = AVL_NEXT(&dlmgmt_dlconf_avl, dlconfp);
		dlmgmt_nextconfid++;
	}
	dlmgmt_nextconfid = 0;
}
