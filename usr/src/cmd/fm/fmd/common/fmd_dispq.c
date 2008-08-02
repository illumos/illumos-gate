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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fm/protocol.h>
#include <sys/bitmap.h>

#include <strings.h>
#include <limits.h>
#include <alloca.h>

#include <fmd_alloc.h>
#include <fmd_string.h>
#include <fmd_module.h>
#include <fmd_dispq.h>
#include <fmd_subr.h>

#include <fmd.h>

static fmd_dispqelem_t *
fmd_dispqelem_create(const char *name)
{
	fmd_dispqelem_t *dep = fmd_alloc(sizeof (fmd_dispqelem_t), FMD_SLEEP);

	dep->dq_name = fmd_strdup(name, FMD_SLEEP);
	dep->dq_link = NULL;
	dep->dq_hashlen = fmd.d_str_buckets;
	dep->dq_hash = fmd_zalloc(sizeof (void *) * dep->dq_hashlen, FMD_SLEEP);
	dep->dq_list = NULL;
	dep->dq_refs = 0;

	return (dep);
}

static void
fmd_dispqelem_destroy(fmd_dispqelem_t *dep)
{
	fmd_dispqlist_t *dlp, *nlp;
	fmd_dispqelem_t *p, *q;
	uint_t i;

	for (dlp = dep->dq_list; dlp != NULL; dlp = nlp) {
		nlp = dlp->dq_next;
		fmd_free(dlp, sizeof (fmd_dispqlist_t));
	}

	for (i = 0; i < dep->dq_hashlen; i++) {
		for (p = dep->dq_hash[i]; p != NULL; p = q) {
			q = p->dq_link;
			fmd_dispqelem_destroy(p);
		}
	}

	fmd_free(dep->dq_hash, sizeof (void *) * dep->dq_hashlen);
	fmd_strfree(dep->dq_name);

	fmd_free(dep, sizeof (fmd_dispqelem_t));
}

static fmd_dispqelem_t *
fmd_dispqelem_lookup(fmd_dispqelem_t *dep, const char *name)
{
	uint_t h = fmd_strhash(name) % dep->dq_hashlen;

	for (dep = dep->dq_hash[h]; dep != NULL; dep = dep->dq_link) {
		if (strcmp(dep->dq_name, name) == 0)
			break;
	}

	return (dep);
}

fmd_dispq_t *
fmd_dispq_create(void)
{
	fmd_dispq_t *dqp = fmd_alloc(sizeof (fmd_dispq_t), FMD_SLEEP);

	(void) pthread_rwlock_init(&dqp->dq_lock, NULL);
	dqp->dq_root = fmd_dispqelem_create(NULL);
	dqp->dq_gids = fmd_idspace_create("dispq_gids", 1, INT_MAX);
	dqp->dq_gmax = 0;

	return (dqp);
}

void
fmd_dispq_destroy(fmd_dispq_t *dqp)
{
	fmd_dispqelem_destroy(dqp->dq_root);
	fmd_idspace_destroy(dqp->dq_gids);
	fmd_free(dqp, sizeof (fmd_dispq_t));
}

static fmd_dispqelem_t *
fmd_dispq_insert_one(fmd_dispqelem_t *dep, const char *name)
{
	uint_t h = fmd_strhash(name) % dep->dq_hashlen;
	fmd_dispqelem_t *ep;

	for (ep = dep->dq_hash[h]; ep != NULL; ep = ep->dq_link) {
		if (strcmp(ep->dq_name, name) == 0)
			break;
	}

	if (ep == NULL) {
		ep = fmd_dispqelem_create(name);

		ep->dq_link = dep->dq_hash[h];
		dep->dq_hash[h] = ep;

		dep->dq_refs++;
		ASSERT(dep->dq_refs != 0);
	}

	return (ep);
}

void
fmd_dispq_insert(fmd_dispq_t *dqp, fmd_eventq_t *eqp, const char *pattern)
{
	char *p, *q, *s = fmd_strdup(pattern, FMD_SLEEP);
	size_t len = strlen(s);

	fmd_dispqlist_t *dlp = fmd_alloc(sizeof (fmd_dispqlist_t), FMD_SLEEP);
	fmd_dispqelem_t *dep;

	(void) pthread_rwlock_wrlock(&dqp->dq_lock);
	dep = dqp->dq_root;

	for (p = strtok_r(s, ".", &q); p != NULL; p = strtok_r(NULL, ".", &q))
		dep = fmd_dispq_insert_one(dep, p);

	dlp->dq_next = dep->dq_list;
	dlp->dq_eventq = eqp;

	dep->dq_list = dlp;
	dep->dq_refs++;
	ASSERT(dep->dq_refs != 0);

	(void) pthread_rwlock_unlock(&dqp->dq_lock);
	fmd_free(s, len + 1);
}

static void
fmd_dispq_delete_one(fmd_dispqelem_t *dep,
    fmd_eventq_t *eqp, int patc, char *patv[])
{
	fmd_dispqlist_t *lp, **lpp;
	fmd_dispqelem_t *ep, **epp;

	uint_t h = fmd_strhash(patv[0]) % dep->dq_hashlen;
	epp = &dep->dq_hash[h];

	for (ep = *epp; ep != NULL; ep = ep->dq_link) {
		if (strcmp(ep->dq_name, patv[0]) != 0)
			epp = &ep->dq_link;
		else
			break;
	}

	ASSERT(ep != NULL);
	lpp = &ep->dq_list;

	if (patc > 1) {
		fmd_dispq_delete_one(ep, eqp, patc - 1, patv + 1);
	} else {
		for (lp = *lpp; lp != NULL; lp = lp->dq_next) {
			if (lp->dq_eventq != eqp)
				lpp = &lp->dq_next;
			else
				break;
		}

		if (lp != NULL) {
			*lpp = lp->dq_next;
			fmd_free(lp, sizeof (fmd_dispqlist_t));
			ASSERT(ep->dq_refs != 0);
			ep->dq_refs--;
		}
	}

	if (ep->dq_refs == 0) {
		*epp = ep->dq_link;
		fmd_dispqelem_destroy(ep);
		ASSERT(dep->dq_refs != 0);
		dep->dq_refs--;
	}
}

void
fmd_dispq_delete(fmd_dispq_t *dqp, fmd_eventq_t *eqp, const char *pattern)
{
	char *p, *q, *s = fmd_strdup(pattern, FMD_SLEEP);
	size_t len = strlen(s);

	char **patv = fmd_zalloc(sizeof (char *) * (len / 2 + 1), FMD_SLEEP);
	int patc = 0;

	for (p = strtok_r(s, ".", &q); p != NULL; p = strtok_r(NULL, ".", &q))
		patv[patc++] = p;

	if (patc != 0) {
		(void) pthread_rwlock_wrlock(&dqp->dq_lock);
		fmd_dispq_delete_one(dqp->dq_root, eqp, patc, patv);
		(void) pthread_rwlock_unlock(&dqp->dq_lock);
	}

	fmd_free(patv, sizeof (char *) * (len / 2 + 1));
	fmd_free(s, len + 1);
}

static uint_t
fmd_dispq_dispatch_one(fmd_dispqelem_t *dep, ulong_t *gids,
    fmd_event_t *ep, const char *class)
{
	fmd_dispqlist_t *dlp;
	uint_t n = 0;

	for (dlp = dep->dq_list; dlp != NULL; dlp = dlp->dq_next, n++) {
		id_t gid = dlp->dq_eventq->eq_sgid;

		if (BT_TEST(gids, gid) != 0)
			continue; /* event already queued for this group ID */

		TRACE((FMD_DBG_DISP, "queue %p (%s) for %s (%d)", (void *)ep,
		    class, dlp->dq_eventq->eq_mod->mod_name, (int)gid));

		fmd_eventq_insert_at_time(dlp->dq_eventq, ep);
		BT_SET(gids, gid);
	}

	return (n);
}

/*
 * This function handles the descent of the dispatch queue hash tree on behalf
 * of fmd_dispq_dispatch().  We recursively descend the tree along two paths:
 * one using the next component of the split class string (stored in cv[0]) and
 * one using the wildcard "*" in place of cv[0].  If we can't find either one,
 * our descent stops.  If we descend far enough to consume cv[] (i.e. cc == 0),
 * then we have a match and we dispatch the event to all modules at that level.
 * We also dispatch the event to modules found at any interior "*" element,
 * allowing a subscription to "a.*" to match "a.b", "a.b.c", and so on.
 */
static uint_t
fmd_dispq_dispatchv(fmd_dispqelem_t *root, ulong_t *gids,
    fmd_event_t *ep, const char *class, uint_t cc, char *cv[])
{
	fmd_dispqelem_t *dep;
	uint_t n = 0;

	if (cc == 0)
		return (fmd_dispq_dispatch_one(root, gids, ep, class));

	if ((dep = fmd_dispqelem_lookup(root, cv[0])) != NULL)
		n += fmd_dispq_dispatchv(dep, gids, ep, class, cc - 1, cv + 1);

	if ((dep = fmd_dispqelem_lookup(root, "*")) != NULL)
		n += fmd_dispq_dispatchv(dep, gids, ep, class, cc - 1, cv + 1);

	if (dep != NULL && cc > 1)
		n += fmd_dispq_dispatch_one(dep, gids, ep, class);

	return (n);
}

static uint_t
fmd_dispq_tokenize(const char *class,
    char *buf, size_t buflen, char **cv, uint_t cvlen)
{
	uint_t cc = 0;
	char *p, *q;

	(void) strlcpy(buf, class, buflen);

	for (p = strtok_r(buf, ".", &q); p != NULL; p = strtok_r(NULL, ".", &q))
		cv[cc++] = p;

	if (cc > cvlen)
		fmd_panic("fmd_dispq_tokenize() cc=%u > cv[%u]\n", cc, cvlen);

	return (cc);
}

void
fmd_dispq_dispatch_gid(fmd_dispq_t *dqp,
    fmd_event_t *ep, const char *class, id_t gid)
{
	size_t cvbuflen = strlen(class) + 1;
	uint_t cc, cvlen, n = 0;
	char *c, *cvbuf, **cv;

	ulong_t *gids;
	uint_t glen, i;

	nvlist_t **nva;
	uint_t nvi, nvc = 0;

	fmd_event_hold(ep);

	/*
	 * If the event is a protocol list.suspect event with one or more
	 * events contained inside of it, determine the maximum length of all
	 * class strings that will be used in this dispatch operation.
	 */
	if (FMD_EVENT_TYPE(ep) == FMD_EVT_PROTOCOL &&
	    (strcmp(class, FM_LIST_SUSPECT_CLASS) == 0 ||
	    strcmp(class, FM_LIST_REPAIRED_CLASS) == 0 ||
	    strcmp(class, FM_LIST_UPDATED_CLASS) == 0) &&
	    nvlist_lookup_nvlist_array(FMD_EVENT_NVL(ep), FM_SUSPECT_FAULT_LIST,
	    &nva, &nvc) == 0) {
		for (nvi = 0; nvi < nvc; nvi++) {
			if (nvlist_lookup_string(nva[nvi], FM_CLASS, &c) == 0) {
				size_t len = strlen(c) + 1;
				cvbuflen = MAX(cvbuflen, len);
			}
		}
	}

	cvbuf = alloca(cvbuflen);
	cvlen = cvbuflen / 2 + 1;
	cv = alloca(sizeof (char *) * cvlen);

	/*
	 * With dq_lock held as reader, allocate a bitmap on the stack for
	 * group IDs for this dispatch, zero it, and then do the dispatch.
	 */
	(void) pthread_rwlock_rdlock(&dqp->dq_lock);

	glen = BT_BITOUL(dqp->dq_gmax);
	gids = alloca(sizeof (ulong_t) * glen);
	bzero(gids, sizeof (ulong_t) * glen);

	/*
	 * If we are dispatching to only a single gid, set all bits in the
	 * group IDs mask and then clear only the bit for the specified gid.
	 */
	if (gid >= 0) {
		for (i = 0; i < glen; i++)
			gids[i] = BT_ULMAXMASK;
		BT_CLEAR(gids, gid);
	}

	for (nvi = 0; nvi < nvc; nvi++) {
		if (nvlist_lookup_string(nva[nvi], FM_CLASS, &c) == 0) {
			cc = fmd_dispq_tokenize(c, cvbuf, cvbuflen, cv, cvlen);
			n += fmd_dispq_dispatchv(dqp->dq_root,
			    gids, ep, c, cc, cv);
		}
	}

	cc = fmd_dispq_tokenize(class, cvbuf, cvbuflen, cv, cvlen);
	n += fmd_dispq_dispatchv(dqp->dq_root, gids, ep, class, cc, cv);

	(void) pthread_rwlock_unlock(&dqp->dq_lock);
	fmd_dprintf(FMD_DBG_DISP, "%s dispatched to %u queues\n", class, n);

	/*
	 * If the total subscriptions matched (n) was zero and we're not being
	 * called for a single gid, send the event to the self-diagnosis module.
	 */
	if (n == 0 && gid < 0 && fmd.d_self != NULL)
		fmd_eventq_insert_at_time(fmd.d_self->mod_queue, ep);

	fmd_event_rele(ep);
}

void
fmd_dispq_dispatch(fmd_dispq_t *dqp, fmd_event_t *ep, const char *class)
{
	fmd_dispq_dispatch_gid(dqp, ep, class, -1);
}

id_t
fmd_dispq_getgid(fmd_dispq_t *dqp, void *cookie)
{
	id_t gid;

	(void) pthread_rwlock_wrlock(&dqp->dq_lock);

	gid = fmd_idspace_alloc_min(dqp->dq_gids, cookie);
	dqp->dq_gmax = MAX(dqp->dq_gmax, gid);

	(void) pthread_rwlock_unlock(&dqp->dq_lock);

	return (gid);
}

void
fmd_dispq_delgid(fmd_dispq_t *dqp, id_t gid)
{
	(void) pthread_rwlock_wrlock(&dqp->dq_lock);

	ASSERT(fmd_idspace_contains(dqp->dq_gids, gid));
	(void) fmd_idspace_free(dqp->dq_gids, gid);

	(void) pthread_rwlock_unlock(&dqp->dq_lock);
}
