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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fm/protocol.h>
#include <strings.h>
#include <alloca.h>

#include <fmd_alloc.h>
#include <fmd_string.h>
#include <fmd_dispq.h>
#include <fmd_eventq.h>
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
		fmd_module_rele(dlp->dq_mod);
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

	return (dqp);
}

void
fmd_dispq_destroy(fmd_dispq_t *dqp)
{
	fmd_dispqelem_destroy(dqp->dq_root);
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
fmd_dispq_insert(fmd_dispq_t *dqp, fmd_module_t *mp, const char *pattern)
{
	char *p, *q, *s = fmd_strdup(pattern, FMD_SLEEP);
	size_t len = strlen(s);

	fmd_dispqlist_t *dlp = fmd_alloc(sizeof (fmd_dispqlist_t), FMD_SLEEP);
	fmd_dispqelem_t *dep;

	fmd_module_hold(mp);

	(void) pthread_rwlock_wrlock(&dqp->dq_lock);
	dep = dqp->dq_root;

	for (p = strtok_r(s, ".", &q); p != NULL; p = strtok_r(NULL, ".", &q))
		dep = fmd_dispq_insert_one(dep, p);

	dlp->dq_next = dep->dq_list;
	dlp->dq_mod = mp;

	dep->dq_list = dlp;
	dep->dq_refs++;
	ASSERT(dep->dq_refs != 0);

	(void) pthread_rwlock_unlock(&dqp->dq_lock);
	fmd_free(s, len + 1);
}

static void
fmd_dispq_delete_one(fmd_dispqelem_t *dep,
    fmd_module_t *mp, int patc, char *patv[])
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
		fmd_dispq_delete_one(ep, mp, patc - 1, patv + 1);
	} else {
		for (lp = *lpp; lp != NULL; lp = lp->dq_next) {
			if (lp->dq_mod != mp)
				lpp = &lp->dq_next;
			else
				break;
		}

		ASSERT(lp != NULL);
		*lpp = lp->dq_next;

		fmd_module_rele(lp->dq_mod);
		fmd_free(lp, sizeof (fmd_dispqlist_t));

		ASSERT(ep->dq_refs != 0);
		ep->dq_refs--;
	}

	if (ep->dq_refs == 0) {
		*epp = ep->dq_link;
		fmd_dispqelem_destroy(ep);
		ASSERT(dep->dq_refs != 0);
		dep->dq_refs--;
	}
}

void
fmd_dispq_delete(fmd_dispq_t *dqp, fmd_module_t *mp, const char *pattern)
{
	char *p, *q, *s = fmd_strdup(pattern, FMD_SLEEP);
	size_t len = strlen(s);

	char **patv = fmd_zalloc(sizeof (char *) * (len / 2 + 1), FMD_SLEEP);
	int patc = 0;

	for (p = strtok_r(s, ".", &q); p != NULL; p = strtok_r(NULL, ".", &q))
		patv[patc++] = p;

	if (patc != 0) {
		(void) pthread_rwlock_wrlock(&dqp->dq_lock);
		fmd_dispq_delete_one(dqp->dq_root, mp, patc, patv);
		(void) pthread_rwlock_unlock(&dqp->dq_lock);
	}

	fmd_free(patv, sizeof (char *) * (len / 2 + 1));
	fmd_free(s, len + 1);
}

static uint_t
fmd_dispq_dispatch_one(fmd_dispqelem_t *dep, fmd_event_t *ep, const char *class)
{
	fmd_dispqlist_t *dlp;
	uint_t n = 0;

	for (dlp = dep->dq_list; dlp != NULL; dlp = dlp->dq_next, n++) {
		TRACE((FMD_DBG_DISP, "queue %p (%s) for %s",
		    (void *)ep, class, dlp->dq_mod->mod_name));

		fmd_eventq_insert_at_time(dlp->dq_mod->mod_queue, ep);
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
fmd_dispq_dispatchv(fmd_dispqelem_t *root,
    fmd_event_t *ep, const char *class, uint_t cc, char *cv[])
{
	fmd_dispqelem_t *dep;
	uint_t n = 0;

	if (cc == 0)
		return (fmd_dispq_dispatch_one(root, ep, class));

	if ((dep = fmd_dispqelem_lookup(root, cv[0])) != NULL)
		n += fmd_dispq_dispatchv(dep, ep, class, cc - 1, cv + 1);

	if ((dep = fmd_dispqelem_lookup(root, "*")) != NULL)
		n += fmd_dispq_dispatchv(dep, ep, class, cc - 1, cv + 1);

	if (dep != NULL && cc > 1)
		n += fmd_dispq_dispatch_one(dep, ep, class);

	return (n);
}

void
fmd_dispq_dispatch(fmd_dispq_t *dqp, fmd_event_t *ep, const char *class)
{
	fmd_event_impl_t *eip = (fmd_event_impl_t *)ep;
	char *p, *q, *s, **cv;
	uint_t n, len, cc;

	nvlist_t **nvp;
	uint_t nvc = 0;

	fmd_event_hold(ep);

	/*
	 * If the event is a protocol list.suspect event with one or more
	 * events contained inside of it, we call fmd_dispq_dispatch()
	 * recursively using the class string of the embedded event.
	 */
	if (eip->ev_type == FMD_EVT_PROTOCOL && strcmp(class,
	    FM_LIST_SUSPECT_CLASS) == 0 && nvlist_lookup_nvlist_array(
	    eip->ev_nvl, FM_SUSPECT_FAULT_LIST, &nvp, &nvc) == 0 && nvc != 0) {
		while (nvc-- != 0) {
			if (nvlist_lookup_string(*nvp++, FM_CLASS, &p) == 0)
				fmd_dispq_dispatch(dqp, ep, p);
		}
	}

	/*
	 * Once we've handled any recursive invocations, grab the dispatch
	 * queue lock and walk down the dispatch queue hashes posting the event
	 * for each subscriber.  If the total subscribers (n) is zero, send
	 * the event by default to the self-diagnosis module for handling.
	 */
	len = strlen(class);
	s = alloca(len + 1);
	(void) strcpy(s, class);

	cv = alloca(sizeof (char *) * (len / 2 + 1));
	cc = 0;

	for (p = strtok_r(s, ".", &q); p != NULL; p = strtok_r(NULL, ".", &q))
		cv[cc++] = p;

	(void) pthread_rwlock_rdlock(&dqp->dq_lock);
	n = fmd_dispq_dispatchv(dqp->dq_root, ep, class, cc, cv);
	(void) pthread_rwlock_unlock(&dqp->dq_lock);

	fmd_dprintf(FMD_DBG_DISP, "%s dispatched to %u modules\n", class, n);

	if (n == 0 && fmd.d_self != NULL)
		fmd_eventq_insert_at_time(fmd.d_self->mod_queue, ep);

	fmd_event_rele(ep);
}
