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
#include <uuid/uuid.h>
#include <alloca.h>

#include <fmd_alloc.h>
#include <fmd_module.h>
#include <fmd_error.h>
#include <fmd_conf.h>
#include <fmd_case.h>
#include <fmd_string.h>
#include <fmd_subr.h>
#include <fmd_protocol.h>
#include <fmd_event.h>
#include <fmd_eventq.h>
#include <fmd_dispq.h>
#include <fmd_buf.h>
#include <fmd_log.h>
#include <fmd_asru.h>

#include <fmd.h>

static const char *const _fmd_case_snames[] = {
	"UNSOLVED",	/* FMD_CASE_UNSOLVED */
	"SOLVED",	/* FMD_CASE_SOLVED */
	"CLOSED",	/* FMD_CASE_CLOSED */
};

fmd_case_hash_t *
fmd_case_hash_create(void)
{
	fmd_case_hash_t *chp = fmd_alloc(sizeof (fmd_case_hash_t), FMD_SLEEP);

	(void) pthread_rwlock_init(&chp->ch_lock, NULL);
	chp->ch_hashlen = fmd.d_str_buckets;
	chp->ch_hash = fmd_zalloc(sizeof (void *) * chp->ch_hashlen, FMD_SLEEP);

	return (chp);
}

/*
 * Destroy the case hash.  Unlike most of our hash tables, no active references
 * are kept by the case hash because cases are destroyed when modules unload.
 * The hash must be destroyed after all modules are unloaded; if anything was
 * present in the hash it would be by definition a reference count leak.
 */
void
fmd_case_hash_destroy(fmd_case_hash_t *chp)
{
	fmd_free(chp->ch_hash, sizeof (void *) * chp->ch_hashlen);
	fmd_free(chp, sizeof (fmd_case_hash_t));
}

static nvlist_t *
fmd_case_mkevent(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_susp_t *cis;

	char *code, **keys, **keyp;
	nvlist_t **nva, **nvp;
	const char *s;

	int msg = B_TRUE;
	boolean_t b;

	ASSERT(MUTEX_HELD(&cip->ci_lock));
	ASSERT(cip->ci_state >= FMD_CASE_SOLVED);

	code = alloca(cip->ci_mod->mod_codelen);
	keys = keyp = alloca(sizeof (char *) * (cip->ci_nsuspects + 1));
	nva = nvp = alloca(sizeof (nvlist_t *) * cip->ci_nsuspects);

	/*
	 * For each suspect associated with the case, store its fault event
	 * nvlist in 'nva' and its fault class in 'keys'.  We also look to see
	 * if any of the suspect faults have asked not to be messaged.  If any
	 * of them have made such a request, propagate that to the suspect list.
	 */
	for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next) {
		if (nvlist_lookup_string(cis->cis_nvl, FM_CLASS, keyp) == 0)
			keyp++;

		*nvp++ = cis->cis_nvl;

		if (nvlist_lookup_boolean_value(cis->cis_nvl,
		    FM_SUSPECT_MESSAGE, &b) == 0 && b == B_FALSE)
			msg = B_FALSE;
	}

	*keyp = NULL; /* mark end of keys[] array for libdiagcode */

	/*
	 * Look up the diagcode corresponding to this suspect list.  If
	 * no suspects were defined for this case or if the lookup
	 * fails, the dictionary or module code is busted or not set up
	 * properly.  Emit the event with our precomputed default code.
	 */
	if (cip->ci_nsuspects == 0 || fmd_module_dc_key2code(
	    cip->ci_mod, keys, code, cip->ci_mod->mod_codelen) != 0) {
		(void) fmd_conf_getprop(fmd.d_conf, "nodiagcode", &s);
		code = alloca(strlen(s) + 1);
		(void) strcpy(code, s);
	}

	return (fmd_protocol_suspects(cip->ci_mod->mod_fmri,
	    cip->ci_uuid, code, cip->ci_nsuspects, nva, msg));
}

/*
 * Publish appropriate events based on the specified case state.  For a case
 * that is FMD_CASE_SOLVED, we send ci_event.  For a case that is
 * FMD_CASE_CLOSED, we send a case-closed event to the owner module.
 */
static void
fmd_case_publish(fmd_case_t *cp, uint_t state)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_event_t *e;
	nvlist_t *nvl;
	char *class;

	switch (state) {
	case FMD_CASE_SOLVED:
		(void) pthread_mutex_lock(&cip->ci_lock);

		/*
		 * If ci_event is NULL, the event was not created because the
		 * case was restored from a checkpoint before _fmd_init() was
		 * called.  Now that the module is ready, create the event.
		 */
		if (cip->ci_event == NULL)
			cip->ci_event = fmd_case_mkevent(cp);

		(void) pthread_mutex_unlock(&cip->ci_lock);

		(void) nvlist_xdup(cip->ci_event, &nvl, &fmd.d_nva);
		(void) nvlist_lookup_string(nvl, FM_CLASS, &class);

		e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);
		(void) pthread_rwlock_rdlock(&fmd.d_log_lock);
		fmd_log_append(fmd.d_fltlog, e, cp);
		(void) pthread_rwlock_unlock(&fmd.d_log_lock);
		fmd_dispq_dispatch(fmd.d_disp, e, class);

		(void) pthread_mutex_lock(&cip->ci_mod->mod_stats_lock);
		cip->ci_mod->mod_stats->ms_casesolved.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&cip->ci_mod->mod_stats_lock);

		break;

	case FMD_CASE_CLOSED:
		fmd_case_hold(cp);
		e = fmd_event_create(FMD_EVT_CLOSE, FMD_HRT_NOW, NULL, cp);
		fmd_eventq_insert_at_head(cip->ci_mod->mod_queue, e);

		(void) pthread_mutex_lock(&cip->ci_mod->mod_stats_lock);
		cip->ci_mod->mod_stats->ms_caseclosed.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&cip->ci_mod->mod_stats_lock);

		break;
	}
}

/*
 * Refresh all of the cases by publishing events for each case if appropriate.
 * We do this once during startup to trigger case close and list.suspect events
 * for cases restored by checkpoints.  By holding the read lock on the case
 * hash, we ensure that we only refresh the current set of cases.  New cases
 * created in response to the events will block in fmd_case_hash_insert().
 */
void
fmd_case_hash_refresh(fmd_case_hash_t *chp)
{
	fmd_case_impl_t *cip;
	uint_t i;

	(void) pthread_rwlock_rdlock(&chp->ch_lock);

	for (i = 0; i < chp->ch_hashlen; i++) {
		for (cip = chp->ch_hash[i]; cip != NULL; cip = cip->ci_next)
			fmd_case_publish((fmd_case_t *)cip, cip->ci_state);
	}

	(void) pthread_rwlock_unlock(&chp->ch_lock);
}

fmd_case_t *
fmd_case_hash_lookup(fmd_case_hash_t *chp, const char *uuid)
{
	fmd_case_impl_t *cip;
	uint_t h;

	(void) pthread_rwlock_rdlock(&chp->ch_lock);
	h = fmd_strhash(uuid) % chp->ch_hashlen;

	for (cip = chp->ch_hash[h]; cip != NULL; cip = cip->ci_next) {
		if (strcmp(cip->ci_uuid, uuid) == 0)
			break;
	}

	if (cip != NULL)
		fmd_case_hold((fmd_case_t *)cip);
	else
		(void) fmd_set_errno(EFMD_CASE_INVAL);

	(void) pthread_rwlock_unlock(&chp->ch_lock);
	return ((fmd_case_t *)cip);
}

static fmd_case_impl_t *
fmd_case_hash_insert(fmd_case_hash_t *chp, fmd_case_impl_t *cip)
{
	fmd_case_impl_t *eip;
	uint_t h;

	(void) pthread_rwlock_wrlock(&chp->ch_lock);
	h = fmd_strhash(cip->ci_uuid) % chp->ch_hashlen;

	for (eip = chp->ch_hash[h]; eip != NULL; eip = eip->ci_next) {
		if (strcmp(cip->ci_uuid, eip->ci_uuid) == 0) {
			(void) pthread_rwlock_unlock(&chp->ch_lock);
			return (NULL); /* uuid already present */
		}
	}

	cip->ci_next = chp->ch_hash[h];
	chp->ch_hash[h] = cip;

	(void) pthread_rwlock_unlock(&chp->ch_lock);
	return (cip);
}

static void
fmd_case_hash_delete(fmd_case_hash_t *chp, fmd_case_impl_t *cip)
{
	fmd_case_impl_t *cp, **pp;
	uint_t h;

	(void) pthread_rwlock_wrlock(&chp->ch_lock);

	h = fmd_strhash(cip->ci_uuid) % chp->ch_hashlen;
	pp = &chp->ch_hash[h];

	for (cp = *pp; cp != NULL; cp = cp->ci_next) {
		if (cp != cip)
			pp = &cp->ci_next;
		else
			break;
	}

	if (cp == NULL) {
		fmd_panic("case %p (%s) not found on hash chain %u\n",
		    (void *)cip, cip->ci_uuid, h);
	}

	*pp = cp->ci_next;
	cp->ci_next = NULL;

	(void) pthread_rwlock_unlock(&chp->ch_lock);
}

fmd_case_t *
fmd_case_create(fmd_module_t *mp, void *data)
{
	fmd_case_impl_t *cip = fmd_zalloc(sizeof (fmd_case_impl_t), FMD_SLEEP);
	uuid_t uuid;

	(void) pthread_mutex_init(&cip->ci_lock, NULL);
	fmd_buf_hash_create(&cip->ci_bufs);

	fmd_module_hold(mp);
	cip->ci_mod = mp;
	cip->ci_refs = 1;
	cip->ci_state = FMD_CASE_UNSOLVED;
	cip->ci_flags = FMD_CF_DIRTY;
	cip->ci_data = data;

	/*
	 * Calling libuuid: get a clue.  The library interfaces cleverly do not
	 * define any constant for the length of an unparse string, and do not
	 * permit the caller to specify a buffer length for safety.  The spec
	 * says it will be 36 bytes, but we make it tunable just in case.
	 */
	(void) fmd_conf_getprop(fmd.d_conf, "uuidlen", &cip->ci_uuidlen);
	cip->ci_uuid = fmd_zalloc(cip->ci_uuidlen + 1, FMD_SLEEP);

	/*
	 * We expect this loop to execute only once, but code it defensively
	 * against the possibility of libuuid bugs.  Keep generating uuids and
	 * attempting to do a hash insert until we get a unique one.
	 */
	do {
		uuid_generate(uuid);
		uuid_unparse(uuid, cip->ci_uuid);
	} while (fmd_case_hash_insert(fmd.d_cases, cip) == NULL);

	ASSERT(fmd_module_locked(mp));
	fmd_list_append(&mp->mod_cases, cip);
	fmd_module_setcdirty(mp);

	(void) pthread_mutex_lock(&cip->ci_mod->mod_stats_lock);
	cip->ci_mod->mod_stats->ms_caseopen.fmds_value.ui64++;
	(void) pthread_mutex_unlock(&cip->ci_mod->mod_stats_lock);

	return ((fmd_case_t *)cip);
}

fmd_case_t *
fmd_case_recreate(fmd_module_t *mp, const char *uuid)
{
	fmd_case_impl_t *cip = fmd_zalloc(sizeof (fmd_case_impl_t), FMD_SLEEP);

	(void) pthread_mutex_init(&cip->ci_lock, NULL);
	fmd_buf_hash_create(&cip->ci_bufs);

	fmd_module_hold(mp);
	cip->ci_mod = mp;
	cip->ci_refs = 1;
	cip->ci_state = FMD_CASE_UNSOLVED;
	cip->ci_uuid = fmd_strdup(uuid, FMD_SLEEP);
	cip->ci_uuidlen = strlen(cip->ci_uuid);

	ASSERT(fmd_module_locked(mp));
	fmd_list_append(&mp->mod_cases, cip);

	(void) pthread_mutex_lock(&cip->ci_mod->mod_stats_lock);
	cip->ci_mod->mod_stats->ms_caseopen.fmds_value.ui64++;
	(void) pthread_mutex_unlock(&cip->ci_mod->mod_stats_lock);

	if (fmd_case_hash_insert(fmd.d_cases, cip) == NULL) {
		fmd_case_destroy((fmd_case_t *)cip);
		return (NULL);
	}

	return ((fmd_case_t *)cip);
}

void
fmd_case_destroy(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_item_t *cit, *ncit;
	fmd_case_susp_t *cis, *ncis;

	ASSERT(MUTEX_HELD(&cip->ci_lock));
	ASSERT(cip->ci_refs == 0);

	fmd_case_hash_delete(fmd.d_cases, cip);

	for (cit = cip->ci_items; cit != NULL; cit = ncit) {
		ncit = cit->cit_next;
		fmd_event_rele(cit->cit_event);
		fmd_free(cit, sizeof (fmd_case_item_t));
	}

	for (cis = cip->ci_suspects; cis != NULL; cis = ncis) {
		ncis = cis->cis_next;
		nvlist_free(cis->cis_nvl);
		fmd_free(cis, sizeof (fmd_case_susp_t));
	}

	if (cip->ci_principal != NULL)
		fmd_event_rele(cip->ci_principal);

	nvlist_free(cip->ci_event);
	fmd_free(cip->ci_uuid, cip->ci_uuidlen + 1);
	fmd_buf_hash_destroy(&cip->ci_bufs);

	/*
	 * Unlike other case functions, fmd_case_destroy() can be called from
	 * fmd_module_unload() after the module is unregistered and mod_stats
	 * has been destroyed.  As such we must check for NULL mod_stats here.
	 */
	(void) pthread_mutex_lock(&cip->ci_mod->mod_stats_lock);
	if (cip->ci_mod->mod_stats != NULL)
		cip->ci_mod->mod_stats->ms_caseopen.fmds_value.ui64--;
	(void) pthread_mutex_unlock(&cip->ci_mod->mod_stats_lock);

	fmd_module_setcdirty(cip->ci_mod);
	fmd_module_rele(cip->ci_mod);
	fmd_free(cip, sizeof (fmd_case_impl_t));
}

void
fmd_case_hold(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	(void) pthread_mutex_lock(&cip->ci_lock);
	cip->ci_refs++;
	ASSERT(cip->ci_refs != 0);
	(void) pthread_mutex_unlock(&cip->ci_lock);
}

void
fmd_case_rele(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	(void) pthread_mutex_lock(&cip->ci_lock);
	ASSERT(cip->ci_refs != 0);

	if (--cip->ci_refs == 0)
		fmd_case_destroy((fmd_case_t *)cip);
	else
		(void) pthread_mutex_unlock(&cip->ci_lock);
}

void
fmd_case_insert_principal(fmd_case_t *cp, fmd_event_t *ep)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_event_t *oep;
	uint_t state;

	fmd_event_hold(ep);
	(void) pthread_mutex_lock(&cip->ci_lock);

	if (cip->ci_state >= FMD_CASE_SOLVED && cip->ci_event != NULL)
		state = FMD_EVS_DIAGNOSED;
	else
		state = FMD_EVS_ACCEPTED;

	oep = cip->ci_principal;
	cip->ci_principal = ep;

	cip->ci_flags |= FMD_CF_DIRTY;
	(void) pthread_mutex_unlock(&cip->ci_lock);

	fmd_module_setcdirty(cip->ci_mod);
	fmd_event_transition(ep, state);

	if (oep != NULL)
		fmd_event_rele(oep);
}

void
fmd_case_insert_event(fmd_case_t *cp, fmd_event_t *ep)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_item_t *cit = fmd_alloc(sizeof (fmd_case_item_t), FMD_SLEEP);
	uint_t state;

	fmd_event_hold(ep);
	(void) pthread_mutex_lock(&cip->ci_lock);

	cit->cit_next = cip->ci_items;
	cit->cit_event = ep;

	cip->ci_items = cit;
	cip->ci_nitems++;

	if (cip->ci_state >= FMD_CASE_SOLVED && cip->ci_event != NULL)
		state = FMD_EVS_DIAGNOSED;
	else
		state = FMD_EVS_ACCEPTED;

	cip->ci_flags |= FMD_CF_DIRTY;
	(void) pthread_mutex_unlock(&cip->ci_lock);

	fmd_module_setcdirty(cip->ci_mod);
	fmd_event_transition(ep, state);
}

void
fmd_case_insert_suspect(fmd_case_t *cp, nvlist_t *nvl)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_susp_t *cis = fmd_alloc(sizeof (fmd_case_susp_t), FMD_SLEEP);

	(void) pthread_mutex_lock(&cip->ci_lock);
	ASSERT(cip->ci_state < FMD_CASE_SOLVED);
	cip->ci_flags |= FMD_CF_DIRTY;

	cis->cis_next = cip->ci_suspects;
	cis->cis_nvl = nvl;

	cip->ci_suspects = cis;
	cip->ci_nsuspects++;

	(void) pthread_mutex_unlock(&cip->ci_lock);
	fmd_module_setcdirty(cip->ci_mod);
}

void
fmd_case_reset_suspects(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_susp_t *cis, *ncis;

	(void) pthread_mutex_lock(&cip->ci_lock);
	ASSERT(cip->ci_state < FMD_CASE_SOLVED);

	for (cis = cip->ci_suspects; cis != NULL; cis = ncis) {
		ncis = cis->cis_next;
		nvlist_free(cis->cis_nvl);
		fmd_free(cis, sizeof (fmd_case_susp_t));
	}

	cip->ci_flags |= FMD_CF_DIRTY;
	cip->ci_suspects = NULL;
	cip->ci_nsuspects = 0;

	(void) pthread_mutex_unlock(&cip->ci_lock);
	fmd_module_setcdirty(cip->ci_mod);
}

void
fmd_case_transition(fmd_case_t *cp, uint_t state)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	nvlist_t *nvl;

	/*
	 * Grab ci_lock and update the case state and set the dirty bit.  If we
	 * are solving the case, create a list.suspects event as cip->ci_event
	 * and iterate over all the case events and mark them as DIAGNOSED.
	 */
	(void) pthread_mutex_lock(&cip->ci_lock);

	if (cip->ci_state >= state) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return; /* already in specified state */
	}

	TRACE((FMD_DBG_CASE, "case %s %s->%s", cip->ci_uuid,
	    _fmd_case_snames[cip->ci_state], _fmd_case_snames[state]));

	cip->ci_state = state;
	cip->ci_flags |= FMD_CF_DIRTY;

	switch (state) {
	case FMD_CASE_SOLVED: {
		fmd_case_item_t *cit;

		/*
		 * If the module has been initialized, then fill in ci_event.
		 * If not, we are being called from the checkpoint code, in
		 * in which case fmd_case_hash_refresh() will create and
		 * publish the event later once the module has initialized.
		 */
		if (cip->ci_mod->mod_flags & FMD_MOD_INIT)
			cip->ci_event = fmd_case_mkevent(cp);

		for (cit = cip->ci_items; cit != NULL; cit = cit->cit_next)
			fmd_event_transition(cit->cit_event, FMD_EVS_DIAGNOSED);

		if (cip->ci_principal != NULL) {
			fmd_event_transition(cip->ci_principal,
			    FMD_EVS_DIAGNOSED);
		}
		break;
	}

	case FMD_CASE_CLOSED: {
		fmd_case_susp_t *cis;
		fmd_asru_t *asru;

		if (cip->ci_flags & FMD_CF_REPAIR)
			break; /* don't change ASRUs if repair closed case */

		/*
		 * For each fault event in the suspect list, attempt to look up
		 * the corresponding ASRU in the ASRU dictionary.  If the ASRU
		 * is found there and is marked faulty, we now mark it unusable
		 * and record the case meta-data and fault event with the ASRU.
		 */
		for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next) {
			if (nvlist_lookup_nvlist(cis->cis_nvl, FM_FAULT_ASRU,
			    &nvl) == 0 && (asru = fmd_asru_hash_lookup_nvl(
			    fmd.d_asrus, nvl, FMD_B_FALSE)) != NULL) {
				(void) fmd_asru_setflags(asru,
				    FMD_ASRU_UNUSABLE,
				    cip->ci_uuid, cis->cis_nvl);
				fmd_asru_hash_release(fmd.d_asrus, asru);
			}
		}
		break;
	}
	}

	(void) pthread_mutex_unlock(&cip->ci_lock);
	fmd_module_setcdirty(cip->ci_mod);

	/*
	 * If the module has been initialized, then publish the appropriate
	 * event for the new case state.  If not, we are being called from
	 * the checkpoint code, in which case fmd_case_hash_refresh() will
	 * publish the event later once all the modules have initialized.
	 */
	if (cip->ci_mod->mod_flags & FMD_MOD_INIT)
		fmd_case_publish(cp, state);
}

void
fmd_case_setdirty(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	(void) pthread_mutex_lock(&cip->ci_lock);
	cip->ci_flags |= FMD_CF_DIRTY;
	(void) pthread_mutex_unlock(&cip->ci_lock);

	fmd_module_setcdirty(cip->ci_mod);
}

void
fmd_case_clrdirty(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	(void) pthread_mutex_lock(&cip->ci_lock);
	cip->ci_flags &= ~FMD_CF_DIRTY;
	(void) pthread_mutex_unlock(&cip->ci_lock);
}

void
fmd_case_commit(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_item_t *cit;

	(void) pthread_mutex_lock(&cip->ci_lock);

	if (cip->ci_flags & FMD_CF_DIRTY) {
		for (cit = cip->ci_items; cit != NULL; cit = cit->cit_next)
			fmd_event_commit(cit->cit_event);

		if (cip->ci_principal != NULL)
			fmd_event_commit(cip->ci_principal);

		fmd_buf_hash_commit(&cip->ci_bufs);
		cip->ci_flags &= ~FMD_CF_DIRTY;
	}

	(void) pthread_mutex_unlock(&cip->ci_lock);
}

/*
 * Indicate that the case may need to change state because one or more of the
 * ASRUs named as a suspect has changed state.  We examine all the suspects
 * and if none are still faulty, we initiate a case close transition.
 */
void
fmd_case_update(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_susp_t *cis;
	fmd_asru_t *asru;
	nvlist_t *nvl;

	int state = 0;

	(void) pthread_mutex_lock(&cip->ci_lock);

	if (cip->ci_state < FMD_CASE_SOLVED) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return; /* update is not yet appropriate */
	}

	for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next) {
		if (nvlist_lookup_nvlist(cis->cis_nvl, FM_FAULT_ASRU,
		    &nvl) == 0 && (asru = fmd_asru_hash_lookup_nvl(
		    fmd.d_asrus, nvl, FMD_B_FALSE)) != NULL) {
			state |= fmd_asru_getstate(asru);
			fmd_asru_hash_release(fmd.d_asrus, asru);
		}
	}

	if (!(state & FMD_ASRU_FAULTY))
		cip->ci_flags |= FMD_CF_REPAIR;

	(void) pthread_mutex_unlock(&cip->ci_lock);

	if (!(state & FMD_ASRU_FAULTY))
		fmd_case_transition(cp, FMD_CASE_CLOSED);
}

/*
 * Indicate that the problem corresponding to a case has been repaired by
 * clearing the faulty bit on each ASRU named as a suspect.  If the case has
 * not already been closed, this function initiates the case close transition.
 */
int
fmd_case_repair(fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_susp_t *cis;
	fmd_asru_t *asru;
	nvlist_t *nvl;

	(void) pthread_mutex_lock(&cip->ci_lock);

	if (cip->ci_state < FMD_CASE_SOLVED) {
		(void) pthread_mutex_unlock(&cip->ci_lock);
		return (fmd_set_errno(EFMD_CASE_STATE));
	}

	for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next) {
		if (nvlist_lookup_nvlist(cis->cis_nvl, FM_FAULT_ASRU,
		    &nvl) == 0 && (asru = fmd_asru_hash_lookup_nvl(
		    fmd.d_asrus, nvl, FMD_B_FALSE)) != NULL) {
			(void) fmd_asru_clrflags(asru,
			    FMD_ASRU_FAULTY, NULL, NULL);
			fmd_asru_hash_release(fmd.d_asrus, asru);
		}
	}

	cip->ci_flags |= FMD_CF_REPAIR;
	(void) pthread_mutex_unlock(&cip->ci_lock);

	fmd_case_transition(cp, FMD_CASE_CLOSED);
	return (0);
}

int
fmd_case_contains(fmd_case_t *cp, fmd_event_t *ep)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_item_t *cit;
	uint_t state;
	int rv = 0;

	(void) pthread_mutex_lock(&cip->ci_lock);

	if (cip->ci_state >= FMD_CASE_SOLVED)
		state = FMD_EVS_DIAGNOSED;
	else
		state = FMD_EVS_ACCEPTED;

	for (cit = cip->ci_items; cit != NULL; cit = cit->cit_next) {
		if ((rv = fmd_event_equal(ep, cit->cit_event)) != 0)
			break;
	}

	if (rv == 0 && cip->ci_principal != NULL)
		rv = fmd_event_equal(ep, cip->ci_principal);

	(void) pthread_mutex_unlock(&cip->ci_lock);

	if (rv != 0)
		fmd_event_transition(ep, state);

	return (rv);
}
