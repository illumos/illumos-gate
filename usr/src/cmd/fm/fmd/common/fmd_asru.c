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

#include <sys/fm/protocol.h>
#include <uuid/uuid.h>

#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <alloca.h>
#include <stddef.h>
#include <fm/libtopo.h>

#include <fmd_alloc.h>
#include <fmd_string.h>
#include <fmd_error.h>
#include <fmd_subr.h>
#include <fmd_protocol.h>
#include <fmd_event.h>
#include <fmd_conf.h>
#include <fmd_fmri.h>
#include <fmd_dispq.h>
#include <fmd_case.h>
#include <fmd_module.h>
#include <fmd_asru.h>

#include <fmd.h>

static const char *const _fmd_asru_events[] = {
	FMD_RSRC_CLASS "asru.ok",		/* UNUSABLE=0 FAULTED=0 */
	FMD_RSRC_CLASS "asru.degraded",		/* UNUSABLE=0 FAULTED=1 */
	FMD_RSRC_CLASS "asru.unknown",		/* UNUSABLE=1 FAULTED=0 */
	FMD_RSRC_CLASS "asru.faulted"		/* UNUSABLE=1 FAULTED=1 */
};

static const char *const _fmd_asru_snames[] = {
	"uf", "uF", "Uf", "UF"			/* same order as above */
};

volatile uint32_t fmd_asru_fake_not_present = 0;

static uint_t
fmd_asru_strhash(fmd_asru_hash_t *ahp, const char *val)
{
	return (topo_fmri_strhash(ahp->ah_topo->ft_hdl, val) % ahp->ah_hashlen);
}

static boolean_t
fmd_asru_strcmp(fmd_asru_hash_t *ahp, const char *a, const char *b)
{
	return (topo_fmri_strcmp(ahp->ah_topo->ft_hdl, a, b));
}

static fmd_asru_t *
fmd_asru_create(fmd_asru_hash_t *ahp, const char *uuid,
    const char *name, nvlist_t *fmri)
{
	fmd_asru_t *ap = fmd_zalloc(sizeof (fmd_asru_t), FMD_SLEEP);
	char *s;

	(void) pthread_mutex_init(&ap->asru_lock, NULL);
	(void) pthread_cond_init(&ap->asru_cv, NULL);

	ap->asru_name = fmd_strdup(name, FMD_SLEEP);
	if (fmri)
		(void) nvlist_xdup(fmri, &ap->asru_fmri, &fmd.d_nva);
	ap->asru_root = fmd_strdup(ahp->ah_dirpath, FMD_SLEEP);
	ap->asru_uuid = fmd_strdup(uuid, FMD_SLEEP);
	ap->asru_uuidlen = ap->asru_uuid ? strlen(ap->asru_uuid) : 0;
	ap->asru_refs = 1;

	if (fmri && nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &s) == 0 &&
	    strcmp(s, FM_FMRI_SCHEME_FMD) == 0)
		ap->asru_flags |= FMD_ASRU_INTERNAL;

	return (ap);
}

static void
fmd_asru_destroy(fmd_asru_t *ap)
{
	ASSERT(MUTEX_HELD(&ap->asru_lock));
	ASSERT(ap->asru_refs == 0);

	nvlist_free(ap->asru_event);
	fmd_strfree(ap->asru_name);
	nvlist_free(ap->asru_fmri);
	fmd_strfree(ap->asru_root);
	fmd_free(ap->asru_uuid, ap->asru_uuidlen + 1);
	fmd_free(ap, sizeof (fmd_asru_t));
}

static void
fmd_asru_hash_insert(fmd_asru_hash_t *ahp, fmd_asru_t *ap)
{
	uint_t h = fmd_asru_strhash(ahp, ap->asru_name);

	ASSERT(RW_WRITE_HELD(&ahp->ah_lock));
	ap->asru_next = ahp->ah_hash[h];
	ahp->ah_hash[h] = ap;
	ahp->ah_count++;
}

static fmd_asru_t *
fmd_asru_hold(fmd_asru_t *ap)
{
	(void) pthread_mutex_lock(&ap->asru_lock);
	ap->asru_refs++;
	ASSERT(ap->asru_refs != 0);
	(void) pthread_mutex_unlock(&ap->asru_lock);
	return (ap);
}

/*
 * Lookup an asru in the hash by name and place a hold on it.  If the asru is
 * not found, no entry is created and NULL is returned.  This internal function
 * is for callers who have the ah_lock held and is used by lookup_name below.
 */
fmd_asru_t *
fmd_asru_hash_lookup(fmd_asru_hash_t *ahp, const char *name)
{
	fmd_asru_t *ap;
	uint_t h;

	ASSERT(RW_LOCK_HELD(&ahp->ah_lock));
	h = fmd_asru_strhash(ahp, name);

	for (ap = ahp->ah_hash[h]; ap != NULL; ap = ap->asru_next) {
		if (fmd_asru_strcmp(ahp, ap->asru_name, name))
			break;
	}

	if (ap != NULL)
		(void) fmd_asru_hold(ap);
	else
		(void) fmd_set_errno(EFMD_ASRU_NOENT);

	return (ap);
}

static int
fmd_asru_replacement_state(nvlist_t *event)
{
	int ps = -1;
	nvlist_t *asru, *fru, *rsrc;

	/*
	 * Check if there is evidence that this object is no longer present.
	 * In general fmd_fmri_present() should be supported on resources and/or
	 * frus, as those are the things that are physically present or not
	 * present - an asru can be spread over a number of frus some of which
	 * are present and some not, so fmd_fmri_present() is not generally
	 * meaningful. However retain a check for asru first for compatibility.
	 * If we have checked all three and we still get -1 then nothing knows
	 * whether it's present or not, so err on the safe side and treat it
	 * as still present.
	 */
	if (fmd_asru_fake_not_present)
		return (fmd_asru_fake_not_present);
	if (nvlist_lookup_nvlist(event, FM_FAULT_ASRU, &asru) == 0)
		ps = fmd_fmri_replaced(asru);
	if (ps == -1) {
		if (nvlist_lookup_nvlist(event, FM_FAULT_RESOURCE, &rsrc) == 0)
			ps = fmd_fmri_replaced(rsrc);
	} else if (ps == FMD_OBJ_STATE_UNKNOWN) {
		/* see if we can improve on UNKNOWN */
		if (nvlist_lookup_nvlist(event, FM_FAULT_RESOURCE,
		    &rsrc) == 0) {
			int ps2 = fmd_fmri_replaced(rsrc);
			if (ps2 == FMD_OBJ_STATE_STILL_PRESENT ||
			    ps2 == FMD_OBJ_STATE_REPLACED)
				ps = ps2;
		}
	}
	if (ps == -1) {
		if (nvlist_lookup_nvlist(event, FM_FAULT_FRU, &fru) == 0)
			ps = fmd_fmri_replaced(fru);
	} else if (ps == FMD_OBJ_STATE_UNKNOWN) {
		/* see if we can improve on UNKNOWN */
		if (nvlist_lookup_nvlist(event, FM_FAULT_FRU, &fru) == 0) {
			int ps2 = fmd_fmri_replaced(fru);
			if (ps2 == FMD_OBJ_STATE_STILL_PRESENT ||
			    ps2 == FMD_OBJ_STATE_REPLACED)
				ps = ps2;
		}
	}
	if (ps == -1)
		ps = FMD_OBJ_STATE_UNKNOWN;
	return (ps);
}

static void
fmd_asru_asru_hash_insert(fmd_asru_hash_t *ahp, fmd_asru_link_t *alp,
    char *name)
{
	uint_t h = fmd_asru_strhash(ahp, name);

	ASSERT(RW_WRITE_HELD(&ahp->ah_lock));
	alp->al_asru_next = ahp->ah_asru_hash[h];
	ahp->ah_asru_hash[h] = alp;
	ahp->ah_al_count++;
}

static void
fmd_asru_case_hash_insert(fmd_asru_hash_t *ahp, fmd_asru_link_t *alp,
    char *name)
{
	uint_t h = fmd_asru_strhash(ahp, name);

	ASSERT(RW_WRITE_HELD(&ahp->ah_lock));
	alp->al_case_next = ahp->ah_case_hash[h];
	ahp->ah_case_hash[h] = alp;
}

static void
fmd_asru_fru_hash_insert(fmd_asru_hash_t *ahp, fmd_asru_link_t *alp, char *name)
{
	uint_t h = fmd_asru_strhash(ahp, name);

	ASSERT(RW_WRITE_HELD(&ahp->ah_lock));
	alp->al_fru_next = ahp->ah_fru_hash[h];
	ahp->ah_fru_hash[h] = alp;
}

static void
fmd_asru_label_hash_insert(fmd_asru_hash_t *ahp, fmd_asru_link_t *alp,
    char *name)
{
	uint_t h = fmd_asru_strhash(ahp, name);

	ASSERT(RW_WRITE_HELD(&ahp->ah_lock));
	alp->al_label_next = ahp->ah_label_hash[h];
	ahp->ah_label_hash[h] = alp;
}

static void
fmd_asru_rsrc_hash_insert(fmd_asru_hash_t *ahp, fmd_asru_link_t *alp,
    char *name)
{
	uint_t h = fmd_asru_strhash(ahp, name);

	ASSERT(RW_WRITE_HELD(&ahp->ah_lock));
	alp->al_rsrc_next = ahp->ah_rsrc_hash[h];
	ahp->ah_rsrc_hash[h] = alp;
}

static void
fmd_asru_al_destroy(fmd_asru_link_t *alp)
{
	ASSERT(alp->al_refs == 0);
	ASSERT(MUTEX_HELD(&alp->al_asru->asru_lock));

	if (alp->al_log != NULL)
		fmd_log_rele(alp->al_log);

	fmd_free(alp->al_uuid, alp->al_uuidlen + 1);
	nvlist_free(alp->al_event);
	fmd_strfree(alp->al_rsrc_name);
	fmd_strfree(alp->al_case_uuid);
	fmd_strfree(alp->al_fru_name);
	fmd_strfree(alp->al_asru_name);
	fmd_strfree(alp->al_label);
	nvlist_free(alp->al_asru_fmri);
	fmd_free(alp, sizeof (fmd_asru_link_t));
}

static fmd_asru_link_t *
fmd_asru_al_hold(fmd_asru_link_t *alp)
{
	fmd_asru_t *ap = alp->al_asru;

	(void) pthread_mutex_lock(&ap->asru_lock);
	ap->asru_refs++;
	alp->al_refs++;
	ASSERT(alp->al_refs != 0);
	(void) pthread_mutex_unlock(&ap->asru_lock);
	return (alp);
}

static void fmd_asru_destroy(fmd_asru_t *ap);

/*ARGSUSED*/
static void
fmd_asru_al_hash_release(fmd_asru_hash_t *ahp, fmd_asru_link_t *alp)
{
	fmd_asru_t *ap = alp->al_asru;

	(void) pthread_mutex_lock(&ap->asru_lock);
	ASSERT(alp->al_refs != 0);
	if (--alp->al_refs == 0)
		fmd_asru_al_destroy(alp);
	ASSERT(ap->asru_refs != 0);
	if (--ap->asru_refs == 0)
		fmd_asru_destroy(ap);
	else
		(void) pthread_mutex_unlock(&ap->asru_lock);
}

static int
fmd_asru_get_namestr(nvlist_t *nvl, char **name, ssize_t *namelen)
{
	if ((*namelen = fmd_fmri_nvl2str(nvl, NULL, 0)) == -1)
		return (EFMD_ASRU_FMRI);
	*name = fmd_alloc(*namelen + 1, FMD_SLEEP);
	if (fmd_fmri_nvl2str(nvl, *name, *namelen + 1) == -1) {
		if (*name != NULL)
			fmd_free(*name, *namelen + 1);
		return (EFMD_ASRU_FMRI);
	}
	return (0);
}

static fmd_asru_link_t *
fmd_asru_al_create(fmd_asru_hash_t *ahp, nvlist_t *nvl, fmd_case_t *cp,
    const char *al_uuid)
{
	nvlist_t *asru = NULL, *fru, *rsrc;
	int got_rsrc = 0, got_asru = 0, got_fru = 0;
	ssize_t fru_namelen, rsrc_namelen, asru_namelen;
	char *asru_name, *rsrc_name, *fru_name, *name, *label;
	fmd_asru_link_t *alp;
	fmd_asru_t *ap;
	boolean_t msg;
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;

	if (nvlist_lookup_nvlist(nvl, FM_FAULT_ASRU, &asru) == 0 &&
	    fmd_asru_get_namestr(asru, &asru_name, &asru_namelen) == 0)
		got_asru = 1;
	if (nvlist_lookup_nvlist(nvl, FM_FAULT_FRU, &fru) == 0 &&
	    fmd_asru_get_namestr(fru, &fru_name, &fru_namelen) == 0)
		got_fru = 1;
	if (nvlist_lookup_nvlist(nvl, FM_FAULT_RESOURCE, &rsrc) == 0 &&
	    fmd_asru_get_namestr(rsrc, &rsrc_name, &rsrc_namelen) == 0)
		got_rsrc = 1;
	if (nvlist_lookup_string(nvl, FM_FAULT_LOCATION, &label) != 0)
		label = "";

	/*
	 * Grab the rwlock as a writer; Then create and insert the asru with
	 * ahp->ah_lock held and hash it in. We'll then drop the rwlock and
	 * proceed to initializing the asru.
	 */
	(void) pthread_rwlock_wrlock(&ahp->ah_lock);

	/*
	 * Create and initialise the per-fault "link" structure.
	 */
	alp = fmd_zalloc(sizeof (fmd_asru_link_t), FMD_SLEEP);
	if (got_asru)
		(void) nvlist_xdup(asru, &alp->al_asru_fmri, &fmd.d_nva);
	alp->al_uuid = fmd_strdup(al_uuid, FMD_SLEEP);
	alp->al_uuidlen = strlen(alp->al_uuid);
	alp->al_refs = 1;

	/*
	 * If this is the first fault for this asru, then create the per-asru
	 * structure and link into the hash.
	 */
	name = got_asru ? asru_name : "";
	if ((ap = fmd_asru_hash_lookup(ahp, name)) == NULL) {
		ap = fmd_asru_create(ahp, al_uuid, name, got_asru ? asru :
		    NULL);
		fmd_asru_hash_insert(ahp, ap);
	} else
		nvlist_free(ap->asru_event);
	(void) nvlist_xdup(nvl, &ap->asru_event, &fmd.d_nva);

	/*
	 * Put the link structure on the list associated with the per-asru
	 * structure. Then put the link structure on the various hashes.
	 */
	fmd_list_append(&ap->asru_list, (fmd_list_t *)alp);
	alp->al_asru = ap;
	alp->al_asru_name = got_asru ? asru_name : fmd_strdup("", FMD_SLEEP);
	fmd_asru_asru_hash_insert(ahp, alp, alp->al_asru_name);
	alp->al_fru_name = got_fru ? fru_name : fmd_strdup("", FMD_SLEEP);
	fmd_asru_fru_hash_insert(ahp, alp, alp->al_fru_name);
	alp->al_rsrc_name = got_rsrc ? rsrc_name : fmd_strdup("", FMD_SLEEP);
	fmd_asru_rsrc_hash_insert(ahp, alp, alp->al_rsrc_name);
	alp->al_label = fmd_strdup(label, FMD_SLEEP);
	fmd_asru_label_hash_insert(ahp, alp, label);
	alp->al_case_uuid = fmd_strdup(cip->ci_uuid, FMD_SLEEP);
	fmd_asru_case_hash_insert(ahp, alp, cip->ci_uuid);
	(void) pthread_mutex_lock(&ap->asru_lock);
	(void) pthread_rwlock_unlock(&ahp->ah_lock);

	ap->asru_case = alp->al_case = cp;
	if (nvlist_lookup_boolean_value(nvl, FM_SUSPECT_MESSAGE, &msg) == 0 &&
	    msg == B_FALSE)
		ap->asru_flags |= FMD_ASRU_INVISIBLE;
	(void) nvlist_xdup(nvl, &alp->al_event, &fmd.d_nva);
	ap->asru_flags |= FMD_ASRU_VALID;
	(void) pthread_cond_broadcast(&ap->asru_cv);
	(void) pthread_mutex_unlock(&ap->asru_lock);
	return (alp);
}

static void
fmd_asru_hash_recreate(fmd_log_t *lp, fmd_event_t *ep, fmd_asru_hash_t *ahp)
{
	nvlist_t *nvl = FMD_EVENT_NVL(ep);
	boolean_t faulty = FMD_B_FALSE, unusable = FMD_B_FALSE;
	int ps;
	boolean_t repaired = FMD_B_FALSE, replaced = FMD_B_FALSE;
	boolean_t acquitted = FMD_B_FALSE;
	nvlist_t *flt, *flt_copy, *asru;
	char *case_uuid = NULL, *case_code = NULL;
	fmd_asru_t *ap;
	fmd_asru_link_t *alp;
	fmd_case_t *cp;
	int64_t *diag_time;
	uint_t nelem;
	topo_hdl_t *thp;
	char *class;
	nvlist_t *rsrc;
	int err;

	/*
	 * Extract the most recent values of 'faulty' from the event log.
	 */
	if (nvlist_lookup_boolean_value(nvl, FM_RSRC_ASRU_FAULTY,
	    &faulty) != 0) {
		fmd_error(EFMD_ASRU_EVENT, "failed to reload asru %s: "
		    "invalid event log record\n", lp->log_name);
		ahp->ah_error = EFMD_ASRU_EVENT;
		return;
	}
	if (nvlist_lookup_nvlist(nvl, FM_RSRC_ASRU_EVENT, &flt) != 0) {
		fmd_error(EFMD_ASRU_EVENT, "failed to reload asru %s: "
		    "invalid event log record\n", lp->log_name);
		ahp->ah_error = EFMD_ASRU_EVENT;
		return;
	}
	(void) nvlist_lookup_string(nvl, FM_RSRC_ASRU_UUID, &case_uuid);
	(void) nvlist_lookup_string(nvl, FM_RSRC_ASRU_CODE, &case_code);
	(void) nvlist_lookup_boolean_value(nvl, FM_RSRC_ASRU_UNUSABLE,
	    &unusable);
	(void) nvlist_lookup_boolean_value(nvl, FM_RSRC_ASRU_REPAIRED,
	    &repaired);
	(void) nvlist_lookup_boolean_value(nvl, FM_RSRC_ASRU_REPLACED,
	    &replaced);
	(void) nvlist_lookup_boolean_value(nvl, FM_RSRC_ASRU_ACQUITTED,
	    &acquitted);

	/*
	 * Attempt to recreate the case in either the CLOSED or REPAIRED state
	 * (depending on whether the faulty bit is still set).
	 * If the case is already present, fmd_case_recreate() will return it.
	 * If not, we'll create a new orphaned case. Either way,  we use the
	 * ASRU event to insert a suspect into the partially-restored case.
	 */
	fmd_module_lock(fmd.d_rmod);
	cp = fmd_case_recreate(fmd.d_rmod, NULL, faulty ? FMD_CASE_CLOSED :
	    FMD_CASE_REPAIRED, case_uuid, case_code);
	fmd_case_hold(cp);
	fmd_module_unlock(fmd.d_rmod);
	if (nvlist_lookup_int64_array(nvl, FM_SUSPECT_DIAG_TIME, &diag_time,
	    &nelem) == 0 && nelem >= 2)
		fmd_case_settime(cp, diag_time[0], diag_time[1]);
	else
		fmd_case_settime(cp, lp->log_stat.st_ctime, 0);
	(void) nvlist_xdup(flt, &flt_copy, &fmd.d_nva);

	/*
	 * For faults with a resource, re-evaluate the asru from the resource.
	 */
	thp = fmd_fmri_topo_hold(TOPO_VERSION);
	if (nvlist_lookup_string(flt_copy, FM_CLASS, &class) == 0 &&
	    strncmp(class, "fault", 5) == 0 &&
	    nvlist_lookup_nvlist(flt_copy, FM_FAULT_RESOURCE, &rsrc) == 0 &&
	    rsrc != NULL && topo_fmri_asru(thp, rsrc, &asru, &err) == 0) {
		(void) nvlist_remove(flt_copy, FM_FAULT_ASRU, DATA_TYPE_NVLIST);
		(void) nvlist_add_nvlist(flt_copy, FM_FAULT_ASRU, asru);
		nvlist_free(asru);
	}
	fmd_fmri_topo_rele(thp);

	(void) nvlist_xdup(flt_copy, &flt, &fmd.d_nva);

	fmd_case_recreate_suspect(cp, flt_copy);

	/*
	 * Now create the resource cache entries.
	 */
	alp = fmd_asru_al_create(ahp, flt, cp, fmd_strbasename(lp->log_name));
	ap = alp->al_asru;

	/*
	 * Check to see if the resource is still present in the system.
	 */
	ps = fmd_asru_replacement_state(flt);
	if (ps == FMD_OBJ_STATE_REPLACED) {
		replaced = FMD_B_TRUE;
	} else if (ps == FMD_OBJ_STATE_STILL_PRESENT ||
	    ps == FMD_OBJ_STATE_UNKNOWN) {
		ap->asru_flags |= FMD_ASRU_PRESENT;
		if (nvlist_lookup_nvlist(alp->al_event, FM_FAULT_ASRU,
		    &asru) == 0) {
			int us;

			switch (fmd_fmri_service_state(asru)) {
			case FMD_SERVICE_STATE_UNUSABLE:
				unusable = FMD_B_TRUE;
				break;
			case FMD_SERVICE_STATE_OK:
			case FMD_SERVICE_STATE_ISOLATE_PENDING:
			case FMD_SERVICE_STATE_DEGRADED:
				unusable = FMD_B_FALSE;
				break;
			case FMD_SERVICE_STATE_UNKNOWN:
			case -1:
				/* not supported by scheme */
				us = fmd_fmri_unusable(asru);
				if (us > 0)
					unusable = FMD_B_TRUE;
				else if (us == 0)
					unusable = FMD_B_FALSE;
				break;
			}
		}
	}

	nvlist_free(flt);

	ap->asru_flags |= FMD_ASRU_RECREATED;
	if (faulty) {
		alp->al_flags |= FMD_ASRU_FAULTY;
		ap->asru_flags |= FMD_ASRU_FAULTY;
	}
	if (unusable) {
		alp->al_flags |= FMD_ASRU_UNUSABLE;
		ap->asru_flags |= FMD_ASRU_UNUSABLE;
	}
	if (replaced)
		alp->al_reason = FMD_ASRU_REPLACED;
	else if (repaired)
		alp->al_reason = FMD_ASRU_REPAIRED;
	else if (acquitted)
		alp->al_reason = FMD_ASRU_ACQUITTED;

	TRACE((FMD_DBG_ASRU, "asru %s recreated as %p (%s)", alp->al_uuid,
	    (void *)ap, _fmd_asru_snames[ap->asru_flags & FMD_ASRU_STATE]));
}

static void
fmd_asru_hash_discard(fmd_asru_hash_t *ahp, const char *uuid, int err)
{
	char src[PATH_MAX], dst[PATH_MAX];

	(void) snprintf(src, PATH_MAX, "%s/%s", ahp->ah_dirpath, uuid);
	(void) snprintf(dst, PATH_MAX, "%s/%s-", ahp->ah_dirpath, uuid);

	if (err != 0)
		err = rename(src, dst);
	else
		err = unlink(src);

	if (err != 0 && errno != ENOENT)
		fmd_error(EFMD_ASRU_EVENT, "failed to rename log %s", src);
}

/*
 * Open a saved log file and restore it into the ASRU hash.  If we can't even
 * open the log, rename the log file to <uuid>- to indicate it is corrupt.  If
 * fmd_log_replay() fails, we either delete the file (if it has reached the
 * upper limit on cache age) or rename it for debugging if it was corrupted.
 */
static void
fmd_asru_hash_logopen(fmd_asru_hash_t *ahp, const char *uuid)
{
	fmd_log_t *lp = fmd_log_tryopen(ahp->ah_dirpath, uuid, FMD_LOG_ASRU);
	uint_t n;

	if (lp == NULL) {
		fmd_asru_hash_discard(ahp, uuid, errno);
		return;
	}

	ahp->ah_error = 0;
	n = ahp->ah_al_count;

	fmd_log_replay(lp, (fmd_log_f *)fmd_asru_hash_recreate, ahp);
	fmd_log_rele(lp);

	if (ahp->ah_al_count == n)
		fmd_asru_hash_discard(ahp, uuid, ahp->ah_error);
}

void
fmd_asru_hash_refresh(fmd_asru_hash_t *ahp)
{
	struct dirent *dp;
	DIR *dirp;
	int zero;

	if ((dirp = opendir(ahp->ah_dirpath)) == NULL) {
		fmd_error(EFMD_ASRU_NODIR,
		    "failed to open asru cache directory %s", ahp->ah_dirpath);
		return;
	}

	(void) fmd_conf_getprop(fmd.d_conf, "rsrc.zero", &zero);

	(void) pthread_rwlock_wrlock(&ahp->ah_lock);

	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue; /* skip "." and ".." */

		if (zero)
			fmd_asru_hash_discard(ahp, dp->d_name, 0);
		else if (!fmd_strmatch(dp->d_name, "*-"))
			fmd_asru_hash_logopen(ahp, dp->d_name);
	}

	(void) pthread_rwlock_unlock(&ahp->ah_lock);
	(void) closedir(dirp);
}

/*
 * If the resource is present and faulty but not unusable, replay the fault
 * event that caused it be marked faulty.  This will cause the agent
 * subscribing to this fault class to again disable the resource.
 */
/*ARGSUSED*/
static void
fmd_asru_hash_replay_asru(fmd_asru_t *ap, void *data)
{
	fmd_event_t *e;
	nvlist_t *nvl;
	char *class;

	if (ap->asru_event != NULL && (ap->asru_flags & (FMD_ASRU_STATE |
	    FMD_ASRU_PRESENT)) == (FMD_ASRU_FAULTY | FMD_ASRU_PRESENT)) {

		fmd_dprintf(FMD_DBG_ASRU,
		    "replaying fault event for %s", ap->asru_name);

		(void) nvlist_xdup(ap->asru_event, &nvl, &fmd.d_nva);
		(void) nvlist_lookup_string(nvl, FM_CLASS, &class);

		(void) nvlist_add_string(nvl, FMD_EVN_UUID,
		    ((fmd_case_impl_t *)ap->asru_case)->ci_uuid);

		e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);
		fmd_dispq_dispatch(fmd.d_disp, e, class);
	}
}

void
fmd_asru_hash_replay(fmd_asru_hash_t *ahp)
{
	fmd_asru_hash_apply(ahp, fmd_asru_hash_replay_asru, NULL);
}

/*
 * Check if the resource is still present. If not, and if the rsrc.age time
 * has expired, then do an implicit repair on the resource.
 */
/*ARGSUSED*/
static void
fmd_asru_repair_if_aged(fmd_asru_link_t *alp, void *arg)
{
	struct timeval tv;
	fmd_log_t *lp;
	hrtime_t hrt;
	int ps;
	int err;

	ps = fmd_asru_replacement_state(alp->al_event);
	if (ps == FMD_OBJ_STATE_REPLACED) {
		fmd_asru_replaced(alp, &err);
	} else if (ps == FMD_OBJ_STATE_NOT_PRESENT) {
		fmd_time_gettimeofday(&tv);
		lp = fmd_log_open(alp->al_asru->asru_root, alp->al_uuid,
		    FMD_LOG_ASRU);
		hrt = (hrtime_t)(tv.tv_sec - lp->log_stat.st_mtime);
		fmd_log_rele(lp);
		if (hrt * NANOSEC >= fmd.d_asrus->ah_lifetime)
			fmd_asru_removed(alp);
	}
}

void
fmd_asru_clear_aged_rsrcs()
{
	fmd_asru_al_hash_apply(fmd.d_asrus, fmd_asru_repair_if_aged, NULL);
}

fmd_asru_hash_t *
fmd_asru_hash_create(const char *root, const char *dir)
{
	fmd_asru_hash_t *ahp;
	char path[PATH_MAX];

	ahp = fmd_alloc(sizeof (fmd_asru_hash_t), FMD_SLEEP);
	(void) pthread_rwlock_init(&ahp->ah_lock, NULL);
	ahp->ah_hashlen = fmd.d_str_buckets;
	ahp->ah_hash = fmd_zalloc(sizeof (void *) * ahp->ah_hashlen, FMD_SLEEP);
	ahp->ah_asru_hash = fmd_zalloc(sizeof (void *) * ahp->ah_hashlen,
	    FMD_SLEEP);
	ahp->ah_case_hash = fmd_zalloc(sizeof (void *) * ahp->ah_hashlen,
	    FMD_SLEEP);
	ahp->ah_fru_hash = fmd_zalloc(sizeof (void *) * ahp->ah_hashlen,
	    FMD_SLEEP);
	ahp->ah_label_hash = fmd_zalloc(sizeof (void *) * ahp->ah_hashlen,
	    FMD_SLEEP);
	ahp->ah_rsrc_hash = fmd_zalloc(sizeof (void *) * ahp->ah_hashlen,
	    FMD_SLEEP);
	(void) snprintf(path, sizeof (path), "%s/%s", root, dir);
	ahp->ah_dirpath = fmd_strdup(path, FMD_SLEEP);
	(void) fmd_conf_getprop(fmd.d_conf, "rsrc.age", &ahp->ah_lifetime);
	(void) fmd_conf_getprop(fmd.d_conf, "fakenotpresent",
	    (uint32_t *)&fmd_asru_fake_not_present);
	ahp->ah_al_count = 0;
	ahp->ah_count = 0;
	ahp->ah_error = 0;
	ahp->ah_topo = fmd_topo_hold();

	return (ahp);
}

void
fmd_asru_hash_destroy(fmd_asru_hash_t *ahp)
{
	fmd_asru_link_t *alp, *np;
	uint_t i;

	for (i = 0; i < ahp->ah_hashlen; i++) {
		for (alp = ahp->ah_case_hash[i]; alp != NULL; alp = np) {
			np = alp->al_case_next;
			alp->al_case_next = NULL;
			fmd_case_rele(alp->al_case);
			alp->al_case = NULL;
			fmd_asru_al_hash_release(ahp, alp);
		}
	}

	fmd_strfree(ahp->ah_dirpath);
	fmd_free(ahp->ah_hash, sizeof (void *) * ahp->ah_hashlen);
	fmd_free(ahp->ah_asru_hash, sizeof (void *) * ahp->ah_hashlen);
	fmd_free(ahp->ah_case_hash, sizeof (void *) * ahp->ah_hashlen);
	fmd_free(ahp->ah_fru_hash, sizeof (void *) * ahp->ah_hashlen);
	fmd_free(ahp->ah_label_hash, sizeof (void *) * ahp->ah_hashlen);
	fmd_free(ahp->ah_rsrc_hash, sizeof (void *) * ahp->ah_hashlen);
	fmd_topo_rele(ahp->ah_topo);
	fmd_free(ahp, sizeof (fmd_asru_hash_t));
}

/*
 * Take a snapshot of the ASRU database by placing an additional hold on each
 * member in an auxiliary array, and then call 'func' for each ASRU.
 */
void
fmd_asru_hash_apply(fmd_asru_hash_t *ahp,
    void (*func)(fmd_asru_t *, void *), void *arg)
{
	fmd_asru_t *ap, **aps, **app;
	uint_t apc, i;

	(void) pthread_rwlock_rdlock(&ahp->ah_lock);

	aps = app = fmd_alloc(ahp->ah_count * sizeof (fmd_asru_t *), FMD_SLEEP);
	apc = ahp->ah_count;

	for (i = 0; i < ahp->ah_hashlen; i++) {
		for (ap = ahp->ah_hash[i]; ap != NULL; ap = ap->asru_next)
			*app++ = fmd_asru_hold(ap);
	}

	ASSERT(app == aps + apc);
	(void) pthread_rwlock_unlock(&ahp->ah_lock);

	for (i = 0; i < apc; i++) {
		if (aps[i]->asru_fmri != NULL)
			func(aps[i], arg);
		fmd_asru_hash_release(ahp, aps[i]);
	}

	fmd_free(aps, apc * sizeof (fmd_asru_t *));
}

void
fmd_asru_al_hash_apply(fmd_asru_hash_t *ahp,
    void (*func)(fmd_asru_link_t *, void *), void *arg)
{
	fmd_asru_link_t *alp, **alps, **alpp;
	uint_t alpc, i;

	(void) pthread_rwlock_rdlock(&ahp->ah_lock);

	alps = alpp = fmd_alloc(ahp->ah_al_count * sizeof (fmd_asru_link_t *),
	    FMD_SLEEP);
	alpc = ahp->ah_al_count;

	for (i = 0; i < ahp->ah_hashlen; i++) {
		for (alp = ahp->ah_case_hash[i]; alp != NULL;
		    alp = alp->al_case_next)
			*alpp++ = fmd_asru_al_hold(alp);
	}

	ASSERT(alpp == alps + alpc);
	(void) pthread_rwlock_unlock(&ahp->ah_lock);

	for (i = 0; i < alpc; i++) {
		func(alps[i], arg);
		fmd_asru_al_hash_release(ahp, alps[i]);
	}

	fmd_free(alps, alpc * sizeof (fmd_asru_link_t *));
}

static void
fmd_asru_do_hash_apply(fmd_asru_hash_t *ahp, char *name,
    void (*func)(fmd_asru_link_t *, void *), void *arg,
    fmd_asru_link_t **hash, size_t match_offset, size_t next_offset)
{
	fmd_asru_link_t *alp, **alps, **alpp;
	uint_t alpc = 0, i;
	uint_t h;

	(void) pthread_rwlock_rdlock(&ahp->ah_lock);

	h = fmd_asru_strhash(ahp, name);

	for (alp = hash[h]; alp != NULL; alp =
	    /* LINTED pointer alignment */
	    FMD_ASRU_AL_HASH_NEXT(alp, next_offset))
		if (fmd_asru_strcmp(ahp,
		    /* LINTED pointer alignment */
		    FMD_ASRU_AL_HASH_NAME(alp, match_offset), name))
			alpc++;

	alps = alpp = fmd_alloc(alpc * sizeof (fmd_asru_link_t *), FMD_SLEEP);

	for (alp = hash[h]; alp != NULL; alp =
	    /* LINTED pointer alignment */
	    FMD_ASRU_AL_HASH_NEXT(alp, next_offset))
		if (fmd_asru_strcmp(ahp,
		    /* LINTED pointer alignment */
		    FMD_ASRU_AL_HASH_NAME(alp, match_offset), name))
			*alpp++ = fmd_asru_al_hold(alp);

	ASSERT(alpp == alps + alpc);
	(void) pthread_rwlock_unlock(&ahp->ah_lock);

	for (i = 0; i < alpc; i++) {
		func(alps[i], arg);
		fmd_asru_al_hash_release(ahp, alps[i]);
	}

	fmd_free(alps, alpc * sizeof (fmd_asru_link_t *));
}

void
fmd_asru_hash_apply_by_asru(fmd_asru_hash_t *ahp, char *name,
    void (*func)(fmd_asru_link_t *, void *), void *arg)
{
	fmd_asru_do_hash_apply(ahp, name, func, arg, ahp->ah_asru_hash,
	    offsetof(fmd_asru_link_t, al_asru_name),
	    offsetof(fmd_asru_link_t, al_asru_next));
}

void
fmd_asru_hash_apply_by_case(fmd_asru_hash_t *ahp, fmd_case_t *cp,
	void (*func)(fmd_asru_link_t *, void *), void *arg)
{
	fmd_asru_do_hash_apply(ahp, ((fmd_case_impl_t *)cp)->ci_uuid, func, arg,
	    ahp->ah_case_hash, offsetof(fmd_asru_link_t, al_case_uuid),
	    offsetof(fmd_asru_link_t, al_case_next));
}

void
fmd_asru_hash_apply_by_fru(fmd_asru_hash_t *ahp, char *name,
    void (*func)(fmd_asru_link_t *, void *), void *arg)
{
	fmd_asru_do_hash_apply(ahp, name, func, arg, ahp->ah_fru_hash,
	    offsetof(fmd_asru_link_t, al_fru_name),
	    offsetof(fmd_asru_link_t, al_fru_next));
}

void
fmd_asru_hash_apply_by_rsrc(fmd_asru_hash_t *ahp, char *name,
    void (*func)(fmd_asru_link_t *, void *), void *arg)
{
	fmd_asru_do_hash_apply(ahp, name, func, arg, ahp->ah_rsrc_hash,
	    offsetof(fmd_asru_link_t, al_rsrc_name),
	    offsetof(fmd_asru_link_t, al_rsrc_next));
}

void
fmd_asru_hash_apply_by_label(fmd_asru_hash_t *ahp, char *name,
    void (*func)(fmd_asru_link_t *, void *), void *arg)
{
	fmd_asru_do_hash_apply(ahp, name, func, arg, ahp->ah_label_hash,
	    offsetof(fmd_asru_link_t, al_label),
	    offsetof(fmd_asru_link_t, al_label_next));
}

/*
 * Lookup an asru in the hash by name and place a hold on it.  If the asru is
 * not found, no entry is created and NULL is returned.
 */
fmd_asru_t *
fmd_asru_hash_lookup_name(fmd_asru_hash_t *ahp, const char *name)
{
	fmd_asru_t *ap;

	(void) pthread_rwlock_rdlock(&ahp->ah_lock);
	ap = fmd_asru_hash_lookup(ahp, name);
	(void) pthread_rwlock_unlock(&ahp->ah_lock);

	return (ap);
}

/*
 * Create a resource cache entry using the fault event "nvl" for one of the
 * suspects from the case "cp".
 *
 * The fault event can have the following components :  FM_FAULT_ASRU,
 * FM_FAULT_FRU, FM_FAULT_RESOURCE. These should be set by the Diagnosis Engine
 * when calling fmd_nvl_create_fault(). In the general case, these are all
 * optional and an entry will always be added into the cache even if one or all
 * of these fields is missing.
 *
 * However, for hardware faults the recommended practice is that the fault
 * event should always have the FM_FAULT_RESOURCE field present and that this
 * should be represented in hc-scheme.
 *
 * Currently the DE should also add the FM_FAULT_ASRU and FM_FAULT_FRU fields
 * where known, though at some future stage fmd might be able to fill these
 * in automatically from the topology.
 */
fmd_asru_link_t *
fmd_asru_hash_create_entry(fmd_asru_hash_t *ahp, fmd_case_t *cp, nvlist_t *nvl)
{
	char *parsed_uuid;
	uuid_t uuid;
	int uuidlen;
	fmd_asru_link_t *alp;

	/*
	 * Generate a UUID for the ASRU.  libuuid cleverly gives us no
	 * interface for specifying or learning the buffer size.  Sigh.
	 * The spec says 36 bytes but we use a tunable just to be safe.
	 */
	(void) fmd_conf_getprop(fmd.d_conf, "uuidlen", &uuidlen);
	parsed_uuid = fmd_zalloc(uuidlen + 1, FMD_SLEEP);
	uuid_generate(uuid);
	uuid_unparse(uuid, parsed_uuid);

	/*
	 * Now create the resource cache entries.
	 */
	fmd_case_hold_locked(cp);
	alp = fmd_asru_al_create(ahp, nvl, cp, parsed_uuid);
	TRACE((FMD_DBG_ASRU, "asru %s created as %p",
	    alp->al_uuid, (void *)alp->al_asru));

	fmd_free(parsed_uuid, uuidlen + 1);
	return (alp);

}

/*
 * Release the reference count on an asru obtained using fmd_asru_hash_lookup.
 * We take 'ahp' for symmetry and in case we need to use it in future work.
 */
/*ARGSUSED*/
void
fmd_asru_hash_release(fmd_asru_hash_t *ahp, fmd_asru_t *ap)
{
	(void) pthread_mutex_lock(&ap->asru_lock);

	ASSERT(ap->asru_refs != 0);
	if (--ap->asru_refs == 0)
		fmd_asru_destroy(ap);
	else
		(void) pthread_mutex_unlock(&ap->asru_lock);
}

static void
fmd_asru_do_delete_entry(fmd_asru_hash_t *ahp, fmd_case_t *cp,
    fmd_asru_link_t **hash, size_t next_offset, char *name)
{
	uint_t h;
	fmd_asru_link_t *alp, **pp, *alpnext, **alpnextp;

	(void) pthread_rwlock_wrlock(&ahp->ah_lock);
	h = fmd_asru_strhash(ahp, name);
	pp = &hash[h];
	for (alp = *pp; alp != NULL; alp = alpnext) {
		/* LINTED pointer alignment */
		alpnextp = FMD_ASRU_AL_HASH_NEXTP(alp, next_offset);
		alpnext = *alpnextp;
		if (alp->al_case == cp) {
			*pp = *alpnextp;
			*alpnextp = NULL;
		} else
			pp = alpnextp;
	}
	(void) pthread_rwlock_unlock(&ahp->ah_lock);
}

static void
fmd_asru_do_hash_delete(fmd_asru_hash_t *ahp, fmd_case_susp_t *cis,
    fmd_case_t *cp, fmd_asru_link_t **hash, size_t next_offset, char *nvname)
{
	nvlist_t *nvl;
	char *name = NULL;
	ssize_t namelen;

	if (nvlist_lookup_nvlist(cis->cis_nvl, nvname, &nvl) == 0 &&
	    (namelen = fmd_fmri_nvl2str(nvl, NULL, 0)) != -1 &&
	    (name = fmd_alloc(namelen + 1, FMD_SLEEP)) != NULL) {
		if (fmd_fmri_nvl2str(nvl, name, namelen + 1) != -1)
			fmd_asru_do_delete_entry(ahp, cp, hash, next_offset,
			    name);
		fmd_free(name, namelen + 1);
	} else
		fmd_asru_do_delete_entry(ahp, cp, hash, next_offset, "");
}

void
fmd_asru_hash_delete_case(fmd_asru_hash_t *ahp, fmd_case_t *cp)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_case_susp_t *cis;
	fmd_asru_link_t *alp, **plp, *alpnext;
	fmd_asru_t *ap;
	char path[PATH_MAX];
	char *label;
	uint_t h;

	/*
	 * first delete hash entries for each suspect
	 */
	for (cis = cip->ci_suspects; cis != NULL; cis = cis->cis_next) {
		fmd_asru_do_hash_delete(ahp, cis, cp, ahp->ah_fru_hash,
		    offsetof(fmd_asru_link_t, al_fru_next), FM_FAULT_FRU);
		fmd_asru_do_hash_delete(ahp, cis, cp, ahp->ah_rsrc_hash,
		    offsetof(fmd_asru_link_t, al_rsrc_next), FM_FAULT_RESOURCE);
		if (nvlist_lookup_string(cis->cis_nvl, FM_FAULT_LOCATION,
		    &label) != 0)
			label = "";
		fmd_asru_do_delete_entry(ahp, cp, ahp->ah_label_hash,
		    offsetof(fmd_asru_link_t, al_label_next), label);
		fmd_asru_do_hash_delete(ahp, cis, cp, ahp->ah_asru_hash,
		    offsetof(fmd_asru_link_t, al_asru_next), FM_FAULT_ASRU);
	}

	/*
	 * then delete associated case hash entries
	 */
	(void) pthread_rwlock_wrlock(&ahp->ah_lock);
	h = fmd_asru_strhash(ahp, cip->ci_uuid);
	plp = &ahp->ah_case_hash[h];
	for (alp = *plp; alp != NULL; alp = alpnext) {
		alpnext = alp->al_case_next;
		if (alp->al_case == cp) {
			*plp = alp->al_case_next;
			alp->al_case_next = NULL;
			ASSERT(ahp->ah_al_count != 0);
			ahp->ah_al_count--;

			/*
			 * decrement case ref.
			 */
			fmd_case_rele_locked(cp);
			alp->al_case = NULL;

			/*
			 * If we found a matching ASRU, unlink its log file and
			 * then release the hash entry. Note that it may still
			 * be referenced if another thread is manipulating it;
			 * this is ok because once we unlink, the log file will
			 * not be restored, and the log data will be freed when
			 * all of the referencing threads release their
			 * respective references.
			 */
			(void) snprintf(path, sizeof (path), "%s/%s",
			    ahp->ah_dirpath, alp->al_uuid);
			if (unlink(path) != 0)
				fmd_error(EFMD_ASRU_UNLINK,
				    "failed to unlink asru %s", path);

			/*
			 * Now unlink from the global per-resource cache
			 * and if this is the last link then remove that from
			 * it's own hash too.
			 */
			ap = alp->al_asru;
			(void) pthread_mutex_lock(&ap->asru_lock);
			fmd_list_delete(&ap->asru_list, alp);
			if (ap->asru_list.l_next == NULL) {
				uint_t h;
				fmd_asru_t *ap2, **pp;
				fmd_asru_t *apnext, **apnextp;

				ASSERT(ahp->ah_count != 0);
				ahp->ah_count--;
				h = fmd_asru_strhash(ahp, ap->asru_name);
				pp = &ahp->ah_hash[h];
				for (ap2 = *pp; ap2 != NULL; ap2 = apnext) {
					apnextp = &ap2->asru_next;
					apnext = *apnextp;
					if (ap2 == ap) {
						*pp = *apnextp;
						*apnextp = NULL;
					} else
						pp = apnextp;
				}
			}
			(void) pthread_mutex_unlock(&ap->asru_lock);
			fmd_asru_al_hash_release(ahp, alp);
		} else
			plp = &alp->al_case_next;
	}
	(void) pthread_rwlock_unlock(&ahp->ah_lock);
}

static void
fmd_asru_repair_containee(fmd_asru_link_t *alp, void *er)
{
	if (er && (alp->al_asru->asru_flags & FMD_ASRU_INVISIBLE) &&
	    alp->al_asru_fmri && fmd_fmri_contains(er,
	    alp->al_asru_fmri) > 0 && fmd_asru_clrflags(alp, FMD_ASRU_FAULTY,
	    FMD_ASRU_REPAIRED))
		fmd_case_update(alp->al_case);
}

void
fmd_asru_repaired(fmd_asru_link_t *alp, void *er)
{
	int flags;
	int rval;

	/*
	 * repair this asru cache entry
	 */
	rval = fmd_asru_clrflags(alp, FMD_ASRU_FAULTY, FMD_ASRU_REPAIRED);

	/*
	 * now check if all entries associated with this asru are repaired and
	 * if so repair containees
	 */
	(void) pthread_mutex_lock(&alp->al_asru->asru_lock);
	flags = alp->al_asru->asru_flags;
	(void) pthread_mutex_unlock(&alp->al_asru->asru_lock);
	if (!(flags & (FMD_ASRU_FAULTY | FMD_ASRU_INVISIBLE)))
		fmd_asru_al_hash_apply(fmd.d_asrus, fmd_asru_repair_containee,
		    alp->al_asru_fmri);

	/*
	 * if called from fmd_adm_repair() and we really did clear the bit then
	 * we need to do a case update to see if the associated case can be
	 * repaired. No need to do this if called from fmd_case_repair() (ie
	 * when er is NULL) as the case will be explicitly repaired anyway.
	 */
	if (er) {
		*(int *)er = 0;
		if (rval)
			fmd_case_update(alp->al_case);
	}
}

static void
fmd_asru_acquit_containee(fmd_asru_link_t *alp, void *er)
{
	if (er && (alp->al_asru->asru_flags & FMD_ASRU_INVISIBLE) &&
	    alp->al_asru_fmri && fmd_fmri_contains(er,
	    alp->al_asru_fmri) > 0 && fmd_asru_clrflags(alp, FMD_ASRU_FAULTY,
	    FMD_ASRU_ACQUITTED))
		fmd_case_update(alp->al_case);
}

void
fmd_asru_acquit(fmd_asru_link_t *alp, void *er)
{
	int flags;
	int rval;

	/*
	 * acquit this asru cache entry
	 */
	rval = fmd_asru_clrflags(alp, FMD_ASRU_FAULTY, FMD_ASRU_ACQUITTED);

	/*
	 * now check if all entries associated with this asru are acquitted and
	 * if so acquit containees
	 */
	(void) pthread_mutex_lock(&alp->al_asru->asru_lock);
	flags = alp->al_asru->asru_flags;
	(void) pthread_mutex_unlock(&alp->al_asru->asru_lock);
	if (!(flags & (FMD_ASRU_FAULTY | FMD_ASRU_INVISIBLE)))
		fmd_asru_al_hash_apply(fmd.d_asrus, fmd_asru_acquit_containee,
		    alp->al_asru_fmri);

	/*
	 * if called from fmd_adm_acquit() and we really did clear the bit then
	 * we need to do a case update to see if the associated case can be
	 * repaired. No need to do this if called from fmd_case_acquit() (ie
	 * when er is NULL) as the case will be explicitly repaired anyway.
	 */
	if (er) {
		*(int *)er = 0;
		if (rval)
			fmd_case_update(alp->al_case);
	}
}

static void
fmd_asru_replaced_containee(fmd_asru_link_t *alp, void *er)
{
	if (er && (alp->al_asru->asru_flags & FMD_ASRU_INVISIBLE) &&
	    alp->al_asru_fmri && fmd_fmri_contains(er,
	    alp->al_asru_fmri) > 0 && fmd_asru_clrflags(alp, FMD_ASRU_FAULTY,
	    FMD_ASRU_REPLACED))
		fmd_case_update(alp->al_case);
}

void
fmd_asru_replaced(fmd_asru_link_t *alp, void *er)
{
	int flags;
	int rval;
	int ps;

	ps = fmd_asru_replacement_state(alp->al_event);
	if (ps == FMD_OBJ_STATE_STILL_PRESENT)
		return;

	/*
	 * mark this cache entry as replaced
	 */
	rval = fmd_asru_clrflags(alp, FMD_ASRU_FAULTY, FMD_ASRU_REPLACED);

	/*
	 * now check if all entries associated with this asru are replaced and
	 * if so replace containees
	 */
	(void) pthread_mutex_lock(&alp->al_asru->asru_lock);
	flags = alp->al_asru->asru_flags;
	(void) pthread_mutex_unlock(&alp->al_asru->asru_lock);
	if (!(flags & (FMD_ASRU_FAULTY | FMD_ASRU_INVISIBLE)))
		fmd_asru_al_hash_apply(fmd.d_asrus, fmd_asru_replaced_containee,
		    alp->al_asru_fmri);

	*(int *)er = 0;
	if (rval)
		fmd_case_update(alp->al_case);
}

static void
fmd_asru_removed_containee(fmd_asru_link_t *alp, void *er)
{
	if (er && (alp->al_asru->asru_flags & FMD_ASRU_INVISIBLE) &&
	    alp->al_asru_fmri && fmd_fmri_contains(er,
	    alp->al_asru_fmri) > 0 && fmd_asru_clrflags(alp, FMD_ASRU_FAULTY,
	    0))
		fmd_case_update(alp->al_case);
}

void
fmd_asru_removed(fmd_asru_link_t *alp)
{
	int flags;
	int rval;

	/*
	 * mark this cache entry as replacded
	 */
	rval = fmd_asru_clrflags(alp, FMD_ASRU_FAULTY, 0);

	/*
	 * now check if all entries associated with this asru are removed and
	 * if so replace containees
	 */
	(void) pthread_mutex_lock(&alp->al_asru->asru_lock);
	flags = alp->al_asru->asru_flags;
	(void) pthread_mutex_unlock(&alp->al_asru->asru_lock);
	if (!(flags & (FMD_ASRU_FAULTY | FMD_ASRU_INVISIBLE)))
		fmd_asru_al_hash_apply(fmd.d_asrus, fmd_asru_removed_containee,
		    alp->al_asru_fmri);
	if (rval)
		fmd_case_update(alp->al_case);
}

static void
fmd_asru_logevent(fmd_asru_link_t *alp)
{
	fmd_asru_t *ap = alp->al_asru;
	boolean_t faulty = (alp->al_flags & FMD_ASRU_FAULTY) != 0;
	boolean_t unusable = (alp->al_flags & FMD_ASRU_UNUSABLE) != 0;
	boolean_t message = (ap->asru_flags & FMD_ASRU_INVISIBLE) == 0;
	boolean_t repaired = (alp->al_reason == FMD_ASRU_REPAIRED);
	boolean_t replaced = (alp->al_reason == FMD_ASRU_REPLACED);
	boolean_t acquitted = (alp->al_reason == FMD_ASRU_ACQUITTED);

	fmd_case_impl_t *cip;
	fmd_event_t *e;
	fmd_log_t *lp;
	nvlist_t *nvl;
	char *class;

	ASSERT(MUTEX_HELD(&ap->asru_lock));
	cip = (fmd_case_impl_t *)alp->al_case;
	ASSERT(cip != NULL);

	if ((lp = alp->al_log) == NULL)
		lp = fmd_log_open(ap->asru_root, alp->al_uuid, FMD_LOG_ASRU);

	if (lp == NULL)
		return; /* can't log events if we can't open the log */

	nvl = fmd_protocol_rsrc_asru(_fmd_asru_events[faulty | (unusable << 1)],
	    alp->al_asru_fmri, cip->ci_uuid, cip->ci_code, faulty, unusable,
	    message, alp->al_event, &cip->ci_tv, repaired, replaced, acquitted);

	(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
	e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);

	fmd_event_hold(e);
	fmd_log_append(lp, e, NULL);
	fmd_event_rele(e);

	/*
	 * For now, we close the log file after every update to conserve file
	 * descriptors and daemon overhead.  If this becomes a performance
	 * issue this code can change to keep a fixed-size LRU cache of logs.
	 */
	fmd_log_rele(lp);
	alp->al_log = NULL;
}

int
fmd_asru_setflags(fmd_asru_link_t *alp, uint_t sflag)
{
	fmd_asru_t *ap = alp->al_asru;
	uint_t nstate, ostate;

	ASSERT(!(sflag & ~FMD_ASRU_STATE));
	ASSERT(sflag != FMD_ASRU_STATE);

	(void) pthread_mutex_lock(&ap->asru_lock);

	ostate = alp->al_flags & FMD_ASRU_STATE;
	alp->al_flags |= sflag;
	nstate = alp->al_flags & FMD_ASRU_STATE;

	if (nstate == ostate) {
		(void) pthread_mutex_unlock(&ap->asru_lock);
		return (0);
	}

	ap->asru_flags |= sflag;
	TRACE((FMD_DBG_ASRU, "asru %s %s->%s", alp->al_uuid,
	    _fmd_asru_snames[ostate], _fmd_asru_snames[nstate]));

	fmd_asru_logevent(alp);

	(void) pthread_cond_broadcast(&ap->asru_cv);
	(void) pthread_mutex_unlock(&ap->asru_lock);
	return (1);
}

int
fmd_asru_clrflags(fmd_asru_link_t *alp, uint_t sflag, uint8_t reason)
{
	fmd_asru_t *ap = alp->al_asru;
	fmd_asru_link_t *nalp;
	uint_t nstate, ostate, flags = 0;

	ASSERT(!(sflag & ~FMD_ASRU_STATE));
	ASSERT(sflag != FMD_ASRU_STATE);

	(void) pthread_mutex_lock(&ap->asru_lock);

	ostate = alp->al_flags & FMD_ASRU_STATE;
	alp->al_flags &= ~sflag;
	nstate = alp->al_flags & FMD_ASRU_STATE;

	if (nstate == ostate) {
		if (reason > alp->al_reason) {
			alp->al_reason = reason;
			fmd_asru_logevent(alp);
			(void) pthread_cond_broadcast(&ap->asru_cv);
		}
		(void) pthread_mutex_unlock(&ap->asru_lock);
		return (0);
	}
	if (reason > alp->al_reason)
		alp->al_reason = reason;

	if (sflag == FMD_ASRU_UNUSABLE)
		ap->asru_flags &= ~sflag;
	else if (sflag == FMD_ASRU_FAULTY) {
		/*
		 * only clear the faulty bit if all links are clear
		 */
		for (nalp = fmd_list_next(&ap->asru_list); nalp != NULL;
		    nalp = fmd_list_next(nalp))
			flags |= nalp->al_flags;
		if (!(flags & FMD_ASRU_FAULTY))
			ap->asru_flags &= ~sflag;
	}

	TRACE((FMD_DBG_ASRU, "asru %s %s->%s", alp->al_uuid,
	    _fmd_asru_snames[ostate], _fmd_asru_snames[nstate]));

	fmd_asru_logevent(alp);

	(void) pthread_cond_broadcast(&ap->asru_cv);
	(void) pthread_mutex_unlock(&ap->asru_lock);

	return (1);
}

/*
 * Report the current known state of the link entry (ie this particular fault
 * affecting this particular ASRU).
 */
int
fmd_asru_al_getstate(fmd_asru_link_t *alp)
{
	int us, st;
	nvlist_t *asru;
	int ps;

	ps = fmd_asru_replacement_state(alp->al_event);
	if (ps == FMD_OBJ_STATE_NOT_PRESENT)
		return ((alp->al_flags & FMD_ASRU_FAULTY) | FMD_ASRU_UNUSABLE);
	if (ps == FMD_OBJ_STATE_REPLACED) {
		if (alp->al_reason < FMD_ASRU_REPLACED)
			alp->al_reason = FMD_ASRU_REPLACED;
		return ((alp->al_flags & FMD_ASRU_FAULTY) | FMD_ASRU_UNUSABLE);
	}

	st = (alp->al_flags & FMD_ASRU_STATE) | FMD_ASRU_PRESENT;
	if (nvlist_lookup_nvlist(alp->al_event, FM_FAULT_ASRU, &asru) == 0) {
		us = fmd_fmri_service_state(asru);
		if (us == -1 || us == FMD_SERVICE_STATE_UNKNOWN) {
			/* not supported by scheme - try fmd_fmri_unusable */
			us = fmd_fmri_unusable(asru);
		} else if (us == FMD_SERVICE_STATE_UNUSABLE) {
			st |= FMD_ASRU_UNUSABLE;
			return (st);
		} else if (us == FMD_SERVICE_STATE_OK) {
			st &= ~FMD_ASRU_UNUSABLE;
			return (st);
		} else if (us == FMD_SERVICE_STATE_ISOLATE_PENDING) {
			st &= ~FMD_ASRU_UNUSABLE;
			return (st);
		} else if (us == FMD_SERVICE_STATE_DEGRADED) {
			st &= ~FMD_ASRU_UNUSABLE;
			st |= FMD_ASRU_DEGRADED;
			return (st);
		}
	} else
		us = (alp->al_flags & FMD_ASRU_UNUSABLE);
	if (us > 0)
		st |= FMD_ASRU_UNUSABLE;
	else if (us == 0)
		st &= ~FMD_ASRU_UNUSABLE;
	return (st);
}

/*
 * Report the current known state of the ASRU by refreshing its unusable status
 * based upon the routines provided by the scheme module.  If the unusable bit
 * is different, we do *not* generate a state change here because that change
 * may be unrelated to fmd activities and therefore we have no case or event.
 * The absence of the transition is harmless as this function is only provided
 * for RPC observability and fmd's clients are only concerned with ASRU_FAULTY.
 */
int
fmd_asru_getstate(fmd_asru_t *ap)
{
	int us, st;

	if (!(ap->asru_flags & FMD_ASRU_INTERNAL) &&
	    (fmd_asru_fake_not_present >= FMD_OBJ_STATE_REPLACED ||
	    fmd_fmri_present(ap->asru_fmri) <= 0))
		return (0); /* do not report non-fmd non-present resources */

	us = fmd_fmri_unusable(ap->asru_fmri);
	st = ap->asru_flags & FMD_ASRU_STATE;

	if (us > 0)
		st |= FMD_ASRU_UNUSABLE;
	else if (us == 0)
		st &= ~FMD_ASRU_UNUSABLE;

	return (st);
}
