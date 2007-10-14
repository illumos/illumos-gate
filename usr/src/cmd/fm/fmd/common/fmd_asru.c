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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fm/protocol.h>
#include <uuid/uuid.h>

#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <alloca.h>

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

static fmd_asru_t *
fmd_asru_create(fmd_asru_hash_t *ahp, const char *uuid,
    const char *name, nvlist_t *fmri)
{
	fmd_asru_t *ap = fmd_alloc(sizeof (fmd_asru_t), FMD_SLEEP);
	char *s;

	(void) pthread_mutex_init(&ap->asru_lock, NULL);
	(void) pthread_cond_init(&ap->asru_cv, NULL);

	ap->asru_next = NULL;
	ap->asru_name = fmd_strdup(name, FMD_SLEEP);
	(void) nvlist_xdup(fmri, &ap->asru_fmri, &fmd.d_nva);
	ap->asru_root = fmd_strdup(ahp->ah_dirpath, FMD_SLEEP);
	ap->asru_uuid = fmd_strdup(uuid, FMD_SLEEP);
	ap->asru_uuidlen = ap->asru_uuid ? strlen(ap->asru_uuid) : 0;
	ap->asru_log = NULL;
	ap->asru_refs = 1;
	ap->asru_flags = 0;
	ap->asru_case = NULL;
	ap->asru_event = NULL;

	if (nvlist_lookup_string(ap->asru_fmri, FM_FMRI_SCHEME, &s) == 0 &&
	    strcmp(s, FM_FMRI_SCHEME_FMD) == 0)
		ap->asru_flags |= FMD_ASRU_INTERNAL;

	return (ap);
}

static void
fmd_asru_destroy(fmd_asru_t *ap)
{
	ASSERT(MUTEX_HELD(&ap->asru_lock));
	ASSERT(ap->asru_refs == 0);

	if (ap->asru_log != NULL)
		fmd_log_rele(ap->asru_log);

	if (ap->asru_case != NULL)
		fmd_case_rele(ap->asru_case);

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
	uint_t h = fmd_strhash(ap->asru_name) % ahp->ah_hashlen;

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
	h = fmd_strhash(name) % ahp->ah_hashlen;

	for (ap = ahp->ah_hash[h]; ap != NULL; ap = ap->asru_next) {
		if (strcmp(ap->asru_name, name) == 0)
			break;
	}

	if (ap != NULL)
		(void) fmd_asru_hold(ap);
	else
		(void) fmd_set_errno(EFMD_ASRU_NOENT);

	return (ap);
}

static void
fmd_asru_hash_recreate(fmd_log_t *lp, fmd_event_t *ep, fmd_asru_hash_t *ahp)
{
	nvlist_t *nvl = FMD_EVENT_NVL(ep);
	char *case_uuid = NULL, *case_code = NULL;
	char *name = NULL;
	ssize_t namelen;

	nvlist_t *fmri, *flt, *flt_copy;
	boolean_t f, u, m;
	fmd_asru_t *ap;
	int ps, us;
	int64_t *diag_time;
	uint_t nelem;

	/*
	 * Extract the resource FMRI and most recent values of 'faulty' and
	 * 'unusable' from the event log.  If the event is malformed, return.
	 */
	if (nvlist_lookup_nvlist(nvl, FM_RSRC_RESOURCE, &fmri) != 0 ||
	    nvlist_lookup_boolean_value(nvl, FM_RSRC_ASRU_FAULTY, &f) != 0 ||
	    nvlist_lookup_boolean_value(nvl, FM_RSRC_ASRU_UNUSABLE, &u) != 0) {
		fmd_error(EFMD_ASRU_EVENT, "failed to reload asru %s: "
		    "invalid event log record\n", lp->log_name);
		ahp->ah_error = EFMD_ASRU_EVENT;
		return;
	}

	/*
	 * If this resource has been explicitly repaired, then return and
	 * discard the log. This is consistant with the behaviour when rsrc.age
	 * expires below.
	 */
	if (!f)
		return;

	/*
	 * Check to see if the resource is still present in the system.  If
	 * so, then update the value of the unusable bit based on the current
	 * system configuration.  If not, then either keep the entry in our
	 * cache if it is recent, or return and discard it if it is too old.
	 */
	if (fmd_asru_fake_not_present)
		ps = 0;
	else if ((ps = fmd_fmri_present(fmri)) == -1) {
		fmd_error(EFMD_ASRU_FMRI, "failed to locate %s", lp->log_name);
		ahp->ah_error = EFMD_ASRU_FMRI;
		return;
	}

	if (ps) {
		if ((us = fmd_fmri_unusable(fmri)) == -1) {
			fmd_error(EFMD_ASRU_FMRI, "failed to update "
			    "status of asru %s", lp->log_name);
			u = FMD_B_FALSE;
		} else
			u = us != 0;

	} else {
		struct timeval tv;

		fmd_time_gettimeofday(&tv);
		if ((hrtime_t)(tv.tv_sec -
		    lp->log_stat.st_mtime) * NANOSEC < ahp->ah_lifetime) {
			u = FMD_B_TRUE; /* not present; set unusable */
		} else
			return;	 /* too old; discard this log */
	}

	/*
	 * In order to insert the ASRU into our hash, convert the FMRI from
	 * nvlist form into a string form and assign this name to the ASRU.
	 */
	if ((namelen = fmd_fmri_nvl2str(fmri, NULL, 0)) == -1 ||
	    (name = fmd_alloc(namelen + 1, FMD_NOSLEEP)) == NULL ||
	    fmd_fmri_nvl2str(fmri, name, namelen + 1) == -1) {
		fmd_error(EFMD_ASRU_FMRI,
		    "failed to reload asru %s", lp->log_name);
		if (name != NULL)
			fmd_free(name, namelen + 1);
		ahp->ah_error = EFMD_ASRU_FMRI;
		return;
	}

	/*
	 * Look to see if the ASRU already exists in the hash: if it does and
	 * the existing ASRU entry is unusable but the duplicate is not, then
	 * delete the existing entry and continue on using the new entry; if
	 * the new entry is no "better", return an error and ignore it.
	 */
	if ((ap = fmd_asru_hash_lookup(ahp, name)) != NULL) {
		if (!u && (ap->asru_flags & FMD_ASRU_UNUSABLE)) {
			(void) fmd_asru_hash_delete_name(ahp, name);
			fmd_asru_hash_release(ahp, ap);
		} else {
			fmd_error(EFMD_ASRU_DUP, "removing duplicate asru "
			    "log %s for %s\n", lp->log_name, name);
			fmd_free(name, namelen + 1);
			fmd_asru_hash_release(ahp, ap);
			ahp->ah_error = EFMD_ASRU_DUP;
			return;
		}
	}

	ap = fmd_asru_create(ahp, fmd_strbasename(lp->log_name), name, fmri);
	fmd_free(name, namelen + 1);
	ap->asru_flags |= FMD_ASRU_RECREATED;

	if (ps)
		ap->asru_flags |= FMD_ASRU_PRESENT;
	if (f)
		ap->asru_flags |= FMD_ASRU_FAULTY;
	if (u)
		ap->asru_flags |= FMD_ASRU_UNUSABLE;

	if (nvlist_lookup_boolean_value(nvl,
	    FM_SUSPECT_MESSAGE, &m) == 0 && m == B_FALSE)
		ap->asru_flags |= FMD_ASRU_INVISIBLE;

	/*
	 * Recreate the case in the CLOSED state. If the case is not closed,
	 * fmd_case_transition_update() will set it to the correct state later.
	 * If the case is already present, fmd_case_recreate() will return
	 * as an orphaned case. If not, it will create a new orphaned case.
	 * Either way we use the ASRU event to insert a suspect into the
	 * restored case.
	 */
	(void) nvlist_lookup_string(nvl, FM_RSRC_ASRU_UUID, &case_uuid);
	(void) nvlist_lookup_string(nvl, FM_RSRC_ASRU_CODE, &case_code);
	(void) nvlist_lookup_nvlist(nvl, FM_RSRC_ASRU_EVENT, &flt);

	fmd_module_lock(fmd.d_rmod);

	ap->asru_case = fmd_case_recreate(fmd.d_rmod, NULL,
	    FMD_CASE_CLOSED, case_uuid, case_code);
	ASSERT(ap->asru_case != NULL);

	ASSERT(fmd_case_orphaned(ap->asru_case));

	fmd_case_hold(ap->asru_case);
	fmd_module_unlock(fmd.d_rmod);

	if (nvlist_lookup_int64_array(nvl, FM_SUSPECT_DIAG_TIME, &diag_time,
	    &nelem) == 0 && nelem >= 2)
		fmd_case_settime(ap->asru_case, diag_time[0], diag_time[1]);
	else
		fmd_case_settime(ap->asru_case, lp->log_stat.st_ctime, 0);

	(void) nvlist_xdup(flt, &ap->asru_event, &fmd.d_nva);
	(void) nvlist_xdup(flt, &flt_copy, &fmd.d_nva);
	fmd_case_recreate_suspect(ap->asru_case, flt_copy);

	ASSERT(!(ap->asru_flags & FMD_ASRU_VALID));
	ap->asru_flags |= FMD_ASRU_VALID;
	fmd_asru_hash_insert(ahp, ap);

	TRACE((FMD_DBG_ASRU, "asru %s recreated as %p (%s)", ap->asru_uuid,
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
	n = ahp->ah_count;

	fmd_log_replay(lp, (fmd_log_f *)fmd_asru_hash_recreate, ahp);
	fmd_log_rele(lp);

	if (ahp->ah_count == n)
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

fmd_asru_hash_t *
fmd_asru_hash_create(const char *root, const char *dir)
{
	fmd_asru_hash_t *ahp;
	char path[PATH_MAX];

	ahp = fmd_alloc(sizeof (fmd_asru_hash_t), FMD_SLEEP);
	(void) pthread_rwlock_init(&ahp->ah_lock, NULL);
	ahp->ah_hashlen = fmd.d_str_buckets;
	ahp->ah_hash = fmd_zalloc(sizeof (void *) * ahp->ah_hashlen, FMD_SLEEP);
	(void) snprintf(path, sizeof (path), "%s/%s", root, dir);
	ahp->ah_dirpath = fmd_strdup(path, FMD_SLEEP);
	(void) fmd_conf_getprop(fmd.d_conf, "rsrc.age", &ahp->ah_lifetime);
	(void) fmd_conf_getprop(fmd.d_conf, "fakenotpresent",
	    (uint32_t *)&fmd_asru_fake_not_present);
	ahp->ah_count = 0;
	ahp->ah_error = 0;

	return (ahp);
}

void
fmd_asru_hash_destroy(fmd_asru_hash_t *ahp)
{
	fmd_asru_t *ap, *np;
	uint_t i;

	for (i = 0; i < ahp->ah_hashlen; i++) {
		for (ap = ahp->ah_hash[i]; ap != NULL; ap = np) {
			np = ap->asru_next;
			ap->asru_next = NULL;
			fmd_asru_hash_release(ahp, ap);
		}
	}

	fmd_strfree(ahp->ah_dirpath);
	fmd_free(ahp->ah_hash, sizeof (void *) * ahp->ah_hashlen);
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
		func(aps[i], arg);
		fmd_asru_hash_release(ahp, aps[i]);
	}

	fmd_free(aps, apc * sizeof (fmd_asru_t *));
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
 * Lookup an asru in the hash and place a hold on it.  If 'create' is true, an
 * absent entry will be created for the caller; otherwise NULL is returned.
 */
fmd_asru_t *
fmd_asru_hash_lookup_nvl(fmd_asru_hash_t *ahp, nvlist_t *fmri, int create)
{
	fmd_asru_t *ap;
	char *name = NULL;
	ssize_t namelen;
	uint_t h;

	/*
	 * In order to lookup the ASRU in our hash, convert the FMRI from
	 * nvlist form into a string form using the scheme module.
	 */
	if ((namelen = fmd_fmri_nvl2str(fmri, NULL, 0)) == -1 ||
	    (name = fmd_alloc(namelen + 1, FMD_NOSLEEP)) == NULL ||
	    fmd_fmri_nvl2str(fmri, name, namelen + 1) == -1) {
		if (name != NULL)
			fmd_free(name, namelen + 1);
		return (NULL);
	}

	/*
	 * If we must create the asru, grab the rwlock as a writer; otherwise
	 * reader is sufficient.  Then search the hash for the given asru name.
	 * If we didn't find the asru in the hash and we need to create it,
	 * create and insert the asru with ahp->ah_lock held and hash it in.
	 * We'll then drop the rwlock and proceed to initializing the asru.
	 */
	if (create)
		(void) pthread_rwlock_wrlock(&ahp->ah_lock);
	else
		(void) pthread_rwlock_rdlock(&ahp->ah_lock);

	h = fmd_strhash(name) % ahp->ah_hashlen;

	for (ap = ahp->ah_hash[h]; ap != NULL; ap = ap->asru_next) {
		if (strcmp(ap->asru_name, name) == 0)
			break;
	}

	if (ap == NULL && create == FMD_B_TRUE) {
		ap = fmd_asru_create(ahp, NULL, name, fmri);
		fmd_asru_hash_insert(ahp, ap);
		(void) pthread_mutex_lock(&ap->asru_lock);
	} else
		create = FMD_B_FALSE;

	(void) pthread_rwlock_unlock(&ahp->ah_lock);
	fmd_free(name, namelen + 1);

	/*
	 * If 'create' is still true, then we need to initialize the asru log;
	 * If 'create' is false and an asru was found, we must cond_wait for
	 * the FMD_ASRU_VALID bit to be set before returning.  In both cases,
	 * we increment asru_refs for the caller.
	 */
	if (create == FMD_B_TRUE) {
		uuid_t uuid;

		ASSERT(MUTEX_HELD(&ap->asru_lock));
		ASSERT(ap->asru_uuid == NULL && ap->asru_log == NULL);

		/*
		 * Generate a UUID for the ASRU.  libuuid cleverly gives us no
		 * interface for specifying or learning the buffer size.  Sigh.
		 * The spec says 36 bytes but we use a tunable just to be safe.
		 */
		(void) fmd_conf_getprop(fmd.d_conf,
		    "uuidlen", &ap->asru_uuidlen);

		ap->asru_uuid = fmd_zalloc(ap->asru_uuidlen + 1, FMD_SLEEP);
		uuid_generate(uuid);
		uuid_unparse(uuid, ap->asru_uuid);

		ASSERT(!(ap->asru_flags & FMD_ASRU_VALID));
		ap->asru_flags |= FMD_ASRU_VALID;

		ap->asru_refs++;
		ASSERT(ap->asru_refs != 0);
		(void) pthread_cond_broadcast(&ap->asru_cv);
		(void) pthread_mutex_unlock(&ap->asru_lock);

		TRACE((FMD_DBG_ASRU, "asru %s created as %p",
		    ap->asru_uuid, (void *)ap));

	} else if (ap != NULL) {
		(void) pthread_mutex_lock(&ap->asru_lock);

		while (!(ap->asru_flags & FMD_ASRU_VALID))
			(void) pthread_cond_wait(&ap->asru_cv, &ap->asru_lock);

		ap->asru_refs++;
		ASSERT(ap->asru_refs != 0);
		(void) pthread_mutex_unlock(&ap->asru_lock);
	}

	return (ap);
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

int
fmd_asru_hash_delete_name(fmd_asru_hash_t *ahp, const char *name)
{
	fmd_asru_t *ap, **pp;
	char path[PATH_MAX];
	uint_t h;

	(void) pthread_rwlock_wrlock(&ahp->ah_lock);

	h = fmd_strhash(name) % ahp->ah_hashlen;
	pp = &ahp->ah_hash[h];

	for (ap = *pp; ap != NULL; ap = ap->asru_next) {
		if (strcmp(ap->asru_name, name) == 0)
			break;
		else
			pp = &ap->asru_next;
	}

	if (ap != NULL) {
		*pp = ap->asru_next;
		ap->asru_next = NULL;
		ASSERT(ahp->ah_count != 0);
		ahp->ah_count--;
	}

	(void) pthread_rwlock_unlock(&ahp->ah_lock);

	if (ap == NULL)
		return (fmd_set_errno(EFMD_ASRU_NOENT));

	/*
	 * If we found a matching ASRU, unlink its log file and then release
	 * the hash entry.  Note that it may still be referenced if another
	 * thread is manipulating it; this is ok because once we unlink, the
	 * log file will not be restored, and the log data will be freed when
	 * all of the referencing threads release their respective references.
	 */
	(void) snprintf(path, sizeof (path),
	    "%s/%s", ahp->ah_dirpath, ap->asru_uuid);

	if (unlink(path) != 0)
		fmd_error(EFMD_ASRU_UNLINK, "failed to unlink asru %s", path);

	fmd_asru_hash_release(ahp, ap);
	return (0);
}

static void
fmd_asru_logevent(fmd_asru_t *ap)
{
	boolean_t f = (ap->asru_flags & FMD_ASRU_FAULTY) != 0;
	boolean_t u = (ap->asru_flags & FMD_ASRU_UNUSABLE) != 0;
	boolean_t m = (ap->asru_flags & FMD_ASRU_INVISIBLE) == 0;

	fmd_case_impl_t *cip;
	fmd_event_t *e;
	fmd_log_t *lp;
	nvlist_t *nvl;
	char *class;

	ASSERT(MUTEX_HELD(&ap->asru_lock));
	cip = (fmd_case_impl_t *)ap->asru_case;
	ASSERT(cip != NULL);

	if ((lp = ap->asru_log) == NULL)
		lp = fmd_log_open(ap->asru_root, ap->asru_uuid, FMD_LOG_ASRU);

	if (lp == NULL)
		return; /* can't log events if we can't open the log */

	nvl = fmd_protocol_rsrc_asru(_fmd_asru_events[f | (u << 1)],
	    ap->asru_fmri, cip->ci_uuid, cip->ci_code, f, u, m, ap->asru_event,
	    &cip->ci_tv);

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
	ap->asru_log = NULL;
}

int
fmd_asru_setflags(fmd_asru_t *ap, uint_t sflag, fmd_case_t *cp, nvlist_t *nvl)
{
	fmd_case_t *old_case = NULL;
	nvlist_t *old_nvl = NULL;
	uint_t nstate, ostate;
	boolean_t msg;

	ASSERT(!(sflag & ~FMD_ASRU_STATE));
	ASSERT(sflag != FMD_ASRU_STATE);

	(void) pthread_mutex_lock(&ap->asru_lock);

	ostate = ap->asru_flags & FMD_ASRU_STATE;
	ap->asru_flags |= sflag;
	nstate = ap->asru_flags & FMD_ASRU_STATE;

	if (nstate == ostate) {
		(void) pthread_mutex_unlock(&ap->asru_lock);
		return (0);
	}

	if (cp != NULL && cp != ap->asru_case) {
		old_case = ap->asru_case;
		fmd_case_hold_locked(cp);
		ap->asru_case = cp;
		old_nvl = ap->asru_event;
		(void) nvlist_xdup(nvl, &ap->asru_event, &fmd.d_nva);
	}

	if (nvl != NULL && nvlist_lookup_boolean_value(nvl,
	    FM_SUSPECT_MESSAGE, &msg) == 0 && msg == B_FALSE)
		ap->asru_flags |= FMD_ASRU_INVISIBLE;

	TRACE((FMD_DBG_ASRU, "asru %s %s->%s", ap->asru_uuid,
	    _fmd_asru_snames[ostate], _fmd_asru_snames[nstate]));

	fmd_asru_logevent(ap);

	(void) pthread_cond_broadcast(&ap->asru_cv);
	(void) pthread_mutex_unlock(&ap->asru_lock);

	if (old_case != NULL)
		fmd_case_rele(old_case);

	if (old_nvl != NULL)
		nvlist_free(old_nvl);

	return (1);
}

int
fmd_asru_clrflags(fmd_asru_t *ap, uint_t sflag, fmd_case_t *cp, nvlist_t *nvl)
{
	fmd_case_t *old_case = NULL;
	nvlist_t *old_nvl = NULL;
	uint_t nstate, ostate;

	ASSERT(!(sflag & ~FMD_ASRU_STATE));
	ASSERT(sflag != FMD_ASRU_STATE);

	(void) pthread_mutex_lock(&ap->asru_lock);

	ostate = ap->asru_flags & FMD_ASRU_STATE;
	ap->asru_flags &= ~sflag;
	nstate = ap->asru_flags & FMD_ASRU_STATE;

	if (nstate == ostate) {
		(void) pthread_mutex_unlock(&ap->asru_lock);
		return (0);
	}

	if (cp != NULL && cp != ap->asru_case) {
		old_case = ap->asru_case;
		fmd_case_hold_locked(cp);
		ap->asru_case = cp;
		old_nvl = ap->asru_event;
		(void) nvlist_xdup(nvl, &ap->asru_event, &fmd.d_nva);
	}

	TRACE((FMD_DBG_ASRU, "asru %s %s->%s", ap->asru_uuid,
	    _fmd_asru_snames[ostate], _fmd_asru_snames[nstate]));

	fmd_asru_logevent(ap);

	if (cp == NULL && (sflag & FMD_ASRU_FAULTY)) {
		old_case = ap->asru_case;
		ap->asru_case = NULL;
		old_nvl = ap->asru_event;
		ap->asru_event = NULL;
	}

	(void) pthread_cond_broadcast(&ap->asru_cv);
	(void) pthread_mutex_unlock(&ap->asru_lock);

	if (old_case != NULL) {
		if (cp == NULL && (sflag & FMD_ASRU_FAULTY))
			fmd_case_update(old_case);
		fmd_case_rele(old_case);
	}

	if (old_nvl != NULL)
		nvlist_free(old_nvl);

	return (1);
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
	    (fmd_asru_fake_not_present || fmd_fmri_present(ap->asru_fmri) <= 0))
		return (0); /* do not report non-fmd non-present resources */

	us = fmd_fmri_unusable(ap->asru_fmri);
	st = ap->asru_flags & FMD_ASRU_STATE;

	if (us > 0)
		st |= FMD_ASRU_UNUSABLE;
	else if (us == 0)
		st &= ~FMD_ASRU_UNUSABLE;

	return (st);
}
