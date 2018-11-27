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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <limits.h>
#include <stddef.h>
#include <unistd.h>
#include <dlfcn.h>

#include <fmd_alloc.h>
#include <fmd_error.h>
#include <fmd_subr.h>
#include <fmd_string.h>
#include <fmd_scheme.h>
#include <fmd_fmri.h>
#include <fmd_module.h>

#include <fmd.h>

/*
 * The fmd resource scheme, used for fmd modules, must be implemented here for
 * the benefit of fmd-self-diagnosis and also in schemes/fmd for fmdump(1M).
 */
ssize_t
fmd_scheme_fmd_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	char *name;

	if (nvlist_lookup_string(nvl, FM_FMRI_FMD_NAME, &name) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	return (snprintf(buf, buflen,
	    "%s:///module/%s", FM_FMRI_SCHEME_FMD, name));
}

static int
fmd_scheme_fmd_present(nvlist_t *nvl)
{
	char *name, *version;
	fmd_module_t *mp;
	int rv = 1;

	if (nvlist_lookup_string(nvl, FM_FMRI_FMD_NAME, &name) != 0 ||
	    nvlist_lookup_string(nvl, FM_FMRI_FMD_VERSION, &version) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if (!fmd.d_loaded)
		return (1);

	if ((mp = fmd_modhash_lookup(fmd.d_mod_hash, name)) != NULL) {
		rv = mp->mod_vers != NULL &&
		    strcmp(mp->mod_vers, version) == 0;
		fmd_module_rele(mp);
	}

	return (rv);
}

static int
fmd_scheme_fmd_replaced(nvlist_t *nvl)
{
	char *name, *version;
	fmd_module_t *mp;
	int rv = 1;

	if (nvlist_lookup_string(nvl, FM_FMRI_FMD_NAME, &name) != 0 ||
	    nvlist_lookup_string(nvl, FM_FMRI_FMD_VERSION, &version) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if (!fmd.d_loaded)
		return (FMD_OBJ_STATE_UNKNOWN);

	if ((mp = fmd_modhash_lookup(fmd.d_mod_hash, name)) != NULL) {
		rv = mp->mod_vers != NULL &&
		    strcmp(mp->mod_vers, version) == 0;
		fmd_module_rele(mp);
	}

	return (rv ? FMD_OBJ_STATE_STILL_PRESENT : FMD_OBJ_STATE_REPLACED);
}

static int
fmd_scheme_fmd_service_state(nvlist_t *nvl)
{
	char *name;
	fmd_module_t *mp;
	int rv = 1;

	if (nvlist_lookup_string(nvl, FM_FMRI_FMD_NAME, &name) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if (!fmd.d_loaded)
		return (FMD_SERVICE_STATE_UNKNOWN);

	if ((mp = fmd_modhash_lookup(fmd.d_mod_hash, name)) != NULL) {
		rv = mp->mod_error != 0;
		fmd_module_rele(mp);
	}

	return (rv ? FMD_SERVICE_STATE_UNUSABLE : FMD_SERVICE_STATE_OK);
}

static int
fmd_scheme_fmd_unusable(nvlist_t *nvl)
{
	char *name;
	fmd_module_t *mp;
	int rv = 1;

	if (nvlist_lookup_string(nvl, FM_FMRI_FMD_NAME, &name) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if (!fmd.d_loaded)
		return (0);

	if ((mp = fmd_modhash_lookup(fmd.d_mod_hash, name)) != NULL) {
		rv = mp->mod_error != 0;
		fmd_module_rele(mp);
	}

	return (rv);
}

static nvlist_t *
fmd_scheme_notranslate(nvlist_t *fmri, nvlist_t *auth __unused)
{
	(void) nvlist_xdup(fmri, &fmri, &fmd.d_nva);
	return (fmri);
}

static ssize_t
fmd_scheme_notsup_nvl2str(nvlist_t *fmri __unused, char *arg1 __unused,
    size_t arg2 __unused)
{
	return (fmd_set_errno(EFMD_FMRI_NOTSUP));
}

static int
fmd_scheme_notsup(nvlist_t *fmri __unused)
{
	return (fmd_set_errno(EFMD_FMRI_NOTSUP));
}

static int
fmd_scheme_notsup2(nvlist_t *fmri1 __unused, nvlist_t *fmri2 __unused)
{
	return (fmd_set_errno(EFMD_FMRI_NOTSUP));
}

static void
fmd_scheme_vnop(void)
{
}

static int
fmd_scheme_nop(void)
{
	return (0);
}

/*
 * Default values for the scheme ops.  If a scheme function is not defined in
 * the module, then this operation is implemented using the default function.
 */
static const fmd_scheme_ops_t _fmd_scheme_default_ops = {
	.sop_init = fmd_scheme_nop,
	.sop_fini = fmd_scheme_vnop,
	.sop_nvl2str = fmd_scheme_notsup_nvl2str,
	.sop_expand = fmd_scheme_notsup,
	.sop_present = fmd_scheme_notsup,
	.sop_replaced = fmd_scheme_notsup,
	.sop_service_state = fmd_scheme_notsup,
	.sop_unusable = fmd_scheme_notsup,
	.sop_contains = fmd_scheme_notsup2,
	.sop_translate = fmd_scheme_notranslate
};

static const fmd_scheme_ops_t _fmd_scheme_builtin_ops = {
	.sop_init = fmd_scheme_nop,
	.sop_fini = fmd_scheme_vnop,
	.sop_nvl2str = fmd_scheme_fmd_nvl2str,
	.sop_expand = fmd_scheme_notsup,
	.sop_present = fmd_scheme_fmd_present,
	.sop_replaced = fmd_scheme_fmd_replaced,
	.sop_service_state = fmd_scheme_fmd_service_state,
	.sop_unusable = fmd_scheme_fmd_unusable,
	.sop_contains = fmd_scheme_notsup2,
	.sop_translate = fmd_scheme_notranslate
};

/*
 * Scheme ops descriptions.  These names and offsets are used by the function
 * fmd_scheme_rtld_init(), defined below, to load up a fmd_scheme_ops_t.
 */
static const fmd_scheme_opd_t _fmd_scheme_ops[] = {
	{ "fmd_fmri_init", offsetof(fmd_scheme_ops_t, sop_init) },
	{ "fmd_fmri_fini", offsetof(fmd_scheme_ops_t, sop_fini) },
	{ "fmd_fmri_nvl2str", offsetof(fmd_scheme_ops_t, sop_nvl2str) },
	{ "fmd_fmri_expand", offsetof(fmd_scheme_ops_t, sop_expand) },
	{ "fmd_fmri_present", offsetof(fmd_scheme_ops_t, sop_present) },
	{ "fmd_fmri_replaced", offsetof(fmd_scheme_ops_t, sop_replaced) },
	{ "fmd_fmri_service_state", offsetof(fmd_scheme_ops_t,
	    sop_service_state) },
	{ "fmd_fmri_unusable", offsetof(fmd_scheme_ops_t, sop_unusable) },
	{ "fmd_fmri_contains", offsetof(fmd_scheme_ops_t, sop_contains) },
	{ "fmd_fmri_translate", offsetof(fmd_scheme_ops_t, sop_translate) },
	{ NULL, 0 }
};

static fmd_scheme_t *
fmd_scheme_create(const char *name)
{
	fmd_scheme_t *sp = fmd_alloc(sizeof (fmd_scheme_t), FMD_SLEEP);

	(void) pthread_mutex_init(&sp->sch_lock, NULL);
	(void) pthread_cond_init(&sp->sch_cv, NULL);
	(void) pthread_mutex_init(&sp->sch_opslock, NULL);

	sp->sch_next = NULL;
	sp->sch_name = fmd_strdup(name, FMD_SLEEP);
	sp->sch_dlp = NULL;
	sp->sch_refs = 1;
	sp->sch_loaded = 0;
	sp->sch_ops = _fmd_scheme_default_ops;

	return (sp);
}

static void
fmd_scheme_destroy(fmd_scheme_t *sp)
{
	ASSERT(MUTEX_HELD(&sp->sch_lock));
	ASSERT(sp->sch_refs == 0);

	if (sp->sch_dlp != NULL) {
		TRACE((FMD_DBG_FMRI, "dlclose scheme %s", sp->sch_name));

		if (sp->sch_ops.sop_fini != NULL)
			sp->sch_ops.sop_fini();

		(void) dlclose(sp->sch_dlp);
	}

	fmd_strfree(sp->sch_name);
	fmd_free(sp, sizeof (fmd_scheme_t));
}

fmd_scheme_hash_t *
fmd_scheme_hash_create(const char *rootdir, const char *dirpath)
{
	fmd_scheme_hash_t *shp;
	char path[PATH_MAX];
	fmd_scheme_t *sp;

	shp = fmd_alloc(sizeof (fmd_scheme_hash_t), FMD_SLEEP);
	(void) snprintf(path, sizeof (path), "%s/%s", rootdir, dirpath);
	shp->sch_dirpath = fmd_strdup(path, FMD_SLEEP);
	(void) pthread_rwlock_init(&shp->sch_rwlock, NULL);
	shp->sch_hashlen = fmd.d_str_buckets;
	shp->sch_hash = fmd_zalloc(sizeof (fmd_scheme_t *) *
	    shp->sch_hashlen, FMD_SLEEP);

	sp = fmd_scheme_create(FM_FMRI_SCHEME_FMD);
	sp->sch_ops = _fmd_scheme_builtin_ops;
	sp->sch_loaded = FMD_B_TRUE;
	shp->sch_hash[fmd_strhash(sp->sch_name) % shp->sch_hashlen] = sp;

	return (shp);
}

void
fmd_scheme_hash_destroy(fmd_scheme_hash_t *shp)
{
	fmd_scheme_t *sp, *np;
	uint_t i;

	for (i = 0; i < shp->sch_hashlen; i++) {
		for (sp = shp->sch_hash[i]; sp != NULL; sp = np) {
			np = sp->sch_next;
			sp->sch_next = NULL;
			fmd_scheme_hash_release(shp, sp);
		}
	}

	fmd_free(shp->sch_hash, sizeof (fmd_scheme_t *) * shp->sch_hashlen);
	fmd_strfree(shp->sch_dirpath);
	fmd_free(shp, sizeof (fmd_scheme_hash_t));
}

void
fmd_scheme_hash_trygc(fmd_scheme_hash_t *shp)
{
	fmd_scheme_t *sp, *np;
	uint_t i;

	if (shp == NULL || pthread_rwlock_trywrlock(&shp->sch_rwlock) != 0)
		return; /* failed to acquire lock: just skip garbage collect */

	for (i = 0; i < shp->sch_hashlen; i++) {
		for (sp = shp->sch_hash[i]; sp != NULL; sp = np) {
			np = sp->sch_next;
			sp->sch_next = NULL;
			fmd_scheme_hash_release(shp, sp);
		}
	}

	bzero(shp->sch_hash, sizeof (fmd_scheme_t *) * shp->sch_hashlen);
	(void) pthread_rwlock_unlock(&shp->sch_rwlock);
}

static int
fmd_scheme_rtld_init(fmd_scheme_t *sp)
{
	const fmd_scheme_opd_t *opd;
	void *p;

	for (opd = _fmd_scheme_ops; opd->opd_name != NULL; opd++) {
		if ((p = dlsym(sp->sch_dlp, opd->opd_name)) != NULL)
			*(void **)((uintptr_t)&sp->sch_ops + opd->opd_off) = p;
	}

	return (0);
}

fmd_scheme_t *
fmd_scheme_hash_xlookup(fmd_scheme_hash_t *shp, const char *name, uint_t h)
{
	fmd_scheme_t *sp;

	ASSERT(RW_LOCK_HELD(&shp->sch_rwlock));

	for (sp = shp->sch_hash[h]; sp != NULL; sp = sp->sch_next) {
		if (strcmp(sp->sch_name, name) == 0)
			break;
	}

	return (sp);
}

/*
 * Lookup a scheme module by name and return with a reference placed on it.  We
 * use the scheme hash to cache "negative" entries (e.g. missing modules) as
 * well so this function always returns successfully with a non-NULL scheme.
 * The caller is responsible for applying fmd_scheme_hash_release() afterward.
 */
fmd_scheme_t *
fmd_scheme_hash_lookup(fmd_scheme_hash_t *shp, const char *name)
{
	fmd_scheme_t *sp, *nsp = NULL;
	uint_t h;

	/*
	 * Grab the hash lock as reader and look for the appropriate scheme.
	 * If the scheme isn't yet loaded, allocate a new scheme and grab the
	 * hash lock as writer to insert it (after checking again for it).
	 */
	(void) pthread_rwlock_rdlock(&shp->sch_rwlock);
	h = fmd_strhash(name) % shp->sch_hashlen;

	if ((sp = fmd_scheme_hash_xlookup(shp, name, h)) == NULL) {
		(void) pthread_rwlock_unlock(&shp->sch_rwlock);
		nsp = fmd_scheme_create(name);
		(void) pthread_rwlock_wrlock(&shp->sch_rwlock);

		if ((sp = fmd_scheme_hash_xlookup(shp, name, h)) == NULL) {
			nsp->sch_next = shp->sch_hash[h];
			shp->sch_hash[h] = sp = nsp;
		} else {
			fmd_scheme_hash_release(shp, nsp);
			nsp = NULL;
		}
	}

	/*
	 * Grab the scheme lock so it can't disappear and then drop the hash
	 * lock so that other lookups in the scheme hash can proceed.
	 */
	(void) pthread_mutex_lock(&sp->sch_lock);
	(void) pthread_rwlock_unlock(&shp->sch_rwlock);

	/*
	 * If we created the scheme, compute its path and try to load it.  If
	 * we found an existing scheme, wait until its loaded bit is set.  Once
	 * we're done with either operation, increment sch_refs and return.
	 */
	if (nsp != NULL) {
		char path[PATH_MAX];

		(void) snprintf(path, sizeof (path),
		    "%s/%s.so", shp->sch_dirpath, sp->sch_name);

		TRACE((FMD_DBG_FMRI, "dlopen scheme %s", sp->sch_name));
		sp->sch_dlp = dlopen(path, RTLD_LOCAL | RTLD_NOW);

		if (sp->sch_dlp == NULL) {
			fmd_error(EFMD_FMRI_SCHEME,
			    "failed to load fmri scheme %s: %s\n", path,
			    dlerror());
		} else if (fmd_scheme_rtld_init(sp) != 0 ||
		    sp->sch_ops.sop_init() != 0) {
			fmd_error(EFMD_FMRI_SCHEME,
			    "failed to initialize fmri scheme %s", path);
			(void) dlclose(sp->sch_dlp);
			sp->sch_dlp = NULL;
			sp->sch_ops = _fmd_scheme_default_ops;
		}

		sp->sch_loaded = FMD_B_TRUE; /* set regardless of success */
		sp->sch_refs++;
		ASSERT(sp->sch_refs != 0);

		(void) pthread_cond_broadcast(&sp->sch_cv);
		(void) pthread_mutex_unlock(&sp->sch_lock);

	} else {
		while (!sp->sch_loaded)
			(void) pthread_cond_wait(&sp->sch_cv, &sp->sch_lock);

		sp->sch_refs++;
		ASSERT(sp->sch_refs != 0);
		(void) pthread_mutex_unlock(&sp->sch_lock);
	}

	return (sp);
}

/*
 * Release the hold on a scheme obtained using fmd_scheme_hash_lookup().
 * We take 'shp' for symmetry and in case we need to use it in future work.
 */
/*ARGSUSED*/
void
fmd_scheme_hash_release(fmd_scheme_hash_t *shp, fmd_scheme_t *sp)
{
	(void) pthread_mutex_lock(&sp->sch_lock);

	ASSERT(sp->sch_refs != 0);
	if (--sp->sch_refs == 0)
		fmd_scheme_destroy(sp);
	else
		(void) pthread_mutex_unlock(&sp->sch_lock);
}
