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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2019, Joyent, Inc. All rights reserved.
 */

#include <signal.h>
#include <dirent.h>
#include <limits.h>
#include <alloca.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <synch.h>
#include <errno.h>
#include <strings.h>
#include <assert.h>
#include <sys/nvpair.h>

#include <topo_string.h>
#include <topo_alloc.h>
#include <topo_module.h>
#include <topo_error.h>
#include <topo_subr.h>

extern nv_alloc_ops_t topo_nv_alloc_ops;

void
topo_mod_release(topo_mod_t *mod, tnode_t *node)
{
	topo_mod_enter(mod);

	if (mod->tm_info->tmi_ops->tmo_release != NULL)
		mod->tm_info->tmi_ops->tmo_release(mod, node);

	topo_mod_exit(mod);
}

void
topo_mod_hold(topo_mod_t *mod)
{
	(void) pthread_mutex_lock(&mod->tm_lock);
	mod->tm_refs++;
	assert(mod->tm_refs != 0);
	(void) pthread_mutex_unlock(&mod->tm_lock);
}

void
topo_mod_rele(topo_mod_t *mod)
{
	assert(mod->tm_refs != 0);

	(void) pthread_mutex_lock(&mod->tm_lock);

	/*
	 * Lazy unload module
	 */
	if (--mod->tm_refs == 0)
		topo_modhash_unload(mod);
	else
		(void) pthread_mutex_unlock(&mod->tm_lock);
}

void
topo_mod_enter(topo_mod_t *mod)
{
	(void) pthread_mutex_lock(&mod->tm_lock);

	while (mod->tm_busy != 0)
		(void) pthread_cond_wait(&mod->tm_cv, &mod->tm_lock);

	++mod->tm_busy;

	(void) pthread_mutex_unlock(&mod->tm_lock);
}

void
topo_mod_exit(topo_mod_t *mod)
{
	(void) pthread_mutex_lock(&mod->tm_lock);
	--mod->tm_busy;

	assert(mod->tm_busy == 0);

	(void) pthread_cond_broadcast(&mod->tm_cv);
	(void) pthread_mutex_unlock(&mod->tm_lock);
}

static void
topo_modhash_lock(topo_modhash_t *mhp)
{
	(void) pthread_mutex_lock(&mhp->mh_lock);
}

static void
topo_modhash_unlock(topo_modhash_t *mhp)
{
	(void) pthread_mutex_unlock(&mhp->mh_lock);
}

static void
topo_mod_stop(topo_mod_t *mod)
{
	if (mod->tm_flags & TOPO_MOD_INIT) {
		(void) mod->tm_mops->mop_fini(mod);
		if (mod->tm_flags & TOPO_MOD_REG)
			topo_mod_unregister(mod);
	}

	mod->tm_flags = TOPO_MOD_FINI;

	topo_dprintf(mod->tm_hdl, TOPO_DBG_MODSVC,
	    "module %s stopped\n", mod->tm_name);
}

static int
topo_mod_start(topo_mod_t *mod, topo_version_t version)
{
	topo_dprintf(mod->tm_hdl, TOPO_DBG_MODSVC,
	    "starting module %s\n", mod->tm_name);

	if (mod->tm_mops->mop_init(mod, version) != 0) {
		if (mod->tm_errno == 0)
			mod->tm_errno = ETOPO_MOD_INIT;
		topo_dprintf(mod->tm_hdl, TOPO_DBG_ERR,
		    "module %s failed to initialize: %s\n", mod->tm_name,
		    topo_strerror(mod->tm_errno));
		return (-1);
	}

	mod->tm_flags |= TOPO_MOD_INIT;

	if (!(mod->tm_flags & TOPO_MOD_REG)) {
		topo_dprintf(mod->tm_hdl, TOPO_DBG_ERR,
		    "module %s failed to register\n", mod->tm_name);
		mod->tm_errno = ETOPO_MOD_NOREG;
		topo_mod_stop(mod);
		return (-1);
	}

	return (0);
}

topo_mod_t *
topo_mod_lookup(topo_hdl_t *thp, const char *name, int bump)
{
	topo_mod_t *mod;
	topo_modhash_t *mhp = thp->th_modhash;

	topo_modhash_lock(mhp);
	mod = topo_modhash_lookup(mhp, name);
	if (mod != NULL && bump != 0)
		topo_mod_hold(mod);
	topo_modhash_unlock(mhp);

	return (mod);
}

static void
topo_mod_destroy(topo_mod_t *mod)
{
	topo_hdl_t *thp;

	if (mod == NULL)
		return;

	thp = mod->tm_hdl;

	assert(mod->tm_refs == 0);
	assert(!MUTEX_HELD(&mod->tm_lock));

	if (mod->tm_name != NULL)
		topo_hdl_strfree(thp, mod->tm_name);
	if (mod->tm_path != NULL)
		topo_hdl_strfree(thp, mod->tm_path);
	if (mod->tm_rootdir != NULL)
		topo_hdl_strfree(thp, mod->tm_rootdir);

	topo_hdl_free(thp, mod, sizeof (topo_mod_t));
}

static topo_mod_t *
set_create_error(topo_hdl_t *thp, topo_mod_t *mod, const char *path, int err)
{
	if (path != NULL)
		topo_dprintf(thp, TOPO_DBG_ERR, "unable to load module %s: "
		    "%s\n", path, topo_strerror(err));
	else
		topo_dprintf(thp, TOPO_DBG_ERR, "unable to load module: "
		    "%s\n", topo_strerror(err));

	if (mod != NULL)
		topo_mod_destroy(mod);

	(void) topo_hdl_seterrno(thp, err);

	return (NULL);
}

static topo_mod_t *
topo_mod_create(topo_hdl_t *thp, const char *name, const char *path,
    const topo_imodops_t *ops, topo_version_t version)
{
	topo_mod_t *mod;

	if (topo_modhash_lookup(thp->th_modhash, name) != NULL)
		return (set_create_error(thp, NULL, path, ETOPO_MOD_LOADED));

	if ((mod = topo_hdl_zalloc(thp, sizeof (topo_mod_t))) == NULL)
		return (set_create_error(thp, mod, path, ETOPO_NOMEM));

	mod->tm_hdl = thp;

	(void) pthread_mutex_init(&mod->tm_lock, NULL);

	mod->tm_name = topo_hdl_strdup(thp, name);
	if (path != NULL)
		mod->tm_path = topo_hdl_strdup(thp, path);
	mod->tm_rootdir = topo_hdl_strdup(thp, thp->th_rootdir);
	if (mod->tm_name == NULL || mod->tm_rootdir == NULL)
		return (set_create_error(thp, mod, path, ETOPO_NOMEM));

	mod->tm_mops = (topo_imodops_t *)ops;
	mod->tm_alloc = thp->th_alloc;

	/*
	 * Module will be held upon a successful return from topo_mod_start()
	 */
	if ((topo_mod_start(mod, version)) < 0)
		return (set_create_error(thp, mod, path, mod->tm_errno));

	topo_dprintf(thp, TOPO_DBG_MODSVC, "loaded module %s\n", mod->tm_name);

	return (mod);
}

topo_modhash_t *
topo_modhash_create(topo_hdl_t *thp)
{
	topo_modhash_t *mhp;

	if ((mhp = topo_hdl_zalloc(thp, sizeof (topo_modhash_t))) == NULL)
		return (NULL);

	mhp->mh_hashlen = TOPO_HASH_BUCKETS;
	if ((mhp->mh_hash = topo_hdl_zalloc(thp,
	    sizeof (void *) * mhp->mh_hashlen)) == NULL) {
		topo_hdl_free(thp, mhp, sizeof (topo_modhash_t));
		return (NULL);
	}
	mhp->mh_nelems = 0;
	(void) pthread_mutex_init(&mhp->mh_lock, NULL);

	thp->th_modhash = mhp;

	return (mhp);
}

void
topo_modhash_destroy(topo_hdl_t *thp)
{
	topo_modhash_t *mhp = thp->th_modhash;

	if (mhp == NULL)
		return;

	assert(mhp->mh_nelems == 0);

	topo_hdl_free(thp, mhp->mh_hash, sizeof (void *) * mhp->mh_hashlen);
	topo_hdl_free(thp, mhp, sizeof (topo_modhash_t));
	thp->th_modhash = NULL;
}

topo_mod_t *
topo_modhash_lookup(topo_modhash_t *mhp, const char *name)
{
	topo_mod_t *mod = NULL;
	uint_t h;

	h = topo_strhash(name) % mhp->mh_hashlen;

	for (mod = mhp->mh_hash[h]; mod != NULL; mod = mod->tm_next) {
		if (strcmp(name, mod->tm_name) == 0)
			break;
	}

	return (mod);
}

topo_mod_t *
topo_modhash_load(topo_hdl_t *thp, const char *name, const char *path,
    const topo_imodops_t *ops, topo_version_t version)
{
	topo_modhash_t *mhp = thp->th_modhash;
	topo_mod_t *mod;
	uint_t h;

	topo_modhash_lock(mhp);

	if ((mod = topo_mod_create(thp, name, path, ops, version)) == NULL) {
		topo_modhash_unlock(mhp);
		return (NULL); /* th_errno set */
	}

	topo_mod_hold(mod);

	h = topo_strhash(name) % mhp->mh_hashlen;
	mod->tm_next = mhp->mh_hash[h];
	mhp->mh_hash[h] = mod;
	mhp->mh_nelems++;
	topo_modhash_unlock(mhp);

	return (mod);
}

void
topo_modhash_unload(topo_mod_t *mod)
{
	uint_t h;
	topo_mod_t **pp, *mp;
	topo_hdl_t *thp = mod->tm_hdl;
	topo_modhash_t *mhp;

	assert(MUTEX_HELD(&mod->tm_lock));
	assert(mod->tm_busy == 0);

	mhp = thp->th_modhash;
	topo_modhash_lock(mhp);

	assert(mhp != NULL);

	h = topo_strhash(mod->tm_name) % mhp->mh_hashlen;
	pp = &mhp->mh_hash[h];

	for (mp = *pp; mp != NULL; mp = mp->tm_next) {
		if (mp == mod)
			break;
		else
			pp = &mp->tm_next;
	}

	if (mp != NULL) {
		*pp = mod->tm_next;

		assert(mhp->mh_nelems != 0);

		mhp->mh_nelems--;

	}
	topo_modhash_unlock(mhp);

	(void) pthread_mutex_unlock(&mod->tm_lock);

	topo_mod_stop(mod);
	topo_mod_destroy(mod);

}

void
topo_modhash_unload_all(topo_hdl_t *thp)
{
	int i;
	topo_modhash_t *mhp = thp->th_modhash;
	topo_mod_t *mp, **pp;

	if (mhp == NULL)
		return;

	topo_modhash_lock(mhp);
	for (i = 0; i < TOPO_HASH_BUCKETS; ++i) {
		pp = &mhp->mh_hash[i];
		mp = *pp;
		while (mp != NULL) {
			topo_mod_stop(mp);

			/*
			 * At this point we are forcing all modules to
			 * stop, ignore any remaining module reference counts.
			 */
			mp->tm_refs = 0;

			*pp = mp->tm_next;
			topo_mod_destroy(mp);
			mp = *pp;

			--mhp->mh_nelems;
		}
	}
	topo_modhash_unlock(mhp);
}
