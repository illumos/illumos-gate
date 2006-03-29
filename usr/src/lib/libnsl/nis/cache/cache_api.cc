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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* The C interface to directory cache class functions */


#include "mt.h"
#include "../../rpc/rpc_mt.h"
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <syslog.h>

#include <rpc/rpc.h>
#include <rpc/types.h>
#include <rpcsvc/nis.h>
#include "../gen/nis_local.h"
#include "local_cache.h"
#include "client_cache.h"
#include "mgr_cache.h"

static mutex_t cur_cache_lock = DEFAULTMUTEX;
static NisCache *cur_cache = NULL;	/* protected by cur_cache_lock */
static NisMgrCache *mgr_cache = NULL;	/* protected by cur_cache_lock */
static int checked_env = 0;		/* protected by cur_cache_lock */
extern char *__nis_server;   /* if set, use only this server for binding */

extern "C" {

extern void __nis_get_environment(); /* in libc/port/gen/nss_common.c */
#define	MGR_CHECK_INTERVAL	300

/*
 * Initializes the client cache. Allocates the global data strucuture
 * NisSharedCache which is used by the other cache routines.
 * We return a copy of the cache variable so that it will remain
 * constant for each thread.  We can change the cache variable
 * from the shared cache to the local cache, but we must not
 * delete the cache because another thread might still be using it
 * (except in this routine if we create a cache with an error).
 */

nis_error
__nis_CacheInit(NisCache **cache)
{
	nis_error status = NIS_SUCCESS;
	static struct timeval then = {0, 0};
	struct timeval now;

	mutex_lock(&cur_cache_lock);

	if (!checked_env) {
		__nis_get_environment(); /* in libc/port/gen/nss_common.c */
		checked_env = 1;
	}

	if (mgr_cache) {
		/*
		 * The manager cache is defined and will always be
		 * available so there's no need to check its validity.
		 * As a precaution we make sure cur_cache is set to
		 * mgr_cache and log a message if we have to correct it.
		 */
		if (cur_cache != mgr_cache) {
			syslog(LOG_WARNING, "__nis_CacheInit: "
				"cur_cache=%lx is not mgr_cache=%lx, corrected",
				cur_cache, mgr_cache);
			cur_cache = mgr_cache;
		}
	} else {
		/*
		 * We dont have a manager cache so we check the validity
		 * of the current cache and create one as necessary.
		 */
		if (cur_cache && !cur_cache->okay()) {
			    cur_cache = NULL;
		}
		/*
		 * Verify cachemgr still running
		 * checkUp() is no-op for local cache
		 */
		if (cur_cache && gettimeofday(&now, 0) != -1 &&
			now.tv_sec > then.tv_sec+MGR_CHECK_INTERVAL) {
			if (cur_cache->checkUp()) {
				then = now;
			} else {
				cur_cache = NULL;
			}
		}

		if (cur_cache == NULL) {
			/*
			 *  If an explicit server for binding has been set, then
			 *  we can't use the shared cache because its server
			 *  rankings will conflict with ours.
			 */
			if (!__nis_server) {
				cur_cache = new NisClientCache(status);
				if (cur_cache == NULL) {
					status = NIS_NOMEMORY;
				} else if (status != NIS_SUCCESS) {
					delete cur_cache;
					cur_cache = NULL;
				}
			}

			if (cur_cache == NULL) {
				cur_cache = new NisLocalCache(status);
				if (cur_cache == NULL) {
					status = NIS_NOMEMORY;
				} else if (status != NIS_SUCCESS) {
					delete cur_cache;
					cur_cache = NULL;
				}
			}
		}
	}
	*cache = cur_cache;
	mutex_unlock(&cur_cache_lock);
	return (status);
}


/*
 *  The Federated Naming code needs to be able to talk to NIS+ servers
 *  in foreign domains.  It does this by calling __nis_CacheAddEntry
 *  with a "fabricated" directory object.  The binding code needs to
 *  check to for these added directories.  The simplest way to handle
 *  it would be to switch over to using the local cache but then we
 *  wouldn't be able to take advantage of the shared directory cache
 *  for lookups in the local domain.  So, instead, we create an
 *  auxiliary local cache and check there for bindings first.
 *
 *  Note that if the application is already using a local cache,
 *  then we will be creating another local cache.  That doesn't
 *  break anything (it just uses more memory), but it makes the
 *  code simpler to not check for this special case, which shouldn't
 *  happen under normal circumstances.
 */
static NisCache *aux_cache = NULL;

static
int
__nis_CacheAuxBind(char *dname, nis_bound_directory **binding, u_int flags)
{
	nis_bound_directory *t;
	nis_error err;
	nis_server *srv;
	int nsrv;

	/* check to see if we have an auxiliary cache */
	mutex_lock(&cur_cache_lock);
	if (aux_cache == NULL) {
		mutex_unlock(&cur_cache_lock);
		return (NIS_NOTFOUND);
	}
	mutex_unlock(&cur_cache_lock);

	/* check to see if directory is in the cache */
	err = aux_cache->searchDir(dname, &t, 0);
	if (err == NIS_CACHEEXPIRED && t != 0) {
		/* Exists, but has expired; refresh it */
		aux_cache->refreshBinding(t);
		nis_free_binding(t);
		err = aux_cache->searchDir(dname, &t, 0);
		/*
		 * If we're still getting NIS_CACHEEXPIRED, we'll
		 * continue using the expired object until the next
		 * refresh attempt.
		 */
		if (err == NIS_CACHEEXPIRED)
			err = NIS_SUCCESS;
	}
	if (err != NIS_SUCCESS)
		return (NIS_NOTFOUND);

	srv = t->dobj.do_servers.do_servers_val;
	nsrv = t->dobj.do_servers.do_servers_len;

	if (flags & MASTER_ONLY) {
		err = aux_cache->bindServer(srv, 1, binding);
	} else {
		err = aux_cache->bindServer(srv, nsrv, binding);
	}
	nis_free_binding(t);

	return (err);
}

void
__nis_CacheStart()
{
	nis_error status;
	NisCache *cache;

	while (1) {
		if ((status = __nis_CacheInit(&cache)) != NIS_SUCCESS)
			return;
		if (cache->okay())
			break;
	}
}

/*
 * The C interface to NisCache::Bind().
 * Returns a directory structure for a given dir_name.
 */

nis_error
__nis_CacheBind(char *dname, directory_obj *dobj)
{
	nis_error status;
	nis_error err;
	nis_bound_directory *binding;
	NisCache *cache;

	while (1) {
		if ((status = __nis_CacheInit(&cache)) != NIS_SUCCESS)
			return (status);

		err = cache->bindReplica(dname, &binding);
		if (cache->okay())
			break;
	}
	if (err == NIS_SUCCESS) {
		*dobj = binding->dobj;
		(void) memset((char *)&binding->dobj, 0,
		    sizeof (directory_obj));
		nis_free_binding(binding);
	} else {
		(void) memset((void *)dobj, 0, sizeof (directory_obj));
	}
	return (err);
}

/*
 * The C interface to NisSharedCache::removeEntry()
 * Removes an entry from the cache.
 */

bool_t
__nis_CacheRemoveEntry(directory_obj *dobj)
{
	nis_error status;
	nis_error err;
	nis_bound_directory *binding;
	NisCache *cache;

	while (1) {
		if ((status = __nis_CacheInit(&cache)) != NIS_SUCCESS)
			return (status);

		err = cache->searchDir(dobj->do_name, &binding, 0);
		/* Expired is good enough, since we intend to refresh it */
		if (err == NIS_CACHEEXPIRED)
			err = NIS_SUCCESS;
		if (cache->okay())
			break;
	}
	if (err == NIS_SUCCESS) {
		/*
		 * For the local cache, we really do want to remove the
		 * binding, but for the shared (mapped) cache, we just
		 * refresh instead. The resetBinding() function will
		 * do this for us.
		 */
		(void) cache->resetBinding(binding);
		nis_free_binding(binding);
	}
	return (NIS_SUCCESS);
}

/*
 * The C interface to NisSharedCache::search()
 * searches the cache for a given directory_name
 */

nis_error
__nis_CacheSearch(char *dname, directory_obj *dobj)
{
	nis_error err;
	nis_bound_directory *binding;
	NisCache *cache;

	if (__nis_CacheAuxBind(dname, &binding, 0) == NIS_SUCCESS) {
		*dobj = binding->dobj;
		(void) memset((char *)&binding->dobj, 0,
		    sizeof (directory_obj));
		nis_free_binding(binding);
		return (NIS_SUCCESS);
	}

	while (1) {
		if ((err = __nis_CacheInit(&cache)) != NIS_SUCCESS)
			return (err);

		err = cache->searchDir(dname, &binding, 1);
		if (err == NIS_CACHEEXPIRED && binding != 0) {
			/* Exists, but has expired; refresh it */
			cache->refreshBinding(binding);
			nis_free_binding(binding);
			err = cache->searchDir(dname, &binding, 1);
			/*
			 * If we're still getting NIS_CACHEEXPIRED, we'll
			 * continue using the expired object until the next
			 * refresh attempt.
			 */
			if (err == NIS_CACHEEXPIRED)
				err = NIS_SUCCESS;
		}
		if (cache->okay())
			break;
	}
	if (err == NIS_SUCCESS) {
		*dobj = binding->dobj;
		(void) memset((char *)&binding->dobj, 0,
		    sizeof (directory_obj));
		nis_free_binding(binding);
	} else {
		(void) memset((void *)dobj, 0, sizeof (directory_obj));
	}
	return (err);
}

/*
 * The C interface to NisSharedCache::read_coldstart().
 * It tells the caching system to reinitialize from the coldstart file.
 * sends a message to cachemgr if the cachefile is valid to do this or
 * if local_cache is valid reads in the coldstart on its own.
 */

void
__nis_CacheRestart()
{
	NisCache *cache;

	while (1) {
		if (__nis_CacheInit(&cache) != NIS_SUCCESS)
			return;

		(void) cache->readColdStart();
		if (cache->okay())
			break;
	}
}

/*
 * The C interface to NisSharedCache::print()
 * dumps the entrire cache on stdout.
 */

void
__nis_CachePrint()
{
	NisCache *cache;

	while (1) {
		if (__nis_CacheInit(&cache) != NIS_SUCCESS)
			return;

		cache->print();
		if (cache->okay())
			break;
	}
}


bool_t
__nis_CacheAddEntry(fd_result *, directory_obj *dobj)
{
	directory_obj *tmp;
	nis_error status = NIS_SUCCESS;

	mutex_lock(&cur_cache_lock);
	if (!aux_cache) {
		aux_cache = new NisLocalCache(status);
		if (aux_cache == NULL) {
			mutex_unlock(&cur_cache_lock);
			return (0);
		} else if (status != NIS_SUCCESS) {
			delete aux_cache;
			aux_cache = NULL;
			mutex_unlock(&cur_cache_lock);
			return (0);
		}
	}
	mutex_unlock(&cur_cache_lock);

	/* make a copy of the dir. obj. because createBinding() frees it */
	tmp = (directory_obj *)calloc(1, sizeof (*tmp));
	if (!tmp) {
		return (NIS_NOMEMORY);
	}
	if (!__nis_xdr_dup((xdrproc_t)xdr_directory_obj,
			(char *)dobj, (char *)tmp)) {
		free((void *)tmp);
		return (NIS_NOMEMORY);
	}
	if (aux_cache->createBinding(tmp) != NIS_SUCCESS)
		return (0);
	return (1);
}

void
__nis_CacheRefreshEntry(char *)
{
	/* this function is obsolete, but remains for compatibility */
}

nis_error
__nis_CacheBindDir(char *dname, nis_bound_directory **binding, int flags)
{
	nis_error status;
	NisCache *cache;

	if (__nis_CacheAuxBind(dname, binding, flags) == NIS_SUCCESS)
		return (NIS_SUCCESS);

	while (1) {
		if ((status = __nis_CacheInit(&cache)) != NIS_SUCCESS)
			return (status);

		if (flags & MASTER_ONLY)
			status = cache->bindMaster(dname, binding);
		else
			status = cache->bindReplica(dname, binding);

		if (cache->okay())
			break;
	}
	return (status);
}

nis_error
__nis_CacheBindMaster(char *dname, nis_bound_directory **binding)
{
	nis_error status;
	NisCache *cache;

	if (__nis_CacheAuxBind(dname, binding, MASTER_ONLY) == NIS_SUCCESS)
		return (NIS_SUCCESS);

	while (1) {
		if ((status = __nis_CacheInit(&cache)) != NIS_SUCCESS)
			return (status);

		status = cache->bindMaster(dname, binding);
		if (cache->okay())
			break;
	}
	return (status);
}

nis_error
__nis_CacheBindServer(nis_server *srv, int nsrv, nis_bound_directory **binding)
{
	nis_error status;
	NisCache *cache;

	while (1) {
		if ((status = __nis_CacheInit(&cache)) != NIS_SUCCESS)
			return (status);

		status = cache->bindServer(srv, nsrv, binding);
		if (cache->okay())
			break;
	}
	return (status);
}

int
__nis_CacheRefreshBinding(nis_bound_directory *binding)
{
	int status;
	NisCache *cache;

	if (binding->dobj.do_name == NULL)
		return (1);

	while (1) {
		if (__nis_CacheInit(&cache) != NIS_SUCCESS)
			return (0);

		status = cache->refreshBinding(binding);
		if (cache->okay())
			break;
	}
	return (status);
}

int
__nis_CacheRefreshAddress(nis_bound_endpoint *bep)
{
	int status;
	NisCache *cache;

	while (1) {
		if (__nis_CacheInit(&cache) != NIS_SUCCESS)
			return (0);

		status = cache->refreshAddress(bep);
		if (cache->okay())
			break;
	}
	return (status);
}

int
__nis_CacheRefreshCallback(nis_bound_endpoint *bep)
{
	int status;
	NisCache *cache;

	while (1) {
		if (__nis_CacheInit(&cache) != NIS_SUCCESS)
			return (0);

		status = cache->refreshCallback(bep);
		if (cache->okay())
			break;
	}
	return (status);
}

uint32_t
__nis_CacheLocalLoadPref()
{
	return (cur_cache->loadPreferredServers());
}


nis_error
__nis_CacheLocalInit(uint32_t *exp_time)
{
	nis_error status = NIS_SUCCESS;

	mutex_lock(&cur_cache_lock);

	if (!checked_env) {
		__nis_get_environment(); /* in libc/port/gen/nss_common.c */
		checked_env = 1;
	}

	cur_cache = new NisLocalCache(status, exp_time);
	if (cur_cache == NULL) {
		status = NIS_NOMEMORY;
	} else if (status != NIS_SUCCESS) {
		delete cur_cache;
		cur_cache = NULL;
	}

	mutex_unlock(&cur_cache_lock);

	return (status);
}

nis_error
__nis_CacheMgrInit_discard(int discardOldCache)
{
	nis_error status = NIS_SUCCESS;

	mutex_lock(&cur_cache_lock);

	if (!checked_env) {
		__nis_get_environment(); /* in libc/port/gen/nss_common.c */
		checked_env = 1;
	}

	mgr_cache = new NisMgrCache(status, discardOldCache);
	if (mgr_cache == NULL) {
		status = NIS_NOMEMORY;
	} else if (status != NIS_SUCCESS) {
		delete mgr_cache;
		mgr_cache = NULL;
	}
	cur_cache = mgr_cache;
	mutex_unlock(&cur_cache_lock);

	if (mgr_cache)
		mgr_cache->start();

	return (status);
}

nis_error
__nis_CacheMgrInit()
{
	return (__nis_CacheMgrInit_discard(0));
}

void
__nis_CacheMgrCleanup()
{
	mutex_lock(&cur_cache_lock);
	if (mgr_cache)
		delete mgr_cache;
	mgr_cache = NULL;
	mutex_unlock(&cur_cache_lock);
}

void
__nis_CacheMgrReadColdstart()
{
	(void) mgr_cache->readColdStart();
}

nis_error
__nis_CacheMgrBindReplica(char *dname)
{
	nis_error err;
	nis_bound_directory *binding;

	err = mgr_cache->bindReplica(dname, &binding);
	if (err == NIS_SUCCESS)
		nis_free_binding(binding);
	return (err);
}

nis_error
__nis_CacheMgrBindMaster(char *dname)
{
	nis_error err;
	nis_bound_directory *binding;

	err = mgr_cache->bindMaster(dname, &binding);
	if (err == NIS_SUCCESS)
		nis_free_binding(binding);
	return (err);
}

nis_error
__nis_CacheMgrBindServer(nis_server *srv, int nsrv)
{
	nis_error err;
	nis_bound_directory *binding;

	err = mgr_cache->bindServer(srv, nsrv, &binding);
	if (err == NIS_SUCCESS)
		nis_free_binding(binding);
	return (err);
}

int
__nis_CacheMgrRefreshBinding(nis_bound_directory *binding)
{
	int	ret;
	uint_t	i;

	if (binding->dobj.do_name == NULL)
		return (1);
	/*
	 * A probable reason for a refresh request from the NIS+
	 * client code is that a server address has changed. Since we
	 * don't know which one the client was trying, we toss out
	 * all of them.
	 */
	for (i = 0; i < binding->BEP.BEP_len; i++) {
		(void) mgr_cache->refreshAddress(&binding->BEP.BEP_val[i]);
	}
	ret = mgr_cache->refreshBinding(binding);
	/* Ping to get new active bindings */
	mgr_cache->ping();
	return (ret);
}

int
__nis_CacheMgrRefreshAddress(nis_bound_endpoint *bep)
{
	return (mgr_cache->refreshAddress(bep));
}

int
__nis_CacheMgrRefreshCallback(nis_bound_endpoint *bep)
{
	return (mgr_cache->refreshCallback(bep));
}

int
__nis_CacheMgrUpdateUaddr(char *uaddr)
{
	return (mgr_cache->updateUaddr(uaddr));
}

void
__nis_CacheMgrMarkUp()
{
	mgr_cache->markUp();
}

uint32_t
__nis_CacheMgrTimers()
{
	return (mgr_cache->timers());
}

uint32_t
__nis_CacheMgrRefreshCache()
{
	return (mgr_cache->refreshCache());
}

uint32_t
__nis_serverRefreshCache()
{
	return (cur_cache->refreshCache());
}

}  /* extern "C" */
