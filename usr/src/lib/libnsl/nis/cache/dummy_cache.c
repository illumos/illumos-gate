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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* The C interface to directory cache class functions */

#include "mt.h"
#include <rpcsvc/nis.h>

int __nis_debuglevel = 0;
struct NisCache;

/* ARGSUSED */
nis_error
__nis_CacheInit(struct NisCache **cache)
{
	return (NIS_NOTFOUND);
}

void
__nis_CacheStart()
{
}

/* ARGSUSED */
nis_error
__nis_CacheBind(char *dname, directory_obj *dobj)
{
	return (NIS_NOTFOUND);
}

/* ARGSUSED */
bool_t
__nis_CacheRemoveEntry(directory_obj *dobj)
{
	return (0);
}

/* ARGSUSED */
nis_error
__nis_CacheSearch(char *dname, directory_obj *dobj)
{
	return (NIS_NOTFOUND);
}

void
__nis_CacheRestart()
{
}

void
__nis_CachePrint()
{
}


/* ARGSUSED */
bool_t
__nis_CacheAddEntry(fd_result *unused, directory_obj *dobj)
{
	return (0);
}

/* ARGSUSED */
void
__nis_CacheRefreshEntry(char *unused)
{
}

/* ARGSUSED */
nis_error
__nis_CacheBindDir(char *dname, nis_bound_directory **binding, int flags)
{
	return (NIS_NOTFOUND);
}

/* ARGSUSED */
nis_error
__nis_CacheBindMaster(char *dname, nis_bound_directory **binding)
{
	return (NIS_NOTFOUND);
}

/* ARGSUSED */
nis_error
__nis_CacheBindServer(nis_server *srv, int nsrv, nis_bound_directory **binding)
{
	return (NIS_NOTFOUND);
}

/* ARGSUSED */
int
__nis_CacheRefreshBinding(nis_bound_directory *binding)
{
	return (0);
}

/* ARGSUSED */
int
__nis_CacheRefreshAddress(nis_bound_endpoint *bep)
{
	return (0);
}

/* ARGSUSED */
int
__nis_CacheRefreshCallback(nis_bound_endpoint *bep)
{
	return (0);
}

uint32_t
__nis_CacheLocalLoadPref()
{
	return (0);
}

/* ARGSUSED */
nis_error
__nis_CacheLocalInit(uint32_t *exp_time)
{
	return (NIS_NOTFOUND);
}

/* ARGSUSED */
nis_error
__nis_CacheMgrInit_discard(int discardOldCache)
{
	return (NIS_NOTFOUND);
}

nis_error
__nis_CacheMgrInit()
{
	return (NIS_NOTFOUND);
}

void
__nis_CacheMgrCleanup()
{
}

void
__nis_CacheMgrReadColdstart()
{
}

/* ARGSUSED */
nis_error
__nis_CacheMgrBindReplica(char *dname)
{
	return (NIS_NOTFOUND);
}

/* ARGSUSED */
nis_error
__nis_CacheMgrBindMaster(char *dname)
{
	return (NIS_NOTFOUND);
}

/* ARGSUSED */
nis_error
__nis_CacheMgrBindServer(nis_server *srv, int nsrv)
{
	return (NIS_NOTFOUND);
}

/* ARGSUSED */
int
__nis_CacheMgrRefreshBinding(nis_bound_directory *binding)
{
	return (0);
}

/* ARGSUSED */
int
__nis_CacheMgrRefreshAddress(nis_bound_endpoint *bep)
{
	return (0);
}

/* ARGSUSED */
int
__nis_CacheMgrRefreshCallback(nis_bound_endpoint *bep)
{
	return (0);
}

/* ARGSUSED */
int
__nis_CacheMgrUpdateUaddr(char *uaddr)
{
	return (0);
}

void
__nis_CacheMgrMarkUp()
{
}

uint32_t
__nis_CacheMgrTimers()
{
	return (0);
}

uint32_t
__nis_CacheMgrRefreshCache()
{
	return (0);
}

uint32_t
__nis_serverRefreshCache()
{
	return (0);
}

/* ARGSUSED */
bool_t
writeColdStartFile(directory_obj *dobj)
{
	return (0);
}

/* ARGSUSED */
bool_t
__readColdStartFile(directory_obj *dobj)
{
	return (0);
}
