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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 */

/*
 * Define and initialize MT client/server data.
 */

#include	<sys/types.h>
#include	<sys/t_lock.h>
#include	<sys/kstat.h>
#include	<sys/systm.h>
#include	<sys/zone.h>

#include	<rpc/types.h>
#include	<rpc/auth.h>
#include	<rpc/clnt.h>

kmutex_t xid_lock;		/* XID allocation */
kmutex_t clnt_pending_lock;	/* for list of pending calls awaiting replies */
kmutex_t clnt_max_msg_lock;	/* updating max message sanity check for cots */

zone_key_t	rpcstat_zone_key;

/*
 * rpcstat_zone_[init|fini]_common() ends up being nearly identical to
 * nfsstat_zone_[init|fini]_common().  Due to them necessarily being in
 * different modules, however, we end up needing to duplicate the code.
 */
kstat_named_t *
rpcstat_zone_init_common(zoneid_t zoneid, const char *module, const char *name,
    const kstat_named_t *template, size_t template_size)
{
	kstat_t *ksp;
	kstat_named_t *ks_data;


/*
 * PSARC 2001/697 Contract Private Interface
 * rpc_clts_client
 * rpc_cots_client
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2001-697@sun.com
 *
 */
	ks_data = kmem_alloc(template_size, KM_SLEEP);
	bcopy(template, ks_data, template_size);
	if ((ksp = kstat_create_zone(module, 0, name, "rpc",
	    KSTAT_TYPE_NAMED, template_size / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE, zoneid)) != NULL) {
		ksp->ks_data = ks_data;
		kstat_install(ksp);
	}
	return (ks_data);
}

void
rpcstat_zone_fini_common(zoneid_t zoneid, const char *module, const char *name)
{
	kstat_delete_byname_zone(module, 0, name, zoneid);
}

static void *
mt_kstat_zone_init(zoneid_t zoneid)
{
	struct rpcstat *rpcstat;

	rpcstat = kmem_alloc(sizeof (*rpcstat), KM_SLEEP);

	clnt_clts_stats_init(zoneid, &rpcstat->rpc_clts_client);
	svc_clts_stats_init(zoneid, &rpcstat->rpc_clts_server);

	clnt_cots_stats_init(zoneid, &rpcstat->rpc_cots_client);
	svc_cots_stats_init(zoneid, &rpcstat->rpc_cots_server);

	return (rpcstat);
}

/*
 * Deletes the previously allocated "rpc" kstats
 */
static void
mt_kstat_zone_fini(zoneid_t zoneid, void *data)
{
	struct rpcstat *rpcstat = data;

	clnt_cots_stats_fini(zoneid, &rpcstat->rpc_cots_client);
	svc_cots_stats_fini(zoneid, &rpcstat->rpc_cots_server);

	clnt_clts_stats_fini(zoneid, &rpcstat->rpc_clts_client);
	svc_clts_stats_fini(zoneid, &rpcstat->rpc_clts_server);

	kmem_free(rpcstat, sizeof (*rpcstat));
}

void
mt_kstat_init(void)
{
	zone_key_create(&rpcstat_zone_key, mt_kstat_zone_init, NULL,
	    mt_kstat_zone_fini);
}

void
mt_kstat_fini(void)
{
	(void) zone_key_delete(rpcstat_zone_key);
}

static bool_t	clnt_xid_initialized = FALSE;
static uint32_t clnt_xid = 0;	/* transaction id used by all clients */

uint32_t
alloc_xid(void)
{
	uint32_t  xid;
	timestruc_t now;

	/*
	 * Do a one time initialzation to better utilize the number
	 * space.
	 */
	mutex_enter(&xid_lock);
	if (clnt_xid_initialized == FALSE) {
		clnt_xid_initialized = TRUE;
		gethrestime(&now);
		clnt_xid = (uint32_t)((now.tv_sec << 20) |
		    (now.tv_nsec >> 10));
	}

	xid = clnt_xid++;

	/*
	 * Don't return a zero xid.  This could happen if the initialization
	 * happens to return zero or if clnt_xid wraps.
	 */
	if (xid == 0)
		xid = clnt_xid++;

	mutex_exit(&xid_lock);
	return (xid);
}

/*
 * These functions are temporary and designed for the upgrade-workaround only.
 * They cannot be used for general zone-crossing RPC client support, and will
 * be removed shortly.
 *
 * Currently these functions route all nfs global clients to the global zone.
 * When this upgrade-workaround is removed these function should return the
 * correct zone or their calls should be changed (rpc_zone() to curproc->p_zone
 * and rpc_zoneid() to getzoneid()).
 */
struct zone *
rpc_zone(void)
{
	return (nfs_global_client_only != 0 ? global_zone : curproc->p_zone);
}

zoneid_t
rpc_zoneid(void)
{
	return (nfs_global_client_only != 0 ? GLOBAL_ZONEID : getzoneid());
}
