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
 *
 *  	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/t_lock.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/errno.h>
#include <sys/buf.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/dnlc.h>
#include <sys/vmsystm.h>
#include <sys/flock.h>
#include <sys/share.h>
#include <sys/cmn_err.h>
#include <sys/tiuser.h>
#include <sys/sysmacros.h>
#include <sys/callb.h>
#include <sys/acl.h>
#include <sys/kstat.h>
#include <sys/signal.h>
#include <sys/list.h>
#include <sys/zone.h>

#include <netsmb/smb_conn.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>

/*
 * The following code provide zone support in order to perform an action
 * for each smbfs mount in a zone.  This is also where we would add
 * per-zone globals and kernel threads for the smbfs module (since
 * they must be terminated by the shutdown callback).
 */

struct smi_globals {
	kmutex_t	smg_lock;  /* lock protecting smg_list */
	list_t		smg_list;  /* list of SMBFS mounts in zone */
	boolean_t	smg_destructor_called;
};
typedef struct smi_globals smi_globals_t;

static zone_key_t smi_list_key;

/* ARGSUSED */
static void *
smbfs_zone_init(zoneid_t zoneid)
{
	smi_globals_t *smg;

	smg = kmem_alloc(sizeof (*smg), KM_SLEEP);
	mutex_init(&smg->smg_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&smg->smg_list, sizeof (smbmntinfo_t),
	    offsetof(smbmntinfo_t, smi_zone_node));
	smg->smg_destructor_called = B_FALSE;
	return (smg);
}

/*
 * Callback routine to tell all SMBFS mounts in the zone to stop creating new
 * threads.  Existing threads should exit.
 */
/* ARGSUSED */
static void
smbfs_zone_shutdown(zoneid_t zoneid, void *data)
{
	smi_globals_t *smg = data;
	smbmntinfo_t *smi;

	ASSERT(smg != NULL);
again:
	mutex_enter(&smg->smg_lock);
	for (smi = list_head(&smg->smg_list); smi != NULL;
	    smi = list_next(&smg->smg_list, smi)) {

		/*
		 * If we've done the shutdown work for this FS, skip.
		 * Once we go off the end of the list, we're done.
		 */
		if (smi->smi_flags & SMI_DEAD)
			continue;

		/*
		 * We will do work, so not done.  Get a hold on the FS.
		 */
		VFS_HOLD(smi->smi_vfsp);

		/*
		 * purge the DNLC for this filesystem
		 */
		(void) dnlc_purge_vfsp(smi->smi_vfsp, 0);

		mutex_enter(&smi->smi_lock);
		smi->smi_flags |= SMI_DEAD;
		mutex_exit(&smi->smi_lock);

		/*
		 * Drop lock and release FS, which may change list, then repeat.
		 * We're done when every mi has been done or the list is empty.
		 */
		mutex_exit(&smg->smg_lock);
		VFS_RELE(smi->smi_vfsp);
		goto again;
	}
	mutex_exit(&smg->smg_lock);
}

static void
smbfs_zone_free_globals(smi_globals_t *smg)
{
	list_destroy(&smg->smg_list);	/* makes sure the list is empty */
	mutex_destroy(&smg->smg_lock);
	kmem_free(smg, sizeof (*smg));

}

/* ARGSUSED */
static void
smbfs_zone_destroy(zoneid_t zoneid, void *data)
{
	smi_globals_t *smg = data;

	ASSERT(smg != NULL);
	mutex_enter(&smg->smg_lock);
	if (list_head(&smg->smg_list) != NULL) {
		/* Still waiting for VFS_FREEVFS() */
		smg->smg_destructor_called = B_TRUE;
		mutex_exit(&smg->smg_lock);
		return;
	}
	smbfs_zone_free_globals(smg);
}

/*
 * Add an SMBFS mount to the per-zone list of SMBFS mounts.
 */
void
smbfs_zonelist_add(smbmntinfo_t *smi)
{
	smi_globals_t *smg;

	smg = zone_getspecific(smi_list_key, smi->smi_zone);
	mutex_enter(&smg->smg_lock);
	list_insert_head(&smg->smg_list, smi);
	mutex_exit(&smg->smg_lock);
}

/*
 * Remove an SMBFS mount from the per-zone list of SMBFS mounts.
 */
void
smbfs_zonelist_remove(smbmntinfo_t *smi)
{
	smi_globals_t *smg;

	smg = zone_getspecific(smi_list_key, smi->smi_zone);
	mutex_enter(&smg->smg_lock);
	list_remove(&smg->smg_list, smi);
	/*
	 * We can be called asynchronously by VFS_FREEVFS() after the zone
	 * shutdown/destroy callbacks have executed; if so, clean up the zone's
	 * smi_globals.
	 */
	if (list_head(&smg->smg_list) == NULL &&
	    smg->smg_destructor_called == B_TRUE) {
		smbfs_zone_free_globals(smg);
		return;
	}
	mutex_exit(&smg->smg_lock);
}


#ifdef NEED_SMBFS_CALLBACKS
/*
 * Call-back hooks for netsmb, in case we want them.
 * Apple's VFS wants them.  We may not need them.
 *
 * I thought I could use the "dead" callback from netsmb
 * to set the SMI_DEAD flag, but that looks like it will
 * interfere with the zone shutdown mechanisms.
 */
static void smbfs_dead(smb_share_t *ssp)
{
#if 0 /* see above */
	smbmntinfo_t *smi = ssp->ss_mount;
	if (smi) {
		mutex_enter(&smi->smi_lock);
		smi->smi_flags |= SMI_DEAD;
		mutex_exit(&smi->smi_lock);
	}
#endif
}

static void smbfs_down(smb_share_t *ss)
{
	/* no-op */
}

static void smbfs_up(smb_share_t *ss)
{
	/* no-op */
}

smb_fscb_t smbfs_cb = {
	.fscb_dead = smbfs_dead,
	.fscb_down = smbfs_down,
	.fscb_up   = smbfs_up };

#endif /* NEED_SMBFS_CALLBACKS */

/*
 * SMBFS Client initialization routine.  This routine should only be called
 * once.  It performs the following tasks:
 *      - Initalize all global locks
 *      - Call sub-initialization routines (localize access to variables)
 */
int
smbfs_clntinit(void)
{
	int error;

	error = smbfs_subrinit();
	if (error)
		return (error);
	zone_key_create(&smi_list_key, smbfs_zone_init, smbfs_zone_shutdown,
	    smbfs_zone_destroy);
#ifdef NEED_SMBFS_CALLBACKS
	smb_fscb_set(&smbfs_cb);
#endif /* NEED_SMBFS_CALLBACKS */
	return (0);
}

/*
 * This routine is called when the modunload is called. This will cleanup
 * the previously allocated/initialized nodes.
 */
void
smbfs_clntfini(void)
{
#ifdef NEED_SMBFS_CALLBACKS
	smb_fscb_set(NULL);
#endif /* NEED_SMBFS_CALLBACKS */
	(void) zone_key_delete(smi_list_key);
	smbfs_subrfini();
}
