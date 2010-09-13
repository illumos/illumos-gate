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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */


#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/buf.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/vfs.h>
#include <sys/swap.h>
#include <sys/vnode.h>
#include <sys/cred.h>
#include <sys/fs/snode.h>
#include <sys/thread.h>

#include <fs/fs_subr.h>

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"specfs",
	specinit,
	VSW_ZMOUNT,
	NULL
};

extern struct mod_ops mod_fsops;

/*
 * Module linkage information for the kernel.
 */
static struct modlfs modlfs = {
	&mod_fsops, "filesystem for specfs", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * N.B.
 * No _fini routine. This module cannot be unloaded once loaded.
 * The NO_UNLOAD_STUB in modstub.s must change if this module ever
 * is modified to become unloadable.
 */

kmutex_t spec_syncbusy;		/* initialized in specinit() */

/*
 * Run though all the snodes and force write-back
 * of all dirty pages on the block devices.
 */
/*ARGSUSED*/
int
spec_sync(struct vfs *vfsp,
	short	flag,
	struct cred *cr)
{
	struct snode *sync_list;
	register struct snode **spp, *sp, *spnext;
	register struct vnode *vp;

	if (mutex_tryenter(&spec_syncbusy) == 0)
		return (0);

	if (flag & SYNC_ATTR) {
		mutex_exit(&spec_syncbusy);
		return (0);
	}
	mutex_enter(&stable_lock);
	sync_list = NULL;
	/*
	 * Find all the snodes that are dirty and add them to the sync_list
	 */
	for (spp = stable; spp < &stable[STABLESIZE]; spp++) {
		for (sp = *spp; sp != NULL; sp = sp->s_next) {
			vp = STOV(sp);
			/*
			 * Don't bother sync'ing a vp if it's
			 * part of a virtual swap device.
			 */
			if (IS_SWAPVP(vp))
				continue;

			if (vp->v_type == VBLK && vn_has_cached_data(vp)) {
				/*
				 * Prevent vp from going away before we
				 * we get a chance to do a VOP_PUTPAGE
				 * via sync_list processing
				 */
				VN_HOLD(vp);
				sp->s_list = sync_list;
				sync_list = sp;
			}
		}
	}
	mutex_exit(&stable_lock);
	/*
	 * Now write out all the snodes we marked asynchronously.
	 */
	for (sp = sync_list; sp != NULL; sp = spnext) {
		spnext = sp->s_list;
		vp = STOV(sp);
		(void) VOP_PUTPAGE(vp, (offset_t)0, (uint_t)0, B_ASYNC, cr,
		    NULL);
		VN_RELE(vp);		/* Release our hold on vnode */
	}
	mutex_exit(&spec_syncbusy);
	return (0);
}
