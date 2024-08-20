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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2024 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/vfs.h>
#include <sys/swap.h>
#include <sys/vnode.h>
#include <sys/cred.h>
#include <sys/thread.h>
#include <sys/zone.h>

#include <fs/fs_subr.h>

#include <sys/stream.h>
#include <sys/socket.h>
#include <sys/stropts.h>
#include <sys/socketvar.h>

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

static zone_key_t sockfs_zone_key;

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"sockfs",
	sockinit,
	VSW_ZMOUNT,
	NULL
};

/*
 * Module linkage information for the kernel.
 */
static struct modlfs modlfs = {
	&mod_fsops, "filesystem for sockfs", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

int
_init(void)
{
	int ret;

	/*
	 * We want to be informed each time a zone is created or
	 * destroyed in the kernel, so we can maintain per-zone
	 * kstat. sock_kstat_init() will also be called for the
	 * global zone, without us having to special case it here.
	 */
	zone_key_create(&sockfs_zone_key,
	    sock_kstat_init, NULL, sock_kstat_fini);

	if ((ret = mod_install(&modlinkage)) != 0) {
		(void) zone_key_delete(sockfs_zone_key);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	/* zone_key_delete(sockfs_zone_key); - if we were ever to be unloaded */

	return (EBUSY);
}

/*
 * N.B.
 * No _fini routine. This module cannot be unloaded once loaded.
 * The NO_UNLOAD_STUB in modstub.s must change if this module ever
 * is modified to become unloadable.
 */

/*
 * In the past, there was no dedicated vfs_t for sockfs ala fifofs and instead
 * every vnode actually had the root filesystem's vfs_t. While there really
 * isn't anything that makes that much sense to put in here, we fill out a token
 * statvfs here. We're not the only system that provides a token, not super
 * useful vfs_t here.
 */
int
sockfs_statvfs(vfs_t *vfsp, struct statvfs64 *stat)
{
	dev32_t d32;

	/*
	 * We explicitly don't set any kind of fundamental block size and leave
	 * this at zero.
	 *
	 * Similarly we don't even try to lie bout the number of blocks and
	 * files, especially as our kmem cache stats aren't zone aware.
	 */
	bzero(stat, sizeof (struct statvfs64));
	stat->f_bsize = PAGESIZE;

	(void) cmpldev(&d32, vfsp->vfs_dev);
	stat->f_fsid = d32;

	(void) strlcpy(stat->f_basetype, "sockfs", sizeof (stat->f_basetype));

	return (0);
}
