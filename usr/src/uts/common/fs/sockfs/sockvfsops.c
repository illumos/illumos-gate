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

extern struct mod_ops mod_fsops;

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
