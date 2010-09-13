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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains interface definitions and wrappers for file
 * system snapshot support.  File systems may depend on this module
 * for symbol resolution while the implementation may remain unloaded
 * until needed.
 */
#include <sys/types.h>
#include <sys/debug.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/fssnap_if.h>

struct fssnap_operations snapops = {
	NULL,	/* fssnap_create */
	NULL,	/* fssnap_set_candidate */
	NULL,	/* fssnap_is_candidate */
	NULL,	/* fssnap_create_done */
	NULL,	/* fssnap_delete */
	NULL	/* fssnap_strategy */
};

void *
fssnap_create(chunknumber_t nchunks, uint_t chunksz, u_offset_t maxsize,
    struct vnode *fsvp, int backfilecount, struct vnode **bfvpp, char *backpath,
    u_offset_t max_backfile_size)
{
	void *snapid = NULL;

	if (snapops.fssnap_create)
		snapid = (snapops.fssnap_create)(nchunks, chunksz, maxsize,
		    fsvp, backfilecount, bfvpp, backpath, max_backfile_size);

	return (snapid);
}

void
fssnap_set_candidate(void *snapshot_id, chunknumber_t chunknumber)
{
	if (snapops.fssnap_set_candidate)
		(snapops.fssnap_set_candidate)(snapshot_id, chunknumber);
}

int
fssnap_is_candidate(void *snapshot_id, u_offset_t off)
{
	int rc = 0;

	if (snapops.fssnap_is_candidate)
		rc = (snapops.fssnap_is_candidate)(snapshot_id, off);

	return (rc);
}

int
fssnap_create_done(void *snapshot_id)
{
	int snapslot = -1;

	if (snapops.fssnap_create_done)
		snapslot = (snapops.fssnap_create_done)(snapshot_id);

	return (snapslot);
}

int
fssnap_delete(void *snapshot_id)
{
	int snapslot = -1;

	if (snapops.fssnap_delete)
		snapslot = (snapops.fssnap_delete)(snapshot_id);

	return (snapslot);
}

void
fssnap_strategy(void *snapshot_id, struct buf *bp)
{
	if (snapops.fssnap_strategy)
		(snapops.fssnap_strategy)(snapshot_id, bp);
}


#include <sys/modctl.h>

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, "File System Snapshot Interface",
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

/*
 * Unloading is MT-safe because our client drivers use
 * the _depends_on[] mechanism - we won't go while they're
 * still around.
 */
int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
