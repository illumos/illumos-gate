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

#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/fs/lofs_node.h>
#include <sys/fs/lofs_info.h>

#include <mdb/mdb_modapi.h>

typedef struct lnode_walk {
	struct lobucket *lw_table;	/* Snapshot of hash table */
	uint_t lw_tabsz;		/* Size of hash table */
	uint_t lw_tabi;			/* Current table index */
	lnode_t *lw_lnode;		/* Current buffer */
} lnode_walk_t;

int
lnode_walk_init(mdb_walk_state_t *wsp)
{
	lnode_walk_t *lwp;

	int lofsfstype;
	struct vfs vfs;
	struct loinfo loinfo;

	if (mdb_readvar(&lofsfstype, "lofsfstype") == -1) {
		mdb_warn("failed to read 'lofsfstype' symbol\n");
		return (WALK_ERR);
	}

	if (wsp->walk_addr == 0) {
		uintptr_t rootvfsp, vfsp;
		uint_t htsize;

		lwp = mdb_alloc(sizeof (lnode_walk_t), UM_SLEEP);

retry:
		lwp->lw_tabsz = 0;
		if (mdb_readvar(&rootvfsp, "rootvfs") == -1) {
			mdb_warn("failed to read 'rootvfs' symbol\n");
			mdb_free(lwp, sizeof (lnode_walk_t));
			return (WALK_ERR);
		}

		vfsp = rootvfsp;
		do {
			(void) mdb_vread(&vfs, sizeof (vfs), vfsp);
			if (lofsfstype != vfs.vfs_fstype) {
				vfsp = (uintptr_t)vfs.vfs_next;
				continue;
			}
			(void) mdb_vread(&loinfo, sizeof (struct loinfo),
			    (uintptr_t)vfs.vfs_data);
			lwp->lw_tabsz += loinfo.li_htsize;
			vfsp = (uintptr_t)vfs.vfs_next;
		} while (vfsp != rootvfsp);

		if (lwp->lw_tabsz == 0) {
			/*
			 * No lofs filesystems mounted.
			 */
			mdb_free(lwp, sizeof (lnode_walk_t));
			return (WALK_DONE);
		}
		lwp->lw_table = mdb_alloc(lwp->lw_tabsz *
		    sizeof (struct lobucket), UM_SLEEP);
		htsize = 0;

		vfsp = rootvfsp;
		do {
			(void) mdb_vread(&vfs, sizeof (vfs), vfsp);
			if (lofsfstype != vfs.vfs_fstype) {
				vfsp = (uintptr_t)vfs.vfs_next;
				continue;
			}
			(void) mdb_vread(&loinfo, sizeof (struct loinfo),
			    (uintptr_t)vfs.vfs_data);
			if (htsize + loinfo.li_htsize > lwp->lw_tabsz) {
				/*
				 * Something must have resized.
				 */
				mdb_free(lwp->lw_table,
				    lwp->lw_tabsz * sizeof (struct lobucket));
				goto retry;
			}
			(void) mdb_vread(lwp->lw_table + htsize,
			    loinfo.li_htsize * sizeof (struct lobucket),
			    (uintptr_t)loinfo.li_hashtable);
			htsize += loinfo.li_htsize;
			vfsp = (uintptr_t)vfs.vfs_next;
		} while (vfsp != rootvfsp);
	} else {
		if (mdb_vread(&vfs, sizeof (vfs_t), wsp->walk_addr) == -1) {
			mdb_warn("failed to read from '%p'\n", wsp->walk_addr);
			return (WALK_ERR);
		}
		if (lofsfstype != vfs.vfs_fstype) {
			mdb_warn("%p does not point to a lofs mount vfs\n",
			    wsp->walk_addr);
			return (WALK_ERR);
		}
		if (mdb_vread(&loinfo, sizeof (loinfo),
		    (uintptr_t)vfs.vfs_data) == -1) {
			mdb_warn("failed to read struct loinfo from '%p'\n",
			    vfs.vfs_data);
			return (WALK_ERR);
		}

		lwp = mdb_alloc(sizeof (lnode_walk_t), UM_SLEEP);
		lwp->lw_tabsz = loinfo.li_htsize;
		lwp->lw_table = mdb_alloc(lwp->lw_tabsz *
		    sizeof (struct lobucket), UM_SLEEP);
		(void) mdb_vread(lwp->lw_table,
		    lwp->lw_tabsz * sizeof (struct lobucket),
		    (uintptr_t)loinfo.li_hashtable);
	}
	lwp->lw_tabi = 0;
	lwp->lw_lnode = mdb_alloc(sizeof (lnode_t), UM_SLEEP);

	wsp->walk_addr = (uintptr_t)lwp->lw_table[0].lh_chain;
	wsp->walk_data = lwp;

	return (WALK_NEXT);
}

int
lnode_walk_step(mdb_walk_state_t *wsp)
{
	lnode_walk_t *lwp = wsp->walk_data;
	uintptr_t addr;

	/*
	 * If the next lnode_t address we want is NULL, advance to the next
	 * hash bucket.  When we reach lw_tabsz, we're done.
	 */
	while (wsp->walk_addr == 0) {
		if (++lwp->lw_tabi < lwp->lw_tabsz)
			wsp->walk_addr =
			    (uintptr_t)lwp->lw_table[lwp->lw_tabi].lh_chain;
		else
			return (WALK_DONE);
	}

	/*
	 * When we have an lnode_t address, read the lnode and invoke the
	 * walk callback.  Keep the next lnode_t address in wsp->walk_addr.
	 */
	addr = wsp->walk_addr;
	(void) mdb_vread(lwp->lw_lnode, sizeof (lnode_t), addr);
	wsp->walk_addr = (uintptr_t)lwp->lw_lnode->lo_next;

	return (wsp->walk_callback(addr, lwp->lw_lnode, wsp->walk_cbdata));
}

void
lnode_walk_fini(mdb_walk_state_t *wsp)
{
	lnode_walk_t *lwp = wsp->walk_data;

	mdb_free(lwp->lw_table, lwp->lw_tabsz * sizeof (struct lobucket));
	mdb_free(lwp->lw_lnode, sizeof (lnode_t));
	mdb_free(lwp, sizeof (lnode_walk_t));
}

/*ARGSUSED*/
static int
lnode_format(uintptr_t addr, const void *data, void *private)
{
	const lnode_t *lop = data;

	mdb_printf("%?p %?p %?p\n",
	    addr, lop->lo_vnode, lop->lo_vp);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
lnode(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %?s %?s%</u>\n",
		    "LNODE", "VNODE", "REALVP");
	}

	if (flags & DCMD_ADDRSPEC) {
		lnode_t lo;

		(void) mdb_vread(&lo, sizeof (lo), addr);
		return (lnode_format(addr, &lo, NULL));
	}

	if (mdb_walk("lnode", lnode_format, NULL) == -1)
		return (DCMD_ERR);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
lnode2dev(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	lnode_t lo;
	vnode_t	vno;
	vfs_t vfs;

	if (argc != 0)
		return (DCMD_ERR);

	(void) mdb_vread(&lo, sizeof (lo), addr);
	(void) mdb_vread(&vno, sizeof (vno), (uintptr_t)lo.lo_vnode);
	(void) mdb_vread(&vfs, sizeof (vfs), (uintptr_t)vno.v_vfsp);

	mdb_printf("lnode %p vfs_dev %0?lx\n", addr, vfs.vfs_dev);
	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "lnode", NULL, "print lnode structure(s)", lnode },
	{ "lnode2dev", ":", "print vfs_dev given lnode", lnode2dev },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "lnode", "hash of lnode structures",
		lnode_walk_init, lnode_walk_step, lnode_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
