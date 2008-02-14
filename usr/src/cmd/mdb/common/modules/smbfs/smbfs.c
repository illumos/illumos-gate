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


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mdb_modapi.h>
#include <sys/types.h>
#include <sys/refstr_impl.h>
#include <sys/vnode.h>
#include <sys/vfs.h>

#include "smbfs.h"
#include "smbfs_node.h"

#define	OPT_VERBOSE	0x0001	/* Be [-v]erbose in dcmd's */

/*
 * This macro lets us easily use both sizeof (typename)
 * and the string-ified typename for the error message.
 */
#define	SMBFS_OBJ_FETCH(obj_addr, obj_type, dest, err) \
	if (mdb_vread(dest, sizeof (obj_type), ((uintptr_t)obj_addr)) \
	!= sizeof (obj_type)) { \
		mdb_warn("error reading "#obj_type" at %p", obj_addr); \
		return (err); \
	}

/*
 * We need to read in a private copy
 * of every string we want to print out.
 */
void
print_str(uintptr_t addr)
{
	char buf[64];
	int len, mx = sizeof (buf) - 4;

	if ((len = mdb_readstr(buf, sizeof (buf), addr)) <= 0) {
		mdb_printf(" (%p)", addr);
	} else {
		if (len > mx)
			strcpy(&buf[mx], "...");
		mdb_printf(" %s", buf);
	}
}

/*
 * Dcmd (and callback function) to print a summary of
 * all "smbfs" entries in the VFS list.
 */

typedef struct smbfs_vfs_cbdata {
	int flags;
	int printed_header;
	uintptr_t vfsops;	/* filter by vfs ops pointer */
	smbmntinfo_t smi;	/* scratch space for smbfs_vfs_cb */
} smbfs_vfs_cbdata_t;

int
smbfs_vfs_cb(uintptr_t addr, const void *data, void *arg)
{
	const vfs_t *vfs = data;
	smbfs_vfs_cbdata_t *cbd = arg;
	uintptr_t ta;

	/* Filter by matching smbfs ops vector. */
	if (cbd->vfsops && cbd->vfsops != (uintptr_t)vfs->vfs_op) {
		return (WALK_NEXT);
	}

	if (cbd->printed_header == 0) {
		cbd->printed_header = 1;
		mdb_printf("// vfs_t smbmntinfo_t mnt_path\n");
	}

	mdb_printf(" %-p", addr);	/* vfs_t */
	mdb_printf(" %-p", (uintptr_t)vfs->vfs_data);
	/*
	 * Note: vfs_mntpt is a refstr_t.
	 * Advance to string member.
	 */
	ta = (uintptr_t)vfs->vfs_mntpt;
	ta += OFFSETOF(struct refstr, rs_string);
	print_str(ta);
	mdb_printf("\n");

	if (cbd->flags & OPT_VERBOSE) {
		mdb_inc_indent(2);
		/* Don't fail the walk if this fails. */
		if (mdb_vread(&cbd->smi, sizeof (cbd->smi),
		    (uintptr_t)vfs->vfs_data) == -1) {
			mdb_warn("error reading smbmntinfo_t at %p",
			    (uintptr_t)vfs->vfs_data);
		} else {
			/* Interesting parts of smbmntinfo_t */
			mdb_printf("smi_share: %p, smi_root: %p\n",
			    cbd->smi.smi_share, cbd->smi.smi_root);
		}
		mdb_dec_indent(2);
	}

	return (WALK_NEXT);
}

int
smbfs_vfs_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smbfs_vfs_cbdata_t *cbd;
	vfs_t *vfs;

	cbd = mdb_zalloc(sizeof (*cbd),  UM_SLEEP | UM_GC);

	/*
	 * Get the ops address here, so things work
	 * even if the smbfs module is loaded later
	 * than this mdb module.
	 */
	if (mdb_readvar(&cbd->vfsops, "smbfs_vfsops") == -1) {
		mdb_warn("failed to find 'smbfs_vfsops'\n");
		return (DCMD_ERR);
	}

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, OPT_VERBOSE, &cbd->flags,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk("genunix`vfs", smbfs_vfs_cb, cbd)
		    == -1) {
			mdb_warn("can't walk smbfs vfs");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	vfs = mdb_alloc(sizeof (*vfs),  UM_SLEEP | UM_GC);
	SMBFS_OBJ_FETCH(addr, vfs_t, vfs, DCMD_ERR);
	smbfs_vfs_cb(addr, vfs, cbd);
	return (DCMD_OK);
}

void
smbfs_vfs_help(void)
{
	mdb_printf(
	    "Display addresses of the mounted smbfs structures\n"
	    "and the pathname of the mountpoint\n"
	    "\nOptions:\n"
	    "  -v    display details of the smbmntinfo\n");
}

/*
 * Walker for the smbnode hash table.
 */

typedef struct smbnode_walk_data {
	rhashq_t *smbtab;	/* (our copy of) the smbtable */
	int tabsize;		/* size of table */
	int nextidx;		/* next bucket index */
	uintptr_t buckptr;	/* target addr of current bucket */
	uintptr_t nodeptr;	/* target addr of current smbnode */
	smbnode_t node; 	/* scratch space for _step */
} smbnode_walk_data_t;

int
smbnode_walk_init(mdb_walk_state_t *wsp)
{
	size_t tabsz_bytes;
	int tabsize;
	uintptr_t smbtab;
	smbnode_walk_data_t *smbw;

	if (wsp->walk_addr != NULL) {
		mdb_warn("smbnode only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_readvar(&tabsize, "smbtablesize") == -1) {
		mdb_warn("failed to read `smbtablesize'\n");
		return (WALK_ERR);
	}

	if (tabsize == 0) {
		return (WALK_DONE);
	}

	if (mdb_readvar(&smbtab, "smbtable") == -1) {
		mdb_warn("failed to read `smbtable'\n");
		return (WALK_ERR);
	}

	smbw = mdb_alloc(sizeof (*smbw), UM_SLEEP | UM_GC);

	tabsz_bytes = tabsize * sizeof (rhashq_t);
	smbw->smbtab  = mdb_alloc(tabsz_bytes, UM_SLEEP | UM_GC);
	if (mdb_vread(smbw->smbtab, tabsz_bytes, smbtab) != tabsz_bytes) {
		mdb_warn("failed to read in smbtable from %p", smbtab);
		return (WALK_ERR);
	}
	smbw->tabsize = tabsize;
	smbw->nextidx = 1;
	smbw->buckptr = smbtab;
	smbw->nodeptr = (uintptr_t)smbw->smbtab[0].r_hashf;
	wsp->walk_data = smbw;

	return (WALK_NEXT);
}

int
smbnode_walk_step(mdb_walk_state_t *wsp)
{
	smbnode_walk_data_t *smbw = wsp->walk_data;
	int status;

next_bucket:
	while (smbw->nodeptr == smbw->buckptr &&
	    smbw->nextidx < smbw->tabsize) {

		/* Skip an empty bucket */
		rhashq_t *h = &smbw->smbtab[smbw->nextidx];
		smbw->nodeptr = (uintptr_t)h->r_hashf;
		smbw->nextidx++;
		smbw->buckptr += sizeof (rhashq_t);
	}

	if (smbw->nodeptr == smbw->buckptr)
		return (WALK_DONE);

	if (mdb_vread(&smbw->node, sizeof (smbw->node),
	    smbw->nodeptr) != sizeof (smbw->node)) {
		mdb_warn("failed to read smbnode at %p in bucket %p\n",
		    smbw->nodeptr, smbw->buckptr);
		/* Proceed with next bucket. */
		smbw->nodeptr = smbw->buckptr;
		goto next_bucket;
	}

	status = wsp->walk_callback(smbw->nodeptr,
	    &smbw->node, wsp->walk_cbdata);

	/* Move to next node in this bucket */
	smbw->nodeptr = (uintptr_t)smbw->node.r_hashf;

	return (status);
}

/*ARGSUSED*/
void
smbnode_walk_fini(mdb_walk_state_t *wsp)
{
	/* UM_GC takes care of it all. */
}

/*
 * Dcmd (and callback function) to print a summary of
 * all smbnodes in the node hash table.
 */

typedef struct smbnode_cbdata {
	int flags;
	int printed_header;
	uintptr_t smi;		/* optional filtering by VFS */
				/* TODO: only nodes with a given [-h]ash */
	vnode_t vn;			/* scratch space for smbnode_cb */
} smbnode_cbdata_t;

int
smbnode_cb(uintptr_t addr, const void *data, void *arg)
{
	const smbnode_t *np = data;
	smbnode_cbdata_t *cbd = arg;

	/* Optional filtering by mount point. */
	if (cbd->smi && cbd->smi != (uintptr_t)np->n_mount) {
		return (WALK_NEXT);
	}

	if (cbd->printed_header == 0) {
		cbd->printed_header = 1;
		mdb_printf("// smbnode vnode rpath\n");
	}

	mdb_printf(" %-p", addr);	/* smbnode */
	mdb_printf(" %-p", (uintptr_t)np->r_vnode);
	print_str((uintptr_t)np->n_rpath);
	mdb_printf("\n");

	if (cbd->flags & OPT_VERBOSE) {
		mdb_inc_indent(2);
		/* Don't fail the walk if this fails. */
		if (mdb_vread(&cbd->vn, sizeof (cbd->vn),
		    (uintptr_t)np->r_vnode) == -1) {
			mdb_warn("error reading vnode_t at %p",
			    (uintptr_t)np->r_vnode);
		} else {
			/* Interesting parts of vnode_t */
			mdb_printf("v_type: %d v_path:",
			    cbd->vn.v_type);
			print_str((uintptr_t)cbd->vn.v_path);
			mdb_printf("\n");
		}
		mdb_dec_indent(2);
	}

	return (WALK_NEXT);
}

int
smbnode_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smbnode_cbdata_t *cbd;
	smbnode_t *np;

	cbd = mdb_zalloc(sizeof (*cbd), UM_SLEEP | UM_GC);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, OPT_VERBOSE, &cbd->flags,
	    'm', MDB_OPT_UINTPTR, &cbd->smi, NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk("smbnode", smbnode_cb, cbd)
		    == -1) {
			mdb_warn("cannot walk smbnodes");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	np = mdb_alloc(sizeof (*np), UM_SLEEP | UM_GC);
	SMBFS_OBJ_FETCH(addr, smbnode_t, np, DCMD_ERR);
	smbnode_cb(addr, np, cbd);

	return (DCMD_OK);
}

void
smbnode_help(void)
{
	mdb_printf("Options:\n"
	    "  -m mntinfo   only show smbnodes belonging to mntinfo\n"
	    "  -v           be verbose when displaying smbnodes\n");
}

static const mdb_dcmd_t dcmds[] = {
	{ "smbfs_vfs", "?[-v]",
		"show smbfs-mounted vfs structs",
		smbfs_vfs_dcmd, smbfs_vfs_help },
	{ "smbnode", "?[-v] [-m mntinfo]",
		"show smbnodes", smbnode_dcmd, smbnode_help },
	{NULL}
};

static const mdb_walker_t walkers[] = {
	{ "smbnode", "walk smbnode hash table",
		smbnode_walk_init, smbnode_walk_step, smbnode_walk_fini },
	{NULL}
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION,
	dcmds,
	walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
