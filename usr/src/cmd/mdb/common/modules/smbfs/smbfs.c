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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/mdb_modapi.h>

#ifdef	_USER
#include "../genunix/avl.h"
#define	_FAKE_KERNEL
#endif

#include <sys/refstr_impl.h>
#include <sys/vnode.h>
#include <sys/vfs.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>

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
		if (mdb_walk("vfs", smbfs_vfs_cb, cbd)
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
 * Dcmd (and callback function) to print a summary of
 * all smbnodes in the node "hash" (cache) AVL tree.
 */

typedef struct smbfs_node_cbdata {
	int flags;
	int printed_header;
	vnode_t vn;
} smbfs_node_cbdata_t;

int
smbfs_node_cb(uintptr_t addr, const void *data, void *arg)
{
	const smbnode_t *np = data;
	smbfs_node_cbdata_t *cbd = arg;

	if (cbd->printed_header == 0) {
		cbd->printed_header = 1;
		mdb_printf("// vnode smbnode rpath\n");
	}

	mdb_printf(" %-p", (uintptr_t)np->r_vnode);
	mdb_printf(" %-p", addr);	/* smbnode */
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
			mdb_printf("v_type=%d v_count=%d",
			    cbd->vn.v_type, cbd->vn.v_count);
			mdb_printf("\n");
		}
		mdb_dec_indent(2);
	}

	return (WALK_NEXT);
}

int
smbfs_node_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smbfs_node_cbdata_t *cbd;

	cbd = mdb_zalloc(sizeof (*cbd), UM_SLEEP | UM_GC);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, OPT_VERBOSE, &cbd->flags,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("expect an smbmntinfo_t addr");
		return (DCMD_USAGE);
	}
	addr += OFFSETOF(smbmntinfo_t, smi_hash_avl);

	if (mdb_pwalk("avl", smbfs_node_cb, cbd, addr) == -1) {
		mdb_warn("cannot walk smbfs nodes");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

void
smbfs_node_help(void)
{
	mdb_printf("Options:\n"
	    "  -v           be verbose when displaying smbnodes\n");
}

static const mdb_dcmd_t dcmds[] = {
	{
		"smbfs_vfs", "?[-v]",
		"show smbfs-mounted vfs structs",
		smbfs_vfs_dcmd, smbfs_vfs_help
	},
	{
		"smbfs_node", "?[-v]",
		"given an smbmntinfo_t, list smbnodes",
		smbfs_node_dcmd, smbfs_node_help
	},
	{NULL}
};

#ifdef _USER
/*
 * Sadly, can't just compile ../genunix/vfs.c with this since
 * it has become a catch-all for FS-specific headers etc.
 */
int
vfs_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == (uintptr_t)NULL &&
	    mdb_readvar(&wsp->walk_addr, "rootvfs") == -1) {
		mdb_warn("failed to read 'rootvfs'");
		return (WALK_ERR);
	}

	wsp->walk_data = (void *)wsp->walk_addr;
	return (WALK_NEXT);
}

int
vfs_walk_step(mdb_walk_state_t *wsp)
{
	vfs_t vfs;
	int status;

	if (mdb_vread(&vfs, sizeof (vfs), wsp->walk_addr) == -1) {
		mdb_warn("failed to read vfs_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, &vfs, wsp->walk_cbdata);

	if (vfs.vfs_next == wsp->walk_data)
		return (WALK_DONE);

	wsp->walk_addr = (uintptr_t)vfs.vfs_next;

	return (status);
}
#endif	// _USER

static const mdb_walker_t walkers[] = {
#ifdef	_USER
	/* from avl.c */
	{ AVL_WALK_NAME, AVL_WALK_DESC,
		avl_walk_init, avl_walk_step, avl_walk_fini },
	/* from vfs.c */
	{ "vfs", "walk file system list",
		vfs_walk_init, vfs_walk_step },
#endif	// _USER
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
