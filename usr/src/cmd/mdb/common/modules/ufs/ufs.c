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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_acl.h>
#include <sys/fs/ufs_fs.h>

#include "ufs_cmds.h"

typedef struct inode_walk_data {
	int iw_inohsz;
	int iw_inohcnt;
	uintptr_t iw_ihead;
	inode_t iw_inode;
} inode_walk_data_t;

static int
inode_walk_init(mdb_walk_state_t *wsp)
{
	int inohsz;
	uintptr_t ihead;
	union ihead ih;
	inode_walk_data_t *iw;

	if (wsp->walk_addr != 0) {
		mdb_warn("inode_cache only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_readvar(&inohsz, "inohsz") == -1) {
		mdb_warn("failed to read 'inohsz'");
		return (WALK_ERR);
	}

	if (inohsz == 0)
		return (WALK_DONE);

	if (mdb_readvar(&ihead, "ihead") == -1) {
		mdb_warn("failed to read 'ihead'");
		return (WALK_ERR);
	}

	if (mdb_vread(&ih, sizeof (union ihead), ihead) == -1) {
		mdb_warn("failed to read ihead at %p", ihead);
		return (WALK_DONE);
	}

	iw = mdb_alloc(sizeof (inode_walk_data_t), UM_SLEEP);
	iw->iw_inohsz = inohsz;
	iw->iw_inohcnt = 0;
	iw->iw_ihead = ihead;

	wsp->walk_addr = (uintptr_t)ih.ih_chain[0];
	wsp->walk_data = iw;

	return (WALK_NEXT);
}

static int
inode_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	inode_walk_data_t *iw = wsp->walk_data;
	union ihead ih;

	while (addr == iw->iw_ihead) {
		if (++iw->iw_inohcnt >= iw->iw_inohsz)
			return (WALK_DONE);

		iw->iw_ihead += sizeof (union ihead);

		if (mdb_vread(&ih, sizeof (union ihead), iw->iw_ihead) == -1) {
			mdb_warn("failed to read ihead at %p", iw->iw_ihead);
			return (WALK_DONE);
		}
		addr = (uintptr_t)ih.ih_chain[0];
	}

	if (mdb_vread(&iw->iw_inode, sizeof (inode_t), addr) == -1) {
		mdb_warn("failed to read inode at %p", addr);
		return (WALK_DONE);
	}

	wsp->walk_addr = (uintptr_t)iw->iw_inode.i_forw;

	return (wsp->walk_callback(addr, (void *)(uintptr_t)iw->iw_inohcnt,
	    wsp->walk_cbdata));
}

static void
inode_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (inode_walk_data_t));
}

typedef struct inode_cbdata {
	ino_t id_inumber;
	dev_t id_device;
	uintptr_t id_addr;
	uint_t id_flags;
} inode_cbdata_t;

static int
inode_cache_cb(uintptr_t addr, const int inohcnt, inode_cbdata_t *id)
{
	inode_t inode;
	int inohsz;

	if (mdb_vread(&inode, sizeof (inode), addr) == -1) {
		mdb_warn("failed to read inode_t at %p", addr);
		return (WALK_ERR);
	}

	if (id->id_device != 0 && inode.i_dev != id->id_device)
		return (WALK_NEXT);

	if (id->id_inumber != 0 && inode.i_number != id->id_inumber)
		return (WALK_NEXT);

	if (id->id_flags & DCMD_ADDRSPEC && addr != id->id_addr)
		return (WALK_NEXT);

	if (id->id_flags & DCMD_PIPE_OUT) {
		mdb_printf("%p\n", addr);
		return (WALK_NEXT);
	}

	mdb_printf("%0?p %10lld %15lx",
	    addr, (u_longlong_t)inode.i_number, inode.i_dev);

	/*
	 * INOHASH needs inohsz.
	 */
	if (mdb_readvar(&inohsz, "inohsz") == -1) {
		mdb_warn("failed to read 'inohsz'");
		return (WALK_ERR);
	}

	/*
	 * Is the inode in the hash chain it should be?
	 */
	if (inohcnt == INOHASH(inode.i_number)) {
		mdb_printf(" %5d\n", inohcnt);
	} else {
		mdb_printf(" %<b>%5d/%5d ??</b>\n",
		    inohcnt, INOHASH(inode.i_number));
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
inode_cache(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	inode_cbdata_t id;

	id.id_inumber = 0;
	id.id_device = 0;
	id.id_addr = addr;
	id.id_flags = flags;

	if (mdb_getopts(argc, argv,
	    'i', MDB_OPT_UINT64, &id.id_inumber,
	    'd', MDB_OPT_UINTPTR, &id.id_device, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags) && (flags & DCMD_PIPE_OUT) == 0) {
		mdb_printf("%<u>%-?s %10s %15s %5s%</u>\n",
		    "ADDR", "INUMBER", "DEVICE", "CHAIN");
	}

	if (mdb_walk("inode_cache", (mdb_walk_cb_t)(uintptr_t)inode_cache_cb,
	    &id) == -1) {
		mdb_warn("can't walk inode cache");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
inode(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = FALSE;
	inode_t inode;
	char buf[64];
	char path[MAXPATHLEN];

	static const mdb_bitmask_t i_flag_masks[] = {
		{ "UPD",		IUPD,		IUPD		},
		{ "ACC",		IACC,		IACC		},
		{ "MOD",		IMOD,		IMOD		},
		{ "CHG",		ICHG,		ICHG		},
		{ "NOACC",		INOACC,		INOACC		},
		{ "MODTIME",		IMODTIME,	IMODTIME	},
		{ "REF",		IREF,		IREF		},
		{ "SYNC",		ISYNC,		ISYNC		},
		{ "FASTSYMLNK",		IFASTSYMLNK,	IFASTSYMLNK	},
		{ "MODACC",		IMODACC,	IMODACC		},
		{ "ATTCHG",		IATTCHG,	IATTCHG		},
		{ "BDWRITE",		IBDWRITE,	IBDWRITE	},
		{ "STALE",		ISTALE,		ISTALE		},
		{ "DEL",		IDEL,		IDEL		},
		{ "DIRECTIO",		IDIRECTIO,	IDIRECTIO	},
		{ "JUNKIQ",		IJUNKIQ,	IJUNKIQ		},
		{ NULL,			0,		0		}
	};

	static const mdb_bitmask_t i_modetype_masks[] = {
		{ "p",	IFMT,	IFIFO		},
		{ "c",	IFMT,	IFCHR		},
		{ "d",	IFMT,	IFDIR		},
		{ "b",	IFMT,	IFBLK		},
		{ "-",	IFMT,	IFREG		},
		{ "l",	IFMT,	IFLNK		},
		{ "S",	IFMT,	IFSHAD		},
		{ "s",	IFMT,	IFSOCK		},
		{ "A",	IFMT,	IFATTRDIR	},
		{ NULL,	0,	0		}
	};

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags) && (flags & DCMD_PIPE_OUT) == 0) {
		mdb_printf("%<u>%-?s %10s %1s %5s %8s",
		    "ADDR", "INUMBER", "T", "MODE", "SIZE");

		if (verbose)
			mdb_printf(" %11s %-22s%</u>\n", "DEVICE", "FLAG");
		else
			mdb_printf(" %-12s %-21s%</u>\n", "MTIME", "NAME");
	}

	if (mdb_vread(&inode, sizeof (inode), addr) == -1) {
		mdb_warn("failed to read inode_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0?p %10lld %b %5#o %8llx",
	    addr, (u_longlong_t)inode.i_number, inode.i_mode, i_modetype_masks,
	    inode.i_mode & ~IFMT, inode.i_size);

	if (verbose) {

		mdb_printf(" %11lx <%b>\n",
		    inode.i_dev, inode.i_flag, i_flag_masks);

		mdb_inc_indent(2);

		mdb_printf("%Y\n", inode.i_mtime.tv_sec);

		if (mdb_vnode2path((uintptr_t)inode.i_vnode, path,
		    sizeof (path)) == 0 && *path != '\0')
			mdb_printf("%s\n", path);
		else
			mdb_printf("??\n");

		mdb_dec_indent(2);

		return (DCMD_OK);
	}

	/*
	 * Not verbose, everything must fit into one line.
	 */
	mdb_snprintf(buf, sizeof (buf), "%Y", inode.i_mtime.tv_sec);
	buf[17] = '\0'; /* drop seconds */
	if (buf[0] == '1' || buf[0] == '2')
		mdb_printf(" %12s", buf + 5); /* drop year */
	else
		mdb_printf(" %-12s", "?");

	if (mdb_vnode2path((uintptr_t)inode.i_vnode, path,
	    sizeof (path)) == 0 && *path != '\0') {
		if (strlen(path) <= 21)
			mdb_printf(" %-21s\n", path);
		else
			mdb_printf(" ...%-18s\n", path + strlen(path) - 18);
	} else {
		mdb_printf(" ??\n");
	}

	return (DCMD_OK);
}

static struct {
	int am_offset;
	char *am_tag;
} acl_map[] = {
	{ offsetof(si_t, aowner), "USER_OBJ" },
	{ offsetof(si_t, agroup), "GROUP_OBJ" },
	{ offsetof(si_t, aother), "OTHER_OBJ" },
	{ offsetof(si_t, ausers), "USER" },
	{ offsetof(si_t, agroups), "GROUP" },
	{ offsetof(si_t, downer), "DEF_USER_OBJ" },
	{ offsetof(si_t, dgroup), "DEF_GROUP_OBJ" },
	{ offsetof(si_t, dother), "DEF_OTHER_OBJ" },
	{ offsetof(si_t, dusers), "DEF_USER" },
	{ offsetof(si_t, dgroups), "DEF_GROUP" },
	{ -1, NULL }
};

static int
acl_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	inode_t inode;
	si_t *si;
	ufs_ic_acl_t **aclpp;

	if (addr == 0) {
		mdb_warn("acl walk needs an inode address\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&inode, sizeof (inode), addr) == -1) {
		mdb_warn("failed to read inode_t at %p", addr);
		return (WALK_ERR);
	}

	if (inode.i_ufs_acl == NULL)
		return (WALK_DONE);

	si = mdb_alloc(sizeof (si_t), UM_SLEEP);

	if (mdb_vread(si, sizeof (si_t), (uintptr_t)inode.i_ufs_acl) == -1) {
		mdb_warn("failed to read si_t at %p", inode.i_ufs_acl);
		mdb_free(si, sizeof (si_t));
		return (WALK_ERR);
	}

	/* LINTED - alignment */
	aclpp = (ufs_ic_acl_t **)((caddr_t)si + acl_map[0].am_offset);

	wsp->walk_addr = (uintptr_t)*aclpp;
	wsp->walk_data = si;
	wsp->walk_arg = 0;

	return (WALK_NEXT);
}

static int
acl_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	si_t *si = wsp->walk_data;
	uint_t i = (uintptr_t)wsp->walk_arg;
	ufs_ic_acl_t **aclpp;
	ufs_ic_acl_t acl;

	while (addr == 0) {
		wsp->walk_arg = (void *)(uintptr_t)++i;

		if (acl_map[i].am_offset == -1)
			return (WALK_DONE);

		/* LINTED - alignment */
		aclpp = (ufs_ic_acl_t **)((caddr_t)si + acl_map[i].am_offset);

		addr = (uintptr_t)*aclpp;
	}

	if (mdb_vread(&acl, sizeof (acl), addr) == -1) {
		mdb_warn("failed to read acl at %p", addr);
		return (WALK_DONE);
	}

	wsp->walk_addr = (uintptr_t)acl.acl_ic_next;

	return (wsp->walk_callback(addr, &acl, acl_map[i].am_tag));
}

static void
acl_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (si_t));
}

static int
acl_cb(uintptr_t addr, const void *arg, void *data)
{
	ufs_ic_acl_t *aclp = (ufs_ic_acl_t *)arg;

	mdb_printf("%?p %-16s %7#o %10d\n",
	    addr, (char *)data, aclp->acl_ic_perm, aclp->acl_ic_who);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
acl_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (argc != 0)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %-16s %7s %10s%</u>\n",
		    "ADDR", "TAG", "PERM", "WHO");
	}

	if (mdb_pwalk("acl", (mdb_walk_cb_t)acl_cb, NULL, addr) == -1) {
		mdb_warn("can't walk acls of inode %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}


static int
cg_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("buf", wsp) == -1) {
		mdb_warn("couldn't walk bio buf hash");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
cg_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = (uintptr_t)((const buf_t *)wsp->walk_layer)->b_un.b_cg;
	struct cg cg;

	if (mdb_vread(&cg, sizeof (cg), addr) == -1) {
		mdb_warn("failed to read cg struct at %p", addr);
		return (WALK_ERR);
	}

	if (cg.cg_magic != CG_MAGIC)
		return (WALK_NEXT);

	return (wsp->walk_callback(addr, &cg, wsp->walk_cbdata));
}

static void
pbits(const uchar_t *cp, const int max, const int linelen)
{
	int i, j, len;
	char entry[40];
	int linecnt = -1;

	for (i = 0; i < max; i++) {
		if (isset(cp, i)) {
			len = mdb_snprintf(entry, sizeof (entry), "%d", i);
			j = i;
			while ((i + 1) < max && isset(cp, i+1))
				i++;
			if (i != j)
				len += mdb_snprintf(entry + len,
				    sizeof (entry) - len, "-%d", i);

			if (linecnt == -1) {
				/* first entry */
				mdb_printf("%s", entry);
				linecnt = linelen - len;
			} else if (linecnt - (len + 3) > 0) {
				/* subsequent entry on same line */
				mdb_printf(", %s", entry);
				linecnt -= len + 2;
			} else {
				/* subsequent enty on new line */
				mdb_printf(",\n%s", entry);
				linecnt = linelen - len;
			}
		}
	}
	mdb_printf("\n");
}

/*ARGSUSED*/
static int
cg(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = FALSE;
	struct cg cg;
	struct cg *cgp = &cg;
	size_t size;
	int i, j, cnt, off;
	int32_t *blktot;
	short *blks;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("cg", "cg", argc, argv) == -1) {
			mdb_warn("can't walk cylinder group structs");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(cgp, sizeof (cg), addr) == -1) {
		mdb_warn("failed to read cg struct at %p", addr);
		return (DCMD_ERR);
	}

	if (!verbose) {
		if (DCMD_HDRSPEC(flags))
			mdb_printf("%<u>%4s %?s %10s %10s %10s %10s%</u>\n",
			    "CGX", "CG", "NDIR", "NBFREE", "NIFREE", "NFFREE");

		mdb_printf("%4d %?p %10d %10d %10d %10d\n", cgp->cg_cgx,
		    addr, cgp->cg_cs.cs_ndir, cgp->cg_cs.cs_nbfree,
		    cgp->cg_cs.cs_nifree, cgp->cg_cs.cs_nffree);

		return (DCMD_OK);
	}

	/*
	 * Verbose: produce output similiar to "fstyp -v".
	 */
	if (cgp->cg_btotoff >= cgp->cg_nextfreeoff ||
	    cgp->cg_boff >= cgp->cg_nextfreeoff ||
	    cgp->cg_iusedoff >= cgp->cg_nextfreeoff ||
	    cgp->cg_freeoff >= cgp->cg_nextfreeoff) {
		mdb_warn("struct cg at %p seems broken\n", addr);
		return (DCMD_ERR);
	}

	size = cgp->cg_nextfreeoff;
	cgp = mdb_alloc(size, UM_SLEEP);

	if (mdb_vread(cgp, size, addr) == -1) {
		mdb_warn("failed to read struct cg and maps at %p", addr);
		mdb_free(cgp, size);
		return (DCMD_ERR);
	}

	mdb_printf("%<b>cg %d (%0?p)%</b>\n", cgp->cg_cgx, addr);

	mdb_inc_indent(4);

	mdb_printf("time:\t%Y\n", cgp->cg_time);
	mdb_printf("ndir:\t%d\n", cgp->cg_cs.cs_ndir);
	mdb_printf("nbfree:\t%d\n", cgp->cg_cs.cs_nbfree);
	mdb_printf("nifree:\t%d\n", cgp->cg_cs.cs_nifree);
	mdb_printf("nffree:\t%d\n", cgp->cg_cs.cs_nffree);

	mdb_printf("frsum:");
	for (i = 1; i < MAXFRAG; i++)
		mdb_printf("\t%d", cgp->cg_frsum[i]);
	mdb_printf("\n");

	off = cgp->cg_iusedoff;
	mdb_printf("used inode map (%0?p):\n", (char *)addr + off);
	mdb_inc_indent(4);
	pbits((uchar_t *)cgp + off, cgp->cg_niblk / sizeof (char), 72);
	mdb_dec_indent(4);

	off = cgp->cg_freeoff;
	mdb_printf("free block map (%0?p):\n", (char *)addr + off);
	mdb_inc_indent(4);
	pbits((uchar_t *)cgp + off, cgp->cg_ndblk / sizeof (char), 72);
	mdb_dec_indent(4);

	/* LINTED - alignment */
	blktot = (int32_t *)((char *)cgp + cgp->cg_btotoff);
	/* LINTED - alignment */
	blks = (short *)((char *)cgp + cgp->cg_boff);
	cnt = (cgp->cg_iusedoff - cgp->cg_boff) / cgp->cg_ncyl / sizeof (short);
	mdb_printf("free block positions:\n");
	mdb_inc_indent(4);

	for (i = 0; i < cgp->cg_ncyl; i++) {
		mdb_printf("c%d:\t(%d)\t", i, blktot[i]);
		for (j = 0; j < cnt; j++)
			mdb_printf(" %d", blks[i*cnt + j]);
		mdb_printf("\n");
	}
	mdb_dec_indent(4);

	mdb_printf("\n");
	mdb_dec_indent(4);

	mdb_free(cgp, size);

	return (DCMD_OK);
}

void
inode_cache_help(void)
{
	mdb_printf(
	    "Displays cached inode_t. If an address, an inode number and/or a\n"
	    "device is specified, searches inode cache for inodes which match\n"
	    "the specified criteria. Prints nothing but the address, if\n"
	    "output is a pipe.\n"
	    "\n"
	    "Options:\n"
	    "  -d device    Filter out inodes, which reside on the specified"
	    " device.\n"
	    "  -i inumber   Filter out inodes with the specified inode"
	    " number.\n");
}

/*
 * MDB module linkage
 */
static const mdb_dcmd_t dcmds[] = {
	{ "inode_cache", "?[-d device] [-i inumber]",
		"search/display inodes from inode cache",
		inode_cache, inode_cache_help },
	{ "inode", ":[-v]", "display summarized inode_t", inode },
	{ "acl", ":", "given an inode, display its in core acl's", acl_dcmd },
	{ "cg", "?[-v]", "display a summarized cylinder group structure", cg },
	{ "mapentry", ":", "dumps ufslog mapentry", mapentry_dcmd },
	{ "mapstats", ":", "dumps ufslog stats", mapstats_dcmd },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "inode_cache", "walk inode cache",
		inode_walk_init, inode_walk_step, inode_walk_fini },
	{ "acl", "given an inode, walk chains of in core acl's",
		acl_walk_init, acl_walk_step, acl_walk_fini },
	{ "cg", "walk cg's in bio buffer cache",
		cg_walk_init, cg_walk_step, NULL },
	{ "ufslogmap", "walk map entries in a ufs_log mt_map",
		ufslogmap_walk_init, ufslogmap_walk_step, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
