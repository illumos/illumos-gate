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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_modapi.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/fs/snode.h>

typedef struct snode_walk_data {
	int sw_stablesz;
	uintptr_t sw_stable;
} snode_walk_data_t;

int
snode_walk_init(mdb_walk_state_t *wsp)
{
	int stablesz;
	GElf_Sym sym;
	uintptr_t stable;
	uintptr_t sp;
	snode_walk_data_t *sw;

	if (mdb_readvar(&stablesz, "stablesz") == -1) {
		mdb_warn("failed to read 'stablesz'");
		return (WALK_ERR);
	}

	if (stablesz == 0)
		return (WALK_DONE);

	if (mdb_lookup_by_name("stable", &sym) == -1) {
		mdb_warn("failed to read 'stable'");
		return (WALK_ERR);
	}

	stable = (uintptr_t)sym.st_value;

	if (mdb_vread(&sp, sizeof (sp), stable) == -1) {
		mdb_warn("failed to read stable entry at %p", stable);
		return (WALK_DONE);
	}

	sw = mdb_alloc(sizeof (snode_walk_data_t), UM_SLEEP);
	sw->sw_stablesz = stablesz;
	sw->sw_stable = stable;

	wsp->walk_addr = sp;
	wsp->walk_data = sw;

	return (WALK_NEXT);
}

int
snode_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	snode_walk_data_t *sw = wsp->walk_data;
	struct snode *sp;
	struct snode snode;

	while (addr == 0) {
		if (--sw->sw_stablesz == 0)
			return (WALK_DONE);

		sw->sw_stable += sizeof (struct snode *);

		if (mdb_vread(&sp, sizeof (sp), sw->sw_stable) == -1) {
			mdb_warn("failed to read stable entry at %p",
			    sw->sw_stable);
			return (WALK_DONE);
		}
		addr = (uintptr_t)sp;
	}

	if (mdb_vread(&snode, sizeof (snode), addr) == -1) {
		mdb_warn("failed to read snode at %p", addr);
		return (WALK_DONE);
	}

	wsp->walk_addr = (uintptr_t)snode.s_next;

	return (wsp->walk_callback(addr, &snode, wsp->walk_cbdata));
}

void
snode_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (snode_walk_data_t));
}

typedef struct snode_cbdata {
	int sd_major;
	int sd_minor;
	int sd_verbose;
} snode_cbdata_t;

static int
snode_cb(uintptr_t addr, const struct snode *snode, snode_cbdata_t *sd)
{
	static const mdb_bitmask_t s_flag_masks[] = {
		{ "UPD",	SUPD,		SUPD		},
		{ "ACC",	SACC,		SACC		},
		{ "CHG",	SCHG,		SCHG		},
		{ "PRIV",	SPRIV,		SPRIV		},
		{ "LOFFSET",	SLOFFSET,	SLOFFSET	},
		{ "LOCKED",	SLOCKED,	SLOCKED		},
		{ "WANT",	SWANT,		SWANT		},
		{ "CLONE",	SCLONE,		SCLONE		},
		{ "NEEDCLOSE",	SNEEDCLOSE,	SNEEDCLOSE	},
		{ "DIPSET",	SDIPSET,	SDIPSET		},
		{ "SIZEVALID",	SSIZEVALID,	SSIZEVALID	},
		{ "MUXED",	SMUXED,		SMUXED		},
		{ "SELFCLONE",	SSELFCLONE,	SSELFCLONE	},
		{ "NOFLUSH",	SNOFLUSH,	SNOFLUSH	},
		{ "CLOSING",	SCLOSING,	SCLOSING	},
		{ NULL,		0,		0		}
	};

	int major = getmajor(snode->s_dev);
	int minor = getminor(snode->s_dev);

	if (sd->sd_major != -1 && sd->sd_major != major)
		return (WALK_NEXT);

	if (sd->sd_minor != -1 && sd->sd_minor != minor)
		return (WALK_NEXT);

	if (sd->sd_verbose) {
		mdb_printf("%0?p %?p %6d %16lx <%b>\n",
		    addr, snode->s_vnode, snode->s_count, snode->s_dev,
		    snode->s_flag, s_flag_masks);
	} else {
		mdb_printf("%p\n", addr);
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
snode(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	snode_cbdata_t sd;
	struct snode snode;
	uintptr_t major = 0, dev = 0;

	sd.sd_major = -1;
	sd.sd_minor = -1;
	sd.sd_verbose = !(flags & DCMD_PIPE_OUT);

	if (mdb_getopts(argc, argv,
	    'm', MDB_OPT_UINTPTR, &major,
	    'd', MDB_OPT_UINTPTR, &dev, NULL) != argc)
		return (DCMD_USAGE);

	if (dev != 0) {
		sd.sd_major = getmajor(dev);
		sd.sd_minor = getminor(dev);
	}

	if (major != 0)
		sd.sd_major = major;

	if (DCMD_HDRSPEC(flags) && !(flags & DCMD_PIPE_OUT)) {
		mdb_printf("%<u>%?s %?s %6s %16s %-15s%</u>\n",
		    "ADDR", "VNODE", "COUNT", "DEV", "FLAG");
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk("snode", (mdb_walk_cb_t)snode_cb, &sd) == -1) {
			mdb_warn("can't walk snodes");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&snode, sizeof (snode), addr) == -1) {
		mdb_warn("failed to read snode structure at %p", addr);
		return (DCMD_ERR);
	}

	snode_cb(addr, &snode, &sd);

	return (DCMD_OK);
}

/*ARGSUSED3*/
int
major2snode(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	snode_cbdata_t sd;

	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	sd.sd_major = addr;
	sd.sd_minor = -1;
	sd.sd_verbose = 0;

	if (mdb_pwalk("snode", (mdb_walk_cb_t)snode_cb, &sd, 0) != 0)
		return (DCMD_ERR);

	return (DCMD_OK);
}

/*ARGSUSED3*/
int
dev2snode(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	snode_cbdata_t sd;

	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	sd.sd_major = getmajor(addr);
	sd.sd_minor = getminor(addr);
	sd.sd_verbose = 0;

	if (mdb_pwalk("snode", (mdb_walk_cb_t)snode_cb, &sd, 0) != 0)
		return (DCMD_ERR);

	return (DCMD_OK);
}

void
snode_help(void)
{
	mdb_printf("Options:\n"
	    "   -d device  filter snodes of the specified dev_t\n"
	    "   -m major   filter snodes of the specified major number\n");
}

/*
 * MDB module linkage
 */
static const mdb_dcmd_t dcmds[] = {
	{ "dev2snode", ":", "given a dev_t, return the snode", dev2snode },
	{ "major2snode", ":", "given a major number, return the snode(s)",
	    major2snode },
	{ "snode", "?[-d device] [-m major]",
		"filter and display snode structures", snode, snode_help },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "snode", "walk global snode lists",
		snode_walk_init, snode_walk_step, snode_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
