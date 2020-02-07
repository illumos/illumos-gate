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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <ctype.h>
#include <sys/mdb_modapi.h>
#include <sys/mach_descrip.h>
#include <sys/mdesc.h>
#include <sys/mdesc_impl.h>

/*ARGSUSED*/
int
mdhdr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = 0;
	uintptr_t mdp;
	machine_descrip_t md;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, 1, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	/* curr_mach_descrip normally points to /dev/mdesc */
	if (mdb_readvar(&mdp, "curr_mach_descrip") == -1) {
		mdb_warn("failed to read 'curr_mach_descrip'");
		return (DCMD_ERR);
	}

	if (verbose)
		mdb_printf("ADDRESS     VA          MEMOPS      SIZE\n");

	do {
		if (mdb_vread(&md, sizeof (md), mdp) == -1) {
			mdb_warn("failed to read machine_descrip_t at %p", mdp);
			return (DCMD_ERR);
		}

		if (verbose)
			mdb_printf("%-11lx %-11lx %-11lx %-11lx\n",
			    mdp, md.va, md.memops, md.size);
		else
			mdb_printf("%p\n", mdp);

	} while ((mdp = (uintptr_t)md.next) != (uintptr_t)NULL);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
mdinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	md_header_t mh;
	machine_descrip_t md;
	md_element_t *mdep;
	char *namep;
	uint8_t *datap;
	int mdesize, namesize, datasize;
	uintptr_t mdp;
	md_element_t *mdeptr, *eof;
	uintptr_t vaddr;

	if (flags & DCMD_ADDRSPEC) {
		if ((addr & 7) != 0) {
			mdb_warn("misaligned address at %p", addr);
			return (DCMD_ERR);
		}
		vaddr = addr;
	} else {
		/* curr_mach_descrip normally points to /dev/mdesc */
		if (mdb_readvar(&mdp, "curr_mach_descrip") == -1) {
			mdb_warn("failed to read 'curr_mach_descrip'");
			return (DCMD_ERR);
		}
		if (mdb_vread(&md, sizeof (md), mdp) == -1) {
			mdb_warn("failed to read machine_descrip_t at %p", mdp);
			return (DCMD_ERR);
		}
		vaddr = (uintptr_t)md.va;
	}

	if (mdb_vread(&mh, sizeof (mh), vaddr) == -1) {
		mdb_warn("failed to read md_header_t at %p", vaddr);
		return (DCMD_ERR);
	}

	mdesize = mh.node_blk_sz;
	namesize = mh.name_blk_sz;
	datasize = mh.data_blk_sz;

	/* find space for each section of the MD */
	if ((mdep = mdb_alloc(mdesize, UM_NOSLEEP)) == NULL) {
		mdb_warn("failed to allocate memory for mde block");
		return (DCMD_ERR);
	}
	if ((namep = mdb_alloc(namesize, UM_NOSLEEP)) == NULL) {
		mdb_warn("failed to allocate memory for name block");
		mdb_free(mdep, mdesize);
		return (DCMD_ERR);
	}
	if ((datap = mdb_alloc(datasize, UM_NOSLEEP)) == NULL) {
		mdb_warn("failed to allocate memory for data block");
		mdb_free(namep, namesize);
		mdb_free(mdep, mdesize);
		return (DCMD_ERR);
	}

	/* store each of the MD sections */
	if (mdb_vread(mdep, mdesize, vaddr + MD_HEADER_SIZE) != mdesize) {
		mdb_warn("failed to read node block %p", vaddr
		    + MD_HEADER_SIZE);
		mdb_free(datap, datasize);
		mdb_free(namep, namesize);
		mdb_free(mdep, mdesize);
		return (DCMD_ERR);
	}
	if (mdb_vread(namep, namesize, vaddr + MD_HEADER_SIZE + mdesize)
	    != namesize) {
		mdb_warn("failed to read node block %p", vaddr + MD_HEADER_SIZE
		    + mdesize);
		mdb_free(datap, datasize);
		mdb_free(namep, namesize);
		mdb_free(mdep, mdesize);
		return (DCMD_ERR);
	}
	if (mdb_vread(datap, datasize, vaddr + MD_HEADER_SIZE + mdesize
	    + namesize) != datasize) {
		mdb_warn("failed to read node block %p", vaddr + MD_HEADER_SIZE
		    + mdesize + namesize);
		mdb_free(datap, datasize);
		mdb_free(namep, namesize);
		mdb_free(mdep, mdesize);
		return (DCMD_ERR);
	}

	mdb_printf("TYPE OFFSET NAME                   PROPERTY\n");
	eof = mdep + (mdesize / sizeof (md_element_t));
	for (mdeptr = mdep; mdeptr < eof; ++mdeptr) {
		switch (MDE_TAG(mdeptr)) {
		case MDET_NODE:
			mdb_printf("node %-6x %-22s idx=%-11lx\n",
			    MDE_NAME(mdeptr), namep + mdeptr->name_offset,
			    MDE_PROP_INDEX(mdeptr));
			break;
		case MDET_PROP_ARC:
			mdb_printf("arc  %-6x %-22s idx=%-11lx\n",
			    MDE_NAME(mdeptr), namep + mdeptr->name_offset,
			    MDE_PROP_INDEX(mdeptr));
			break;
		case MDET_PROP_DAT:
			mdb_printf("data %-6x %-22s len=%x, offset=%x\n",
			    MDE_NAME(mdeptr), namep + mdeptr->name_offset,
			    MDE_PROP_DATA_LEN(mdeptr),
			    MDE_PROP_DATA_OFFSET(mdeptr));
			break;
		case MDET_PROP_STR:
			mdb_printf("str  %-6x %-22s len=%x, offset=%x\n",
			    MDE_NAME(mdeptr), namep + mdeptr->name_offset,
			    MDE_PROP_DATA_LEN(mdeptr),
			    MDE_PROP_DATA_OFFSET(mdeptr));
			break;
		case MDET_PROP_VAL:
			mdb_printf("val  %-6x %-22s val=%-11lx\n",
			    MDE_NAME(mdeptr), namep + mdeptr->name_offset,
			    MDE_PROP_VALUE(mdeptr));
			break;
		case MDET_NODE_END:
			mdb_printf("end\n");
			break;
		case MDET_NULL:
			mdb_printf("null\n");
			break;
		case MDET_LIST_END:
			mdb_printf("end of list\n");
			break;
		default:
			mdb_printf("unkown tag=%x\n", MDE_TAG(mdeptr));
			break;
		}
	}

	mdb_free(datap, datasize);
	mdb_free(namep, namesize);
	mdb_free(mdep, mdesize);
	return (DCMD_OK);
}

/*ARGSUSED*/
int
mdformat(uintptr_t addr, int size, int indent)
{
	mdb_inc_indent(indent);
	if (mdb_dumpptr((uintptr_t)addr, size,
	    MDB_DUMP_RELATIVE | MDB_DUMP_TRIM | MDB_DUMP_ASCII |
	    MDB_DUMP_HEADER | MDB_DUMP_GROUP(4), NULL, NULL)) {
		mdb_dec_indent(indent);
		return (DCMD_ERR);
	}
	mdb_dec_indent(indent);
	return (DCMD_OK);
}

/*ARGSUSED*/
int
mddump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t mdp, mdep, namep, datap;
	machine_descrip_t md;
	md_header_t mh;
	uintptr_t vaddr;

	if (flags & DCMD_ADDRSPEC) {
		if ((addr & 7) != 0) {
			mdb_warn("misaligned address at %p", addr);
			return (DCMD_ERR);
		}
		vaddr = addr;
	} else {
		/* curr_mach_descrip normally points to /dev/mdesc */
		if (mdb_readvar(&mdp, "curr_mach_descrip") == -1) {
			mdb_warn("failed to read 'curr_mach_descrip'");
			return (DCMD_ERR);
		}
		if (mdb_vread(&md, sizeof (md), mdp) == -1) {
			mdb_warn("failed to read machine_descrip_t at %p", mdp);
			return (DCMD_ERR);
		}
		vaddr = (uintptr_t)md.va;
	}

	if (mdb_vread(&mh, sizeof (mh), (uintptr_t)vaddr) == -1) {
		mdb_warn("failed to read md_header_t at %p", vaddr);
		return (DCMD_ERR);
	}

	mdep = (uintptr_t)vaddr + MD_HEADER_SIZE;
	namep = mdep + mh.node_blk_sz;
	datap = namep + mh.name_blk_sz;

	mdb_printf("header (md_header_t) section at %lx:\n", vaddr);
	if (mdformat((uintptr_t)md.va, MD_HEADER_SIZE, 4) != DCMD_OK)
		return (DCMD_ERR);

	mdb_printf("\nnode (md_element_t) section at %lx:\n", mdep);
	if (mdformat(mdep, mh.node_blk_sz, 2) != DCMD_OK)
		return (DCMD_ERR);

	mdb_printf("\nname section at %lx:\n", namep);
	if (mdformat(namep, mh.name_blk_sz, 2) != DCMD_OK)
		return (DCMD_ERR);

	mdb_printf("\ndata section at %lx:\n", datap);
	if (mdformat(datap, mh.data_blk_sz, 2) != DCMD_OK)
		return (DCMD_ERR);

	return (DCMD_OK);
}

/*
 * MDB module linkage information:
 *
 * Declare a list of structures describing dcmds, and a function
 * named _mdb_init to return a pointer to module information.
 */

static const mdb_dcmd_t dcmds[] = {
	{ "mdeschdr", "[-v]", "addr of current sun4v MD header", mdhdr },
	{ "mdescinfo", "?", "print md_elements with names from sun4v MD",
	    mdinfo },
	{ "mdescdump", "?", "dump node, name, data sections of sun4v MD",
	    mddump },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, NULL
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
