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

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddipropdefs.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/sunldi_impl.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include "ldi.h"

/*
 * ldi handle walker structure
 */
typedef struct lh_walk {
	struct ldi_handle	**hash;	/* current bucket pointer	*/
	struct ldi_handle	*lhp;	/* ldi handle pointer		*/
	size_t			index;	/* hash table index		*/
	struct ldi_handle	buf;	/* buffer used for handle reads */
} lh_walk_t;

/*
 * ldi identifier walker structure
 */
typedef struct li_walk {
	struct ldi_ident	**hash;	/* current bucket pointer	*/
	struct ldi_ident	*lip;	/* ldi handle pointer		*/
	size_t			index;	/* hash table index		*/
	struct ldi_ident	buf;	/* buffer used for ident reads */
} li_walk_t;

/*
 * Options for ldi_handles dcmd
 */
#define	LH_IDENTINFO	0x1

/*
 * LDI walkers
 */
int
ldi_handle_walk_init(mdb_walk_state_t *wsp)
{
	lh_walk_t	*lhwp;
	GElf_Sym	sym;

	/* get the address of the hash table */
	if (mdb_lookup_by_name("ldi_handle_hash", &sym) == -1) {
		mdb_warn("couldn't find ldi_handle_hash");
		return (WALK_ERR);
	}

	lhwp = mdb_alloc(sizeof (lh_walk_t), UM_SLEEP|UM_GC);
	lhwp->hash = (struct ldi_handle **)(uintptr_t)sym.st_value;
	lhwp->index = 0;

	/* get the address of the first element in the first hash bucket */
	if ((mdb_vread(&lhwp->lhp, sizeof (struct ldi_handle *),
	    (uintptr_t)lhwp->hash)) == -1) {
		mdb_warn("couldn't read ldi handle hash at %p", lhwp->hash);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)lhwp->lhp;
	wsp->walk_data = lhwp;

	return (WALK_NEXT);
}

int
ldi_handle_walk_step(mdb_walk_state_t *wsp)
{
	lh_walk_t	*lhwp = (lh_walk_t *)wsp->walk_data;
	int		status;

	/* check if we need to go to the next hash bucket */
	while (wsp->walk_addr == 0) {

		/* advance to the next bucket */
		if (++(lhwp->index) >= LH_HASH_SZ)
			return (WALK_DONE);

		/* get handle address from the hash bucket */
		if ((mdb_vread(&lhwp->lhp, sizeof (struct ldi_handle *),
		    (uintptr_t)(lhwp->hash + lhwp->index))) == -1) {
			mdb_warn("couldn't read ldi handle hash at %p",
			    (uintptr_t)lhwp->hash + lhwp->index);
			return (WALK_ERR);
		}

		wsp->walk_addr = (uintptr_t)lhwp->lhp;
	}

	/* invoke the walker callback for this hash element */
	status = wsp->walk_callback(wsp->walk_addr, NULL, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	/* get a pointer to the next hash element */
	if (mdb_vread(&lhwp->buf, sizeof (struct ldi_handle),
	    wsp->walk_addr) == -1) {
		mdb_warn("couldn't read ldi handle at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)lhwp->buf.lh_next;
	return (WALK_NEXT);
}

int
ldi_ident_walk_init(mdb_walk_state_t *wsp)
{
	li_walk_t	*liwp;
	GElf_Sym	sym;

	/* get the address of the hash table */
	if (mdb_lookup_by_name("ldi_ident_hash", &sym) == -1) {
		mdb_warn("couldn't find ldi_ident_hash");
		return (WALK_ERR);
	}

	liwp = mdb_alloc(sizeof (li_walk_t), UM_SLEEP|UM_GC);
	liwp->hash = (struct ldi_ident **)(uintptr_t)sym.st_value;
	liwp->index = 0;

	/* get the address of the first element in the first hash bucket */
	if ((mdb_vread(&liwp->lip, sizeof (struct ldi_ident *),
	    (uintptr_t)liwp->hash)) == -1) {
		mdb_warn("couldn't read ldi ident hash at %p", liwp->hash);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)liwp->lip;
	wsp->walk_data = liwp;

	return (WALK_NEXT);
}

int
ldi_ident_walk_step(mdb_walk_state_t *wsp)
{
	li_walk_t	*liwp = (li_walk_t *)wsp->walk_data;
	int		status;

	/* check if we need to go to the next hash bucket */
	while (wsp->walk_addr == 0) {

		/* advance to the next bucket */
		if (++(liwp->index) >= LI_HASH_SZ)
			return (WALK_DONE);

		/* get handle address from the hash bucket */
		if ((mdb_vread(&liwp->lip, sizeof (struct ldi_ident *),
		    (uintptr_t)(liwp->hash + liwp->index))) == -1) {
			mdb_warn("couldn't read ldi ident hash at %p",
			    (uintptr_t)liwp->hash + liwp->index);
			return (WALK_ERR);
		}

		wsp->walk_addr = (uintptr_t)liwp->lip;
	}

	/* invoke the walker callback for this hash element */
	status = wsp->walk_callback(wsp->walk_addr, NULL, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	/* get a pointer to the next hash element */
	if (mdb_vread(&liwp->buf, sizeof (struct ldi_ident),
	    wsp->walk_addr) == -1) {
		mdb_warn("couldn't read ldi ident at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)liwp->buf.li_next;
	return (WALK_NEXT);
}

/*
 * LDI dcmds
 */
static void
ldi_ident_header(int start, int refs)
{
	if (start) {
		mdb_printf("%-?s ", "IDENT");
	} else {
		mdb_printf("%?s ", "IDENT");
	}

	if (refs)
		mdb_printf("%4s ", "REFS");

	mdb_printf("%?s %5s %5s %s\n", "DIP", "MINOR", "MODID", "MODULE NAME");
}

static int
ldi_ident_print(uintptr_t addr, int refs)
{
	struct ldi_ident	li;

	/* read the ldi ident */
	if (mdb_vread(&li, sizeof (struct ldi_ident), addr) == -1) {
		mdb_warn("couldn't read ldi ident at %p", addr);
		return (1);
	}

	/* display the ident address */
	mdb_printf("%0?p ", addr);

	/* display the ref count */
	if (refs)
		mdb_printf("%4u ", li.li_ref);

	/* display the dip (if any) */
	if (li.li_dip != NULL) {
		mdb_printf("%0?p ", li.li_dip);
	} else {
		mdb_printf("%?s ", "-");
	}

	/* display the minor node (if any) */
	if (li.li_dev != DDI_DEV_T_NONE) {
		mdb_printf("%5u ", getminor(li.li_dev));
	} else {
		mdb_printf("%5s ", "-");
	}

	/* display the module info */
	mdb_printf("%5d %s\n", li.li_modid, li.li_modname);

	return (0);
}

int
ldi_ident(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int	start = 1;
	int	refs = 1;

	/* Determine if there is an ldi identifier address */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("ldi_ident", "ldi_ident",
		    argc, argv) == -1) {
			mdb_warn("can't walk ldi idents");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/* display the header line */
	if (DCMD_HDRSPEC(flags))
		ldi_ident_header(start, refs);

	/* display the ldi ident */
	if (ldi_ident_print(addr, refs))
		return (DCMD_ERR);

	return (DCMD_OK);
}

static void
ldi_handle_header(int refs, int ident)
{
	mdb_printf("%-?s ", "HANDLE");

	if (refs)
		mdb_printf("%4s ", "REFS");

	mdb_printf("%?s %10s %5s %?s ", "VNODE", "DRV", "MINOR", "EVENTS");

	if (!ident) {
		mdb_printf("%?s\n", "IDENT");
	} else {
		ldi_ident_header(0, 0);
	}
}

static int
ldi_handle_print(uintptr_t addr, int ident, int refs)
{
	vnode_t			vnode;
	struct ldi_handle	lh;
	const char		*name;

	/* read in the ldi handle */
	if (mdb_vread(&lh, sizeof (struct ldi_handle), addr) == -1) {
		mdb_warn("couldn't read ldi handle at %p", addr);
		return (DCMD_ERR);
	}

	/* display the handle address */
	mdb_printf("%0?p ", addr);

	/* display the ref count */
	if (refs)
		mdb_printf("%4u ", lh.lh_ref);

	/* display the vnode */
	mdb_printf("%0?p ", lh.lh_vp);

	/* read in the vnode associated with the handle */
	addr = (uintptr_t)lh.lh_vp;
	if (mdb_vread(&vnode, sizeof (vnode_t), addr) == -1) {
		mdb_warn("couldn't read vnode at %p", addr);
		return (1);
	}

	/* display the driver name */
	if ((name = mdb_major_to_name(getmajor(vnode.v_rdev))) == NULL) {
		mdb_warn("failed to convert major number to name\n");
		return (1);
	}
	mdb_printf("%10s ", name);

	/* display the minor number */
	mdb_printf("%5d ", getminor(vnode.v_rdev));

	/* display the event pointer (if any) */
	if (lh.lh_events != NULL) {
		mdb_printf("%0?p ", lh.lh_events);
	} else {
		mdb_printf("%?s ", "-");
	}

	if (!ident) {
		/* display the ident address */
		mdb_printf("%0?p\n", lh.lh_ident);
		return (0);
	}

	/* display the entire ident  */
	return (ldi_ident_print((uintptr_t)lh.lh_ident, refs));
}

int
ldi_handle(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int			ident = 0;
	int			refs = 1;

	if (mdb_getopts(argc, argv,
	    'i', MDB_OPT_SETBITS, TRUE, &ident, NULL) != argc)
		return (DCMD_USAGE);

	if (ident)
		refs = 0;

	/* Determine if there is an ldi handle address */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("ldi_handle", "ldi_handle",
		    argc, argv) == -1) {
			mdb_warn("can't walk ldi handles");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/* display the header line */
	if (DCMD_HDRSPEC(flags))
		ldi_handle_header(refs, ident);

	/* display the ldi handle */
	if (ldi_handle_print(addr, ident, refs))
		return (DCMD_ERR);

	return (DCMD_OK);
}

void
ldi_ident_help(void)
{
	mdb_printf("Displays an ldi identifier.\n"
	    "Without the address of an \"ldi_ident_t\", "
	    "print all identifiers.\n"
	    "With an address, print the specified identifier.\n");
}

void
ldi_handle_help(void)
{
	mdb_printf("Displays an ldi handle.\n"
	    "Without the address of an \"ldi_handle_t\", "
	    "print all handles.\n"
	    "With an address, print the specified handle.\n\n"
	    "Switches:\n"
	    "  -i  print the module identifier information\n");
}
