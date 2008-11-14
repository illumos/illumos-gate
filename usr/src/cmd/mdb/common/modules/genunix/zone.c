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

#include <mdb/mdb_param.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include "zone.h"

#include <stddef.h>
#include <sys/zone.h>

#define	ZONE_NAMELEN	20
#ifdef _LP64
#define	ZONE_PATHLEN	32
#else
#define	ZONE_PATHLEN	40
#endif

int
zoneprt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	zone_t zn;
	char name[ZONE_NAMELEN];
	char path[ZONE_PATHLEN];
	int len;

	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("zone", "zone", argc, argv) == -1) {
			mdb_warn("can't walk zones");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %6s %-20s %-s%</u>\n",
		    "ADDR", "ID", "NAME", "PATH");
	}
	if (mdb_vread(&zn, sizeof (zone_t), addr) == -1) {
		mdb_warn("can't read zone_t structure at %p", addr);
		return (DCMD_ERR);
	}
	len = mdb_readstr(name, ZONE_NAMELEN, (uintptr_t)zn.zone_name);
	if (len > 0) {
		if (len == ZONE_NAMELEN)
			(void) strcpy(&name[len - 4], "...");
	} else {
		(void) strcpy(name, "??");
	}
	len = mdb_readstr(path, ZONE_PATHLEN, (uintptr_t)zn.zone_rootpath);
	if (len > 0) {
		if (len == ZONE_PATHLEN)
			(void) strcpy(&path[len - 4], "...");
	} else {
		(void) strcpy(path, "??");
	}
	mdb_printf("%0?p %6d %-20s %s\n", addr, zn.zone_id, name, path);
	return (DCMD_OK);
}

int
zone_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;

	if (wsp->walk_addr == NULL) {
		if (mdb_lookup_by_name("zone_active", &sym) == -1) {
			mdb_warn("failed to find 'zone_active'");
			return (WALK_ERR);
		}
		wsp->walk_addr = (uintptr_t)sym.st_value;
	}
	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("couldn't walk 'list'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
zone_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

int
zsd_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("global walk not supported\n");
		return (WALK_ERR);
	}
	wsp->walk_addr += offsetof(struct zone, zone_zsd);
	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("couldn't walk 'list'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
zsd_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * Helper structure used when walking ZSD entries via zsd().
 */
struct zsd_cb_data {
	uint_t		keygiven;	/* Was a key specified (are we */
					/* searching for a specific ZSD */
					/* entry)? */
	zone_key_t	key;		/* Key of ZSD for which we're looking */
	uint_t		found;		/* Was the specific ZSD entry found? */
	uint_t		voptgiven;	/* Display verbose information? */
};

/*
 * Helper function for zsd() that displays information from a single ZSD struct.
 * 'datap' must point to a valid zsd_cb_data struct.
 */
/* ARGSUSED */
static int
zsd_print(uintptr_t addrp, const void * datap, void * privatep)
{
	struct zsd_entry entry;
	struct zsd_cb_data *cbdp;

	if (mdb_vread(&entry, sizeof (entry), addrp) == -1) {
		mdb_warn("couldn't read zsd_entry at %p", addrp);
		return (WALK_ERR);
	}
	cbdp = (struct zsd_cb_data *)privatep;

	/*
	 * Are we looking for a single entry specified by a key?  Then make sure
	 * that the current ZSD's key is what we're looking for.
	 */
	if (cbdp->keygiven == TRUE && cbdp->key != entry.zsd_key)
		return (WALK_NEXT);

	mdb_printf("%?x %0?p %8x\n", entry.zsd_key, entry.zsd_data,
	    entry.zsd_flags);
	if (cbdp->voptgiven == TRUE)
		mdb_printf("    Create CB:   %a\n    Shutdown CB: %a\n"
		    "    Destroy CB:  %a\n", entry.zsd_create,
		    entry.zsd_shutdown, entry.zsd_destroy);
	if (cbdp->keygiven == TRUE) {
		cbdp->found = TRUE;
		return (WALK_DONE);
	}
	return (WALK_NEXT);
}

int
zsd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	zone_t zone;
	const mdb_arg_t *argp;
	int argcindex;
	struct zsd_cb_data cbd;
	char name[ZONE_NAMELEN];
	int len;

	/*
	 * Walk all zones if necessary.
	 */
	if (argc > 2)
		return (DCMD_USAGE);
	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk_dcmd("zone", "zsd", argc, argv) == -1) {
			mdb_warn("failed to walk zone\n");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/*
	 * Make sure a zone_t can be read from the specified address.
	 */
	if (mdb_vread(&zone, sizeof (zone), addr) == -1) {
		mdb_warn("couldn't read zone_t at %p", (void *)addr);
		return (DCMD_ERR);
	}

	/*
	 * Get the optional arguments (key or -v or both).  Note that
	 * mdb_getopts() will not parse a key argument because it is not
	 * preceded by an option letter.  We'll get around this by requiring
	 * that all options precede the optional key argument.
	 */
	cbd.keygiven = FALSE;
	cbd.voptgiven = FALSE;
	if (argc > 0 && (argcindex = mdb_getopts(argc, argv, 'v',
	    MDB_OPT_SETBITS, TRUE, &cbd.voptgiven, NULL)) != argc) {
		/*
		 * No options may appear after the key.
		 */
		if (argcindex != argc - 1)
			return (DCMD_USAGE);

		/*
		 * The missed argument should be a key.
		 */
		argp = &argv[argcindex];
		if (argp->a_type == MDB_TYPE_IMMEDIATE)
			cbd.key = argp->a_un.a_val;
		else
			cbd.key = mdb_strtoull(argp->a_un.a_str);
		cbd.keygiven = TRUE;
		cbd.found = FALSE;
	}

	/*
	 * Prepare to output the specified zone's ZSD information.
	 */
	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%-20s %?s %?s %8s%</u>\n", "ZONE", "KEY",
		    "VALUE", "FLAGS");
	len = mdb_readstr(name, ZONE_NAMELEN, (uintptr_t)zone.zone_name);
	if (len > 0) {
		if (len == ZONE_NAMELEN)
			(void) strcpy(&name[len - 4], "...");
	} else {
		(void) strcpy(name, "??");
	}
	mdb_printf("%-20s ", name);

	/*
	 * Display the requested ZSD entries.
	 */
	mdb_inc_indent(21);
	if (mdb_pwalk("zsd", zsd_print, &cbd, addr) != 0) {
		mdb_warn("failed to walk zsd\n");
		mdb_dec_indent(21);
		return (DCMD_ERR);
	}
	if (cbd.keygiven == TRUE && cbd.found == FALSE) {
		mdb_printf("no corresponding ZSD entry found\n");
		mdb_dec_indent(21);
		return (DCMD_ERR);
	}
	mdb_dec_indent(21);
	return (DCMD_OK);
}
