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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc.  All rights reserved.
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

/*
 * Names corresponding to zone_status_t values in sys/zone.h
 */
char *zone_status_names[] = {
	"uninitialized",	/* ZONE_IS_UNINITIALIZED */
	"initialized",		/* ZONE_IS_INITIALIZED */
	"ready",		/* ZONE_IS_READY */
	"booting",		/* ZONE_IS_BOOTING */
	"running",		/* ZONE_IS_RUNNING */
	"shutting_down",	/* ZONE_IS_SHUTTING_DOWN */
	"empty",		/* ZONE_IS_EMPTY */
	"down",			/* ZONE_IS_DOWN */
	"dying",		/* ZONE_IS_DYING */
	"dead"			/* ZONE_IS_DEAD */
};

static int
zid_lookup_cb(uintptr_t addr, const zone_t *zone, void *arg)
{
	zoneid_t zid = *(uintptr_t *)arg;
	if (zone->zone_id == zid)
		mdb_printf("%p\n", addr);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
zid2zone(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_walk("zone", (mdb_walk_cb_t)zid_lookup_cb, &addr) == -1) {
		mdb_warn("failed to walk zone");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

int
zoneprt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	zone_t zn;
	char name[ZONE_NAMELEN];
	char path[ZONE_PATHLEN];
	int len;
	uint_t vopt_given;
	uint_t ropt_given;

	if (argc > 2)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("zone", "zone", argc, argv) == -1) {
			mdb_warn("can't walk zones");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/*
	 * Get the optional -r (reference counts) and -v (verbose output)
	 * arguments.
	 */
	vopt_given = FALSE;
	ropt_given = FALSE;
	if (argc > 0 && mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE,
	    &vopt_given, 'r', MDB_OPT_SETBITS, TRUE, &ropt_given, NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * -v can only be specified with -r.
	 */
	if (vopt_given == TRUE && ropt_given == FALSE)
		return (DCMD_USAGE);

	/*
	 * Print a table header, if necessary.
	 */
	if (DCMD_HDRSPEC(flags)) {
		if (ropt_given == FALSE)
			mdb_printf("%<u>%?s %6s %-13s %-20s %-s%</u>\n",
			    "ADDR", "ID", "STATUS", "NAME", "PATH");
		else
			mdb_printf("%<u>%?s %6s %10s %10s %-20s%</u>\n",
			    "ADDR", "ID", "REFS", "CREFS", "NAME");
	}

	/*
	 * Read the zone_t structure at the given address and read its name.
	 */
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

	if (ropt_given == FALSE) {
		char *statusp;

		/*
		 * Default display
		 * Fetch the zone's path and print the results.
		 */
		len = mdb_readstr(path, ZONE_PATHLEN,
		    (uintptr_t)zn.zone_rootpath);
		if (len > 0) {
			if (len == ZONE_PATHLEN)
				(void) strcpy(&path[len - 4], "...");
		} else {
			(void) strcpy(path, "??");
		}
		if (zn.zone_status >= ZONE_IS_UNINITIALIZED && zn.zone_status <=
		    ZONE_IS_DEAD)
			statusp = zone_status_names[zn.zone_status];
		else
			statusp = "???";
		mdb_printf("%0?p %6d %-13s %-20s %s\n", addr, zn.zone_id,
		    statusp, name, path);
	} else {
		/*
		 * Display the zone's reference counts.
		 * Display the zone's subsystem-specific reference counts if
		 * the user specified the '-v' option.
		 */
		mdb_printf("%0?p %6d %10u %10u %-20s\n", addr, zn.zone_id,
		    zn.zone_ref, zn.zone_cred_ref, name);
		if (vopt_given == TRUE) {
			GElf_Sym subsys_names_sym;
			uintptr_t **zone_ref_subsys_names;
			uint_t num_subsys;
			uint_t n;

			/*
			 * Read zone_ref_subsys_names from the kernel image.
			 */
			if (mdb_lookup_by_name("zone_ref_subsys_names",
			    &subsys_names_sym) != 0) {
				mdb_warn("can't find zone_ref_subsys_names");
				return (DCMD_ERR);
			}
			if (subsys_names_sym.st_size != ZONE_REF_NUM_SUBSYS *
			    sizeof (char *)) {
				mdb_warn("number of subsystems in target "
				    "differs from what mdb expects (mismatched"
				    " kernel versions?)");
				if (subsys_names_sym.st_size <
				    ZONE_REF_NUM_SUBSYS * sizeof (char *))
					num_subsys = subsys_names_sym.st_size /
					    sizeof (char *);
				else
					num_subsys = ZONE_REF_NUM_SUBSYS;
			} else {
				num_subsys = ZONE_REF_NUM_SUBSYS;
			}
			if ((zone_ref_subsys_names = mdb_alloc(
			    subsys_names_sym.st_size, UM_GC)) == NULL) {
				mdb_warn("out of memory");
				return (DCMD_ERR);
			}
			if (mdb_readvar(zone_ref_subsys_names,
			    "zone_ref_subsys_names") == -1) {
				mdb_warn("can't find zone_ref_subsys_names");
				return (DCMD_ERR);
			}

			/*
			 * Display each subsystem's reference count if it's
			 * nonzero.
			 */
			mdb_inc_indent(7);
			for (n = 0; n < num_subsys; ++n) {
				char subsys_name[16];

				/*
				 * Skip subsystems lacking outstanding
				 * references.
				 */
				if (zn.zone_subsys_ref[n] == 0)
					continue;

				/*
				 * Each subsystem's name must be read from
				 * the target's image.
				 */
				if (mdb_readstr(subsys_name,
				    sizeof (subsys_name),
				    (uintptr_t)zone_ref_subsys_names[n]) ==
				    -1) {
					mdb_warn("unable to read subsystem name"
					    " from zone_ref_subsys_names[%u]",
					    n);
					return (DCMD_ERR);
				}
				mdb_printf("%15s: %10u\n", subsys_name,
				    zn.zone_subsys_ref[n]);
			}
			mdb_dec_indent(7);
		}
	}
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
