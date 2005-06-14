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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

struct zsd_cb_data {
	zone_key_t	key;
	int		found;
};

/* ARGSUSED */
static int
zsd_match(uintptr_t addr, const void *data, void *private)
{
	struct zsd_entry ze;
	struct zsd_cb_data *cbdata = private;

	if (mdb_vread(&ze, sizeof (struct zsd_entry), addr) == -1) {
		mdb_warn("couldn't read zsd_entry at %p", addr);
		return (WALK_ERR);
	}
	if (ze.zsd_key != cbdata->key)
		return (WALK_NEXT);
	cbdata->found = 1;
	mdb_printf("%p\n", ze.zsd_data);
	return (WALK_DONE);
}

int
zsd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	zone_t zone;
	const mdb_arg_t *argp = &argv[0];
	zone_key_t key;
	struct zsd_cb_data cbd;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn("address of zone not specified\n");
		return (DCMD_ERR);
	}
	if (argc != 1)
		return (DCMD_USAGE);
	if (argp->a_type == MDB_TYPE_IMMEDIATE)
		key = argp->a_un.a_val;
	else
		key = mdb_strtoull(argp->a_un.a_str);
	if (mdb_vread(&zone, sizeof (struct zone), addr) == -1) {
		mdb_warn("couldn't read zone_t at %p", addr);
		return (DCMD_ERR);
	}
	cbd.key = key;
	cbd.found = 0;
	if (mdb_pwalk("zsd", zsd_match, &cbd, addr) != 0) {
		mdb_warn("failed to walk zsd\n");
		return (DCMD_ERR);
	}
	if (cbd.found == 0) {
		mdb_warn("no corresponding ZSD value found for key %d\n",
		    key);
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}
