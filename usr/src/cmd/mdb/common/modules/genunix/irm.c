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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/mdb_modapi.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/ddi_intr.h>
#include <sys/ddi_intr_impl.h>
#include <stddef.h>

#include "list.h"

extern int	mdb_devinfo2driver(uintptr_t, char *, size_t);

static char *
irm_get_type(int type)
{
	if (type == (DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_MSIX))
		return ("MSI/X");

	switch (type) {
	case DDI_INTR_TYPE_FIXED:
		return ("Fixed");
	case DDI_INTR_TYPE_MSI:
		return ("MSI");
	case DDI_INTR_TYPE_MSIX:
		return ("MSI-X");
	default:
		return ("Unknown");
	}
}

static int
check_irm_enabled(void)
{
	GElf_Sym	sym;
	uintptr_t	addr;
	int		value;

	if (mdb_lookup_by_name("irm_enable", &sym) == -1) {
		mdb_warn("couldn't find irm_enable");
		return (0);
	}

	addr = (uintptr_t)sym.st_value;

	if (mdb_vread(&value, sizeof (value), addr) != sizeof (value)) {
		mdb_warn("couldn't read irm_enable at %p", addr);
		return (0);
	}

	return (value);
}

int
irmpools_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;

	if (mdb_lookup_by_name("irm_pools_list", &sym) == -1) {
		mdb_warn("couldn't find irm_pools_list");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)sym.st_value;

	return (list_walk_init_named(wsp, "interrupt pools", "pool"));
}

int
irmreqs_walk_init(mdb_walk_state_t *wsp)
{
	wsp->walk_addr = (uintptr_t)(wsp->walk_addr +
	    offsetof(ddi_irm_pool_t, ipool_req_list));

	return (list_walk_init_named(wsp, "interrupt requests", "request"));
}

int
irmpools_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ddi_irm_pool_t	pool;
	struct dev_info	dev;
	char		driver[MODMAXNAMELEN] = "";
	char		devname[MODMAXNAMELEN] = "";

	if (argc != 0)
		return (DCMD_USAGE);

	if (check_irm_enabled() == 0) {
		mdb_warn("IRM is not enabled");
		return (DCMD_ERR);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("irmpools", "irmpools", argc, argv) == -1) {
			mdb_warn("can't walk interrupt pools");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s  %-18s  %-8s  %-6s  %-9s  %-8s%</u>\n",
		    "ADDR", "OWNER", "TYPE", "SIZE", "REQUESTED", "RESERVED");
	}

	if (mdb_vread(&pool, sizeof (pool), addr) != sizeof (pool)) {
		mdb_warn("couldn't read interrupt pool at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&dev, sizeof (dev),
	    (uintptr_t)pool.ipool_owner) != sizeof (dev)) {
		mdb_warn("couldn't read dev_info at %p", pool.ipool_owner);
		return (DCMD_ERR);
	}

	mdb_devinfo2driver((uintptr_t)pool.ipool_owner, driver,
	    sizeof (driver));
	/*
	 * Include driver instance number only if the node has an
	 * instance number assigned (i.e. instance != -1) to it.
	 * This will cover cases like rootnex driver which doesn't
	 * have instance number assigned to it.
	 */
	if (dev.devi_instance != -1)
		mdb_snprintf(devname, sizeof (devname), "%s#%d", driver,
		    dev.devi_instance);
	else
		mdb_snprintf(devname, sizeof (devname), "%s", driver);

	mdb_printf("%0?p  %-18s  %-8s  %-6d  %-9d  %-8d\n", addr, devname,
	    irm_get_type(pool.ipool_types), pool.ipool_totsz,
	    pool.ipool_reqno, pool.ipool_resno);

	return (DCMD_OK);
}

int
irmreqs_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0)
		return (DCMD_USAGE);

	if (check_irm_enabled() == 0) {
		mdb_warn("IRM is not enabled");
		return (DCMD_ERR);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("can't perform global interrupt request walk");
		return (DCMD_ERR);
	}

	if (mdb_pwalk_dcmd("irmreqs", "irmreq", argc, argv, addr) == -1) {
		mdb_warn("can't walk interrupt requests");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
int
irmreq_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ddi_irm_req_t		req;
	struct dev_info		dev;
	struct devinfo_intr	intr;
	char			driver[MODMAXNAMELEN] = "";
	char			devname[MODMAXNAMELEN] = "";

	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s  %-18s  %-8s  %-8s  %-6s  %-4s  "
		    "%-6s%</u>\n", "ADDR", "OWNER", "TYPE", "CALLBACK",
		    "NINTRS", "NREQ", "NAVAIL");
	}

	if (mdb_vread(&req, sizeof (req), addr) != sizeof (req)) {
		mdb_warn("couldn't read interrupt request at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&dev, sizeof (dev),
	    (uintptr_t)req.ireq_dip) != sizeof (dev)) {
		mdb_warn("couldn't read dev_info at %p", req.ireq_dip);
		return (DCMD_ERR);
	}

	if (mdb_vread(&intr, sizeof (intr),
	    (uintptr_t)dev.devi_intr_p) != sizeof (intr)) {
		mdb_warn("couldn't read devinfo_intr at %p", dev.devi_intr_p);
		return (DCMD_ERR);
	}

	mdb_devinfo2driver((uintptr_t)req.ireq_dip, driver, sizeof (driver));
	mdb_snprintf(devname, sizeof (devname), "%s#%d", driver,
	    dev.devi_instance);

	mdb_printf("%0?p  %-18s  %-8s  %-8s  %-6d  %-4d  %-6d\n",
	    addr, devname, irm_get_type(req.ireq_type),
	    (req.ireq_flags & DDI_IRM_FLAG_CALLBACK) ? "Yes" : "No",
	    intr.devi_intr_sup_nintrs, req.ireq_nreq, req.ireq_navail);

	return (DCMD_OK);
}
