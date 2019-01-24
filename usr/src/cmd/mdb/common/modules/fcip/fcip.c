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
 *
 * FCIP mdb module
 */


#include <sys/mdb_modapi.h>
#include <sys/mutex.h>
#include <sys/modctl.h>
#include <sys/ethernet.h>
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/impl/fc_ulpif.h>
#include <sys/fibre-channel/impl/fctl_private.h>
#include <sys/fibre-channel/ulp/fcip.h>

/*
 * Leadville fcip walker/dcmd code
 */

static int
fcip_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0 &&
	    mdb_readvar(&wsp->walk_addr, "fcip_port_head") == -1) {
		mdb_warn("failed to read 'fcip_port_head'");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (fcip_port_info_t), UM_SLEEP);
	return (WALK_NEXT);
}

static int
fcip_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (fcip_port_info_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read fcip_port_info at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((fcip_port_info_t *)wsp->walk_data)->fcipp_next);

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.  Since we
 * dynamically allocated a fc_fca_port_t in port_walk_i, we must free it now.
 */
static void
fcip_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (fc_fca_port_t));
}


static int
fcip(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	fcip_port_info_t	pinfo;

	if (argc != 0) {
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("fcip", "fcip",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'fcip_port_head'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%12s %12s %12s %16s %16s\n",
		    "FCIP Struct", "Handle", "DIP", "Port WWN", "Node WWN");

	/*
	 * For each port, we just need to read the fc_fca_port_t struct, read
	 * the port_handle
	 */
	if (mdb_vread(&pinfo, sizeof (fcip_port_info_t), addr) ==
	    sizeof (fcip_port_info_t)) {
		mdb_printf("%12p %12p %12p %02x%02x%02x%02x%02x%02x%02x%02x "
		    "%02x%02x%02x%02x%02x%02x%02x%02x\n",
		    pinfo.fcipp_fcip, pinfo.fcipp_handle, pinfo.fcipp_dip,
		    pinfo.fcipp_pwwn.raw_wwn[0], pinfo.fcipp_pwwn.raw_wwn[1],
		    pinfo.fcipp_pwwn.raw_wwn[2], pinfo.fcipp_pwwn.raw_wwn[3],
		    pinfo.fcipp_pwwn.raw_wwn[4], pinfo.fcipp_pwwn.raw_wwn[5],
		    pinfo.fcipp_pwwn.raw_wwn[6], pinfo.fcipp_pwwn.raw_wwn[7],
		    pinfo.fcipp_nwwn.raw_wwn[0], pinfo.fcipp_nwwn.raw_wwn[1],
		    pinfo.fcipp_nwwn.raw_wwn[2], pinfo.fcipp_nwwn.raw_wwn[3],
		    pinfo.fcipp_nwwn.raw_wwn[4], pinfo.fcipp_nwwn.raw_wwn[5],
		    pinfo.fcipp_nwwn.raw_wwn[6], pinfo.fcipp_nwwn.raw_wwn[7]);

	} else
		mdb_warn("failed to read port info at %p", addr);

	return (DCMD_OK);
}


/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, a list of structures
 * describing our walkers, and a function named _mdb_init to return a pointer
 * to our module information.
 */

static const mdb_dcmd_t dcmds[] = {
	{ "fcip", NULL, "Leadville fcip instances", fcip },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "fcip", "walk list of Leadville fcip instances",
		fcip_walk_i, fcip_walk_s, fcip_walk_f },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
