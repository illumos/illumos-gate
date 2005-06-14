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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "main.h"

/*
 * MDB module linkage information:
 */

static const mdb_dcmd_t dcmds[] = {
	{ "vhci_states", "[ -v ]", "dump all the vhci state pointers",
		vhci_states },
	{ "mdipi", NULL, "given a path, dump mdi_pathinfo "
		"and detailed pi_prop list", mdipi },
	{ "mdiprops", NULL, "given a pi_prop, dump the pi_prop list",
		mdiprops },
	{ "mdiphci", NULL, "given a phci, dump mdi_phci and "
		"list all paths", mdiphci },
	{ "mdivhci", NULL, "given a vhci, dump mdi_vhci and list "
		"all phcis", mdivhci },
	{ "mdiclient_paths", NULL, "given a path, walk mdi_pathinfo "
		"client links", mdiclient_paths },
	{ "mdiphci_paths", NULL, "given a path, walk through mdi_pathinfo "
		"phci links", mdiphci_paths },
	{ "mdiphcis", NULL, "given a phci, walk through mdi_phci ph_next links",
		mdiphcis },
	{ "vhciguid", NULL, "list all clients or given a guid, list one client",
		vhciguid },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "mdipi_client_list", "Walker for mdi_pathinfo pi_client_link",
		mdi_pi_client_link_walk_init,
		mdi_pi_client_link_walk_step,
		mdi_pi_client_link_walk_fini },

	{ "mdipi_phci_list", "Walker for mdi_pathinfo pi_phci_link",
		mdi_pi_phci_link_walk_init,
		mdi_pi_phci_link_walk_step,
		mdi_pi_phci_link_walk_fini },

	{ "mdiphci_list", "Walker for mdi_phci ph_next link",
		mdi_phci_ph_next_walk_init,
		mdi_phci_ph_next_walk_step,
		mdi_phci_ph_next_walk_fini },

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

char *client_lb_str[] =
{
	"NONE",
	"RR",
	"LBA",
	NULL
};

char *mdi_client_states[] =
{
	NULL,
	"OPTIMAL",
	"DEGRADED",
	"FAILED",
	NULL
};

char *client_flags[] =
{
	"MDI_CLIENT_FLAGS_OFFLINE",
	"MDI_CLIENT_FLAGS_SUSPEND",
	"MDI_CLIENT_FLAGS_POWER_DOWN",
	"MDI_CLIENT_FLAGS_DETACH",
	"MDI_CLIENT_FLAGS_FAILOVER",
	"MDI_CLIENT_FLAGS_REPORT_DEV",
	"MDI_CLIENT_FLAGS_PATH_FREE_IN_PROGRESS",
	"MDI_CLIENT_FLAGS_ASYNC_FREE",
	"MDI_CLIENT_FLAGS_DEV_NOT_SUPPORTED",
	NULL
};

char *mdi_pathinfo_states[] =
{
	"MDI_PATHINFO_STATE_INIT",
	"MDI_PATHINFO_STATE_ONLINE",
	"MDI_PATHINFO_STATE_STANDBY",
	"MDI_PATHINFO_STATE_FAULT",
	"MDI_PATHINFO_STATE_OFFLINE",
	NULL
};

char *mdi_pathinfo_ext_states[] =
{
	"MDI_PATHINFO_STATE_USER_DISABLE",
	"MDI_PATHINFO_STATE_DRV_DISABLE",
	"MDI_PATHINFO_STATE_DRV_DISABLE_TRANSIENT",
	NULL
};

char *mdi_phci_flags[] =
{
	"MDI_PHCI_FLAGS_OFFLINE",
	"MDI_PHCI_FLAGS_SUSPEND",
	"MDI_PHCI_FLAGS_POWER_DOWN",
	"MDI_PHCI_FLAGS_DETACH",
	"MDI_PHCI_FLAGS_USER_DISABLE",
	"MDI_PHCI_FLAGS_D_DISABLE",
	"MDI_PHCI_FLAGS_D_DISABLE_TRANS",
	"MDI_PHCI_FLAGS_POWER_TRANSITION",
	NULL
};

char *vhci_conf_flags[] =
{
	"VHCI_CONF_FLAGS_AUTO_FAILBACK",
	NULL
};

char *svlun_flags[] =
{
	"VLUN_TASK_D_ALIVE_FLG",
	"VLUN_RESERVE_ACTIVE_FLG",
	"VLUN_QUIESCED_FLG",
	NULL
};
