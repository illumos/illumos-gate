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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <sys/mdb_modapi.h>
#include <sys/dditypes.h>
#include <sys/sysinfo.h>
#include <sys/1394/s1394.h>

static int print_node_info(s1394_hal_t *hal);

/*
 * speedmap()
 *    is used to print node information (speed map, node number, GUID, etc.)
 *    about the 1394 devices currently attached to the 1394 bus.
 */
static int
speedmap(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	s1394_hal_t	hal;
	int		ret;

	if (flags & DCMD_ADDRSPEC) {
		if (mdb_vread(&hal, sizeof (s1394_hal_t), addr) == -1) {
			mdb_warn("failed to read the HAL structure");
			return (DCMD_ERR);
		}

		ret = print_node_info(&hal);
		if (ret == DCMD_ERR)
		    return (DCMD_ERR);
	} else {
		(void) mdb_walk_dcmd("speedmap", "speedmap", argc, argv);
	}

	return (DCMD_OK);
}

static int
speedmap_walk_init(mdb_walk_state_t *wsp)
{
	s1394_state_t	*statep;
	s1394_state_t	state;

	if (wsp->walk_addr == 0) {
		if (mdb_readvar(&statep, "s1394_statep") == -1) {
			mdb_warn("failed to find the s1394_statep pointer");
			return (WALK_ERR);
		}
		if (mdb_vread(&state, sizeof (s1394_state_t),
		    (uintptr_t)statep) == -1) {
			mdb_warn("failed to read the s1394_statep structure");
			return (WALK_ERR);
		}
		wsp->walk_addr = (uintptr_t)state.hal_head;
	}

	return (WALK_NEXT);
}

static int
speedmap_walk_step(mdb_walk_state_t *wsp)
{
	s1394_hal_t	hal;
	uintptr_t	addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&hal, sizeof (s1394_hal_t), addr) == -1) {
		mdb_warn("failed to read the HAL structure");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)hal.hal_next;
	return (wsp->walk_callback(addr, &hal, wsp->walk_cbdata));
}

/*ARGSUSED*/
static void
speedmap_walk_fini(mdb_walk_state_t *wsp)
{
	/* Nothing to do here */
}

static const mdb_dcmd_t dcmds[] = {
	{ "speedmap", NULL, "print 1394 bus information", speedmap },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "speedmap", "iterate over HAL structures", speedmap_walk_init,
		speedmap_walk_step, speedmap_walk_fini },
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

/*
 * print_node_info()
 *    is used to do the actual printing, given a HAL pointer.
 */
static int
print_node_info(s1394_hal_t *hal)
{
	s1394_node_t	node[IEEE1394_MAX_NODES];
	uint32_t	cfgrom[IEEE1394_CONFIG_ROM_QUAD_SZ];
	char		str[512], tmp[512];
	uint_t		hal_node_num, num_nodes;
	int		i, j;

	num_nodes = hal->number_of_nodes;
	if (mdb_vread(node, (num_nodes * sizeof (s1394_node_t)),
	    (uintptr_t)hal->topology_tree) == -1) {
		mdb_warn("failed to read the node structures");
		return (DCMD_ERR);
	}

	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);

	mdb_printf("Speed Map:\n");

	(void) strcpy(str, "    |");
	for (i = 0; i < num_nodes; i++) {
		(void) mdb_snprintf(tmp, sizeof (tmp), " %2d ", i);
		(void) strcat(str, tmp);
	}
	(void) strcat(str, "  |       GUID\n");
	mdb_printf("%s", str);

	(void) strcpy(str, "----|");
	for (i = 0; i < hal->number_of_nodes; i++) {
		(void) mdb_snprintf(tmp, sizeof (tmp), "----");
		(void) strcat(str, tmp);
	}
	(void) strcat(str, "--|------------------\n");
	mdb_printf("%s", str);

	for (i = 0; i < num_nodes; i++) {
		if (node[i].cfgrom != NULL) {
			if (mdb_vread(&cfgrom, IEEE1394_CONFIG_ROM_SZ,
			    (uintptr_t)node[i].cfgrom) == -1) {
				mdb_warn("failed to read Config ROM");
				return (DCMD_ERR);
			}
		}

		(void) mdb_snprintf(str, sizeof (str), " %2d |", i);

		for (j = 0; j < num_nodes; j++) {
			(void) mdb_snprintf(tmp, sizeof (tmp), " %3d",
			    hal->speed_map[i][j]);
			(void) strcat(str, tmp);
		}

		if (i == hal_node_num) {
			(void) strcat(str, "  | Local OHCI Card\n");

		} else if (node[i].link_active == 0) {
			(void) strcat(str, "  | Link off\n");

		} else if (CFGROM_BIB_READ(&node[i])) {
			(void) mdb_snprintf(tmp, sizeof (tmp),
			    "  | %08x%08x\n", cfgrom[3], cfgrom[4]);
			(void) strcat(str, tmp);

		} else {
			(void) strcat(str, "  | ????????????????\n");
		}
		mdb_printf("%s", str);
	}
	mdb_printf("\n");
	return (DCMD_OK);
}
