/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/mdb_modapi.h>
#include "i40e_sw.h"

#define	RSRC_MAX	0x13
static const char *i40e_switch_rsrc_names[] = {
	"VEBs",
	"VSIs",
	"Perfect Match MAC Addresses",
	"S-Tags",
	"Reserved",
	"Multicast Hash Entries",
	"Reserved",
	"VLANs",
	"VSI Lists",
	"Reserved",
	"VLAN Stat pools",
	"Mirror rules",
	"Queue sets",
	"Inner VLAN Forwarding",
	"Reserved",
	"Inner MACs",
	"IPs",
	"GRE/VN1 Keys",
	"VN2 Keys",
	"Tunnelling Ports"
};

/*
 * i40e mdb dcmds
 */
/* ARGSUSED */
static int
i40e_switch_rsrcs_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	i40e_t i40e;
	int i;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("::i40e_switch_rsrcs does not operate globally\n");
		return (DCMD_USAGE);
	}

	if (mdb_vread(&i40e, sizeof (i40e_t), addr) != sizeof (i40e_t)) {
		mdb_warn("failed to read i40e_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%-28s %-12s %-8s %-8s %s\n", "TYPE", "GUARANTEE",
	    "TOTAL", "USED", "UNALLOCED");

	for (i = 0; i < i40e.i40e_switch_rsrc_actual; i++) {
		i40e_switch_rsrc_t rsrc;
		uintptr_t raddr = (uintptr_t)i40e.i40e_switch_rsrcs +
		    i * sizeof (i40e_switch_rsrc_t);
		const char *name;

		if (mdb_vread(&rsrc, sizeof (i40e_switch_rsrc_t), raddr) !=
		    sizeof (i40e_switch_rsrc_t)) {
			mdb_warn("failed to read i40e_switch_rsrc_t %d at %p",
			    i, raddr);
			return (DCMD_ERR);
		}

		if (rsrc.resource_type <= RSRC_MAX) {
			name = i40e_switch_rsrc_names[rsrc.resource_type];
		} else {
			char *buf;
			size_t s = mdb_snprintf(NULL, 0, "Unknown type (%d)",
			    rsrc.resource_type);
			buf = mdb_alloc(s + 1, UM_GC | UM_SLEEP);
			(void) mdb_snprintf(buf, s + 1, "Unknown type (%d)",
			    rsrc.resource_type);
			name = buf;
		}

		mdb_printf("%-28s %-12d %-8d %-8d %d\n", name,
		    LE_16(rsrc.guaranteed), LE_16(rsrc.total), LE_16(rsrc.used),
		    LE_16(rsrc.total_unalloced));
	}

	return (DCMD_OK);
}

static const mdb_dcmd_t i40e_dcmds[] = {
	{ "i40e_switch_rsrcs", NULL, "print switch resources",
	    i40e_switch_rsrcs_dcmd, NULL },
	{ NULL }
};

static const mdb_modinfo_t i40e_modinfo = {
	MDB_API_VERSION, i40e_dcmds, NULL
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&i40e_modinfo);
}
