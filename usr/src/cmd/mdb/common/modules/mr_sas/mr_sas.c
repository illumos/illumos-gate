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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 */

#include <limits.h>
#include <sys/mdb_modapi.h>
#include <sys/sysinfo.h>
#include <sys/sunmdi.h>
#include <sys/scsi/scsi.h>
#include "mr_sas.h"

int
construct_path(uintptr_t addr, char *result)
{
	struct	dev_info	d;
	char	devi_node[PATH_MAX];
	char	devi_addr[PATH_MAX];

	if (mdb_vread(&d, sizeof (d), addr) == -1) {
		mdb_warn("couldn't read dev_info");
		return (DCMD_ERR);
	}

	if (d.devi_parent) {
		construct_path((uintptr_t)d.devi_parent, result);
		mdb_readstr(devi_node, sizeof (devi_node),
		    (uintptr_t)d.devi_node_name);
		mdb_readstr(devi_addr, sizeof (devi_addr),
		    (uintptr_t)d.devi_addr);
		mdb_snprintf(result+strlen(result),
		    PATH_MAX-strlen(result),
		    "/%s%s%s", devi_node, (*devi_addr ? "@" : ""),
		    devi_addr);
	}
	return (DCMD_OK);
}

void
display_targets(struct mrsas_instance *m, int verbose)
{
	int	tgt;
	struct mrsas_ld mr_ldp[MRDRV_MAX_LD];
	struct mrsas_tbolt_pd mr_pdp[MRSAS_TBOLT_PD_TGT_MAX];
	char	device_path[PATH_MAX];

	if (verbose) {
		*device_path = 0;
		if (construct_path((uintptr_t)m->dip, device_path) != DCMD_OK) {
			strcpy(device_path, "couldn't determine device path");
		}
	}

	mdb_printf("\n");
	if (verbose)
		mdb_printf("%s\n", device_path);
	mdb_printf("Physical/Logical Target\n");
	mdb_printf("-----------------------\n");

	if (mdb_vread(&mr_ldp, sizeof (mr_ldp), (uintptr_t)m->mr_ld_list)
	    == -1 ||
	    mdb_vread(&mr_pdp, sizeof (mr_pdp), (uintptr_t)m->mr_tbolt_pd_list)
	    == -1) {
		mdb_warn("can't read list of disks");
		return;
	}

	for (tgt = 0; tgt < MRDRV_MAX_LD; tgt++) {
		if (mr_ldp[tgt].dip != NULL &&
		    mr_ldp[tgt].lun_type == MRSAS_LD_LUN) {
			mdb_printf("Logical          sd %d\n", tgt);
		}
	}
	for (tgt = 0; tgt < MRSAS_TBOLT_PD_TGT_MAX; tgt++) {
		if (mr_pdp[tgt].dip != NULL &&
		    mr_pdp[tgt].lun_type == MRSAS_TBOLT_PD_LUN) {
			mdb_printf("Physical         sd %d\n", tgt);
		}
	}
	mdb_printf("\n");
}

void
display_deviceinfo(struct mrsas_instance *m)
{
	uint16_t vid, did, svid, sid;

	vid = m->vendor_id;
	did = m->device_id;
	svid = m->subsysvid;
	sid = m->subsysid;

	mdb_printf("\n");
	mdb_printf("vendor_id device_id subsysvid subsysid");
	mdb_printf("\n");
	mdb_printf("--------------------------------------");
	mdb_printf("\n");
	mdb_printf("    0x%x   0x%x    0x%x    0x%x",
	    vid, did, svid, sid);
	mdb_printf("\n");
}

static int
mr_sas_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct mrsas_instance m;

	int	instance;
	uint16_t ncmds;
	uint_t	verbose = FALSE;
	uint_t	device_info = FALSE;
	uint_t	target_info = FALSE;
	int	rv = DCMD_OK;
	void	*mrsas_state;

	if (!(flags & DCMD_ADDRSPEC)) {
		mrsas_state = NULL;
		if (mdb_readvar(&mrsas_state, "mrsas_state") == -1) {
			mdb_warn("can't read mrsas_state");
			return (DCMD_ERR);
		}
		if (mdb_pwalk_dcmd("genunix`softstate", "mr_sas`mr_sas",
		    argc, argv, (uintptr_t)mrsas_state) == -1) {
			mdb_warn("mdb_pwalk_dcmd failed");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, TRUE, &device_info,
	    't', MDB_OPT_SETBITS, TRUE, &target_info,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&m, sizeof (m), addr) == -1) {
		mdb_warn("couldn't read mrsas_instance struct at 0x%p", addr);
		return (DCMD_ERR);
	}
	instance = m.instance;

	/* cmd slot info */
	ncmds = m.max_fw_cmds;

	/* processing completed */
	if (((flags & DCMD_ADDRSPEC) && !(flags & DCMD_LOOP)) ||
	    (flags & DCMD_LOOPFIRST)) {
		if ((flags & DCMD_LOOP) && !(flags & DCMD_LOOPFIRST))
			mdb_printf("\n");
		mdb_printf("         mrsas_t inst max_fw_cmds intr_type");
		mdb_printf("\n");
		mdb_printf("===========================================");
		mdb_printf("\n");
	}

	mdb_printf("%16p %4d      %4d    ", addr, instance, ncmds);
	switch (m.intr_type) {
		case DDI_INTR_TYPE_MSIX:
			mdb_printf("MSI-X");
			break;
		case DDI_INTR_TYPE_MSI:
			mdb_printf("MSI");
			break;
		case DDI_INTR_TYPE_FIXED:
			mdb_printf("FIXED");
			break;
		default:
			mdb_printf("INVALD");
	}
	mdb_printf("\n");

	if (target_info)
		display_targets(&m, verbose);

	if (device_info)
		display_deviceinfo(&m);

	return (rv);
}

void
mr_sas_help(void)
{
	mdb_printf("Prints summary information about each mr_sas instance, "
	    "Without the address of a \"struct mrsas_instance\", prints every "
	    "instance.\n\n"
	    "Switches:\n"
	    "  -t   includes information about targets\n"
	    "  -d   includes information about the hardware\n"
	    "  -v   displays extra information for some options\n");
}

static const mdb_dcmd_t dcmds[] = {
	{ "mr_sas", "?[-tdv]", "print mr_sas information", mr_sas_dcmd,
	    mr_sas_help },
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
