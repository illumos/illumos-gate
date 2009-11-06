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
 * x86 Generic FMA Topology Enumerator
 */


#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <strings.h>
#include <sys/fcntl.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <sys/systeminfo.h>
#include <sys/smbios.h>
#include <sys/smbios_impl.h>
#include <sys/fm/protocol.h>
#include <x86pi_impl.h>


static int x86pi_enum_start(topo_mod_t *, x86pi_enum_t *);
static int x86pi_enum_gentopo(topo_mod_t *, tnode_t *, smbios_hdl_t *);

/*
 * Entry point called by libtopo when enumeration is required
 */
static topo_enum_f x86pi_enum;	/* libtopo enumeration entry point */

/*
 * Declare the operations vector and information structure used during
 * module registration
 */
static topo_modops_t x86pi_ops =
	{ x86pi_enum, NULL };

static topo_modinfo_t	x86pi_modinfo =
	{ X86PI_DESC, X86PI_SCHEME, X86PI_VERSION, &x86pi_ops };

/*
 * Used to pass SMBIOS' FM compatibility to the
 * chip enumerator
 */
int x86pi_smbios = 0;

/*
 * Called by libtopo when the topo module is loaded.
 */
int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	int	result;
	char	isa[MAXNAMELEN];

	if (getenv("TOPOX86PIDBG") != NULL) {
		/* Debugging is requested for this module */
		topo_mod_setdebug(mod);
	}
	topo_mod_dprintf(mod, "module initializing.\n");

	if (version != TOPO_VERSION) {
		(void) topo_mod_seterrno(mod, EMOD_VER_NEW);
		topo_mod_dprintf(mod, "incompatible topo version %d\n",
		    version);
		return (-1);
	}

	/* Verify that this is a i86pc architecture machine */
	(void) sysinfo(SI_MACHINE, isa, MAXNAMELEN);
	if (strncmp(isa, "i86pc", MAXNAMELEN) != 0) {
		topo_mod_dprintf(mod, "not i86pc architecture: %s\n", isa);
		return (-1);
	}

	result = topo_mod_register(mod, &x86pi_modinfo, TOPO_VERSION);
	if (result < 0) {
		topo_mod_dprintf(mod, "registration failed: %s\n",
		    topo_mod_errmsg(mod));
		/* module errno already set */
		return (-1);
	}
	topo_mod_dprintf(mod, "module ready.\n");
	return (0);
}


/*
 * Clean up any data used by the module before it is unloaded.
 */
void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_dprintf(mod, "module finishing.\n");

	x86pi_hbr_enum_fini(mod);

	/* Unregister from libtopo */
	topo_mod_unregister(mod);
}


/*
 * Enumeration entry point for the x86 Generic topology enumerator
 */
/* ARGSUSED */
static int
x86pi_enum(topo_mod_t *mod, tnode_t *t_parent, const char *name,
    topo_instance_t min, topo_instance_t max, void *pi_private, void *data)
{
	int		result;
	hrtime_t	starttime;
	x86pi_enum_t	x86pi;

	/* Begin enumeration */
	starttime = gethrtime();
	topo_mod_dprintf(mod, "enumeration starting.\n");

	/*
	 * Let's do some enumeration.
	 */
	bzero(&x86pi, sizeof (x86pi_enum_t));
	x86pi.t_parent = t_parent;
	result = x86pi_enum_start(mod, &x86pi);
	if (result != 0) {
		topo_mod_dprintf(mod, "Enumeration failed.\n");
		return (-1);
	}

	/* Complete enumeration */
	topo_mod_dprintf(mod, "enumeration complete in %lld ms.\n",
	    ((gethrtime() - starttime)/MICROSEC));

	/* All done */
	return (result);
}

static int
x86pi_enum_start(topo_mod_t *mod, x86pi_enum_t *x86pi)
{
	int		rv;
	int		complvl = 0;
	smbios_hdl_t	*shp;
	char		*f = "x86pi_enum_start";

	/*
	 * Verify BIOS compliance.
	 */
	shp = x86pi_smb_open(mod);
	if (shp == NULL) {
		topo_mod_dprintf(mod, "%s: failed to open SMBIOS\n", f);
		complvl = X86PI_NONE;
	} else {
		complvl = x86pi_check_comp(mod, shp);
	}

	topo_mod_dprintf(mod, "%s: SMBIOS x86pi compliance: %s\n", f,
	    complvl == X86PI_FULL ? "FULL" : "NONE");

	if (complvl == X86PI_NONE) {
		/* fall back to legacy enumeration */
		topo_mod_dprintf(mod,
		    "%s: Calling legacy enumeration\n", f);

		return (topo_mod_enummap(mod, x86pi->t_parent,
		    "i86pc-legacy", FM_FMRI_SCHEME_HC));
	}

	x86pi->priv = (void *)shp;
	x86pi_smbios = complvl;

	if (x86pi_hbr_enum_init(mod) < 0) {
		topo_mod_dprintf(mod, "%s: x86pi_hbr_enum_init() failed.\n", f);
		return (-1);
	}

	/*
	 * Create the topology.
	 */
	fac_done = 0;
	rv = x86pi_enum_gentopo(mod, x86pi->t_parent, shp);
	if (rv != 0) {
		return (-1);
	}
	x86pi->mod = mod;

	if (fac_done == 0) {
		(void) topo_mod_enummap(mod, x86pi->t_parent, "chassis",
		    FM_FMRI_SCHEME_HC);
		(void) topo_mod_enummap(mod, x86pi->t_parent, "fan",
		    FM_FMRI_SCHEME_HC);
		(void) topo_mod_enummap(mod, x86pi->t_parent, "psu",
		    FM_FMRI_SCHEME_HC);
	}

	/* All done */
	topo_mod_dprintf(mod, "%s: done.\n", f);
	return (rv);
}

/*
 * Create the i86pc topology
 *
 * If either Type 2 or Type 3 structures have contained elements/handles,
 * walk them creating the topo.
 *
 * If there are no contained elements/handles, build this topo:
 *
 *    Main Chassis
 *      Motherboard
 *        CMP Chip/Core/Strands
 *          Memory Controllers/Memory Devices (DIMMs)
 *        PCIE HostBrige
 *          PCIE Root Complex
 *
 */
static int
x86pi_enum_gentopo(topo_mod_t *mod, tnode_t *t_parent, smbios_hdl_t *shp)
{
	int		rv;
	int		nch, nbb, ncmp, i;
	int		ch_smbid, bb_smbid;
	tnode_t		*chassis_node = NULL;
	tnode_t		*basebd_node = NULL;
	smbs_cnt_t	*smbc;
	tnode_t		*motherchassis_node = NULL;
	tnode_t		*pnode = NULL;
	id_t		psmbid;
	int		notvisited;
	int		bb_count, ch_count;
	int		min, max;
	int		ch_inst = 0;
	topo_instance_t	 hbri = 0, rci = 0;
	smbios_pciexrc_t hbr;
	char		*f = "x86pi_enum_gentopo";

	if (t_parent == NULL) {
		topo_mod_dprintf(mod, "%s: NULL parent\n", f);
		return (-1);
	}

	/*
	 * "Chassis'"
	 */
	/* Type 3 structs */
	stypes[SMB_TYPE_CHASSIS].type = SMB_TYPE_CHASSIS;
	x86pi_smb_strcnt(shp, &stypes[SMB_TYPE_CHASSIS]);

	ch_count = stypes[SMB_TYPE_CHASSIS].count;

	for (nch = 0; nch < ch_count; nch++) {
		topo_mod_dprintf(mod, "%s: found %d chassis\n", f,
		    stypes[SMB_TYPE_CHASSIS].count);

		ch_smbid = stypes[SMB_TYPE_CHASSIS].ids[nch].id;

		/*
		 * Expect SMBIOS to set the first Chassis Structure to be the
		 * parent/mother of all chassis
		 */
		if (nch == 0)
			motherchassis_node = chassis_node =
			    x86pi_gen_chassis(mod, t_parent, shp,
			    ch_smbid, ch_inst++);
		else {
			if (motherchassis_node != NULL)
				chassis_node = x86pi_gen_chassis(mod,
				    motherchassis_node, shp,
				    ch_smbid, ch_inst++);
			else
				chassis_node = x86pi_gen_chassis(mod,
				    t_parent, shp, ch_smbid, ch_inst++);
		}

		if (chassis_node == NULL) {
			topo_mod_dprintf(mod,
			    "%s: Failed to create chassis %d\n", f, nch);
			continue;
		}
		stypes[SMB_TYPE_CHASSIS].ids[nch].node = chassis_node;
	}

	/*
	 * "Base Board"
	 */
	/* Type 2 structs */
	stypes[SMB_TYPE_BASEBOARD].type = SMB_TYPE_BASEBOARD;
	x86pi_smb_strcnt(shp, &stypes[SMB_TYPE_BASEBOARD]);
	bb_count = notvisited = stypes[SMB_TYPE_BASEBOARD].count;

	for (nbb = 0; nbb < bb_count; nbb++) {
		stypes[SMB_TYPE_BASEBOARD].ids[nbb].visited = 0;
		stypes[SMB_TYPE_BASEBOARD].ids[nbb].con_by_id = 0;
		stypes[SMB_TYPE_BASEBOARD].ids[nbb].node = NULL;
	}
	(void) x86pi_bb_contains(mod, shp);

	min = 0;
	nbb = 0;
	do {
		/*
		 * We have reached end of the array due to the
		 * parent-child relationship, without visiting all
		 * baseboards! so re-iterate..
		 * (or)
		 * All baseboards are visited and their contained
		 * processors are enumerated
		 * (and/or)
		 * More baseboards pending a visit
		 */
		if (nbb > bb_count && notvisited)
			nbb = 0;
		else if (nbb > bb_count && !notvisited)
			break;
		if (stypes[SMB_TYPE_BASEBOARD].ids[nbb].visited ==
		    X86PI_VISITED) {
			nbb++;
			continue;
		}

		/*
		 * Get the Top-most Parent Baseboard, irrespective
		 * of its index in the array of Type-2s
		 * If this Baseboard has no Baseboard parents
		 * place it under the chassis that contains it
		 */
		bb_smbid = x86pi_bb_topparent(shp, nbb, &pnode, &psmbid);
		if (bb_smbid == -1 || pnode == NULL) {
			topo_mod_dprintf(mod,
			    "Failed to get BaseBoard node (%d): parent\n",
			    nbb);
			return (-1);
		}

		if (stypes[SMB_TYPE_BASEBOARD].ids[nbb].id != bb_smbid) {
			for (int i = 0; i < bb_count; i++) {
				if (bb_smbid ==
				    stypes[SMB_TYPE_BASEBOARD].ids[i].id) {
					stypes[SMB_TYPE_BASEBOARD].ids[i].\
					    visited = 1;
					notvisited--;
					break;
				}
			}
		} else {
			stypes[SMB_TYPE_BASEBOARD].ids[nbb].visited = 1;
			notvisited--;
		}

		basebd_node = x86pi_gen_bboard(mod, pnode, shp,
		    bb_smbid, nbb, psmbid);
		if (basebd_node == NULL) {
			topo_mod_dprintf(mod,
			    "Failed to create BaseBoard node (%d)\n", nbb);
			nbb++;
			continue;
		}

		stypes[SMB_TYPE_BASEBOARD].ids[nbb].node = basebd_node;
		/*
		 * Look for contained handles here and if there are
		 * make sure the chip handle below is part of it.
		 */
		ncmp = x86pi_bb_getchips(mod, shp, nbb, bb_count);
		if (ncmp > 0) {
			max = min + ncmp - 1;
			/* make sure the chip enum is loaded */
			topo_mod_dprintf(mod, "%s: loading chip enum\n", f);

			if (topo_mod_load(mod, CHIP, TOPO_VERSION) == NULL) {
				topo_mod_dprintf(mod,
				    "%s: Failed to load %s module: %s\n", f,
				    CHIP, topo_strerror(topo_mod_errno(mod)));
			} else {
				/* create node range */
				topo_mod_dprintf(mod,
				    "%s: chip range %d to %d\n",
				    f, min, max);
				rv = topo_node_range_create(mod, basebd_node,
				    CHIP, min, max);
				if (rv != 0) {
					topo_mod_dprintf(mod,
					    "%s: Failed to create node range: "
					    "%s\n", f,
					    topo_strerror(topo_mod_errno(mod)));
				} else {
					/* call the chip enumerator */
					topo_mod_dprintf(mod, "%s: calling"
					    " chip enum\n", f);
					rv =
					    topo_mod_enumerate(mod, basebd_node,
					    CHIP, CHIP, min, max,
					    &x86pi_smbios);
					min = max + 1;
					if (rv != 0)
						topo_mod_dprintf(mod, "%s:%s"
						    "enumeration failed: \n",
						    f, CHIP);
				}
			}
		}

		/* enumerate the hostbridge node */
		rv = topo_node_range_create(mod, basebd_node, HOSTBRIDGE,
		    0, 255);
		if (rv != 0) {
			topo_mod_dprintf(mod,
			    "%s: Failed to create %s range: %s\n",
			    f, HOSTBRIDGE, topo_mod_errmsg(mod));
			continue;
		}

		smbc = &stypes[SUN_OEM_PCIEXRC];
		smbc->type = SUN_OEM_PCIEXRC;
		x86pi_smb_strcnt(shp, smbc);
		for (i = 0; i < smbc->count; i++) {
			if (smbios_info_pciexrc(shp, smbc->ids[i].id,
			    &hbr) != 0) {
				topo_mod_dprintf(mod,
				    "smbios_info_pciexrc failed: "
				    "id = %d\n", (int)smbc->ids[i].id);
				continue;
			}

			if (hbr.smbpcie_bb != bb_smbid)
				continue;
			rv = x86pi_gen_hbr(mod, basebd_node, shp,
			    smbc->ids[i].id, hbri, &rci);
			if (rv != 0)
				topo_mod_dprintf(mod,
				    "couldn't create hostbridge=%d\n", hbri);
			hbri++;
		}
		nbb++;

	} while (notvisited);

	return (0);
}
