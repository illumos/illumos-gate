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

/*
 * i86pc Generic hostbridge/pciex/pci enumerator
 *
 * hostbridge/pciexrc/pcibus topo nodes are created per SMBIOS type 138
 * (SUN_OEM_PCIEXRC) records.   Each type 138 record can either represent
 * a hostbridge or a pciexrc/pcibus determined by whether it points to
 * a baseboard record or another type 138 record.
 *
 * x86pi_gen_hbr() is called when a new hostbridge node needs to be created..
 * It then searches all the type 138 records that connected to it.  For each
 * of the records, bdf is compared to find a matching di_node.  If the
 * di_node is a pciex root port, a pciexrc (bad name!) node will be created.
 * When pciexrc creation is done, or the di_node is a pcibus, in either
 * case the pcibus module will loaded to enumerate pciexbus/pcibus etc.
 *
 * The enumeration uses did routines heavily, which requires a did hash
 * pointer stored in x86pi's module-specific area.
 */

#include <sys/types.h>
#include <strings.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <sys/systeminfo.h>
#include <sys/smbios_impl.h>
#include <sys/fm/protocol.h>
#include <x86pi_impl.h>
#include <did.h>
#include <did_impl.h>
#include <did_props.h>
#include <hostbridge.h>

#define	PCI_ENUM	"pcibus"
#define	PCI_ENUMR_VERS	1
#define	MAX_HB_BUSES	255

extern txprop_t RC_common_props[], HB_common_props[], ExHB_common_props[];
extern int RC_propcnt, HB_propcnt, ExHB_propcnt;

static topo_mod_t *pcimp = NULL;

int
x86pi_hbr_enum_init(topo_mod_t *mod)
{
	const char *f = "x86pi_hbr_enum_init";

	if (did_hash_init(mod) < 0) {
		topo_mod_dprintf(mod, "%s: did_hash_init() failed.\n", f);
		return (-1);
	}

	if ((pcimp = topo_mod_load(mod, PCI_ENUM, PCI_ENUMR_VERS)) == NULL) {
		topo_mod_dprintf(mod,
		    "%s: %s enumerator could not load %s.\n",
		    f, HOSTBRIDGE, PCI_ENUM);
		did_hash_fini(mod);
		return (-1);
	}

	return (0);
}

void
x86pi_hbr_enum_fini(topo_mod_t *mod)
{
	did_hash_fini(mod);
	topo_mod_unload(pcimp);
	pcimp = NULL;
}

static int
pciex_process(topo_mod_t *mod, tnode_t *tn_hbr, di_node_t rcn,
    topo_instance_t rci)
{
	did_t		*did;
	int		rv;
	tnode_t		*tn_rc;
	x86pi_hcfmri_t	hcfmri = {0};
	tnode_t		*tn_bb = topo_node_parent(tn_hbr);
	const char	*f = "pciexrc_process";

	if ((did = did_create(mod, rcn, topo_node_instance(tn_bb),
	    topo_node_instance(tn_hbr), rci, TRUST_BDF)) == NULL)
		return (-1);

	did_markrc(did);

	/*
	 * Let did set the hostbridge properties excluding FRU and label.
	 */
	(void) did_props_set(tn_hbr, did, ExHB_common_props, ExHB_propcnt - 2);

	if (topo_node_range_create(mod, tn_hbr, PCIEX_ROOT, 0,
	    MAX_HB_BUSES) != 0 && topo_mod_errno(mod) != EMOD_NODE_DUP) {
		topo_mod_dprintf(mod,
		    "%s: create child range for %s failed: %s\n",
		    f, PCIEX_ROOT, topo_mod_errmsg(mod));
		return (-1);
	}

	hcfmri.hc_name = PCIEX_ROOT;
	hcfmri.instance = rci;
	rv = x86pi_enum_generic(mod, &hcfmri, tn_hbr, tn_hbr, &tn_rc, 0);
	if (rv != 0) {
		topo_mod_dprintf(mod, "%s: failed to create %s = %" PRIu64 "\n",
		    f, PCIEX_ROOT, rci);
		return (-1);
	}

	/*
	 * pcibus enumerator requires di_node_t be set in node specific
	 */
	topo_node_setspecific(tn_rc, rcn);

	/*
	 * Let did set the RC properties excluding FRU, and label.
	 */
	if (did_props_set(tn_rc, did, RC_common_props, RC_propcnt - 2) < 0) {
		topo_mod_dprintf(mod, "%s: did_props_set failed for %s = %"
		    PRIu64 "\n", f, PCIEX_ROOT, rci);
		topo_node_unbind(tn_rc);
		return (-1);
	}

	if (topo_node_range_create(mod, tn_rc, PCIEX_BUS, 0,
	    MAX_HB_BUSES) != 0 && topo_mod_errno(mod) != EMOD_NODE_DUP) {
		topo_mod_dprintf(mod,
		    "%s: create child range for %s failed: %s\n",
		    f, PCIEX_BUS, topo_mod_errmsg(mod));
		return (-1);
	}

	return (topo_mod_enumerate(mod, tn_rc, PCI_BUS, PCIEX_BUS,
	    0, MAX_HB_BUSES, did));
}

static int
pci_process(topo_mod_t *mod, tnode_t *tn_hbr, di_node_t bn)
{
	did_t *did;
	tnode_t *tn_bb = topo_node_parent(tn_hbr);

	if ((did = did_create(mod, bn, topo_node_instance(tn_bb),
	    topo_node_instance(tn_hbr), NO_RC, TRUST_BDF)) == NULL)
		return (-1);

	/*
	 * Let did set the hostbridge properties excluding FRU and label.
	 */
	(void) did_props_set(tn_hbr, did, HB_common_props, HB_propcnt - 2);

	if (topo_node_range_create(mod, tn_hbr, PCI_BUS, 0,
	    MAX_HB_BUSES) != 0 && topo_mod_errno(mod) != EMOD_NODE_DUP) {
		topo_mod_dprintf(mod, "create child range for %s failed: %s\n",
		    PCI_BUS, topo_mod_errmsg(mod));
		return (-1);
	}

	return (topo_mod_enumerate(mod, tn_hbr, PCI_BUS, PCI_BUS,
	    0, MAX_HB_BUSES, did));
}

static int
x86pi_gen_pci_pciexrc(topo_mod_t *mod, tnode_t *tn_hbr, uint16_t bdf,
    topo_instance_t *rcip)
{
	di_node_t devtree, pnode, cnode;

	topo_mod_dprintf(mod, "creating pci/pciexrc node bdf = %#x\n",
	    (int)bdf);

	devtree = topo_mod_devinfo(mod);
	if (devtree == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "devinfo init failed.\n");
		return (-1);
	}

	for (pnode = di_drv_first_node(PCI, devtree);
	    pnode != DI_NODE_NIL; pnode = di_drv_next_node(pnode))
		if (x86pi_bdf(mod, pnode) == bdf)
			return (pci_process(mod, tn_hbr, pnode));

	pnode = di_drv_first_node(NPE, devtree);
	while (pnode != DI_NODE_NIL) {
		for (cnode = di_child_node(pnode); cnode != DI_NODE_NIL;
		    cnode = di_sibling_node(cnode)) {
			if (di_driver_name(cnode) == NULL ||
			    x86pi_bdf(mod, cnode) != bdf)
				continue;

			if (strcmp(di_driver_name(cnode), PCI_PCI) == 0)
				return (pci_process(mod, tn_hbr, cnode));

			if (strcmp(di_driver_name(cnode), PCIEB) == 0)
				return (pciex_process(mod, tn_hbr,
				    cnode, (*rcip)++));

			topo_mod_dprintf(mod, "no matching driver found: "
			    "bdf = %#x\n", (int)bdf);
		}
		pnode = di_drv_next_node(pnode);
	}

	topo_mod_dprintf(mod, "no matching bdf found: bdf = %#x\n", (int)bdf);

	return (0);
}

int
x86pi_gen_hbr(topo_mod_t *mod, tnode_t *tn_bb,
    int hbr_smbid, topo_instance_t hbri, topo_instance_t *rcip)
{
	x86pi_hcfmri_t	hcfmri = {0};
	tnode_t		*tn_hbr;
	smbs_cnt_t	*smbc = &stypes[SUN_OEM_PCIEXRC];
	smbios_pciexrc_t smb_rc;
	int		i, rv, err = 0;
	const char	*f = "x86pi_gen_hbr";
	smbios_hdl_t	*shp;

	shp = topo_mod_smbios(mod);
	if (shp == NULL)
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));

	hcfmri.hc_name = HOSTBRIDGE;
	hcfmri.instance = hbri;

	/* create and bind the "hostbridge" node */
	rv = x86pi_enum_generic(mod, &hcfmri, tn_bb, tn_bb, &tn_hbr, 0);
	if (rv != 0) {
		topo_mod_dprintf(mod, "%s: failed to create %s = %" PRIu64 "\n",
		    f, HOSTBRIDGE, hbri);
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}

	/*
	 * Walk the smbios records and create the pci/pciexrc nodes
	 */
	for (i = 0; i < smbc->count; i++) {
		if (smbios_info_pciexrc(shp, smbc->ids[i].id, &smb_rc) != 0)
			topo_mod_dprintf(mod,
			    "%s: failed: id = %d\n", f, (int)smbc->ids[i].id);
		else if (smb_rc.smbpcie_bb == hbr_smbid &&
		    x86pi_gen_pci_pciexrc(mod, tn_hbr, smb_rc.smbpcie_bdf,
		    rcip) != 0)
			err++;
	}

	return (err == 0 ? 0 : topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
}
