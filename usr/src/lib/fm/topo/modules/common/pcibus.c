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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fm/protocol.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>
#include <sys/param.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <libdevinfo.h>
#include <libnvpair.h>
#include <fm/topo_mod.h>

#include "hostbridge.h"
#include "pcibus.h"
#include "did.h"
#include "did_props.h"
#include "util.h"

extern txprop_t Bus_common_props[];
extern txprop_t Dev_common_props[];
extern txprop_t Fn_common_props[];
extern int Bus_propcnt;
extern int Dev_propcnt;
extern int Fn_propcnt;

extern int platform_pci_label(tnode_t *, nvlist_t *, nvlist_t **);

di_prom_handle_t Promtree = DI_PROM_HANDLE_NIL;
topo_mod_t *PciHdl;

static void pci_release(topo_mod_t *, tnode_t *);
static int pci_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *);
static int pci_contains(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int pci_present(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int pci_label(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);

const topo_modinfo_t Pci_info =
	{ PCI_BUS, PCI_ENUMR_VERS, pci_enum, pci_release };

const topo_method_t Pci_methods[] = {
	{ "pci_contains", "pci element contains other element", PCI_ENUMR_VERS,
	    TOPO_STABILITY_INTERNAL, pci_contains },
	{ "pci_present", "pci element currently present", PCI_ENUMR_VERS,
	    TOPO_STABILITY_INTERNAL, pci_present },
	{ TOPO_METH_LABEL, TOPO_METH_LABEL_DESC,
	    TOPO_METH_LABEL_VERSION, TOPO_STABILITY_INTERNAL, pci_label },
	{ NULL }
};

static did_hash_t *Didhash;

void
_topo_init(topo_mod_t *modhdl)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOPCIDBG") != NULL)
		topo_mod_setdebug(modhdl, TOPO_DBG_ALL);
	topo_mod_dprintf(modhdl, "initializing pcibus builtin\n");

	if ((Promtree = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		topo_mod_dprintf(modhdl,
		    "Pcibus enumerator: di_prom_handle_init failed.\n");
		return;
	}
	PciHdl = modhdl;
	topo_mod_register(PciHdl, &Pci_info, NULL);
	topo_mod_dprintf(PciHdl, "PCI Enumr initd\n");
}

void
_topo_fini(topo_mod_t *modhdl)
{
	di_prom_fini(Promtree);
	topo_mod_unregister(modhdl);
}

/*ARGSUSED*/
static int
pci_contains(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (0);
}

/*ARGSUSED*/
static int
pci_present(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (0);
}

static int
pci_label(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_LABEL_VERSION)
		return (topo_mod_seterrno(mp, EMOD_VER_NEW));
	return (platform_pci_label(node, in, out));
}

static tnode_t *
pci_tnode_create(tnode_t *parent,
    const char *name, topo_instance_t i, void *priv)
{
	tnode_t *ntn;

	if ((ntn = tnode_create(PciHdl, parent, name, i, priv)) == NULL)
		return (NULL);
	if (topo_method_register(PciHdl, ntn, Pci_methods) < 0) {
		topo_mod_dprintf(PciHdl, "topo_method_register failed: %s\n",
		    topo_strerror(topo_mod_errno(PciHdl)));
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

/*ARGSUSED*/
static int
hostbridge_asdevice(tnode_t *bus)
{
	did_t *pd;
	di_node_t di;
	tnode_t *dev32;

	pd = topo_node_private(bus);
	assert(pd != NULL);
	di = did_dinode(pd);
	assert(di != DI_NODE_NIL);

	if ((dev32 = pcidev_declare(bus, di, 32)) == NULL)
		return (-1);
	if (pcifn_declare(dev32, di, 0) == NULL)
		return (-1);
	return (0);
}

tnode_t *
pciexfn_declare(tnode_t *parent, di_node_t dn, topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(Didhash, dn)) == NULL)
		return (NULL);
	if ((ntn = pci_tnode_create(parent, PCIEX_FUNCTION, i, pd)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, Fn_common_props, Fn_propcnt) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We may find pci-express buses or plain-pci buses beneath a function
	 */
	if (child_range_add(PciHdl, ntn, PCIEX_BUS, 0, MAX_HB_BUSES) < 0) {
		topo_node_range_destroy(ntn, PCIEX_BUS);
		return (NULL);
	}
	if (child_range_add(PciHdl, ntn, PCI_BUS, 0, MAX_HB_BUSES) < 0) {
		topo_node_range_destroy(ntn, PCI_BUS);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pciexdev_declare(tnode_t *parent, di_node_t dn, topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(Didhash, dn)) == NULL)
		return (NULL);
	if ((ntn = pci_tnode_create(parent, PCIEX_DEVICE, i, pd)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, Dev_common_props, Dev_propcnt) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We can expect to find pci-express functions beneath the device
	 */
	if (child_range_add(PciHdl,
	    ntn, PCIEX_FUNCTION, 0, MAX_PCIDEV_FNS) < 0) {
		topo_node_range_destroy(ntn, PCIEX_FUNCTION);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pciexbus_declare(tnode_t *parent, di_node_t dn, topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(Didhash, dn)) == NULL)
		return (NULL);
	if ((ntn = pci_tnode_create(parent, PCIEX_BUS, i, pd)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, Bus_common_props, Bus_propcnt) < 0) {
		topo_node_range_destroy(ntn, PCI_DEVICE);
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We can expect to find pci-express devices beneath the bus
	 */
	if (child_range_add(PciHdl,
	    ntn, PCIEX_DEVICE, 0, MAX_PCIBUS_DEVS) < 0) {
		topo_node_range_destroy(ntn, PCIEX_DEVICE);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pcifn_declare(tnode_t *parent, di_node_t dn, topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(Didhash, dn)) == NULL)
		return (NULL);
	if ((ntn = pci_tnode_create(parent, PCI_FUNCTION, i, pd)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, Fn_common_props, Fn_propcnt) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We may find pci buses beneath a function
	 */
	if (child_range_add(PciHdl, ntn, PCI_BUS, 0, MAX_HB_BUSES) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pcidev_declare(tnode_t *parent, di_node_t dn, topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(Didhash, dn)) == NULL)
		return (NULL);
	if ((ntn = pci_tnode_create(parent, PCI_DEVICE, i, pd)) == NULL)
		return (NULL);
	/*
	 * If our devinfo node is lacking certain information of its
	 * own, we may need/want to inherit the information available
	 * from our parent node's private data.
	 */
	did_inherit(parent, ntn);
	if (did_props_set(ntn, pd, Dev_common_props, Dev_propcnt) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We can expect to find pci functions beneath the device
	 */
	if (child_range_add(PciHdl, ntn, PCI_FUNCTION, 0, MAX_PCIDEV_FNS) < 0) {
		topo_node_range_destroy(ntn, PCI_FUNCTION);
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pcibus_declare(tnode_t *parent, di_node_t dn, topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn;
	int hbchild = 0;

	if ((pd = did_find(Didhash, dn)) == NULL)
		return (NULL);
	if ((ntn = pci_tnode_create(parent, PCI_BUS, i, pd)) == NULL)
		return (NULL);
	/*
	 * If our devinfo node is lacking certain information of its
	 * own, and our parent topology node is a hostbridge, we may
	 * need/want to inherit information available in the
	 * hostbridge node's private data.
	 */
	if (strcmp(topo_node_name(parent), HOSTBRIDGE) == 0)
		hbchild = 1;
	if (did_props_set(ntn, pd, Bus_common_props, Bus_propcnt) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We can expect to find pci devices beneath the bus
	 */
	if (child_range_add(PciHdl, ntn, PCI_DEVICE, 0, MAX_PCIBUS_DEVS) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * On each bus child of the hostbridge, we represent the
	 * hostbridge as a device outside the range of legal device
	 * numbers.
	 */
	if (hbchild == 1) {
		if (hostbridge_asdevice(ntn) < 0) {
			topo_node_range_destroy(ntn, PCI_DEVICE);
			topo_node_unbind(ntn);
			return (NULL);
		}
	}
	return (ntn);
}

static int
declare_dev_and_fn(tnode_t *bus, tnode_t **dev, di_node_t din,
    int board, int bridge, int rc, int devno, int fnno, int depth)
{
	tnode_t *fn;
	uint_t class, subclass;
	int err;

	if (*dev == NULL) {
		if (rc >= 0)
			*dev = pciexdev_declare(bus, din, devno);
		else
			*dev = pcidev_declare(bus, din, devno);
		if (*dev == NULL)
			return (-1);
	}
	if (rc >= 0)
		fn = pciexfn_declare(*dev, din, fnno);
	else
		fn = pcifn_declare(*dev, din, fnno);
	if (fn == NULL)
		return (-1);
	if (pci_classcode_get(Didhash, din, &class, &subclass) < 0)
		return (-1);
	if (class == PCI_CLASS_BRIDGE && subclass == PCI_BRIDGE_PCI) {
		int excap, extyp;

		excap = pciex_cap_get(Didhash, din);
		extyp = excap & PCIE_PCIECAP_DEV_TYPE_MASK;
		if (excap <= 0 ||
		    extyp != PCIE_PCIECAP_DEV_TYPE_PCIE2PCI)
			err = pci_children_instantiate(fn,
			    din, board, bridge, rc, TRUST_BDF, depth + 1);
		else
			err = pci_children_instantiate(fn,
			    din, board, bridge, rc - TO_PCI,
			    TRUST_BDF, depth + 1);
		if (err < 0)
			return (-1);
	}
	return (0);
}

int
pci_children_instantiate(tnode_t *parent, di_node_t pn,
    int board, int bridge, int rc, int bover, int depth)
{
	did_t *pps[MAX_PCIBUS_DEVS][MAX_PCIDEV_FNS];
	did_t *bp = NULL;
	did_t *np;
	di_node_t sib;
	di_node_t din;
	tnode_t *bn = NULL;
	tnode_t *dn = NULL;
	int pb = -1;
	int b, d, f;

	for (d = 0; d < MAX_PCIBUS_DEVS; d++)
		for (f = 0; f < MAX_PCIDEV_FNS; f++)
			pps[d][f] = NULL;

	/* start at the parent's first sibling */
	sib = di_child_node(pn);
	while (sib != DI_NODE_NIL) {
		np = did_create(Didhash, sib, board, bridge, rc, bover);
		if (np == NULL)
			return (-1);
		did_BDF(np, &b, &d, &f);
		pps[d][f] = np;
		if (bp == NULL)
			bp = np;
		if (pb < 0)
			pb = ((bover == TRUST_BDF) ? b : bover);
		sib = di_sibling_node(sib);
	}
	if (pb < 0 && bover < 0)
		return (0);
	if (rc >= 0)
		bn = pciexbus_declare(parent, pn, ((pb < 0) ? bover : pb));
	else
		bn = pcibus_declare(parent, pn, ((pb < 0) ? bover : pb));
	if (bn == NULL)
		return (-1);
	if (pb < 0)
		return (0);

	for (d = 0; d < MAX_PCIBUS_DEVS; d++) {
		for (f = 0; f < MAX_PCIDEV_FNS; f++) {
			if (pps[d][f] == NULL)
				continue;
			din = did_dinode(pps[d][f]);
			if ((declare_dev_and_fn(bn,
			    &dn, din, board, bridge, rc, d, f, depth)) != 0)
				return (-1);
			did_rele(pps[d][f]);
		}
		dn = NULL;
	}
	return (0);
}

/*ARGSUSED*/
static int
pci_enum(topo_mod_t *ignored, tnode_t *troot, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused)
{
	did_t *hbdid, *didp;
	char *pname;

	topo_mod_dprintf(PciHdl, "Enumerating pci!\n");

	if (strcmp(name, PCI_BUS) != 0 && strcmp(name, PCIEX_BUS) != 0) {
		topo_mod_dprintf(PciHdl,
		    "Currently only know how to enumerate %s or %s not %s.\n",
		    PCI_BUS, PCIEX_BUS, name);
		return (0);
	}
	pname = topo_node_name(troot);
	if (strcmp(pname, HOSTBRIDGE) != 0 && strcmp(pname, PCIEX_ROOT) != 0) {
		topo_mod_dprintf(PciHdl,
		    "Currently can only enumerate a %s or %s directly\n",
		    PCI_BUS, PCIEX_BUS);
		topo_mod_dprintf(PciHdl,
		    "descended from a %s or %s node.\n",
		    HOSTBRIDGE, PCIEX_ROOT);
		return (0);
	}
	if ((hbdid = topo_node_private(troot)) == NULL) {
		topo_mod_dprintf(PciHdl,
		    "Parent %s node missing private data.\n"
		    "Unable to proceed with %s enumeration.\n",
		    pname, name);
		return (0);
	}
	Didhash = did_hash(hbdid);
	/*
	 * If we're looking for a specific bus-instance, find the right
	 * did_t in the chain, otherwise, there should be only one did_t.
	 * Cache the did_t of interest in *this* enumerator's cache.
	 */
	if (min == max) {
		int b;
		didp = hbdid;
		while (didp != NULL) {
			did_BDF(didp, &b, NULL, NULL);
			if (b == min)
				break;
			didp = did_link_get(didp);
		}
		if (didp == NULL) {
			topo_mod_dprintf(PciHdl,
			    "Parent %s node missing private data related\n"
			    "to %s instance %d.\n", pname, name, min);
			return (0);
		}
	} else {
		assert(did_link_get(hbdid) == NULL);
		didp = hbdid;
	}
	return (pci_children_instantiate(troot, did_dinode(didp),
	    did_board(didp), did_bridge(didp), did_rc(didp),
	    (min == max) ? min : TRUST_BDF, 0));
}

/*ARGSUSED*/
static void
pci_release(topo_mod_t *mp, tnode_t *node)
{
	topo_method_unregister_all(mp, node);

	/*
	 * node private data (did_t) for this node is destroyed in
	 * did_hash_destroy()
	 */

	topo_node_unbind(node);
}
