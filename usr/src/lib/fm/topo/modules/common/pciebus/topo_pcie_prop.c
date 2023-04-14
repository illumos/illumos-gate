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
 * Copyright 2023 Oxide Computer Company
 */

#include <fcntl.h>
#include <libdevinfo.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_list.h>
#include <fm/topo_method.h>
#include <fm/topo_hc.h>

#include "topo_pcie_impl.h"

static const topo_pgroup_info_t io_pgroup = {
	.tpi_name = TOPO_PCIE_PGROUP_IO,
	.tpi_namestab = TOPO_STABILITY_PRIVATE,
	.tpi_datastab = TOPO_STABILITY_PRIVATE,
	.tpi_version = 1
};

static const topo_pgroup_info_t pcicfg_pgroup = {
	.tpi_name = TOPO_PCIE_PGROUP_PCI_CFG,
	.tpi_namestab = TOPO_STABILITY_PRIVATE,
	.tpi_datastab = TOPO_STABILITY_PRIVATE,
	.tpi_version = 1
};

static const topo_pgroup_info_t pci_pgroup = {
	.tpi_name = TOPO_PCIE_PGROUP_PCI,
	.tpi_namestab = TOPO_STABILITY_PRIVATE,
	.tpi_datastab = TOPO_STABILITY_PRIVATE,
	.tpi_version = 1
};

static const topo_pgroup_info_t port_pgroup = {
	.tpi_name = TOPO_PCIE_PGROUP_PORT,
	.tpi_namestab = TOPO_STABILITY_PRIVATE,
	.tpi_datastab = TOPO_STABILITY_PRIVATE,
	.tpi_version = 1
};

const topo_pgroup_info_t pcielink_pgroup = {
	.tpi_name = TOPO_PCIE_PGROUP_PCIE_LINK,
	.tpi_namestab = TOPO_STABILITY_PRIVATE,
	.tpi_datastab = TOPO_STABILITY_PRIVATE,
	.tpi_version = 1
};

static const topo_pgroup_info_t pcilink_pgroup = {
	.tpi_name = TOPO_PCIE_PGROUP_PCI_LINK,
	.tpi_namestab = TOPO_STABILITY_PRIVATE,
	.tpi_datastab = TOPO_STABILITY_PRIVATE,
	.tpi_version = 1
};

typedef struct pcie_prop pcie_prop_t;
typedef bool (*f_prop)(topo_mod_t *, pcie_t *, pcie_node_t *, tnode_t *,
    pcie_prop_t *);
typedef struct pcie_prop {
	const topo_pgroup_info_t	*pp_group;
	const char			*pp_di_prop;
	const char			*pp_topo_prop;
	f_prop				pp_func;
} pcie_prop_t;

static bool
devinfostr(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	return (pcie_topo_prop_copy(mod, node->pn_did, tn, prop->pp_group,
	    TOPO_TYPE_STRING, prop->pp_di_prop, prop->pp_topo_prop));
}

static bool
opt_devinfostr(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	(void) devinfostr(mod, pcie, node, tn, prop);
	return (true);
}

static bool
devinfo32(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	return (pcie_topo_prop_copy(mod, node->pn_did, tn, prop->pp_group,
	    TOPO_TYPE_UINT32, prop->pp_di_prop, prop->pp_topo_prop));
}

static bool
opt_devinfo32(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	(void) devinfo32(mod, pcie, node, tn, prop);
	return (true);
}

static bool
devinfo64(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	return (pcie_topo_prop_copy(mod, node->pn_did, tn, prop->pp_group,
	    TOPO_TYPE_UINT64, prop->pp_di_prop, prop->pp_topo_prop));
}

static bool
devinfo64_array(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	return (pcie_topo_prop_copy(mod, node->pn_did, tn, prop->pp_group,
	    TOPO_TYPE_UINT64_ARRAY, prop->pp_di_prop, prop->pp_topo_prop));
}

static bool
opt_devinfo32_array(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node,
    tnode_t *tn, pcie_prop_t *prop)
{
	(void) pcie_topo_prop_copy(mod, node->pn_did, tn, prop->pp_group,
	    TOPO_TYPE_UINT32_ARRAY, prop->pp_di_prop, prop->pp_topo_prop);
	return (true);
}

static bool
devinfobool(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node,
    tnode_t *tn, pcie_prop_t *prop)
{
	bool val =  pcie_devinfo_getbool(mod, node->pn_did, prop->pp_di_prop);

	return (pcie_topo_prop_set32(mod, tn, prop->pp_group,
	    prop->pp_topo_prop, val ? 1 : 0));
}

/* io properties */

static bool
set_devpath(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	return (pcie_topo_prop_setstr(mod, tn, prop->pp_group,
	    prop->pp_topo_prop, node->pn_path));
}

static bool
set_driver(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	if (node->pn_drvname == NULL)
		return (true);

	return (pcie_topo_prop_setstr(mod, tn, prop->pp_group,
	    prop->pp_topo_prop, node->pn_drvname));
}

static bool
set_instance(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	if (node->pn_drvname == NULL)
		return (true);

	return (pcie_topo_prop_set64(mod, tn, prop->pp_group,
	    prop->pp_topo_prop, node->pn_drvinst));
}

static pcie_prop_t io_props[] = {
	{ &io_pgroup, NULL, TOPO_PCIE_IO_DEV_PATH, set_devpath },
	{ &io_pgroup, NULL, TOPO_PCIE_IO_DRIVER, set_driver },
	{ &io_pgroup, NULL, TOPO_PCIE_IO_INSTANCE, set_instance },
};

/* link properties */

static bool
link_state(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	const char *val;

	switch (topo_pcie_link_status(mod, node)) {
	case PCI_LINK_UP:
		val = TOPO_PCIE_LINK_UP_STR;
		break;
	case PCI_LINK_DOWN:
		val = TOPO_PCIE_LINK_DOWN_STR;
		break;
	default:
		/* Omit the property if link status is unknown */
		return (true);
	}

	return (pcie_topo_prop_setstr(mod, tn, prop->pp_group,
	    prop->pp_topo_prop, val));
}

static bool
link_targspeed(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	if (!pcie_devinfo_getbool(mod, node->pn_did, DI_PCIE_ADMIN_TAG))
		return (true);

	return (devinfo64(mod, pcie, node, tn, prop));
}

static pcie_prop_t pcie_link_props[] = {
	{ &pcielink_pgroup, NULL, TOPO_PCIE_LINK_STATE, link_state },
	{ &pcielink_pgroup, DI_PCIE_CUR_SPEED, TOPO_PCIE_LINK_CUR_SPEED,
	    devinfo64 },
	{ &pcielink_pgroup, DI_PCIE_CUR_WIDTH, TOPO_PCIE_LINK_CUR_WIDTH,
	    devinfo32 },
	{ &pcielink_pgroup, DI_PCIE_MAX_SPEED, TOPO_PCIE_LINK_MAX_SPEED,
	    devinfo64 },
	{ &pcielink_pgroup, DI_PCIE_MAX_WIDTH, TOPO_PCIE_LINK_MAX_WIDTH,
	    devinfo32 },
	{ &pcielink_pgroup, DI_PCIE_SUP_SPEEDS, TOPO_PCIE_LINK_SUP_SPEED,
	    devinfo64_array },
	{ &pcielink_pgroup, DI_PCIE_TARG_SPEED, TOPO_PCIE_LINK_ADMIN_SPEED,
	    link_targspeed },
};

static pcie_prop_t pci_link_props[] = {
	{ &pcilink_pgroup, NULL, TOPO_PCIE_LINK_STATE, link_state },
	{ &pcilink_pgroup, DI_PCI_66MHZ_CAPABLE, TOPO_PCIE_LINK_66MHZ_CAPABLE,
	    devinfobool },
};

/* link methods */

static int
topo_pcie_link_unusable(topo_mod_t *mod, tnode_t *tn, topo_version_t ver,
    nvlist_t *in, nvlist_t **out)
{
	pcie_node_t *node = topo_node_getspecific(tn);
	nvlist_t *nvl;
	uint32_t unusable;

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	unusable = 1;
	if (node != NULL && topo_pcie_link_status(mod, node) == PCI_LINK_UP)
		unusable = 0;

	if (nvlist_add_uint32(nvl, TOPO_METH_UNUSABLE_RET, unusable) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*out = nvl;

	return (0);
}

static const topo_method_t link_methods[] = {
	{
		.tm_name = TOPO_METH_UNUSABLE,
		.tm_desc = TOPO_METH_UNUSABLE_DESC,
		.tm_version = TOPO_METH_UNUSABLE_VERSION,
		.tm_stability = TOPO_STABILITY_INTERNAL,
		.tm_func = topo_pcie_link_unusable
	},
	{ .tm_name = NULL }
};

/* pci properties */

static bool
set_bdf(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	int32_t *val;
	int nval;

	if (node->pn_type == PCIE_NODE_ROOTNEXUS)
		return (true);

	nval = di_prop_lookup_ints(DDI_DEV_T_ANY, node->pn_did,
	    prop->pp_di_prop, &val);
	if (nval < 1)
		return (true);

	return (
	    pcie_topo_prop_set32(mod, tn, prop->pp_group,
	    TOPO_PCIE_PCI_BUS, PCI_REG_BUS_G(val[0])) &&
	    pcie_topo_prop_set32(mod, tn, prop->pp_group,
	    TOPO_PCIE_PCI_DEVICE, PCI_REG_DEV_G(val[0])) &&
	    pcie_topo_prop_set32(mod, tn, prop->pp_group,
	    TOPO_PCIE_PCI_FUNCTION, PCI_REG_FUNC_G(val[0])) &&
	    pcie_topo_prop_set32(mod, tn, prop->pp_group,
	    TOPO_PCIE_PCI_SEGMENT, 0));
}

static bool
set_pci_type(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	return (pcie_topo_prop_setstr(mod, tn, prop->pp_group,
	    prop->pp_topo_prop, pcie_type_name(node->pn_type)));
}

static bool
set_class(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	if (node->pn_class == 0)
		return (true);

	return (pcie_topo_prop_set32(mod, tn, prop->pp_group,
	    TOPO_PCIE_PCI_CLASS, node->pn_class) &&
	    pcie_topo_prop_set32(mod, tn, prop->pp_group,
	    TOPO_PCIE_PCI_SUBCLASS, node->pn_subclass) &&
	    pcie_topo_prop_set32(mod, tn, prop->pp_group,
	    TOPO_PCIE_PCI_INTERFACE, node->pn_intf));
}

static bool
set_pcidb(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	int32_t vid, devid, ssvid, ssdevid;
	pcidb_vendor_t *pciv;
	pcidb_device_t *pcid;
	pcidb_subvd_t *pcis;
	di_node_t did = node->pn_did;

	if (pcie->tp_pcidb_hdl == NULL)
		goto out;

	vid = pcie_devinfo_get32(mod, did, DI_VENDIDPROP);
	devid = pcie_devinfo_get32(mod, did, DI_DEVIDPROP);
	ssvid = pcie_devinfo_get32(mod, did, DI_SUBVENDIDPROP);
	ssdevid = pcie_devinfo_get32(mod, did, DI_SUBSYSTEMID);

	if (vid == -1)
		goto out;

	pciv = pcidb_lookup_vendor(pcie->tp_pcidb_hdl, (uint16_t)vid);
	if (pciv == NULL)
		goto out;
	(void) pcie_topo_prop_setstr(mod, tn, prop->pp_group,
	    TOPO_PCIE_PCI_VENDOR_NAME, pcidb_vendor_name(pciv));

	if (devid == -1)
		goto out;

	pcid = pcidb_lookup_device_by_vendor(pciv, (uint16_t)devid);
	if (pcid == NULL)
		goto out;
	(void) pcie_topo_prop_setstr(mod, tn, prop->pp_group,
	    TOPO_PCIE_PCI_DEV_NAME, pcidb_device_name(pcid));

	if (ssvid == -1 || ssdevid == -1 || ssvid == 0 || ssdevid == 0)
		goto out;

	pcis = pcidb_lookup_subvd_by_device(pcid, (uint16_t)ssvid,
	    (uint16_t)ssdevid);
	if (pcis == NULL)
		goto out;
	(void) pcie_topo_prop_setstr(mod, tn, prop->pp_group,
	    TOPO_PCIE_PCI_SUBSYSTEM_NAME, pcidb_subvd_name(pcis));

out:
	/*
	 * We always return success here, even if one or more of the lookups
	 * failed, or if the we don't have an open database handle.
	 */
	return (true);
}

static bool
set_busrange(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node, tnode_t *tn,
    pcie_prop_t *prop)
{
	int32_t *val;
	int nval;
	uint32_t arr[3];

	nval = di_prop_lookup_ints(DDI_DEV_T_ANY, node->pn_did,
	    prop->pp_di_prop, &val);
	if (nval != 2)
		return (true);

	arr[0] = val[0];
	arr[1] = val[1];

	return (pcie_topo_prop_set32_array(mod, tn, prop->pp_group,
	    prop->pp_topo_prop, arr, 2));
}

static pcie_prop_t pci_props[] = {
	/* io */
	{ &io_pgroup, NULL, TOPO_PCIE_IO_DEV_PATH, set_devpath },
	{ &io_pgroup, NULL, TOPO_PCIE_IO_DRIVER, set_driver },
	{ &io_pgroup, NULL, TOPO_PCIE_IO_INSTANCE, set_instance },
	{ &io_pgroup, DI_DEVTYPPROP, TOPO_PCIE_IO_DEVTYPE, opt_devinfostr },

	/* pci-cfg */
	{ &pcicfg_pgroup, DI_REGPROP, NULL, set_bdf },
	{ &pcicfg_pgroup, DI_BUSRANGE, TOPO_PCIE_PCI_BUS_RANGE, set_busrange },
	{ &pcicfg_pgroup, DI_AADDRPROP, TOPO_PCIE_PCI_ASSIGNED_ADDR,
	    opt_devinfo32_array }, // XXX - decode further?

	/* pci */
	{ &pci_pgroup, NULL, TOPO_PCIE_PCI_TYPE, set_pci_type },
	{ &pci_pgroup, NULL, NULL, set_class },
	{ &pci_pgroup, DI_MODELNAME, TOPO_PCIE_PCI_CLASS_STRING,
	    opt_devinfostr },
	{ &pci_pgroup, DI_VENDIDPROP, TOPO_PCIE_PCI_VENDOR_ID, opt_devinfo32 },
	{ &pci_pgroup, DI_DEVIDPROP, TOPO_PCIE_PCI_DEV_ID, opt_devinfo32 },
	{ &pci_pgroup, DI_SUBVENDIDPROP, TOPO_PCIE_PCI_SSVENDORID,
	    opt_devinfo32 },
	{ &pci_pgroup, DI_SUBSYSTEMID, TOPO_PCIE_PCI_SSID, opt_devinfo32 },
	{ &pci_pgroup, DI_REVIDPROP, TOPO_PCIE_PCI_REVID, opt_devinfo32 },
	{ &pci_pgroup, DI_PHYSPROP, TOPO_PCIE_PCI_SLOT, opt_devinfo32 },
	{ &pci_pgroup, NULL, NULL, set_pcidb },
};

static bool
pcie_apply_props(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node,
    tnode_t *tn, pcie_prop_t props[], size_t num)
{
	bool ret = true;

	for (size_t i = 0; i < num; i++) {
		pcie_prop_t *p = &props[i];

		if (p->pp_group != NULL &&
		    !pcie_topo_pgroup_create(mod, tn, p->pp_group)) {
			return (false);
		}

		if (!p->pp_func(mod, pcie, node, tn, p))
			ret = false;
	}

	return (ret);
}

bool
topo_pcie_set_io_props(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node,
    tnode_t *tn)
{
	return (pcie_apply_props(mod, pcie, node, tn, io_props,
	    ARRAY_SIZE(io_props)));
}

bool
topo_pcie_set_pci_props(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node,
    tnode_t *tn)
{
	return (pcie_apply_props(mod, pcie, node, tn, pci_props,
	    ARRAY_SIZE(pci_props)));
}

bool
topo_pcie_set_port_props(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node,
    tnode_t *tn, topo_port_type_t type)
{
	const topo_pgroup_info_t *pg = &port_pgroup;

	if (!pcie_topo_pgroup_create(mod, tn, pg))
		return (false);

	return (pcie_topo_prop_setstr(mod, tn, pg, TOPO_PCIE_PORT_TYPE,
	    type == TOPO_PORT_DOWNSTREAM ? TOPO_PCIE_PORT_TYPE_DS :
	    TOPO_PCIE_PORT_TYPE_US));
}

bool
topo_pcie_set_link_props(topo_mod_t *mod, pcie_t *pcie, pcie_node_t *node,
    tnode_t *tn)
{
	bool ret = false;

	switch (node->pn_type) {
	case PCIE_NODE_PCI_DEV:
	case PCIE_NODE_PCIE_PCI:
		ret = pcie_apply_props(mod, pcie, node, tn, pci_link_props,
		    ARRAY_SIZE(pci_link_props));
		break;
	default:
		ret = pcie_apply_props(mod, pcie, node, tn, pcie_link_props,
		    ARRAY_SIZE(pcie_link_props));
		break;
	}

	if (topo_method_register(mod, tn, link_methods) != 0) {
		topo_mod_dprintf(mod, "failed to register link methods: %s",
		    topo_mod_errmsg(mod));
		ret = false;
	}

	return (ret);
}
