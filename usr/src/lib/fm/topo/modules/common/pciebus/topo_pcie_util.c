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

#include <stdbool.h>
#include <string.h>

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_list.h>
#include <fm/topo_method.h>

#include "topo_pcie_impl.h"

const char *
pcie_type_name(pcie_node_type_t type)
{
	switch (type) {
	case PCIE_NODE_ROOTNEXUS:
		return ("root-complex");
	case PCIE_NODE_ROOTPORT:
		return ("root-port");
	case PCIE_NODE_PCI_DEV:
		return ("pci");
	case PCIE_NODE_PCIE_DEV:
		return ("pcie");
	case PCIE_NODE_SWITCH_UP:
		return ("upstream-switch");
	case PCIE_NODE_SWITCH_DOWN:
		return ("downstream-switch");
	case PCIE_NODE_PCIE_PCI:
		return ("pcie-pci-bridge");
	case PCIE_NODE_PCI_PCIE:
		return ("pci-pcie-bridge");
	default:
		return ("unhandled type name");
	}
}

uint_t
pcie_speed2gen(int64_t speed)
{
	switch (speed) {
	case 2500000000LL:
		return (1);
	case 5000000000LL:
		return (2);
	case 8000000000LL:
		return (3);
	case 16000000000LL:
		return (4);
	case 32000000000LL:
		return (5);
	default:
		break;
	}
	return (0);
}

const char *
pcie_speed2str(int64_t speed)
{
	switch (speed) {
	case 2500000000LL:
		return ("2.5");
	case 5000000000LL:
		return ("5.0");
	case 8000000000LL:
		return ("8.0");
	case 16000000000LL:
		return ("16.0");
	case 32000000000LL:
		return ("32.0");
	default:
		break;
	}
	return ("0");
}

bool
pcie_topo_pgroup_create(topo_mod_t *mod, tnode_t *tn,
    const topo_pgroup_info_t *pg)
{
	int err;

	if (topo_pgroup_create(tn, pg, &err) != 0) {
		if (err == ETOPO_PROP_DEFD)
			return (true);
		topo_mod_dprintf(mod, "failed to create property group %s: %s",
		    pg->tpi_name, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		return (false);
	}
	return (true);
}

bool
pcie_topo_range_create(topo_mod_t *mod, tnode_t *tn, const char *name,
    topo_instance_t min, topo_instance_t max)
{
	int err;

	err = topo_node_range_create(mod, tn, name, min, max);
	if (err == EMOD_NODE_DUP)
		return (true);
	if (err != 0) {
		topo_mod_dprintf(mod,
		    "Failed to create range for %s [%"PRIu64",%"PRIu64"]: %s",
		    name, min, max, topo_mod_errmsg(mod));
		return (false);
	}
	return (true);
}

static bool
pcie_topo_prop_set(topo_mod_t *mod, tnode_t *tn, const topo_pgroup_info_t *pg,
    topo_type_t type, const char *name, void *val)
{
	int ret, err;
	/*
	 * All properties are flagged as immutable as they reflect read-only
	 * information derived from the device tree/device.
	 */
	const int flag = TOPO_PROP_IMMUTABLE;

	switch (type) {
	case TOPO_TYPE_UINT32:
		ret = topo_prop_set_uint32(tn, pg->tpi_name, name, flag,
		    *(uint32_t *)val, &err);
		break;
	case TOPO_TYPE_UINT64:
		ret = topo_prop_set_uint64(tn, pg->tpi_name, name, flag,
		    *(uint64_t *)val, &err);
		break;
	case TOPO_TYPE_STRING:
		ret = topo_prop_set_string(tn, pg->tpi_name, name, flag,
		    (char *)val, &err);
		break;
	default:
		topo_mod_dprintf(mod, "%s - unhandled property type %u",
		    __func__, type);
		return (false);
	}

	if (ret != 0) {
		topo_mod_dprintf(mod, "failed to set property %s/%s: %s",
		    pg->tpi_name, name, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		return (false);
	}

	return (true);
}

bool
pcie_topo_prop_set32(topo_mod_t *mod, tnode_t *tn, const topo_pgroup_info_t *pg,
    const char *name, uint32_t val)
{
	return (pcie_topo_prop_set(mod, tn, pg, TOPO_TYPE_UINT32, name,
	    (void *)&val));
}

bool
pcie_topo_prop_set64(topo_mod_t *mod, tnode_t *tn, const topo_pgroup_info_t *pg,
    const char *name, uint64_t val)
{
	return (pcie_topo_prop_set(mod, tn, pg, TOPO_TYPE_UINT64, name,
	    (void *)&val));
}

bool
pcie_topo_prop_set32_array(topo_mod_t *mod, tnode_t *tn,
    const topo_pgroup_info_t *pg, const char *name, uint32_t *vals, int nval)
{
	int ret, err;

	ret = topo_prop_set_uint32_array(tn, pg->tpi_name, name, 0,
	    vals, nval, &err);
	if (ret != 0) {
		topo_mod_dprintf(mod, "failed to set property %s/%s: %s",
		    pg->tpi_name, name, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		return (false);
	}

	return (true);
}

bool
pcie_topo_prop_set64_array(topo_mod_t *mod, tnode_t *tn,
    const topo_pgroup_info_t *pg, const char *name, uint64_t *vals, int nval)
{
	int ret, err;

	ret = topo_prop_set_uint64_array(tn, pg->tpi_name, name, 0,
	    vals, nval, &err);
	if (ret != 0) {
		topo_mod_dprintf(mod, "failed to set property %s/%s: %s",
		    pg->tpi_name, name, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		return (false);
	}

	return (true);
}

bool
pcie_topo_prop_setstr(topo_mod_t *mod, tnode_t *tn,
    const topo_pgroup_info_t *pg, const char *name, const char *val)
{
	return (pcie_topo_prop_set(mod, tn, pg, TOPO_TYPE_STRING, name,
	    (void *)val));
}

int32_t
pcie_devinfo_get32(topo_mod_t *mod, di_node_t did, const char *name)
{
	int32_t *iprop;
	int nprop;

	nprop = di_prop_lookup_ints(DDI_DEV_T_ANY, did, name, &iprop);

	if (nprop != 1) {
		if (nprop != -1) {
			topo_mod_dprintf(mod,
			    "devinfo property %s has %u value(s); skipping",
			    name, nprop);
		}
		return (-1);
	}

	return (iprop[0]);
}

int64_t
pcie_devinfo_get64(topo_mod_t *mod, di_node_t did, const char *name)
{
	int64_t *iprop;
	int nprop;

	nprop = di_prop_lookup_int64(DDI_DEV_T_ANY, did, name, &iprop);

	if (nprop != 1) {
		if (nprop != -1) {
			topo_mod_dprintf(mod,
			    "devinfo property %s has %u value(s); skipping",
			    name, nprop);
		}
		return (-1);
	}

	return (iprop[0]);
}

bool
pcie_devinfo_getbool(topo_mod_t *mod, di_node_t did, const char *name)
{
	di_prop_t prop;

	prop = di_prop_find(DDI_DEV_T_ANY, did, name);

	return (prop != DI_PROP_NIL &&
	    di_prop_type(prop) == DI_PROP_TYPE_BOOLEAN);
}

/*
 * This is a convenience function to copy a property from a devinfo node to
 * a topo node property group, with appropriate error checking and output if
 * anything goes wrong.
 * devinfo numeric properties are signed but we always do explicit conversion to
 * unsigned when storing the values back to the topo node.
 */
bool
pcie_topo_prop_copy(topo_mod_t *mod, di_node_t did, tnode_t *tn,
    const topo_pgroup_info_t *pg, topo_type_t type,
    const char *src, const char *dst)
{
	int32_t *iprop;
	int64_t *lprop;
	char *sprop;
	int nprop;

	switch (type) {
	case TOPO_TYPE_UINT32:
	case TOPO_TYPE_UINT32_ARRAY:
		nprop = di_prop_lookup_ints(DDI_DEV_T_ANY, did, src, &iprop);
		break;
	case TOPO_TYPE_UINT64:
	case TOPO_TYPE_UINT64_ARRAY:
		nprop = di_prop_lookup_int64(DDI_DEV_T_ANY, did, src, &lprop);
		break;
	case TOPO_TYPE_STRING:
		nprop = di_prop_lookup_strings(DDI_DEV_T_ANY, did, src, &sprop);
		break;
	default:
		topo_mod_dprintf(mod, "%s - unhandled property type %u\n",
		    __func__, type);
		return (false);
	}

	if (nprop < 1) {
		if (nprop != -1) {
			topo_mod_dprintf(mod,
			    "devinfo property %s has %u value(s); skipping",
			    src, nprop);
		}
		return (false);
	}

	switch (type) {
	case TOPO_TYPE_UINT32:
		return (pcie_topo_prop_set32(mod, tn, pg, dst, iprop[0]));
	case TOPO_TYPE_UINT32_ARRAY:
		return (pcie_topo_prop_set32_array(mod, tn, pg, dst,
		    (uint32_t *)iprop, nprop));
	case TOPO_TYPE_UINT64:
		return (pcie_topo_prop_set64(mod, tn, pg, dst, lprop[0]));
	case TOPO_TYPE_UINT64_ARRAY:
		return (pcie_topo_prop_set64_array(mod, tn, pg, dst,
		    (uint64_t *)lprop, nprop));
	case TOPO_TYPE_STRING:
		return (pcie_topo_prop_setstr(mod, tn, pg, dst, sprop));
	default:
		abort();
	}

	return (false);
}
