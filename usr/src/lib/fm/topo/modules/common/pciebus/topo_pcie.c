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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * The purpose of this module is to build topology information for the
 * 'pcie' scheme. It works in conjunction with the XML file that corresponds to
 * a given hardware platform. That XML file provides the basic structure and
 * passes responsibility for enumerating various parts of the PCIe topology
 * tree to this module.
 *
 * Since the PCIe topology tree structure depends very much on the underlying
 * hardware and its configuration, almost all of the tree is built
 * programmatically. The static XML file defines just the root of the tree, a
 * CPU enumerator, and then a PCIe root complex enumerator under each CPU.
 * Each root complex is discovered, attached to the corresponding CPU and then
 * recursively enumerated to discover bridges, switches, devices, etc. that lie
 * underneath. Platform-specific modules can augment the discovered tree by
 * adding labels or nodes that cannot be discovered, such as re-timers.
 */

#include <fcntl.h>
#include <libdevinfo.h>
#include <priv.h>
#include <stdbool.h>
#include <strings.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/devfm.h>

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <fm/topo_list.h>
#include <fm/topo_method.h>
#include <fm/fmd_agent.h>

#include <io/amdzen/amdzen_topo.h>

#include "topo_pcie_impl.h"

typedef struct pcie_enum_state {
	di_node_t		pes_devinfo;
	uint8_t			pes_nchip;
	nvlist_t		*pes_cpupcidata;
	topo_list_t		pes_rootnexus;
} pcie_enum_state_t;

typedef struct cbdata {
	pcie_enum_state_t	*cbd_state;
	topo_mod_t		*cbd_mod;
	bool			cbd_fatal;
} cbdata_t;

typedef struct pcie_enum pcie_enum_t;
typedef int (*pcie_enum_f)(topo_mod_t *, pcie_t *, const pcie_enum_t *,
    tnode_t *, tnode_t *, topo_instance_t, topo_instance_t);

typedef enum {
	/*
	 * This flag is used to indicate that we are okay operating on a range
	 * of instances. This should only happen during the range enumeration
	 * phase, not during the post-creation enumeration phase.
	 */
	PCIE_ENUM_F_MULTI_RANGE		= 1 << 0,
} pcie_enum_flags_t;

struct pcie_enum {
	const char *pe_name;
	pcie_enum_flags_t pe_flags;
	pcie_enum_f pe_range_enum;
	pcie_enum_f pe_post_enum;
};

static tnode_t *pcie_topo_add_bridge(topo_mod_t *, pcie_t *, tnode_t *,
    pcie_node_t *);

static void
pcie_node_print(topo_mod_t *mod, topo_list_t *list, uint_t indent)
{
	pcie_node_t *node;

	for (node = topo_list_next(list); node != NULL;
	    node = topo_list_next(node)) {
		char suffix[0x10] = "";

		if (node->pn_type == PCIE_NODE_ROOTNEXUS) {
			(void) snprintf(suffix, sizeof (suffix), " cpu%" PRIu64,
			    node->pn_cpu);
		}
		topo_mod_dprintf(mod, "%*s[%x/%x/%x] %s [%s%d] {%x/%x/%x} %s%s",
		    indent, "",
		    node->pn_bus, node->pn_dev, node->pn_func,
		    pcie_type_name(node->pn_type),
		    node->pn_drvname == NULL ? "" : node->pn_drvname,
		    node->pn_drvinst,
		    node->pn_class, node->pn_subclass, node->pn_intf,
		    node->pn_path, suffix);
		pcie_node_print(mod, &node->pn_children, indent + 4);
	}
}

static void
pcie_node_free(topo_mod_t *mod, pcie_node_t *node)
{
	topo_mod_strfree(mod, node->pn_drvname);
	if (node->pn_path != NULL)
		di_devfs_path_free((char *)node->pn_path);
	topo_mod_free(mod, node, sizeof (*node));
}

static void
pcie_free_tree(topo_mod_t *mod, pcie_node_t *node)
{
	pcie_node_t *child, *nchild;

	for (child = topo_list_next(&node->pn_children); child != NULL;
	    child = nchild) {
		nchild = topo_list_next(child);
		pcie_free_tree(mod, child);
	}

	pcie_node_free(mod, node);
}

static pcie_node_t *
pcie_node_create(topo_mod_t *mod, di_node_t did, pcie_node_type_t type,
    pcie_node_t *parent)
{
	char *drvname;
	pcie_node_t *node;
	char *path;
	int inst;

	drvname = di_driver_name(did);
	if (drvname != NULL) {
		drvname = topo_mod_strdup(mod, drvname);
		if (drvname == NULL) {
			(void) topo_mod_seterrno(mod, EMOD_NOMEM);
			topo_mod_dprintf(mod,
			    "failed to duplicate driver name");
			return (NULL);
		}
	}

	inst = di_instance(did);
	path = di_devfs_path(did);

	if (path == NULL) {
		topo_mod_dprintf(mod, "failed to get /devices path for "
		    "%s%d: %s", drvname == NULL ? "<unknown>" : drvname, inst,
		    strerror(errno));
		(void) topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
		topo_mod_strfree(mod, drvname);
		return (NULL);
	}

	if ((node = topo_mod_zalloc(mod, sizeof (*node))) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		topo_mod_strfree(mod, drvname);
		di_devfs_path_free(path);
		return (NULL);
	}

	node->pn_did = did;
	node->pn_type = type;
	node->pn_path = path;
	node->pn_drvname = drvname;
	node->pn_drvinst = inst;

	if (parent != NULL) {
		topo_list_append(&parent->pn_children, node);
		node->pn_parent = parent;
	}

	return (node);
}

static void
pcie_tn_data_free(topo_mod_t *mod, pcie_tn_data_t *data)
{
	if (data == NULL)
		return;
	if (data->ptd_nexus_path != NULL)
		topo_mod_strfree(mod, data->ptd_nexus_path);
	topo_mod_free(mod, data, sizeof (*data));
}

static pcie_tn_data_t *
pcie_tn_data_create(topo_mod_t *mod, const pcie_node_t *node)
{
	pcie_tn_data_t *data;
	const char *nexus_path;

	if ((data = topo_mod_zalloc(mod, sizeof (*data))) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		return (NULL);
	}

	data->ptd_bus = node->pn_bus;
	data->ptd_dev = node->pn_dev;
	data->ptd_func = node->pn_func;

	nexus_path = pcie_node_nexus_path(node);
	if (nexus_path != NULL) {
		data->ptd_nexus_path = topo_mod_strdup(mod, nexus_path);
		if (data->ptd_nexus_path == NULL) {
			pcie_tn_data_free(mod, data);
			(void) topo_mod_seterrno(mod, EMOD_NOMEM);
			return (NULL);
		}
	}

	return (data);
}

static tnode_t *
pcie_topo_node_create(topo_mod_t *mod, pcie_t *pcie, tnode_t *parent,
    pcie_node_t *node, const char *name, topo_instance_t inst)
{
	nvlist_t *fmri, *auth;
	pcie_tn_data_t *data = NULL;
	tnode_t *tn, *dtn;

	topo_mod_dprintf(mod, "topo node create %s=%" PRIu64 " (%s)",
	    name, inst, node == NULL ? "" : node->pn_path);

	auth = mod_pcie_platform_auth(mod, pcie, parent);
	if (auth == NULL) {
		topo_mod_dprintf(mod, "could not get auth from parent: %s",
		    topo_mod_errmsg(mod));
		return (NULL);
	}
	fmri = topo_mod_pciefmri(mod, parent, FM_PCIE_SCHEME_VERSION,
	    name, inst, auth);

	if (fmri == NULL) {
		topo_mod_dprintf(mod, "fmri creation failed: %s",
		    topo_mod_errmsg(mod));
		nvlist_free(auth);
		return (NULL);
	}

	tn = topo_node_bind(mod, parent, name, inst, fmri);
	if (tn == NULL) {
		topo_mod_dprintf(mod, "bind failed: %s", topo_mod_errmsg(mod));
		goto error;
	}

	if (node != NULL) {
		data = pcie_tn_data_create(mod, node);
		if (data == NULL) {
			topo_mod_dprintf(mod,
			    "failed to allocate per-tnode data: %s",
			    topo_mod_errmsg(mod));
			goto error;
		}
		topo_node_setspecific(tn, data);

		if (!topo_pcie_set_pci_props(mod, pcie, node, tn))
			goto error;

		node->pn_inst = inst;
	}

	topo_pgroup_hcset(tn, auth);

	/*
	 * Give the platform-specific module an opportunity to decorate or
	 * extend the new topology node.
	 */
	dtn = mod_pcie_platform_topo_node_decorate(mod, pcie, node, tn);
	if (dtn == NULL)
		goto error;

	nvlist_free(auth);
	nvlist_free(fmri);
	return (dtn);

error:
	nvlist_free(auth);
	nvlist_free(fmri);
	if (tn != NULL) {
		topo_node_setspecific(tn, NULL);
		topo_node_unbind(tn);
	}
	pcie_tn_data_free(mod, data);
	return (NULL);
}

static void
pcie_topo_node_free(topo_mod_t *mod, tnode_t *tn)
{
	pcie_tn_data_free(mod, topo_node_getspecific(tn));
	topo_node_setspecific(tn, NULL);
}

static void
pcie_socket_map(topo_mod_t *mod, pcie_enum_state_t *state, pcie_node_t *node)
{
	int32_t *busrange;
	nvlist_t **dfs;
	uint_t ndfs;
	int nval;
	int err;

	node->pn_cpu = 0;

	if (state->pes_cpupcidata == NULL)
		return;

	nval = di_prop_lookup_ints(DDI_DEV_T_ANY, node->pn_did,
	    DI_BUSRANGE, &busrange);
	if (nval != 2) {
		topo_mod_dprintf(mod, "failed to retrieve nexus bus range");
		return;
	}

	err = nvlist_lookup_nvlist_array(state->pes_cpupcidata,
	    FM_PCI_DATA_DFS, &dfs, &ndfs);
	if (err != 0 || dfs == NULL) {
		topo_mod_dprintf(mod, "CPU PCI data does not contain %s",
		    FM_PCI_DATA_DFS);
		return;
	}

	for (uint_t i = 0; i < ndfs; i++) {
		uint32_t nb_busno;
		int32_t sockid;

		err = nvlist_lookup_int32(dfs[i], FM_PCI_DATA_CHIP_ID,
		    &sockid);
		if (err != 0) {
			topo_mod_dprintf(mod, "DF[%d] is missing key '%s'",
			    i, FM_PCI_DATA_CHIP_ID);
			continue;
		}
		err = nvlist_lookup_uint32(dfs[i], FM_PCI_DATA_NB_BUSNO,
		    &nb_busno);
		if (err != 0) {
			topo_mod_dprintf(mod, "DF[%d] is missing key '%s'",
			    i, FM_PCI_DATA_NB_BUSNO);
			continue;
		}
		if (busrange[0] <= nb_busno) {
			node->pn_cpu = sockid;
			topo_mod_dprintf(mod,
			    "Mapped root complex %s to socket %" PRIu64,
			    node->pn_path, node->pn_cpu);
			break;
		}
	}
}

static bool
pcie_physcpu_enum(topo_mod_t *mod, pcie_enum_state_t *state)
{
	fmd_agent_hdl_t *hdl;

	if ((hdl = fmd_agent_open(FMD_AGENT_VERSION)) == NULL) {
		topo_mod_dprintf(mod, "failed to open fmd agent interface: %s",
		    strerror(errno));
		return (false);
	}

	if (fmd_agent_chip_count(hdl, &state->pes_nchip) != 0) {
		topo_mod_dprintf(mod,
		    "failed to retrieve physical CPU count: %s",
		    fmd_agent_errmsg(hdl));
		fmd_agent_close(hdl);
		return (false);
	}

	if (fmd_agent_physcpu_pci(hdl, &state->pes_cpupcidata) != 0) {
		topo_mod_dprintf(mod,
		    "failed to retrieve physical CPU PCI data: %s",
		    fmd_agent_errmsg(hdl));
		/*
		 * This is not fatal, we just won't be able to properly map
		 * root complexes to physical CPUs and will report them all
		 * as being under the first CPU.
		 */
	}

	fmd_agent_close(hdl);

	return (true);
}

static int
pcie_rootnexus_enum_cb(di_node_t did, void *arg)
{
	cbdata_t *cbd = arg;
	topo_mod_t *mod = cbd->cbd_mod;
	pcie_enum_state_t *state = cbd->cbd_state;
	char *compat;
	bool found = false;
	int *ents, nents;

	nents = di_prop_lookup_strings(DDI_DEV_T_ANY, did, DI_COMPATPROP,
	    &compat);
	if (nents > 0) {
		for (uint_t i = 0; i < nents; i++) {
			if (strcmp(PCIE_ROOT_NEXUS, compat) == 0) {
				found = true;
				break;
			}
			compat += strlen(compat) + 1;
		}
	}

	if (!found) {
		/* Check for a PCI nexus */
		char *drv = di_driver_name(did);

		if (drv != NULL && strcmp(drv, "pci") == 0 &&
		    di_prop_lookup_ints(DDI_DEV_T_ANY, did, DI_BUSRANGE,
		    &ents) == 2) {
			found = true;
		}
	}

	if (!found)
		return (DI_WALK_CONTINUE);

	pcie_node_t *node = pcie_node_create(mod, did,
	    PCIE_NODE_ROOTNEXUS, NULL);
	if (node == NULL) {
		topo_mod_dprintf(mod,
		    "failed to create root nexus pcie node: %s",
		    topo_mod_errmsg(mod));
		cbd->cbd_fatal = true;
		return (DI_WALK_TERMINATE);
	}

	pcie_socket_map(mod, state, node);

	topo_list_append(&state->pes_rootnexus, node);

	return (DI_WALK_PRUNECHILD);
}

static bool
pcie_rootnexus_enum(topo_mod_t *mod, pcie_enum_state_t *state)
{
	cbdata_t cbd = {
		.cbd_state = state,
		.cbd_mod = mod,
		.cbd_fatal = false
	};

	(void) di_walk_node(state->pes_devinfo, DI_WALK_CLDFIRST,
	    &cbd, pcie_rootnexus_enum_cb);

	return (!cbd.cbd_fatal);
}

static pcie_node_t *
pcie_process_node(topo_mod_t *mod, pcie_node_t *parent, di_node_t did)
{
	int nents;
	int *ents;
	int class, subclass, interface, bus, dev, func;
	uint16_t pcie_type;
	bool is_pcie, is_pcibr;
	pcie_node_t *node = NULL;
	pcie_node_type_t type;

	nents = di_prop_lookup_ints(DDI_DEV_T_ANY, did, DI_CLASSPROP, &ents);
	if (nents != 1)
		return (NULL);

	class = GETCLASS(ents[0]);
	subclass = GETSUBCLASS(ents[0]);
	interface = GETINTF(ents[0]);

	nents = di_prop_lookup_ints(DDI_DEV_T_ANY, did, DI_REGPROP, &ents);
	if (nents > 0) {
		bus = PCI_REG_BUS_G(ents[0]);
		dev = PCI_REG_DEV_G(ents[0]);
		func = PCI_REG_FUNC_G(ents[0]);
	} else {
		bus = dev = func = -1;
	}

	is_pcibr = (class == PCI_CLASS_BRIDGE && subclass == PCI_BRIDGE_PCI);

	nents = di_prop_lookup_ints(DDI_DEV_T_ANY, did, DI_PCIETYPPROP, &ents);
	if (nents == 1) {
		is_pcie = true;
		pcie_type = (uint16_t)(ents[0] << PCIE_PCIECAP_DEV_TYPE_SHIFT);
	} else {
		is_pcie = false;
		pcie_type = PCIE_PCIECAP_DEV_TYPE_PCI_DEV;
	}

	type = PCIE_NODE_PCI_DEV;
	if (!is_pcie) {
		type = is_pcibr ? PCIE_NODE_PCIE_PCI : PCIE_NODE_PCI_DEV;
	} else if (is_pcibr) {
		switch (pcie_type) {
		case PCIE_PCIECAP_DEV_TYPE_ROOT:
			type = PCIE_NODE_ROOTPORT;
			break;
		case PCIE_PCIECAP_DEV_TYPE_UP:
			type = PCIE_NODE_SWITCH_UP;
			break;
		case PCIE_PCIECAP_DEV_TYPE_DOWN:
			type = PCIE_NODE_SWITCH_DOWN;
			break;
		case PCIE_PCIECAP_DEV_TYPE_PCIE2PCI:
			type = PCIE_NODE_PCIE_PCI;
			break;
		case PCIE_PCIECAP_DEV_TYPE_PCI2PCIE:
			type = PCIE_NODE_PCI_PCIE;
			break;
		default:
			topo_mod_dprintf(mod,
			    "pcie_type unhandled bridge type 0x%x", pcie_type);
			abort();
		}
	} else {
		switch (pcie_type) {
		case PCIE_PCIECAP_DEV_TYPE_ROOT:
			type = PCIE_NODE_ROOTPORT;
			break;
		case PCIE_PCIECAP_DEV_TYPE_PCIE_DEV:
			type = PCIE_NODE_PCIE_DEV;
			break;
		case PCIE_PCIECAP_DEV_TYPE_PCI_DEV:
			type = PCIE_NODE_PCI_DEV;
			break;
		case PCIE_PCIECAP_DEV_TYPE_RC_IEP:
		case PCIE_PCIECAP_DEV_TYPE_RC_EC:
			/* These types are not currently handled */
			return (NULL);
		default:
			topo_mod_dprintf(mod, "pcie_type unhandled type 0x%x",
			    pcie_type);
			abort();
		}
	}

	node = pcie_node_create(mod, did, type, parent);

	node->pn_class = class;
	node->pn_subclass = subclass;
	node->pn_intf = interface;
	node->pn_bus = bus;
	node->pn_dev = dev;
	node->pn_func = func;
	node->pn_is_pcie = is_pcie;

	return (node);
}

static void
pcie_enum_children(topo_mod_t *mod, pcie_node_t *parent)
{
	di_node_t did;

	for (did = di_child_node(parent->pn_did); did != DI_NODE_NIL;
	    did = di_sibling_node(did)) {
		pcie_node_t *node;

		node = pcie_process_node(mod, parent, did);
		if (node != NULL)
			pcie_enum_children(mod, node);
	}
}

static void
pcie_rootnexus_enum_children(topo_mod_t *mod, pcie_enum_state_t *state)
{
	pcie_node_t *nexus;

	for (nexus = topo_list_next(&state->pes_rootnexus); nexus != NULL;
	    nexus = topo_list_next(nexus)) {
		topo_mod_dprintf(mod, "enumerate nexus %s", nexus->pn_path);
		pcie_enum_children(mod, nexus);
	}
}

static void
pcie_enum_state_init(pcie_enum_state_t *state)
{
	bzero(state, sizeof (*state));
	state->pes_devinfo = DI_NODE_NIL;
}

static void
pcie_enum_state_fini(topo_mod_t *mod, pcie_enum_state_t *state)
{
	pcie_node_t *nexus, *nnexus;

	for (nexus = topo_list_next(&state->pes_rootnexus); nexus != NULL;
	    nexus = nnexus) {
		nnexus = topo_list_next(nexus);
		topo_list_delete(&state->pes_rootnexus, nexus);
		pcie_free_tree(mod, nexus);
	}
	nvlist_free(state->pes_cpupcidata);
	state->pes_cpupcidata = NULL;
	state->pes_devinfo = DI_NODE_NIL;
}

/*
 * Populate the enumeration scratch state: capture the current devinfo handle,
 * query the physical CPU layout, and build the pcie_node_t tree that mirrors
 * the PCIe topology beneath each root nexus.
 */
static bool
pcie_gather(topo_mod_t *mod, pcie_enum_state_t *state)
{
	if ((state->pes_devinfo = topo_mod_devinfo(mod)) == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "No devinfo node from framework");
		return (false);
	}

	if (!pcie_physcpu_enum(mod, state))
		return (false);

	if (!pcie_rootnexus_enum(mod, state))
		return (false);

	pcie_rootnexus_enum_children(mod, state);

	pcie_node_print(mod, &state->pes_rootnexus, 0);

	return (true);
}

static tnode_t *
pcie_topo_add_link(topo_mod_t *mod, pcie_t *pcie, tnode_t *pnode,
    pcie_node_t *node)
{
	tnode_t *tn;

	if (!pcie_topo_range_create(mod, pnode, "link", 0, 0))
		return (NULL);

	tn = pcie_topo_node_create(mod, pcie, pnode, NULL, "link", 0);
	if (tn == NULL)
		return (NULL);

	(void) topo_pcie_set_link_props(mod, pcie, node, tn);

	return (tn);
}

static tnode_t *
pcie_topo_add_bridge(topo_mod_t *mod, pcie_t *pcie, tnode_t *pnode,
    pcie_node_t *node)
{
	tnode_t *tn = pnode;

	if (!pcie_topo_range_create(mod, tn, "port", 0, 0))
		return (NULL);

	tn = pcie_topo_node_create(mod, pcie, tn, NULL, "port", 0);
	if (tn == NULL)
		return (NULL);

	(void) topo_pcie_set_port_props(mod, pcie, node, tn,
	    TOPO_PORT_DOWNSTREAM);

	tn = pcie_topo_add_link(mod, pcie, tn, node);

	return (tn);
}

static tnode_t *
pcie_topo_add_device(topo_mod_t *mod, pcie_t *pcie, tnode_t *pnode,
    pcie_node_t *node, topo_instance_t *inst)
{
	topo_instance_t fninst;
	tnode_t *dev, *func;

	topo_mod_dprintf(mod, "add_device: %s (%s)",
	    node->pn_path, pcie_type_name(node->pn_type));

	if (node->pn_parent->pn_type == PCIE_NODE_ROOTNEXUS) {
		/*
		 * Devices directly under under the artificial root complex
		 * node are presented as functions, without an intermediate
		 * device or any attempt to represent the internal fabric.
		 */
		dev = pnode;
		fninst = *inst;
		(*inst)++;
	} else {
		pcie_node_t *parent;
		size_t idx;

		if (node->pn_type == PCIE_NODE_SWITCH_DOWN) {
			/*
			 * A downstream switch is a child of an upstream one
			 * in the devinfo tree, but is represented in the topo
			 * tree underneath the same device as the upstream
			 * bridge.
			 */
			VERIFY(node->pn_parent->pn_type == PCIE_NODE_SWITCH_UP);
			parent = node->pn_parent->pn_parent;
			idx = node->pn_parent->pn_dev;
		} else {
			parent = node->pn_parent;
			idx = node->pn_dev;
		}

		VERIFY3U(idx, <=, sizeof (parent->pn_devices));

		dev = parent->pn_devices[idx];

		if (dev == NULL) {
			topo_instance_t max;
			tnode_t *port;

			max = topo_list_size(&parent->pn_children);
			if (node->pn_type == PCIE_NODE_SWITCH_UP)
				max += topo_list_size(&node->pn_children);

			if (!pcie_topo_range_create(mod, pnode, "port", 0, max))
				return (NULL);
			port = pcie_topo_node_create(mod, pcie, pnode, NULL,
			    "port", *inst);

			if (port == NULL)
				return (NULL);

			(void) topo_pcie_set_port_props(mod, pcie, node, port,
			    TOPO_PORT_UPSTREAM);

			if (!pcie_topo_range_create(mod, port, "device", 0,
			    max)) {
				return (NULL);
			}

			dev = pcie_topo_node_create(mod, pcie, port, NULL,
			    "device", *inst);
			if (dev == NULL)
				return (NULL);
			(*inst)++;
			parent->pn_devices[idx] = dev;
			parent->pn_devfunc[idx] = 0;
			if (!pcie_topo_range_create(mod, dev, "function", 0,
			    max)) {
				return (NULL);
			}
		}
		fninst = parent->pn_devfunc[idx];
		/*
		 * pn_devfunc records the next available function number for
		 * this device.
		 */
		parent->pn_devfunc[idx]++;
	}

	func = pcie_topo_node_create(mod, pcie, dev, node, "function", fninst);

	return (func);
}

static bool
pcie_topo_process_functions(topo_mod_t *mod, pcie_t *pcie, tnode_t *pnode,
    pcie_node_t *node, topo_instance_t *fninst)
{
	pcie_node_t *func;
	topo_instance_t i;
	size_t children = topo_list_size(&node->pn_children);

	topo_mod_dprintf(mod,
	    "-> functions for %s (%s) [%"PRIu64"] children %zd",
	    node->pn_path, pcie_type_name(node->pn_type), *fninst, children);

	for (func = topo_list_next(&node->pn_children); func != NULL;
	    func = topo_list_next(func)) {
		tnode_t *fn;

		topo_mod_dprintf(mod, "    fn %s (%s)",
		    func->pn_path, pcie_type_name(func->pn_type));

		switch (func->pn_type) {
		case PCIE_NODE_ROOTPORT:
			fn = pcie_topo_node_create(mod, pcie, pnode, func,
			    "function", *fninst);
			(*fninst)++;
			fn = pcie_topo_add_bridge(mod, pcie, fn, func);
			if (fn == NULL)
				return (false);
			if (topo_list_size(&func->pn_children) == 0)
				break;
			i = 0;
			if (!pcie_topo_process_functions(mod, pcie, fn,
			    func, &i)) {
				return (false);
			}
			break;
		case PCIE_NODE_PCIE_PCI:
		case PCIE_NODE_PCI_PCIE:
			fn = pcie_topo_add_device(mod, pcie, pnode, func,
			    fninst);
			if (fn == NULL)
				return (false);
			fn = pcie_topo_add_bridge(mod, pcie, fn, func);
			if (fn == NULL)
				return (false);
			i = 0;
			if (!pcie_topo_process_functions(mod, pcie, fn,
			    func, &i)) {
				return (false);
			}
			break;
		case PCIE_NODE_SWITCH_UP:
			fn = pcie_topo_add_device(mod, pcie, pnode, func,
			    fninst);
			if (fn == NULL)
				return (false);
			if (!pcie_topo_process_functions(mod, pcie, pnode,
			    func, fninst)) {
				return (false);
			}
			break;
		case PCIE_NODE_SWITCH_DOWN:
			fn = pcie_topo_add_device(mod, pcie, pnode, func,
			    fninst);
			if (fn == NULL)
				return (false);
			if (topo_list_size(&func->pn_children) == 0)
				break;
			fn = pcie_topo_add_bridge(mod, pcie, fn, func);
			if (fn == NULL)
				return (false);
			i = 0;
			if (!pcie_topo_process_functions(mod, pcie, fn,
			    func, &i)) {
				return (false);
			}
			break;
		case PCIE_NODE_PCI_DEV:
		case PCIE_NODE_PCIE_DEV:
			fn = pcie_topo_add_device(mod, pcie, pnode, func,
			    fninst);
			if (fn == NULL)
				return (false);
			break;
		default:
			topo_mod_dprintf(mod, "unhandled device type %u (%s)",
			    func->pn_type, pcie_type_name(func->pn_type));
			abort();
		}
	}

	return (true);
}

static int
pcie_topo_enum_cpu(topo_mod_t *mod, pcie_t *pcie, const pcie_enum_t *pe,
    tnode_t *pnode, tnode_t *tnode, topo_instance_t min, topo_instance_t max)
{
	pcie_enum_state_t state;
	int ret = 0;

	pcie_enum_state_init(&state);

	if (!pcie_physcpu_enum(mod, &state)) {
		pcie_enum_state_fini(mod, &state);
		return (-1);
	}

	topo_mod_dprintf(mod, "physical CPU count: %u", state.pes_nchip);

	for (uint_t chipid = 0; chipid < state.pes_nchip; chipid++) {
		tnode_t *cpu;

		if (chipid < min || chipid > max) {
			topo_mod_dprintf(mod, "cpu chipid %" PRId32 " "
			    "out of range [%" PRIu64 ", %" PRIu64 "]",
			    chipid, min, max);
			continue;
		}

		topo_mod_dprintf(mod, "creating CPU chip %" PRId32, chipid);

		cpu = pcie_topo_node_create(mod, pcie, pnode, NULL,
		    pe->pe_name, chipid);
		if (cpu == NULL) {
			ret = -1;
			break;
		}
	}

	pcie_enum_state_fini(mod, &state);
	return (ret);
}

static int
pcie_topo_enum_root_complex(topo_mod_t *mod, pcie_t *pcie,
    const pcie_enum_t *pe, tnode_t *pnode, tnode_t *tnode,
    topo_instance_t min, topo_instance_t max)
{
	pcie_enum_state_t state;
	topo_instance_t rcinst, cpuinst;
	pcie_node_t *rc;
	int ret = 0;

	pcie_enum_state_init(&state);

	if (!pcie_gather(mod, &state)) {
		pcie_enum_state_fini(mod, &state);
		return (-1);
	}

	cpuinst = topo_node_instance(pnode);

	for (rcinst = min, rc = topo_list_next(&state.pes_rootnexus);
	    rc != NULL; rc = topo_list_next(rc)) {
		tnode_t *rcnode;
		topo_instance_t fninst = 0;

		if (rc->pn_cpu != cpuinst)
			continue;

		if (rcinst > max) {
			ret = -1;
			break;
		}

		rcnode = pcie_topo_node_create(mod, pcie, pnode, rc,
		    pe->pe_name, rcinst);

		if (rcnode == NULL) {
			ret = -1;
			break;
		}

		if (!pcie_topo_range_create(mod, rcnode, "function", 0,
		    topo_list_size(&rc->pn_children))) {
			ret = -1;
			break;
		}

		if (!pcie_topo_process_functions(mod, pcie, rcnode, rc,
		    &fninst)) {
			ret = -1;
			break;
		}

		rcinst++;
	}

	pcie_enum_state_fini(mod, &state);
	return (ret);
}

/*
 * At present, the XML file only goes as far as:
 *    cpu -> root-complex
 * with the "root-complex" enumerator iterating to complete the tree.
 *
 * This is because the tree structure is variable below each root complex.
 */
const pcie_enum_t pcie_enum_common[] = {
	{
		.pe_name = CPU,
		.pe_range_enum = pcie_topo_enum_cpu,
		.pe_flags = PCIE_ENUM_F_MULTI_RANGE,
	},
	{
		.pe_name = "root-complex",
		.pe_range_enum = pcie_topo_enum_root_complex,
		.pe_flags = PCIE_ENUM_F_MULTI_RANGE,
	},
};

/*
 * This is our module's primary enumerator entry point. All types that we
 * declare and handle ourselves enter this function. In general, this is driven
 * by the corresponding topology map and this means that we are called
 * potentially twice by the XML processing logic for each range.
 *
 * 1) The first time we will be called is when we are being asked to enumerate
 *    a range declaration. The range declarations give us a number of different
 *    entries that we can possibly process and will ask us to create as many as
 *    we believe we make sense.
 *
 * 2) There is a second phase where we can be called into to take action. This
 *    occurs if there are XML <node> entries that are used to declare
 *    information about the node. The most common use case here is to decorate
 *    specific nodes with properties and property groups. When we are called
 *    this time, our instance tnode_t point directly to the node itself and not
 *    to the parent.
 *
 * In general, since the PCIe topology is somewhat arbitrary after the first
 * couple of levels (CPUs, internal functions and root ports), we only provide
 * enumerators into these first two levels of the tree. XML files are just
 * wrappers around these enumerators and do not generally contain static
 * annotations.
 *
 * In the current implementation, no handlers are registered for the second
 * pass (that is, none of the entries in pcie_enum_common have a pe_post_enum
 * callback).
 */
static int
pcie_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *modarg, void *data)
{
	pcie_t *pcie;
	const pcie_enum_t *pe;
	const char *pname;
	tnode_t *tn = NULL;
	bool post, range;

	topo_mod_dprintf(mod, "enum: %s [%" PRIu64 ", %" PRIu64 "] on "
	    "%s%" PRIu64, name, min, max,
	    topo_node_name(pnode), topo_node_instance(pnode));

	/*
	 * Enumerating pcie requires PRIV_SYS_CONFIG. If the caller does not
	 * have that, we cannot enumerate. We return success so as not to block
	 * enumerating other schemes.
	 */
	if (!priv_ineffect(PRIV_SYS_CONFIG)) {
		topo_mod_dprintf(mod, "privilege %s is not in effect",
		    PRIV_SYS_CONFIG);
		return (0);
	}

	if ((pcie = topo_mod_getspecific(mod)) == NULL)
		return (-1);

	/*
	 * Look for whether we are in the case where we've been asked to come
	 * back over our specific node. In this case the range's min/max will
	 * stay the same, but our node will have our own name. This means that
	 * we can't really have children as a parent right this moment.
	 */
	pname = topo_node_name(pnode);
	range = (min != max);
	post = false;
	if (strcmp(pname, name) == 0) {
		topo_instance_t pinst = topo_node_instance(pnode);

		VERIFY3U(pinst, >=, min);
		VERIFY3U(pinst, <=, max);

		tn = pnode;
		pnode = topo_node_parent(tn);
		pname = topo_node_name(pnode);
		post = true;
	}

	topo_mod_dprintf(mod, "enum: %s for %s (parent %s=%" PRIu64 ")",
	    post ? "post" : "initial", name,
	    pname, topo_node_instance(pnode));

	pe = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(pcie_enum_common); i++) {
		if (strcmp(pcie_enum_common[i].pe_name, name) == 0) {
			pe = &pcie_enum_common[i];
			break;
		}
	}

	if (pe == NULL) {
		topo_mod_dprintf(mod, "enum: component %s unknown", name);
		return (-1);
	}

	if (range && !post && (pe->pe_flags & PCIE_ENUM_F_MULTI_RANGE) == 0) {
		topo_mod_dprintf(mod,
		    "enum: multi-instance range enumeration not supported");
		return (topo_mod_seterrno(mod, EMOD_NODE_RANGE));
	}

	if (post) {
		if (pe->pe_post_enum == NULL) {
			topo_mod_dprintf(mod,
			    "enum: skipping post: no processing function");
			return (0);
		}
		return (pe->pe_post_enum(mod, pcie, pe, pnode, tn, min, max));
	}

	/*
	 * While there are cases that we might get called into post-enumeration
	 * just because of how we've constructed the topo map even if we don't
	 * need to do anything (but we want to make sure it doesn't go to some
	 * other module), we pretty much always expect to have something for
	 * initial enumeration right now.
	 */
	if (pe->pe_range_enum == NULL) {
		topo_mod_dprintf(mod,
		    "enum: missing initial enumeration function!");
		return (-1);
	}

	return (pe->pe_range_enum(mod, pcie, pe, pnode, tn, min, max));
}

bool
pcie_set_platdata(pcie_t *pcie, void *val)
{
	pcie->tp_privdata = val;
	return (true);
}

void *
pcie_get_platdata(const pcie_t *pcie)
{
	return (pcie->tp_privdata);
}

static void
pcie_free(topo_mod_t *mod, pcie_t *pcie)
{
	if (pcie == NULL)
		return;

	if (pcie->tp_pcidb_hdl != NULL)
		pcidb_close(pcie->tp_pcidb_hdl);

	topo_mod_free(mod, pcie, sizeof (*pcie));
}

static pcie_t *
pcie_alloc(topo_mod_t *mod)
{
	pcie_t *pcie;

	if ((pcie = topo_mod_zalloc(mod, sizeof (*pcie))) == NULL) {
		topo_mod_dprintf(mod,
		    "Could not allocate memory for pcie_t: %s",
		    topo_strerror(EMOD_NOMEM));
		return (NULL);
	}

	if ((pcie->tp_pcidb_hdl = pcidb_open(PCIDB_VERSION)) == NULL) {
		topo_mod_dprintf(mod, "Failed to open pcidb");
		/* Carry on regardless, we just won't have descriptions. */
	}

	return (pcie);
}

static const topo_modops_t pcie_ops = {
	.tmo_enum = pcie_enum,
	.tmo_release = pcie_topo_node_free,
};

static topo_modinfo_t pcie_mod = {
	.tmi_desc = PCIE,
	.tmi_scheme = FM_FMRI_SCHEME_PCIE,
	PCIE_VERSION,
	&pcie_ops,
};

int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	pcie_t *pcie;

	if (getenv("TOPOPCIEDEBUG") != NULL)
		topo_mod_setdebug(mod);

	topo_mod_dprintf(mod, "initialising %s enumerator\n", PCIE);

	if (version != PCIE_VERSION)
		return (-1);

	if ((pcie = pcie_alloc(mod)) == NULL)
		return (-1);

	if (topo_mod_register(mod, &pcie_mod, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register module");
		pcie_free(mod, pcie);
		return (-1);
	}

	if (!mod_pcie_platform_init(mod, pcie)) {
		topo_mod_unregister(mod);
		pcie_free(mod, pcie);
		return (-1);
	}

	topo_mod_setspecific(mod, pcie);

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	pcie_t *pcie;

	pcie = topo_mod_getspecific(mod);

	if (pcie != NULL) {
		topo_mod_setspecific(mod, NULL);
		mod_pcie_platform_fini(mod, pcie);
		pcie_free(mod, pcie);
	}

	topo_mod_unregister(mod);
}
