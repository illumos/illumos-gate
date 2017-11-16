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
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_list.h>
#include <fm/topo_method.h>

#include <topo_port.h>

/*
 * Common routines to create port entries in the topology tree.
 */

static const topo_pgroup_info_t port_pgroup = {
	TOPO_PGROUP_PORT,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

int
port_range_create(topo_mod_t *mod, tnode_t *pnode, topo_instance_t min,
    topo_instance_t max)
{
	return (topo_node_range_create(mod, pnode, PORT, min, max));
}

/*
 * Create a port node, specifying the type of port it is. This will create the
 * common port property group and populate it. The caller will need to populate
 * the port-specific property group as needed.
 */
static tnode_t *
port_create_common(topo_mod_t *mod, tnode_t *pnode, topo_instance_t inst,
    const char *type)
{
	int err;
	tnode_t *tn = NULL;
	nvlist_t *fmri = NULL, *auth = NULL, *presource = NULL;

	if (type == NULL) {
		topo_mod_dprintf(mod, "port_create_common missing type "
		    "argument\n");
		goto error;
	}

	if ((auth = topo_mod_auth(mod, pnode)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_auth() failed: %s\n",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if ((fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION, PORT,
	    inst, NULL, auth, NULL, NULL, NULL)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s\n",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if ((tn = topo_node_bind(mod, pnode, PORT, inst, fmri)) == NULL) {
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s\n",
		    topo_mod_errmsg(mod));
		goto error;
	}

	/*
	 * The FRU is always set to the FMRI of the parent device for a port.
	 */
	if (topo_node_resource(pnode, &presource, &err) != 0) {
		topo_mod_dprintf(mod, "topo_node_resource() failed: %s\n",
		    topo_strerror(err));
		goto error;
	}

	if (topo_node_fru_set(tn, presource, 0, &err) != 0) {
		topo_mod_dprintf(mod, "topo_node_fru_set() failed: %s\n",
		    topo_strerror(err));
		goto error;
	}

	if (topo_pgroup_create(tn, &port_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create property group %s: "
		    "%s\n", TOPO_PGROUP_PORT, topo_strerror(err));
		goto error;
	}

	if (topo_prop_set_string(tn, TOPO_PGROUP_PORT, TOPO_PROP_PORT_TYPE,
	    TOPO_PROP_IMMUTABLE, type, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s\n",
		    TOPO_PROP_PORT_TYPE, topo_strerror(err));
		goto error;
	}

	nvlist_free(fmri);
	nvlist_free(auth);
	nvlist_free(presource);
	return (tn);
error:
	topo_node_unbind(tn);
	nvlist_free(fmri);
	nvlist_free(auth);
	nvlist_free(presource);
	return (NULL);
}

int
port_create_sff(topo_mod_t *mod, tnode_t *pnode, topo_instance_t inst,
    tnode_t **nodep)
{
	tnode_t *tn;

	tn = port_create_common(mod, pnode, inst, TOPO_PROP_PORT_TYPE_SFF);
	if (tn == NULL)
		return (-1);
	*nodep = tn;
	return (0);
}
