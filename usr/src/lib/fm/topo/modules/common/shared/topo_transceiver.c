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

/*
 * Common routines to create transceiver entries in the topology tree.
 */

static const topo_pgroup_info_t transceiver_pgroup = {
	TOPO_PGROUP_TRANSCEIVER,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t sff_transceiver_pgroup = {
	TOPO_PGROUP_SFF_TRANSCEIVER,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

int
transceiver_range_create(topo_mod_t *mod, tnode_t *pnode, topo_instance_t min,
    topo_instance_t max)
{
	return (topo_node_range_create(mod, pnode, TRANSCEIVER, min, max));
}

static tnode_t *
transceiver_create_common(topo_mod_t *mod, tnode_t *pnode, topo_instance_t inst,
    const char *type, boolean_t usable, const char *part, const char *rev,
    const char *serial)
{
	int err;
	tnode_t *tn = NULL;
	nvlist_t *fmri = NULL, *auth = NULL;

	if (type == NULL) {
		topo_mod_dprintf(mod, "transceiver_create_common missing type "
		    "argument");
		goto error;
	}

	if ((auth = topo_mod_auth(mod, pnode)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_auth() failed: %s\n",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if ((fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION,
	    TRANSCEIVER, inst, NULL, auth, part, rev, serial)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s\n",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if ((tn = topo_node_bind(mod, pnode, TRANSCEIVER, inst, fmri)) ==
	    NULL) {
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s\n",
		    topo_mod_errmsg(mod));
		goto error;
	}

	/*
	 * The FRU for a transceiver is always itself.
	 */
	if (topo_node_fru_set(tn, fmri, 0, &err) != 0) {
		topo_mod_dprintf(mod, "topo_node_fru_set() failed: %s\n",
		    topo_strerror(err));
		goto error;
	}

	if (topo_pgroup_create(tn, &transceiver_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create property group %s: "
		    "%s\n", TOPO_PGROUP_TRANSCEIVER, topo_strerror(err));
		goto error;
	}

	if (topo_prop_set_string(tn, TOPO_PGROUP_TRANSCEIVER,
	    TOPO_PROP_TRANSCEIVER_TYPE, TOPO_PROP_IMMUTABLE, type,
	    &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s\n",
		    TOPO_PROP_TRANSCEIVER_TYPE, topo_strerror(err));
		goto error;
	}

	if (topo_prop_set_string(tn, TOPO_PGROUP_TRANSCEIVER,
	    TOPO_PROP_TRANSCEIVER_USABLE, TOPO_PROP_IMMUTABLE,
	    usable ? "true" : "false", &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s\n",
		    TOPO_PROP_TRANSCEIVER_USABLE, topo_strerror(err));
		goto error;
	}

	nvlist_free(fmri);
	nvlist_free(auth);
	return (tn);

error:
	topo_node_unbind(tn);
	nvlist_free(fmri);
	nvlist_free(auth);
	return (NULL);
}

int
transceiver_create_sff(topo_mod_t *mod, tnode_t *pnode, topo_instance_t inst,
    boolean_t useable, const char *vendor, const char *part, const char *rev,
    const char *serial, tnode_t **nodep)
{
	int err;
	tnode_t *tn = NULL;

	if ((tn = transceiver_create_common(mod, pnode, inst,
	    TOPO_PROP_PORT_TYPE_SFF, useable, part, rev, serial)) == NULL) {
		return (-1);
	}

	/*
	 * Always create the SFF property group, even if we can't fill in any
	 * properties.
	 */
	if (topo_pgroup_create(tn, &sff_transceiver_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create property group %s: "
		    "%s\n", TOPO_PGROUP_SFF_TRANSCEIVER, topo_strerror(err));
		goto error;
	}

	if (vendor != NULL && topo_prop_set_string(tn,
	    TOPO_PGROUP_SFF_TRANSCEIVER, TOPO_PORT_SFF_TRANSCEIVER_VENDOR,
	    TOPO_PROP_IMMUTABLE, vendor, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s\n",
		    TOPO_PORT_SFF_TRANSCEIVER_VENDOR, topo_strerror(err));
		goto error;
	}

	if (part != NULL && topo_prop_set_string(tn,
	    TOPO_PGROUP_SFF_TRANSCEIVER, TOPO_PORT_SFF_TRANSCEIVER_PN,
	    TOPO_PROP_IMMUTABLE, part, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s\n",
		    TOPO_PORT_SFF_TRANSCEIVER_PN, topo_strerror(err));
		goto error;
	}

	if (rev != NULL && topo_prop_set_string(tn,
	    TOPO_PGROUP_SFF_TRANSCEIVER, TOPO_PORT_SFF_TRANSCEIVER_REV,
	    TOPO_PROP_IMMUTABLE, rev, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s\n",
		    TOPO_PORT_SFF_TRANSCEIVER_REV, topo_strerror(err));
		goto error;
	}

	if (serial != NULL && topo_prop_set_string(tn,
	    TOPO_PGROUP_SFF_TRANSCEIVER, TOPO_PORT_SFF_TRANSCEIVER_SN,
	    TOPO_PROP_IMMUTABLE, serial, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set %s property: %s\n",
		    TOPO_PORT_SFF_TRANSCEIVER_SN, topo_strerror(err));
		goto error;
	}

	if (nodep != NULL)
		*nodep = tn;
	return (0);

error:
	topo_node_unbind(tn);
	return (-1);
}
