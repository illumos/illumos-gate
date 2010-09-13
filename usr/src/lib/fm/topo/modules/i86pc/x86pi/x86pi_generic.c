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
 * Create a generic topology node.
 */
#include <sys/types.h>
#include <strings.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <x86pi_impl.h>

#define	_ENUM_NAME	"enum_generic"
#define	_FAC_PROV	"fac_prov_ipmi"

/*
 * Create a generic topo node based on the hcfmri strcuture passed in.
 */
int
x86pi_enum_generic(topo_mod_t *mod, x86pi_hcfmri_t *hcfmri,
    tnode_t *t_bindparent, tnode_t *t_fmriparent, tnode_t **t_node, int flag)
{
	int		rv;
	int		err;
	nvlist_t	*out;
	nvlist_t	*fmri;
	nvlist_t	*auth;

	topo_mod_dprintf(mod, "%s adding entry for type (%s)\n",
	    _ENUM_NAME, hcfmri->hc_name);

	if (t_bindparent == NULL) {
		topo_mod_dprintf(mod,
		    "%s called with NULL parent for type %s\n",
		    _ENUM_NAME, hcfmri->hc_name);
		return (-1);
	}

	/* Create the FMRI for this node */
	auth = topo_mod_auth(mod, t_bindparent);
	fmri = topo_mod_hcfmri(mod, t_fmriparent, FM_HC_SCHEME_VERSION,
	    hcfmri->hc_name, hcfmri->instance, NULL, auth,
	    hcfmri->part_number, hcfmri->version, hcfmri->serial_number);

	nvlist_free(auth);

	if (fmri == NULL) {
		topo_mod_dprintf(mod,
		    "%s failed to create %s fmri : %s\n", _ENUM_NAME,
		    hcfmri->hc_name, topo_strerror(topo_mod_errno(mod)));
		return (-1);
	}

	rv = topo_node_range_create(mod, t_bindparent, hcfmri->hc_name, 0, 4);
	if (rv != 0 && topo_mod_errno(mod) != EMOD_NODE_DUP) {
		topo_mod_dprintf(mod, "%s range create failed for node %s\n",
		    _ENUM_NAME, hcfmri->hc_name);
	}

	/* Bind this node to the parent */
	*t_node = x86pi_node_bind(mod, t_bindparent, hcfmri, fmri, flag);
	nvlist_free(fmri);
	if (*t_node == NULL) {
		topo_mod_dprintf(mod,
		    "%s failed to bind %s node instance %d: %s\n",
		    _ENUM_NAME, hcfmri->hc_name, hcfmri->instance,
		    topo_strerror(topo_mod_errno(mod)));
		return (-1);
	}

	/* call IPMI facility provider to register fac methods */
	if (topo_mod_load(mod, _FAC_PROV, TOPO_VERSION) == NULL) {
		topo_mod_dprintf(mod,
		    "%s: Failed to load %s module: %s\n", _ENUM_NAME, _FAC_PROV,
		    topo_mod_errmsg(mod));
		return (-1);
	}

	rv = topo_mod_enumerate(mod, *t_node, _FAC_PROV, _FAC_PROV, 0, 0, NULL);
	if (rv != 0) {
		topo_mod_dprintf(mod,
		    "%s: %s failed: %s\n", _ENUM_NAME, _FAC_PROV,
		    topo_mod_errmsg(mod));
		return (-1);
	}

	/* invoke fac_prov_ipmi_enum method */
	if (topo_method_supported(*t_node, TOPO_METH_FAC_ENUM, 0)) {
		if (topo_method_invoke(*t_node, TOPO_METH_FAC_ENUM, 0, NULL,
		    &out, &err) != 0) {
			/* log the error and drive on */
			topo_mod_dprintf(mod,
			    "%s: TOPO_METH_FAC_ENUM failed\n", _ENUM_NAME);
		} else {
			fac_done = 1;
		}
	}

	topo_mod_dprintf(mod, "%s added (%s) node\n", _ENUM_NAME,
	    topo_node_name(*t_node));

	return (0);
}


tnode_t *
x86pi_node_bind(topo_mod_t *mod, tnode_t *t_parent, x86pi_hcfmri_t *hcfmri,
    nvlist_t *fmri, int flag)
{
	int	result;
	tnode_t	*t_node;
	char	*f = "x86pi_node_bind";

	if (t_parent == NULL) {
		topo_mod_dprintf(mod,
		    "%s: NULL parent for %s node instance %d\n",
		    f, hcfmri->hc_name, hcfmri->instance);
		return (NULL);
	}

	/* Bind this node to the parent */
	t_node = topo_node_bind(mod, t_parent, hcfmri->hc_name,
	    hcfmri->instance, fmri);
	if (t_node == NULL) {
		topo_mod_dprintf(mod,
		    "%s: failed to bind %s node instance %d: %s\n",
		    f, hcfmri->hc_name, (uint32_t)hcfmri->instance,
		    topo_strerror(topo_mod_errno(mod)));
		return (NULL);
	}
	topo_mod_dprintf(mod, "%s: bound %s node instance %d type %s\n",
	    f, hcfmri->hc_name, hcfmri->instance, hcfmri->hc_name);

	/*
	 * We have bound the node.  Now decorate it with an appropriate
	 * FRU and label (which may be inherited from the parent).
	 */
	result = x86pi_set_frufmri(mod, hcfmri, t_parent, t_node, flag);
	if (result != 0) {
		/*
		 * Though we have failed to set the FRU FMRI we still continue.
		 * The module errno is set by the called routine, so we report
		 * the problem and move on.
		 */
		topo_mod_dprintf(mod,
		    "%s: failed to set FRU FMRI for %s node\n",
		    f, hcfmri->hc_name);
	}

	result = x86pi_set_label(mod, hcfmri->location, hcfmri->hc_name,
	    t_node);
	if (result != 0) {
		/*
		 * Though we have failed to set the label, we still continue.
		 * The module errno is set by the called routine, so we report
		 * the problem and move on.
		 */
		topo_mod_dprintf(mod, "%s: no label for %s node\n",
		    f, hcfmri->hc_name);
	}

	result = x86pi_set_auth(mod, hcfmri, t_parent, t_node);
	if (result != 0) {
		/*
		 * Though we have failed to set the authority, we still
		 * continue. The module errno is set by the called routine, so
		 * we report the problem and move on.
		 */
		topo_mod_dprintf(mod,
		    "%s: no authority information for %s node\n",
		    f, hcfmri->hc_name);
	}

	result = x86pi_set_system(mod, t_node);
	if (result != 0) {
		/*
		 * Though we have failed to set the system group, we still
		 * continue. The module errno is set by the called routine, so
		 * we report the problem and move on.
		 */
		topo_mod_dprintf(mod,
		    "%s: no system information for %s node\n",
		    f, hcfmri->hc_name);
	}

	return (t_node);
}
