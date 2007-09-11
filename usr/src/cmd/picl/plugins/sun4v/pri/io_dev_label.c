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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "priplugin.h"

static int
find_node_by_string_prop(picl_nodehdl_t rooth, const char *pname,
    const char *pval, picl_nodehdl_t *nodeh);
static int
compare_string_propval(picl_nodehdl_t nodeh, const char *pname,
    const char *pval);

/*
 * Gather IO device nodes from the PRI and use the info to
 * find the corresponding nodes in PICL's device tree, insert
 * a Label into the devtree containing the "nac" from the PRI,
 * and add a reference property to the corresponding fru tree node.
 */
void
io_dev_addlabel(md_t *mdp)
{
	int status, substatus, i, node_count, component_count, busaddr_match;
	int type_size, nac_size;
	picl_nodehdl_t platnode, tpn;
	char busaddr[PICL_PROPNAMELEN_MAX], *p, *q;
	char path[PICL_PROPNAMELEN_MAX];
	mde_cookie_t *components, md_rootnode;
	char *type, *nac, *pri_path, *saved_path;

	if (mdp == NULL)
		return;

	md_rootnode = md_root_node(mdp);

	/*
	 * Find and remember the roots of the /frutree and /platform trees.
	 */
	if ((status = ptree_get_node_by_path(PLATFORM_PATH, &platnode)) !=
	    PICL_SUCCESS) {
		pri_debug(LOG_NOTICE,
		    "io_dev_label: can't find platform node: %s\n",
		    picl_strerror(status));
		return;
	}

	node_count = md_node_count(mdp);
	if (node_count == 0) {
		pri_debug(LOG_NOTICE, "io_dev_addlabel: no nodes to "
		    "process\n");
		return;
	}
	components = (mde_cookie_t *)malloc(node_count *
	    sizeof (mde_cookie_t));
	if (components == NULL) {
		pri_debug(LOG_NOTICE,
		    "io_dev_addlabel: can't get memory for IO nodes\n");
		return;
	}

	component_count = md_scan_dag(mdp, md_rootnode,
	    md_find_name(mdp, "component"),
	    md_find_name(mdp, "fwd"), components);

	for (i = 0; i < component_count; ++i) {
		tpn = platnode;

		/*
		 * Try to fetch the "type" as a string or as "data" until we
		 * can agree on what its tag type should be.
		 */
		if (md_get_prop_str(mdp, components[i], "type", &type) ==
		    -1) {
			if (md_get_prop_data(mdp, components[i], "type",
			    (uint8_t **)&type, &type_size)) {
				pri_debug(LOG_NOTICE, "io_add_devlabel: "
				    "can't get type for component %d\n", i);
			continue;
			}
		}

		/*
		 * Isolate components of type "io".
		 */
		if (strcmp((const char *)type, "io")) {
			pri_debug(LOG_NOTICE,
			    "io_add_devlabel: skipping component %d with "
			    "type %s\n", i, type);
			continue;
		}

		/*
		 * Now get the nac and raw path from the PRI.
		 */
		if (md_get_prop_str(mdp, components[i], "nac", &nac) == -1) {
			pri_debug(LOG_NOTICE,
			    "io_add_devlabel: can't get nac value for device "
			    "<%s>\n", type);
			continue;
		} else
			nac_size = strlen(nac) + 1;

		if (md_get_prop_str(mdp, components[i], "path", &pri_path) ==
		    -1) {
			pri_debug(LOG_NOTICE,
			    "io_add_devlabel: can't get path value for "
			    "device <%s>\n", type);
			continue;
		}

		(void) strlcpy(path, pri_path, sizeof (path));

		pri_debug(LOG_NOTICE, "io_add_devlabel: processing component "
		    "%d, type <%s>, nac <%s>, path <%s>\n", i, type, nac,
		    path);

		/*
		 * This loop visits each path component where those
		 * components are delimited with '/' and '@' characters.
		 * Each path component is a search key into the /platform
		 * tree; we're looking to match the bus-addr field of
		 * a node if that field is defined.  If each path component
		 * matches up then we now have the corresponding device
		 * path for that IO device.  Add a Label property to the
		 * leaf node.
		 */
		for (busaddr_match = 1, p = q = (char *)path; q; p = q + 1) {

			/*
			 * Isolate the bus address for this node by skipping
			 * over the first delimiter if present and writing
			 * a NUL character over the next '/'.
			 */
			if (*p == '/')
				++p;
			if (*p == '@')
				++p;
			if ((q = strchr((const char *)p, '/')) != NULL)
				*q = '\0';

			/*
			 * See if there's a match, at this level only, in the
			 * device tree.  We cannot skip generations in the
			 * device tree, which is why we're not doing a
			 * recursive search for bus-addr.  bus-addr must
			 * be found at each node along the way.  By doing
			 * this we'll stay in sync with the path components
			 * in the PRI.
			 */
			if ((status = find_node_by_string_prop(tpn,
			    PICL_PROP_BUS_ADDR, (const char *)p, &tpn)) !=
			    PICL_SUCCESS) {
				pri_debug(LOG_NOTICE,
				    "can't find %s property of <%s> "
				    "for nac %s: %s\n",
				    PICL_PROP_BUS_ADDR, p, nac,
				    picl_strerror(status));
				busaddr_match = 0;
				break;
			}

			/*
			 * Note path component for the leaf so we can use
			 * it below.
			 */
			saved_path = p;
		}

		/*
		 * We could not drill down through the bus-addrs, so skip this
		 * device and move on to the next.
		 */
		if (busaddr_match == 0) {
			pri_debug(LOG_NOTICE, "io_add_devlabel: no matching "
			    "bus-addr path for this nac - skipping\n");
			continue;
		}

		nac_size = strlen((const char *)nac) + 1;

		/*
		 * This loop adds a Label property to all the functions
		 * on the device we matched from the PRI path.
		 */
		for (status = PICL_SUCCESS; status == PICL_SUCCESS;
		    status = ptree_get_propval_by_name(tpn,
		    PICL_PROP_PEER, &tpn, sizeof (picl_nodehdl_t))) {
			/*
			 * Add Labels to peers that have the same bus-addr
			 * value (ignoring the function numbers.)
			 */
			if ((substatus = ptree_get_propval_by_name(tpn,
			    PICL_PROP_BUS_ADDR,
			    busaddr, sizeof (busaddr))) != PICL_SUCCESS) {
				pri_debug(LOG_NOTICE,
				    "io_add_device: can't get %s "
				    "property from picl devtree: %s\n",
				    PICL_PROP_BUS_ADDR,
				    picl_strerror(substatus));
			} else {
				if (strncmp(busaddr, saved_path,
				    PICL_PROPNAMELEN_MAX) == 0) {
					add_md_prop(tpn, nac_size,
					    PICL_PROP_LABEL, nac,
					    PICL_PTYPE_CHARSTRING);
				}
			}
		}
	}
}

/*
 * These two functions shamelessly stolen from picldevtree.c
 */

/*
 * Return 1 if this node has this property with the given value.
 */
static int
compare_string_propval(picl_nodehdl_t nodeh, const char *pname,
    const char *pval)
{
	char *pvalbuf;
	int err;
	int len;
	ptree_propinfo_t pinfo;
	picl_prophdl_t proph;

	err = ptree_get_prop_by_name(nodeh, pname, &proph);
	if (err != PICL_SUCCESS)	/* prop doesn't exist */
		return (0);

	err = ptree_get_propinfo(proph, &pinfo);
	if (pinfo.piclinfo.type != PICL_PTYPE_CHARSTRING)
		return (0);	/* not string prop */

	len = strlen(pval) + 1;

	pvalbuf = alloca(len);
	if (pvalbuf == NULL)
		return (0);

	err = ptree_get_propval(proph, pvalbuf, len);
	if ((err == PICL_SUCCESS) && (strcmp(pvalbuf, pval) == 0))
		return (1);	/* prop match */

	return (0);
}

/*
 * Search this node's children for the given property.
 */
static int
find_node_by_string_prop(picl_nodehdl_t rooth, const char *pname,
    const char *pval, picl_nodehdl_t *nodeh)
{
	picl_nodehdl_t childh;
	int err;

	for (err = ptree_get_propval_by_name(rooth, PICL_PROP_CHILD, &childh,
	    sizeof (picl_nodehdl_t)); err != PICL_PROPNOTFOUND;
	    err = ptree_get_propval_by_name(childh, PICL_PROP_PEER,
	    &childh, sizeof (picl_nodehdl_t))) {
		if (err != PICL_SUCCESS)
			return (err);

		if (compare_string_propval(childh, pname, pval)) {
			*nodeh = childh;
			return (PICL_SUCCESS);
		}
	}
	return (PICL_ENDOFLIST);
}
