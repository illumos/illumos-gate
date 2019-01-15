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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <assert.h>
#include <pthread.h>
#include <strings.h>
#include <sys/fm/protocol.h>

#include <topo_alloc.h>
#include <topo_error.h>
#include <topo_method.h>
#include <topo_prop.h>
#include <topo_protocol.h>
#include <topo_subr.h>

#include <libtopo.h>

int
topo_node_asru(tnode_t *node, nvlist_t **asru, nvlist_t *priv, int *err)
{
	nvlist_t *prop, *ap;

	if (topo_prop_getprop(node, TOPO_PGROUP_PROTOCOL,
	    TOPO_PROP_ASRU, priv, &prop, err) < 0)
		return (-1);

	if (nvlist_lookup_nvlist(prop, TOPO_PROP_VAL_VAL, &ap) != 0 ||
	    topo_hdl_nvdup(node->tn_hdl, ap, asru) < 0) {
		*err = ETOPO_PROP_NVL;
		nvlist_free(prop);
		return (-1);
	}

	nvlist_free(prop);

	return (0);
}

int
topo_node_fru(tnode_t *node, nvlist_t **fru, nvlist_t *priv, int *err)
{
	nvlist_t *prop, *fp;

	if (topo_prop_getprop(node, TOPO_PGROUP_PROTOCOL, TOPO_PROP_FRU,
	    priv, &prop, err) < 0)
		return (-1);

	if (nvlist_lookup_nvlist(prop, TOPO_PROP_VAL_VAL, &fp) != 0 ||
	    topo_hdl_nvdup(node->tn_hdl, fp, fru) < 0) {
		*err = ETOPO_PROP_NVL;
		nvlist_free(prop);
		return (-1);
	}

	nvlist_free(prop);

	return (0);
}

int
topo_node_resource(tnode_t *node, nvlist_t **resource, int *err)
{

	return (topo_prop_get_fmri(node, TOPO_PGROUP_PROTOCOL,
	    TOPO_PROP_RESOURCE, resource, err));
}

int
topo_node_label(tnode_t *node, char **label, int *err)
{

	return (topo_prop_get_string(node, TOPO_PGROUP_PROTOCOL,
	    TOPO_PROP_LABEL, label, err));
}

int
topo_node_asru_set(tnode_t *node, nvlist_t *asru, int flag, int *err)
{
	/*
	 * Inherit ASRU property from our parent if asru not specified
	 */
	if (asru == NULL) {
		if (topo_prop_inherit(node, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_ASRU, err) < 0) {
			return (-1);
		}

		return (0);
	}

	if (flag & TOPO_ASRU_COMPUTE) {
		if (topo_prop_method_register(node, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_ASRU, TOPO_TYPE_FMRI, TOPO_METH_ASRU_COMPUTE,
		    asru, err) < 0)
			return (-1);
	} else {
		if (topo_prop_set_fmri(node, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_ASRU, TOPO_PROP_IMMUTABLE, asru, err) < 0)
			return (-1);
	}

	return (0);
}

int
topo_node_fru_set(tnode_t *node, nvlist_t *fru, int flag, int *err)
{

	/*
	 * Inherit FRU property from our parent if not specified
	 */
	if (fru == NULL) {
		if (topo_prop_inherit(node, TOPO_PGROUP_PROTOCOL, TOPO_PROP_FRU,
		    err) < 0) {
			return (-1);
		}
	} else if (flag & TOPO_FRU_COMPUTE) {
		if (topo_prop_method_register(node, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_FRU, TOPO_TYPE_FMRI, TOPO_METH_FRU_COMPUTE,
		    fru, err) < 0)
			return (-1);
	} else {
		if (topo_prop_set_fmri(node, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_FRU, TOPO_PROP_IMMUTABLE, fru, err) < 0)
			return (-1);
	}


	return (0);
}

int
topo_node_label_set(tnode_t *node, const char *label, int *err)
{

	/*
	 * Inherit label property from our parent if * not specified
	 */
	if (label == NULL) {
		if (topo_prop_inherit(node, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_LABEL, err) < 0) {
			return (-1);
		}
	} else {
		if (topo_prop_set_string(node, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_LABEL, TOPO_PROP_IMMUTABLE, label, err) < 0)
			return (-1);
	}

	return (0);
}
