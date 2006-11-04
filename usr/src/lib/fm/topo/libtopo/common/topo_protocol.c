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

#include <assert.h>
#include <pthread.h>
#include <strings.h>
#include <sys/fm/protocol.h>

#include <topo_alloc.h>
#include <topo_error.h>
#include <topo_method.h>
#include <topo_protocol.h>
#include <topo_subr.h>

#include <libtopo.h>

static int
topo_compute(tnode_t *node, nvlist_t *stub, const char *method,
    topo_version_t version, nvlist_t *rsrc, nvlist_t **asru, int *err)
{
	int rc;
	char *scheme;
	topo_hdl_t *thp = node->tn_hdl;
	tnode_t *rnode;

	/*
	 * First try the originating enumerator for
	 * a compute method.  If none is supported, try the
	 * node's scheme-specific enumerator.
	 */
	if (topo_method_invoke(node, method, version, rsrc, asru, err) == 0)
		return (0);

	if (*err != ETOPO_METHOD_NOTSUP)
		return (-1);

	if ((rc = nvlist_lookup_string(stub, FM_FMRI_SCHEME, &scheme)) != 0) {
		if (rc == ENOENT) {
			*err = ETOPO_FMRI_MALFORM;
		} else {
			*err = ETOPO_FMRI_NVL;
		}
		return (-1);
	}

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL) {
		*err = ETOPO_METHOD_NOTSUP;
		return (-1);
	}

	if (topo_method_invoke(rnode, method, version, rsrc, asru, err) != 0)
		return (-1);

	return (0);
}

int
topo_node_asru(tnode_t *node, nvlist_t **asru, nvlist_t *priv, int *err)
{
	int rc;
	nvlist_t *ap;

	if (topo_prop_get_fmri(node, TOPO_PGROUP_PROTOCOL, TOPO_PROP_ASRU, &ap,
	    err) != 0)
		return (-1);

	if (node->tn_fflags & TOPO_ASRU_COMPUTE) {
		rc = topo_compute(node, ap, TOPO_METH_ASRU_COMPUTE,
		    TOPO_METH_ASRU_COMPUTE_VERSION, priv, asru, err);
		nvlist_free(ap);
		return (rc);
	} else {
		*asru = ap;
		return (0);
	}
}

int
topo_node_fru(tnode_t *node, nvlist_t **fru, nvlist_t *priv, int *err)
{
	int rc;
	nvlist_t *fp;

	if (topo_prop_get_fmri(node, TOPO_PGROUP_PROTOCOL, TOPO_PROP_FRU, &fp,
	    err) != 0)
		return (-1);

	if (node->tn_fflags & TOPO_FRU_COMPUTE) {
		rc = topo_compute(node, fp, TOPO_METH_FRU_COMPUTE,
		    TOPO_METH_FRU_COMPUTE_VERSION, priv, fru, err);
		nvlist_free(fp);
		return (rc);
	} else {
		*fru = fp;
		return (0);
	}
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
	 * Inherit ASRU property from our parent if not specified
	 */
	if (asru == NULL) {
		if (topo_prop_inherit(node, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_ASRU, err) < 0) {
			return (-1);
		}
	} else {
		/*
		 * ASRU must be computed on the fly.  asru will
		 * contain the scheme module to call for the
		 * computation
		 */
		if (flag & TOPO_ASRU_COMPUTE)
			node->tn_fflags |= TOPO_ASRU_COMPUTE;

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
	 * Inherit FRU property from our parent if * not specified
	 */
	if (fru == NULL) {
		if (topo_prop_inherit(node, TOPO_PGROUP_PROTOCOL, TOPO_PROP_FRU,
		    err) < 0) {
			return (-1);
		}
	} else {
		/*
		 * FRU must be computed on the fly
		 */
		if (flag & TOPO_FRU_COMPUTE)
			node->tn_fflags |= TOPO_FRU_COMPUTE;

		if (topo_prop_set_fmri(node, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_FRU, TOPO_PROP_IMMUTABLE, fru, err) < 0)
			return (-1);
	}

	return (0);
}

int
topo_node_label_set(tnode_t *node, char *label, int *err)
{

	/*
	 * Inherit FRU property from our parent if * not specified
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
