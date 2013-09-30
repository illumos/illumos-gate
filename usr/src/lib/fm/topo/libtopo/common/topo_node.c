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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Topology Nodes
 *
 * Topology nodes, tnode_t, are data structures containing per-FMRI
 * information and are linked together to form the topology tree.
 * Nodes are created during the enumeration process of topo_snap_hold()
 * and destroyed during topo_snap_rele().  For the most part, tnode_t data
 * is read-only and no lock protection is required.  Nodes are
 * held in place during tree walk functions.  Tree walk functions
 * may access node data safely without locks.  The exception to this rule
 * is data associated with node properties (topo_prop.c).  Properties
 * may change at anytime and are protected by a per-property locking
 * strategy.
 *
 * Enumerator plugin modules may also safely access topology nodes within their
 * scope of operation: the parent node passed into the enumeration op or those
 * nodes created by the enumerator.  Enumeration occurs only during
 * topo_snap_hold() where a per-topo_hdl_t lock prevents multi-threaded access
 * to the topology trees.
 *
 * Enumerator method operation functions may safely access and change topology
 * node property data, and contruct or destroy child nodes for the node
 * on which the operation applies.  The method may also be called to destroy
 * the node for which the method operation is called.  This permits
 * dynamic topology tree snapshots and partial enumerations for branches that
 * may not be needed right away.
 *
 * Node Interfaces
 *
 * Nodes are created when an enumerator calls topo_node_bind().  Prior to
 * calling topo_node_bind(), the enumerator should have reserved a range of
 * node instances with topo_node_range_create().  topo_node_range_create()
 * does not allocate any node resources but creates the infrastruture
 * required for a fully populated topology level.  This allows enumerators
 * reading from a <scheme>-topology.xml file to parse the file for a range
 * of resources before confirming the existence of a resource via a helper
 * plugin.  Only when the resource has been confirmed to exist should
 * the node be bound.
 *
 * Node range and node linkage and unlinkage is performed during enumeration and
 * method operations when it is safe to change node hash lists. Nodes and node
 * ranges are deallocated when all references to the node have been released:
 * last walk completes and topo_snap_rele() is called.
 *
 * Node Hash/Ranges
 *
 * Each parent node may have one or more ranges of child nodes.  Each range
 * is uniquely named and serves as a hash list of like sibling nodes with
 * different instance numbers.  A parent may have more than one node hash
 * (child range). If that is the case, the hash lists are strung together to
 * form sibling relationships between ranges.  Hash/Ranges are sparsely
 * populated with only nodes that have represented resources in the system.
 *
 *	_________________
 *	|		|
 *      |   tnode_t	|    -----------------------------
 *      |      tn_phash ---> |  topo_nodehash_t          |
 *      |     (children)|    |     th_nodearr (instances)|
 *      -----------------    |     -------------------   |
 *                           |  ---| 0 | 1  | ...| N |   |
 *                           |  |  -------------------   |  -------------------
 *                           |  |  th_list (siblings) ----->| topo_nodehash_t |
 *                           |  |                        |  -------------------
 *                           ---|-------------------------
 *                              |
 *                              v
 *                           -----------
 *                           | tnode_t |
 *                           -----------
 *
 * Facility Nodes
 *
 * Facility nodes are always leaf nodes in the topology and represent a FMRI
 * sensor or indicator facility for the path to which it is connected.
 * Facility nodes are bound to the topology with topo_node_facbind() and
 * unbound with topo_node_unbind().
 */

#include <assert.h>
#include <pthread.h>
#include <strings.h>
#include <sys/fm/protocol.h>
#include <topo_alloc.h>
#include <topo_error.h>
#include <topo_list.h>
#include <topo_method.h>
#include <topo_subr.h>
#include <topo_tree.h>

static topo_pgroup_info_t protocol_pgroup = {
	TOPO_PGROUP_PROTOCOL,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t auth_pgroup = {
	FM_FMRI_AUTHORITY,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static void
topo_node_destroy(tnode_t *node)
{
	int i;
	tnode_t *pnode = node->tn_parent;
	topo_nodehash_t *nhp;
	topo_mod_t *hmod, *mod = node->tn_enum;

	if (node == NULL)
		return;

	topo_dprintf(mod->tm_hdl, TOPO_DBG_MODSVC, "destroying node %s=%d\n",
	    topo_node_name(node), topo_node_instance(node));

	assert(node->tn_refs == 0);

	/*
	 * If not a root node, remove this node from the parent's node hash
	 */

	if (!(node->tn_state & TOPO_NODE_ROOT)) {
		topo_node_lock(pnode);

		nhp = node->tn_phash;
		for (i = 0; i < nhp->th_arrlen; i++) {
			if (node == nhp->th_nodearr[i]) {
				nhp->th_nodearr[i] = NULL;

				/*
				 * Release hold on parent
				 */
				--pnode->tn_refs;
				if (pnode->tn_refs == 0)
					topo_node_destroy(pnode);
			}
		}
		topo_node_unlock(pnode);
	}

	topo_node_unlock(node);

	/*
	 * Allow enumerator to clean-up private data and then release
	 * ref count
	 */
	if (mod->tm_info->tmi_ops->tmo_release != NULL)
		mod->tm_info->tmi_ops->tmo_release(mod, node);

	topo_method_unregister_all(mod, node);

	/*
	 * Destroy all node hash lists
	 */
	while ((nhp = topo_list_next(&node->tn_children)) != NULL) {
		for (i = 0; i < nhp->th_arrlen; i++) {
			assert(nhp->th_nodearr[i] == NULL);
		}
		hmod = nhp->th_enum;
		topo_mod_strfree(hmod, nhp->th_name);
		topo_mod_free(hmod, nhp->th_nodearr,
		    nhp->th_arrlen * sizeof (tnode_t *));
		topo_list_delete(&node->tn_children, nhp);
		topo_mod_free(hmod, nhp, sizeof (topo_nodehash_t));
		topo_mod_rele(hmod);
	}

	/*
	 * Destroy all property data structures, free the node and release
	 * the module that created it
	 */
	topo_pgroup_destroy_all(node);
	topo_mod_free(mod, node, sizeof (tnode_t));
	topo_mod_rele(mod);
}

void
topo_node_lock(tnode_t *node)
{
	(void) pthread_mutex_lock(&node->tn_lock);
}

void
topo_node_unlock(tnode_t *node)
{
	(void) pthread_mutex_unlock(&node->tn_lock);
}

void
topo_node_hold(tnode_t *node)
{
	topo_node_lock(node);
	++node->tn_refs;
	topo_node_unlock(node);
}

void
topo_node_rele(tnode_t *node)
{
	topo_node_lock(node);
	--node->tn_refs;

	/*
	 * Ok to remove this node from the topo tree and destroy it
	 */
	if (node->tn_refs == 0)
		topo_node_destroy(node);
	else
		topo_node_unlock(node);
}

char *
topo_node_name(tnode_t *node)
{
	return (node->tn_name);
}

topo_instance_t
topo_node_instance(tnode_t *node)
{
	return (node->tn_instance);
}

tnode_t *
topo_node_parent(tnode_t *node)
{
	return (node->tn_parent);
}

int
topo_node_flags(tnode_t *node)
{
	return (node->tn_fflags);
}

void
topo_node_setspecific(tnode_t *node, void *data)
{
	node->tn_priv = data;
}

void *
topo_node_getspecific(tnode_t *node)
{
	return (node->tn_priv);
}

static int
node_create_seterror(topo_mod_t *mod, tnode_t *pnode, topo_nodehash_t *nhp,
    int err)
{
	topo_node_unlock(pnode);

	topo_dprintf(mod->tm_hdl, TOPO_DBG_ERR, "unable to insert child:"
	    "%s\n", topo_strerror(err));

	if (nhp != NULL) {
		if (nhp->th_name != NULL)
			topo_mod_strfree(mod, nhp->th_name);
		if (nhp->th_nodearr != NULL) {
			topo_mod_free(mod, nhp->th_nodearr,
			    nhp->th_arrlen * sizeof (tnode_t *));
		}
		topo_mod_free(mod, nhp, sizeof (topo_nodehash_t));
	}

	return (topo_mod_seterrno(mod, err));
}

int
topo_node_range_create(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max)
{
	topo_nodehash_t *nhp;

	topo_node_lock(pnode);

	assert((pnode->tn_state & TOPO_NODE_BOUND) ||
	    (pnode->tn_state & TOPO_NODE_ROOT));

	for (nhp = topo_list_next(&pnode->tn_children); nhp != NULL;
	    nhp = topo_list_next(nhp)) {
		if (strcmp(nhp->th_name, name) == 0)
			return (node_create_seterror(mod, pnode, NULL,
			    EMOD_NODE_DUP));
	}

	if (min < 0 || max < min)
		return (node_create_seterror(mod, pnode, NULL,
		    EMOD_NODE_RANGE));

	if ((nhp = topo_mod_zalloc(mod, sizeof (topo_nodehash_t))) == NULL)
		return (node_create_seterror(mod, pnode, nhp, EMOD_NOMEM));

	if ((nhp->th_name = topo_mod_strdup(mod, name)) == NULL)
		return (node_create_seterror(mod, pnode, nhp, EMOD_NOMEM));

	nhp->th_arrlen = max - min + 1;

	if ((nhp->th_nodearr = topo_mod_zalloc(mod,
	    nhp->th_arrlen * sizeof (tnode_t *))) == NULL)
		return (node_create_seterror(mod, pnode, nhp, EMOD_NOMEM));

	nhp->th_range.tr_min = min;
	nhp->th_range.tr_max = max;
	nhp->th_enum = mod;
	topo_mod_hold(mod);

	/*
	 * Add these nodes to parent child list
	 */
	topo_list_append(&pnode->tn_children, nhp);
	topo_node_unlock(pnode);

	topo_dprintf(mod->tm_hdl, TOPO_DBG_MODSVC,
	    "created node range %s[%d-%d]\n", name, min, max);

	return (0);
}

void
topo_node_range_destroy(tnode_t *pnode, const char *name)
{
	int i;
	topo_nodehash_t *nhp;
	topo_mod_t *mod;

	topo_node_lock(pnode);
	for (nhp = topo_list_next(&pnode->tn_children); nhp != NULL;
	    nhp = topo_list_next(nhp)) {
		if (strcmp(nhp->th_name, name) == 0) {
			break;
		}
	}

	if (nhp == NULL) {
		topo_node_unlock(pnode);
		return;
	}

	for (i = 0; i < nhp->th_arrlen; i++)
		assert(nhp->th_nodearr[i] == NULL);

	topo_list_delete(&pnode->tn_children, nhp);
	topo_node_unlock(pnode);

	mod = nhp->th_enum;
	if (nhp->th_name != NULL)
		topo_mod_strfree(mod, nhp->th_name);
	if (nhp->th_nodearr != NULL) {
		topo_mod_free(mod, nhp->th_nodearr,
		    nhp->th_arrlen * sizeof (tnode_t *));
	}
	topo_mod_free(mod, nhp, sizeof (topo_nodehash_t));
	topo_mod_rele(mod);

}

tnode_t *
topo_node_lookup(tnode_t *pnode, const char *name, topo_instance_t inst)
{
	int h;
	tnode_t *node;
	topo_nodehash_t *nhp;

	topo_dprintf(pnode->tn_hdl, TOPO_DBG_MODSVC,
	    "topo_node_lookup: looking for '%s' instance %d\n", name, inst);

	topo_node_lock(pnode);
	for (nhp = topo_list_next(&pnode->tn_children); nhp != NULL;
	    nhp = topo_list_next(nhp)) {
		if (strcmp(nhp->th_name, name) == 0) {

			if (inst > nhp->th_range.tr_max ||
			    inst < nhp->th_range.tr_min) {
				topo_node_unlock(pnode);
				return (NULL);
			}

			h = topo_node_hash(nhp, inst);
			node = nhp->th_nodearr[h];
			topo_node_unlock(pnode);
			return (node);
		}
	}
	topo_node_unlock(pnode);

	return (NULL);
}

int
topo_node_hash(topo_nodehash_t *nhp, topo_instance_t inst)
{
	return ((inst - nhp->th_range.tr_min) % nhp->th_arrlen);
}

static tnode_t *
node_bind_seterror(topo_mod_t *mod, tnode_t *pnode, tnode_t *node,
    boolean_t pnode_locked, int err)
{
	if (pnode_locked)
		topo_node_unlock(pnode);

	(void) topo_mod_seterrno(mod, err);

	if (node == NULL)
		return (NULL);

	topo_dprintf(mod->tm_hdl, TOPO_DBG_ERR, "unable to bind %s=%d: "
	    "%s\n", (node->tn_name != NULL ? node->tn_name : "unknown"),
	    node->tn_instance, topo_strerror(err));

	topo_node_lock(node); /* expected to be locked */
	topo_node_destroy(node);

	return (NULL);
}

tnode_t *
topo_node_bind(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t inst, nvlist_t *fmri)
{
	int h, err;
	tnode_t *node;
	topo_nodehash_t *nhp;

	topo_node_lock(pnode);
	for (nhp = topo_list_next(&pnode->tn_children); nhp != NULL;
	    nhp = topo_list_next(nhp)) {
		if (strcmp(nhp->th_name, name) == 0) {

			if (inst > nhp->th_range.tr_max ||
			    inst < nhp->th_range.tr_min)
				return (node_bind_seterror(mod, pnode, NULL,
				    B_TRUE, EMOD_NODE_RANGE));

			h = topo_node_hash(nhp, inst);
			if (nhp->th_nodearr[h] != NULL)
				return (node_bind_seterror(mod, pnode, NULL,
				    B_TRUE, EMOD_NODE_BOUND));
			else
				break;

		}
	}

	if (nhp == NULL)
		return (node_bind_seterror(mod, pnode, NULL, B_TRUE,
		    EMOD_NODE_NOENT));

	if ((node = topo_mod_zalloc(mod, sizeof (tnode_t))) == NULL)
		return (node_bind_seterror(mod, pnode, NULL, B_TRUE,
		    EMOD_NOMEM));

	(void) pthread_mutex_init(&node->tn_lock, NULL);

	node->tn_enum = mod;
	node->tn_hdl = mod->tm_hdl;
	node->tn_parent = pnode;
	node->tn_name = nhp->th_name;
	node->tn_instance = inst;
	node->tn_phash = nhp;
	node->tn_refs = 0;

	/* Ref count module that bound this node */
	topo_mod_hold(mod);

	if (fmri == NULL)
		return (node_bind_seterror(mod, pnode, node, B_TRUE,
		    EMOD_NVL_INVAL));

	if (topo_pgroup_create(node, &protocol_pgroup, &err) < 0)
		return (node_bind_seterror(mod, pnode, node, B_TRUE, err));

	if (topo_prop_set_fmri(node, TOPO_PGROUP_PROTOCOL, TOPO_PROP_RESOURCE,
	    TOPO_PROP_IMMUTABLE, fmri, &err) < 0)
		return (node_bind_seterror(mod, pnode, node, B_TRUE, err));

	topo_dprintf(mod->tm_hdl, TOPO_DBG_MODSVC,
	    "node bound %s=%d/%s=%d\n", topo_node_name(pnode),
	    topo_node_instance(pnode), node->tn_name, node->tn_instance);

	node->tn_state |= TOPO_NODE_BOUND;

	topo_node_hold(node);
	nhp->th_nodearr[h] = node;
	++pnode->tn_refs;

	topo_node_unlock(pnode);

	if (topo_pgroup_create(node, &auth_pgroup, &err) == 0) {
		(void) topo_prop_inherit(node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, &err);
		(void) topo_prop_inherit(node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT_SN, &err);
		(void) topo_prop_inherit(node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, &err);
		(void) topo_prop_inherit(node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, &err);
	}

	return (node);
}

tnode_t *
topo_node_facbind(topo_mod_t *mod, tnode_t *pnode, const char *name,
    const char *type)
{
	int h, err;
	tnode_t *node;
	topo_nodehash_t *nhp;
	topo_instance_t inst = 0;
	nvlist_t *pfmri, *fnvl;

	/*
	 * Create a single entry range for this facility
	 */
	if (topo_node_range_create(mod, pnode, name, 0, 0) < 0)
		return (NULL);  /* mod errno set */

	topo_node_hold(pnode);
	topo_node_lock(pnode);
	for (nhp = topo_list_next(&pnode->tn_children); nhp != NULL;
	    nhp = topo_list_next(nhp)) {
		if (strcmp(nhp->th_name, name) == 0) {

			if (inst > nhp->th_range.tr_max ||
			    inst < nhp->th_range.tr_min) {
				topo_node_rele(pnode);
				return (node_bind_seterror(mod, pnode, NULL,
				    B_TRUE, EMOD_NVL_INVAL));
			}
			h = topo_node_hash(nhp, inst);
			if (nhp->th_nodearr[h] != NULL) {
				topo_node_rele(pnode);
				return (node_bind_seterror(mod, pnode, NULL,
				    B_TRUE, EMOD_NODE_BOUND));
			} else
				break;

		}
	}
	topo_node_unlock(pnode);

	if (nhp == NULL) {
		topo_node_rele(pnode);
		return (node_bind_seterror(mod, pnode, NULL, B_FALSE,
		    EMOD_NODE_NOENT));
	}
	if ((node = topo_mod_zalloc(mod, sizeof (tnode_t))) == NULL) {
		topo_node_rele(pnode);
		return (node_bind_seterror(mod, pnode, NULL, B_FALSE,
		    EMOD_NOMEM));
	}

	(void) pthread_mutex_init(&node->tn_lock, NULL);

	node->tn_enum = mod;
	node->tn_hdl = mod->tm_hdl;
	node->tn_parent = pnode;
	node->tn_name = nhp->th_name;
	node->tn_instance = inst;
	node->tn_phash = nhp;
	node->tn_refs = 0;
	node->tn_fflags = TOPO_NODE_FACILITY;

	/* Ref count module that bound this node */
	topo_mod_hold(mod);

	if (topo_pgroup_create(node, &protocol_pgroup, &err) < 0) {
		topo_node_rele(pnode);
		return (node_bind_seterror(mod, pnode, node, B_FALSE, err));
	}
	if (topo_mod_nvalloc(mod, &fnvl, NV_UNIQUE_NAME) < 0) {
		topo_node_rele(pnode);
		return (node_bind_seterror(mod, pnode, node, B_FALSE,
		    EMOD_NOMEM));
	}
	if (nvlist_add_string(fnvl, FM_FMRI_FACILITY_NAME, name) != 0 ||
	    nvlist_add_string(fnvl, FM_FMRI_FACILITY_TYPE, type) != 0) {
		nvlist_free(fnvl);
		topo_node_rele(pnode);
		return (node_bind_seterror(mod, pnode, node,  B_FALSE,
		    EMOD_FMRI_NVL));
	}

	if (topo_node_resource(pnode, &pfmri, &err) < 0) {
		nvlist_free(fnvl);
		topo_node_rele(pnode);
		return (node_bind_seterror(mod, pnode, node, B_FALSE, err));
	}

	if (nvlist_add_nvlist(pfmri, FM_FMRI_FACILITY, fnvl) != 0) {
		nvlist_free(fnvl);
		nvlist_free(pfmri);
		topo_node_rele(pnode);
		return (node_bind_seterror(mod, pnode, node,  B_FALSE,
		    EMOD_FMRI_NVL));
	}

	nvlist_free(fnvl);

	if (topo_prop_set_fmri(node, TOPO_PGROUP_PROTOCOL, TOPO_PROP_RESOURCE,
	    TOPO_PROP_IMMUTABLE, pfmri, &err) < 0) {
		nvlist_free(pfmri);
		topo_node_rele(pnode);
		return (node_bind_seterror(mod, pnode, node, B_FALSE, err));
	}

	nvlist_free(pfmri);

	topo_dprintf(mod->tm_hdl, TOPO_DBG_MODSVC,
	    "facility node bound %s=%s\n", type, node->tn_name);

	node->tn_state |= TOPO_NODE_BOUND;

	topo_node_hold(node);
	nhp->th_nodearr[h] = node;

	topo_node_lock(pnode);
	++pnode->tn_refs;
	topo_node_unlock(pnode);
	topo_node_rele(pnode);

	if (topo_pgroup_create(node, &auth_pgroup, &err) == 0) {
		(void) topo_prop_inherit(node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, &err);
		(void) topo_prop_inherit(node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT_SN, &err);
		(void) topo_prop_inherit(node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, &err);
		(void) topo_prop_inherit(node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, &err);
	}

	return (node);
}

int
topo_node_facility(topo_hdl_t *thp, tnode_t *node, const char *fac_type,
    uint32_t fac_subtype, topo_faclist_t *faclist, int *errp)
{
	tnode_t *tmp;
	nvlist_t *rsrc, *fac;
	char *tmp_factype;
	uint32_t tmp_facsubtype;
	boolean_t list_empty = 1;
	topo_faclist_t *fac_ele;

	bzero(faclist, sizeof (topo_faclist_t));
	for (tmp = topo_child_first(node); tmp != NULL;
	    tmp = topo_child_next(node, tmp)) {

		topo_node_hold(tmp);
		/*
		 * If it's not a facility node, move on
		 */
		if (topo_node_flags(tmp) != TOPO_NODE_FACILITY) {
			topo_node_rele(tmp);
			continue;
		}

		/*
		 * Lookup whether the fac type is sensor or indicator and if
		 * it's not the type we're looking for, move on
		 */
		if (topo_node_resource(tmp, &rsrc, errp) != 0) {
			topo_dprintf(thp, TOPO_DBG_ERR,
			    "Failed to get resource for node %s=%d (%s)\n",
			    topo_node_name(node), topo_node_instance(node),
			    topo_strerror(*errp));
			topo_node_rele(tmp);
			return (-1);
		}
		if ((nvlist_lookup_nvlist(rsrc, "facility", &fac) != 0) ||
		    (nvlist_lookup_string(fac, FM_FMRI_FACILITY_TYPE,
		    &tmp_factype) != 0)) {

			nvlist_free(rsrc);
			topo_node_rele(tmp);
			return (-1);
		}

		if (strcmp(fac_type, tmp_factype) != 0) {
			topo_node_rele(tmp);
			nvlist_free(rsrc);
			continue;
		}
		nvlist_free(rsrc);

		/*
		 * Finally, look up the subtype, which is a property in the
		 * facility propgroup.  If it's a match return a pointer to the
		 * node.  Otherwise, move on.
		 */
		if (topo_prop_get_uint32(tmp, TOPO_PGROUP_FACILITY,
		    TOPO_FACILITY_TYPE, &tmp_facsubtype, errp) != 0) {
			topo_node_rele(tmp);
			return (-1);
		}
		if (fac_subtype == tmp_facsubtype ||
		    fac_subtype == TOPO_FAC_TYPE_ANY) {
			if ((fac_ele = topo_mod_zalloc(tmp->tn_enum,
			    sizeof (topo_faclist_t))) == NULL) {
				*errp = ETOPO_NOMEM;
				topo_node_rele(tmp);
				return (-1);
			}
			fac_ele->tf_node = tmp;
			topo_list_append(&faclist->tf_list, fac_ele);
			list_empty = 0;
		}
		topo_node_rele(tmp);
	}

	if (list_empty) {
		*errp = ETOPO_FAC_NOENT;
		return (-1);
	}
	return (0);
}

void
topo_node_unbind(tnode_t *node)
{
	if (node == NULL)
		return;

	topo_node_lock(node);
	if (!(node->tn_state & TOPO_NODE_BOUND)) {
		topo_node_unlock(node);
		return;
	}

	node->tn_state &= ~TOPO_NODE_BOUND;
	topo_node_unlock(node);

	topo_dprintf(node->tn_hdl, TOPO_DBG_MODSVC,
	    "node unbound %s=%d/%s=%d refs = %d\n",
	    topo_node_name(node->tn_parent),
	    topo_node_instance(node->tn_parent), node->tn_name,
	    node->tn_instance, node->tn_refs);

	topo_node_rele(node);
}

/*ARGSUSED*/
int
topo_node_present(tnode_t *node)
{
	return (0);
}

/*ARGSUSED*/
int
topo_node_contains(tnode_t *er, tnode_t *ee)
{
	return (0);
}

/*ARGSUSED*/
int
topo_node_unusable(tnode_t *node)
{
	return (0);
}

topo_walk_t *
topo_node_walk_init(topo_hdl_t *thp, topo_mod_t *mod, tnode_t *node,
    int (*cb_f)(), void *pdata, int *errp)
{
	tnode_t *child;
	topo_walk_t *wp;

	topo_node_hold(node);

	if ((wp = topo_hdl_zalloc(thp, sizeof (topo_walk_t))) == NULL) {
		*errp = ETOPO_HDL_NOMEM;
		topo_node_rele(node);
		return (NULL);
	}

	/*
	 * If this is the root of the scheme tree, start with the first
	 * child
	 */
	topo_node_lock(node);
	if (node->tn_state & TOPO_NODE_ROOT) {
		if ((child = topo_child_first(node)) == NULL) {
			/* Nothing to walk */
			*errp = ETOPO_WALK_EMPTY;
			topo_node_unlock(node);
			topo_node_rele(node);
			topo_hdl_free(thp, wp, sizeof (topo_walk_t));
			return (NULL);
		}
		topo_node_unlock(node);
		topo_node_hold(child);
		wp->tw_node = child;
	} else {
		topo_node_unlock(node);
		topo_node_hold(node); /* rele at walk end */
		wp->tw_node = node;
	}

	wp->tw_root = node;
	wp->tw_cb = cb_f;
	wp->tw_pdata = pdata;
	wp->tw_thp = thp;
	wp->tw_mod = mod;

	return (wp);
}

/*
 * Walk the direct children of the given node.
 */
int
topo_node_child_walk(topo_hdl_t *thp, tnode_t *pnode, topo_walk_cb_t cb_f,
    void *arg, int *errp)
{
	int ret = TOPO_WALK_TERMINATE;
	tnode_t *cnode;

	topo_node_hold(pnode);

	/*
	 * First Child:
	 */
	topo_node_lock(pnode);
	cnode = topo_child_first(pnode);
	topo_node_unlock(pnode);

	if (cnode == NULL) {
		*errp = ETOPO_WALK_EMPTY;
		ret = TOPO_WALK_ERR;
		goto out;
	}

	while (cnode != NULL) {
		int iret;

		/*
		 * Call the walker callback:
		 */
		topo_node_hold(cnode);
		iret = cb_f(thp, cnode, arg);
		topo_node_rele(cnode);
		if (iret != TOPO_WALK_NEXT) {
			ret = iret;
			break;
		}

		/*
		 * Next child:
		 */
		topo_node_lock(pnode);
		cnode = topo_child_next(pnode, cnode);
		topo_node_unlock(pnode);
	}

out:
	topo_node_rele(pnode);
	return (ret);
}
