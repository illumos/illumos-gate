/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Enumerator plugin modules may also safely access node data.  Enumeration
 * occurs only during topo_snap_hold() where a per-topo_hdl_t lock prevents
 * multi-threaded access to the topology trees.
 *
 * Like tree walking functions, method plugin modules have access to read-only
 * node data but may make changes to property information.
 *
 * Node Interfaces
 *
 * Nodes are created when an enumerator calls topo_node_bind().  Prior to the
 * call to topo_node_bind(), the caller should have reserved a range of
 * node instances with topo_node_range_create().  topo_node_range_create()
 * does not allocate any node resources but creates the infrastruture
 * required for a fully populated topology level.  This allows enumerators
 * reading from a <scheme>-topology.xml file to parse the file for a range
 * of resources before confirming the existence of a resource via a helper
 * plugin.  Only when the resource has been confirmed to exist should
 * the node be bound.
 *
 * Node range and node linkage is only performed during enumeration when it
 * is safe to change node hash lists and next pointers. Nodes and node ranges
 * are deallocated when all references to the node have been released:
 * last walk completes and topo_snap_rele() is called.
 *
 * Node Hash/Ranges
 *
 * Each parent node may have one or more ranges of child nodes.  Each range
 * serves as a hash list of like sibling nodes all with the same name but
 * different instance numbers.  A parent may have more than one node hash
 * (child range). If that is the case, the hash lists are strung together to
 * form sibling relationships between ranges.  Hash/Ranges are sparsely
 * populated with only nodes that have represented resources in the system.
 */

#include <assert.h>
#include <pthread.h>
#include <strings.h>
#include <topo_alloc.h>
#include <topo_tree.h>
#include <topo_subr.h>
#include <topo_error.h>

static void
topo_node_destroy(tnode_t *node)
{
	int i;
	tnode_t *pnode = node->tn_parent;
	topo_nodehash_t *nhp;
	topo_mod_t *hmod, *mod = node->tn_enum;

	if (node == NULL)
		return;

	assert(node->tn_refs == 0);

	topo_dprintf(TOPO_DBG_TREE, "destroying node %s=%d\n", node->tn_name,
	    node->tn_instance);
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
	if (mod->tm_info->tmi_release != NULL)
		mod->tm_info->tmi_release(mod, node);

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

void *
topo_node_private(tnode_t *node)
{
	return (node->tn_priv);
}

static int
node_create_seterror(topo_mod_t *mod, tnode_t *pnode, topo_nodehash_t *nhp,
    int err)
{
	topo_node_unlock(pnode);

	topo_dprintf(TOPO_DBG_ERR, "unable to insert child:"
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
			    ETOPO_NODE_DUP));
	}

	if (min < 0 || max < min)
		return (node_create_seterror(mod, pnode, NULL,
		    ETOPO_NODE_INVAL));

	if ((nhp = topo_mod_zalloc(mod, sizeof (topo_nodehash_t))) == NULL)
		return (node_create_seterror(mod, pnode, nhp, ETOPO_NOMEM));

	if ((nhp->th_name = topo_mod_strdup(mod, name)) == NULL)
		return (node_create_seterror(mod, pnode, nhp, ETOPO_NOMEM));

	nhp->th_arrlen = max - min + 1;

	if ((nhp->th_nodearr = topo_mod_zalloc(mod,
	    nhp->th_arrlen * sizeof (tnode_t *))) == NULL)
		return (node_create_seterror(mod, pnode, nhp, ETOPO_NOMEM));

	nhp->th_range.tr_min = min;
	nhp->th_range.tr_max = max;
	nhp->th_enum = mod;
	topo_mod_hold(mod);

	/*
	 * Add these nodes to parent child list
	 */
	topo_list_append(&pnode->tn_children, nhp);
	topo_node_unlock(pnode);

	topo_dprintf(TOPO_DBG_MOD, "created node range %s[%d-%d]\n", name,
	    min, max);

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

	topo_list_delete(&pnode->tn_children, nhp);
	topo_node_unlock(pnode);

	/*
	 * Should be an empty node range
	 */
	for (i = 0; i < nhp->th_arrlen; i++) {
		topo_node_unbind(nhp->th_nodearr[i]);
	}

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
	return (nhp->th_range.tr_max == 0 ?
	    nhp->th_range.tr_max : inst % (nhp->th_range.tr_max + 1));
}

static tnode_t *
node_bind_seterror(topo_mod_t *mod, tnode_t *pnode, tnode_t *node, int err)
{
	topo_node_unlock(pnode);

	(void) topo_mod_seterrno(mod, err);

	if (node == NULL)
		return (NULL);

	topo_dprintf(TOPO_DBG_ERR, "unable to bind %s=%d: "
	    "%s\n", (node->tn_name != NULL ? node->tn_name : "unknown"),
	    node->tn_instance, topo_strerror(err));

	topo_node_lock(node); /* expected to be locked */
	topo_node_destroy(node);

	return (NULL);
}

tnode_t *
topo_node_bind(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t inst, nvlist_t *fmri, void *priv)
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
				    ETOPO_NODE_INVAL));

			h = topo_node_hash(nhp, inst);
			if (nhp->th_nodearr[h] != NULL)
				return (node_bind_seterror(mod, pnode, NULL,
				    ETOPO_NODE_BOUND));
			else
				break;

		}
	}

	if (nhp == NULL)
		return (node_bind_seterror(mod, pnode, NULL, ETOPO_NODE_NOENT));

	if ((node = topo_mod_zalloc(mod, sizeof (tnode_t))) == NULL)
		return (node_bind_seterror(mod, pnode, NULL, ETOPO_NOMEM));

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
		return (node_bind_seterror(mod, pnode, node, ETOPO_NODE_INVAL));

	if (topo_pgroup_create(node, TOPO_PGROUP_PROTOCOL,
	    TOPO_STABILITY_PRIVATE, &err) < 0)
		return (node_bind_seterror(mod, pnode, node, err));

	if (topo_prop_set_fmri(node, TOPO_PGROUP_PROTOCOL, TOPO_PROP_RESOURCE,
	    TOPO_PROP_SET_ONCE, fmri, &err) < 0)
		return (node_bind_seterror(mod, pnode, node, err));

	topo_dprintf(TOPO_DBG_MOD, "node bound %s=%d\n", node->tn_name,
	    node->tn_instance);

	node->tn_state |= TOPO_NODE_BOUND;
	node->tn_priv = priv;

	topo_node_hold(node);
	nhp->th_nodearr[h] = node;
	++pnode->tn_refs;
	topo_node_unlock(pnode);

	if (topo_pgroup_create(node, TOPO_PGROUP_SYSTEM,
	    TOPO_STABILITY_PRIVATE, &err) == 0) {
		(void) topo_prop_inherit(node, TOPO_PGROUP_SYSTEM,
		    TOPO_PROP_PLATFORM, &err);
		(void) topo_prop_inherit(node, TOPO_PGROUP_SYSTEM,
		    TOPO_PROP_ISA, &err);
		(void) topo_prop_inherit(node, TOPO_PGROUP_SYSTEM,
		    TOPO_PROP_MACHINE, &err);
	}

	return (node);
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
