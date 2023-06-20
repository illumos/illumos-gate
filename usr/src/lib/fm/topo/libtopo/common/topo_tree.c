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
 * Topology Trees
 *
 * Toplogy trees are instantiated for each builtin (FMRI) scheme specified
 * in topo_builtin.c.  Each ttree_t data structure contains the
 * skeleton of the topology tree (scheme, root node, and file information).
 * The root node of a topology does not represent any FMRI but rather serves
 * as the entry point for topology access interfaces.  The file information
 * provides a handle to access static .xml files that seed scheme-specifc
 * topologies
 *
 * Topology trees will remain unpopulated until topo_snap_hold() is called.
 * At that time, a ttree_t structure is allocated and added to the list
 * trees maintained in topo_hdl_t.  Builtin scheme-specific enumerators are
 * called upon to create nodes that represent FMRIs for resources present in the
 * system.  If a <scheme>-topology.xml file exists in a standard file
 * location, the file is used to seed the topology while the rest is
 * dynamically created by the builtin or helper enumerator modules.
 * For example, the 'hc' tree is enumerated by the hc enumerator (hc.c)
 * after the hc-topology.xml is read from /usr/platform/`uname -i`/lib/fm/topo,
 * /usr/platform/`uname -r`/lib/fm/topo, or /usr/lib/fm/topo.  Each node
 * is created with a properly formatted hc FMRI resource.
 *
 * Toplogy trees are released and deallocated when topo_snap_hold is called.
 * Upon return from topo_snap_rele(), all node resources are deallocated
 * and all that remains is the ttree_t structure containing the root node.
 */

#include <pthread.h>
#include <limits.h>
#include <assert.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>

#include <topo_alloc.h>
#include <topo_error.h>
#include <topo_file.h>
#include <topo_module.h>
#include <topo_string.h>
#include <topo_subr.h>
#include <topo_tree.h>

static ttree_t *
set_create_error(topo_hdl_t *thp, ttree_t *tp, int err)
{
	if (tp != NULL)
		topo_tree_destroy(tp);

	if (err != 0)
		(void) topo_hdl_seterrno(thp, err);

	return (NULL);
}

ttree_t *
topo_tree_create(topo_hdl_t *thp, topo_mod_t *mod, const char *scheme)
{
	ttree_t *tp;
	tnode_t *rp;

	if ((tp = topo_mod_zalloc(mod, sizeof (ttree_t))) == NULL)
		return (set_create_error(thp, NULL, ETOPO_NOMEM));

	tp->tt_mod = mod;

	if ((tp->tt_scheme = topo_mod_strdup(mod, scheme)) == NULL)
		return (set_create_error(thp, tp, ETOPO_NOMEM));

	/*
	 * Initialize a private walker for internal use
	 */
	if ((tp->tt_walk = topo_mod_zalloc(mod, sizeof (topo_walk_t))) == NULL)
		return (set_create_error(thp, tp, ETOPO_NOMEM));

	/*
	 * Create the root of this tree: LINKED but never BOUND
	 */
	if ((rp = topo_mod_zalloc(mod, sizeof (tnode_t))) == NULL)
		return (set_create_error(thp, tp, 0)); /* th_errno set */

	rp->tn_state = TOPO_NODE_ROOT | TOPO_NODE_INIT;
	rp->tn_name = tp->tt_scheme;
	rp->tn_instance = 0;
	rp->tn_enum = mod;
	rp->tn_hdl = thp;

	topo_node_hold(rp);

	tp->tt_walk->tw_root = rp;
	tp->tt_walk->tw_thp = thp;

	topo_mod_hold(mod); /* released when root node destroyed */

	tp->tt_root = rp;

	return (tp);
}

void
topo_tree_destroy(ttree_t *tp)
{
	topo_mod_t *mod;

	if (tp == NULL)
		return;

	mod = tp->tt_mod;
	if (tp->tt_walk != NULL)
		topo_mod_free(mod, tp->tt_walk, sizeof (topo_walk_t));

	if (tp->tt_root != NULL) {
		assert(tp->tt_root->tn_refs == 1);
		topo_node_rele(tp->tt_root);
	}
	/*
	 * Deallocate this last, because a pointer alias for tt_scheme
	 * (stored in the root node's name field) may be used in
	 * topo_node_rele().
	 */
	if (tp->tt_scheme != NULL)
		topo_mod_strfree(mod, tp->tt_scheme);

	topo_mod_free(mod, tp, sizeof (ttree_t));
}

static int
topo_tree_enum(topo_hdl_t *thp, ttree_t *tp)
{
	int rv = 0;
	char *pp;

	/*
	 * Attempt to enumerate the tree from a topology map in the
	 * following order:
	 *	<product-name>-<scheme>-topology
	 *	<platform-name>-<scheme>-topology (uname -i)
	 *	<machine-name>-<scheme>-topology (uname -m)
	 *	<scheme>-topology
	 *
	 * Trim any SUNW, from the product or platform name
	 * before loading file
	 */
	if ((pp = strchr(thp->th_product, ',')) == NULL)
		pp = thp->th_product;
	else
		pp++;
	if (topo_file_load(tp->tt_root->tn_enum, tp->tt_root,
	    pp, tp->tt_scheme, 0) < 0) {
		if ((pp = strchr(thp->th_platform, ',')) == NULL)
			pp = thp->th_platform;
		else
			pp++;

		if (topo_file_load(tp->tt_root->tn_enum, tp->tt_root,
		    pp, tp->tt_scheme, 0) < 0) {
			if (topo_file_load(tp->tt_root->tn_enum, tp->tt_root,
			    thp->th_machine, tp->tt_scheme, 0) < 0) {

				if ((rv = topo_file_load(tp->tt_root->tn_enum,
				    tp->tt_root, NULL, tp->tt_scheme, 0)) < 0) {
					topo_dprintf(thp, TOPO_DBG_ERR, "no "
					    "topology map found for the %s "
					    "FMRI set\n", tp->tt_scheme);
				}
			}
		}
	}

	if (rv != 0)
		return (topo_hdl_seterrno(thp, ETOPO_ENUM_NOMAP));

	return (0);
}

int
topo_tree_enum_all(topo_hdl_t *thp)
{
	int err = 0;
	ttree_t *tp;

	for (tp = topo_list_next(&thp->th_trees); tp != NULL;
	    tp = topo_list_next(tp)) {
		err |= topo_tree_enum(thp, tp);
	}

	if (err != 0)
		return (-1);
	else
		return (0);
}
