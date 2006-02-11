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
#include <topo_module.h>
#include <topo_string.h>
#include <topo_subr.h>
#include <topo_tree.h>

static ttree_t *
set_create_error(topo_hdl_t *thp, ttree_t *tp, int err)
{
	if (tp != NULL)
		topo_tree_destroy(thp, tp);

	if (err != 0)
		(void) topo_hdl_seterrno(thp, err);

	return (NULL);
}

static void
set_system_props(tnode_t *node)
{
	int err;
	char platform[MAXNAMELEN];
	char isa[MAXNAMELEN];
	struct utsname uts;

	platform[0] = '\0';
	isa[0] = '\0';
	(void) sysinfo(SI_PLATFORM, platform, sizeof (platform));
	(void) sysinfo(SI_ARCHITECTURE, isa, sizeof (isa));
	(void) uname(&uts);

	(void) topo_pgroup_create(node, TOPO_PGROUP_SYSTEM,
	    TOPO_STABILITY_PRIVATE, &err);
	(void) topo_prop_set_string(node, TOPO_PGROUP_SYSTEM,
	    TOPO_PROP_PLATFORM, TOPO_PROP_SET_ONCE, platform, &err);
	(void) topo_prop_set_string(node, TOPO_PGROUP_SYSTEM,
	    TOPO_PROP_ISA, TOPO_PROP_SET_ONCE, isa, &err);
	(void) topo_prop_set_string(node, TOPO_PGROUP_SYSTEM,
	    TOPO_PROP_MACHINE, TOPO_PROP_SET_ONCE, uts.machine, &err);
}

ttree_t *
topo_tree_create(topo_hdl_t *thp, topo_mod_t *mod, const char *scheme)
{
	ttree_t *tp;
	tnode_t *rp;

	if ((tp = topo_hdl_zalloc(thp, sizeof (ttree_t))) == NULL)
		return (set_create_error(thp, NULL, ETOPO_NOMEM));

	if ((tp->tt_scheme = topo_hdl_strdup(thp, scheme)) == NULL)
		return (set_create_error(thp, tp, ETOPO_NOMEM));

	/*
	 * Initialize a private walker for internal use
	 */
	if ((tp->tt_walk = topo_hdl_zalloc(thp, sizeof (topo_walk_t))) == NULL)
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

	set_system_props(rp);
	topo_node_hold(rp);

	tp->tt_walk->tw_root = rp;
	tp->tt_walk->tw_thp = thp;

	topo_mod_hold(mod); /* released when root node destroyed */

	tp->tt_root = rp;

	return (tp);
}

void
topo_tree_destroy(topo_hdl_t *thp, ttree_t *tp)
{
	if (tp == NULL)
		return;

	if (tp->tt_scheme != NULL)
		topo_hdl_strfree(thp, tp->tt_scheme);
	if (tp->tt_walk != NULL)
		topo_hdl_free(thp, tp->tt_walk, sizeof (topo_walk_t));

	if (tp->tt_file != NULL)
		topo_file_unload(thp, tp);

	if (tp->tt_root != NULL) {
		assert(tp->tt_root->tn_refs == 1);
		topo_node_rele(tp->tt_root);
	}

	topo_hdl_free(thp, tp, sizeof (ttree_t));
}

static int
topo_tree_enum(topo_hdl_t *thp, ttree_t *tp)
{
	tnode_t *rnode;

	rnode = tp->tt_root;
	/*
	 * Attempt to populate the tree from a topology file
	 */
	if (topo_file_load(thp, rnode->tn_enum, tp) < 0) {
		/*
		 * If this tree does not have a matching static topology file,
		 * continue on.
		 */
		if (topo_hdl_errno(thp) != ETOPO_FILE_NOENT)
			return (topo_hdl_seterrno(thp, ETOPO_ENUM_PARTIAL));
	}
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
