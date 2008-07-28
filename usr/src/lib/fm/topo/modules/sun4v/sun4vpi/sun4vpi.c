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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Main entry points for SUN4V Platform Independent topology enumerator
 */
#include <sys/types.h>
#include <strings.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <sys/systeminfo.h>
#include <pi_impl.h>

/*
 * Entry point called by libtopo when enumeration is required
 */
static topo_enum_f	pi_enum;	/* libtopo enumeration entry point */


/*
 * Declare the operations vector and information structure used during
 * module registration
 */
static topo_modops_t	pi_ops	= {pi_enum, NULL};
static topo_modinfo_t	pi_modinfo	= {
    SUN4VPI_DESC, SUN4VPI_SCHEME, SUN4VPI_VERSION, &pi_ops
};

static int pi_enum_components(pi_enum_t *, tnode_t *, const char *,
    mde_cookie_t, mde_str_cookie_t, mde_str_cookie_t);


/*
 * Called by libtopo when the topo module is loaded.
 */
void
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	int		result;
	char		isa[MAXNAMELEN];

	if (getenv("TOPOSUN4VPIDBG") != NULL) {
		/* Debugging is requested for this module */
		topo_mod_setdebug(mod);
	}
	topo_mod_dprintf(mod, "sun4vpi module initializing.\n");

	if (version != TOPO_VERSION) {
		topo_mod_seterrno(mod, EMOD_VER_NEW);
		topo_mod_dprintf(mod, "incompatible topo version %d\n",
		    version);
		return;
	}

	/* Verify that this is a SUN4V architecture machine */
	(void) sysinfo(SI_MACHINE, isa, MAXNAMELEN);
	if (strncmp(isa, "sun4v", MAXNAMELEN) != 0) {
		topo_mod_dprintf(mod, "not sun4v architecture: %s\n", isa);
		return;
	}

	result = topo_mod_register(mod, &pi_modinfo, TOPO_VERSION);
	if (result < 0) {
		topo_mod_dprintf(mod, "registration failed: %s\n",
		    topo_mod_errmsg(mod));

		/* module errno already set */
		return;
	}
	topo_mod_dprintf(mod, "module ready.\n");
}


/*
 * Clean up any data used by the module before it is unloaded.
 */
void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_dprintf(mod, "module finishing.\n");

	/* Unregister from libtopo */
	topo_mod_unregister(mod);
}


/*
 * Enumeration entry point for the SUN4V topology enumerator
 */
/* ARGSUSED */
static int
pi_enum(topo_mod_t *mod, tnode_t *t_parent, const char *name,
    topo_instance_t min, topo_instance_t max, void *pi_private, void *data)
{
	int		result;
	int		idx;
	int		num_components;
	size_t		csize;
	hrtime_t	starttime;

	pi_enum_t	pi;

	mde_cookie_t	*components;
	mde_str_cookie_t arc_cookie;
	mde_str_cookie_t component_cookie;

	/* Begin enumeration */
	starttime = gethrtime();
	topo_mod_dprintf(mod, "enumeration starting.\n");

	/* Initialize the walker */
	result = pi_walker_init(mod);
	if (result != 0) {
		topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
		return (-1);
	}

	/* Open a connection to the LDOM PRI */
	bzero(&pi, sizeof (pi_enum_t));
	result = pi_ldompri_open(mod, &pi);
	if (result != 0) {
		pi_walker_fini(mod);
		topo_mod_dprintf(mod, "could not open LDOM PRI\n");
		topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
		return (-1);
	}
	pi.mod = mod;

	/*
	 * Find the top of the components graph in the PRI using the machine
	 * description library.
	 */
	num_components = pi_find_mdenodes(mod, pi.mdp, MDE_INVAL_ELEM_COOKIE,
	    MD_STR_COMPONENTS, MD_STR_FWD, &components, &csize);
	if (num_components < 0 || components == NULL) {
		/* No nodes were found */
		pi_walker_fini(mod);
		topo_mod_dprintf(mod, "could not find components in PRI\n");
		topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
		return (-1);
	}

	/*
	 * There should be a single components node.  But scan all of the
	 * results just in case a future machine has multiple hierarchies
	 * for some unknown reason.
	 *
	 * We continue to walk components nodes until they are all exhausted
	 * and do not stop if a node cannot be enumerated.  Instead, we
	 * enumerate what we can and return a partial-enumeration error if
	 * there is a problem.
	 */
	topo_mod_dprintf(mod, "enumerating %d components hierarchies\n",
	    num_components);

	component_cookie = md_find_name(pi.mdp, MD_STR_COMPONENT);
	arc_cookie	 = md_find_name(pi.mdp, MD_STR_FWD);
	result = 0;
	for (idx = 0; idx < num_components; idx++) {
		int	skip;

		/*
		 * We have found a component hierarchy to process.  First,
		 * make sure we are not supposed to skip the graph.
		 */
		skip = pi_skip_node(mod, pi.mdp, components[idx]);
		if (skip == 0) {
			/*
			 * We have found a components node.  Find the top-
			 * level nodes and create a topology tree from them.
			 */
			result = pi_enum_components(&pi, t_parent, name,
			    components[idx], component_cookie, arc_cookie);
		}
	}
	topo_mod_free(mod, components, csize);

	/* Close our connection to the PRI */
	pi_ldompri_close(mod, &pi);

	/* Clean up after the walker */
	pi_walker_fini(mod);

	/* Complete enumeration */
	topo_mod_dprintf(mod, "enumeration complete in %lld ms.\n",
	    ((gethrtime() - starttime)/MICROSEC));

	/* All done */
	return (result);
}


/*
 * This routined is called once for each mde node of type 'components'.  It
 * initiates enumeration of the graph starting with with this node.
 */
static int
pi_enum_components(pi_enum_t *pip, tnode_t *t_parent, const char *hc_name,
    mde_cookie_t mde_node, mde_str_cookie_t component_cookie,
    mde_str_cookie_t arc_cookie)
{
	int		result;

	int		num_arcs;
	mde_cookie_t	*arcp;
	size_t		arcsize;
	int		arcidx;

	topo_mod_t	*mod = pip->mod;
	md_t		*mdp = pip->mdp;

	if (t_parent == NULL) {
		topo_mod_dprintf(mod,
		    "walker failed to create node range with a NULL parent\n");
		topo_mod_seterrno(mod, EMOD_METHOD_INVAL);
		return (-1);
	}

	/* Determine how many children the given node has */
	num_arcs = md_get_prop_arcs(mdp, mde_node, MD_STR_FWD, NULL, 0);
	if (num_arcs == 0) {
		/*
		 * This components node has no children and is not a topo
		 * node itself, so set partial enumeration and return.
		 */
		topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
		return (0);
	}
	topo_mod_dprintf(mod, "node_0x%llx has %d children\n",
	    (uint64_t)mde_node, num_arcs);

	/* Get the indexes for all the child nodes and put them in an array */
	arcsize = sizeof (mde_cookie_t) * num_arcs;
	arcp = topo_mod_zalloc(mod, arcsize);
	if (arcp == NULL) {
		topo_mod_dprintf(mod, "out of memory\n");
		topo_mod_seterrno(mod, EMOD_NOMEM);
		return (-1);
	}
	num_arcs = md_get_prop_arcs(mdp, mde_node, MD_STR_FWD, arcp,
	    arcsize);

	result = 0;
	for (arcidx = 0; arcidx < num_arcs; arcidx++) {
		/*
		 * Initiate walking the PRI graph starting with the current
		 * child of the components node.
		 */
		result = pi_walker(pip, t_parent, hc_name,
		    arcp[arcidx], component_cookie, arc_cookie);
		if (result != 0) {
			topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
		}
	}
	topo_mod_free(mod, arcp, arcsize);

	/*
	 * We have now walked the entire PRI graph.  Execute any deferred
	 * enumeration routines that need all the nodes to be available.
	 */
	result = pi_defer_exec(mod, mdp);

	return (result);
}
