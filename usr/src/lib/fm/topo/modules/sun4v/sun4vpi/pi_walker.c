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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Walk the LDOM PRI component nodes and create appropriate topology nodes
 */

#include <sys/types.h>
#include <sys/time.h>
#include <stddef.h>
#include <inttypes.h>
#include <strings.h>
#include <string.h>
#include <libuutil.h>
#include <libnvpair.h>
#include <sys/mdesc.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include "pi_impl.h"

#define	PI_STR_MIN	"instance_min"
#define	PI_STR_MAX	"instance_max"

/*
 * Allow for custom topo node creation routines based on topo-hc-name.
 */
struct pi_enum_functions_s {
	pi_enum_fn_t	*func;
	char		*hc_name;	/* topo-hc-name */
};
typedef struct pi_enum_functions_s pi_enum_functions_t;

struct pi_methods_s {
	topo_method_t	*meths;
	char		*hc_name;
};
typedef struct pi_methods_s pi_methods_t;

extern topo_method_t pi_cpu_methods[], pi_mem_methods[];

/*
 * List of custom enumerators for PRI nodes that require them.  The most
 * common nodes are listed first.
 */
static pi_enum_functions_t pi_enum_fns_builtin[] = {
	{pi_enum_cpu,		STRAND},
	{pi_enum_cpu,		CPU},
	{pi_enum_mem,		DIMM},
	{pi_enum_cpu,		CORE},
	{pi_enum_cpu,		CHIP},
	{pi_enum_hostbridge,	HOSTBRIDGE},
	{pi_enum_pciexrc,	PCIEX_ROOT},
	{pi_enum_niu,		NIU},
	{pi_enum_bay,		BAY},
	{NULL, NULL}
};
static nvlist_t *pi_enum_fns;

/* List of methods that will be registered in the nodes. */
static pi_methods_t pi_meths_builtin[] = {
	{pi_cpu_methods,	CHIP},
	{pi_cpu_methods,	CORE},
	{pi_cpu_methods,	STRAND},
	{pi_cpu_methods,	CPU},
	{pi_mem_methods,	DIMM},
	{NULL, NULL}
};
nvlist_t *pi_meths;

/*
 * In order to create a topology node from a PRI MDE node we need to know the
 * topology parent node that should be used.  So, after creating a topology
 * node from an MDE node, we associate children of the MDE node with the new
 * topology node.  Thus, when the children are visited we can know the
 * appropriate parent topology node to use.
 *
 * We take advantage of the libtopo threading model here, which guarantees a
 * single thread and a single invocation at a time for an enumerator.  This
 * makes using a file-global safe.
 */
static uu_list_pool_t	*walker_pool = NULL;
static uu_list_t	*walker_list = NULL;

struct pi_walkernode_s {
	uu_list_node_t	walker_node;
	tnode_t		*t_parent;	/* Parent topology node */
	mde_cookie_t	mde_node;	/* Child MDE node index */
};
typedef struct pi_walkernode_s pi_walkernode_t;


/* The routine called for each node in the PRI while walking the graph */
static int pi_walker_node(md_t *, mde_cookie_t, mde_cookie_t, void *);

/*
 * Create a sub-range for a given PRI node and associate the given topology
 * node with the children.
 */
static int  pi_walker_node_range(topo_mod_t *, md_t *, tnode_t *, mde_cookie_t);
static int  pi_walker_node_create(topo_mod_t *, md_t *, mde_cookie_t, tnode_t *,
    topo_instance_t, tnode_t **);

/* Routines to handle the list of topology parents and mde_nodes */
static int  pi_walkerlist_compare(const void *, const void *, void *);
static int  pi_walkerlist_create(topo_mod_t *);
static void pi_walkerlist_destroy(topo_mod_t *);
static int  pi_walkerlist_add(topo_mod_t *, tnode_t *, mde_cookie_t);
static int  pi_walkerlist_addtype(topo_mod_t *, nvlist_t *, char *, uint32_t,
    uint32_t);
static int  pi_walkerlist_find(topo_mod_t *, mde_cookie_t, tnode_t **);


int
pi_walker_init(topo_mod_t *mod)
{
	int			result;
	pi_enum_functions_t	*fp;
	pi_methods_t		*mp;

	result = topo_mod_nvalloc(mod, &pi_enum_fns, NV_UNIQUE_NAME);
	result |= topo_mod_nvalloc(mod, &pi_meths, NV_UNIQUE_NAME);
	if (result != 0) {
		topo_mod_dprintf(mod, "pi_walker_init failed\n");
		nvlist_free(pi_enum_fns);
		nvlist_free(pi_meths);
		return (-1);
	}

	/* Add the builtin functions to the list */
	fp = pi_enum_fns_builtin;
	while (fp != NULL && fp->hc_name != NULL) {
		uint64_t	faddr;

		faddr = (uint64_t)(uintptr_t)*(fp->func);
		result |= nvlist_add_uint64(pi_enum_fns, fp->hc_name, faddr);
		fp++;
	}

	/* Add the builtin methods to the list */
	mp = pi_meths_builtin;
	while (mp != NULL && mp->hc_name != NULL) {
		uint64_t	maddr;

		maddr = (uint64_t)(uintptr_t)mp->meths;
		result |= nvlist_add_uint64(pi_meths, mp->hc_name, maddr);
		mp++;
	}

	if (result != 0) {
		topo_mod_dprintf(mod, "pi_walker_init failed\n");
		nvlist_free(pi_enum_fns);
		nvlist_free(pi_meths);
		return (-1);
	}

	return (0);
}


void
pi_walker_fini(topo_mod_t *mod)
{
	topo_mod_dprintf(mod, "pi_walker_fini: enter\n");
	nvlist_free(pi_enum_fns);
	nvlist_free(pi_meths);
}


/*
 * Begin to walk the machine description array starting at the given PRI node.
 */
int
pi_walker(pi_enum_t *pip, tnode_t *t_parent, const char *hc_name,
    mde_cookie_t mde_node, mde_str_cookie_t component_cookie,
    mde_str_cookie_t arc_cookie)
{
	int		result;
	hrtime_t	starttime;
	hrtime_t	endtime;
	topo_mod_t	*mod;

	if (pip == NULL) {
		return (-1);
	}
	mod = pip->mod;

	starttime = gethrtime();
	topo_mod_dprintf(mod, "walker starting at node_0x%llx\n",
	    mde_node);

	/*
	 * Create a list to store topology nodes and their associated machine
	 * description index.  This allows the code to know the parent of a
	 * node when creating topology entries.
	 */
	result = pi_walkerlist_create(mod);
	if (result != 0) {
		topo_mod_dprintf(mod, "walker could not create list\n");
		return (result);
	}

	/* Create a walker node for the parent of the start node */
	result = pi_walkerlist_add(mod, t_parent, mde_node);
	if (result != 0) {
		pi_walkerlist_destroy(mod);
		topo_mod_dprintf(mod, "walker could not add to list\n");
		(void) topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
		return (result);
	}

	/*
	 * This is a top-level node.  Make sure we call the top level
	 * enumerator if there is not already a custom enumerator registered.
	 */
	if (! nvlist_exists(pi_enum_fns, hc_name)) {
		uint64_t	faddr;

		/*
		 * There is no enumerator function registered for this
		 * hc name.  Automatically register the top level node
		 * enumerator function.
		 */
		faddr = (uint64_t)(uintptr_t)pi_enum_top;
		result = nvlist_add_uint64(pi_enum_fns, hc_name, faddr);
		if (result != 0) {
			pi_walkerlist_destroy(mod);
			topo_mod_dprintf(mod,
			    "walker could not register enumerator for type "
			    "%s\n", hc_name);
			(void) topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
			return (-1);
		}
		topo_mod_dprintf(mod,
		    "walker registered pi_enum_top enumerator for type %s\n",
		    hc_name);
	}

	/* Walk the machine description list starting at the given node */
	result = md_walk_dag(pip->mdp, mde_node, component_cookie, arc_cookie,
	    pi_walker_node, (void *)pip);
	switch (result) {
		case 0:
			/* Successful completion */
			/* DO NOTHING */
		break;

		case MDE_WALK_ERROR:
			/*
			 * Store that we have a partial enumeration and return
			 * that we have encountered an error.
			 */
			(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
			result = -1;
		break;

		default:
			/*
			 * This should not happen.  We want to always produce
			 * as complete a topology as possible, even in the face
			 * of errors, however, so set an error and continue.
			 */
			topo_mod_dprintf(mod,
			    "walker encountered invalid result: %d. "
			    "Continuing\n", result);
			(void) topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
			result = 0;
		break;
	}

	/* Destroy the walker list, which is no longer necessary */
	pi_walkerlist_destroy(mod);

	topo_mod_dprintf(mod, "walker done with node_0x%llx\n", mde_node);

	endtime = gethrtime();
	topo_mod_dprintf(mod, "walker scan time %lld ms\n",
	    (endtime-starttime)/MICROSEC);

	return (result);
}


/*
 * Visited once for each node in the machine description.  Creates a topo
 * node for the machine description node and associates it with it's parent,
 * by calling an appropriate creation routine for the node type.
 *
 * Output:
 *	This routine returns MDE_WALK_NEXT, MDE_WALK_DONE or MDE_WALK_ERROR
 * only.
 */
static int
pi_walker_node(md_t *mdp, mde_cookie_t parent_mde_node, mde_cookie_t mde_node,
    void *private)
{
	int		result;
	pi_enum_t	*pip	= (pi_enum_t *)private;
	uint64_t	skip;		/* flag in md to skip this node	*/
	tnode_t		*t_parent;	/* topo parent to this md node	*/
	tnode_t		*t_node;	/* topo parent to this md node	*/
	topo_instance_t	inst;

	topo_mod_t	*mod;

	/* Make sure we have our private data */
	if (pip == NULL) {
		return (MDE_WALK_ERROR);
	}
	mod = pip->mod;

	topo_mod_dprintf(pip->mod,
	    "walker processing node_0x%llx parent node 0x%llx\n",
	    (uint64_t)mde_node, (uint64_t)parent_mde_node);

	/* Should we skip this node ? */
	skip = pi_skip_node(mod, pip->mdp, mde_node);
	if (skip) {
		/* Skip this node and continue to the next node */
		topo_mod_dprintf(mod, "walker skipping node_0x%llx\n",
		    (uint64_t)mde_node);
		return (MDE_WALK_NEXT);
	}

	result = pi_get_instance(mod, mdp, mde_node, &inst);
	if (result != 0) {
		/*
		 * No ID available to place this mde node in the topology so
		 * we cannot create a topology node.
		 */
		topo_mod_dprintf(mod, "walker skipping node_0x%llx: "
		    "no instance\n", (uint64_t)mde_node);
		(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
		return (MDE_WALK_NEXT);
	}

	/*
	 * Find the parent topo node for this machine description node.
	 *
	 * If found, the element will also be removed from the list and the
	 * memory used to keep track of it released.  We will only visit an
	 * MDE node once and so the memory is no longer needed.
	 */
	t_parent = NULL;
	result = pi_walkerlist_find(mod, mde_node, &t_parent);
	if (result != 0 || t_parent == NULL) {
		/*
		 * No parent was found or a NULL parent encountered.  We
		 * cannot create a new topology node without a parent (
		 * even for top level nodes).  We associate children of
		 * this MDE node with a NULL parent to silently skip the
		 * remainder of this MDE branch.
		 */
		topo_mod_dprintf(mod, "no topo parent found for node_0x%llx\n",
		    mde_node);
		result = pi_walker_node_range(mod, mdp, NULL, mde_node);
		(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);

		return (result);
	}

	/*
	 * We have the mde node instance and parent information.
	 * Attempt to create a topology node for this mde node.
	 */
	t_node = NULL;
	result = pi_walker_node_create(mod, mdp, mde_node, t_parent, inst,
	    &t_node);
	if (result != MDE_WALK_NEXT || t_node == NULL) {
		/*
		 * We have failed to create a new topology node based on
		 * the current MDE node.  We set partial enumeration and
		 * return without associating the children of this MDE
		 * node with a topology parent.  This will propgate the
		 * creation error down this MDE branch.
		 */
		(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
		return (result);
	}

	/*
	 * Associate the new topology node with any children of this mde node.
	 */
	result = pi_walker_node_range(mod, mdp, t_node, mde_node);

	topo_mod_dprintf(mod, "walker completed node_0x%llx result = %d\n",
	    (uint64_t)mde_node, result);

	return (result);
}


static int
pi_walker_node_create(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    tnode_t *t_parent, topo_instance_t inst, tnode_t **t_node)
{
	int		result;
	char		*hc_name;
	uint64_t	faddr;
	pi_enum_fn_t	*func;

	if (t_parent == NULL) {
		/*
		 * A parent topology node is required even for top-level
		 * nodes.
		 */
		return (MDE_WALK_NEXT);
	}

	/*
	 * Find the topo-hc-name for this node which is used to find
	 * the specific creation function
	 */
	hc_name = pi_get_topo_hc_name(mod, mdp, mde_node);
	if (hc_name == NULL) {
		/* Cannot get the hc-name */
		topo_mod_dprintf(mod,
		    "failed to find hc-name for node_0x%llx\n", mde_node);
		return (MDE_WALK_NEXT);
	}

	/* Determine the topology node creation routine to use */
	func = pi_enum_generic;
	faddr = 0;
	result = nvlist_lookup_uint64(pi_enum_fns, hc_name, &faddr);
	if (result == 0) {
		/*
		 * A function is registered for this node. Convert the
		 * address to a pointer to function
		 */
		func = (pi_enum_fn_t *)(uintptr_t)faddr;
	}

	/*
	 * Create a topology node for this mde node by calling the identified
	 * enumeration function
	 */
	*t_node = NULL;
	result = (func)(mod, mdp, mde_node, inst, t_parent, hc_name, t_node);
	if (result != 0) {
		topo_mod_dprintf(mod,
		    "failed to create topo entry for node_0x%llx type %s\n",
		    (uint64_t)mde_node, hc_name);
	}

	topo_mod_strfree(mod, hc_name);

	return (MDE_WALK_NEXT);
}


/*
 * Scan the children of a given MDE node and find all the sets of topo-hc-name
 * types and their instance ranges.  From this information we create topology
 * node ranges on the given parent so that when the children are visited and a
 * topology node is created, the range exists and the creation will succeed.
 */
static int
pi_walker_node_range(topo_mod_t *mod, md_t *mdp, tnode_t *t_parent,
    mde_cookie_t mde_node)
{
	int		result;
	int		rc;
	int		num_arcs;
	nvlist_t	*typelist;
	nvpair_t	*nvp;
	mde_cookie_t	*arcp;
	size_t		arcsize;
	int		arcidx;
	char		*hc_name;
	nvlist_t	*hc_range;
	topo_instance_t	inst;
	uint32_t	min;
	uint32_t	max;

	if (t_parent == NULL) {
		topo_mod_dprintf(mod,
		"walker failed to create node range with a NULL parent\n");
		return (MDE_WALK_NEXT);
	}

	/* Determine how many children the given node has */
	num_arcs = md_get_prop_arcs(mdp, mde_node, MD_STR_FWD, NULL, 0);
	if (num_arcs == 0) {
		/* This node has no children */
		return (MDE_WALK_NEXT);
	}
	topo_mod_dprintf(mod, "node_0x%llx has %d children\n",
	    (uint64_t)mde_node, num_arcs);

	/* Get the indexes for all the child nodes and put them in an array */
	arcsize	= sizeof (mde_cookie_t) * num_arcs;
	arcp = topo_mod_zalloc(mod, arcsize);
	if (arcp == NULL) {
		topo_mod_dprintf(mod, "out of memory\n");
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		return (MDE_WALK_ERROR);
	}
	num_arcs = md_get_prop_arcs(mdp, mde_node, MD_STR_FWD, arcp, arcsize);

	/*
	 * The children of the given node may have multiple types.
	 * Potentially, each child may have a different type and we need to
	 * create a topo node range for each one.
	 *
	 * We loop through the children and collect the type information for
	 * each one and associate the child with the given parent topo node.
	 */
	result = topo_mod_nvalloc(mod, &typelist, NV_UNIQUE_NAME);
	if (result != 0) {
		topo_mod_free(mod, arcp, arcsize);
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		return (MDE_WALK_ERROR);
	}

	arcidx = 0;
	for (arcidx = 0; arcidx < num_arcs; arcidx++) {
		/* Should this node be skipped? */
		if (pi_skip_node(mod, mdp, arcp[arcidx])) {
			/* Skip this node */
			topo_mod_dprintf(mod, "skipping node_0x%llx\n",
			    (uint64_t)arcp[arcidx]);
			continue;
		}

		/* Get the type of this node */
		hc_name = pi_get_topo_hc_name(mod, mdp, arcp[arcidx]);
		rc = pi_get_instance(mod, mdp, arcp[arcidx], &inst);
		if (rc == 0 && hc_name != NULL) {
			/* Increment the count of nodes with this type */
			hc_range = NULL;
			rc = nvlist_lookup_nvlist(typelist, hc_name, &hc_range);
			if (rc != 0) {
				/*
				 * We have not visited this type yet.  Create
				 * a new range based on this nodes instance
				 * information.
				 */
				result = pi_walkerlist_addtype(mod, typelist,
				    hc_name, (uint32_t)inst, (uint32_t)inst);
				if (result != 0) {
					/*
					 * This error can only if there was a
					 * memory failure of some kind.  Stop
					 * the walk or it will just get worse.
					 */
					nvlist_free(typelist);
					topo_mod_strfree(mod, hc_name);
					topo_mod_free(mod, arcp, arcsize);
					(void) topo_mod_seterrno(mod,
					    EMOD_PARTIAL_ENUM);
					return (MDE_WALK_ERROR);
				}

				/*
				 * We know the list exists now or the above
				 * would have failed.  Just look it up.
				 */
				(void) nvlist_lookup_nvlist(typelist, hc_name,
				    &hc_range);
			}

			/* Re-calculate the range minimums and maximums */
			(void) nvlist_lookup_uint32(hc_range, PI_STR_MIN, &min);
			(void) nvlist_lookup_uint32(hc_range, PI_STR_MAX, &max);
			min = MIN(min, (uint32_t)inst);
			max = MAX(max, (uint32_t)inst);
			(void) nvlist_add_uint32(hc_range, PI_STR_MIN, min);
			(void) nvlist_add_uint32(hc_range, PI_STR_MAX, max);

		} else {
			if (hc_name == NULL) {
				topo_mod_dprintf(mod, "node_0x%llx has no "
				    "topo_hc_name.", (uint64_t)arcp[arcidx]);
				(void) topo_mod_seterrno(mod,
				    EMOD_PARTIAL_ENUM);
				return (MDE_WALK_ERROR);
			}

			topo_mod_dprintf(mod, "node_0x%llx type %s has no id. "
			    "Excluding from range", (uint64_t)arcp[arcidx],
			    hc_name);
		}
		topo_mod_strfree(mod, hc_name);

		/*
		 * Associate this node with the given topo parent even if it
		 * has no instance.  We do this so that later an error with
		 * the PRI node will be reported instead of an internal
		 * error about not being able to find the parent of a node
		 */
		rc = pi_walkerlist_add(mod, t_parent, arcp[arcidx]);
		if (rc != 0) {
			topo_mod_dprintf(mod,
			    "could not add node_0x%llx to walker list\n",
			    (uint64_t)arcp[arcidx]);
		}
	}

	/*
	 * We have associated all the child nodes with the given topo parent
	 * in the walker list.  Now we need to create topo ranges for each
	 * set of child types under the parent.
	 */
	nvp = nvlist_next_nvpair(typelist, NULL);
	while (nvp != NULL) {
		/* Get the type name and count from the list element */
		hc_name = nvpair_name(nvp);
		(void) nvpair_value_nvlist(nvp, &hc_range);
		(void) nvlist_lookup_uint32(hc_range, PI_STR_MIN, &min);
		(void) nvlist_lookup_uint32(hc_range, PI_STR_MAX, &max);

		/*
		 * We have the number of children with this type.
		 * Create an appropriate range.
		 */
		topo_mod_dprintf(mod,
		    "creating instance range %d to %d of type %s\n",
		    min, max, hc_name);
		rc = topo_node_range_create(mod, t_parent, hc_name,
		    (topo_instance_t)min, (topo_instance_t)max);
		if (rc != 0) {
			topo_mod_dprintf(mod,
			    "failed to created node range %d to %d for "
			    "nodes of type %s\n", min, max, hc_name);
		}

		/* Check the next node */
		nvp = nvlist_next_nvpair(typelist, nvp);
	}
	topo_mod_free(mod, arcp, arcsize);
	nvlist_free(typelist);

	return (MDE_WALK_NEXT);
}


static int
pi_walkerlist_addtype(topo_mod_t *mod, nvlist_t *typelist, char *hc_name,
    uint32_t min, uint32_t max)
{
	int		result;
	nvlist_t	*nvl;

	result = topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME);
	if (result != 0) {
		return (result);
	}

	/* Create min and max elements in this list */
	if (nvlist_add_uint32(nvl, PI_STR_MIN, min) != 0 ||
	    nvlist_add_uint32(nvl, PI_STR_MAX, max) != 0 ||
	    nvlist_add_nvlist(typelist, hc_name, nvl) != 0) {
		nvlist_free(nvl);
		return (-1);
	}
	nvlist_free(nvl);

	return (0);
}


/* ARGSUSED */
static int
pi_walkerlist_compare(const void *left, const void *right, void *private)
{
	pi_walkernode_t	*lp = (pi_walkernode_t *)left;
	pi_walkernode_t	*rp = (pi_walkernode_t *)right;

	if (lp->mde_node > rp->mde_node) {
		return (1);
	}
	if (lp->mde_node < rp->mde_node) {
		return (-1);
	}
	return (0);
}


static int
pi_walkerlist_create(topo_mod_t *mod)
{
	/* Initialize the uutil list structure */
	walker_pool = uu_list_pool_create("pi_walker_pool",
	    sizeof (pi_walkernode_t), offsetof(pi_walkernode_t, walker_node),
	    pi_walkerlist_compare, 0);
	if (walker_pool == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		return (-1);
	}
	walker_list = uu_list_create(walker_pool, NULL, 0);
	if (walker_list == NULL) {
		uu_list_pool_destroy(walker_pool);
		walker_pool = NULL;
		return (-1);
	}

	return (0);
}


static void
pi_walkerlist_destroy(topo_mod_t *mod)
{
	void		*wvp;
	pi_walkernode_t	*wp;

	/* Destroy our list of items */
	while ((wvp = uu_list_first(walker_list)) != NULL) {
		/*
		 * First, we empty the list of elements and free each one.
		 * We do not free the data elements as they are libtopo nodes
		 * and will be freed by libtopo
		 */
		wp = (pi_walkernode_t *)wvp;
		uu_list_remove(walker_list, wvp);
		uu_list_node_fini(wp, &(wp->walker_node), walker_pool);

		topo_mod_free(mod, wvp, sizeof (pi_walkernode_t));
	}
	uu_list_destroy(walker_list);
	uu_list_pool_destroy(walker_pool);
	walker_list = NULL;
	walker_pool = NULL;
}


static int
pi_walkerlist_add(topo_mod_t *mod, tnode_t *t_parent, mde_cookie_t mde_node)
{
	uu_list_index_t	idx;
	pi_walkernode_t	*wnp;

	wnp = topo_mod_zalloc(mod, sizeof (pi_walkernode_t));
	if (wnp == NULL) {
		topo_mod_dprintf(mod, "failed to add node_0x%llx parent %p\n",
		    (uint64_t)mde_node, t_parent);
		return (-1);
	}
	uu_list_node_init(wnp, &(wnp->walker_node), walker_pool);

	wnp->t_parent	= t_parent;
	wnp->mde_node	= mde_node;

	(void) uu_list_find(walker_list, wnp, NULL, &idx);
	uu_list_insert(walker_list, wnp, idx);

	return (0);
}


/*
 * Find the parent topo node for this machine description node.
 *
 * Nodes are removed from the list as they are found.  They are only
 * visited once and this eliminates the need for a separate routine
 * that walks the list to free elements later.
 */
static int
pi_walkerlist_find(topo_mod_t *mod, mde_cookie_t mde_node, tnode_t **tpp)
{
	pi_walkernode_t	*result;

	uu_list_index_t	idx;
	pi_walkernode_t	search_criteria;

	search_criteria.mde_node = mde_node;
	search_criteria.t_parent = NULL;

	*tpp = NULL;
	result = uu_list_find(walker_list, &search_criteria, NULL, &idx);
	if (result == NULL) {
		return (-1);
	}
	*tpp = result->t_parent;

	/* Remove this element from the list */
	uu_list_remove(walker_list, result);
	uu_list_node_fini(result, &(result->walker_node), walker_pool);
	topo_mod_free(mod, result, sizeof (pi_walkernode_t));

	return (0);
}
