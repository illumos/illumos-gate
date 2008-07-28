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
 * Some topology creation routines may need to defer completing enumeration
 * until after the entire PRI graph has been visited.  This file includes
 * the interfaces necessary to permit these routines to do this in a general
 * way.
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

static uu_list_pool_t	*defer_pool;
static uu_list_t	*defer_list;

struct pi_defernode_s {
	uu_list_node_t	defer_node;

	mde_cookie_t	mde_node;	/* MDE node index */
	tnode_t		*t_parent;	/* Parent topology node */
	tnode_t		*t_node;	/* Topo node associated with MDE node */
	void		*private;	/* Private data for defer routine */

	pi_deferenum_fn_t *func;	/* Defered enumeration routine */
};
typedef struct pi_defernode_s pi_defernode_t;

/* Routines to handle the list of topology parents and mde_nodes */
static int  pi_deferlist_create(topo_mod_t *);
static int  pi_deferlist_compare(const void *, const void *, void *);


/*
 * Add a new routine to the list of deferred enumeration routines
 */
int
pi_defer_add(topo_mod_t *mod, mde_cookie_t mde_node, tnode_t *t_parent,
    tnode_t *t_node, pi_deferenum_fn_t func, void *private)
{
	int		result;
	uu_list_index_t	idx;
	pi_defernode_t	*dnp;

	if (defer_list == NULL) {
		result = pi_deferlist_create(mod);
		if (result != 0) {
			return (result);
		}
	}

	/*
	 * Create a data structure to store information about the node for
	 * which to defer enumeration.  The defer_pool is created by the
	 * list creation routine, above.
	 */
	dnp = topo_mod_zalloc(mod, sizeof (pi_defernode_t));
	if (dnp == NULL) {
		topo_mod_seterrno(mod, EMOD_NOMEM);
		return (-1);
	}
	uu_list_node_init(dnp, &(dnp->defer_node), defer_pool);

	dnp->mde_node	= mde_node;
	dnp->t_parent	= t_parent;
	dnp->t_node	= t_node;
	dnp->private	= private;
	dnp->func	= func;

	(void) uu_list_find(defer_list, dnp, NULL, &idx);
	uu_list_insert(defer_list, dnp, idx);

	return (0);
}


/*
 * Execute the list of deferred enumeration routines, destroying the list as
 * we go.
 */
int
pi_defer_exec(topo_mod_t *mod, md_t *mdp)
{
	int		result;

	void		*dvp;
	pi_defernode_t	*dp;
	topo_instance_t	inst;
	mde_cookie_t	mde_node;
	tnode_t		*t_parent;
	tnode_t		*t_node;
	void		*private;
	char		*hc_name;

	pi_deferenum_fn_t *func;

	topo_mod_dprintf(mod, "beginning deferred enumerator execution\n");
	if (defer_list == NULL) {
		topo_mod_dprintf(mod, "no deferred enumerators.  done.\n");
		return (0);
	}

	while ((dvp = uu_list_first(defer_list)) != NULL) {
		/* Extract the necessary information from the defernode_t */
		dp = (pi_defernode_t *)dvp;
		mde_node = dp->mde_node;
		t_parent = dp->t_parent;
		t_node   = dp->t_node;
		private  = dp->private;
		func	 = dp->func;

		/*
		 * Remove the element from the list.  Once we are done calling
		 * the routine we do not need it any more.
		 */
		uu_list_remove(defer_list, dvp);
		uu_list_node_fini(dp, &(dp->defer_node), defer_pool);
		topo_mod_free(mod, dp, sizeof (pi_defernode_t));

		/* Get the instance value from the mde node */
		if (pi_get_instance(mod, mdp, mde_node, &inst) != 0) {
			topo_mod_dprintf(mod, "deferred node_0x%llx invalid\n",
			    (uint64_t)mde_node);

			/* Move on to the next node */
			topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
			continue;
		}

		/* Get the hc name from the mde node */
		hc_name = pi_get_topo_hc_name(mod, mdp, mde_node);
		if (hc_name == NULL) {
			topo_mod_dprintf(mod,
			    "deferred node_0x%llx has invalid NULL hc_name\n",
			    (uint64_t)mde_node);

			/* Move on to the next node */
			topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
			continue;
		}
		topo_mod_dprintf(mod,
		    "calling deferred enumerator for node_0x%llx\n",
		    (uint64_t)mde_node);

		/* Call the deferred enumeration function */
		result = (func)(mod, mdp, mde_node, inst, t_parent, hc_name,
		    t_node, private);
		if (result != 0) {
			topo_mod_dprintf(mod,
			    "deferred enumeration for node_0x%llx failed\n",
			    (uint64_t)mde_node);
			topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
		}

		/* Clean up from the deferred call */
		topo_mod_strfree(mod, hc_name);
	}
	topo_mod_dprintf(mod, "deferred enumeration completed.\n");

	uu_list_destroy(defer_list);
	uu_list_pool_destroy(defer_pool);

	return (0);
}


static int
pi_deferlist_create(topo_mod_t *mod)
{
	/* Initialize the uutil list structure */
	defer_pool = uu_list_pool_create("pi_defer_pool",
	    sizeof (pi_defernode_t), offsetof(pi_defernode_t, defer_node),
	    pi_deferlist_compare, 0);
	if (defer_pool == NULL) {
		topo_mod_seterrno(mod, EMOD_NOMEM);
		return (-1);
	}
	defer_list = uu_list_create(defer_pool, NULL, 0);
	if (defer_list == NULL) {
		uu_list_pool_destroy(defer_pool);
		topo_mod_seterrno(mod, EMOD_NOMEM);
		return (-1);
	}

	return (0);
}


/* ARGSUSED */
static int
pi_deferlist_compare(const void *l_arg, const void *r_arg, void *private)
{
	pi_defernode_t	*lp = (pi_defernode_t *)l_arg;
	pi_defernode_t	*rp = (pi_defernode_t *)r_arg;

	if (lp->func != rp->func) {
		return (1);
	}
	if (lp->t_parent != rp->t_parent) {
		return (-1);
	}
	return (0);
}
