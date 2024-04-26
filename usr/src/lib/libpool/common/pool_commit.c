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

/*
 * These functions implement the process of commitment for a pool
 * configuration. This process can be described as taking instructions
 * from a static configuration file and using the information about
 * the target system contained in the dynamic configuration to make
 * decisions about how best to allocate resources to meet the
 * constraints specified in the static configuration file.
 *
 * Mechanically, this process relies upon ordering the individual
 * components of the file and stepping through the lists of components
 * and taking actions depending on their type and which file they are
 * part of.
 *
 * Configuration components can be broken down into different types
 * which are then treated according to the following table:
 *
 * Element Type		Action
 * system || pool ||
 * res_comp || res_agg	If the element is a required element, then create or
 *			update it (don't destroy required elements in the
 *			static configuration) otherwise manipulate the
 *			dynamic configuration to create, destroy or update
 *			the element on the system.
 * comp			Create, destroy or update the static configuration
 *			component.
 *
 * The treatment of the different elements reflects the fact that all
 * elements other than comp are configurable and thus libpool can
 * create, destroy and modify these elements at will. comp elements
 * reflect the disposition of the system, these elements can be moved
 * around but they can't be created or destroyed in the dynamic
 * configuration in the commit process. comp elements can be created
 * and destroyed in the static configuration file as a result of a
 * commit operation, since it's possible for a comp to not appear in
 * the dynamic configuration. For instance, if the static
 * configuration file was created on a different machine or after a DR
 * operation which has removed or added components.
 *
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include <pool.h>
#include "pool_internal.h"
#include "pool_impl.h"

#define	MIN(x, y) ((x) < (y) ? (x) : (y))
#define	MAX(x, y) ((x) > (y) ? (x) : (y))
#define	POA_IMPORTANCE_NUM	0
#define	POA_SURPLUS_TO_DEFAULT_NUM	1

/*
 * This resource specific structure is used to determine allocation of resources
 * during resource set allocation.  Each set will receive its min, plus
 * some number of dealt resources based on the global allocation policy.
 */
typedef struct res_info {
	pool_resource_t	*ri_res;	/* Resource set */
	uint64_t	ri_min;		/* Resource set's low watermark */
	uint64_t	ri_max;		/* Resource set's high watermark */
	uint64_t	ri_oldsize;	/* Size of resource set at the start */
	uint64_t	ri_newsize;	/* New resource set size allocated */
	uint64_t	ri_pinned;	/* Count of pinned resources in set */
	uint64_t	ri_dealt;	/* Count of resources dealt to set */
	int64_t		ri_transfer;	/* oldsize - newsize */
					/* The signed quantity of resources */
					/* to tranfer into or out of this */
					/* resource set */
					/* + transfer: tranfer resources out */
					/* - transfer: tranfer resources in */
} res_info_t;

/*
 * diff_and_fix operations
 */
static int		commit_create(pool_conf_t *, pool_elem_t **);
static int		commit_delete(pool_elem_t *);
static int		commit_update(pool_elem_t *, pool_elem_t *, int);

/*
 * configuration commit processing
 */
static int		diff_and_fix(pool_conf_t *, pool_conf_t *);
static int		process_elem_lt(pool_elem_t *, pool_conf_t *);
static int		process_elem_gt(pool_elem_t *, pool_conf_t *,
    pool_conf_t *);
static int		process_lists(int, pool_conf_t *,
    pool_conf_t *, int);
static pool_elem_t	**get_elem_list(const pool_conf_t *, int, uint_t *);
static int		share_resources(pool_conf_t *);
static int		resource_allocate(const char *, pool_resource_t **,
    uint_t);
static int		resource_allocate_default(pool_resource_t **, uint_t);
static int		pset_allocate_imp(pool_resource_t **, uint_t);
static int		resource_compare_by_descending_importance(const void *,
    const void *);
static int		compute_size_to_transfer(const void *, const void *);
static int		set_importance_cb(pool_conf_t *, pool_t *, void *);
static int		unset_importance_cb(pool_conf_t *, pool_t *, void *);
static int		add_importance_props(pool_conf_t *);
static int		remove_importance_props(pool_conf_t *);
static int		clone_element(pool_conf_t *, pool_elem_t *,
    const char *, pool_value_t *, void *);
static int		clean_element(pool_conf_t *, pool_elem_t *,
    const char *, pool_value_t *, void *);

/*
 * commit_create() is used to create a configuration element upon the
 * system.  Since only pools and resource actually need to perform any
 * action, other elements are ignored as a no-op.
 */
static int
commit_create(pool_conf_t *conf, pool_elem_t **e1)
{
	pool_resource_t *res;
	pool_t *pool;
	const char *res_type;
	pool_elem_t *src = *e1;
	uint64_t smin, smax, dmax;
	pool_value_t val = POOL_VALUE_INITIALIZER;
	char *name;

	switch (pool_elem_class(src)) {
	case PEC_SYSTEM:	/* NO-OP */
		break;
	case PEC_POOL:
		name = elem_get_name(src);
		if ((pool = pool_create(conf, name)) == NULL) {
			free(name);
			return (PO_FAIL);
		}
		free(name);
		/*
		 * Now copy the properties from the original pool to the
		 * new one
		 */
		if (pool_walk_properties(TO_CONF(src), src, TO_ELEM(pool),
		    clone_element) != PO_SUCCESS)
			return (PO_FAIL);
		/*
		 * Add a pointer to the src element which can be
		 * updated with a sys_id when the sys_id is allocated
		 * to the created element.
		 */
		pool_set_pair(TO_ELEM(pool), src);
		*e1 = TO_ELEM(pool);
		break;
	case PEC_RES_COMP:
	case PEC_RES_AGG:
		name = elem_get_name(src);
		res_type = pool_elem_class_string(src);
		if ((res = pool_resource_create(conf, res_type, name)) ==
		    NULL) {
			free(name);
			return (PO_FAIL);
		}
		free(name);
		/*
		 * Need to do some ordering of property updates.
		 * Compare the values of source min/max and
		 * destination min/max. If smin < dmax then update the
		 * smin first, else update the max first.
		 */
		if (resource_get_min(pool_elem_res(src), &smin) != PO_SUCCESS ||
		    resource_get_max(pool_elem_res(src), &smax) != PO_SUCCESS ||
		    resource_get_max(res, &dmax) != PO_SUCCESS)
			return (PO_FAIL);
		if (smin < dmax) {
			pool_value_set_uint64(&val, smin);
			if (pool_put_ns_property(TO_ELEM(res), c_min_prop,
			    &val) != PO_SUCCESS)
				return (PO_FAIL);
		} else {
			pool_value_set_uint64(&val, smax);
			if (pool_put_ns_property(TO_ELEM(res), c_max_prop,
			    &val) != PO_SUCCESS)
				return (PO_FAIL);
		}
		/*
		 * Now copy the properties from the original resource
		 * to the new one
		 */
		if (pool_walk_properties(TO_CONF(src), src, TO_ELEM(res),
		    clone_element) != PO_SUCCESS)
			return (PO_FAIL);
		/*
		 * Add a pointer to the src element which can be
		 * updated with a sys_id when the sys_id is allocated
		 * to the created element.
		 */
		pool_set_pair(TO_ELEM(res), src);
		*e1 = TO_ELEM(res);
		break;
	case PEC_COMP:		/* NO-OP */
		break;
	default:
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}


/*
 * commit_delete() is used to delete a configuration element upon the
 * system.  Since only pools and resources actually need to perform
 * any action, other elements are ignored as a no-op.
 */
static int
commit_delete(pool_elem_t *pe)
{
	pool_resource_t *res;
	pool_t *pool;
	int ret = 0;

	if (elem_is_tmp(pe))
		return (PO_SUCCESS);

	switch (pool_elem_class(pe)) {
	case PEC_SYSTEM:	/* NO-OP */
		break;
	case PEC_POOL:
		pool = pool_elem_pool(pe);
		ret = pool_destroy(TO_CONF(pe), pool);
		break;
	case PEC_RES_COMP:
	case PEC_RES_AGG:
		res = pool_elem_res(pe);
		ret = pool_resource_destroy(TO_CONF(pe), res);
		break;
	case PEC_COMP:		/* NO-OP */
		break;
	default:
		return (PO_FAIL);
	}
	return (ret);
}

/*
 * commit_update() is used to update a configuration element upon the
 * system or in a static configuration file. The pass parameter
 * governs whether properties are being updated or associations.  In
 * pass 0, properties are updated. If the element is of class
 * PEC_COMP, then make sure that the element in the static
 * configuration file is correctly located before proceeding with the
 * update. Then, the element in the dynamic configuration file is
 * updated. In pass 1, ie. pass != 0, any pool components have their
 * associations updated in the dynamic configuration.
 */
static int
commit_update(pool_elem_t *e1, pool_elem_t *e2, int pass)
{
	if (pass == 0) {
		pool_resource_t *res1;
		pool_resource_t *res2;
		if (pool_elem_class(e1) == PEC_COMP) {
			res1 = pool_get_owning_resource(TO_CONF(e1),
			    pool_elem_comp(e1));
			res2 = pool_get_owning_resource(TO_CONF(e2),
			    pool_elem_comp(e2));
			if (pool_elem_compare_name(TO_ELEM(res1),
			    TO_ELEM(res2)) != 0) {
				char *name;
				const pool_resource_t *newres;
				pool_component_t *comps[2] = { NULL };

				comps[0] = pool_elem_comp(e2);
				name = elem_get_name(TO_ELEM(res1));
				newres = pool_get_resource(TO_CONF(e2),
				    pool_elem_class_string(TO_ELEM(res1)),
				    name);
				free(name);
				assert(newres);
#ifdef DEBUG
				pool_dprintf("transferring: res, comp\n");
				pool_elem_dprintf(TO_ELEM(newres));
				pool_elem_dprintf(e2);
#endif	/* DEBUG */
				(void) pool_resource_xtransfer(TO_CONF(e2),
				    res2, (pool_resource_t *)newres, comps);
			}
		}
		if (pool_walk_properties(TO_CONF(e2), e2, NULL,
		    clean_element) != PO_SUCCESS) {
			return (PO_FAIL);
		}
		/*
		 * Need to do some ordering of property updates if the
		 * element to be updated is a resource.  Compare the
		 * values of source min/max and destination
		 * min/max. If smin < dmax then update the smin first,
		 * else update the max first.
		 */
		if (pool_elem_class(e1) == PEC_RES_COMP ||
		    pool_elem_class(e1) == PEC_RES_AGG) {
			uint64_t smin, smax, dmax;
			pool_value_t val = POOL_VALUE_INITIALIZER;

			if (resource_get_min(pool_elem_res(e1), &smin) !=
			    PO_SUCCESS ||
			    resource_get_max(pool_elem_res(e1), &smax) !=
			    PO_SUCCESS ||
			    resource_get_max(pool_elem_res(e2), &dmax) !=
			    PO_SUCCESS)
				return (PO_FAIL);
			if (smin < dmax) {
				pool_value_set_uint64(&val, smin);
				if (pool_put_ns_property(e2, c_min_prop,
				    &val) != PO_SUCCESS)
					return (PO_FAIL);
			} else {
				pool_value_set_uint64(&val, smax);
				if (pool_put_ns_property(e2, c_max_prop,
				    &val) != PO_SUCCESS)
					return (PO_FAIL);
			}
		}
		/*
		 * This next couple of steps needs some
		 * explanation. The first walk, copies all the
		 * properties that are writeable from the static
		 * configuration to the dynamic configuration. The
		 * second walk copies all properties (writeable or
		 * not) from the dynamic configuration element back to
		 * the static configuration element. This ensures that
		 * updates from the static configuration element are
		 * correctly applied to the dynamic configuration and
		 * then the static configuration element is updated
		 * with the latest values of the read-only xproperties
		 * from the dynamic configuration element. The
		 * enforcing of permisssions is performed in
		 * clone_element by its choice of property
		 * manipulation function.
		 */
		if (pool_walk_properties(TO_CONF(e1), e1, e2, clone_element) !=
		    PO_SUCCESS) {
			return (PO_FAIL);
		}
		if (pool_walk_properties(TO_CONF(e2), e2, e1, clone_element) !=
		    PO_SUCCESS) {
			return (PO_FAIL);
		}
	} else {
		if (pool_elem_class(e1) == PEC_POOL) {
			pool_resource_t **rs;
			uint_t nelem;
			int i;
			pool_value_t val = POOL_VALUE_INITIALIZER;
			pool_value_t *pvals[] = { NULL, NULL };

			pvals[0] = &val;
			if (pool_value_set_string(&val, "pset") != PO_SUCCESS ||
			    pool_value_set_name(&val, c_type) != PO_SUCCESS)
				return (PO_FAIL);
			if ((rs = pool_query_pool_resources(TO_CONF(e1),
			    pool_elem_pool(e1), &nelem, pvals)) != NULL) {
				for (i = 0; i < nelem; i++) {
					const pool_resource_t *tgt_res;
					char *res_name =
					    elem_get_name(TO_ELEM(rs[i]));

					if ((tgt_res = pool_get_resource(
					    TO_CONF(e2), pool_elem_class_string(
					    TO_ELEM(rs[i])), res_name)) ==
					    NULL) {
						tgt_res = get_default_resource(
						    rs[i]);
					}
					free(res_name);
					if (pool_associate(TO_CONF(e2),
					    pool_elem_pool(e2), tgt_res) !=
					    PO_SUCCESS) {
						free(rs);
						return (PO_FAIL);
					}
				}
				free(rs);
			}
		}
	}
	return (PO_SUCCESS);
}

/*
 * diff_and_fix() works out the differences between two configurations
 * and modifies the state of the system to match the operations
 * required to bring the two configurations into sync.
 *
 * Returns PO_SUCCESS/PO_FAIL.
 */
static int
diff_and_fix(pool_conf_t *stc, pool_conf_t *dyn)
{
	/*
	 * The ordering of the operations is significant, we must
	 * process the system element, then the pools elements, then
	 * the resource elements, then the pools elements again and
	 * finally the resource components.
	 *
	 * TODO
	 * PEC_RES_COMP are the only type of resources
	 * currently. When PEC_RES_AGG resources are added they must
	 * also be processed.
	 */
	if (process_lists(PEC_SYSTEM, stc, dyn, 0) != PO_SUCCESS) {
		return (PO_FAIL);
	}
	if (process_lists(PEC_POOL, stc, dyn, 0) != PO_SUCCESS) {
		return (PO_FAIL);
	}
	if (process_lists(PEC_RES_COMP, stc, dyn, 0) != PO_SUCCESS) {
		return (PO_FAIL);
	}
	if (process_lists(PEC_COMP, stc, dyn, 0) != PO_SUCCESS) {
		return (PO_FAIL);
	}
	if (process_lists(PEC_POOL, stc, dyn, 1) != PO_SUCCESS) {
		return (PO_FAIL);
	}
	/*
	 * Share the resources. It has to be called for both
	 * configurations to ensure that the configurations still look
	 * the same.
	 */
	if (share_resources(dyn) != PO_SUCCESS) {
		return (PO_FAIL);
	}
	if (share_resources(stc) != PO_SUCCESS) {
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

static int
process_elem_lt(pool_elem_t *pe, pool_conf_t *dyn)
{
	if (pool_elem_class(pe) == PEC_COMP) {
		if (pool_component_destroy(pool_elem_comp(pe)) == PO_FAIL) {
			return (PO_FAIL);
		}
	} else if (! elem_is_default(pe)) {
		if (commit_create(dyn, &pe) != PO_SUCCESS) {
			return (PO_FAIL);
		}
	}
	return (PO_SUCCESS);
}

static int
process_elem_gt(pool_elem_t *pe, pool_conf_t *stc, pool_conf_t *dyn)
{
	if (pool_elem_class(pe) == PEC_COMP) {
		pool_resource_t *owner;
		const pool_resource_t *parent_res;
		pool_value_t val = POOL_VALUE_INITIALIZER;
		const pool_component_t *newcomp;
		const char *resname;
		const char *restype;
		/*
		 * I have to find the right parent in the static
		 * configuration. It may not exist, in which case it's
		 * correct to put it in the default
		 */
		owner = pool_get_owning_resource(dyn,
		    pool_elem_comp(pe));
		if (pool_get_ns_property(TO_ELEM(owner), "name", &val) ==
		    POC_INVAL)
			return (PO_FAIL);

		if (pool_value_get_string(&val, &resname) == PO_FAIL)
			return (PO_FAIL);

		if ((resname = strdup(resname)) == NULL)
			return (PO_FAIL);

		restype = pool_elem_class_string(TO_ELEM(owner));
		parent_res = pool_get_resource(stc, restype, resname);
		free((void *)resname);
		if (parent_res == NULL)
			parent_res = resource_by_sysid(stc, PS_NONE, restype);
		/*
		 * Now need to make a copy of the component in the
		 * dynamic configuration in the static configuration.
		 */
		if ((newcomp = pool_component_create(stc, parent_res,
		    elem_get_sysid(pe))) == NULL)
			return (PO_FAIL);

		if (pool_walk_properties(TO_CONF(pe), pe, TO_ELEM(newcomp),
		    clone_element) != PO_SUCCESS)
			return (PO_FAIL);
	} else if (elem_is_default(pe)) {
		pool_resource_t *newres;
		pool_t *newpool;
		char *name;

		if ((name = elem_get_name(pe)) == NULL)
			return (PO_FAIL);
		switch (pool_elem_class(pe)) {
		case PEC_POOL:
			if ((newpool = pool_create(stc, name)) == NULL) {
				free(name);
				return (PO_FAIL);
			}
			free(name);
			if (pool_walk_properties(TO_CONF(pe), pe,
			    TO_ELEM(newpool), clone_element) != PO_SUCCESS)
				return (PO_FAIL);
			break;
		case PEC_RES_AGG:
		case PEC_RES_COMP:
			if ((newres = pool_resource_create(stc,
			    pool_elem_class_string(pe), name)) ==
			    NULL) {
				free(name);
				return (PO_FAIL);
			}
			free(name);
			if (pool_walk_properties(TO_CONF(pe), pe,
			    TO_ELEM(newres), clone_element) != PO_SUCCESS)
				return (PO_FAIL);
			break;
		default:
			free(name);
			break;
		}
	} else {
		if (commit_delete(pe) != PO_SUCCESS)
			return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * This function compares the elements of the supplied type in the
 * static and dynamic configurations supplied. The lists of elements
 * are compared and used to create, delete and updated elements in
 * both the static and dynamic configurations. The pass parameter is
 * used to indicate to commit_update() whether property updates or
 * association updates should be performed.
 */
static int
process_lists(int type, pool_conf_t *stc, pool_conf_t *dyn, int pass)
{
	uint_t stc_nelem = 0, dyn_nelem = 0;
	pool_elem_t **stc_elems, **dyn_elems;
	int i, j;
	int status = PO_SUCCESS;

	if ((stc_elems = get_elem_list(stc, type, &stc_nelem)) == NULL)
		return (PO_FAIL);

	qsort(stc_elems, stc_nelem, sizeof (pool_elem_t *),
	    qsort_elem_compare);

	if ((dyn_elems = get_elem_list(dyn, type, &dyn_nelem)) == NULL) {
		free(stc_elems);
		return (PO_FAIL);
	}

	qsort(dyn_elems, dyn_nelem, sizeof (pool_elem_t *),
	    qsort_elem_compare);
	/*
	 * Step through and do the updating, remember that we are
	 * comparing using the compare function for the configuration
	 * and that is fixed.
	 */
	i = j = 0;
	while (status == PO_SUCCESS && i < stc_nelem && j < dyn_nelem) {
		int compare;
		/*
		 * We are going to do this by stepping through the static
		 * list first.
		 */
		if (elem_is_default(stc_elems[i]) &&
		    elem_is_default(dyn_elems[j]))
			compare = 0;
		else
			compare = pool_elem_compare_name(stc_elems[i],
			    dyn_elems[j]);
		if (compare < 0) {
			status = process_elem_lt(stc_elems[i], dyn);
			i++;
		} else if (compare > 0) {
			status = process_elem_gt(dyn_elems[j], stc, dyn);
			j++;
		} else {	/* compare == 0 */
			if (commit_update(stc_elems[i], dyn_elems[j], pass)
			    != PO_SUCCESS) {
				status = PO_FAIL;
			}
			i++;
			j++;
		}
	}
	if (status == PO_FAIL) {
		free(stc_elems);
		free(dyn_elems);
		return (PO_FAIL);
	}
	while (status == PO_SUCCESS && i < stc_nelem) {
		status = process_elem_lt(stc_elems[i], dyn);
		i++;
	}
	if (status == PO_FAIL) {
		free(stc_elems);
		free(dyn_elems);
		return (PO_FAIL);
	}
	while (status == PO_SUCCESS && j < dyn_nelem) {
		status = process_elem_gt(dyn_elems[j], stc, dyn);
		j++;
	}
	free(stc_elems);
	free(dyn_elems);
	return (status);
}

/*
 * get_elem_list() returns a list of pool_elem_t's. The size of the
 * list is written into nelem. The list contains elements of all types
 * that pools is interested in: i.e. system, pool, resources and
 * resource components. It is the caller's responsibility to free the
 * list when it is finished with.
 *
 * The array of pointers returned by the type specific query can be
 * safely cast to be an array of pool_elem_t pointers. In the case of
 * PEC_RES_COMP some additional processing is required to qualify the
 * list of elements.
 *
 * Returns a pointer to a list of pool_elem_t's or NULL on failure.
 */
static pool_elem_t **
get_elem_list(const pool_conf_t *conf, int type, uint_t *nelem)
{
	pool_resource_t **rl;
	pool_t **pl;
	pool_component_t **cl;
	pool_elem_t **elems = NULL;
	int i;

	switch (type) {
	case PEC_SYSTEM:
		if ((elems = malloc(sizeof (pool_elem_t *))) == NULL)
			return (NULL);
		*nelem = 1;
		elems[0] = pool_conf_to_elem(conf);
		break;
	case PEC_POOL:
		if ((pl = pool_query_pools(conf, nelem, NULL)) != NULL) {
			elems = (pool_elem_t **)pl;
		}
		break;
	case PEC_RES_COMP:
		if ((rl = pool_query_resources(conf, nelem, NULL)) != NULL) {
			int j = 0;
			elems = (pool_elem_t **)rl;
			for (i = 0; i < *nelem; i++) {
				if (pool_elem_class(TO_ELEM(rl[i])) ==
				    PEC_RES_COMP)
					elems[j++] = TO_ELEM(rl[i]);
			}
			*nelem = j;
		}
		break;
	case PEC_COMP:
		if ((cl = pool_query_components(conf, nelem, NULL)) != NULL) {
			elems = (pool_elem_t **)cl;
		}
		break;
	default:
		abort();
		break;
	}
	return (elems);
}

/*
 * share_resources() sets up the allocation of resources by each
 * provider.  Firstly all resources are updated with the importance of
 * each pool, then each resource provider is invoked in turn with a
 * list of it's own resources.  Finally, the pool importance details
 * are removed from the resources.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
share_resources(pool_conf_t *conf)
{
	pool_resource_t **resources;
	uint_t nelem;
	pool_value_t *props[] = { NULL, NULL };
	pool_value_t val = POOL_VALUE_INITIALIZER;

	props[0] = &val;

	/*
	 * Call an allocation function for each type of supported resource.
	 * This function is responsible for "sharing" resources to resource
	 * sets as determined by the system.allocate-method.
	 */

	if (pool_value_set_string(props[0], "pset") != PO_SUCCESS ||
	    pool_value_set_name(props[0], c_type) != PO_SUCCESS)
		return (PO_FAIL);

	if (add_importance_props(conf) != PO_SUCCESS) {
		(void) remove_importance_props(conf);
		return (PO_FAIL);
	}

	if ((resources = pool_query_resources(conf, &nelem, props)) != NULL) {
		/*
		 * 'pool.importance' defines the importance of a pool;
		 * resources inherit the importance of the pool that
		 * is associated with them. If more than one pool is
		 * associated with a resource, the importance of the
		 * resource is the maximum importance of all
		 * associated pools.  Use '_importance' on resources
		 * to determine who gets extra.
		 */
		if (resource_allocate("pset", resources, nelem) != PO_SUCCESS) {
			free(resources);
			(void) remove_importance_props(conf);
			return (PO_FAIL);
		}
	}
	free(resources);
	(void) remove_importance_props(conf);
	return (PO_SUCCESS);
}


/*
 * Work out which allocation method to use based on the value of the
 * system.allocate-method property.
 */
int
resource_allocate(const char *type, pool_resource_t **res, uint_t nelem)
{
	pool_elem_t *pe;
	const char *method_name;
	uint64_t method;
	pool_value_t val = POOL_VALUE_INITIALIZER;
	int ret;

	pe = pool_conf_to_elem(TO_CONF(TO_ELEM(res[0])));

	if (pool_get_ns_property(pe, "allocate-method", &val) != POC_STRING)
		method_name = POA_IMPORTANCE;
	else {
		(void) pool_value_get_string(&val, &method_name);
	}
	if (strcmp(POA_IMPORTANCE, method_name) != 0) {
		if (strcmp(POA_SURPLUS_TO_DEFAULT, method_name) != 0) {
			pool_seterror(POE_INVALID_CONF);
			return (PO_FAIL);
		} else {
			method = POA_SURPLUS_TO_DEFAULT_NUM;
		}
	} else {
		method = POA_IMPORTANCE_NUM;
	}
	switch (method) {
	case POA_IMPORTANCE_NUM:
		/*
		 * TODO: Add support for new resource types
		 */
		switch (pool_resource_elem_class_from_string(type)) {
		case PREC_PSET:
			ret = pset_allocate_imp(res, nelem);
			break;
		default:
			ret = PO_FAIL;
			break;
		}
		break;
	case POA_SURPLUS_TO_DEFAULT_NUM:
		ret = resource_allocate_default(res, nelem);
		break;
	}

	return (ret);
}

/*
 * Each set will get its minimum, however if there is more than the
 * total minimum available, then leave this in the default set.
 */
int
resource_allocate_default(pool_resource_t **res, uint_t nelem)
{
	res_info_t *res_info;
	uint_t j;
	pool_resource_t *default_res = NULL;

	if (nelem == 1)
		return (PO_SUCCESS);

	if ((res_info = calloc(nelem, sizeof (res_info_t))) == NULL) {
		return (PO_FAIL);
	}

	/* Load current resource values. */
	for (j = 0; j < nelem; j++) {

		if (default_res == NULL &&
		    resource_is_default(res[j]) == PO_TRUE)
			default_res = res[j];

		if (resource_get_max(res[j],
		    &res_info[j].ri_max) == PO_FAIL ||
		    resource_get_min(res[j],
		    &res_info[j].ri_min) == PO_FAIL ||
		    resource_get_size(res[j],
		    &res_info[j].ri_oldsize) == PO_FAIL ||
		    resource_get_pinned(res[j],
		    &res_info[j].ri_pinned) == PO_FAIL) {
			free(res_info);
			return (PO_FAIL);
		}
		res_info[j].ri_res = res[j];
	}

	/*
	 * Firstly, for all resources that have size greater than min,
	 * transfer all movable size above min to the default resource.
	 */
	for (j = 0; j < nelem; j++) {

		uint64_t real_min;

		/* compute the real minimum number of resources */
		real_min = MAX(res_info[j].ri_pinned, res_info[j].ri_min);
		if (res_info[j].ri_res != default_res &&
		    res_info[j].ri_oldsize > real_min) {

			uint64_t num;

			num = res_info[j].ri_oldsize - real_min;
			if (pool_resource_transfer(
			    TO_CONF(TO_ELEM(default_res)),
			    res_info[j].ri_res, default_res, num) !=
			    PO_SUCCESS) {
				free(res_info);
				return (PO_FAIL);
			}
		}
	}
	/*
	 * Now, transfer resources below min from the default.
	 */
	for (j = 0; j < nelem; j++) {
		/*
		 * We don't want to interfere with resources which are reserved
		 */
		if (res_info[j].ri_res != default_res &&
		    res_info[j].ri_oldsize < res_info[j].ri_min) {
			if (pool_resource_transfer(
			    TO_CONF(TO_ELEM(default_res)),
			    default_res, res_info[j].ri_res,
			    res_info[j].ri_min - res_info[j].ri_oldsize) !=
			    PO_SUCCESS) {
				free(res_info);
				return (PO_FAIL);
			}
		}
	}
	free(res_info);
	return (PO_SUCCESS);
}

/*
 * Allocate cpus to pset resource sets, favoring sets with higher importance.
 *
 * Step 1: Sort resource sets by decreasing importance, and load each sets
 *	   current size (oldsize), min, max, and number of pinned cpus.
 *	   Compute the total number of cpus by totaling oldsize.
 *
 * Step 2: Compute the newsize for each set:
 *
 *	Give each set its min number of cpus.  This min may be greater than
 *	its pset.min due to pinned cpus. If there are more cpus than the total
 *	of all mins, then the surplus cpus are dealt round-robin to all sets
 *	(up to their max) in order of decreasing importance.  A set may be
 *	skipped during dealing because it started with more than its min due to
 *	pinned cpus.  The dealing stops when there are no more cpus or all
 *	sets are at their max. If all sets are at their max, any remaining cpus
 *	are given to the default set.
 *
 * Step 3: Transfer cpus from sets with (oldsize > newsize) to sets with
 *	   (oldsize < newsize).
 */
int
pset_allocate_imp(pool_resource_t **res, uint_t nelem)
{
	res_info_t *res_info;
	res_info_t *default_res_info;
	const pool_resource_t *default_res = NULL;
	uint64_t tot_resources = 0;	/* total count of resources */
	uint64_t tot_min = 0;		/* total of all resource set mins */
	uint64_t num_to_deal = 0;	/* total resources above mins to deal */
	uint64_t sets_maxed = 0;	/* number of resource sets dealt to  */
					/* their max */
	uint64_t sets_finished = 0;	/* number of resource sets that have */
					/* size == newsize */
	int donor, receiver;
	int deal;
	int j;
	int ret = PO_SUCCESS;

	/*
	 * Build list of res_info_t's
	 */
	if ((res_info = calloc(nelem, sizeof (res_info_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}

	/* Order resources by importance, most important being first */
	qsort(res, nelem, sizeof (pool_resource_t *),
	    resource_compare_by_descending_importance);

	for (j = 0; j < nelem; j++) {

		/* Track which resource is the default */
		if (default_res == NULL &&
		    resource_is_default(res[j]) == PO_TRUE) {
			default_res = res[j];
			default_res_info = &(res_info[j]);
		}

		/* Load sets' current values */
		if (resource_get_max(res[j], &res_info[j].ri_max) == PO_FAIL ||
		    resource_get_min(res[j], &res_info[j].ri_min) == PO_FAIL ||
		    resource_get_size(res[j], &res_info[j].ri_oldsize) ==
		    PO_FAIL ||
		    resource_get_pinned(res[j],
		    &res_info[j].ri_pinned) == PO_FAIL) {
			free(res_info);
			return (PO_FAIL);
		}

		/* Start each set's newsize out at their min. */
		res_info[j].ri_newsize = res_info[j].ri_min;

		/* pre-deal pinned resources that exceed min */
		if (res_info[j].ri_pinned > res_info[j].ri_min) {
			res_info[j].ri_newsize = res_info[j].ri_pinned;
			res_info[j].ri_dealt =
			    res_info[j].ri_newsize - res_info[j].ri_min;
		}
		res_info[j].ri_res = res[j];

		/* Compute total number of resources to deal out */
		tot_resources += res_info[j].ri_oldsize;
		tot_min += res_info[j].ri_newsize;

#ifdef DEBUG
		pool_dprintf("res allocation details\n");
		pool_elem_dprintf(TO_ELEM(res[j]));
		pool_dprintf("size=%llu\n", res_info[j].ri_oldsize);
#endif	/* DEBUG */
	}

	num_to_deal = tot_resources - tot_min;

	/*
	 * Deal one resource to each set, and then another, until all
	 * resources are dealt or all sets are at their max.
	 */
	for (deal = 1; num_to_deal > 0 && sets_maxed < nelem; deal++) {
		for (j = 0; j < nelem; j++) {

			/*
			 * Skip this resource set if it has already been
			 * pre-dealt a resource due to pinned resources.
			 */
			if (res_info[j].ri_dealt >= deal)
				continue;

			if (res_info[j].ri_newsize < res_info[j].ri_max) {

				res_info[j].ri_dealt++;
				res_info[j].ri_newsize++;
				if (res_info[j].ri_newsize ==
				    res_info[j].ri_max)
					sets_maxed++;

				num_to_deal--;
				if (num_to_deal == 0)
					break;
			}
		}
	}

	/*
	 * If all resource sets are at their max, deal the remaining to the
	 * default resource set.
	 */
	if ((sets_maxed == nelem) && (num_to_deal > 0)) {
		default_res_info->ri_dealt += num_to_deal;
		default_res_info->ri_newsize += num_to_deal;
	}

	/*
	 * Sort so that resource sets needing resources preced resource sets
	 * that have extra resources.  The sort function will also compute
	 * The quantity of resources that need to be transfered into or out
	 * of each set so that it's size == newsize.
	 */
	qsort(res_info, nelem, sizeof (res_info_t),
	    compute_size_to_transfer);

	/*
	 * The donor index starts at the end of the resource set list and
	 * walks up.  The receiver index starts at the beginning of the
	 * resource set list and walks down.  Cpu's are transfered from the
	 * donors to the receivers until all sets have transfer == 0).
	 */
	donor = nelem - 1;
	receiver = 0;

	/* Number of sets with transfer == 0 */
	sets_finished = 0;

	/* Tranfer resources so that each set's size becomes newsize */
	for (;;) {

		uint64_t ntrans;
		if (donor == receiver) {
			if (res_info[donor].ri_transfer != 0) {
				free(res_info);
				return (PO_FAIL);
			}
			sets_finished++;
			break;
		}
		if (res_info[donor].ri_transfer == 0) {
			sets_finished++;
			donor--;
			continue;
		}
		if (res_info[receiver].ri_transfer == 0) {
			sets_finished++;
			receiver++;
			continue;
		}

		/* Transfer resources from the donor set to the receiver */
		ntrans = MIN(res_info[donor].ri_transfer,
		    -res_info[receiver].ri_transfer);

		if (pool_resource_transfer(
		    TO_CONF(TO_ELEM(res_info[donor].ri_res)),
		    res_info[donor].ri_res, res_info[receiver].ri_res,
		    ntrans) != PO_SUCCESS) {
			free(res_info);
			return (PO_FAIL);
		}
		res_info[donor].ri_transfer -= ntrans;
		res_info[receiver].ri_transfer += ntrans;
	}

	if (sets_finished != nelem)
		ret = PO_FAIL;

	free(res_info);
	return (ret);
}

/*
 * Used as a qsort parameter to help order resources in terms of their
 * importance, higher importance being first.
 */
int
resource_compare_by_descending_importance(const void *arg1, const void *arg2)
{
	pool_elem_t *elem1;
	pool_elem_t *elem2;
	pool_resource_t **res1 = (pool_resource_t **)arg1;
	pool_resource_t **res2 = (pool_resource_t **)arg2;
	pool_value_t val = POOL_VALUE_INITIALIZER;
	int64_t i1 = 0, i2 = 0;

	elem1 = TO_ELEM(*res1);
	elem2 = TO_ELEM(*res2);

	if (pool_get_property(TO_CONF(elem1), elem1, "_importance", &val) ==
	    POC_INT)
		(void) pool_value_get_int64(&val, &i1);

	if (pool_get_property(TO_CONF(elem2), elem2, "_importance", &val) ==
	    POC_INT)
		(void) pool_value_get_int64(&val, &i2);
	return (i1 > i2 ? -1 : (i1 < i2 ? 1 : 0));
}

/*
 * Sort in increasing order so that resource sets with extra resources are at
 * the end and resource sets needing resources are at the beginning.
 */
int
compute_size_to_transfer(const void *arg1, const void *arg2)
{
	res_info_t *r1 = (res_info_t *)arg1, *r2 = (res_info_t *)arg2;
	r1->ri_transfer = (int64_t)r1->ri_oldsize - (int64_t)r1->ri_newsize;
	r2->ri_transfer = (int64_t)r2->ri_oldsize - (int64_t)r2->ri_newsize;
	return (r1->ri_transfer > r2->ri_transfer ? 1 :
	    (r1->ri_transfer < r2->ri_transfer ? -1 : 0));
}

/*
 * set_importance_cb() is used to create "_importance" props on each
 * resource associated with a pool.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
/*ARGSUSED*/
static int
set_importance_cb(pool_conf_t *conf, pool_t *pool, void *unused)
{
	pool_value_t val = POOL_VALUE_INITIALIZER;
	int64_t importance;
	pool_resource_t **res;
	uint_t nelem, i;

	if (pool_get_property(conf, TO_ELEM(pool), "pool.importance", &val) !=
	    POC_INT) {
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	(void) pool_value_get_int64(&val, &importance);
	if ((res = pool_query_pool_resources(conf, pool, &nelem, NULL)) ==
	    NULL) {
		return (PO_FAIL);
	}
	for (i = 0; res[i] != NULL; i++) {
		int64_t old_importance = INT64_MIN;
		pool_elem_t *elem = TO_ELEM(res[i]);

		if (pool_get_property(conf, elem, "_importance", &val) ==
		    POC_INT)
			(void) pool_value_get_int64(&val, &old_importance);
		if (old_importance <= importance) {
			(void) pool_value_set_int64(&val, importance);
			(void) pool_put_property(conf, elem, "_importance",
			    &val);
		}
	}
	free(res);
	return (PO_SUCCESS);
}

/*
 * unset_importance_cb() is used to remove "_importance" props from
 * each resource associated with a pool.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
/*ARGSUSED*/
static int
unset_importance_cb(pool_conf_t *conf, pool_t *pool, void *unused)
{
	pool_resource_t **res;
	uint_t nelem, i;

	if ((res = pool_query_pool_resources(conf, pool, &nelem, NULL)) ==
	    NULL) {
		return (PO_FAIL);
	}
	for (i = 0; res[i] != NULL; i++) {
		if (pool_rm_property(conf, TO_ELEM(res[i]), "_importance") ==
		    PO_FAIL) {
			free(res);
			return (PO_FAIL);
		}
	}
	free(res);
	return (PO_SUCCESS);
}

/*
 * add_importance_props() is used to create "_importance" props on
 * each resource associated with a pool.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
add_importance_props(pool_conf_t *conf)
{
	return (pool_walk_pools(conf, NULL, set_importance_cb));
}

/*
 * remove_importance_props() is used to remove "_importance" props on
 * each resource associated with a pool.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
static int
remove_importance_props(pool_conf_t *conf)
{
	return (pool_walk_pools(conf, NULL, unset_importance_cb));
}

/*
 * pool_conf_commit_sys() takes a configuration and modifies both the
 * supplied configuration and the dynamic configuration. The goal of
 * this modification is to generate a dynamic configuration which best
 * represents the constraints laid down in the static configuration
 * and to update the static configuration with the results of this
 * process.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
int
pool_conf_commit_sys(pool_conf_t *conf, int validate)
{
	pool_conf_t *dyn;

	if ((dyn = pool_conf_alloc()) == NULL)
		return (PO_FAIL);
	if (pool_conf_open(dyn, pool_dynamic_location(), PO_RDWR) !=
	    PO_SUCCESS) {
		pool_conf_free(dyn);
		return (PO_FAIL);
	}
	if (validate == PO_TRUE) {
		if (pool_conf_validate(conf, POV_RUNTIME) != PO_SUCCESS) {
			(void) pool_conf_close(dyn);
			pool_conf_free(dyn);
			return (PO_FAIL);
		}
	}
	/*
	 * Now try to make the two things "the same".
	 */
	if (diff_and_fix(conf, dyn) != PO_SUCCESS) {
		(void) pool_conf_close(dyn);
		pool_conf_free(dyn);
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}
	if (dyn->pc_prov->pc_commit(dyn) != PO_SUCCESS) {
		(void) pool_conf_close(dyn);
		pool_conf_free(dyn);
		return (PO_FAIL);
	}
	(void) pool_conf_close(dyn);
	pool_conf_free(dyn);
	return (PO_SUCCESS);
}

/*
 * Copies all properties from one element to another. If the property
 * is a readonly property, then don't copy it.
 */
/* ARGSUSED */
static int
clone_element(pool_conf_t *conf, pool_elem_t *pe, const char *name,
    pool_value_t *pv, void *user)
{
	pool_elem_t *tgt = (pool_elem_t *)user;
	const pool_prop_t *prop;
#ifdef DEBUG
	pool_dprintf("Cloning %s from %s\n",
	    pool_conf_location(TO_CONF(TO_ELEM(tgt))),
	    pool_conf_location(TO_CONF(pe)));
	assert(TO_CONF(TO_ELEM(tgt)) != TO_CONF(pe));
	pool_dprintf("clone_element: Processing %s\n", name);
	pool_value_dprintf(pv);
#endif	/* DEBUG */
	/*
	 * Some properties should be ignored
	 */
	if ((prop = provider_get_prop(pe, name)) != NULL &&
	    prop_is_readonly(prop) == PO_TRUE)
		return (PO_SUCCESS);

	/* The temporary property needs special handling */
	if (strstr(name, ".temporary") != NULL)
		return (pool_set_temporary(TO_CONF(tgt), tgt) ==
		    PO_FAIL ?  PO_FAIL : PO_SUCCESS);
	else
		return (pool_put_property(TO_CONF(tgt), tgt, name, pv) ==
		    PO_FAIL ? PO_FAIL : PO_SUCCESS);
}

/*
 * Removes all properties from one element. Properties which are
 * managed by the configuration are ignored.
 */
/* ARGSUSED3 */
static int
clean_element(pool_conf_t *conf, pool_elem_t *pe, const char *name,
    pool_value_t *pv, void *user)
{
	const pool_prop_t *prop;
	/*
	 * Some properties should be ignored
	 */
	if (strstr(name, ".temporary") != NULL ||
	    ((prop = provider_get_prop(pe, name)) != NULL &&
	    prop_is_optional(prop) == PO_FALSE))
		return (PO_SUCCESS);
	return (pool_rm_property(conf, (pool_elem_t *)pe, name) == PO_FAIL);
}
