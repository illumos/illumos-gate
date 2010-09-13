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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * sa_libpool - libpool statistic adapter, collect statistic data provided
 * by libpool.
 */

#include <string.h>
#include <locale.h>
#include <assert.h>

#include <pool.h>

#include "utils.h"
#include "poolstat.h"

typedef int (*prop_walk_cb_t)
	(pool_conf_t *, pool_elem_t *, const char *, pool_value_t *, void *);

/* user data used in the property walk callback function.	*/
typedef struct {
	int	ud_result;
	void*   ud_bag;
} userdata_cb_t;

static pool_conf_t *conf;
static const char *conf_loc;

static void update_pset(statistic_bag_t *);

/*
 * If not NULL use the passed 'configuration' to access the pool framework,
 * otherwise create and open a private access point.
 */
void
sa_libpool_init(void *configuration)
{
	if (configuration) {
		conf = configuration;
	} else {
		conf_loc = pool_dynamic_location();
		if ((conf = pool_conf_alloc()) == NULL)
			die(gettext(ERR_NOMEM));
		if (pool_conf_open(conf, conf_loc, PO_RDONLY | PO_UPDATE)
			!= PO_SUCCESS)
			die(gettext(ERR_OPEN_STATIC), conf_loc, get_errstr());
	}
}

/*ARGSUSED*/
void
sa_libpool_update(statistic_bag_t *sbag, int flags)
{
	static int changed;

	/* The SA_REFRESH flag forces the update of local data structures. */
	if (flags & SA_REFRESH) {
		changed = 0;
		if (pool_conf_update(conf, &changed) != PO_SUCCESS)
			die(gettext(ERR_CONF_UPDATE), get_errstr());
		sbag->sb_changed = changed;
	}
	if (strcmp(sbag->sb_type, PSET_TYPE_NAME) == 0) {
		if (changed & POU_PSET || changed & POU_CPU)
			((pset_statistic_bag_t *)sbag->bag)->pset_sb_changed =
				changed;
		else
			((pset_statistic_bag_t *)sbag->bag)->pset_sb_changed =
				0;
		update_pset(sbag);
	} else if (strcmp(sbag->sb_type, POOL_TYPE_NAME) == 0) {
		return;
	} else {
		die(gettext(ERR_UNSUPP_STYPE), sbag->sb_type);
	}
}

/*
 * callback function to property walker, copies the property value from
 * the passed 'pvalue' to the corresponding field in the statistic data bag.
 */
/*ARGSUSED*/
static int
populate_userdata_cb(pool_conf_t *unused1, pool_elem_t *unused2,
	const char *name, pool_value_t *pval, userdata_cb_t *ud)
{
	pset_statistic_bag_t *bag = (pset_statistic_bag_t *)ud->ud_bag;

	ud->ud_result = 0;
	if (strcmp("pset.min", name) == 0) {
		ud->ud_result = pool_value_get_uint64(pval, &bag->pset_sb_min);
	} else if (strcmp("pset.max", name) == 0) {
		ud->ud_result = pool_value_get_uint64(pval, &bag->pset_sb_max);
	} else if (strcmp("pset.load", name) == 0) {
		uint64_t load;

		ud->ud_result = pool_value_get_uint64(pval, &load);
		bag->pset_sb_load = (double)load / 1000.0;
	} else if (strcmp("pset.size", name) == 0) {
		ud->ud_result = pool_value_get_uint64(pval, &bag->pset_sb_size);
	} else if (strcmp("pset.sys_id", name) == 0) {
		ud->ud_result = pool_value_get_int64(pval, &bag->pset_sb_sysid);
	}

	return (0);
}

/*
 * Update statistic data for the procssor set with the name 'sbag->name'.
 * Use 'sbag->bag' to store the data.
 */
static void
update_pset(statistic_bag_t *sbag)
{
	pool_resource_t *pset_reso;
	pool_elem_t	*pset_elem;
	userdata_cb_t	ud;

	ud.ud_bag = (void *) sbag->bag;
	if ((pset_reso = pool_get_resource(conf, PSET_TYPE_NAME, sbag->sb_name))
		== NULL)
		die(gettext(ERR_STATS_RES_N), sbag->sb_name, get_errstr());
	if ((pset_elem = pool_resource_to_elem(conf, pset_reso)) == NULL)
		die(gettext(ERR_STATS_RES_N), sbag->sb_name, get_errstr());

	/* use the property walker to collect the resource properties	*/
	if (pool_walk_properties(conf, pset_elem, &ud,
		(prop_walk_cb_t)populate_userdata_cb) == -1)
		die(gettext(ERR_STATS_RES_N), sbag->sb_name, get_errstr());
}
