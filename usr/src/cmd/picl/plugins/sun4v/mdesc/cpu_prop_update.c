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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mdescplugin.h"
#include <limits.h>

/* These 3 variable are defined and set in mdescplugin.c */
extern picl_nodehdl_t	root_node;
extern md_t		*mdp;
extern mde_cookie_t	rootnode;

void
set_prop_info(ptree_propinfo_t *propinfo, int size, char *name, int type)
{
	propinfo->version = PICLD_PLUGIN_VERSION_1;
	propinfo->read = NULL;
	propinfo->write = NULL;
	propinfo->piclinfo.type = type;
	propinfo->piclinfo.accessmode = PICL_READ;
	propinfo->piclinfo.size = size;
	(void) strncpy(propinfo->piclinfo.name, name,
	    sizeof (propinfo->piclinfo.name));
}

static boolean_t
prop_exists(picl_nodehdl_t node, char *name)
{
	int status;
	picl_prophdl_t proph;

	status = ptree_get_prop_by_name(node, name, &proph);
	if (status == PICL_SUCCESS)
		return (B_TRUE);
	else
		return (B_FALSE);
}

static void
add_md_prop(picl_nodehdl_t node, int size, char *name, void* value, int type)
{
	ptree_propinfo_t propinfo;
	picl_prophdl_t proph;

	if (!prop_exists(node, name)) {
		set_prop_info(&propinfo, size, name, type);

		(void) ptree_create_and_add_prop(node, &propinfo,
		    value, &proph);
	}
}
static void
add_tlb_props(picl_nodehdl_t node, mde_cookie_t *tlblistp, int ntlbs)
{
	int i;
	uint64_t int_value;
	uint8_t *type;
	char str[MAXSTRLEN];
	char property[MAXSTRLEN];
	char tlb_str[MAXSTRLEN];
	int type_size, str_size, total_size, type_flag;

	for (i = 0; i < ntlbs; i++) {
		if (md_get_prop_data(mdp, tlblistp[i], "type", &type,
		    &type_size)) {
			return;
		}

		total_size = type_flag = 0;

		while (total_size < type_size) {
			str_size = strlen((char *)type + total_size) + 1;
			(void) strncpy(str, (char *)type + total_size,
			    sizeof (str));
			if (strncmp(str, "instn", sizeof (str)) == 0)
				type_flag |= ICACHE_FLAG;
			if (strncmp(str, "data", sizeof (str)) == 0)
				type_flag |= DCACHE_FLAG;
			total_size += str_size;
		}

		switch (type_flag) {
		case 1:
			(void) snprintf(tlb_str, sizeof (tlb_str),
			    "itlb");
			break;
		case 2:
			(void) snprintf(tlb_str, sizeof (tlb_str),
			    "dtlb");
			break;
		default:
			(void) snprintf(tlb_str, sizeof (tlb_str),
			    "Not a known cache type");
		}

		if (!(md_get_prop_val(mdp, tlblistp[i], "entries",
		    &int_value))) {
			(void) snprintf(property, sizeof (property),
			    "%s-entries", tlb_str);
			add_md_prop(node, sizeof (int_value), property,
			    &int_value, PICL_PTYPE_INT);
		}
	}
}

static void
add_cache_props(picl_nodehdl_t node, mde_cookie_t *cachelistp, int ncaches)
{
	int i;
	uint64_t int_value;
	uint8_t *type;
	char str[MAXSTRLEN];
	char property[MAXSTRLEN];
	char cache_str[MAXSTRLEN];
	int type_size, str_size, total_size, type_flag;

	for (i = 0; i < ncaches; i++) {
		if (md_get_prop_data(mdp, cachelistp[i], "type", &type,
		    &type_size)) {
			return;
		}

		if (md_get_prop_val(mdp, cachelistp[i], "level", &int_value)) {
			return;
		}

		total_size = type_flag = 0;

		while (total_size < type_size) {
			str_size = strlen((char *)type + total_size) + 1;
			(void) strncpy(str, (char *)type + total_size,
			    sizeof (str));
			if (strncmp(str, "instn", sizeof (str)) == 0)
				type_flag |= ICACHE_FLAG;
			if (strncmp(str, "data", sizeof (str)) == 0)
				type_flag |= DCACHE_FLAG;
			total_size += str_size;
		}

		switch (type_flag) {
		case 1:
			(void) snprintf(cache_str, sizeof (cache_str),
			    "l%d-icache", (int)int_value);
			break;
		case 2:
			(void) snprintf(cache_str, sizeof (cache_str),
			    "l%d-dcache", (int)int_value);
			break;
		case 3:
			(void) snprintf(cache_str, sizeof (cache_str),
			    "l%d-cache", (int)int_value);
			break;
		default:
			(void) snprintf(cache_str, sizeof (cache_str),
			    "Not a known cache type");
		}

		if (!(md_get_prop_val(mdp, cachelistp[i], "associativity",
		    &int_value))) {
			(void) snprintf(property, sizeof (property),
			    "%s-associativity", cache_str);
			add_md_prop(node, sizeof (int_value), property,
			    &int_value, PICL_PTYPE_INT);
		}

		if (!(md_get_prop_val(mdp, cachelistp[i], "size",
		    &int_value))) {
			(void) snprintf(property, sizeof (property), "%s-size",
			    cache_str);
			add_md_prop(node, sizeof (int_value), property,
			    &int_value, PICL_PTYPE_INT);
		}

		if (!(md_get_prop_val(mdp, cachelistp[i], "line-size",
		    &int_value))) {
			(void) snprintf(property, sizeof (property),
			    "%s-line-size", cache_str);
			add_md_prop(node, sizeof (int_value), property,
			    &int_value, PICL_PTYPE_INT);
		}
	}
}

int
add_cpu_prop(picl_nodehdl_t node, void *args)
{
	mde_cookie_t *cpulistp;
	mde_cookie_t *cachelistp;
	mde_cookie_t *tlblistp;
	int x, num_nodes;
	int ncpus, ncaches, ntlbs;
	int status;
	int reg_prop[SUN4V_CPU_REGSIZE], cpuid;
	uint64_t int64_value;
	int int_value;

	status = ptree_get_propval_by_name(node, OBP_REG, reg_prop,
	    sizeof (reg_prop));
	if (status != PICL_SUCCESS) {
		return (PICL_WALK_TERMINATE);
	}

	cpuid = CFGHDL_TO_CPUID(reg_prop[0]);

	/*
	 * Allocate space for our searches.
	 */

	num_nodes = md_node_count(mdp);

	cpulistp = (mde_cookie_t *) alloca(sizeof (mde_cookie_t) *num_nodes);
	if (cpulistp == NULL) {
		return (PICL_WALK_TERMINATE);
	}

	cachelistp = (mde_cookie_t *) alloca(sizeof (mde_cookie_t) *num_nodes);
	if (cachelistp == NULL) {
		return (PICL_WALK_TERMINATE);
	}

	tlblistp = (mde_cookie_t *) alloca(sizeof (mde_cookie_t) *num_nodes);
	if (tlblistp == NULL) {
		return (PICL_WALK_TERMINATE);
	}

	/*
	 * Starting at the root node, scan the "fwd" dag for
	 * all the cpus in this description.
	 */

	ncpus = md_scan_dag(mdp, rootnode, md_find_name(mdp, "cpu"),
	    md_find_name(mdp, "fwd"), cpulistp);

	if (ncpus < 0) {
		return (PICL_WALK_TERMINATE);
	}

	/*
	 * Create PD cpus with a few select properties
	 */

	for (x = 0; x < ncpus; x++) {
		if (md_get_prop_val(mdp, cpulistp[x], "id", &int64_value)) {
			continue;
		}

		if (int64_value != cpuid)
			continue;

		int_value = (int)(int64_value & INT32_MAX);

		add_md_prop(node, sizeof (int_value), OBP_PROP_CPUID,
		    &int_value, PICL_PTYPE_INT);

		add_md_prop(node, sizeof (int_value), OBP_PROP_PORTID,
		    &int_value, PICL_PTYPE_INT);

		/* get caches for CPU */
		ncaches = md_scan_dag(mdp, cpulistp[x],
		    md_find_name(mdp, "cache"),
		    md_find_name(mdp, "fwd"),
		    cachelistp);

		add_cache_props(node, cachelistp, ncaches);

		/* get tlbs for CPU */
		ntlbs = md_scan_dag(mdp, cpulistp[x],
		    md_find_name(mdp, "tlb"),
		    md_find_name(mdp, "fwd"),
		    tlblistp);

		add_tlb_props(node, tlblistp, ntlbs);
	}

	return (PICL_WALK_CONTINUE);
}
