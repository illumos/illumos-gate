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

/*
 * Enumerate a CPU node
 */
#include <sys/types.h>
#include <strings.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include "pi_impl.h"

#define	_ENUM_NAME	"enum_cpu"

typedef struct cpuwalk_s {
	topo_mod_t	*mod;
	char		*serial;
} cpuwalk_t;

static int pi_enum_cpu_serial(topo_mod_t *, md_t *, mde_cookie_t, char **);
static int pi_enum_cpu_serial_cb(md_t *, mde_cookie_t, mde_cookie_t, void *);

int
pi_enum_cpu(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    topo_instance_t inst, tnode_t *t_parent, const char *hc_name,
    tnode_t **t_node)
{
	int		result;
	int		err;
	int		cpumask;
	nvlist_t	*asru = NULL;
	char		*serial = NULL;

	*t_node = NULL;

	/*
	 * Create the basic topology node for the CPU using the generic
	 * enumerator.
	 */
	result = pi_enum_generic_impl(mod, mdp, mde_node, inst, t_parent,
	    t_parent, hc_name, _ENUM_NAME, t_node, 0);
	if (result != 0) {
		/* Error messages are printed by the generic routine */
		return (result);
	}

	/*
	 * If the hc_name is "chip" or "core", set asru to resource,
	 * otherwise for "cpu" and "strand", set asru to CPU scheme FMRI.
	 */
	if (strcmp(hc_name, CHIP) == 0 || strcmp(hc_name, CORE) == 0) {
		result = topo_node_resource(*t_node, &asru, &err);
		if (result != 0) {
			topo_mod_dprintf(mod,
			    "%s node_0x%llx failed to get resource: %s\n",
			    _ENUM_NAME, (uint64_t)mde_node, topo_strerror(err));
			return (-1);
		}
	} else {
		/*
		 * Compute ASRU for "cpu" and "strand" node.
		 * Get the parameters required to create an FMRI.  The cpumask
		 * is on the chip itself and while it may be part of an ereport
		 * payload is unavailable here, so we set it to zero.
		 */
		cpumask = 0;

		/*
		 * Find the serial number, which is on the "chip" node, not the
		 * "cpu" node.
		 */
		result = pi_enum_cpu_serial(mod, mdp, mde_node, &serial);
		if (result != 0 || serial == NULL) {
			topo_mod_dprintf(mod,
			    "%s node_0x%llx failed to find serial number.\n",
			    _ENUM_NAME, (uint64_t)mde_node);
			return (result);
		}

		/*
		 * Create a CPU scheme FMRI and set it as the ASRU for the CPU
		 * node
		 */
		asru = topo_mod_cpufmri(mod, FM_CPU_SCHEME_VERSION, inst,
		    cpumask, serial);
		topo_mod_strfree(mod, serial);
		if (asru == NULL) {
			topo_mod_dprintf(mod, "%s node_0x%llx failed to "
			    "compute cpu scheme ASRU: %s\n",
			    _ENUM_NAME, (uint64_t)mde_node,
			    topo_strerror(topo_mod_errno(mod)));
			return (-1);
		}
	}

	/* Set the ASRU on the node without flags (the 0) */
	result = topo_node_asru_set(*t_node, asru, 0, &err);
	nvlist_free(asru);
	if (result != 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to set ASRU: %s\n", _ENUM_NAME,
		    (uint64_t)mde_node, topo_strerror(err));
		return (-1);
	}

	return (0);
}


static int
pi_enum_cpu_serial(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    char **serial)
{
	int			result;
	cpuwalk_t		args;
	mde_str_cookie_t	component_cookie;
	mde_str_cookie_t	back_cookie;

	args.mod = mod;
	args.serial = NULL;

	/*
	 * Search backwards through the PRI graph, starting at the current
	 * strand (aka cpu) mde_node, and find the MD_STR_CHIP node.  This
	 * node has the serial number for the cpu.
	 */
	component_cookie = md_find_name(mdp, MD_STR_COMPONENT);
	back_cookie	 = md_find_name(mdp, MD_STR_BACK);

	result = md_walk_dag(mdp, mde_node, component_cookie, back_cookie,
	    pi_enum_cpu_serial_cb, (void *)&args);
	*serial = args.serial;

	return (result);
}


/*ARGSUSED*/
static int
pi_enum_cpu_serial_cb(md_t *mdp, mde_cookie_t mde_parent,
    mde_cookie_t mde_node, void *private)
{
	char		*hc_name;
	cpuwalk_t	*args = (cpuwalk_t *)private;

	if (args == NULL) {
		return (MDE_WALK_ERROR);
	}
	args->serial = NULL;

	hc_name = pi_get_topo_hc_name(args->mod, mdp, mde_node);
	if (hc_name != NULL && strcmp(hc_name, MD_STR_CHIP) == 0) {
		args->serial = pi_get_serial(args->mod, mdp, mde_node);
	}
	topo_mod_strfree(args->mod, hc_name);

	return ((args->serial == NULL ? MDE_WALK_NEXT : MDE_WALK_DONE));
}
