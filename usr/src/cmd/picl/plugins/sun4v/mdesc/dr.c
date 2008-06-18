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

#include "mdescplugin.h"

static	di_prom_handle_t	ph = DI_PROM_HANDLE_NIL;

typedef struct cpu_lookup {
	di_node_t di_node;
	picl_nodehdl_t nodeh;
	int result;
} cpu_lookup_t;

extern int add_cpu_prop(picl_nodehdl_t node, void *args);
extern md_t *mdesc_devinit(void);

/*
 * This function is identical to the one in the picldevtree plugin.
 * Unfortunately we can't just reuse that code.
 */
int
add_string_list_prop(picl_nodehdl_t nodeh, char *name, char *strlist,
    unsigned int nrows)
{
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;
	picl_prophdl_t		tblh;
	int			err;
	unsigned int		i;
	unsigned int		j;
	picl_prophdl_t		*proprow;
	int			len;

#define	NCOLS_IN_STRING_TABLE	1

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_TABLE, PICL_READ, sizeof (picl_prophdl_t), name,
	    NULL, NULL);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_table(&tblh);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_and_add_prop(nodeh, &propinfo, &tblh, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	proprow = alloca(sizeof (picl_prophdl_t) * nrows);
	if (proprow == NULL) {
		(void) ptree_destroy_prop(proph);
		return (PICL_FAILURE);
	}

	for (j = 0; j < nrows; ++j) {
		len = strlen(strlist) + 1;
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ, len, name,
		    NULL, NULL);
		if (err != PICL_SUCCESS)
			break;
		err = ptree_create_prop(&propinfo, strlist, &proprow[j]);
		if (err != PICL_SUCCESS)
			break;
		strlist += len;
		err = ptree_add_row_to_table(tblh, NCOLS_IN_STRING_TABLE,
		    &proprow[j]);
		if (err != PICL_SUCCESS)
			break;
	}

	if (err != PICL_SUCCESS) {
		for (i = 0; i < j; ++i)
			(void) ptree_destroy_prop(proprow[i]);
		(void) ptree_delete_prop(proph);
		(void) ptree_destroy_prop(proph);
		return (err);
	}

	return (PICL_SUCCESS);
}

/*
 * This function is identical to the one in the picldevtree plugin.
 * Unfortunately we can't just reuse that code.
 */
static void
add_devinfo_props(picl_nodehdl_t nodeh, di_node_t di_node)
{
	int			instance;
	char			*di_val;
	di_prop_t		di_prop;
	int			di_ptype;
	ptree_propinfo_t	propinfo;

	instance = di_instance(di_node);
	(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_INT, PICL_READ, sizeof (instance), PICL_PROP_INSTANCE,
	    NULL, NULL);
	(void) ptree_create_and_add_prop(nodeh, &propinfo, &instance, NULL);

	di_val = di_bus_addr(di_node);
	if (di_val) {
		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(di_val) + 1,
		    PICL_PROP_BUS_ADDR, NULL, NULL);
		(void) ptree_create_and_add_prop(nodeh, &propinfo, di_val,
		    NULL);
	}

	di_val = di_binding_name(di_node);
	if (di_val) {
		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(di_val) + 1,
		    PICL_PROP_BINDING_NAME, NULL, NULL);
		(void) ptree_create_and_add_prop(nodeh, &propinfo, di_val,
		    NULL);
	}

	di_val = di_driver_name(di_node);
	if (di_val) {
		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(di_val) + 1,
		    PICL_PROP_DRIVER_NAME, NULL, NULL);
		(void) ptree_create_and_add_prop(nodeh, &propinfo, di_val,
		    NULL);
	}

	di_val = di_devfs_path(di_node);
	if (di_val) {
		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(di_val) + 1,
		    PICL_PROP_DEVFS_PATH, NULL, NULL);
		(void) ptree_create_and_add_prop(nodeh, &propinfo, di_val,
		    NULL);
		di_devfs_path_free(di_val);
	}

	for (di_prop = di_prop_next(di_node, DI_PROP_NIL);
	    di_prop != DI_PROP_NIL;
	    di_prop = di_prop_next(di_node, di_prop)) {

		di_val = di_prop_name(di_prop);
		di_ptype = di_prop_type(di_prop);
		switch (di_ptype) {
		case DI_PROP_TYPE_BOOLEAN:
			(void) ptree_init_propinfo(&propinfo,
			    PTREE_PROPINFO_VERSION, PICL_PTYPE_VOID,
			    PICL_READ, (size_t)0, di_val, NULL, NULL);
			(void) ptree_create_and_add_prop(nodeh, &propinfo,
			    NULL, NULL);
			break;
		case DI_PROP_TYPE_INT: {
			int	*idata;
			int	len;

			len = di_prop_ints(di_prop, &idata);
			if (len < 0)
				/* Recieved error, so ignore prop */
				break;

			if (len == 1)
				(void) ptree_init_propinfo(&propinfo,
				    PTREE_PROPINFO_VERSION, PICL_PTYPE_INT,
				    PICL_READ, len * sizeof (int), di_val,
				    NULL, NULL);
			else
				(void) ptree_init_propinfo(&propinfo,
				    PTREE_PROPINFO_VERSION,
				    PICL_PTYPE_BYTEARRAY, PICL_READ,
				    len * sizeof (int), di_val,
				    NULL, NULL);

			(void) ptree_create_and_add_prop(nodeh, &propinfo,
			    idata, NULL);
		}
		break;
		case DI_PROP_TYPE_STRING: {
			char	*sdata;
			int	len;

			len = di_prop_strings(di_prop, &sdata);
			if (len < 0)
				break;

			if (len == 1) {
				(void) ptree_init_propinfo(&propinfo,
				    PTREE_PROPINFO_VERSION,
				    PICL_PTYPE_CHARSTRING, PICL_READ,
				    strlen(sdata) + 1, di_val,
				    NULL, NULL);
				(void) ptree_create_and_add_prop(nodeh,
				    &propinfo, sdata, NULL);
			} else {
				(void) add_string_list_prop(nodeh, di_val,
				    sdata, len);
			}
		}
		break;
		case DI_PROP_TYPE_BYTE: {
			int		len;
			unsigned char *bdata;

			len = di_prop_bytes(di_prop, &bdata);
			if (len < 0)
				break;
			(void) ptree_init_propinfo(&propinfo,
			    PTREE_PROPINFO_VERSION, PICL_PTYPE_BYTEARRAY,
			    PICL_READ, len, di_val, NULL, NULL);
			(void) ptree_create_and_add_prop(nodeh, &propinfo,
			    bdata, NULL);
		}
		break;
		case DI_PROP_TYPE_UNKNOWN:
			break;
		case DI_PROP_TYPE_UNDEF_IT:
			break;
		default:
			break;
		}
	}
}

/*
 * add OBP_REG property to picl cpu node if it's not already there.
 */
static void
add_reg_prop(picl_nodehdl_t pn, di_node_t dn)
{
	int 			reg_prop[SUN4V_CPU_REGSIZE];
	int 			status;
	int 			dlen;
	int			*pdata;
	ptree_propinfo_t	propinfo;

	status = ptree_get_propval_by_name(pn, OBP_REG, reg_prop,
	    sizeof (reg_prop));
	if (status == PICL_SUCCESS) {
		return;
	}
	dlen = di_prom_prop_lookup_ints(ph, dn, OBP_REG, &pdata);
	if (dlen < 0) {
		return;
	}
	status = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_BYTEARRAY, PICL_READ, dlen * sizeof (int), OBP_REG,
	    NULL, NULL);
	if (status != PICL_SUCCESS) {
		return;
	}
	(void) ptree_create_and_add_prop(pn, &propinfo, pdata, NULL);
}

/*
 * Create a  picl node of type cpu and fill it.
 * properties are filled from both the device tree and the
 * Machine description.
 */
static int
construct_cpu_node(picl_nodehdl_t plath, di_node_t dn)
{
	int		err;
	char		*nodename;
	picl_nodehdl_t	anodeh;

	nodename = di_node_name(dn);	/* PICL_PROP_NAME */

	err = ptree_create_and_add_node(plath, nodename, PICL_CLASS_CPU,
	    &anodeh);
	if (err != PICL_SUCCESS)
		return (err);

	add_devinfo_props(anodeh, dn);
	add_reg_prop(anodeh, dn);
	(void) add_cpu_prop(anodeh, NULL);

	return (err);
}

/*
 * Given a devinfo node find its reg property.
 */
static int
get_reg_prop(di_node_t dn, int **pdata)
{
	int dret = 0;

	dret = di_prop_lookup_ints(DDI_DEV_T_ANY, dn, OBP_REG, pdata);
	if (dret > 0)
		return (dret);

	if (!ph)
		return (0);
	dret = di_prom_prop_lookup_ints(ph, dn, OBP_REG, pdata);
	return (dret < 0? 0 : dret);
}

/*
 * Given a devinfo cpu node find its cpuid property.
 */
int
get_cpuid(di_node_t di_node)
{
	int	len;
	int	*idata;
	int	dcpuid = -1;

	len = get_reg_prop(di_node, &idata);

	if (len != SUN4V_CPU_REGSIZE)
		return (dcpuid);
	if (len == SUN4V_CPU_REGSIZE)
		dcpuid = CFGHDL_TO_CPUID(idata[0]);

	return (dcpuid);
}

int
find_cpu(di_node_t node, int cpuid)
{
	int	dcpuid;
	di_node_t cnode;
	char	*nodename;

	for (cnode = di_child_node(node); cnode != DI_NODE_NIL;
	    cnode = di_sibling_node(cnode)) {
		nodename = di_node_name(cnode);
		if (nodename == NULL)
			continue;
		if (strcmp(nodename, OBP_CPU) == 0) {
			dcpuid = get_cpuid(cnode);
			if (dcpuid == cpuid) {
				return (1);
			}
		}
	}
	return (0);
}

/*
 * Callback to the ptree walk function during remove_cpus.
 * As a part of the args receives a picl nodeh, searches
 * the device tree for a cpu whose cpuid matches the picl cpu node.
 * Sets arg struct's result to 1 if it failed to match and terminates
 * the walk.
 */
static int
remove_cpu_candidate(picl_nodehdl_t nodeh, void *c_args)
{
	di_node_t	di_node;
	cpu_lookup_t	*cpu_arg;
	int	err;
	int	pcpuid;
	int reg_prop[SUN4V_CPU_REGSIZE];

	if (c_args == NULL)
		return (PICL_INVALIDARG);

	cpu_arg = c_args;
	di_node = cpu_arg->di_node;

	err = ptree_get_propval_by_name(nodeh, OBP_REG, reg_prop,
	    sizeof (reg_prop));

	if (err != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	pcpuid = CFGHDL_TO_CPUID(reg_prop[0]);

	if (!find_cpu(di_node, pcpuid)) {
		cpu_arg->result = 1;
		cpu_arg->nodeh = nodeh;
		return (PICL_WALK_TERMINATE);
	}

	cpu_arg->result = 0;
	return (PICL_WALK_CONTINUE);
}

/*
 * Given the start node of the device tree.
 * find all cpus in the picl tree that don't have
 * device tree counterparts and remove them.
 */
static void
remove_cpus(di_node_t di_start)
{
	int		err;
	picl_nodehdl_t	plath;
	cpu_lookup_t	cpu_arg;

	err = ptree_get_node_by_path(PLATFORM_PATH, &plath);
	if (err != PICL_SUCCESS)
		return;

	do {
		cpu_arg.di_node = di_start;
		cpu_arg.nodeh = 0;
		cpu_arg.result = 0;

		if (ptree_walk_tree_by_class(plath,
		    PICL_CLASS_CPU, &cpu_arg, remove_cpu_candidate)
		    != PICL_SUCCESS)
			return;

		if (cpu_arg.result == 1) {
			err = ptree_delete_node(cpu_arg.nodeh);
			if (err == PICL_SUCCESS)
				ptree_destroy_node(cpu_arg.nodeh);
		}
	} while (cpu_arg.result);
}

/*
 * Callback to the ptree walk function during add_cpus.
 * As a part of the args receives a cpu di_node, compares
 * each picl cpu node's cpuid to the device tree node's cpuid.
 * Sets arg struct's result to 1 on a match.
 */
static int
cpu_exists(picl_nodehdl_t nodeh, void *c_args)
{
	di_node_t	di_node;
	cpu_lookup_t	*cpu_arg;
	int	err;
	int	dcpuid, pcpuid;
	int reg_prop[4];

	if (c_args == NULL)
		return (PICL_INVALIDARG);

	cpu_arg = c_args;
	di_node = cpu_arg->di_node;
	dcpuid = get_cpuid(di_node);

	err = ptree_get_propval_by_name(nodeh, OBP_REG, reg_prop,
	    sizeof (reg_prop));

	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);

	pcpuid = CFGHDL_TO_CPUID(reg_prop[0]);

	if (dcpuid == pcpuid) {
		cpu_arg->result = 1;
		return (PICL_WALK_TERMINATE);
	}

	cpu_arg->result = 0;
	return (PICL_WALK_CONTINUE);
}

/*
 * Given the root node of the device tree.
 * compare it to the picl tree and add to it cpus
 * that are new.
 */
static void
add_cpus(di_node_t di_node)
{
	int		err;
	di_node_t	cnode;
	picl_nodehdl_t	plath;
	cpu_lookup_t	cpu_arg;
	char		*nodename;

	err = ptree_get_node_by_path(PLATFORM_PATH, &plath);
	if (err != PICL_SUCCESS)
		return;

	for (cnode = di_child_node(di_node); cnode != DI_NODE_NIL;
	    cnode = di_sibling_node(cnode)) {
		nodename = di_node_name(cnode);
		if (nodename == NULL)
			continue;
		if (strcmp(nodename, OBP_CPU) == 0) {
			cpu_arg.di_node = cnode;

			if (ptree_walk_tree_by_class(plath,
			    PICL_CLASS_CPU, &cpu_arg, cpu_exists)
			    != PICL_SUCCESS)
				return;

			if (cpu_arg.result == 0)
				/*
				 * Didn't find a matching cpu, add it.
				 */
				(void) construct_cpu_node(plath,
				    cnode);
		}
	}
}

/*
 * Handle DR events. Only supports cpu add and remove.
 */
int
update_devices(char *dev, int op)
{
	di_node_t	di_root;

	if ((di_root = di_init("/", DINFOCPYALL)) == DI_NODE_NIL)
		return (PICL_FAILURE);

	if ((ph = di_prom_init()) == NULL)
		return (PICL_FAILURE);

	if (op == DEV_ADD) {
		if (strcmp(dev, OBP_CPU) == 0)
			add_cpus(di_root);
	}

	if (op == DEV_REMOVE) {
		if (strcmp(dev, OBP_CPU) == 0)
			remove_cpus(di_root);
	}

	di_fini(di_root);
	di_prom_fini(ph);
	return (PICL_SUCCESS);
}
