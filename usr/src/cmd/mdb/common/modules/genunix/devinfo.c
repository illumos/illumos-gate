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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddifm.h>
#include <sys/ddipropdefs.h>
#include <sys/modctl.h>
#include <sys/hwconf.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/sunmdi.h>
#include <sys/mdi_impldefs.h>

#include <ctype.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include "nvpair.h"
#include "devinfo.h"

#define	DEVINFO_TREE_INDENT	4	/* Indent for devs one down in tree */
#define	DEVINFO_PROP_INDENT	4	/* Indent for properties */
#define	DEVINFO_PROPLIST_INDENT	8	/* Indent for properties lists */

/*
 * devinfo node state map. Used by devinfo() and devinfo_audit().
 * Long words are deliberately truncated so that output
 * fits in 80 column with 64-bit addresses.
 */
static const char *const di_state[] = {
	"DS_INVAL",
	"DS_PROTO",
	"DS_LINKED",
	"DS_BOUND",
	"DS_INITIA",
	"DS_PROBED",
	"DS_ATTACH",
	"DS_READY",
	"?"
};

#define	DI_STATE_MAX	((sizeof (di_state) / sizeof (char *)) - 1)

void
prtconf_help(void)
{
	mdb_printf("Prints the devinfo tree from a given node.\n"
	    "Without the address of a \"struct devinfo\" given, "
	    "prints from the root;\n"
	    "with an address, prints the parents of, "
	    "and all children of, that address.\n\n"
	    "Switches:\n"
	    "  -v          be verbose - print device property lists\n"
	    "  -p          only print the ancestors of the given node\n"
	    "  -c          only print the children of the given node\n"
	    "  -d driver   only print instances of driver\n");
}

void
devinfo_help(void)
{
	mdb_printf("Switches:\n"
	    "  -q   be quiet - don't print device property lists\n"
	    "  -s   print summary of dev_info structures\n");
}


/*
 * Devinfo walker.
 */

typedef struct {
	/*
	 * The "struct dev_info" must be the first thing in this structure.
	 */
	struct dev_info din_dev;

	/*
	 * This is for the benefit of prtconf().
	 */
	int din_depth;
} devinfo_node_t;

typedef struct devinfo_parents_walk_data {
	devinfo_node_t dip_node;
#define	dip_dev dip_node.din_dev
#define	dip_depth dip_node.din_depth
	struct dev_info *dip_end;

	/*
	 * The following three elements are for walking the parents of a node:
	 * "dip_base_depth" is the depth of the given node from the root.
	 *   This starts at 1 (if we're walking devinfo_root), because
	 *   it's the size of the dip_parent_{nodes,addresses} arrays,
	 *   and has to include the given node.
	 * "dip_parent_nodes" is a collection of the parent node structures,
	 *   already read in via mdb_vread().  dip_parent_nodes[0] is the
	 *   root, dip_parent_nodes[1] is a child of the root, etc.
	 * "dip_parent_addresses" holds the vaddrs of all the parent nodes.
	 */
	int dip_base_depth;
	devinfo_node_t *dip_parent_nodes;
	uintptr_t *dip_parent_addresses;
} devinfo_parents_walk_data_t;

int
devinfo_parents_walk_init(mdb_walk_state_t *wsp)
{
	devinfo_parents_walk_data_t *dip;
	uintptr_t addr;
	uintptr_t devinfo_root;		/* Address of root of devinfo tree */
	int i;

	if (mdb_readvar(&devinfo_root, "top_devinfo") == -1) {
		mdb_warn("failed to read 'top_devinfo'");
		return (NULL);
	}

	if (wsp->walk_addr == NULL)
		wsp->walk_addr = devinfo_root;
	addr = wsp->walk_addr;

	dip = mdb_alloc(sizeof (devinfo_parents_walk_data_t), UM_SLEEP);
	wsp->walk_data = dip;

	dip->dip_end = (struct dev_info *)wsp->walk_addr;
	dip->dip_depth = 0;
	dip->dip_base_depth = 1;

	do {
		if (mdb_vread(&dip->dip_dev, sizeof (dip->dip_dev),
		    addr) == -1) {
			mdb_warn("failed to read devinfo at %p", addr);
			mdb_free(dip, sizeof (devinfo_parents_walk_data_t));
			wsp->walk_data = NULL;
			return (WALK_ERR);
		}
		addr = (uintptr_t)dip->dip_dev.devi_parent;
		if (addr != 0)
			dip->dip_base_depth++;
	} while (addr != 0);

	addr = wsp->walk_addr;

	dip->dip_parent_nodes = mdb_alloc(
	    dip->dip_base_depth * sizeof (devinfo_node_t), UM_SLEEP);
	dip->dip_parent_addresses = mdb_alloc(
	    dip->dip_base_depth * sizeof (uintptr_t), UM_SLEEP);
	for (i = dip->dip_base_depth - 1; i >= 0; i--) {
		if (mdb_vread(&dip->dip_parent_nodes[i].din_dev,
		    sizeof (struct dev_info), addr) == -1) {
			mdb_warn("failed to read devinfo at %p", addr);
			return (WALK_ERR);
		}
		dip->dip_parent_nodes[i].din_depth = i;
		dip->dip_parent_addresses[i] = addr;
		addr = (uintptr_t)
		    dip->dip_parent_nodes[i].din_dev.devi_parent;
	}

	return (WALK_NEXT);
}

int
devinfo_parents_walk_step(mdb_walk_state_t *wsp)
{
	devinfo_parents_walk_data_t *dip = wsp->walk_data;
	int status;

	if (dip->dip_depth == dip->dip_base_depth)
		return (WALK_DONE);

	status = wsp->walk_callback(
	    dip->dip_parent_addresses[dip->dip_depth],
	    &dip->dip_parent_nodes[dip->dip_depth],
	    wsp->walk_cbdata);

	dip->dip_depth++;
	return (status);
}

void
devinfo_parents_walk_fini(mdb_walk_state_t *wsp)
{
	devinfo_parents_walk_data_t *dip = wsp->walk_data;

	mdb_free(dip->dip_parent_nodes,
	    dip->dip_base_depth * sizeof (devinfo_node_t));
	mdb_free(dip->dip_parent_addresses,
	    dip->dip_base_depth * sizeof (uintptr_t));
	mdb_free(wsp->walk_data, sizeof (devinfo_parents_walk_data_t));
}


typedef struct devinfo_children_walk_data {
	devinfo_node_t dic_node;
#define	dic_dev dic_node.din_dev
#define	dic_depth dic_node.din_depth
	struct dev_info *dic_end;
	int dic_print_first_node;
} devinfo_children_walk_data_t;

int
devinfo_children_walk_init(mdb_walk_state_t *wsp)
{
	devinfo_children_walk_data_t *dic;
	uintptr_t devinfo_root;		/* Address of root of devinfo tree */

	if (mdb_readvar(&devinfo_root, "top_devinfo") == -1) {
		mdb_warn("failed to read 'top_devinfo'");
		return (NULL);
	}

	if (wsp->walk_addr == NULL)
		wsp->walk_addr = devinfo_root;

	dic = mdb_alloc(sizeof (devinfo_children_walk_data_t), UM_SLEEP);
	wsp->walk_data = dic;
	dic->dic_end = (struct dev_info *)wsp->walk_addr;

	/*
	 * This could be set by devinfo_walk_init().
	 */
	if (wsp->walk_arg != NULL) {
		dic->dic_depth = (*(int *)wsp->walk_arg - 1);
		dic->dic_print_first_node = 0;
	} else {
		dic->dic_depth = 0;
		dic->dic_print_first_node = 1;
	}

	return (WALK_NEXT);
}

int
devinfo_children_walk_step(mdb_walk_state_t *wsp)
{
	devinfo_children_walk_data_t *dic = wsp->walk_data;
	struct dev_info *v;
	devinfo_node_t *cur;
	uintptr_t addr = wsp->walk_addr;
	int status = WALK_NEXT;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&dic->dic_dev, sizeof (dic->dic_dev), addr) == -1) {
		mdb_warn("failed to read devinfo at %p", addr);
		return (WALK_DONE);
	}
	cur = &dic->dic_node;

	if (dic->dic_print_first_node == 0)
		dic->dic_print_first_node = 1;
	else
		status = wsp->walk_callback(addr, cur, wsp->walk_cbdata);

	/*
	 * "v" is always a virtual address pointer,
	 *  i.e. can't be deref'ed.
	 */
	v = (struct dev_info *)addr;

	if (dic->dic_dev.devi_child != NULL) {
		v = dic->dic_dev.devi_child;
		dic->dic_depth++;
	} else if (dic->dic_dev.devi_sibling != NULL && v != dic->dic_end) {
		v = dic->dic_dev.devi_sibling;
	} else {
		while (v != NULL && v != dic->dic_end &&
		    dic->dic_dev.devi_sibling == NULL) {
			v = dic->dic_dev.devi_parent;
			if (v == NULL)
				break;

			mdb_vread(&dic->dic_dev,
			    sizeof (struct dev_info), (uintptr_t)v);
			dic->dic_depth--;
		}
		if (v != NULL && v != dic->dic_end)
			v = dic->dic_dev.devi_sibling;
		if (v == dic->dic_end)
			v = NULL;	/* Done */
	}

	wsp->walk_addr = (uintptr_t)v;
	return (status);
}

void
devinfo_children_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (devinfo_children_walk_data_t));
}

typedef struct devinfo_walk_data {
	mdb_walk_state_t diw_parent, diw_child;
	enum { DIW_PARENT, DIW_CHILD, DIW_DONE } diw_mode;
} devinfo_walk_data_t;

int
devinfo_walk_init(mdb_walk_state_t *wsp)
{
	devinfo_walk_data_t *diw;
	devinfo_parents_walk_data_t *dip;

	diw = mdb_alloc(sizeof (devinfo_walk_data_t), UM_SLEEP);
	diw->diw_parent = *wsp;
	diw->diw_child = *wsp;
	wsp->walk_data = diw;

	diw->diw_mode = DIW_PARENT;

	if (devinfo_parents_walk_init(&diw->diw_parent) == -1) {
		mdb_free(diw, sizeof (devinfo_walk_data_t));
		return (WALK_ERR);
	}

	/*
	 * This is why the "devinfo" walker needs to be marginally
	 * complicated - the child walker needs this initialization
	 * data, and the best way to get it is out of the parent walker.
	 */
	dip = diw->diw_parent.walk_data;
	diw->diw_child.walk_arg = &dip->dip_base_depth;

	if (devinfo_children_walk_init(&diw->diw_child) == -1) {
		devinfo_parents_walk_fini(&diw->diw_parent);
		mdb_free(diw, sizeof (devinfo_walk_data_t));
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
devinfo_walk_step(mdb_walk_state_t *wsp)
{
	devinfo_walk_data_t *diw = wsp->walk_data;
	int status = WALK_NEXT;

	if (diw->diw_mode == DIW_PARENT) {
		status = devinfo_parents_walk_step(&diw->diw_parent);
		if (status != WALK_NEXT) {
			/*
			 * Keep on going even if the parents walk hit an error.
			 */
			diw->diw_mode = DIW_CHILD;
			status = WALK_NEXT;
		}
	} else if (diw->diw_mode == DIW_CHILD) {
		status = devinfo_children_walk_step(&diw->diw_child);
		if (status != WALK_NEXT) {
			diw->diw_mode = DIW_DONE;
			status = WALK_DONE;
		}
	} else
		status = WALK_DONE;

	return (status);
}

void
devinfo_walk_fini(mdb_walk_state_t *wsp)
{
	devinfo_walk_data_t *diw = wsp->walk_data;

	devinfo_children_walk_fini(&diw->diw_child);
	devinfo_parents_walk_fini(&diw->diw_parent);
	mdb_free(diw, sizeof (devinfo_walk_data_t));
}

/*
 * Given a devinfo pointer, figure out which driver is associated
 * with the node (by driver name, from the devnames array).
 */
/*ARGSUSED*/
int
devinfo2driver(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char dname[MODMAXNAMELEN + 1];
	struct dev_info devi;


	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&devi, sizeof (devi), addr) == -1) {
		mdb_warn("failed to read devinfo struct at %p", addr);
		return (DCMD_ERR);
	}

	if (devi.devi_node_state < DS_ATTACHED) {
		/* No driver attached to this devinfo - nothing to do. */
		mdb_warn("%p: No driver attached to this devinfo node\n", addr);
		return (DCMD_ERR);
	}

	if (mdb_devinfo2driver(addr, dname, sizeof (dname)) != 0) {
		mdb_warn("failed to determine driver name");
		return (DCMD_ERR);
	}

	mdb_printf("Driver '%s' is associated with devinfo %p.\n", dname, addr);

	return (DCMD_OK);
}


typedef struct devnames_walk {
	struct devnames *dnw_names;
	int dnw_ndx;
	int dnw_devcnt;
	uintptr_t dnw_base;
	uintptr_t dnw_size;
} devnames_walk_t;

int
devnames_walk_init(mdb_walk_state_t *wsp)
{
	devnames_walk_t *dnw;
	int devcnt;
	uintptr_t devnamesp;

	if (wsp->walk_addr != NULL) {
		mdb_warn("devnames walker only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_readvar(&devcnt, "devcnt") == -1) {
		mdb_warn("failed to read 'devcnt'");
		return (WALK_ERR);
	}

	if (mdb_readvar(&devnamesp, "devnamesp") == -1) {
		mdb_warn("failed to read 'devnamesp'");
		return (WALK_ERR);
	}

	dnw = mdb_zalloc(sizeof (devnames_walk_t), UM_SLEEP);
	dnw->dnw_size = sizeof (struct devnames) * devcnt;
	dnw->dnw_devcnt = devcnt;
	dnw->dnw_base = devnamesp;
	dnw->dnw_names = mdb_alloc(dnw->dnw_size, UM_SLEEP);

	if (mdb_vread(dnw->dnw_names, dnw->dnw_size, dnw->dnw_base) == -1) {
		mdb_warn("couldn't read devnames array at %p", devnamesp);
		return (WALK_ERR);
	}

	wsp->walk_data = dnw;
	return (WALK_NEXT);
}

int
devnames_walk_step(mdb_walk_state_t *wsp)
{
	devnames_walk_t *dnw = wsp->walk_data;
	int status;

	if (dnw->dnw_ndx == dnw->dnw_devcnt)
		return (WALK_DONE);

	status = wsp->walk_callback(dnw->dnw_ndx * sizeof (struct devnames) +
	    dnw->dnw_base, &dnw->dnw_names[dnw->dnw_ndx], wsp->walk_cbdata);

	dnw->dnw_ndx++;
	return (status);
}

void
devnames_walk_fini(mdb_walk_state_t *wsp)
{
	devnames_walk_t *dnw = wsp->walk_data;

	mdb_free(dnw->dnw_names, dnw->dnw_size);
	mdb_free(dnw, sizeof (devnames_walk_t));
}

int
devinfo_siblings_walk_init(mdb_walk_state_t *wsp)
{
	struct dev_info di;
	uintptr_t addr = wsp->walk_addr;

	if (addr == NULL) {
		mdb_warn("a dev_info struct address must be provided\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&di, sizeof (di), addr) == -1) {
		mdb_warn("failed to read dev_info struct at %p", addr);
		return (WALK_ERR);
	}

	if (di.devi_parent == NULL) {
		mdb_warn("no parent for devinfo at %p", addr);
		return (WALK_DONE);
	}

	if (mdb_vread(&di, sizeof (di), (uintptr_t)di.devi_parent) == -1) {
		mdb_warn("failed to read parent dev_info struct at %p",
		    (uintptr_t)di.devi_parent);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)di.devi_child;
	return (WALK_NEXT);
}

int
devinfo_siblings_walk_step(mdb_walk_state_t *wsp)
{
	struct dev_info di;
	uintptr_t addr = wsp->walk_addr;

	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&di, sizeof (di), addr) == -1) {
		mdb_warn("failed to read dev_info struct at %p", addr);
		return (WALK_DONE);
	}

	wsp->walk_addr = (uintptr_t)di.devi_sibling;
	return (wsp->walk_callback(addr, &di, wsp->walk_cbdata));
}

int
devi_next_walk_step(mdb_walk_state_t *wsp)
{
	struct dev_info di;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&di, sizeof (di), wsp->walk_addr) == -1)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, &di, wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)di.devi_next;
	return (status);
}

/*
 * Helper functions.
 */

static int
is_printable_string(unsigned char *prop_value)
{
	while (*prop_value != 0)
		if (!isprint(*prop_value++))
			return (0);
	return (1);
}

static void
devinfo_print_props_type(int type)
{
	char *type_str = NULL;

	switch (type) {
	case DDI_PROP_TYPE_ANY:
		type_str = "any";
		break;
	case DDI_PROP_TYPE_COMPOSITE:
		type_str = "composite";
		break;
	case DDI_PROP_TYPE_INT64:
		type_str = "int64";
		break;
	case DDI_PROP_TYPE_INT:
		type_str = "int";
		break;
	case DDI_PROP_TYPE_BYTE:
		type_str = "byte";
		break;
	case DDI_PROP_TYPE_STRING:
		type_str = "string";
		break;
	}

	if (type_str != NULL)
		mdb_printf("type=%s", type_str);
	else
		mdb_printf("type=0x%x", type);
}

static void
devinfo_print_props_value(int elem_size, int nelem,
    unsigned char *prop_value, int prop_value_len)
{
	int i;

	mdb_printf("value=");

	if (elem_size == 0) {
		/* if elem_size == 0, then we are printing out string(s) */
		char *p = (char *)prop_value;

		for (i = 0; i < nelem - 1; i++) {
			mdb_printf("'%s' + ", p);
			p += strlen(p) + 1;
		}
		mdb_printf("'%s'", p);
	} else {
		/*
		 * if elem_size != 0 then we are printing out an array
		 * where each element is of elem_size
		 */
		mdb_nhconvert(prop_value, prop_value, elem_size);
		mdb_printf("%02x", *prop_value);
		for (i = 1; i < prop_value_len; i++) {
			if ((i % elem_size) == 0) {
				mdb_nhconvert(&prop_value[i],
				    &prop_value[i], elem_size);
				mdb_printf(".");
			}

			mdb_printf("%02x", prop_value[i]);
		}
	}
}

/*
 * devinfo_print_props_guess()
 * Guesses how to interpret the value of the property
 *
 * Params:
 * 	type      - Should be the type value of the property
 * 	prop_val  - Pointer to the property value data buffer
 * 	prop_len  - Length of the property value data buffer
 *
 * Return values:
 * 	nelem     - The number of elements stored in the property value
 * 			data buffer pointed to by prop_val.
 * 	elem_size - The size (in bytes) of the elements stored in the property
 * 			value data buffer pointed to by prop_val.
 * 			Upon return if elem_size == 0 and nelem != 0 then
 * 			the property value data buffer contains strings
 * 	len_err   - There was an error with the length of the data buffer.
 * 			Its size is not a multiple of the array value type.
 * 			It will be interpreted as an array of bytes.
 */
static void
devinfo_print_props_guess(int type, unsigned char *prop_val, int prop_len,
    int *elem_size, int *nelem, int *len_err)
{
	*len_err = 0;
	if (prop_len == NULL) {
		*elem_size = 0;
		*nelem = 0;
		return;
	}

	/* by default, assume an array of bytes */
	*elem_size = 1;
	*nelem = prop_len;

	switch (type) {
	case DDI_PROP_TYPE_BYTE:
		/* default case, that was easy */
		break;
	case DDI_PROP_TYPE_INT64:
		if ((prop_len % sizeof (int64_t)) == 0) {
			*elem_size = sizeof (int64_t);
			*nelem = prop_len / *elem_size;
		} else {
			/* array is not a multiple of type size, error */
			*len_err = 1;
		}
		break;
	case DDI_PROP_TYPE_INT:
		if ((prop_len % sizeof (int)) == 0) {
			*elem_size = sizeof (int);
			*nelem = prop_len / *elem_size;
		} else {
			/* array is not a multiple of type size, error */
			*len_err = 1;
		}
		break;
	case DDI_PROP_TYPE_STRING:
	case DDI_PROP_TYPE_COMPOSITE:
	case DDI_PROP_TYPE_ANY:
	default:
		/*
		 * if we made it here the type is either unknown
		 * or a string.  Try to interpret is as a string
		 * and if that fails assume an array of bytes.
		 */
		if (prop_val[prop_len - 1] == '\0') {
			unsigned char	*s = prop_val;
			int		i;

			/* assume an array of strings */
			*elem_size = 0;
			*nelem = 0;

			for (i = 0; i < prop_len; i++) {
				if (prop_val[i] != '\0')
					continue;

				/*
				 * If the property is typed as a string
				 * property, then interpret empty strings
				 * as strings. Otherwise default to an
				 * array of bytes. If there are unprintable
				 * characters, always default to an array of
				 * bytes.
				 */
				if ((*s == '\0' && type !=
				    DDI_PROP_TYPE_STRING) ||
				    !is_printable_string(s)) {
					*elem_size = 1;
					*nelem = prop_len;
					break;
				}

				(*nelem)++;
				s = &prop_val[i + 1];
			}
		}
		break;
	}
}

static void
devinfo_print_props(char *name, ddi_prop_t *p)
{
	if (p == NULL)
		return;

	if (name != NULL)
		mdb_printf("%s ", name);

	mdb_printf("properties at %p:\n", p);
	mdb_inc_indent(DEVINFO_PROP_INDENT);

	while (p != NULL) {
		ddi_prop_t	prop;
		char		prop_name[128];
		unsigned char	*prop_value;
		int		type, elem_size, nelem, prop_len_error;

		/* read in the property struct */
		if (mdb_vread(&prop, sizeof (prop), (uintptr_t)p) == -1) {
			mdb_warn("could not read property at 0x%p", p);
			break;
		}

		/* print the property name */
		if (mdb_readstr(prop_name, sizeof (prop_name),
		    (uintptr_t)prop.prop_name) == -1) {
			mdb_warn("could not read property name at 0x%p",
			    prop.prop_name);
			goto next;
		}
		mdb_printf("name='%s' ", prop_name);

		/* get the property type and print it out */
		type = (prop.prop_flags & DDI_PROP_TYPE_MASK);
		devinfo_print_props_type(type);

		/* get the property value */
		if (prop.prop_len > 0) {
			prop_value = mdb_alloc(prop.prop_len, UM_SLEEP|UM_GC);
			if (mdb_vread(prop_value, prop.prop_len,
			    (uintptr_t)prop.prop_val) == -1) {
				mdb_warn("could not read property value at "
				    "0x%p", prop.prop_val);
				goto next;
			}
		} else {
			prop_value = NULL;
		}

		/* take a guess at interpreting the property value */
		devinfo_print_props_guess(type, prop_value, prop.prop_len,
		    &elem_size, &nelem, &prop_len_error);

		/* print out the number ot items */
		mdb_printf(" items=%d", nelem);

		/* print out any associated device information */
		if (prop.prop_dev != DDI_DEV_T_NONE) {
			mdb_printf(" dev=");
			if (prop.prop_dev == DDI_DEV_T_ANY)
				mdb_printf("any");
			else if (prop.prop_dev == DDI_MAJOR_T_UNKNOWN)
				mdb_printf("unknown");
			else
				mdb_printf("(%u,%u)",
				    getmajor(prop.prop_dev),
				    getminor(prop.prop_dev));
		}

		/* print out the property value */
		if (prop_value != NULL) {
			mdb_printf("\n");
			mdb_inc_indent(DEVINFO_PROP_INDENT);
			if (prop_len_error)
				mdb_printf("NOTE: prop length is not a "
				    "multiple of element size\n");
			devinfo_print_props_value(elem_size, nelem,
			    prop_value, prop.prop_len);
			mdb_dec_indent(DEVINFO_PROP_INDENT);
		}

next:
		mdb_printf("\n");
		p = prop.prop_next;
	}

	mdb_dec_indent(DEVINFO_PROP_INDENT);
}

static void
devinfo_pathinfo_state(mdi_pathinfo_state_t state)
{
	char *type_str = NULL;

	switch (state) {
	case MDI_PATHINFO_STATE_INIT:
		type_str = "init";
		break;
	case MDI_PATHINFO_STATE_ONLINE:
		type_str = "online";
		break;
	case MDI_PATHINFO_STATE_STANDBY:
		type_str = "standby";
		break;
	case MDI_PATHINFO_STATE_FAULT:
		type_str = "fault";
		break;
	case MDI_PATHINFO_STATE_OFFLINE:
		type_str = "offline";
		break;
	}
	if (type_str != NULL)
		mdb_printf("state=%s\n", type_str);
	else
		mdb_printf("state=0x%x\n", state);
}

static void
devinfo_print_pathing(int mdi_component, void *mdi_client)
{
	mdi_client_t		mdi_c;
	struct mdi_pathinfo	*pip;

	/* we only print out multipathing info for client nodes */
	if ((mdi_component & MDI_COMPONENT_CLIENT) == 0)
		return;

	mdb_printf("Client multipath info at: 0x%p\n", mdi_client);
	mdb_inc_indent(DEVINFO_PROP_INDENT);

	/* read in the client multipathing info */
	if (mdb_readstr((void*) &mdi_c, sizeof (mdi_c),
	    (uintptr_t)mdi_client) == -1) {
		mdb_warn("failed to read mdi_client at %p",
		    (uintptr_t)mdi_client);
		goto exit;
	}

	/*
	 * walk through the clients list of pathinfo structures and print
	 * out the properties for each path
	 */
	pip = (struct mdi_pathinfo *)mdi_c.ct_path_head;
	while (pip != NULL) {
		char			binding_name[128];
		struct mdi_pathinfo	pi;
		mdi_phci_t		ph;
		struct dev_info		ph_di;

		/* read in the pathinfo structure */
		if (mdb_vread((void*)&pi, sizeof (pi),
		    (uintptr_t)pip) == -1) {
			mdb_warn("failed to read mdi_pathinfo at %p",
			    (uintptr_t)pip);
			goto exit;
		}

		/* read in the pchi (path host adapter) info */
		if (mdb_vread((void*)&ph, sizeof (ph),
		    (uintptr_t)pi.pi_phci) == -1) {
			mdb_warn("failed to read mdi_pchi at %p",
			    (uintptr_t)pi.pi_phci);
			goto exit;
		}

		/* read in the dip of the phci so we can get it's name */
		if (mdb_vread((void*)&ph_di, sizeof (ph_di),
		    (uintptr_t)ph.ph_dip) == -1) {
			mdb_warn("failed to read mdi_pchi at %p",
			    (uintptr_t)ph.ph_dip);
			goto exit;
		}
		if (mdb_vread(binding_name, sizeof (binding_name),
		    (uintptr_t)ph_di.devi_binding_name) == -1) {
			mdb_warn("failed to read binding_name at %p",
			    (uintptr_t)ph_di.devi_binding_name);
			goto exit;
		}

		mdb_printf("%s#%d, ", binding_name, ph_di.devi_instance);
		devinfo_pathinfo_state(pi.pi_state);

		/* print out the pathing info */
		mdb_inc_indent(DEVINFO_PROP_INDENT);
		if (mdb_pwalk_dcmd(NVPAIR_WALKER_FQNAME, NVPAIR_DCMD_FQNAME,
		    0, NULL, (uintptr_t)pi.pi_prop) != 0) {
			mdb_dec_indent(DEVINFO_PROP_INDENT);
			goto exit;
		}
		mdb_dec_indent(DEVINFO_PROP_INDENT);
		pip = pi.pi_client_link;
	}

exit:
	mdb_dec_indent(DEVINFO_PROP_INDENT);
}

static int
devinfo_print(uintptr_t addr, struct dev_info *dev, devinfo_cb_data_t *data)
{
	/*
	 * We know the walker passes us extra data after the dev_info.
	 */
	char		binding_name[128];
	char		dname[MODMAXNAMELEN + 1];
	devinfo_node_t	*din = (devinfo_node_t *)dev;
	ddi_prop_t	*global_props = NULL;
	boolean_t	hdname = B_FALSE;

	if (mdb_readstr(binding_name, sizeof (binding_name),
	    (uintptr_t)dev->devi_binding_name) == -1) {
		mdb_warn("failed to read binding_name at %p",
		    (uintptr_t)dev->devi_binding_name);
		return (WALK_ERR);
	}

	/* if there are any global properties, get a pointer to them */
	if (dev->devi_global_prop_list != NULL) {
		ddi_prop_list_t	plist;
		if (mdb_vread((void*)&plist, sizeof (plist),
		    (uintptr_t)dev->devi_global_prop_list) == -1) {
			mdb_warn("failed to read global prop_list at %p",
			    (uintptr_t)dev->devi_global_prop_list);
			return (WALK_ERR);
		}
		global_props = plist.prop_list;
	}

	if (dev->devi_node_state > DS_ATTACHED) {
		if (mdb_devinfo2driver(addr, dname, sizeof (dname)) == 0)
			hdname = B_TRUE;
	}

	/*
	 * If a filter is installed and we don't have the driver's name, we
	 * always skip it. Also if the filter doesn't match, then we'll also
	 * skip the driver.
	 */
	if (data->di_filter != NULL &&
	    (!hdname || strcmp(data->di_filter, dname) != 0)) {
		return (WALK_NEXT);
	}

	/*
	 * If we are output to a pipe, we only print the address of the
	 * devinfo_t.
	 */
	if (data->di_flags & DEVINFO_PIPE) {
		mdb_printf("%-0?p\n", addr);
		return (WALK_NEXT);
	}

	mdb_inc_indent(din->din_depth * DEVINFO_TREE_INDENT);
	if ((addr == data->di_base) || (data->di_flags & DEVINFO_ALLBOLD))
		mdb_printf("%<b>");
	mdb_printf("%-0?p %s", addr, binding_name);
	if ((addr == data->di_base) || (data->di_flags & DEVINFO_ALLBOLD))
		mdb_printf("%</b>");
	if (dev->devi_instance >= 0)
		mdb_printf(", instance #%d", dev->devi_instance);

	if (dev->devi_node_state < DS_ATTACHED)
		mdb_printf(" (driver not attached)");
	else if (hdname == B_FALSE)
		mdb_printf(" (could not determine driver name)");
	else
		mdb_printf(" (driver name: %s)", dname);

	mdb_printf("\n");
	if (data->di_flags & DEVINFO_VERBOSE) {
		mdb_inc_indent(DEVINFO_PROPLIST_INDENT);
		devinfo_print_props("System", dev->devi_sys_prop_ptr);
		devinfo_print_props("Driver", dev->devi_drv_prop_ptr);
		devinfo_print_props("Hardware", dev->devi_hw_prop_ptr);
		devinfo_print_props("Global", global_props);

		devinfo_print_pathing(dev->devi_mdi_component,
		    dev->devi_mdi_client);

		mdb_dec_indent(DEVINFO_PROPLIST_INDENT);
	}

	mdb_dec_indent(din->din_depth * DEVINFO_TREE_INDENT);
	return (WALK_NEXT);
}

/*ARGSUSED*/
int
prtconf(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	devinfo_cb_data_t data;
	uintptr_t devinfo_root;		/* Address of root of devinfo tree */
	int status;

	data.di_flags = DEVINFO_PARENT | DEVINFO_CHILD;
	data.di_filter = NULL;

	if (flags & DCMD_PIPE_OUT)
		data.di_flags |= DEVINFO_PIPE;

	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_STR, &data.di_filter,
	    'v', MDB_OPT_SETBITS, DEVINFO_VERBOSE, &data.di_flags,
	    'p', MDB_OPT_CLRBITS, DEVINFO_CHILD, &data.di_flags,
	    'c', MDB_OPT_CLRBITS, DEVINFO_PARENT, &data.di_flags, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_readvar(&devinfo_root, "top_devinfo") == -1) {
		mdb_warn("failed to read 'top_devinfo'");
		return (NULL);
	}

	if ((flags & DCMD_ADDRSPEC) == 0) {
		addr = devinfo_root;
		if (data.di_flags & DEVINFO_VERBOSE)
			data.di_flags |= DEVINFO_ALLBOLD;
	}

	data.di_base = addr;
	if (!(flags & DCMD_PIPE_OUT))
		mdb_printf("%<u>%-?s %-50s%</u>\n", "DEVINFO", "NAME");

	if ((data.di_flags & (DEVINFO_PARENT | DEVINFO_CHILD)) ==
	    (DEVINFO_PARENT | DEVINFO_CHILD)) {
		status = mdb_pwalk("devinfo",
		    (mdb_walk_cb_t)devinfo_print, &data, addr);
	} else if (data.di_flags & DEVINFO_PARENT) {
		status = mdb_pwalk("devinfo_parents",
		    (mdb_walk_cb_t)devinfo_print, &data, addr);
	} else if (data.di_flags & DEVINFO_CHILD) {
		status = mdb_pwalk("devinfo_children",
		    (mdb_walk_cb_t)devinfo_print, &data, addr);
	} else {
		devinfo_node_t din;
		if (mdb_vread(&din.din_dev, sizeof (din.din_dev), addr) == -1) {
			mdb_warn("failed to read device");
			return (DCMD_ERR);
		}
		din.din_depth = 0;
		return (devinfo_print(addr, (struct dev_info *)&din, &data));
	}

	if (status == -1) {
		mdb_warn("couldn't walk devinfo tree");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
int
devinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char tmpstr[MODMAXNAMELEN];
	char nodename[MODMAXNAMELEN];
	char bindname[MAXPATHLEN];
	int size, length;
	struct dev_info devi;
	devinfo_node_t din;
	devinfo_cb_data_t data;

	static const mdb_bitmask_t devi_state_masks[] = {
	    { "DEVICE_OFFLINE",	DEVI_DEVICE_OFFLINE,	DEVI_DEVICE_OFFLINE },
	    { "DEVICE_DOWN",	DEVI_DEVICE_DOWN,	DEVI_DEVICE_DOWN },
	    { "DEVICE_DEGRADED", DEVI_DEVICE_DEGRADED,	DEVI_DEVICE_DEGRADED },
	    { "DEVICE_REMOVED", DEVI_DEVICE_REMOVED,	DEVI_DEVICE_REMOVED },
	    { "BUS_QUIESCED",	DEVI_BUS_QUIESCED,	DEVI_BUS_QUIESCED },
	    { "BUS_DOWN",	DEVI_BUS_DOWN,		DEVI_BUS_DOWN },
	    { "NDI_CONFIG",	DEVI_NDI_CONFIG,	DEVI_NDI_CONFIG	},

	    { "S_ATTACHING",	DEVI_S_ATTACHING,	DEVI_S_ATTACHING },
	    { "S_DETACHING",	DEVI_S_DETACHING,	DEVI_S_DETACHING },
	    { "S_ONLINING",	DEVI_S_ONLINING,	DEVI_S_ONLINING },
	    { "S_OFFLINING",	DEVI_S_OFFLINING,	DEVI_S_OFFLINING },
	    { "S_INVOKING_DACF", DEVI_S_INVOKING_DACF,	DEVI_S_INVOKING_DACF },
	    { "S_UNBOUND",	DEVI_S_UNBOUND,		DEVI_S_UNBOUND },
	    { "S_REPORT",	DEVI_S_REPORT,		DEVI_S_REPORT },
	    { "S_EVADD",	DEVI_S_EVADD,		DEVI_S_EVADD },
	    { "S_EVREMOVE",	DEVI_S_EVREMOVE,	DEVI_S_EVREMOVE },
	    { "S_NEED_RESET",	DEVI_S_NEED_RESET,	DEVI_S_NEED_RESET },
	    { NULL,		0,			0 }
	};

	static const mdb_bitmask_t devi_flags_masks[] = {
	    { "BUSY",		DEVI_BUSY,		DEVI_BUSY },
	    { "MADE_CHILDREN",	DEVI_MADE_CHILDREN,	DEVI_MADE_CHILDREN },
	    { "ATTACHED_CHILDREN",
				DEVI_ATTACHED_CHILDREN,	DEVI_ATTACHED_CHILDREN},
	    { "BRANCH_HELD",	DEVI_BRANCH_HELD,	DEVI_BRANCH_HELD },
	    { "NO_BIND",	DEVI_NO_BIND,		DEVI_NO_BIND },
	    { "DEVI_CACHED_DEVID",
				DEVI_CACHED_DEVID,	DEVI_CACHED_DEVID },
	    { "PHCI_SIGNALS_VHCI",
				DEVI_PHCI_SIGNALS_VHCI,
				DEVI_PHCI_SIGNALS_VHCI },
	    { "REBIND",		DEVI_REBIND,		DEVI_REBIND },
	    { NULL,		0,			0 }
	};

	data.di_flags = DEVINFO_VERBOSE;
	data.di_base = addr;
	data.di_filter = NULL;

	if (mdb_getopts(argc, argv,
	    'q', MDB_OPT_CLRBITS, DEVINFO_VERBOSE, &data.di_flags,
	    's', MDB_OPT_SETBITS, DEVINFO_SUMMARY, &data.di_flags, NULL)
	    != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn(
		    "devinfo doesn't give global information (try prtconf)\n");
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags) && data.di_flags & DEVINFO_SUMMARY)
		mdb_printf(
		    "%-?s %5s %?s %-20s %-s\n"
		    "%-?s %5s %?s %-20s %-s\n"
		    "%<u>%-?s %5s %?s %-20s %-15s%</u>\n",
		    "DEVINFO", "MAJ",  "REFCNT",   "NODENAME", "NODESTATE",
		    "",        "INST", "CIRCULAR", "BINDNAME", "STATE",
		    "",        "",     "THREAD",   "",         "FLAGS");

	if (mdb_vread(&devi, sizeof (devi), addr) == -1) {
		mdb_warn("failed to read device");
		return (DCMD_ERR);
	}

	if (data.di_flags & DEVINFO_SUMMARY) {
		*nodename = '\0';
		size = sizeof (nodename);

		if ((length = mdb_readstr(tmpstr, size,
		    (uintptr_t)devi.devi_node_name)) > 0) {
			strcat(nodename, tmpstr);
			size -= length;
		}

		if (devi.devi_addr != NULL && mdb_readstr(tmpstr, size - 1,
		    (uintptr_t)devi.devi_addr) > 0) {
			strcat(nodename, "@");
			strcat(nodename, tmpstr);
		}

		if (mdb_readstr(bindname, sizeof (bindname),
		    (uintptr_t)devi.devi_binding_name) == -1)
			*bindname = '\0';

		mdb_printf("%0?p %5d %?d %-20s %s\n",
		    addr, devi.devi_major, devi.devi_ref, nodename,
		    di_state[MIN(devi.devi_node_state + 1, DI_STATE_MAX)]);
		mdb_printf("%?s %5d %?d %-20s <%b>\n",
		    "", devi.devi_instance, devi.devi_circular, bindname,
		    devi.devi_state, devi_state_masks);
		mdb_printf("%?s %5s %?p %-20s <%b>\n\n",
		    "", "", devi.devi_busy_thread, "",
		    devi.devi_flags, devi_flags_masks);

		return (DCMD_OK);
	} else {
		din.din_dev = devi;
		din.din_depth = 0;
		return (devinfo_print(addr, (struct dev_info *)&din, &data));
	}
}

/*ARGSUSED*/
int
m2d_walk_dinfo(uintptr_t addr, struct dev_info *di, char *mod_name)
{
	char name[MODMAXNAMELEN];

	if (mdb_readstr(name, MODMAXNAMELEN,
	    (uintptr_t)di->devi_binding_name) == -1) {
		mdb_warn("couldn't read devi_binding_name at %p",
		    di->devi_binding_name);
		return (WALK_ERR);
	}

	if (strcmp(name, mod_name) == 0)
		mdb_printf("%p\n", addr);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
modctl2devinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct modctl modctl;
	char name[MODMAXNAMELEN];

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&modctl, sizeof (modctl), addr) == -1) {
		mdb_warn("couldn't read modctl at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_readstr(name, MODMAXNAMELEN,
	    (uintptr_t)modctl.mod_modname) == -1) {
		mdb_warn("couldn't read modname at %p", modctl.mod_modname);
		return (DCMD_ERR);
	}

	if (mdb_walk("devinfo", (mdb_walk_cb_t)m2d_walk_dinfo, name) == -1) {
		mdb_warn("couldn't walk devinfo");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
major_to_addr(major_t major, uintptr_t *vaddr)
{
	uint_t devcnt;
	uintptr_t devnamesp;

	if (mdb_readvar(&devcnt, "devcnt") == -1) {
		mdb_warn("failed to read 'devcnt'");
		return (-1);
	}

	if (mdb_readvar(&devnamesp, "devnamesp") == -1) {
		mdb_warn("failed to read 'devnamesp'");
		return (-1);
	}

	if (major >= devcnt) {
		mdb_warn("%x is out of range [0x0-0x%x]\n", major, devcnt - 1);
		return (-1);
	}

	*vaddr = devnamesp + (major * sizeof (struct devnames));
	return (0);
}

/*ARGSUSED*/
int
devnames(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	static const mdb_bitmask_t dn_flag_bits[] = {
		{ "DN_CONF_PARSED",	DN_CONF_PARSED, DN_CONF_PARSED },
		{ "DN_DRIVER_BUSY",	DN_DRIVER_BUSY, DN_DRIVER_BUSY },
		{ "DN_DRIVER_HELD",	DN_DRIVER_HELD, DN_DRIVER_HELD },
		{ "DN_TAKEN_GETUDEV",	DN_TAKEN_GETUDEV, DN_TAKEN_GETUDEV },
		{ "DN_DRIVER_REMOVED",	DN_DRIVER_REMOVED, DN_DRIVER_REMOVED},
		{ "DN_FORCE_ATTACH",	DN_FORCE_ATTACH, DN_FORCE_ATTACH},
		{ "DN_LEAF_DRIVER",	DN_LEAF_DRIVER, DN_LEAF_DRIVER},
		{ "DN_NETWORK_DRIVER",	DN_NETWORK_DRIVER, DN_NETWORK_DRIVER},
		{ "DN_NO_AUTODETACH",	DN_NO_AUTODETACH, DN_NO_AUTODETACH },
		{ "DN_GLDV3_DRIVER",	DN_GLDV3_DRIVER, DN_GLDV3_DRIVER},
		{ "DN_PHCI_DRIVER",	DN_PHCI_DRIVER, DN_PHCI_DRIVER},
		{ "DN_OPEN_RETURNS_EINTR", \
				DN_OPEN_RETURNS_EINTR, DN_OPEN_RETURNS_EINTR},
		{ "DN_SCSI_SIZE_CLEAN",	DN_SCSI_SIZE_CLEAN, DN_SCSI_SIZE_CLEAN},
		{ "DN_NETWORK_PHYSDRIVER", \
				DN_NETWORK_PHYSDRIVER, DN_NETWORK_PHYSDRIVER},
		{ NULL, 0, 0 }
	};

	const mdb_arg_t *argp = NULL;
	uint_t opt_v = FALSE, opt_m = FALSE;
	major_t major;
	size_t i;

	char name[MODMAXNAMELEN + 1];
	struct devnames dn;

	if ((i = mdb_getopts(argc, argv,
	    'm', MDB_OPT_SETBITS, TRUE, &opt_m,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v,
	    NULL)) != argc) {
		if (argc - i > 1)
			return (DCMD_USAGE);
		argp = &argv[i];
	}

	if (opt_m) {
		if (!(flags & DCMD_ADDRSPEC))
			return (DCMD_USAGE);

		if (major_to_addr(addr, &addr) == -1)
			return (DCMD_ERR);

	} else if (!(flags & DCMD_ADDRSPEC)) {
		if (argp == NULL) {
			if (mdb_walk_dcmd("devnames", "devnames", argc, argv)) {
				mdb_warn("failed to walk devnames");
				return (DCMD_ERR);
			}
			return (DCMD_OK);
		}

		if (argp->a_type == MDB_TYPE_IMMEDIATE)
			major = (major_t)argp->a_un.a_val;
		else
			major = (major_t)mdb_strtoull(argp->a_un.a_str);

		if (major_to_addr(major, &addr) == -1)
			return (DCMD_ERR);
	}

	if (mdb_vread(&dn, sizeof (struct devnames), addr) == -1) {
		mdb_warn("failed to read devnames struct at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		if (opt_v)
			mdb_printf("%<u>%-16s%</u>\n", "NAME");
		else
			mdb_printf("%<u>%-16s %-?s%</u>\n", "NAME", "DN_HEAD");
	}

	if ((flags & DCMD_LOOP) && (dn.dn_name == NULL))
		return (DCMD_OK); /* Skip empty slots if we're printing table */

	if (mdb_readstr(name, sizeof (name), (uintptr_t)dn.dn_name) == -1)
		(void) mdb_snprintf(name, sizeof (name), "0x%p", dn.dn_name);

	if (opt_v) {
		ddi_prop_list_t prop_list;
		mdb_printf("%<b>%-16s%</b>\n", name);
		mdb_inc_indent(2);

		mdb_printf("          flags %b\n", dn.dn_flags, dn_flag_bits);
		mdb_printf("             pl %p\n", (void *)dn.dn_pl);
		mdb_printf("           head %p\n", dn.dn_head);
		mdb_printf("       instance %d\n", dn.dn_instance);
		mdb_printf("         inlist %p\n", dn.dn_inlist);
		mdb_printf("global_prop_ptr %p\n", dn.dn_global_prop_ptr);
		if (mdb_vread(&prop_list, sizeof (ddi_prop_list_t),
		    (uintptr_t)dn.dn_global_prop_ptr) != -1) {
			devinfo_print_props(NULL, prop_list.prop_list);
		}

		mdb_dec_indent(2);
	} else
		mdb_printf("%-16s %-?p\n", name, dn.dn_head);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
name2major(uintptr_t vaddr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	major_t major;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	if (argc != 1 || argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (mdb_name_to_major(argv->a_un.a_str, &major) != 0) {
		mdb_warn("failed to convert name to major number\n");
		return (DCMD_ERR);
	}

	mdb_printf("0x%x\n", major);
	return (DCMD_OK);
}

/*
 * Get a numerical argument of a dcmd from addr if an address is specified
 * or from argv if no address is specified. Return the argument in ret.
 */
static int
getarg(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    uintptr_t *ret)
{
	if (argc == 0 && (flags & DCMD_ADDRSPEC)) {
		*ret = addr;

	} else if (argc == 1 && !(flags & DCMD_ADDRSPEC)) {
		*ret = (argv[0].a_type == MDB_TYPE_IMMEDIATE) ?
		    (uintptr_t)argv[0].a_un.a_val :
		    (uintptr_t)mdb_strtoull(argv->a_un.a_str);

	} else {
		return (-1);
	}

	return (0);
}

/*ARGSUSED*/
int
major2name(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t major;
	const char *name;

	if (getarg(addr, flags, argc, argv, &major) < 0)
		return (DCMD_USAGE);

	if ((name = mdb_major_to_name((major_t)major)) == NULL) {
		mdb_warn("failed to convert major number to name\n");
		return (DCMD_ERR);
	}

	mdb_printf("%s\n", name);
	return (DCMD_OK);
}

/*ARGSUSED*/
int
dev2major(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t dev;

	if (getarg(addr, flags, argc, argv, &dev) < 0)
		return (DCMD_USAGE);

	if (flags & DCMD_PIPE_OUT)
		mdb_printf("%x\n", getmajor(dev));
	else
		mdb_printf("0x%x (0t%d)\n", getmajor(dev), getmajor(dev));

	return (DCMD_OK);
}

/*ARGSUSED*/
int
dev2minor(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t dev;

	if (getarg(addr, flags, argc, argv, &dev) < 0)
		return (DCMD_USAGE);

	if (flags & DCMD_PIPE_OUT)
		mdb_printf("%x\n", getminor(dev));
	else
		mdb_printf("0x%x (0t%d)\n", getminor(dev), getminor(dev));

	return (DCMD_OK);
}

/*ARGSUSED*/
int
devt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t dev;

	if (getarg(addr, flags, argc, argv, &dev) < 0)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%10s%</u>  %<u>%10s%</u>\n", "MAJOR",
		    "MINOR");
	}

	mdb_printf("%10d  %10d\n", getmajor(dev), getminor(dev));

	return (DCMD_OK);
}

/*ARGSUSED*/
int
softstate(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t statep;
	int instance;


	if (argc != 1) {
		return (DCMD_USAGE);
	}

	if (argv[0].a_type == MDB_TYPE_IMMEDIATE)
		instance = argv[0].a_un.a_val;
	else
		instance = mdb_strtoull(argv->a_un.a_str);

	if (mdb_get_soft_state_byaddr(addr, instance, &statep, NULL, 0) == -1) {
		if (errno == ENOENT) {
			mdb_warn("instance %d unused\n", instance);
		} else {
			mdb_warn("couldn't determine softstate for "
			    "instance %d", instance);
		}

		return (DCMD_ERR);
	}

	mdb_printf("%p\n", statep);
	return (DCMD_OK);
}

/*
 * Walker for all possible pointers to a driver state struct in an
 * i_ddi_soft_state instance chain.  Returns all non-NULL pointers.
 */
typedef struct soft_state_walk {
	struct i_ddi_soft_state	ssw_ss;	/* Local copy of i_ddi_soft_state */
	void		**ssw_pointers;	/* to driver state structs */
	uint_t		ssw_index;	/* array entry we're using */
} soft_state_walk_t;

int
soft_state_walk_init(mdb_walk_state_t *wsp)
{
	soft_state_walk_t *sst;


	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	sst = mdb_zalloc(sizeof (soft_state_walk_t), UM_SLEEP|UM_GC);
	wsp->walk_data = sst;


	if (mdb_vread(&(sst->ssw_ss), sizeof (sst->ssw_ss), wsp->walk_addr) !=
	    sizeof (sst->ssw_ss)) {
		mdb_warn("failed to read i_ddi_soft_state at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}


	/* Read array of pointers to state structs into local storage. */
	sst->ssw_pointers = mdb_alloc((sst->ssw_ss.n_items * sizeof (void *)),
	    UM_SLEEP|UM_GC);

	if (mdb_vread(sst->ssw_pointers, (sst->ssw_ss.n_items *
	    sizeof (void *)), (uintptr_t)sst->ssw_ss.array) !=
	    (sst->ssw_ss.n_items * sizeof (void *))) {
		mdb_warn("failed to read i_ddi_soft_state at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	sst->ssw_index = 0;

	return (WALK_NEXT);
}

int
soft_state_walk_step(mdb_walk_state_t *wsp)
{
	soft_state_walk_t *sst = (soft_state_walk_t *)wsp->walk_data;
	int status = WALK_NEXT;


	/*
	 * If the entry indexed has a valid pointer to a soft state struct,
	 * invoke caller's callback func.
	 */
	if (sst->ssw_pointers[sst->ssw_index] != NULL) {
		status = wsp->walk_callback(
		    (uintptr_t)(sst->ssw_pointers[sst->ssw_index]), NULL,
		    wsp->walk_cbdata);
	}

	sst->ssw_index += 1;

	if (sst->ssw_index == sst->ssw_ss.n_items)
		return (WALK_DONE);

	return (status);
}

int
soft_state_all_walk_step(mdb_walk_state_t *wsp)
{
	soft_state_walk_t *sst = (soft_state_walk_t *)wsp->walk_data;
	int status = WALK_NEXT;


	status = wsp->walk_callback(
	    (uintptr_t)(sst->ssw_pointers[sst->ssw_index]), NULL,
	    wsp->walk_cbdata);

	sst->ssw_index += 1;

	if (sst->ssw_index == sst->ssw_ss.n_items)
		return (WALK_DONE);

	return (status);
}

/*ARGSUSED*/
int
devbindings(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const mdb_arg_t *arg;
	struct devnames dn;
	uintptr_t dn_addr;
	major_t major;

	if (!(flags & DCMD_ADDRSPEC) && argc < 1)
		return (DCMD_USAGE);

	if (flags & DCMD_ADDRSPEC) {
		/*
		 * If there's an address, then it's a major number
		 */
		major = addr;
	} else {
		/*
		 * We interpret the last argument. Any other arguments are
		 * forwarded to "devinfo"
		 */
		arg = &argv[argc - 1];
		argc--;

		if (arg->a_type == MDB_TYPE_IMMEDIATE) {
			major = (uintptr_t)arg->a_un.a_val;

		} else if (arg->a_un.a_str[0] == '-') {
			/* the argument shouldn't be an option */
			return (DCMD_USAGE);

		} else if (isdigit(arg->a_un.a_str[0])) {
			major = (uintptr_t)mdb_strtoull(arg->a_un.a_str);

		} else {
			if (mdb_name_to_major(arg->a_un.a_str, &major) != 0) {
				mdb_warn("failed to get major number for %s\n",
				    arg->a_un.a_str);
				return (DCMD_ERR);
			}
		}
	}

	if (major_to_addr(major, &dn_addr) != 0)
		return (DCMD_ERR);

	if (mdb_vread(&dn, sizeof (struct devnames), dn_addr) == -1) {
		mdb_warn("couldn't read devnames array at %p", dn_addr);
		return (DCMD_ERR);
	}

	if (mdb_pwalk_dcmd("devi_next", "devinfo", argc, argv,
	    (uintptr_t)dn.dn_head) != 0) {
		mdb_warn("couldn't walk the devinfo chain at %p", dn.dn_head);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * walk binding hashtable (as of of driver names (e.g., mb_hashtab))
 */
int
binding_hash_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	wsp->walk_data = mdb_alloc(sizeof (void *) * MOD_BIND_HASHSIZE,
	    UM_SLEEP|UM_GC);
	if (mdb_vread(wsp->walk_data, sizeof (void *) * MOD_BIND_HASHSIZE,
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read mb_hashtab");
		return (WALK_ERR);
	}

	wsp->walk_arg = 0;	/* index into mb_hashtab array to start */

	return (WALK_NEXT);
}

int
binding_hash_walk_step(mdb_walk_state_t *wsp)
{
	int		status;
	uintptr_t	bind_p;
	struct bind	bind;


	/*
	 * Walk the singly-linked list of struct bind
	 */
	bind_p = ((uintptr_t *)wsp->walk_data)[(ulong_t)wsp->walk_arg];
	while (bind_p != NULL) {

		if (mdb_vread(&bind, sizeof (bind), bind_p) == -1) {
			mdb_warn("failed to read bind struct at %p",
			    wsp->walk_addr);
			return (WALK_ERR);
		}

		if ((status = wsp->walk_callback(bind_p, &bind,
		    wsp->walk_cbdata)) != WALK_NEXT) {
			return (status);
		}

		bind_p = (uintptr_t)bind.b_next;
	}

	wsp->walk_arg = (void *)((char *)wsp->walk_arg + 1);

	if (wsp->walk_arg == (void *)(MOD_BIND_HASHSIZE - 1))
		return (WALK_DONE);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
binding_hash_entry(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	struct bind 	bind;
	/* Arbitrary lengths based on output format below */
	char name[MAXPATHLEN] = "???";
	char bind_name[MAXPATHLEN] = "<null>";

	if ((flags & DCMD_ADDRSPEC) == NULL)
		return (DCMD_USAGE);

	/* Allow null addresses to be passed (as from a walker) */
	if (addr == NULL)
		return (DCMD_OK);

	if (mdb_vread(&bind, sizeof (bind), addr) == -1) {
		mdb_warn("failed to read struct bind at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s% %-5s %s%</u>\n",
		    "NEXT", "MAJOR", "NAME(S)");
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)bind.b_name) == -1)
		mdb_warn("failed to read 'name'");

	/* There may be bind_name, so this may fail */
	if (mdb_readstr(bind_name, sizeof (bind_name),
	    (uintptr_t)bind.b_bind_name) == -1) {
		mdb_printf("%?p %5d %s\n",
		    bind.b_next, bind.b_num, name);
	} else {
		mdb_printf("%?p %5d %s %s\n",
		    bind.b_next, bind.b_num, name, bind_name);
	}

	return (DCMD_OK);
}

typedef struct devinfo_audit_log_walk_data {
	devinfo_audit_t dil_buf;	/* buffer of last entry */
	uintptr_t dil_base;		/* starting address of log buffer */
	int dil_max;			/* maximum index */
	int dil_start;			/* starting index */
	int dil_index;			/* current walking index */
} devinfo_audit_log_walk_data_t;

int
devinfo_audit_log_walk_init(mdb_walk_state_t *wsp)
{
	devinfo_log_header_t header;
	devinfo_audit_log_walk_data_t *dil;
	uintptr_t devinfo_audit_log;

	/* read in devinfo_log_header structure */
	if (mdb_readvar(&devinfo_audit_log, "devinfo_audit_log") == -1) {
		mdb_warn("failed to read 'devinfo_audit_log'");
		return (WALK_ERR);
	}

	if (mdb_vread(&header, sizeof (devinfo_log_header_t),
	    devinfo_audit_log) == -1) {
		mdb_warn("couldn't read devinfo_log_header at %p",
		    devinfo_audit_log);
		return (WALK_ERR);
	}

	dil = mdb_zalloc(sizeof (devinfo_audit_log_walk_data_t), UM_SLEEP);
	wsp->walk_data = dil;

	dil->dil_start = dil->dil_index = header.dh_curr;
	dil->dil_max = header.dh_max;
	if (dil->dil_start < 0)		/* no log entries */
		return (WALK_DONE);

	dil->dil_base = devinfo_audit_log +
	    offsetof(devinfo_log_header_t, dh_entry);
	wsp->walk_addr = dil->dil_base +
	    dil->dil_index * sizeof (devinfo_audit_t);

	return (WALK_NEXT);
}

int
devinfo_audit_log_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	devinfo_audit_log_walk_data_t *dil = wsp->walk_data;
	devinfo_audit_t *da = &dil->dil_buf;
	int status = WALK_NEXT;

	/* read in current entry and invoke callback */
	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&dil->dil_buf, sizeof (devinfo_audit_t), addr) == -1) {
		mdb_warn("failed to read devinfo_audit at %p", addr);
		status = WALK_DONE;
	}
	status = wsp->walk_callback(wsp->walk_addr, da, wsp->walk_cbdata);

	/* step to the previous log entry in time */
	if (--dil->dil_index < 0)
		dil->dil_index += dil->dil_max;
	if (dil->dil_index == dil->dil_start) {
		wsp->walk_addr = NULL;
		return (WALK_DONE);
	}

	wsp->walk_addr = dil->dil_base +
	    dil->dil_index * sizeof (devinfo_audit_t);
	return (status);
}

void
devinfo_audit_log_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (devinfo_audit_log_walk_data_t));
}

/*
 * display devinfo_audit_t stack trace
 */
/*ARGSUSED*/
int
devinfo_audit(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = FALSE;
	devinfo_audit_t da;
	int i, depth;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf(" %-?s %16s %-?s %-?s %5s\n",
		    "AUDIT", "TIMESTAMP", "THREAD", "DEVINFO", "STATE");
	}

	if (mdb_vread(&da, sizeof (da), addr) == -1) {
		mdb_warn("couldn't read devinfo_audit at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf(" %0?p %16llx %0?p %0?p %s\n",
	    addr, da.da_timestamp, da.da_thread, da.da_devinfo,
	    di_state[MIN(da.da_node_state + 1, DI_STATE_MAX)]);

	if (!verbose)
		return (DCMD_OK);

	mdb_inc_indent(4);

	/*
	 * Guard against bogus da_depth in case the devinfo_audit_t
	 * is corrupt or the address does not really refer to a
	 * devinfo_audit_t.
	 */
	depth = MIN(da.da_depth, DDI_STACK_DEPTH);

	for (i = 0; i < depth; i++)
		mdb_printf("%a\n", da.da_stack[i]);

	mdb_printf("\n");
	mdb_dec_indent(4);

	return (DCMD_OK);
}

int
devinfo_audit_log(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	if (flags & DCMD_ADDRSPEC)
		return (devinfo_audit(addr, flags, argc, argv));

	(void) mdb_walk_dcmd("devinfo_audit_log", "devinfo_audit", argc, argv);
	return (DCMD_OK);
}

typedef struct devinfo_audit_node_walk_data {
	devinfo_audit_t dih_buf;	/* buffer of last entry */
	uintptr_t dih_dip;		/* address of dev_info */
	int dih_on_devinfo;		/* devi_audit on dev_info struct */
} devinfo_audit_node_walk_data_t;

int
devinfo_audit_node_walk_init(mdb_walk_state_t *wsp)
{
	devinfo_audit_node_walk_data_t *dih;
	devinfo_audit_t *da;
	struct dev_info devi;
	uintptr_t addr = wsp->walk_addr;

	/* read in devinfo structure */
	if (mdb_vread(&devi, sizeof (struct dev_info), addr) == -1) {
		mdb_warn("couldn't read dev_info at %p", addr);
		return (WALK_ERR);
	}

	dih = mdb_zalloc(sizeof (devinfo_audit_node_walk_data_t), UM_SLEEP);
	wsp->walk_data = dih;
	da = &dih->dih_buf;

	/* read in devi_audit structure */
	if (mdb_vread(da, sizeof (devinfo_audit_t), (uintptr_t)devi.devi_audit)
	    == -1) {
		mdb_warn("couldn't read devi_audit at %p", devi.devi_audit);
		return (WALK_ERR);
	}
	dih->dih_dip = addr;
	dih->dih_on_devinfo = 1;
	wsp->walk_addr = (uintptr_t)devi.devi_audit;

	return (WALK_NEXT);
}

int
devinfo_audit_node_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr;
	devinfo_audit_node_walk_data_t *dih = wsp->walk_data;
	devinfo_audit_t *da = &dih->dih_buf;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);
	(void) wsp->walk_callback(wsp->walk_addr, NULL, wsp->walk_cbdata);

skip:
	/* read in previous entry */
	if ((addr = (uintptr_t)da->da_lastlog) == 0)
		return (WALK_DONE);

	if (mdb_vread(&dih->dih_buf, sizeof (devinfo_audit_t), addr) == -1) {
		mdb_warn("failed to read devinfo_audit at %p", addr);
		return (WALK_DONE);
	}

	/* check if last log was over-written */
	if ((uintptr_t)da->da_devinfo != dih->dih_dip)
		return (WALK_DONE);

	/*
	 * skip the first common log entry, which is a duplicate of
	 * the devi_audit buffer on the dev_info structure
	 */
	if (dih->dih_on_devinfo) {
		dih->dih_on_devinfo = 0;
		goto skip;
	}
	wsp->walk_addr = addr;

	return (WALK_NEXT);
}

void
devinfo_audit_node_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (devinfo_audit_node_walk_data_t));
}

int
devinfo_audit_node(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	(void) mdb_pwalk_dcmd("devinfo_audit_node", "devinfo_audit",
	    argc, argv, addr);
	return (DCMD_OK);
}

/*
 * mdb support for per-devinfo fault management data
 */
/*ARGSUSED*/
int
devinfo_fm(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct dev_info devi;
	struct i_ddi_fmhdl fhdl;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s IPL CAPS DROP FMCFULL FMCMISS ACCERR "
		    "DMAERR %?s %?s%</u>\n", "ADDR", "DMACACHE", "ACCCACHE");
	}

	if (mdb_vread(&devi, sizeof (devi), addr) == -1) {
		mdb_warn("failed to read devinfo struct at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&fhdl, sizeof (fhdl), (uintptr_t)devi.devi_fmhdl) == -1) {
		mdb_warn("failed to read devinfo fm struct at %p",
		    (uintptr_t)devi.devi_fmhdl);
		return (DCMD_ERR);
	}

	mdb_printf("%?p %3u %c%c%c%c %4llu %7llu %7llu %6llu %6llu %?p %?p\n",
	    (uintptr_t)devi.devi_fmhdl, fhdl.fh_ibc,
	    (DDI_FM_EREPORT_CAP(fhdl.fh_cap) ? 'E' : '-'),
	    (DDI_FM_ERRCB_CAP(fhdl.fh_cap) ? 'C' : '-'),
	    (DDI_FM_ACC_ERR_CAP(fhdl.fh_cap) ? 'A' : '-'),
	    (DDI_FM_DMA_ERR_CAP(fhdl.fh_cap) ? 'D' : '-'),
	    fhdl.fh_kstat.fek_erpt_dropped.value.ui64,
	    fhdl.fh_kstat.fek_fmc_full.value.ui64,
	    fhdl.fh_kstat.fek_fmc_miss.value.ui64,
	    fhdl.fh_kstat.fek_acc_err.value.ui64,
	    fhdl.fh_kstat.fek_dma_err.value.ui64,
	    fhdl.fh_dma_cache, fhdl.fh_acc_cache);


	return (DCMD_OK);
}

/*ARGSUSED*/
int
devinfo_fmce(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct i_ddi_fmc_entry fce;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %?s %?s%</u>\n", "ADDR",
		    "RESOURCE", "BUS_SPECIFIC");
	}

	if (mdb_vread(&fce, sizeof (fce), addr) == -1) {
		mdb_warn("failed to read fm cache struct at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%?p %?p %?p\n",
	    (uintptr_t)addr, fce.fce_resource, fce.fce_bus_specific);


	return (DCMD_OK);
}

int
devinfo_fmc_walk_init(mdb_walk_state_t *wsp)
{
	struct i_ddi_fmc fec;

	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	if (mdb_vread(&fec, sizeof (fec), wsp->walk_addr) == -1) {
		mdb_warn("failed to read fm cache at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if (fec.fc_head == NULL)
		return (WALK_DONE);

	wsp->walk_addr = (uintptr_t)fec.fc_head;
	return (WALK_NEXT);
}

int
devinfo_fmc_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	struct i_ddi_fmc_entry fe;

	if (mdb_vread(&fe, sizeof (fe), wsp->walk_addr) == -1) {
		mdb_warn("failed to read active fm cache entry at %p",
		    wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, &fe, wsp->walk_cbdata);

	if (fe.fce_next == NULL)
		return (WALK_DONE);

	wsp->walk_addr = (uintptr_t)fe.fce_next;
	return (status);
}

int
minornode_walk_init(mdb_walk_state_t *wsp)
{
	struct dev_info di;
	uintptr_t addr = wsp->walk_addr;

	if (addr == NULL) {
		mdb_warn("a dev_info struct address must be provided\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&di, sizeof (di), wsp->walk_addr) == -1) {
		mdb_warn("failed to read dev_info struct at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)di.devi_minor;
	return (WALK_NEXT);
}

int
minornode_walk_step(mdb_walk_state_t *wsp)
{
	struct ddi_minor_data md;
	uintptr_t addr = wsp->walk_addr;

	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&md, sizeof (md), addr) == -1) {
		mdb_warn("failed to read dev_info struct at %p", addr);
		return (WALK_DONE);
	}

	wsp->walk_addr = (uintptr_t)md.next;
	return (wsp->walk_callback(addr, &md, wsp->walk_cbdata));
}

static const char *const md_type[] = {
	"DDI_MINOR",
	"DDI_ALIAS",
	"DDI_DEFAULT",
	"DDI_I_PATH",
	"?"
};

#define	MD_TYPE_MAX	((sizeof (md_type) / sizeof (char *)) - 1)

/*ARGSUSED*/
static int
print_minornode(uintptr_t addr, const void *arg, void *data)
{
	char name[128];
	char nodetype[128];
	char *spectype;
	struct ddi_minor_data *mdp = (struct ddi_minor_data *)arg;

	if (mdb_readstr(name, sizeof (name), (uintptr_t)mdp->ddm_name) == -1)
		*name = '\0';

	if (mdb_readstr(nodetype, sizeof (nodetype),
	    (uintptr_t)mdp->ddm_node_type) == -1)
		*nodetype = '\0';

	switch (mdp->ddm_spec_type) {
		case S_IFCHR:	spectype = "c";	break;
		case S_IFBLK:	spectype = "b";	break;
		default:	spectype = "?";	break;
	}

	mdb_printf("%?p %16lx %-4s %-11s %-10s %s\n",
	    addr, mdp->ddm_dev, spectype, md_type[MIN(mdp->type, MD_TYPE_MAX)],
	    name, nodetype);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
minornodes(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%?s %16s %-4s %-11s %-10s %-16s%</u>\n",
		    "ADDR", "DEV", "SPEC", "TYPE", "NAME", "NODETYPE");

	if (mdb_pwalk("minornode", print_minornode, NULL, addr) == -1) {
		mdb_warn("can't walk minornode");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}
