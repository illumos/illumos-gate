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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/*
 * For machines that support the openprom, fetch and print the list
 * of devices that the kernel has fetched from the prom or conjured up.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <strings.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/sunddi.h>
#include <sys/openpromio.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <zone.h>
#include <libnvpair.h>
#include <pcidb.h>
#include "prtconf.h"


typedef char *(*dump_propname_t)(void *);
typedef int (*dump_proptype_t)(void *);
typedef int (*dump_propints_t)(void *, int **);
typedef int (*dump_propint64_t)(void *, int64_t **);
typedef int (*dump_propstrings_t)(void *, char **);
typedef int (*dump_propbytes_t)(void *, uchar_t **);
typedef int (*dump_proprawdata_t)(void *, uchar_t **);

typedef struct dumpops_common {
	dump_propname_t doc_propname;
	dump_proptype_t doc_proptype;
	dump_propints_t doc_propints;
	dump_propint64_t doc_propint64;
	dump_propstrings_t doc_propstrings;
	dump_propbytes_t doc_propbytes;
	dump_proprawdata_t doc_proprawdata;
} dumpops_common_t;

static const dumpops_common_t prop_dumpops = {
	(dump_propname_t)di_prop_name,
	(dump_proptype_t)di_prop_type,
	(dump_propints_t)di_prop_ints,
	(dump_propint64_t)di_prop_int64,
	(dump_propstrings_t)di_prop_strings,
	(dump_propbytes_t)di_prop_bytes,
	(dump_proprawdata_t)di_prop_rawdata
}, pathprop_common_dumpops = {
	(dump_propname_t)di_path_prop_name,
	(dump_proptype_t)di_path_prop_type,
	(dump_propints_t)di_path_prop_ints,
	(dump_propint64_t)di_path_prop_int64s,
	(dump_propstrings_t)di_path_prop_strings,
	(dump_propbytes_t)di_path_prop_bytes,
	(dump_proprawdata_t)di_path_prop_bytes
};

typedef void *(*dump_nextprop_t)(void *, void *);
typedef dev_t (*dump_propdevt_t)(void *);

typedef struct dumpops {
	const dumpops_common_t *dop_common;
	dump_nextprop_t dop_nextprop;
	dump_propdevt_t dop_propdevt;
} dumpops_t;

typedef struct di_args {
	di_prom_handle_t	prom_hdl;
	di_devlink_handle_t	devlink_hdl;
	pcidb_hdl_t 		*pcidb_hdl;
} di_arg_t;

static const dumpops_t sysprop_dumpops = {
	&prop_dumpops,
	(dump_nextprop_t)di_prop_sys_next,
	NULL
}, globprop_dumpops = {
	&prop_dumpops,
	(dump_nextprop_t)di_prop_global_next,
	NULL
}, drvprop_dumpops = {
	&prop_dumpops,
	(dump_nextprop_t)di_prop_drv_next,
	(dump_propdevt_t)di_prop_devt
}, hwprop_dumpops = {
	&prop_dumpops,
	(dump_nextprop_t)di_prop_hw_next,
	NULL
}, pathprop_dumpops = {
	&pathprop_common_dumpops,
	(dump_nextprop_t)di_path_prop_next,
	NULL
};

#define	PROPNAME(ops) (ops->dop_common->doc_propname)
#define	PROPTYPE(ops) (ops->dop_common->doc_proptype)
#define	PROPINTS(ops) (ops->dop_common->doc_propints)
#define	PROPINT64(ops) (ops->dop_common->doc_propint64)
#define	PROPSTRINGS(ops) (ops->dop_common->doc_propstrings)
#define	PROPBYTES(ops) (ops->dop_common->doc_propbytes)
#define	PROPRAWDATA(ops) (ops->dop_common->doc_proprawdata)
#define	NEXTPROP(ops) (ops->dop_nextprop)
#define	PROPDEVT(ops) (ops->dop_propdevt)
#define	NUM_ELEMENTS(A) (sizeof (A) / sizeof (A[0]))

static int prop_type_guess(const dumpops_t *, void *, void **, int *);
static void walk_driver(di_node_t, di_arg_t *);
static int dump_devs(di_node_t, void *);
static int dump_prop_list(const dumpops_t *, const char *,
				int, void *, dev_t, int *);
static int _error(const char *, ...);
static int is_openprom();
static void walk(uchar_t *, uint_t, int);
static void dump_node(nvlist_t *, int);
static void dump_prodinfo(di_prom_handle_t, di_node_t, const char **,
				char *, int);
static di_node_t find_node_by_name(di_prom_handle_t, di_node_t, char *);
static int get_propval_by_name(di_prom_handle_t, di_node_t,
				const char *, uchar_t **);
static int dump_compatible(char *, int, di_node_t);
static void dump_pathing_data(int, di_node_t);
static void dump_minor_data(int, di_node_t, di_devlink_handle_t);
static void dump_link_data(int, di_node_t, di_devlink_handle_t);
static int print_composite_string(const char *, char *, int);
static void print_one(nvpair_t *, int);
static int unprintable(char *, int);
static int promopen(int);
static void promclose();
static di_node_t find_target_node(di_node_t);
static void node_display_set(di_node_t);
static int dump_pciid(char *, int, di_node_t, pcidb_hdl_t *);

void
prtconf_devinfo(void)
{
	struct di_priv_data	fetch;
	di_arg_t		di_arg;
	di_prom_handle_t	prom_hdl = DI_PROM_HANDLE_NIL;
	di_devlink_handle_t	devlink_hdl = NULL;
	pcidb_hdl_t		*pcidb_hdl = NULL;
	di_node_t		root_node;
	uint_t			flag;
	char			*rootpath;

	dprintf("verbosemode %s\n", opts.o_verbose ? "on" : "off");

	/* determine what info we need to get from kernel */
	flag = DINFOSUBTREE;
	rootpath = "/";

	if (opts.o_target) {
		flag |= (DINFOMINOR | DINFOPATH);
	}

	if (opts.o_pciid) {
		flag |= DINFOPROP;
		if ((prom_hdl = di_prom_init()) == DI_PROM_HANDLE_NIL)
			exit(_error("di_prom_init() failed."));
	}

	if (opts.o_forcecache) {
		if (dbg.d_forceload) {
			exit(_error(NULL, "option combination not supported"));
		}
		if (strcmp(rootpath, "/") != 0) {
			exit(_error(NULL, "invalid root path for option"));
		}
		flag = DINFOCACHE;
	} else if (opts.o_verbose) {
		flag |= (DINFOPROP | DINFOMINOR |
		    DINFOPRIVDATA | DINFOPATH | DINFOLYR);
	}

	if (dbg.d_forceload) {
		flag |= DINFOFORCE;
	}

	if (opts.o_verbose) {
		init_priv_data(&fetch);
		root_node = di_init_impl(rootpath, flag, &fetch);

		/* get devlink (aka aliases) data */
		if ((devlink_hdl = di_devlink_init(NULL, 0)) == NULL)
			exit(_error("di_devlink_init() failed."));
	} else
		root_node = di_init(rootpath, flag);

	if (root_node == DI_NODE_NIL) {
		(void) _error(NULL, "devinfo facility not available");
		/* not an error if this isn't the global zone */
		if (getzoneid() == GLOBAL_ZONEID)
			exit(-1);
		else
			exit(0);
	}

	if (opts.o_verbose || opts.o_pciid) {
		pcidb_hdl = pcidb_open(PCIDB_VERSION);
		if (pcidb_hdl == NULL)
			(void) _error(NULL, "pcidb facility not available, "
			    "continuing anyways");
	}

	di_arg.prom_hdl = prom_hdl;
	di_arg.devlink_hdl = devlink_hdl;
	di_arg.pcidb_hdl = pcidb_hdl;

	/*
	 * ...and walk all nodes to report them out...
	 */
	if (dbg.d_bydriver) {
		opts.o_target = 0;
		walk_driver(root_node, &di_arg);
		if (prom_hdl != DI_PROM_HANDLE_NIL)
			di_prom_fini(prom_hdl);
		if (devlink_hdl != NULL)
			(void) di_devlink_fini(&devlink_hdl);
		di_fini(root_node);
		return;
	}

	if (opts.o_target) {
		di_node_t target_node, node;

		target_node = find_target_node(root_node);
		if (target_node == DI_NODE_NIL) {
			(void) fprintf(stderr, "%s: "
			    "invalid device path specified\n",
			    opts.o_progname);
			exit(1);
		}

		/* mark the target node so we display it */
		node_display_set(target_node);

		if (opts.o_ancestors) {
			/*
			 * mark the ancestors of this node so we display
			 * them as well
			 */
			node = target_node;
			while (node = di_parent_node(node))
				node_display_set(node);
		} else {
			/*
			 * when we display device tree nodes the indentation
			 * level is based off of tree depth.
			 *
			 * here we increment o_target to reflect the
			 * depth of the target node in the tree.  we do
			 * this so that when we calculate the indentation
			 * level we can subtract o_target so that the
			 * target node starts with an indentation of zero.
			 */
			node = target_node;
			while (node = di_parent_node(node))
				opts.o_target++;
		}

		if (opts.o_children) {
			/*
			 * mark the children of this node so we display
			 * them as well
			 */
			(void) di_walk_node(target_node, DI_WALK_CLDFIRST,
			    (void *)1,
			    (int (*)(di_node_t, void *))
			    node_display_set);
		}
	}

	(void) di_walk_node(root_node, DI_WALK_CLDFIRST, &di_arg,
	    dump_devs);

	if (prom_hdl != DI_PROM_HANDLE_NIL)
		di_prom_fini(prom_hdl);
	if (devlink_hdl != NULL)
		(void) di_devlink_fini(&devlink_hdl);
	if (pcidb_hdl != NULL)
		pcidb_close(pcidb_hdl);
	di_fini(root_node);
}

/*
 * utility routines
 */
static int
i_find_target_node(di_node_t node, void *arg)
{
	di_node_t *target = (di_node_t *)arg;

	if (opts.o_devices_path != NULL) {
		char *path;

		if ((path = di_devfs_path(node)) == NULL)
			exit(_error("failed to allocate memory"));

		if (strcmp(opts.o_devices_path, path) == 0) {
			di_devfs_path_free(path);
			*target = node;
			return (DI_WALK_TERMINATE);
		}

		di_devfs_path_free(path);
	} else if (opts.o_devt != DDI_DEV_T_NONE) {
		di_minor_t	minor = DI_MINOR_NIL;

		while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
			if (opts.o_devt == di_minor_devt(minor)) {
				*target = node;
				return (DI_WALK_TERMINATE);
			}
		}
	} else {
		/* we should never get here */
		exit(_error(NULL, "internal error"));
	}
	return (DI_WALK_CONTINUE);
}

static di_node_t
find_target_node(di_node_t root_node)
{
	di_node_t target = DI_NODE_NIL;

	/* special case to allow displaying of the root node */
	if (opts.o_devices_path != NULL) {
		if (strlen(opts.o_devices_path) == 0)
			return (root_node);
		if (strcmp(opts.o_devices_path, ".") == 0)
			return (root_node);
	}

	(void) di_walk_node(root_node, DI_WALK_CLDFIRST, &target,
	    i_find_target_node);
	return (target);
}

#define	NODE_DISPLAY		(1<<0)

static long
node_display(di_node_t node)
{
	long data = (long)di_node_private_get(node);
	return (data & NODE_DISPLAY);
}

static void
node_display_set(di_node_t node)
{
	long data = (long)di_node_private_get(node);
	data |= NODE_DISPLAY;
	di_node_private_set(node, (void *)data);
}

#define	LNODE_DISPLAYED		(1<<0)

static long
lnode_displayed(di_lnode_t lnode)
{
	long data = (long)di_lnode_private_get(lnode);
	return (data & LNODE_DISPLAYED);
}

static void
lnode_displayed_set(di_lnode_t lnode)
{
	long data = (long)di_lnode_private_get(lnode);
	data |= LNODE_DISPLAYED;
	di_lnode_private_set(lnode, (void *)data);
}

static void
lnode_displayed_clear(di_lnode_t lnode)
{
	long data = (long)di_lnode_private_get(lnode);
	data &= ~LNODE_DISPLAYED;
	di_lnode_private_set(lnode, (void *)data);
}

#define	MINOR_DISPLAYED		(1<<0)
#define	MINOR_PTR		(~(0x3))

static long
minor_displayed(di_minor_t minor)
{
	long data = (long)di_minor_private_get(minor);
	return (data & MINOR_DISPLAYED);
}

static void
minor_displayed_set(di_minor_t minor)
{
	long data = (long)di_minor_private_get(minor);
	data |= MINOR_DISPLAYED;
	di_minor_private_set(minor, (void *)data);
}

static void
minor_displayed_clear(di_minor_t minor)
{
	long data = (long)di_minor_private_get(minor);
	data &= ~MINOR_DISPLAYED;
	di_minor_private_set(minor, (void *)data);
}

static void *
minor_ptr(di_minor_t minor)
{
	long data = (long)di_minor_private_get(minor);
	return ((void *)(data & MINOR_PTR));
}

static void
minor_ptr_set(di_minor_t minor, void *ptr)
{
	long data = (long)di_minor_private_get(minor);
	data = (data & ~MINOR_PTR) | (((long)ptr) & MINOR_PTR);
	di_minor_private_set(minor, (void *)data);
}

/*
 * In this comment typed properties are those of type DI_PROP_TYPE_UNDEF_IT,
 * DI_PROP_TYPE_BOOLEAN, DI_PROP_TYPE_INT, DI_PROP_TYPE_INT64,
 * DI_PROP_TYPE_BYTE, and DI_PROP_TYPE_STRING.
 *
 * The guessing algorithm is:
 * 1. If the property is typed and the type is consistent with the value of
 *    the property, then the property is of that type. If the type is not
 *    consistent with value of the property, then the type is treated as
 *    alien to prtconf.
 * 2. If the property is of type DI_PROP_TYPE_UNKNOWN the following steps
 *    are carried out.
 *    a. If the value of the property is consistent with a string property,
 *       the type of the property is DI_PROP_TYPE_STRING.
 *    b. Otherwise, if the value of the property is consistent with an integer
 *       property, the type of the property is DI_PROP_TYPE_INT.
 *    c. Otherwise, the property type is treated as alien to prtconf.
 * 3. If the property type is alien to prtconf, then the property value is
 *    read by the appropriate routine for untyped properties and the following
 *    steps are carried out.
 *    a. If the length that the property routine returned is zero, the
 *       property is of type DI_PROP_TYPE_BOOLEAN.
 *    b. Otherwise, if the length that the property routine returned is
 *       positive, then the property value is treated as raw data of type
 *       DI_PROP_TYPE_UNKNOWN.
 *    c. Otherwise, if the length that the property routine returned is
 *       negative, then there is some internal inconsistency and this is
 *       treated as an error and no type is determined.
 */
static int
prop_type_guess(const dumpops_t *propops, void *prop, void **prop_data,
    int *prop_type)
{
	int len, type;

	type = PROPTYPE(propops)(prop);
	switch (type) {
	case DI_PROP_TYPE_UNDEF_IT:
	case DI_PROP_TYPE_BOOLEAN:
		*prop_data = NULL;
		*prop_type = type;
		return (0);
	case DI_PROP_TYPE_INT:
		len = PROPINTS(propops)(prop, (int **)prop_data);
		break;
	case DI_PROP_TYPE_INT64:
		len = PROPINT64(propops)(prop, (int64_t **)prop_data);
		break;
	case DI_PROP_TYPE_BYTE:
		len = PROPBYTES(propops)(prop, (uchar_t **)prop_data);
		break;
	case DI_PROP_TYPE_STRING:
		len = PROPSTRINGS(propops)(prop, (char **)prop_data);
		break;
	case DI_PROP_TYPE_UNKNOWN:
		len = PROPSTRINGS(propops)(prop, (char **)prop_data);
		if ((len > 0) && ((*(char **)prop_data)[0] != 0)) {
			*prop_type = DI_PROP_TYPE_STRING;
			return (len);
		}

		len = PROPINTS(propops)(prop, (int **)prop_data);
		type = DI_PROP_TYPE_INT;

		break;
	default:
		len = -1;
	}

	if (len > 0) {
		*prop_type = type;
		return (len);
	}

	len = PROPRAWDATA(propops)(prop, (uchar_t **)prop_data);
	if (len < 0) {
		return (-1);
	} else if (len == 0) {
		*prop_type = DI_PROP_TYPE_BOOLEAN;
		return (0);
	}

	*prop_type = DI_PROP_TYPE_UNKNOWN;
	return (len);
}

/*
 * Returns 0 if nothing is printed, 1 otherwise
 */
static int
dump_prop_list(const dumpops_t *dumpops, const char *name, int ilev,
    void *node, dev_t dev, int *compat_printed)
{
	void		*prop = DI_PROP_NIL, *prop_data;
	di_minor_t	minor;
	char		*p;
	int		i, prop_type, nitems;
	dev_t		pdev;
	int		nprop = 0;

	if (compat_printed)
		*compat_printed = 0;

	while ((prop = NEXTPROP(dumpops)(node, prop)) != DI_PROP_NIL) {

		/* Skip properties a dev_t oriented caller is not requesting */
		if (PROPDEVT(dumpops)) {
			pdev = PROPDEVT(dumpops)(prop);

			if (dev == DDI_DEV_T_ANY) {
				/*
				 * Caller requesting print all properties
				 */
				goto print;
			} else if (dev == DDI_DEV_T_NONE) {
				/*
				 * Caller requesting print of properties
				 * associated with devinfo (not minor).
				 */
				if ((pdev == DDI_DEV_T_ANY) ||
				    (pdev == DDI_DEV_T_NONE))
					goto print;

				/*
				 * Property has a minor association, see if
				 * we have a minor with this dev_t. If there
				 * is no such minor we print the property now
				 * so it gets displayed.
				 */
				minor = DI_MINOR_NIL;
				while ((minor = di_minor_next((di_node_t)node,
				    minor)) != DI_MINOR_NIL) {
					if (di_minor_devt(minor) == pdev)
						break;
				}
				if (minor == DI_MINOR_NIL)
					goto print;
			} else if (dev == pdev) {
				/*
				 * Caller requesting print of properties
				 * associated with a specific matching minor
				 * node.
				 */
				goto print;
			}

			/* otherwise skip print */
			continue;
		}

print:		nitems = prop_type_guess(dumpops, prop, &prop_data, &prop_type);
		if (nitems < 0)
			continue;

		if (nprop == 0) {
			if (name) {
				indent_to_level(ilev);
				(void) printf("%s properties:\n", name);
			}
			ilev++;
		}
		nprop++;

		indent_to_level(ilev);
		(void) printf("name='%s' type=", PROPNAME(dumpops)(prop));

		/* report 'compatible' as processed */
		if (compat_printed &&
		    (strcmp(PROPNAME(dumpops)(prop), "compatible") == 0))
			*compat_printed = 1;

		switch (prop_type) {
		case DI_PROP_TYPE_UNDEF_IT:
			(void) printf("undef");
			break;
		case DI_PROP_TYPE_BOOLEAN:
			(void) printf("boolean");
			break;
		case DI_PROP_TYPE_INT:
			(void) printf("int");
			break;
		case DI_PROP_TYPE_INT64:
			(void) printf("int64");
			break;
		case DI_PROP_TYPE_BYTE:
			(void) printf("byte");
			break;
		case DI_PROP_TYPE_STRING:
			(void) printf("string");
			break;
		case DI_PROP_TYPE_UNKNOWN:
			(void) printf("unknown");
			break;
		default:
			/* Should never be here */
			(void) printf("0x%x", prop_type);
		}

		if (nitems != 0)
			(void) printf(" items=%i", nitems);

		/* print the major and minor numbers for a device property */
		if (PROPDEVT(dumpops)) {
			if ((pdev == DDI_DEV_T_NONE) ||
			    (pdev == DDI_DEV_T_ANY)) {
				(void) printf(" dev=none");
			} else {
				(void) printf(" dev=(%u,%u)",
				    (uint_t)major(pdev), (uint_t)minor(pdev));
			}
		}

		(void) putchar('\n');

		if (nitems == 0)
			continue;

		indent_to_level(ilev);

		(void) printf("    value=");

		switch (prop_type) {
		case DI_PROP_TYPE_INT:
			for (i = 0; i < nitems - 1; i++)
				(void) printf("%8.8x.", ((int *)prop_data)[i]);
			(void) printf("%8.8x", ((int *)prop_data)[i]);
			break;
		case DI_PROP_TYPE_INT64:
			for (i = 0; i < nitems - 1; i++)
				(void) printf("%16.16llx.",
				    ((long long *)prop_data)[i]);
			(void) printf("%16.16llx", ((long long *)prop_data)[i]);
			break;
		case DI_PROP_TYPE_STRING:
			p = (char *)prop_data;
			for (i = 0; i < nitems - 1; i++) {
				(void) printf("'%s' + ", p);
				p += strlen(p) + 1;
			}
			(void) printf("'%s'", p);
			break;
		default:
			for (i = 0; i < nitems - 1; i++)
				(void) printf("%2.2x.",
				    ((uint8_t *)prop_data)[i]);
			(void) printf("%2.2x", ((uint8_t *)prop_data)[i]);
		}

		(void) putchar('\n');
	}

	return (nprop ? 1 : 0);
}

/*
 * walk_driver is a debugging facility.
 */
static void
walk_driver(di_node_t root, di_arg_t *di_arg)
{
	di_node_t node;

	node = di_drv_first_node(dbg.d_drivername, root);

	while (node != DI_NODE_NIL) {
		(void) dump_devs(node, di_arg);
		node = di_drv_next_node(node);
	}
}

/*
 * print out information about this node, returns appropriate code.
 */
/*ARGSUSED1*/
static int
dump_devs(di_node_t node, void *arg)
{
	di_arg_t		*di_arg = arg;
	di_devlink_handle_t	devlink_hdl = di_arg->devlink_hdl;
	int			ilev = 0;	/* indentation level */
	char			*driver_name;
	di_node_t		root_node, tmp;
	int			compat_printed;
	int			printed;

	if (dbg.d_debug) {
		char *path = di_devfs_path(node);
		dprintf("Dump node %s\n", path);
		di_devfs_path_free(path);
	}

	if (dbg.d_bydriver) {
		ilev = 1;
	} else {
		/* figure out indentation level */
		tmp = node;
		while ((tmp = di_parent_node(tmp)) != DI_NODE_NIL)
			ilev++;

		if (opts.o_target && !opts.o_ancestors) {
			ilev -= opts.o_target - 1;
		}
	}

	if (opts.o_target && !node_display(node)) {
		/*
		 * if we're only displaying certain nodes and this one
		 * isn't flagged, skip it.
		 */
		return (DI_WALK_CONTINUE);
	}

	indent_to_level(ilev);

	(void) printf("%s", di_node_name(node));
	if (opts.o_pciid)
		(void) print_pciid(node, di_arg->prom_hdl, di_arg->pcidb_hdl);

	/*
	 * if this node does not have an instance number or is the
	 * root node (1229946), we don't print an instance number
	 */
	root_node = tmp = node;
	while ((tmp = di_parent_node(tmp)) != DI_NODE_NIL)
		root_node = tmp;
	if ((di_instance(node) >= 0) && (node != root_node))
		(void) printf(", instance #%d", di_instance(node));

	if (opts.o_drv_name) {
		driver_name = di_driver_name(node);
		if (driver_name != NULL)
			(void) printf(" (driver name: %s)", driver_name);
	} else if (di_retired(node)) {
		(void) printf(" (retired)");
	} else if (di_state(node) & DI_DRIVER_DETACHED)
		(void) printf(" (driver not attached)");
	(void) printf("\n");

	if (opts.o_verbose)  {
		if (dump_prop_list(&sysprop_dumpops, "System", ilev + 1,
		    node, DDI_DEV_T_ANY, NULL)) {
			(void) dump_prop_list(&globprop_dumpops, NULL, ilev + 1,
			    node, DDI_DEV_T_ANY, NULL);
		} else {
			(void) dump_prop_list(&globprop_dumpops,
			    "System software", ilev + 1,
			    node, DDI_DEV_T_ANY, NULL);
		}
		(void) dump_prop_list(&drvprop_dumpops, "Driver", ilev + 1,
		    node, DDI_DEV_T_NONE, NULL);

		printed = dump_prop_list(&hwprop_dumpops, "Hardware",
		    ilev + 1, node, DDI_DEV_T_ANY, &compat_printed);

		/* Ensure that 'compatible' is printed under Hardware header */
		if (!compat_printed)
			printed |= dump_compatible(printed ? NULL : "Hardware",
			    ilev + 1, node);

		/* Ensure that pci id information is printed under Hardware */
		(void) dump_pciid(printed ? NULL : "Hardware",
		    ilev + 1, node, di_arg->pcidb_hdl);

		dump_priv_data(ilev + 1, node);
		dump_pathing_data(ilev + 1, node);
		dump_link_data(ilev + 1, node, devlink_hdl);
		dump_minor_data(ilev + 1, node, devlink_hdl);
	}

	if (opts.o_target)
		return (DI_WALK_CONTINUE);

	if (!opts.o_pseudodevs && (strcmp(di_node_name(node), "pseudo") == 0))
		return (DI_WALK_PRUNECHILD);

	return (DI_WALK_CONTINUE);
}

/* _error([no_perror, ] fmt [, arg ...]) */
static int
_error(const char *opt_noperror, ...)
{
	int saved_errno;
	va_list ap;
	int no_perror = 0;
	const char *fmt;

	saved_errno = errno;

	(void) fprintf(stderr, "%s: ", opts.o_progname);

	va_start(ap, opt_noperror);
	if (opt_noperror == NULL) {
		no_perror = 1;
		fmt = va_arg(ap, char *);
	} else
		fmt = opt_noperror;
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (no_perror)
		(void) fprintf(stderr, "\n");
	else {
		(void) fprintf(stderr, ": ");
		errno = saved_errno;
		perror("");
	}

	return (-1);
}


/*
 * The rest of the routines handle printing the raw prom devinfo (-p option).
 *
 * 128 is the size of the largest (currently) property name
 * 16k - MAXNAMESZ - sizeof (int) is the size of the largest
 * (currently) property value that is allowed.
 * the sizeof (uint_t) is from struct openpromio
 */

#define	MAXNAMESZ	128
#define	MAXVALSIZE	(16384 - MAXNAMESZ - sizeof (uint_t))
#define	BUFSIZE		(MAXNAMESZ + MAXVALSIZE + sizeof (uint_t))
typedef union {
	char buf[BUFSIZE];
	struct openpromio opp;
} Oppbuf;

static int prom_fd;
static uchar_t *prom_snapshot;

static int
is_openprom(void)
{
	Oppbuf	oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	unsigned int i;

	opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMGETCONS, opp) < 0)
		exit(_error("OPROMGETCONS"));

	i = (unsigned int)((unsigned char)opp->oprom_array[0]);
	return ((i & OPROMCONS_OPENPROM) == OPROMCONS_OPENPROM);
}

int
do_prominfo(void)
{
	uint_t arg = opts.o_verbose;

	if (promopen(O_RDONLY))  {
		exit(_error("openeepr device open failed"));
	}

	if (is_openprom() == 0)  {
		(void) fprintf(stderr, "System architecture does not "
		    "support this option of this command.\n");
		return (1);
	}

	/* OPROMSNAPSHOT returns size in arg */
	if (ioctl(prom_fd, OPROMSNAPSHOT, &arg) < 0)
		exit(_error("OPROMSNAPSHOT"));

	if (arg == 0)
		return (1);

	if ((prom_snapshot = malloc(arg)) == NULL)
		exit(_error("failed to allocate memory"));

	/* copy out the snapshot for printing */
	/*LINTED*/
	*(uint_t *)prom_snapshot = arg;
	if (ioctl(prom_fd, OPROMCOPYOUT, prom_snapshot) < 0)
		exit(_error("OPROMCOPYOUT"));

	promclose();

	/* print out information */
	walk(prom_snapshot, arg, 0);
	free(prom_snapshot);

	return (0);
}

static void
walk(uchar_t *buf, uint_t size, int level)
{
	int error;
	nvlist_t *nvl, *cnvl;
	nvpair_t *child = NULL;
	uchar_t *cbuf = NULL;
	uint_t csize;

	/* Expand to an nvlist */
	if (nvlist_unpack((char *)buf, size, &nvl, 0))
		exit(_error("error processing snapshot"));

	/* print current node */
	dump_node(nvl, level);

	/* print children */
	error = nvlist_lookup_byte_array(nvl, "@child", &cbuf, &csize);
	if ((error == ENOENT) || (cbuf == NULL))
		return;		/* no child exists */

	if (error || nvlist_unpack((char *)cbuf, csize, &cnvl, 0))
		exit(_error("error processing snapshot"));

	while (child = nvlist_next_nvpair(cnvl, child)) {
		char *name = nvpair_name(child);
		data_type_t type = nvpair_type(child);
		uchar_t *nodebuf;
		uint_t nodesize;
		if (strcmp("node", name) != 0) {
			dprintf("unexpected nvpair name %s != name\n", name);
			continue;
		}
		if (type != DATA_TYPE_BYTE_ARRAY) {
			dprintf("unexpected nvpair type %d, not byte array \n",
			    type);
			continue;
		}

		(void) nvpair_value_byte_array(child,
		    (uchar_t **)&nodebuf, &nodesize);
		walk(nodebuf, nodesize, level + 1);
	}

	nvlist_free(nvl);
}

/*
 * Print all properties and values
 */
static void
dump_node(nvlist_t *nvl, int level)
{
	int id = 0;
	char *name = NULL;
	nvpair_t *nvp = NULL;

	indent_to_level(level);
	(void) printf("Node");
	if (!opts.o_verbose) {
		if (nvlist_lookup_string(nvl, "name", &name))
			(void) printf("data not available");
		else
			(void) printf(" '%s'", name);
		(void) putchar('\n');
		return;
	}
	(void) nvlist_lookup_int32(nvl, "@nodeid", &id);
	(void) printf(" %#08x\n", id);

	while (nvp = nvlist_next_nvpair(nvl, nvp)) {
		name = nvpair_name(nvp);
		if (name[0] == '@')
			continue;

		print_one(nvp, level + 1);
	}
	(void) putchar('\n');
}

static const char *
path_state_name(di_path_state_t st)
{
	switch (st) {
		case DI_PATH_STATE_ONLINE:
			return ("online");
		case DI_PATH_STATE_STANDBY:
			return ("standby");
		case DI_PATH_STATE_OFFLINE:
			return ("offline");
		case DI_PATH_STATE_FAULT:
			return ("faulted");
	}
	return ("unknown");
}

/*
 * Print all phci's each client is connected to.
 */
static void
dump_pathing_data(int ilev, di_node_t node)
{
	di_path_t	pi = DI_PATH_NIL;
	di_node_t	phci_node;
	char		*phci_path;
	int		path_instance;
	int		firsttime = 1;

	if (node == DI_PATH_NIL)
		return;

	while ((pi = di_path_client_next_path(node, pi)) != DI_PATH_NIL) {

		/* It is not really a path if we failed to capture the pHCI */
		phci_node = di_path_phci_node(pi);
		if (phci_node == DI_NODE_NIL)
			continue;

		/* Print header for the first path */
		if (firsttime) {
			indent_to_level(ilev);
			firsttime = 0;
			ilev++;
			(void) printf("Paths from multipath bus adapters:\n");
		}

		/*
		 * Print the path instance and full "pathinfo" path, which is
		 * the same as the /devices devifo path had the device been
		 * enumerated under pHCI.
		 */
		phci_path = di_devfs_path(phci_node);
		if (phci_path) {
			path_instance = di_path_instance(pi);
			if (path_instance > 0) {
				indent_to_level(ilev);
				(void) printf("Path %d: %s/%s@%s\n",
				    path_instance, phci_path,
				    di_node_name(node),
				    di_path_bus_addr(pi));
			}
			di_devfs_path_free(phci_path);
		}

		/* print phci driver, instance, and path state information */
		indent_to_level(ilev);
		(void) printf("%s#%d (%s)\n", di_driver_name(phci_node),
		    di_instance(phci_node), path_state_name(di_path_state(pi)));

		(void) dump_prop_list(&pathprop_dumpops, NULL, ilev + 1,
		    pi, DDI_DEV_T_ANY, NULL);
	}
}

static int
dump_minor_data_links(di_devlink_t devlink, void *arg)
{
	int ilev = (intptr_t)arg;
	indent_to_level(ilev);
	(void) printf("dev_link=%s\n", di_devlink_path(devlink));
	return (DI_WALK_CONTINUE);
}

static void
dump_minor_data_paths(int ilev, di_minor_t minor,
    di_devlink_handle_t devlink_hdl)
{
	char	*path, *type;
	int	spec_type;

	/* get the path to the device and the minor node name */
	if ((path = di_devfs_minor_path(minor)) == NULL)
		exit(_error("failed to allocate memory"));

	/* display the path to this minor node */
	indent_to_level(ilev);
	(void) printf("dev_path=%s\n", path);

	if (devlink_hdl != NULL) {

		/* get the device minor node information */
		spec_type = di_minor_spectype(minor);
		switch (di_minor_type(minor)) {
			case DDM_MINOR:
				type = "minor";
				break;
			case DDM_ALIAS:
				type = "alias";
				break;
			case DDM_DEFAULT:
				type = "default";
				break;
			case DDM_INTERNAL_PATH:
				type = "internal";
				break;
			default:
				type = "unknown";
				break;
		}

		/* display the device minor node information */
		indent_to_level(ilev + 1);
		(void) printf("spectype=%s type=%s\n",
		    (spec_type == S_IFBLK) ? "blk" : "chr", type);

		/* display all the devlinks for this device minor node */
		(void) di_devlink_walk(devlink_hdl, NULL, path,
		    0, (void *)(intptr_t)(ilev + 1), dump_minor_data_links);
	}

	di_devfs_path_free(path);
}

static void
create_minor_list(di_node_t node)
{
	di_minor_t	minor, minor_head, minor_tail, minor_prev, minor_walk;
	int		major;

	/* if there are no minor nodes, bail */
	if (di_minor_next(node, DI_MINOR_NIL) == DI_MINOR_NIL)
		return;

	/*
	 * here we want to create lists of minor nodes with the same
	 * dev_t.  to do this we first sort all the minor nodes by devt.
	 *
	 * the algorithm used here is a bubble sort, so performance sucks.
	 * but it's probably ok here because most device instances don't
	 * have that many minor nodes.  also we're doing this as we're
	 * displaying each node so it doesn't look like we're pausing
	 * output for a long time.
	 */
	major = di_driver_major(node);
	minor_head = minor_tail = minor = DI_MINOR_NIL;
	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		dev_t	dev = di_minor_devt(minor);

		/* skip /pseudo/clone@0 minor nodes */
		if (major != major(dev))
			continue;

		minor_ptr_set(minor, DI_MINOR_NIL);
		if (minor_head == DI_MINOR_NIL) {
			/* this is the first minor node we're looking at */
			minor_head = minor_tail = minor;
			continue;
		}

		/*
		 * if the new dev is less than the old dev, update minor_head
		 * so it points to the beginning of the list.  ie it points
		 * to the node with the lowest dev value
		 */
		if (dev <= di_minor_devt(minor_head)) {
			minor_ptr_set(minor, minor_head);
			minor_head = minor;
			continue;
		}

		minor_prev = minor_head;
		minor_walk = minor_ptr(minor_head);
		while ((minor_walk != DI_MINOR_NIL) &&
		    (dev > di_minor_devt(minor_walk))) {
			minor_prev = minor_walk;
			minor_walk = minor_ptr(minor_walk);
		}
		minor_ptr_set(minor, minor_walk);
		minor_ptr_set(minor_prev, minor);
		if (minor_walk == NULL)
			minor_tail = minor;
	}

	/* check if there were any non /pseudo/clone@0 nodes.  if not, bail */
	if (minor_head == DI_MINOR_NIL)
		return;

	/*
	 * now that we have a list of minor nodes sorted by devt
	 * we walk through the list and break apart the entire list
	 * to create circular lists of minor nodes with matching devts.
	 */
	minor_prev = minor_head;
	minor_walk = minor_ptr(minor_head);
	while (minor_walk != DI_MINOR_NIL) {
		if (di_minor_devt(minor_prev) != di_minor_devt(minor_walk)) {
			minor_ptr_set(minor_prev, minor_head);
			minor_head = minor_walk;
		}
		minor_prev = minor_walk;
		minor_walk = minor_ptr(minor_walk);
	}
	minor_ptr_set(minor_tail, minor_head);
}

static void
link_lnode_disp(di_link_t link, uint_t endpoint, int ilev,
    di_devlink_handle_t devlink_hdl)
{
	di_lnode_t	lnode;
	char		*name, *path;
	int		displayed_path, spec_type;
	di_node_t	node = DI_NODE_NIL;
	dev_t		devt = DDI_DEV_T_NONE;

	lnode = di_link_to_lnode(link, endpoint);

	indent_to_level(ilev);
	name = di_lnode_name(lnode);
	spec_type = di_link_spectype(link);

	(void) printf("mod=%s", name);

	/*
	 * if we're displaying the source of a link, we should display
	 * the target access mode.  (either block or char.)
	 */
	if (endpoint == DI_LINK_SRC)
		(void) printf(" accesstype=%s",
		    (spec_type == S_IFBLK) ? "blk" : "chr");

	/*
	 * check if the lnode is bound to a specific device
	 * minor node (i.e.  if it's bound to a dev_t) and
	 * if so display the dev_t value and any possible
	 * minor node pathing information.
	 */
	displayed_path = 0;
	if (di_lnode_devt(lnode, &devt) == 0) {
		di_minor_t	minor = DI_MINOR_NIL;

		(void) printf(" dev=(%u,%u)\n",
		    (uint_t)major(devt), (uint_t)minor(devt));

		/* display paths to the src devt minor node */
		while (minor = di_minor_next(node, minor)) {
			if (devt != di_minor_devt(minor))
				continue;

			if ((endpoint == DI_LINK_TGT) &&
			    (spec_type != di_minor_spectype(minor)))
				continue;

			dump_minor_data_paths(ilev + 1, minor, devlink_hdl);
			displayed_path = 1;
		}
	} else {
		(void) printf("\n");
	}

	if (displayed_path)
		return;

	/*
	 * This device lnode is not did not have any minor node
	 * pathing information so display the path to device node.
	 */
	node = di_lnode_devinfo(lnode);
	if ((path = di_devfs_path(node)) == NULL)
		exit(_error("failed to allocate memory"));

	indent_to_level(ilev + 1);
	(void) printf("dev_path=%s\n", path);
	di_devfs_path_free(path);
}

static void
dump_minor_link_data(int ilev, di_node_t node, dev_t devt,
    di_devlink_handle_t devlink_hdl)
{
	int		first = 1;
	di_link_t	link;

	link = DI_LINK_NIL;
	while (link = di_link_next_by_node(node, link, DI_LINK_TGT)) {
		di_lnode_t	tgt_lnode;
		dev_t		tgt_devt = DDI_DEV_T_NONE;

		tgt_lnode = di_link_to_lnode(link, DI_LINK_TGT);

		if (di_lnode_devt(tgt_lnode, &tgt_devt) != 0)
			continue;

		if (devt != tgt_devt)
			continue;

		if (first) {
			first = 0;
			indent_to_level(ilev);
			(void) printf("Device Minor Layered Under:\n");
		}

		/* displayed this lnode */
		lnode_displayed_set(tgt_lnode);
		link_lnode_disp(link, DI_LINK_SRC, ilev + 1, devlink_hdl);
	}

	link = DI_LINK_NIL;
	while (link = di_link_next_by_node(node, link, DI_LINK_SRC)) {
		di_lnode_t	src_lnode;
		dev_t		src_devt = DDI_DEV_T_NONE;

		src_lnode = di_link_to_lnode(link, DI_LINK_SRC);

		if (di_lnode_devt(src_lnode, &src_devt) != 0)
			continue;

		if (devt != src_devt)
			continue;

		if (first) {
			first = 0;
			indent_to_level(ilev);
			(void) printf("Device Minor Layered Over:\n");
		}

		/* displayed this lnode */
		lnode_displayed_set(src_lnode);
		link_lnode_disp(link, DI_LINK_TGT, ilev + 1, devlink_hdl);
	}
}

static void
dump_minor_data(int ilev, di_node_t node, di_devlink_handle_t devlink_hdl)
{
	di_minor_t	minor, minor_next;
	di_lnode_t	lnode;
	di_link_t	link;
	int		major, firstminor = 1;

	/*
	 * first go through and mark all lnodes and minor nodes for this
	 * node as undisplayed
	 */
	lnode = DI_LNODE_NIL;
	while (lnode = di_lnode_next(node, lnode))
		lnode_displayed_clear(lnode);
	minor = DI_MINOR_NIL;
	while (minor = di_minor_next(node, minor)) {
		minor_displayed_clear(minor);
	}

	/*
	 * when we display the minor nodes we want to coalesce nodes
	 * that have the same dev_t.  we do this by creating circular
	 * lists of minor nodes with the same devt.
	 */
	create_minor_list(node);

	/* now we display the driver defined minor nodes */
	major = di_driver_major(node);
	minor = DI_MINOR_NIL;
	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		dev_t	devt;

		/*
		 * skip /pseudo/clone@0 minor nodes.
		 * these are only created for DLPIv2 network devices.
		 * since these minor nodes are associated with a driver
		 * and are only bound to a device instance after they
		 * are opened and attached we don't print them out
		 * here.
		 */
		devt = di_minor_devt(minor);
		if (major != major(devt))
			continue;

		/* skip nodes that may have already been displayed */
		if (minor_displayed(minor))
			continue;

		if (firstminor) {
			firstminor = 0;
			indent_to_level(ilev++);
			(void) printf("Device Minor Nodes:\n");
		}

		/* display the device minor node information */
		indent_to_level(ilev);
		(void) printf("dev=(%u,%u)\n",
		    (uint_t)major(devt), (uint_t)minor(devt));

		minor_next = minor;
		do {
			/* display device minor node path info */
			minor_displayed_set(minor_next);
			dump_minor_data_paths(ilev + 1, minor_next,
			    devlink_hdl);

			/* get a pointer to the next node */
			minor_next = minor_ptr(minor_next);
		} while (minor_next != minor);

		/* display who has this device minor node open */
		dump_minor_link_data(ilev + 1, node, devt, devlink_hdl);

		/* display properties associated with this devt */
		(void) dump_prop_list(&drvprop_dumpops, "Minor",
		    ilev + 1, node, devt, NULL);
	}

	/*
	 * now go through all the target lnodes for this node and
	 * if they haven't yet been displayed, display them now.
	 *
	 * this happens in the case of clone opens when an "official"
	 * minor node does not exist for the opened devt
	 */
	link = DI_LINK_NIL;
	while (link = di_link_next_by_node(node, link, DI_LINK_TGT)) {
		dev_t		devt;

		lnode = di_link_to_lnode(link, DI_LINK_TGT);

		/* if we've already displayed this target lnode, skip it */
		if (lnode_displayed(lnode))
			continue;

		if (firstminor) {
			firstminor = 0;
			indent_to_level(ilev++);
			(void) printf("Device Minor Nodes:\n");
		}

		/* display the device minor node information */
		indent_to_level(ilev);
		(void) di_lnode_devt(lnode, &devt);
		(void) printf("dev=(%u,%u)\n",
		    (uint_t)major(devt), (uint_t)minor(devt));

		indent_to_level(ilev + 1);
		(void) printf("dev_path=<clone>\n");

		/* display who has this cloned device minor node open */
		dump_minor_link_data(ilev + 1, node, devt, devlink_hdl);

		/* mark node as displayed */
		lnode_displayed_set(lnode);
	}
}

static void
dump_link_data(int ilev, di_node_t node, di_devlink_handle_t devlink_hdl)
{
	int		first = 1;
	di_link_t	link;

	link = DI_LINK_NIL;
	while (link = di_link_next_by_node(node, link, DI_LINK_SRC)) {
		di_lnode_t	src_lnode;
		dev_t		src_devt = DDI_DEV_T_NONE;

		src_lnode = di_link_to_lnode(link, DI_LINK_SRC);

		/*
		 * here we only want to print out layering information
		 * if we are the source and our source lnode is not
		 * associated with any particular dev_t.  (which means
		 * we won't display this link while dumping minor node
		 * info.)
		 */
		if (di_lnode_devt(src_lnode, &src_devt) != -1)
			continue;

		if (first) {
			first = 0;
			indent_to_level(ilev);
			(void) printf("Device Layered Over:\n");
		}

		/* displayed this lnode */
		link_lnode_disp(link, DI_LINK_TGT, ilev + 1, devlink_hdl);
	}
}

/*
 * certain 'known' property names may contain 'composite' strings.
 * Handle them here, and print them as 'string1' + 'string2' ...
 */
static int
print_composite_string(const char *var, char *value, int size)
{
	char *p, *q;
	char *firstp;

	if ((strcmp(var, "version") != 0) &&
	    (strcmp(var, "compatible") != 0))
		return (0);	/* Not a known composite string */

	/*
	 * Verify that each string in the composite string is non-NULL,
	 * is within the bounds of the property length, and contains
	 * printable characters or white space. Otherwise let the
	 * caller deal with it.
	 */
	for (firstp = p = value; p < (value + size); p += strlen(p) + 1) {
		if (strlen(p) == 0)
			return (0);		/* NULL string */
		for (q = p; *q; q++) {
			if (!(isascii(*q) && (isprint(*q) || isspace(*q))))
				return (0);	/* Not printable or space */
		}
		if (q > (firstp + size))
			return (0);		/* Out of bounds */
	}

	for (firstp = p = value; p < (value + size); p += strlen(p) + 1) {
		if (p == firstp)
			(void) printf("'%s'", p);
		else
			(void) printf(" + '%s'", p);
	}
	(void) putchar('\n');
	return (1);
}

/*
 * Print one property and its value. Handle the verbose case.
 */
static void
print_one(nvpair_t *nvp, int level)
{
	int i;
	int endswap = 0;
	uint_t valsize;
	char *value;
	char *var = nvpair_name(nvp);

	indent_to_level(level);
	(void) printf("%s: ", var);

	switch (nvpair_type(nvp)) {
	case DATA_TYPE_BOOLEAN:
		(void) printf(" \n");
		return;
	case DATA_TYPE_BYTE_ARRAY:
		if (nvpair_value_byte_array(nvp, (uchar_t **)&value,
		    &valsize)) {
			(void) printf("data not available.\n");
			return;
		}
		valsize--;	/* take out null added by driver */

		/*
		 * Do not print valsize > MAXVALSIZE, to be compatible
		 * with old behavior. E.g. intel's eisa-nvram property
		 * has a size of 65 K.
		 */
		if (valsize > MAXVALSIZE) {
			(void) printf(" \n");
			return;
		}
		break;
	default:
		(void) printf("data type unexpected.\n");
		return;
	}

	/*
	 * Handle printing verbosely
	 */
	if (print_composite_string(var, value, valsize)) {
		return;
	}

	if (!unprintable(value, valsize)) {
		(void) printf(" '%s'\n", value);
		return;
	}

	(void) printf(" ");
#ifdef	__x86
	/*
	 * Due to backwards compatibility constraints x86 int
	 * properties are not in big-endian (ieee 1275) byte order.
	 * If we have a property that is a multiple of 4 bytes,
	 * let's assume it is an array of ints and print the bytes
	 * in little endian order to make things look nicer for
	 * the user.
	 */
	endswap = (valsize % 4) == 0;
#endif	/* __x86 */
	for (i = 0; i < valsize; i++) {
		int out;
		if (i && (i % 4 == 0))
			(void) putchar('.');
		if (endswap)
			out = value[i + (3 - 2 * (i % 4))] & 0xff;
		else
			out = value[i] & 0xff;

		(void) printf("%02x", out);
	}
	(void) putchar('\n');
}

static int
unprintable(char *value, int size)
{
	int i;

	/*
	 * Is this just a zero?
	 */
	if (size == 0 || value[0] == '\0')
		return (1);
	/*
	 * If any character is unprintable, or if a null appears
	 * anywhere except at the end of a string, the whole
	 * property is "unprintable".
	 */
	for (i = 0; i < size; ++i) {
		if (value[i] == '\0')
			return (i != (size - 1));
		if (!isascii(value[i]) || iscntrl(value[i]))
			return (1);
	}
	return (0);
}

static int
promopen(int oflag)
{
	for (;;)  {
		if ((prom_fd = open(opts.o_promdev, oflag)) < 0)  {
			if (errno == EAGAIN)   {
				(void) sleep(5);
				continue;
			}
			if (errno == ENXIO)
				return (-1);
			if (getzoneid() == GLOBAL_ZONEID) {
				_exit(_error("cannot open %s",
				    opts.o_promdev));
			}
			/* not an error if this isn't the global zone */
			(void) _error(NULL, "openprom facility not available");
			exit(0);
		} else
			return (0);
	}
}

static void
promclose(void)
{
	if (close(prom_fd) < 0)
		exit(_error("close error on %s", opts.o_promdev));
}

/*
 * Get and print the name of the frame buffer device.
 */
int
do_fbname(void)
{
	int	retval;
	char fbuf_path[MAXPATHLEN];

	retval =  modctl(MODGETFBNAME, (caddr_t)fbuf_path);

	if (retval == 0) {
		(void) printf("%s\n", fbuf_path);
	} else {
		if (retval == EFAULT) {
			(void) fprintf(stderr,
			"Error copying fb path to userland\n");
		} else {
			(void) fprintf(stderr,
			"Console output device is not a frame buffer\n");
		}
		return (1);
	}
	return (0);
}

/*
 * Get and print the PROM version.
 */
int
do_promversion(void)
{
	Oppbuf	oppbuf;
	struct openpromio *opp = &(oppbuf.opp);

	if (promopen(O_RDONLY))  {
		(void) fprintf(stderr, "Cannot open openprom device\n");
		return (1);
	}

	opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMGETVERSION, opp) < 0)
		exit(_error("OPROMGETVERSION"));

	(void) printf("%s\n", opp->oprom_array);
	promclose();
	return (0);
}

int
do_prom_version64(void)
{
#ifdef	sparc
	Oppbuf	oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	/*LINTED*/
	struct openprom_opr64 *opr = (struct openprom_opr64 *)opp->oprom_array;

	static const char msg[] =
	    "NOTICE: The firmware on this system does not support the "
	    "64-bit OS.\n"
	    "\tPlease upgrade to at least the following version:\n"
	    "\t\t%s\n\n";

	if (promopen(O_RDONLY))  {
		(void) fprintf(stderr, "Cannot open openprom device\n");
		return (-1);
	}

	opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMREADY64, opp) < 0)
		exit(_error("OPROMREADY64"));

	if (opr->return_code == 0)
		return (0);

	(void) printf(msg, opr->message);

	promclose();
	return (opr->return_code);
#else
	return (0);
#endif
}

int
do_productinfo(void)
{
	di_node_t root, next_node;
	di_prom_handle_t promh;
	static const char *root_prop[] = { "name", "model", "banner-name",
					"compatible" };
	static const char *root_propv[] = { "name", "model", "banner-name",
					"compatible", "idprom" };
	static const char *oprom_prop[] = { "model", "version" };


	root = di_init("/", DINFOCPYALL);

	if (root == DI_NODE_NIL) {
		(void) fprintf(stderr, "di_init() failed\n");
		return (1);
	}

	promh = di_prom_init();

	if (promh == DI_PROM_HANDLE_NIL) {
		(void) fprintf(stderr, "di_prom_init() failed\n");
		return (1);
	}

	if (opts.o_verbose) {
		dump_prodinfo(promh, root, root_propv, "root",
		    NUM_ELEMENTS(root_propv));

		/* Get model and version properties under node "openprom" */
		next_node = find_node_by_name(promh, root, "openprom");
		if (next_node != DI_NODE_NIL)
			dump_prodinfo(promh, next_node, oprom_prop,
			    "openprom", NUM_ELEMENTS(oprom_prop));

	} else
		dump_prodinfo(promh, root, root_prop, "root",
		    NUM_ELEMENTS(root_prop));
	di_prom_fini(promh);
	di_fini(root);
	return (0);
}

di_node_t
find_node_by_name(di_prom_handle_t promh, di_node_t parent,
		char *node_name)
{
	di_node_t next_node;
	uchar_t *prop_valp;

	for (next_node = di_child_node(parent); next_node != DI_NODE_NIL;
	    next_node = di_sibling_node(next_node)) {
		int len;

		len = get_propval_by_name(promh, next_node, "name", &prop_valp);
		if ((len != -1) && (strcmp((char *)prop_valp, node_name) == 0))
			return (next_node);
	}
	return (DI_NODE_NIL);
}


int
get_propval_by_name(di_prom_handle_t promh, di_node_t node, const char *name,
			uchar_t **valp)
{
	int len;
	uchar_t *bufp;

	len = di_prom_prop_lookup_bytes(promh, node, name,
	    (uchar_t **)&bufp);
	if (len != -1) {
		*valp = (uchar_t *)malloc(len);
		(void) memcpy(*valp, bufp, len);
	}
	return (len);
}


static void
dump_prodinfo(di_prom_handle_t promh, di_node_t node, const char **propstr,
		char *node_name, int num)
{
	int out, len, index1, index, endswap = 0;
	uchar_t *prop_valp;

	for (index1 = 0; index1 < num; index1++) {
		len = get_propval_by_name(promh, node, propstr[index1],
		    &prop_valp);
		if (len != -1) {
			if (strcmp(node_name, "root"))
				(void) printf("%s ", node_name);

			(void) printf("%s: ", propstr[index1]);

			if (print_composite_string((const char *)
			    propstr[index1], (char *)prop_valp, len)) {
				free(prop_valp);
				continue;
			}

			if (!unprintable((char *)prop_valp, len)) {
				(void) printf(" %s\n", (char *)prop_valp);
				free(prop_valp);
				continue;
			}

			(void) printf(" ");
#ifdef  __x86
			endswap = (len % 4) == 0;
#endif  /* __x86 */
			for (index = 0; index < len; index++) {
				if (index && (index % 4 == 0))
					(void) putchar('.');
				if (endswap)
					out = prop_valp[index +
					    (3 - 2 * (index % 4))] & 0xff;
				else
					out = prop_valp[index] & 0xff;
				(void) printf("%02x", out);
			}
			(void) putchar('\n');
			free(prop_valp);
		}
	}
}

static int
dump_compatible(char *name, int ilev, di_node_t node)
{
	int	ncompat;
	char	*compat_array;
	char	*p, *q;
	int	i;

	if (node == DI_PATH_NIL)
		return (0);

	ncompat = di_compatible_names(node, &compat_array);
	if (ncompat <= 0)
		return (0);	/* no 'compatible' available */

	/* verify integrety of compat_array */
	for (i = 0, p = compat_array; i < ncompat; i++, p += strlen(p) + 1) {
		if (strlen(p) == 0)
			return (0);		/* NULL string */
		for (q = p; *q; q++) {
			if (!(isascii(*q) && (isprint(*q) || isspace(*q))))
				return (0);	/* Not printable or space */
		}
	}

	/* If name is non-NULL, produce header */
	if (name) {
		indent_to_level(ilev);
		(void) printf("%s properties:\n", name);
	}
	ilev++;

	/* process like a string array property */
	indent_to_level(ilev);
	(void) printf("name='compatible' type=string items=%d\n", ncompat);
	indent_to_level(ilev);
	(void) printf("    value=");
	for (i = 0, p = compat_array; i < (ncompat - 1);
	    i++, p += strlen(p) + 1)
		(void) printf("'%s' + ", p);
	(void) printf("'%s'", p);
	(void) putchar('\n');
	return (1);
}

static int
dump_pciid(char *name, int ilev, di_node_t node, pcidb_hdl_t *pci)
{
	char *t = NULL;
	int *vid, *did, *svid, *sdid;
	const char *vname, *dname, *sname;
	pcidb_vendor_t *pciv;
	pcidb_device_t *pcid;
	pcidb_subvd_t *pcis;
	di_node_t pnode = di_parent_node(node);

	const char *unov = "unknown vendor";
	const char *unod = "unknown device";
	const char *unos = "unknown subsystem";

	if (pci == NULL)
		return (0);

	vname = unov;
	dname = unod;
	sname = unos;

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, pnode,
	    "device_type", &t) <= 0)
		return (0);

	if (t == NULL || (strcmp(t, "pci") != 0 &&
	    strcmp(t, "pciex") != 0))
		return (0);

	/*
	 * All devices should have a vendor and device id, if we fail to find
	 * one, then we're going to return right here and not print anything.
	 *
	 * We're going to also check for the subsystem-vendor-id and
	 * subsystem-id. If we don't find one of them, we're going to assume
	 * that this device does not have one. In that case, we will never
	 * attempt to try and print anything related to that. If it does have
	 * both, then we are going to look them up and print the appropriate
	 * string if we find it or not.
	 */
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "vendor-id", &vid) <= 0)
		return (0);

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "device-id", &did) <= 0)
		return (0);

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "subsystem-vendor-id",
	    &svid) <= 0 || di_prop_lookup_ints(DDI_DEV_T_ANY, node,
	    "subsystem-id", &sdid) <= 0) {
		svid = NULL;
		sdid = NULL;
		sname = NULL;
	}

	pciv = pcidb_lookup_vendor(pci, vid[0]);
	if (pciv == NULL)
		goto print;
	vname = pcidb_vendor_name(pciv);

	pcid = pcidb_lookup_device_by_vendor(pciv, did[0]);
	if (pcid == NULL)
		goto print;
	dname = pcidb_device_name(pcid);

	if (svid != NULL) {
		pcis = pcidb_lookup_subvd_by_device(pcid, svid[0], sdid[0]);
		if (pcis == NULL)
			goto print;
		sname = pcidb_subvd_name(pcis);
	}

print:
	/* If name is non-NULL, produce header */
	if (name) {
		indent_to_level(ilev);
		(void) printf("%s properties:\n", name);
	}
	ilev++;

	/* These are all going to be single string properties */
	indent_to_level(ilev);
	(void) printf("name='vendor-name' type=string items=1\n");
	indent_to_level(ilev);
	(void) printf("    value='%s'\n", vname);

	indent_to_level(ilev);
	(void) printf("name='device-name' type=string items=1\n");
	indent_to_level(ilev);
	(void) printf("    value='%s'\n", dname);

	if (sname != NULL) {
		indent_to_level(ilev);
		(void) printf("name='subsystem-name' type=string items=1\n");
		indent_to_level(ilev);
		(void) printf("    value='%s'\n", sname);
	}

	return (0);
}
