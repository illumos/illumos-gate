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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation to interact with libdevinfo to find port nodes,
 * and information regarding each node (fru, port, location).
 */

#include <stdio.h>
#include <libdevinfo.h>
#include <picl.h>
#include <picltree.h>
#include <strings.h>
#include <stdlib.h>
#include <config_admin.h>
#include <sys/types.h>
#include <sys/obpdefs.h>
#include <sys/pci.h>
#include <picldefs.h>
#include "piclfrutree.h"

#include <syslog.h>

static di_prom_handle_t	prom_handle = DI_PROM_HANDLE_NIL;
extern int frutree_debug;

typedef struct {
	di_node_t rnode;
	char 	bus_addr[PICL_PROPNAMELEN_MAX];
	char 	path[PICL_PROPNAMELEN_MAX];
	void 	*arg;
	picl_errno_t retval;
} frutree_devinfo_t;

typedef struct p_info {
	frutree_port_type_t	type;
	int  geo_addr;
	int  instance;
	char drv_name[20];
	char bus_addr[20];
	char devfs_path[MAXPATHLEN];
	struct p_info	*next;
}port_info_t;

typedef struct {
	port_info_t	*first;
	port_info_t	*last;
	int		n_serial;
	int		n_parallel;
	int		n_network;
} plist_t;

static void
free_list(plist_t *listptr)
{
	port_info_t	*tmp;
	port_info_t	*nextptr;
	if (listptr == NULL)
		return;

	nextptr = listptr->first;
	while (nextptr != NULL) {
		tmp = nextptr;
		nextptr = nextptr->next;
		free(tmp);
	}
}

/* (callback function for qsort) compare the bus_addr */
static int
compare(const void *a, const void *b)
{
	port_info_t *pinfo1, *pinfo2;
	port_info_t **ptr2pinfo1, **ptr2pinfo2;

	ptr2pinfo1 = (port_info_t **)a;
	ptr2pinfo2 = (port_info_t **)b;

	pinfo1 = (port_info_t *)*ptr2pinfo1;
	pinfo2 = (port_info_t *)*ptr2pinfo2;
	return (strcmp(pinfo1->bus_addr, pinfo2->bus_addr));
}

/*
 * assigns GeoAddr property for ports based on bus-addr
 */
static picl_errno_t
assign_geo_addr(plist_t *list, frutree_port_type_t type)
{

	int i = 0;
	port_info_t **port_info = NULL;
	port_info_t *nextptr = NULL;
	int num_ports = 0;

	if (list == NULL) {
		return (PICL_FAILURE);
	}

	if (list->first == NULL) {
		return (PICL_SUCCESS);
	}

	switch (type) {
	case SERIAL_PORT:
	if (list->n_serial == 0) {
		return (PICL_SUCCESS);
	}
	num_ports = list->n_serial;
	break;

	case PARALLEL_PORT:
	if (list->n_parallel == 0) {
		return (PICL_SUCCESS);
	}
	num_ports = list->n_parallel;
	break;

	case NETWORK_PORT:
	if (list->n_network == 0) {
		return (PICL_SUCCESS);
	}
	num_ports = list->n_network;
	break;

	}

	port_info = (port_info_t **)malloc(
		sizeof (port_info_t *) * num_ports);
	if (port_info == NULL) {
		return (PICL_NOSPACE);
	}

	/* traverse thru list and look for ports of given type */
	nextptr = list->first;
	while (nextptr != NULL) {
		if (nextptr->type != type) {
			nextptr = nextptr->next;
			continue;
		}
		port_info[i] = nextptr;
		nextptr = nextptr->next;
		i++;
	}

	/* sort the nodes to assign geo_address */
	(void) qsort((void *)port_info, num_ports,
		sizeof (port_info_t *), compare);
	for (i = 0; i < num_ports; i++) {
		if (port_info[i] != NULL) {
			port_info[i]->geo_addr = i + 1;
		}
	}
	free(port_info);
	return (PICL_SUCCESS);
}

static picl_errno_t
create_port_config_info(plist_t *list, frutree_device_args_t *devp)
{
	port_info_t *port_info = NULL;
	frutree_cache_t	*cachep = NULL;
	char port_type[PICL_PROPNAMELEN_MAX];
	char label[PICL_PROPNAMELEN_MAX];

	if (list == NULL) {
		return (PICL_FAILURE);
	}

	port_info = list->first;
	while (port_info != NULL) {

		cachep = (frutree_cache_t *)malloc(sizeof (frutree_cache_t));
		if (cachep == NULL) {
			return (PICL_NOSPACE);
		}

		switch (port_info->type) {
		case NETWORK_PORT:
			(void) strncpy(label, SANIBEL_NETWORK_LABEL,
				sizeof (label));
			(void) strncpy(port_type, SANIBEL_NETWORK_PORT,
				sizeof (port_type));
			break;
		case PARALLEL_PORT:
			(void) strncpy(label, SANIBEL_PARALLEL_PORT,
				sizeof (label));
			(void) strncpy(port_type, SANIBEL_PARALLEL_PORT,
				sizeof (port_type));
			break;
		case SERIAL_PORT:
			(void) strncpy(label, SANIBEL_SERIAL_PORT,
				sizeof (label));
			(void) strncpy(port_type, SANIBEL_SERIAL_PORT,
				sizeof (port_type));
			break;
		default:
			port_info = port_info->next;
		}
		cachep->buf[0] = '\0';
		cachep->next = NULL;
		(void) snprintf(cachep->buf,
			sizeof (cachep->buf),
			"\n%s %s%d %s\n"
			"\t%s %s %s %s 0 \"%s %d\"\n"
			"\t%s %s %s %s 0 \"%s\"\n"
			"\t%s %s %s %s 1 %d\n"
			"\t%s %s %s %s 0 \"%s\"\n"
			"\t%s %s %s %s 0 \"%s\"\n"
			"%s\n",
			"NODE", port_info->drv_name, port_info->instance,
				PICL_CLASS_PORT,
			"PROP", PICL_PROP_LABEL, "string", "r",
				label, (port_info->geo_addr -1),
			"PROP", PICL_PROP_BUS_ADDR, "string",
				"r", port_info->bus_addr,
			"PROP", PICL_PROP_GEO_ADDR, "uint",
				"r", port_info->geo_addr,
			"PROP", PICL_PROP_PORT_TYPE, "string",
				"r", port_type,
			"PROP", PICL_PROP_DEVFS_PATH, "string",
				"r", port_info->devfs_path,
			"ENDNODE");

			/* add to the cache */
			if (devp->first == NULL) {	/* 1st node */
				devp->first = cachep;
				devp->last = NULL;
			} else if (devp->last != NULL) { /* last node */
				devp->last->next = cachep;
				devp->last = cachep;
			} else {			/* 2nd node */
				devp->first->next = cachep;
				devp->last = cachep;
			}
		port_info = port_info->next;	/* advance to next node */
	}
	return (PICL_SUCCESS);
}

/*ARGSUSED*/
static int
load_driver(di_node_t node, void *arg)
{
	char *drv_name = NULL;
	char cmd[MAXPATHLEN];

	if (di_node_state(node) >= DS_ATTACHED) {
		return (DI_WALK_CONTINUE);
	}
	drv_name = di_driver_name(node);
	if (drv_name == NULL) {
		return (DI_WALK_CONTINUE);
	}

	(void) snprintf(cmd, sizeof (cmd), "%s %s",
		DEVFSADM_CMD, drv_name);
	(void) pclose(popen(cmd, "r"));
	return (DI_WALK_CONTINUE);
}

static picl_errno_t
load_drivers(char *path)
{
	di_node_t	rnode;
	if (path == NULL) {
		return (PICL_INVALIDARG);
	}

	rnode = di_init(path, DINFOSUBTREE|DINFOMINOR);
	if (rnode == DI_NODE_NIL) {
		return (PICL_FAILURE);
	}

	if (di_walk_node(rnode, DI_WALK_CLDFIRST, NULL, load_driver) != 0) {
		di_fini(rnode);
		return (PICL_FAILURE);
	}

	di_fini(rnode);
	return (PICL_SUCCESS);
}

/*
 * probe for port nodes
 */
static int
probe_tree(di_node_t node, void *arg)
{
	char *nodetype = NULL;
	char *devfs_path = NULL;
	char *bus_addr = NULL;
	char *drv_name = NULL;
	plist_t *listptr = NULL;
	port_info_t *port_info = NULL;
	frutree_port_type_t port_type = UNKNOWN_PORT;
	di_minor_t minor = DI_MINOR_NIL;

	if (arg == NULL) {
		return (DI_WALK_TERMINATE);
	}
	listptr = (plist_t *)arg;

	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		nodetype = di_minor_nodetype(minor);
		if (nodetype == NULL) {
			continue;
		}

		if (strcmp(nodetype, DDI_NT_NET) == 0) {
			port_type = NETWORK_PORT;
		} else if (strcmp(nodetype, DDI_NT_PARALLEL) == 0) {
			port_type = PARALLEL_PORT;
		} else if ((strcmp(nodetype, DDI_NT_SERIAL) == 0) ||
			(strcmp(nodetype, DDI_NT_SERIAL_MB) == 0) ||
			(strcmp(nodetype, DDI_NT_SERIAL_DO) == 0) ||
			(strcmp(nodetype, DDI_NT_SERIAL_MB_DO) == 0)) {
			port_type = SERIAL_PORT;
		} else {
			continue;
		}

		/* found port node */
		devfs_path = di_devfs_path(node);
		if (devfs_path == NULL) {
			continue;
		}

		bus_addr = di_bus_addr(node);
		drv_name = di_driver_name(node);

		if ((bus_addr == NULL) || (drv_name == NULL)) {
			di_devfs_path_free(devfs_path);
			continue;
		}

		port_info = malloc(sizeof (port_info_t));
		if (port_info == NULL) {
			di_devfs_path_free(devfs_path);
			return (PICL_NOSPACE);
		}

		(void) strncpy(port_info->devfs_path, devfs_path,
			sizeof (port_info->devfs_path));
		(void) strncpy(port_info->bus_addr, bus_addr,
			sizeof (port_info->bus_addr));
		(void) strncpy(port_info->drv_name, drv_name,
			sizeof (port_info->drv_name));
		port_info->type = port_type;
		port_info->instance = di_instance(node);
		port_info->geo_addr = -1;
		port_info->next = NULL;

		switch (port_type) {
		case NETWORK_PORT:
			listptr->n_network++;
			break;
		case SERIAL_PORT:
			listptr->n_serial++;
			break;
		case PARALLEL_PORT:
			listptr->n_parallel++;
			break;
		}

		/* add to the list */
		if (listptr->first == NULL) {	/* 1st node */
			listptr->first = port_info;
			listptr->last = NULL;
		} else if (listptr->last != NULL) { /* last node */
			listptr->last->next = port_info;
			listptr->last = port_info;
		} else {			/* 2nd node */
			listptr->first->next = port_info;
			listptr->last = port_info;
		}
		di_devfs_path_free(devfs_path);
		return (DI_WALK_CONTINUE);
	}
	return (DI_WALK_CONTINUE);
}

/* This routine probes libdevinfo for port nodes */
picl_errno_t
probe_libdevinfo(frutree_frunode_t *frup, frutree_device_args_t ** device,
	boolean_t load_drv)
{
	di_node_t	rnode;
	picl_errno_t	rc;
	plist_t	list;

	if (frup == NULL) {
		return (PICL_FAILURE);
	}
	FRUTREE_DEBUG1(EVENTS, "loading drivers for %s", frup->name);

	if (load_drv == B_TRUE) {
		if ((rc = load_drivers(frup->fru_path)) != PICL_SUCCESS) {
			return (rc);
		}
	}
	FRUTREE_DEBUG1(EVENTS, "done with loading drivers for %s", frup->name);

	rnode = di_init(frup->fru_path, DINFOSUBTREE|DINFOMINOR);
	if (rnode == DI_NODE_NIL) {
		return (PICL_FAILURE);
	}

	list.first = NULL;
	list.last = NULL;
	list.n_network = 0;
	list.n_serial = 0;
	list.n_parallel = 0;

	if (di_walk_node(rnode, DI_WALK_CLDFIRST, &list, probe_tree) != 0) {
		di_fini(rnode);
		free_list(&list);
		return (PICL_FAILURE);
	}

	if (list.n_serial > 0)
	if ((rc = assign_geo_addr(&list, SERIAL_PORT)) != PICL_SUCCESS) {
		di_fini(rnode);
		free_list(&list);
		return (rc);
	}

	if (list.n_network > 0)
	if ((rc = assign_geo_addr(&list, NETWORK_PORT)) != PICL_SUCCESS) {
		di_fini(rnode);
		free_list(&list);
		return (rc);
	}

	if (list.n_parallel > 0)
	if ((rc = assign_geo_addr(&list, PARALLEL_PORT)) != PICL_SUCCESS) {
		di_fini(rnode);
		free_list(&list);
		return (rc);
	}

	if ((rc = create_port_config_info(&list, *device)) != PICL_SUCCESS) {
		di_fini(rnode);
		free_list(&list);
		return (rc);
	}

	di_fini(rnode);
	free_list(&list);
	FRUTREE_DEBUG1(EVENTS, "done with probing %s", frup->name);
	return (PICL_SUCCESS);
}

static int
get_reg_dev(di_node_t node)
{
	int *reg = NULL;
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, OBP_REG, &reg) < 0) {
		if (di_prom_prop_lookup_ints(prom_handle, node, OBP_REG,
			&reg) < 0) {
			return (-1);
		}
		return (PCI_REG_DEV_G(reg[0]));
	}
	return (PCI_REG_DEV_G(reg[0]));
}

static int
walk_tree(di_node_t node, void *arg)
{
	char	*path = NULL;
	char	*bus_addr = NULL;
	char	*char_di_bus_addr = NULL;
	int	busaddr = 0;
	int	di_busaddr = 0;
	char 	*node_name = NULL;
	frutree_devinfo_t *devinfo;
	frutree_frunode_t *frup = NULL;

	devinfo = *(frutree_devinfo_t **)arg;
	frup = (frutree_frunode_t *)devinfo->arg;
	if (frup == NULL) {
		return (DI_WALK_TERMINATE);
	}

	if (devinfo->rnode == node) {	/* skip the root node */
		return (DI_WALK_CONTINUE);
	}
	bus_addr = devinfo->bus_addr;

	char_di_bus_addr = di_bus_addr(node);
	if (char_di_bus_addr == NULL) {
		/*
		 * look for reg property
		 * This applies to only cPCI devices
		 */
		if (strstr(bus_addr, ",") != NULL) {
			/* bus addr is of type 1,0 */
			/* we dont handle this case yet */
			return (DI_WALK_PRUNECHILD);
		}
		di_busaddr = get_reg_dev(node);
		if (di_busaddr == -1) {
			/* reg prop not found */
			return (DI_WALK_PRUNECHILD);
		}

		/* check if the bus addresses are same */
		errno = 0;
		busaddr = strtol(bus_addr, (char **)NULL, 16);
		if (errno != 0) {
			return (DI_WALK_TERMINATE);
		}
		if (di_busaddr != busaddr) {
			return (DI_WALK_PRUNECHILD);
		}

		/* build the fru path name */
		/* parent_path/nodename@bus_addr */
		node_name = di_node_name(node);
		if (node_name == NULL) {
			return (DI_WALK_TERMINATE);
		}
		(void) snprintf(devinfo->path, sizeof (devinfo->path),
			"%s/%s@%s", frup->fru_path, node_name, bus_addr);
		return (DI_WALK_TERMINATE);
	}

	if (strstr(bus_addr, ",") != NULL) { /* bus addr is of type 1,0 */
		if (strcmp(bus_addr, char_di_bus_addr) != 0) {
			return (DI_WALK_PRUNECHILD);
		}
	} else { /* bus addr is of type 0x */

		/* check if the values are same */
		errno = 0;
		busaddr = strtol(bus_addr, (char **)NULL, 16);
		if (errno != 0) {
			return (DI_WALK_TERMINATE);
		}

		errno = 0;
		di_busaddr = strtol(char_di_bus_addr, (char **)NULL, 16);
		if (errno != 0) {
			return (DI_WALK_TERMINATE);
		}

		if (di_busaddr != busaddr) {
			return (DI_WALK_PRUNECHILD);
		}
	}

	/* node found */
	path = di_devfs_path(node);
	(void) strncpy(devinfo->path, path, sizeof (devinfo->path));
	di_devfs_path_free(path);
	return (DI_WALK_TERMINATE);
}

picl_errno_t
get_fru_path(char *parent_path, frutree_frunode_t *frup)
{
	picl_errno_t rc = 0;
	picl_nodehdl_t loch;
	di_node_t rnode;
	frutree_devinfo_t *devinfo = NULL;
	char slot_type[PICL_PROPNAMELEN_MAX];
	char probe_path[PICL_PROPNAMELEN_MAX];
	char bus_addr[PICL_PROPNAMELEN_MAX];

	if ((rc = ptree_get_propval_by_name(frup->frunodeh, PICL_PROP_PARENT,
		&loch, sizeof (loch))) != PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = ptree_get_propval_by_name(loch, PICL_PROP_SLOT_TYPE,
		slot_type, sizeof (slot_type))) != PICL_SUCCESS) {
		return (rc);
	}

	if (strcmp(slot_type, SANIBEL_SCSI_SLOT) == 0 ||
		strcmp(slot_type, SANIBEL_IDE_SLOT) == 0) {
		if (ptree_get_propval_by_name(loch, PICL_PROP_PROBE_PATH,
			probe_path, sizeof (probe_path)) != PICL_SUCCESS) {
			return (rc);
		}
		(void) strncpy(frup->fru_path, probe_path,
			sizeof (frup->fru_path));
		return (PICL_SUCCESS);
	}

	prom_handle = di_prom_init();
	rnode = di_init(parent_path, DINFOSUBTREE|DINFOMINOR);
	if (rnode == DI_NODE_NIL) {
		di_prom_fini(prom_handle);
		return (PICL_FAILURE);
	}

	devinfo = (frutree_devinfo_t *)malloc(sizeof (frutree_devinfo_t));
	if (devinfo == NULL) {
		di_fini(rnode);
		di_prom_fini(prom_handle);
		return (PICL_NOSPACE);
	}

	if (ptree_get_propval_by_name(loch, PICL_PROP_BUS_ADDR,
		bus_addr, sizeof (bus_addr)) != PICL_SUCCESS) {
		free(devinfo);
		di_fini(rnode);
		di_prom_fini(prom_handle);
		return (rc);
	}

	devinfo->rnode = rnode;
	(void) strncpy(devinfo->bus_addr, bus_addr, sizeof (devinfo->bus_addr));
	devinfo->path[0] = '\0';
	devinfo->arg = frup;

	if (di_walk_node(rnode, DI_WALK_SIBFIRST, &devinfo, walk_tree) != 0) {
		di_fini(rnode);
		di_prom_fini(prom_handle);
		free(devinfo);
		return (PICL_FAILURE);
	}
	di_fini(rnode);
	di_prom_fini(prom_handle);

	if (devinfo->path[0]) {
		(void) strncpy(frup->fru_path, devinfo->path,
			sizeof (frup->fru_path));
		free(devinfo);
		return (PICL_SUCCESS);
	} else {
		free(devinfo);
		return (PICL_NODENOTFOUND);
	}
}

static int
find_fru_node(di_node_t node, void *arg)
{
	frutree_locnode_t *locp = NULL;
	char	*char_di_bus_addr = NULL;
	int	busaddr = 0;
	int	di_busaddr = 0;
	char bus_addr[PICL_PROPNAMELEN_MAX];
	frutree_devinfo_t *devinfo = NULL;

	devinfo = *(frutree_devinfo_t **)arg;
	locp = *(frutree_locnode_t **)devinfo->arg;

	if (devinfo->rnode == node) {
		return (DI_WALK_CONTINUE);
	}

	char_di_bus_addr = di_bus_addr(node);
	if (char_di_bus_addr == NULL) {
		return (DI_WALK_PRUNECHILD);
	}

	if (ptree_get_propval_by_name(locp->locnodeh, PICL_PROP_BUS_ADDR,
		bus_addr, sizeof (bus_addr)) != PICL_SUCCESS) {
		return (DI_WALK_PRUNECHILD);
	}

	if (strstr(bus_addr, ",") != NULL) {
		/* bus addr is of type 1,0 */
		if (strcmp(bus_addr, char_di_bus_addr) == 0) {
			devinfo->retval = PICL_SUCCESS;
			return (DI_WALK_TERMINATE);
		} else {
			return (DI_WALK_PRUNECHILD);
		}
	} else { /* bus addr is of type 0x */

		/* check if the values are same */
		errno = 0;
		busaddr = strtol(bus_addr, (char **)NULL, 16);
		if (errno != 0) {
			return (DI_WALK_PRUNECHILD);
		}

		errno = 0;
		di_busaddr = strtol(char_di_bus_addr, (char **)NULL, 16);
		if (errno != 0) {
			return (DI_WALK_PRUNECHILD);
		}

		if (di_busaddr == busaddr) {
			devinfo->retval = PICL_SUCCESS;
			return (DI_WALK_TERMINATE);
		} else {
			return (DI_WALK_PRUNECHILD);
		}
	}
}

/*
 * checks if a fru is present under location using pdev-path and busaddr
 */
boolean_t
is_fru_present_under_location(frutree_locnode_t *locp)
{
	di_node_t		rnode;
	frutree_devinfo_t	*devinfo = NULL;
	char probe_path[PICL_PROPNAMELEN_MAX];

	if (locp == NULL) {
		return (B_FALSE);
	}

	if (ptree_get_propval_by_name(locp->locnodeh, PICL_PROP_PROBE_PATH,
		probe_path, sizeof (probe_path)) != PICL_SUCCESS) {
		if (ptree_get_propval_by_name(locp->locnodeh,
			PICL_PROP_DEVFS_PATH, probe_path,
			sizeof (probe_path)) != PICL_SUCCESS) {
			return (B_FALSE);
		}
	}

	rnode = di_init(probe_path, DINFOSUBTREE);
	if (rnode == DI_NODE_NIL) {
		di_fini(rnode);
		return (B_FALSE);
	}

	devinfo = (frutree_devinfo_t *)malloc(sizeof (frutree_devinfo_t));
	if (devinfo == NULL) {
		di_fini(rnode);
		return (B_FALSE);
	}
	devinfo->rnode = rnode;
	devinfo->arg = (frutree_locnode_t **)&locp;
	devinfo->retval = PICL_FAILURE;

	if (di_walk_node(rnode, DI_WALK_SIBFIRST, &devinfo,
		find_fru_node) != 0) {
		di_fini(rnode);
		free(devinfo);
		return (B_FALSE);
	}
	di_fini(rnode);

	if (devinfo->retval == PICL_SUCCESS) {
		free(devinfo);
		return (B_TRUE);
	} else {
		free(devinfo);
		return (B_FALSE);
	}
}

/*
 * initializes the port driver and instance fields based on libdevinfo
 */
picl_errno_t
get_port_info(frutree_portnode_t *portp)
{
	picl_errno_t rc;
	di_node_t rnode, curr, peer;
	char devfs_path[PICL_PROPNAMELEN_MAX];
	char bus_addr[PICL_PROPNAMELEN_MAX];
	char *di_busaddr = NULL, *di_drv = NULL;
	int di_int_busaddr, int_busaddr;

	if ((rc = ptree_get_propval_by_name(portp->portnodeh,
		PICL_PROP_DEVFS_PATH, devfs_path,
		sizeof (devfs_path))) != PICL_SUCCESS) {
		return (rc);
	}

	if (ptree_get_propval_by_name(portp->portnodeh, PICL_PROP_BUS_ADDR,
		bus_addr, sizeof (bus_addr)) != PICL_SUCCESS) {
		return (rc);
	}

	rnode = di_init(devfs_path, DINFOCPYALL);
	if (rnode == DI_NODE_NIL) {
		return (PICL_FAILURE);
	}

	peer = di_child_node(rnode);
	while (peer != DI_NODE_NIL) {
		curr = peer;
		peer = di_sibling_node(curr);

		di_busaddr = di_bus_addr(curr);
		if (di_busaddr == NULL) {
			continue;
		}

		/* compare the bus_addr */
		if (strstr(bus_addr, ",") != NULL) {
			/* bus addr is of type 1,0 */
			if (strcmp(bus_addr, di_busaddr) != 0) {
				continue;
			}
		} else { /* bus addr is of type 0x */
			errno = 0;
			int_busaddr = strtol(bus_addr, (char **)NULL, 16);
			if (errno != 0) {
				continue;
			}

			errno = 0;
			di_int_busaddr = strtol(di_busaddr, (char **)NULL, 16);
			if (errno != 0) {
				continue;
			}

			if (di_int_busaddr != int_busaddr) {
				continue;
			}
		}
		di_drv = di_driver_name(curr);
		if (di_drv == NULL) {
			di_fini(rnode);
			return (PICL_FAILURE);
		}
		/* initialize the driver name and instance number */
		(void) strncpy(portp->driver, di_drv, sizeof (portp->driver));
		portp->instance = di_instance(curr);
		di_fini(rnode);
		return (PICL_SUCCESS);
	}
	di_fini(rnode);
	return (PICL_NODENOTFOUND);
}
