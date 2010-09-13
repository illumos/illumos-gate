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

/* implementation specific to scsi nodes probing */

#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/param.h>
#include <config_admin.h>
#include <string.h>
#include <strings.h>
#include <picl.h>
#include <picltree.h>
#include <libintl.h>
#include <libdevinfo.h>
#include <sys/types.h>
#include <picldefs.h>
#include "piclfrutree.h"

#define	SCSI_SLOT	"scsi-bus"
#define	SCSI_LOC_FORMAT	"t%dd0"
#define	TARGET		"target"
#define	CLASS		"class"
#define	BUF_SIZE	256

#define	SCSI_INITIATOR_ID	7
#define	DRV_TYPE_DSK	1
#define	DRV_TYPE_TAPE	2
#define	NUM_DSK_TARGS	15
/*
 * No support for wide tapes for now.
 * If required wide support, set this to 8
 * See st.conf.
 */
#define	NUM_TAPE_TARGS	7

#define	DIRLINK_DSK	"dsk"
#define	DIRLINK_RMT	"rmt"
#define	DRV_SCSI_DSK	"sd"
#define	DRV_SCSI_TAPE	"st"
#define	NULL_ENTRY	0

/* currently supported directory strings for SCSI FRUs in cfgadm APs */
static char *scsi_dirlink_names[] = { DIRLINK_DSK, DIRLINK_RMT, NULL_ENTRY};
/* currently supported SCSI FRU drivers */
static struct scsi_drv_info {
	char *drv_name;
	uint8_t num_targets;
	uint8_t drv_type;
} scsi_drv[] = {
		DRV_SCSI_DSK, NUM_DSK_TARGS, DRV_TYPE_DSK,
		DRV_SCSI_TAPE, NUM_TAPE_TARGS, DRV_TYPE_TAPE,
		NULL_ENTRY,	NULL_ENTRY,	NULL_ENTRY
		};

/* the following defs are based on defines in scsi cfgadm plugin */
#define	CDROM		"CD-ROM"
#define	RMM		"tape"
#define	DISK		"disk"

extern boolean_t is_location_present_in_subtree(frutree_frunode_t *,
	const char *, const char *);
extern picl_errno_t create_children(frutree_frunode_t *, char *, char *,
	int, char *, boolean_t);
extern char *strtok_r(char *s1, const char *s2, char **lasts);
extern boolean_t frutree_connects_initiated;
extern int frutree_debug;

typedef struct node {
	struct node *next;
	cfga_list_data_t *data;
} node_t;

typedef struct linked_list {
	node_t *first;
	int num_nodes;
} plist_t;

typedef struct scsi_info {
	frutree_frunode_t *frup;
	cfga_list_data_t *cfgalist;
	plist_t *list;
	int num_list;
	boolean_t compare_cfgadm;
	int geo_addr;
} scsi_info_t;

static plist_t *scsi_list = NULL;
static cfga_list_data_t *cfglist = NULL;
static int nlist = 0;

static void
free_list(plist_t *list)
{
	node_t	*tmp = NULL, *tmp1 = NULL;

	if (list == NULL)
		return;
	tmp = list->first;
	while (tmp != NULL) {
		free(tmp->data);
		tmp1 = tmp->next;
		free(tmp);
		tmp = tmp1;
	}
}

/*
 * This routine gets the list of scsi controllers present
 */
static cfga_err_t
populate_controllers_list(plist_t *cntrl_list, cfga_list_data_t *list, int num)
{
	int i;
	node_t *nodeptr = NULL;
	cfga_list_data_t *temp = NULL;

	if (cntrl_list == NULL || list == NULL) {
		return (CFGA_ATTR_INVAL);
	}

	cntrl_list->first = NULL;
	cntrl_list->num_nodes = 0;

	if (num == 0) {
		return (CFGA_OK);
	}

	for (i = 0; i < num; i++) {
		if (strcmp(list[i].ap_type, SCSI_SLOT) != 0) {
			continue;
		}

		/* scsi controller */
		temp = (cfga_list_data_t *)malloc(sizeof (cfga_list_data_t));
		if (temp == NULL) {
			return (CFGA_ERROR);
		}
		(void) memcpy(temp, &list[i], sizeof (cfga_list_data_t));

		nodeptr = (node_t *)malloc(sizeof (node_t));
		if (nodeptr == NULL) {
			free(temp);
			return (CFGA_ERROR);
		}
		nodeptr->data = temp;
		nodeptr->next = NULL;

		/* append to the list */
		if (cntrl_list->first == NULL) {
			cntrl_list->first = nodeptr;
			cntrl_list->num_nodes++;
		} else {
			nodeptr->next = cntrl_list->first;
			cntrl_list->first = nodeptr;
			cntrl_list->num_nodes++;
		}
	}
	return (CFGA_OK);
}

picl_errno_t
scsi_info_init()
{
	cfga_err_t	ap_list_err;

	ap_list_err = config_list_ext(0, NULL, &cfglist, &nlist, NULL,
		NULL, NULL, CFGA_FLAG_LIST_ALL);

	if (ap_list_err != CFGA_OK) {
		if (ap_list_err == CFGA_NOTSUPP) {
			return (PICL_SUCCESS);
		} else {
			return (PICL_FAILURE);
		}
	}

	scsi_list = (plist_t *)malloc(sizeof (plist_t));
	if (scsi_list == NULL) {
		free(cfglist);
		return (PICL_NOSPACE);
	}

	ap_list_err = populate_controllers_list(scsi_list, cfglist, nlist);
	if (ap_list_err != CFGA_OK) {
		free(cfglist);
		free(scsi_list);
		return (PICL_FAILURE);
	}
	return (PICL_SUCCESS);
}

void
scsi_info_fini()
{
	free(cfglist);
	free_list(scsi_list);
	free(scsi_list);
}

/*
 * This routine searches the controllers list to find the mapping based
 * on given devfs_path.
 * caller should allocate memory for ap_id
 */
static picl_errno_t
find_scsi_controller(char *devfs_path, plist_t *list, char *ap_id)
{
	node_t	*tmp = NULL;
	char *lasts = NULL;
	char *token = NULL;
	char path[MAXPATHLEN];

	if (devfs_path == NULL || ap_id == NULL) {
		return (PICL_INVALIDARG);
	}
	(void) snprintf((char *)path, sizeof (path), "/devices%s", devfs_path);

	tmp = list->first;
	while (tmp != NULL) {
		lasts = tmp->data->ap_phys_id;
		token = (char *)strtok_r(lasts, (const char *)":",
			(char **)&lasts);
		if (token == NULL) {
			tmp = tmp->next;
			continue;
		}

		if (strcmp(path, token) == 0) {	/* match found */
			(void) strncpy(ap_id, tmp->data->ap_log_id,
				sizeof (ap_id));
			return (PICL_SUCCESS);
		}
		tmp = tmp->next;
	}
	return (PICL_NODENOTFOUND);
}

/*
 * This routine dynamically determines the cfgadm attachment point
 * for a given devfspath and target id.
 * memory for name should be allocated by the caller.
 */
picl_errno_t
get_scsislot_name(char *devfs_path, char *bus_addr, char *name)
{
	picl_errno_t	rc;
	int target_id = 0;
	int numlist;
	plist_t			list;
	cfga_err_t		ap_list_err;
	cfga_list_data_t 	*cfgalist = NULL;
	char controller[MAXPATHLEN];

	ap_list_err = config_list_ext(0, NULL, &cfgalist,
		&numlist, NULL, NULL, NULL, CFGA_FLAG_LIST_ALL);
	if (ap_list_err != CFGA_OK) {
		return (PICL_NODENOTFOUND);
	}

	ap_list_err = populate_controllers_list(&list, cfgalist,
		numlist);
	if (ap_list_err != CFGA_OK) {
		free_list(&list);
		free(cfgalist);
		return (PICL_NODENOTFOUND);
	}

	if (list.num_nodes <= 0) {
		free(cfgalist);
		return (PICL_NODENOTFOUND);
	}

	if ((rc = find_scsi_controller(devfs_path, &list,
		controller)) != PICL_SUCCESS) {
		free(cfgalist);
		free_list(&list);
		return (rc);
	}
	target_id = strtol(bus_addr, (char **)NULL, 16);
	(void) sprintf(name, "%s::dsk/%st%dd0", controller,
		controller, target_id);
	free(cfgalist);
	free_list(&list);
	return (PICL_SUCCESS);
}

/*
 * Arg scsi_loc can be any of the following forms appearing in cfgadm output
 *	c0::dsk/c0t0d0
 *	c1::sd56
 *	c2::rmt/0
 *	c3::st41
 *	dsk/c1t1d0
 *	rmt/1
 *	/devices/pci@1f,0/pci@1,1/scsi@2:scsi::dsk/c0t0d0
 *
 *	On return, bus_addr contains the target id of the device.
 *	Please note that currently the target id is computed. It is better
 *	to eventually change this to getting from libdevinfo.
 *	Also, please note that SCSI_INITIATOR_ID should not
 *	be hardcoded, but should be dynamically retrieved from an OBP property.
 */
static void
get_bus_addr(char *scsi_loc, char **bus_addr)
{
	char *ap, *token, *p, *ap_idp;
	int len = 0, i = 0;
	char parse_link = 0;
	char addr[BUF_SIZE], ap_id[BUF_SIZE];
	char fileinfo[BUF_SIZE], ap_id_link[BUF_SIZE];

	(void) strncpy(ap_id, scsi_loc, sizeof (ap_id));
	ap = strrchr(ap_id, ':');
	if (!ap)
		ap = ap_idp = ap_id;
	else
		ap_idp = ++ap;

	while (scsi_dirlink_names[i] && !len) {
		len = strspn(ap, scsi_dirlink_names[i++]);
		/*
		 * strspn may return positive len even when there is no
		 * complete string matches!!! hence the following check is
		 * necessary. So ensure the string match.
		 */
		if (len && strstr(ap, scsi_dirlink_names[i-1]))
			break;
		len = 0;
	}
	if (len)
		parse_link = 1;
	else {
		i = 0;
		while (scsi_drv[i].drv_name && !len) {
			len = strspn(ap, scsi_drv[i++].drv_name);
			if (len && strstr(ap, scsi_drv[i-1].drv_name))
				break;
			len = 0;
		}
	}
	ap += len;
	if (strlen(ap) && parse_link) {

		/* slice 0 must be present in the system */
		if (strstr(ap, "/c")) {
			if (strstr(ap, "s0") == NULL)
				(void) strcat(ap, "s0");
		}
		/* get the devlink and read the target id from minor node */
		(void) snprintf(ap_id_link, sizeof (ap_id_link), "/dev/%s",
			ap_idp);
		(void) bzero(fileinfo, sizeof (fileinfo));
		if (readlink(ap_id_link, fileinfo, sizeof (fileinfo)) < 0)
			return;
		if (!fileinfo[0])
			return;
		ap = strrchr(fileinfo, '@');
		ap++;
	}
	token = (char *)strtok_r(ap, ",", &p);
	(void) strncpy(addr, token, sizeof (addr));
	if (!parse_link) {
		int drv_inst = atoi(token);
		int tmp_targ_id = drv_inst % scsi_drv[i-1].num_targets;
		int targ_id = scsi_drv[i-1].drv_type == DRV_TYPE_DSK ?
			(tmp_targ_id < SCSI_INITIATOR_ID ?
			tmp_targ_id : tmp_targ_id+1):
			DRV_TYPE_TAPE ? tmp_targ_id : drv_inst;
		(void) snprintf(addr, sizeof (addr), "%d", targ_id);
	}
	if (strlen(addr)) {
		*bus_addr = (char *)malloc(strlen(addr)+1);
		if ((*bus_addr) == NULL)
			return;
		(void) strcpy((char *)*bus_addr, addr);
	}
}

/*
 * This routine determines all the scsi nodes under a FRU and
 * creates a subtree of all the scsi nodes with basic properties.
 */
static picl_errno_t
dyn_probe_for_scsi_frus(frutree_frunode_t *frup, cfga_list_data_t *cfgalist,
	plist_t *list, int numlist)
{
	picl_errno_t rc;
	int i, geo_addr = 0;
	node_t *curr = NULL;
	char *bus_addr = NULL;
	char path[MAXPATHLEN];
	char controller_name[MAXPATHLEN];

	/* for each controller in the list, find if disk/fru is present */
	curr = list->first;
	while (curr != NULL) {
		/* compare the path */
		(void) snprintf((char *)path, sizeof (path),  "/devices%s",
			frup->fru_path);
		if (strstr(curr->data->ap_phys_id, path) == NULL) {
			curr = curr->next;
			continue;

		}
		(void) snprintf(controller_name, sizeof (controller_name),
			"%s::", curr->data->ap_log_id);

		for (i = 0; i < numlist; i++) {
			if (strcmp(cfgalist[i].ap_type, SCSI_SLOT) == 0) {
				continue;
			}
			if (strstr(cfgalist[i].ap_log_id,
				controller_name) == NULL) {
				continue;
			}
			/* check if device is under fru */
			if (strstr(cfgalist[i].ap_phys_id, path) == NULL) {
				continue;
			}

			/* we found a scsi fru */
			geo_addr++;
			/* check if the device is present in subtree */
			if (is_location_present_in_subtree(frup,
				cfgalist[i].ap_log_id, path) == B_TRUE) {
				continue;
			}
			get_bus_addr(cfgalist[i].ap_log_id, &bus_addr);
			if (bus_addr == NULL) {
				continue;
			}
			rc = create_children(frup, cfgalist[i].ap_log_id,
				bus_addr, geo_addr, SANIBEL_SCSI_SLOT, B_TRUE);
			free(bus_addr);
			if (rc != PICL_SUCCESS) {
				FRUTREE_DEBUG3(FRUTREE_INIT, "SUNW_frutree:"
				"Error in creating node %s under %s(error=%d)",
					cfgalist[i].ap_log_id, frup->name, rc);
			}
		}
		curr = curr->next;
	}
	return (PICL_SUCCESS);
}

/*
 * data used here is cached information (cfglist, nlist)
 */
static picl_errno_t
cache_probe_for_scsi_frus(frutree_frunode_t *frup)
{
	int i, geo_addr = 0;
	picl_errno_t rc;
	node_t *curr = NULL;
	char path[MAXPATHLEN];
	char controller_name[MAXPATHLEN];
	char *bus_addr = NULL;

	/* for each controller in the list, find if disk/fru is present */
	if (scsi_list == NULL) {
		return (PICL_SUCCESS);
	}
	curr = scsi_list->first;
	while (curr != NULL) {
		/* compare the path */
		(void) snprintf((char *)path, sizeof (path), "/devices%s",
			frup->fru_path);
		if (strstr(curr->data->ap_phys_id, path) == NULL) {
			curr = curr->next;
			continue;
		}
		(void) snprintf(controller_name, sizeof (controller_name),
			"%s::", curr->data->ap_log_id);

		for (i = 0; i < nlist; i++) {
			if (strcmp(cfglist[i].ap_type, SCSI_SLOT) == 0) {
				continue;
			}
			if (strstr(cfglist[i].ap_log_id,
				controller_name) == NULL) {
				continue;
			}
			/* check if the device is under fru */
			if (strstr(cfglist[i].ap_phys_id, path) == NULL) {
				continue;
			}

			/* we found a scsi fru */
			geo_addr++;
			/* check if the device is present in subtree */
			if (is_location_present_in_subtree(frup,
				cfglist[i].ap_log_id, path) == B_TRUE) {
				continue;
			}
			get_bus_addr(cfglist[i].ap_log_id, &bus_addr);
			if (bus_addr == NULL) {
				continue;
			}
			rc = create_children(frup, cfglist[i].ap_log_id,
				bus_addr, geo_addr, SANIBEL_SCSI_SLOT, B_TRUE);
			free(bus_addr);
			if (rc != PICL_SUCCESS) {
				FRUTREE_DEBUG3(FRUTREE_INIT, "SUNW_frutree:"
				"Error in creating node %s under %s(error=%d)",
					cfglist[i].ap_log_id, frup->name, rc);
			}
		}
		curr = curr->next;
	}
	return (PICL_SUCCESS);
}

/*
 * This routine checks if the node (scsi device) is present in cfgadm data
 * Algorithm:
 * 1. traverse thru list of controllers and find
 *    the controller of interest
 * 2. go thru list of devices under controller and compare if the target is same
 * 3. if yes
 *      - device is already represented
 * 4. if No
 * 	- The node must be repreented in PICL tree.
 */
static boolean_t
is_node_present(scsi_info_t *scsi_info, char *devfs_path, int target)
{
	node_t	*curr = NULL;
	char	path[MAXPATHLEN];
	char	controller[MAXPATHLEN];
	char 	*bus_addr = NULL;
	char 	*lasts = NULL, *token = NULL;
	int	i = 0;

	if (scsi_info == NULL) {
		return (B_FALSE);
	}

	if (scsi_info->list == NULL) {
		return (B_FALSE);
	}

	(void) snprintf(path, sizeof (path), "/devices%s", devfs_path);

	curr = scsi_info->list->first;
	while (curr != NULL) {

		lasts = curr->data->ap_phys_id;
		token = (char *)strtok_r(lasts, (const char *)":",
			(char **)&lasts);
		if (token == NULL) {
			curr = curr->next;
			continue;
		}

		if (strstr(path, token) == NULL) {
			/* this controller is not of interest */
			curr = curr->next;
			continue;
		}

		(void) snprintf(controller, sizeof (controller), "%s::",
			curr->data->ap_log_id);
		for (i = 0; i < scsi_info->num_list; i++) {
			if (strcmp(scsi_info->cfgalist[i].ap_type,
				SCSI_SLOT) == 0) {
				continue;
			}

			if (strstr(scsi_info->cfgalist[i].ap_log_id,
				controller) == NULL) {
				continue;
			}

			get_bus_addr(scsi_info->cfgalist[i].ap_phys_id,
				&bus_addr);
			/*
			 * compare  with target value
			 */
			if (bus_addr == NULL) {
				return (B_TRUE);
			}
			if (strtoul(bus_addr, NULL, 16) == target) {
				/*
				 * this device is already represented
				 * in fru tree
				 */
				free(bus_addr);
				return (B_TRUE);
			}
			free(bus_addr);
		}
		curr = curr->next;
	}
	return (B_FALSE);
}

static di_prop_t
get_prop_by_name(di_node_t node, char *name)
{
	di_prop_t prop = DI_PROP_NIL;
	char *prop_name = NULL;

	prop = di_prop_next(node, DI_PROP_NIL);
	while (prop != DI_PROP_NIL) {
		prop_name = di_prop_name(prop);
		if (prop_name != NULL) {
			if (strcmp(prop_name, name) == 0) {
				return (prop);
			}
		}
		prop = di_prop_next(node, prop);
	}
	return (DI_PROP_NIL);
}

static int
get_geoaddr(picl_nodehdl_t nodeh, void *c_args)
{
	picl_errno_t rc;
	uint8_t *geo_addr = NULL;
	char slot_type[PICL_PROPNAMELEN_MAX];

	if (c_args == NULL)
		return (PICL_INVALIDARG);
	geo_addr = (uint8_t *)c_args;

	if ((rc = ptree_get_propval_by_name(nodeh, PICL_PROP_SLOT_TYPE,
		slot_type, sizeof (slot_type))) != PICL_SUCCESS) {
		return (rc);
	}

	if (strcmp(slot_type, SANIBEL_SCSI_SLOT) == 0 ||
		strcmp(slot_type, SANIBEL_IDE_SLOT) == 0) {
		*geo_addr = *geo_addr + 1;
	}
	return (PICL_WALK_CONTINUE);
}

static int
frutree_get_geoaddr(frutree_frunode_t *frup)
{
	int geo_addr = 1;
	if (ptree_walk_tree_by_class(frup->frunodeh, PICL_CLASS_LOCATION,
		&geo_addr, get_geoaddr) != PICL_SUCCESS) {
		return (geo_addr);
	}
	return (geo_addr);
}

static int
probe_disks(di_node_t node, void *arg)
{
	di_prop_t prop;
	picl_errno_t rc;
	int *target_val = NULL;
	char *nodetype = NULL;
	char *devfs_path = NULL;
	char *bus_addr = NULL;
	char *drv_name = NULL;
	scsi_info_t *data = NULL;
	di_minor_t minor = DI_MINOR_NIL;
	char *class = NULL;
	char node_name[BUF_SIZE];
	char slot_type[PICL_PROPNAMELEN_MAX];

	if (arg == NULL)
		return (DI_WALK_TERMINATE);

	data = *(scsi_info_t **)arg;
	if (data == NULL) {
		return (DI_WALK_TERMINATE);
	}

	/* initialize the geo_addr value */
	if (data->geo_addr == 0) {
		if (data->compare_cfgadm == B_FALSE) {
			data->geo_addr = 1;
		} else {
			data->geo_addr = frutree_get_geoaddr(data->frup);
		}
	}

	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		nodetype = di_minor_nodetype(minor);
		if (nodetype == NULL) {
			continue;
		}

		if (strcmp(nodetype, DDI_NT_BLOCK_CHAN) == 0 ||
			strcmp(nodetype, DDI_NT_BLOCK_WWN) == 0) {
			(void) snprintf(node_name, sizeof (node_name),
				"%s%d", DISK, data->geo_addr);
		} else if (strcmp(nodetype, DDI_NT_TAPE) == 0) {
			(void) snprintf(node_name, sizeof (node_name),
				"%s%d", RMM, data->geo_addr);
		} else if (strcmp(nodetype, DDI_NT_CD) == 0 ||
			strcmp(nodetype, DDI_NT_CD_CHAN) == 0) {
			(void) snprintf(node_name, sizeof (node_name),
				"%s%d", CDROM, data->geo_addr);
		} else {
			continue;
		}

		devfs_path = di_devfs_path(node);
		drv_name = di_driver_name(node);
		bus_addr = di_bus_addr(node);
		if (devfs_path == NULL) {
			continue;
		}
		if (drv_name == NULL || bus_addr == NULL) {
			di_devfs_path_free(devfs_path);
			continue;
		}
		prop = get_prop_by_name(node, TARGET);
		if (prop != DI_PROP_NIL) {
			di_prop_ints(prop, &target_val);
			if (data->compare_cfgadm) {
				/* check if node is present in cfgadm data */
				if (is_node_present(data, devfs_path,
					*target_val) == B_TRUE) {
					di_devfs_path_free(devfs_path);
					return (DI_WALK_CONTINUE);
				}
			}

			di_devfs_path_free(devfs_path);
			prop = get_prop_by_name(node, CLASS);
			if (prop != DI_PROP_NIL) {
				di_prop_strings(prop, &class);
			}

			/* determine the slot type based on class code */
			if (class != NULL) {
				if (strcmp(class, DEVICE_CLASS_SCSI) == 0) {
					(void) strncpy(slot_type,
						SANIBEL_SCSI_SLOT,
						sizeof (slot_type));
				} else if (strcmp(class,
					DEVICE_CLASS_IDE) == 0) {
					(void) strncpy(slot_type,
						SANIBEL_IDE_SLOT,
						sizeof (slot_type));
				} else {
					(void) strncpy(slot_type,
						SANIBEL_UNKNOWN_SLOT,
						sizeof (slot_type));
				}

			} else {
				(void) strncpy(slot_type, SANIBEL_UNKNOWN_SLOT,
					sizeof (slot_type));
			}

			if ((rc = create_children(data->frup, node_name,
				bus_addr, data->geo_addr, slot_type,
				B_FALSE)) != PICL_SUCCESS) {
				return (rc);
			}
			/* increment the geo_addr */
			data->geo_addr++;
		} else {
			di_devfs_path_free(devfs_path);
			continue;
		}
		return (DI_WALK_CONTINUE);
	}
	return (DI_WALK_CONTINUE);
}

static picl_errno_t
probe_scsi_in_libdevinfo(frutree_frunode_t *frup, cfga_list_data_t *cfgalist,
	plist_t *list, int num_list, boolean_t compare_cfgadm)
{
	di_node_t	rnode;
	scsi_info_t	*scsi_data = NULL;

	if (frup == NULL) {
		return (PICL_FAILURE);
	}

	rnode = di_init(frup->fru_path, DINFOCPYALL);
	if (rnode == DI_NODE_NIL) {
		return (PICL_FAILURE);
	}

	scsi_data = (scsi_info_t *)malloc(sizeof (scsi_info_t));
	if (scsi_data == NULL) {
		di_fini(rnode);
		return (PICL_NOSPACE);
	}

	scsi_data->frup = frup;
	scsi_data->cfgalist = cfgalist;
	scsi_data->list = list;
	scsi_data->num_list = num_list;
	scsi_data->compare_cfgadm = compare_cfgadm;
	scsi_data->geo_addr = 0;
	if (di_walk_node(rnode, DI_WALK_CLDFIRST, &scsi_data,
		probe_disks) != 0) {
		free(scsi_data);
		di_fini(rnode);
		return (PICL_FAILURE);
	}

	free(scsi_data);
	di_fini(rnode);
	return (PICL_SUCCESS);
}

picl_errno_t
probe_for_scsi_frus(frutree_frunode_t *frup)
{
	int numlist;
	picl_errno_t rc;
	plist_t list;
	cfga_err_t ap_list_err;
	cfga_list_data_t *cfgalist = NULL;

	if (frutree_connects_initiated == B_TRUE) { /* probing after hotswap */
		ap_list_err = config_list_ext(0, NULL, &cfgalist,
			&numlist, NULL, NULL, NULL, CFGA_FLAG_LIST_ALL);

		if (ap_list_err != CFGA_OK) {
			rc = probe_scsi_in_libdevinfo(frup, NULL, NULL,
				0, B_FALSE);
			return (rc);
		}

		/* get list of all controllers in the system */
		ap_list_err = populate_controllers_list(&list, cfgalist,
			numlist);
		if (ap_list_err != CFGA_OK) {
			free_list(&list);
			free(cfgalist);
			rc = probe_scsi_in_libdevinfo(frup, NULL, NULL,
				0, B_FALSE);
			return (rc);
		}

		/* no controllers found */
		if (list.num_nodes <= 0) {
			free_list(&list);
			free(cfgalist);
			rc = probe_scsi_in_libdevinfo(frup, NULL, NULL,
				0, B_FALSE);
			return (rc);
		}
		/*
		 * we have to fetch cfgadm, look for scsi controllers
		 * dynamically
		 */
		(void) dyn_probe_for_scsi_frus(frup, cfgalist, &list, numlist);
		rc = probe_scsi_in_libdevinfo(frup, cfgalist, &list,
			numlist, B_TRUE);
		free_list(&list);
		free(cfgalist);
		return (rc);
	} else {
		/* during initialization */
		/* use the cached cfgadm data */
		rc = cache_probe_for_scsi_frus(frup);
		if (scsi_list && scsi_list->num_nodes > 0) {
			rc = probe_scsi_in_libdevinfo(frup, cfglist,
				scsi_list, nlist, B_TRUE);
		} else {
			rc = probe_scsi_in_libdevinfo(frup, NULL,
				NULL, 0, B_FALSE);
		}
		return (rc);
	}
}
