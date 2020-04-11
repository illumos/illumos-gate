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

/*
 * This file contains code for setting up environmental related nodes
 * and properties in the PICL tree.
 *
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sys/open.h>
#include <ctype.h>
#include <string.h>
#include <alloca.h>
#include <libintl.h>
#include <sys/systeminfo.h>
#include <picl.h>
#include <picltree.h>
#include <picld_pluginutil.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include "picldefs.h"
#include "envd.h"

/*
 * Volatile property read/write function typedef
 */
typedef int ptree_vol_rdfunc_t(ptree_rarg_t *parg, void *buf);
typedef int ptree_vol_wrfunc_t(ptree_warg_t *parg, const void *buf);

extern int monitor_disk_temp;
extern sensor_ctrl_blk_t sensor_ctrl[];
extern fan_ctrl_blk_t fan_ctrl[];
extern env_tuneable_t	tuneables[];
extern	int errno;
extern	int	ntuneables;
#define	PROP_FAN_SPEED_UNIT_VALUE	"rpm"



/*
 * Sensor node data structure
 */
typedef struct {
	char		*parent_path;	/* parent path */
	char		*sensor_name;	/* sensor name */
	env_sensor_t	*sensorp;	/* sensor info */
	picl_nodehdl_t	nodeh;		/* sensor node handle */
	picl_prophdl_t	proph;		/* "Temperature" property handle */
	picl_prophdl_t	target_proph;	/* "TargetTemp" property handle */
} sensor_node_t;


/*
 * Sensor nodes array
 */
static sensor_node_t sensor_nodes[] = {
	{"/platform/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,58",
	SENSOR_CPU0_DIE, NULL, 0, 0, 0},

	{"/platform/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,58",
	SENSOR_CPU1_DIE, NULL, 0, 0, 0},

	{"/platform/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,58",
	SENSOR_INT_AMB_0, NULL, 0, 0, 0},

	{"/platform/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,5c",
	SENSOR_SYS_OUT, NULL, 0, 0, 0},

	{"/platform/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,5c",
	SENSOR_SYS_IN, NULL, 0, 0, 0},

	{"/platform/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,5c",
	SENSOR_INT_AMB_1, NULL, 0, 0, 0},

};
#define	N_SENSOR_NODES	(sizeof (sensor_nodes)/sizeof (sensor_nodes[0]))


/*
 * Fan node data structure
 */
typedef struct {
	char		*parent_path;	/* parent node path */
	char		*fan_name;	/* fan name */
	env_fan_t	*fanp;		/* fan information */
	char		*speed_unit;	/* speed unit string */
	picl_nodehdl_t	nodeh;		/* "fan" node handle */
	picl_prophdl_t	proph;		/* "Speed" property handle */
} fan_node_t;


/*
 * Fan node array
 */
static fan_node_t fan_nodes[] =  {
	{"/platform/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,58",
	ENV_CPU0_FAN, NULL, PROP_FAN_SPEED_UNIT_VALUE, 0, 0},

	{"/platform/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,58",
	ENV_CPU1_FAN, NULL, PROP_FAN_SPEED_UNIT_VALUE, 0, 0},

	{"/platform/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,5c",
	ENV_SYSTEM_OUT_FAN, NULL, PROP_FAN_SPEED_UNIT_VALUE, 0, 0},

	{"/platform/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,5c",
	ENV_SYSTEM_INTAKE_FAN, NULL, PROP_FAN_SPEED_UNIT_VALUE, 0, 0},

	{"/platform/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,52",
	ENV_DIMM_FAN, NULL, PROP_FAN_SPEED_UNIT_VALUE, 0, 0},

};
#define	N_FAN_NODES	(sizeof (fan_nodes)/sizeof (fan_nodes[0]))

/*
 * Disk node data structure
 */
typedef struct {
	char		*parent_path;	/* parent node path */
	char		*disk_name;	/* disk name */
	env_disk_t	*diskp;		/* disk information */
	picl_nodehdl_t	nodeh;		/* "disk" node handle */
	picl_prophdl_t	proph;		/* "Temperature" property handle */
} disk_node_t;

/*
 * Disk node array
 */
static disk_node_t disk_nodes[] =  {
	{DISK0_NODE_PATH, ENV_DISK0, NULL, 0, 0},
	{DISK1_NODE_PATH, ENV_DISK1, NULL, 0, 0},
};
#define	N_DISK_NODES	(sizeof (disk_nodes)/sizeof (disk_nodes[0]))

/*
 * Miscellaneous declarations
 */
static void delete_sensor_nodes_and_props(void);
static void delete_disk_nodes_and_props(void);
static void delete_fan_nodes_and_props(void);


/*
 * Read function for volatile "Temperature" property
 */
static int
get_current_temp(ptree_rarg_t *parg, void *buf)
{
	tempr_t		temp;
	picl_prophdl_t	proph;
	sensor_node_t	*snodep;
	int		i;

	/*
	 * Locate the sensor in our sensor_nodes table by matching the
	 * property handle and get its temperature.
	 */
	proph = parg->proph;
	for (i = 0; i < N_SENSOR_NODES; ++i) {
		snodep = &sensor_nodes[i];
		if (snodep->proph != proph)
			continue;

		if (get_temperature(snodep->sensorp, &temp) < 0)
			break;
		(void) memcpy(buf, (caddr_t)&temp, sizeof (tempr_t));
		return (PICL_SUCCESS);
	}
	return (PICL_FAILURE);
}

/*
 * Read function for volatile "Temperature" property
 */
static int
get_disk_temp(ptree_rarg_t *parg, void *buf)
{
	tempr_t		temp;
	picl_prophdl_t	proph;
	disk_node_t	*dnodep;
	int		i;

	/*
	 * Locate the sensor in our sensor_nodes table by matching the
	 * property handle and get its temperature.
	 */
	proph = parg->proph;
	for (i = 0; i < N_DISK_NODES; ++i) {
		dnodep = &disk_nodes[i];
		if (dnodep->proph != proph)
			continue;

		if (disk_temperature(dnodep->diskp, &temp) < 0)
			break;
		(void) memcpy(buf, (caddr_t)&temp, sizeof (tempr_t));
		return (PICL_SUCCESS);
	}
	return (PICL_FAILURE);
}

/*
 * Read function for volatile "Speed" property on "fan" class node
 */
static int
set_current_speed(ptree_warg_t *parg, const void *buf)
{
	fanspeed_t	speed;
	picl_prophdl_t	proph;
	fan_node_t	*fnodep;
	int		i, ret;

	/*
	 * Locate the fan in our fan_nodes table by matching the
	 * property handle and get fan speed.
	 */
	proph = parg->proph;
	for (i = 0; i < N_FAN_NODES; ++i) {
		fnodep = &fan_nodes[i];
		if (fnodep->proph != proph)
			continue;
		if (fnodep->fanp->fd == -1)
			continue;

		(void) memcpy((caddr_t)&speed, buf, sizeof (speed));

		ret = set_fan_speed(fnodep->fanp, speed);

		if (ret < 0) {
			if (ret == -1 && errno == EBUSY)
				return (PICL_NOTWRITABLE);
			if (ret == -2)
				return (PICL_INVALIDARG);
			break;
		}


		return (PICL_SUCCESS);
	}
	return (PICL_FAILURE);
}


/*
 * Read function for volatile "Speed" property on "fan" class node
 */
static int
get_current_speed(ptree_rarg_t *parg, void *buf)
{
	fanspeed_t	speed;
	picl_prophdl_t	proph;
	fan_node_t	*fnodep;
	int		i;

	/*
	 * Locate the fan in our fan_nodes table by matching the
	 * property handle and get fan speed.
	 */
	proph = parg->proph;
	for (i = 0; i < N_FAN_NODES; ++i) {
		fnodep = &fan_nodes[i];
		if (fnodep->proph != proph)
			continue;
		if (fnodep->fanp->fd == -1)
			continue;
		if (get_fan_speed(fnodep->fanp, &speed) < 0)
			break;

		(void) memcpy(buf, (caddr_t)&speed, sizeof (speed));
		return (PICL_SUCCESS);
	}
	return (PICL_FAILURE);
}

/*
 * Create and add the specified regular property
 */

static int
add_regular_prop(picl_nodehdl_t nodeh, char *name, int type, int access,
    int size, void *valbuf, picl_prophdl_t *prophp)
{
	int			err;
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    type, access, size, name, NULL, NULL);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_and_add_prop(nodeh, &propinfo, valbuf, &proph);
	if (err == PICL_SUCCESS && prophp)
		*prophp = proph;
	return (err);
}


/*
 * Create and add the specified volatile property
 */
static int
add_volatile_prop(picl_nodehdl_t nodeh, char *name, int type, int access,
    int size, ptree_vol_rdfunc_t *rdfunc, ptree_vol_wrfunc_t *wrfunc,
    picl_prophdl_t *prophp)
{
	int			err;
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    type, (access|PICL_VOLATILE), size, name, rdfunc, wrfunc);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_and_add_prop(nodeh, &propinfo, NULL, &proph);
	if (err == PICL_SUCCESS && prophp)
		*prophp = proph;
	return (err);
}

/*
 * Add temperature threshold properties
 */
static void
add_sensor_thresh_props(picl_nodehdl_t nodeh, sensor_ctrl_blk_t *threshp)
{
	picl_prophdl_t	proph;

	(void) add_regular_prop(nodeh, PICL_PROP_LOW_POWER_OFF,
	    PICL_PTYPE_INT, PICL_READ,
	    sizeof (threshp->low_power_off),
	    (void *)&(threshp->low_power_off), &proph);

	(void) add_regular_prop(nodeh, PICL_PROP_LOW_SHUTDOWN,
	    PICL_PTYPE_INT, PICL_READ,
	    sizeof (threshp->low_shutdown),
	    (void *)&(threshp->low_shutdown), &proph);

	(void) add_regular_prop(nodeh, PICL_PROP_LOW_WARNING,
	    PICL_PTYPE_INT, PICL_READ,
	    sizeof (threshp->low_warning),
	    (void *)&(threshp->low_warning), &proph);

	(void) add_regular_prop(nodeh, PICL_PROP_HIGH_WARNING,
	    PICL_PTYPE_INT, PICL_READ,
	    sizeof (threshp->high_warning),
	    (void *)&(threshp->high_warning), &proph);

	(void) add_regular_prop(nodeh, PICL_PROP_HIGH_SHUTDOWN,
	    PICL_PTYPE_INT, PICL_READ,
	    sizeof (threshp->high_shutdown),
	    (void *)&(threshp->high_shutdown), &proph);

	(void) add_regular_prop(nodeh, PICL_PROP_HIGH_POWER_OFF,
	    PICL_PTYPE_INT, PICL_READ,
	    sizeof (threshp->high_power_off),
	    (void *)&(threshp->high_power_off), &proph);
}


/*
 * Go through the sensor_nodes array and create those nodes
 * and the Temperature property to report the temperature.
 */
static int
add_sensor_nodes_and_props()
{
	int		err;
	char		*pname, *nodename, *devfs_path;
	sensor_node_t	*snodep;
	sensor_ctrl_blk_t *threshp;
	picl_nodehdl_t	nodeh, cnodeh;
	picl_prophdl_t	proph;
	env_sensor_t	*sensorp;
	int		i;

	for (i = 0; i < N_SENSOR_NODES; ++i) {
		snodep = &sensor_nodes[i];
		/*
		 * Get the parent nodeh
		 */
		err = ptree_get_node_by_path(snodep->parent_path, &nodeh);
		if (err != PICL_SUCCESS)
			continue;
		sensorp = snodep->sensorp;
		if (sensorp->present == B_FALSE)
			continue;
		/*
		 * Create temperature-sensor node
		 */
		nodename = snodep->sensor_name;
		err = ptree_create_and_add_node(nodeh, nodename,
		    PICL_CLASS_TEMPERATURE_SENSOR, &cnodeh);
		if (env_debug)
			envd_log(LOG_INFO,
			    "Creating PICL sensor node '%s' err:%d\n",
			    nodename, err);
		if (err != PICL_SUCCESS)
			break;

		/* save node handle */
		snodep->nodeh = cnodeh;

		/*
		 * Add "devfs_path" property in child node
		 */
		devfs_path = sensorp->devfs_path;
		pname = PICL_PROP_DEVFS_PATH;
		err = add_regular_prop(cnodeh, pname,
		    PICL_PTYPE_CHARSTRING, PICL_READ,
		    strlen(devfs_path)+1, (void *)devfs_path, &proph);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Now add volatile "temperature" volatile property
		 * in this "temperature-sensor" class node.
		 */
		pname = PICL_PROP_TEMPERATURE;
		err = add_volatile_prop(cnodeh, pname,
		    PICL_PTYPE_INT, PICL_READ, sizeof (tempr_t),
		    get_current_temp, NULL, &proph);
		if (err != PICL_SUCCESS)
			break;

		/* Save prop handle */
		snodep->proph = proph;

		/*
		 * Add threshold related properties
		 */
		threshp = sensorp->es_ptr;

		if (threshp != NULL)
			add_sensor_thresh_props(cnodeh, threshp);

	}
	if (err != PICL_SUCCESS) {
		delete_sensor_nodes_and_props();
		if (env_debug)
			envd_log(LOG_INFO,
			    "Can't create prop/node for sensor '%s'\n",
			    nodename);
		return (err);
	}
	return (PICL_SUCCESS);
}

/*
 * Delete all sensor nodes and related properties created by the
 * add_sensor_prop() for each sensor node in the PICL tree.
 */
static void
delete_sensor_nodes_and_props(void)
{
	sensor_node_t	*snodep;
	int		i;

	/*
	 * Delete/destroy any property created in the sensed device
	 * as well as the sensor node and all properties under it.
	 * Note that deleiing/destroying a node deletes/destroys
	 * all properties within that node.
	 */

	for (i = 0; i < N_SENSOR_NODES; ++i) {
		snodep = &sensor_nodes[i];
		if (snodep->nodeh != 0) {
			/* delete node and all properties under it */
			(void) ptree_delete_node(snodep->nodeh);
			(void) ptree_destroy_node(snodep->nodeh);
			snodep->nodeh = 0;
			snodep->proph = 0;
		}
	}
}

/*
 * Go through the disk_nodes array and create those nodes
 * and the Temperature property to report the temperature.
 */
static int
add_disk_nodes_and_props()
{
	int		err;
	char		*pname, *nodename, *devfs_path;
	disk_node_t	*dnodep;
	picl_nodehdl_t	nodeh, cnodeh;
	picl_prophdl_t	proph;
	env_disk_t	*diskp;
	int		i;

	for (i = 0; i < N_DISK_NODES; ++i) {
		dnodep = &disk_nodes[i];
		/*
		 * Get the parent nodeh
		 */
		err = ptree_get_node_by_path(dnodep->parent_path, &nodeh);
		if (err != PICL_SUCCESS) {
			if (env_debug)
				envd_log(LOG_ERR,
				    "failed to get node for path %s\n",
				    dnodep->parent_path);
			err = PICL_SUCCESS;
			continue;
		}
		diskp = dnodep->diskp;
		if (diskp->present == B_FALSE)
			continue;
		/*
		 * Create temperature-sensor node
		 */
		nodename = dnodep->disk_name;
		err = ptree_create_and_add_node(nodeh, nodename,
		    PICL_CLASS_TEMPERATURE_SENSOR, &cnodeh);
		if (env_debug)
			envd_log(LOG_ERR,
			    "Creating PICL disk node '%s' err:%d\n",
			    nodename, err);
		if (err != PICL_SUCCESS)
			break;

		/* save node handle */
		dnodep->nodeh = cnodeh;

		/*
		 * Add "devfs_path" property in child node
		 */
		devfs_path = diskp->devfs_path;
		pname = PICL_PROP_DEVFS_PATH;
		err = add_regular_prop(cnodeh, pname,
		    PICL_PTYPE_CHARSTRING, PICL_READ,
		    strlen(devfs_path)+1, (void *)devfs_path, &proph);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Now add volatile "temperature" volatile property
		 * in this "temperature-sensor" class node.
		 */
		pname = PICL_PROP_TEMPERATURE;
		err = add_volatile_prop(cnodeh, pname,
		    PICL_PTYPE_INT, PICL_READ, sizeof (tempr_t),
		    get_disk_temp, NULL, &proph);
		if (err != PICL_SUCCESS)
			break;

		/* Save prop handle */
		dnodep->proph = proph;

		/*
		 * Add threshold related properties
		 */

		(void) add_regular_prop(cnodeh, PICL_PROP_LOW_SHUTDOWN,
		    PICL_PTYPE_INT, PICL_READ,
		    sizeof (diskp->low_shutdown),
		    (void *)&(diskp->low_shutdown), &proph);

		(void) add_regular_prop(cnodeh, PICL_PROP_LOW_WARNING,
		    PICL_PTYPE_INT, PICL_READ,
		    sizeof (diskp->low_warning),
		    (void *)&(diskp->low_warning), &proph);

		(void) add_regular_prop(cnodeh, PICL_PROP_HIGH_WARNING,
		    PICL_PTYPE_INT, PICL_READ,
		    sizeof (diskp->high_warning),
		    (void *)&(diskp->high_warning), &proph);

		(void) add_regular_prop(cnodeh, PICL_PROP_HIGH_SHUTDOWN,
		    PICL_PTYPE_INT, PICL_READ,
		    sizeof (diskp->high_shutdown),
		    (void *)&(diskp->high_shutdown), &proph);

	}
	if (err != PICL_SUCCESS) {
		delete_disk_nodes_and_props();
		if (env_debug)
			envd_log(LOG_INFO,
			    "Can't create prop/node for disk '%s'\n",
			    nodename);
		return (err);
	}
	return (PICL_SUCCESS);
}

/*
 * Delete all disk nodes and related properties created by the
 * add_disk_props() for each disk node in the PICL tree.
 */
static void
delete_disk_nodes_and_props(void)
{
	disk_node_t	*dnodep;
	int		i;

	/*
	 * Delete/destroy disk node and all properties under it.
	 * Note that deleting/destroying a node deletes/destroys
	 * all properties within that node.
	 */

	for (i = 0; i < N_DISK_NODES; ++i) {
		dnodep = &disk_nodes[i];
		if (dnodep->nodeh != 0) {
			(void) ptree_delete_node(dnodep->nodeh);
			(void) ptree_destroy_node(dnodep->nodeh);
			dnodep->nodeh = 0;
			dnodep->proph = 0;
		}
	}
}

/*
 * For each entry in fan_nodes[] array, do the following:
 *	- Create specified "fan" class node.
 *	- Create "Speed" volatile propery under "fan" class node.
 *	- Create "SpeedUnit" property under "fan" class node.
 */
static int
add_fan_nodes_and_props()
{
	int		err;
	char		*pname, *nodename, *devfs_path;
	env_fan_t	*fanp;
	fan_node_t	*fnodep;
	picl_nodehdl_t	nodeh, cnodeh;
	picl_prophdl_t	proph;
	int		i;

	for (i = 0; i < N_FAN_NODES; ++i) {
		/*
		 * Add various fan nodes and properties
		 */
		fnodep = &fan_nodes[i];
		if (fnodep->fanp->present == B_FALSE)
			continue;
		/*
		 * get parent nodeh
		 */
		err = ptree_get_node_by_path(fnodep->parent_path, &nodeh);
		if (err != PICL_SUCCESS) {
			if (env_debug)
				envd_log(LOG_ERR,
		"node for %s NOT FOUND.\n", fnodep->parent_path);
			err = PICL_SUCCESS;
			continue;
		}
		/*
		 * Create "fan" class node and save node handle
		 */
		nodename = fnodep->fan_name;
		err = ptree_create_and_add_node(nodeh, nodename,
		    PICL_CLASS_FAN, &cnodeh);
		if (env_debug)
			envd_log(LOG_ERR,
			    "Creating PICL fan node '%s' err:%d\n",
			    nodename, err);

		if (err != PICL_SUCCESS)
			break;
		fnodep->nodeh = cnodeh;

		/*
		 * Add "devfs_path" property in child node
		 */
		fanp = fnodep->fanp;
		devfs_path  = fanp->devfs_path;
		pname = PICL_PROP_DEVFS_PATH;
		err = add_regular_prop(cnodeh, pname,
		    PICL_PTYPE_CHARSTRING, PICL_READ,
		    strlen(devfs_path)+1, (void *)devfs_path, &proph);

		if (err != PICL_SUCCESS)

			break;

		/*
		 * Add "Speed" volatile property in this "fan"
		 * class node and save prop handle.
		 */
		pname = PICL_PROP_FAN_SPEED;
		if (fanp->id == DIMM_FAN_ID) {
			/*
			 * We do not permit setting of DIMM FAN speeds.
			 */
			err = add_volatile_prop(cnodeh, pname, PICL_PTYPE_INT,
			    PICL_READ, sizeof (fanspeed_t),
			    get_current_speed,
			    NULL, &proph);
		} else {
			err = add_volatile_prop(cnodeh, pname, PICL_PTYPE_INT,
			    PICL_READ|PICL_WRITE, sizeof (fanspeed_t),
			    get_current_speed,
			    set_current_speed, &proph);
		}

		if (err != PICL_SUCCESS)
			break;
		fnodep->proph = proph;

		/*
		 * Add other "fan" class properties
		 */
		pname = PICL_PROP_FAN_SPEED_UNIT;
		err = add_regular_prop(cnodeh, pname,
		    PICL_PTYPE_CHARSTRING, PICL_READ,
		    strlen(fnodep->speed_unit)+1,
		    (void *)fnodep->speed_unit, &proph);

		if (err != PICL_SUCCESS)
			break;
	}
	if (err != PICL_SUCCESS) {
		delete_fan_nodes_and_props();
		if (env_debug)
			envd_log(LOG_WARNING,
			    "Can't create prop/node for fan '%s'\n",
			    nodename);
		return (err);
	}
	return (PICL_SUCCESS);
}


/*
 * Delete all fan nodes and related properties created by the
 * add_fan_props() for each fan node in the PICL tree.
 */
static void
delete_fan_nodes_and_props(void)
{
	fan_node_t	*fnodep;
	int		i;

	/*
	 * Delete/destroy fan node and all properties under it.
	 * Note that deleting/destroying a node deletes/destroys
	 * all properties within that node.
	 */

	for (i = 0; i < N_FAN_NODES; ++i) {
		fnodep = &fan_nodes[i];
		if (fnodep->nodeh != 0) {
			(void) ptree_delete_node(fnodep->nodeh);
			(void) ptree_destroy_node(fnodep->nodeh);
			fnodep->nodeh = 0;
		}
	}
}
/*
 * Tuneables publishing functions
 */
static int
copy_persistent_tuneable(env_tuneable_t *tune, char *buf)
{

	switch (tune->type) {
	case PICL_PTYPE_INT : {
		(void) memcpy((int *)tune->value,
		    buf, tune->nbytes);
		break;
	}
	case PICL_PTYPE_CHARSTRING : {
		(void) memcpy((caddr_t)tune->value,
		    buf, tune->nbytes);
		break;
	}
	default	: {
		return (PICL_FAILURE);
	}
	}
	return (PICL_SUCCESS);
}

static void
env_parse_tunables(picl_nodehdl_t rooth)
{
	char	nmbuf[SYS_NMLN];
	char    pname[PATH_MAX];

	if (sysinfo(SI_PLATFORM, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, TUNABLE_CONF_FILE, PATH_MAX);
		if (access(pname, R_OK) == 0) {
			(void) picld_pluginutil_parse_config_file(rooth, pname);
			return;
		}
	}
}

int
env_picl_setup_tuneables(void)
{
	int		err;
	int		i;
	picl_nodehdl_t	nodeh;
	picl_nodehdl_t	rooth;
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;
	char		read_buf[BUFSIZ];

	if (ptree_get_root(&rooth) != PICL_SUCCESS) {
		return (PICL_FAILURE);
	}
	err = ptree_create_and_add_node(rooth, PICL_PLUGINS_NODE,
	    PICL_CLASS_PICL, &nodeh);
	if (err != PICL_SUCCESS)
		return (PICL_FAILURE);
	err = ptree_create_and_add_node(nodeh, PICL_ENVIRONMENTAL_NODE,
	    PICL_CLASS_PICL, &nodeh);
	if (err != PICL_SUCCESS) {
		return (PICL_FAILURE);
	}

	/*
	 * Parse the conf file
	 */
	env_parse_tunables(rooth);
	for (i = 0; i < ntuneables; i++) {
		tuneablep = &tuneables[i];
		err = ptree_get_propval_by_name(nodeh, tuneablep->name,
		    read_buf, tuneablep->nbytes);

		if (err != PICL_SUCCESS) {
			/*
			 * Add volitle functions to environmental node
			 */
			err = add_volatile_prop(nodeh, tuneablep->name,
			    tuneablep->type,
			    PICL_READ|PICL_WRITE, tuneablep->nbytes,
			    tuneablep->rfunc,
			    tuneablep->wfunc, &proph);

			tuneablep->proph = proph;
		} else {
			/*
			 * property is persistent
			 */
			(void) copy_persistent_tuneable(tuneablep,
			    read_buf);
		}
	}

	return	(PICL_SUCCESS);
}

/*
 * Find the ENVMODEL_CONF_FILE file.
 */
static int
get_envmodel_conf_file(char *outfilename)
{
	char	nmbuf[SYS_NMLN];
	char    pname[PATH_MAX];

	if (sysinfo(SI_PLATFORM, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, ENV_CONF_FILE, PATH_MAX);
		if (access(pname, R_OK) == 0) {
			(void) strlcpy(outfilename, pname, PATH_MAX);
			return (0);
		}
	}

	if (sysinfo(SI_MACHINE, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, ENV_CONF_FILE, PATH_MAX);
		if (access(pname, R_OK) == 0) {
			(void) strlcpy(outfilename, pname, PATH_MAX);
			return (0);
		}
	}

	(void) snprintf(pname, PATH_MAX, "%s/%s", PICLD_COMMON_PLUGIN_DIR,
	    ENV_CONF_FILE);

	if (access(pname, R_OK) == 0) {
		(void) strlcpy(outfilename, pname, PATH_MAX);
		return (0);
	}

	return (-1);
}

/* Delete all sensor/fan nodes and any properties created by this plugin */
void
env_picl_destroy(void)
{
	delete_fan_nodes_and_props();
	delete_sensor_nodes_and_props();
	delete_disk_nodes_and_props();
}

void
env_picl_setup(void)
{
	int		err;
	sensor_node_t	*snodep;
	fan_node_t	*fnodep;
	disk_node_t	*dnodep;
	picl_nodehdl_t	plath;
	char		fullfilename[PATH_MAX];
	picl_nodehdl_t  rooth;
	int		i;


	/*
	 * Initialize sensorp and other fields in the sensor_nodes[] array
	 */

	for (i = 0; i < N_SENSOR_NODES; ++i) {
		snodep = &sensor_nodes[i];
		snodep->sensorp = sensor_lookup(snodep->sensor_name);
		snodep->nodeh = 0;
		snodep->proph = 0;
		snodep->target_proph = 0;
	}

	/*
	 * Initialize fanp and other fields in the fan_nodes[] array
	 */
	for (i = 0; i < N_FAN_NODES; ++i) {
		fnodep = &fan_nodes[i];
		fnodep->fanp = fan_lookup(fnodep->fan_name);
		fnodep->nodeh = 0;
		fnodep->proph = 0;
	}

	/*
	 * Initialize diskp and other fields in the disk_nodes[] array
	 */
	for (i = 0; i < N_DISK_NODES; ++i) {
		dnodep = &disk_nodes[i];
		dnodep->diskp = disk_lookup(dnodep->disk_name);
		dnodep->nodeh = 0;
		dnodep->proph = 0;
	}

	/*
	 * Get platform handle and populate PICL tree with environmental
	 * nodes and properties
	 */
	err = ptree_get_node_by_path("/platform", &plath);

	if (err == PICL_SUCCESS)
		err = add_sensor_nodes_and_props();
	if (err == PICL_SUCCESS)
		err = add_fan_nodes_and_props();
	if ((err == PICL_SUCCESS) && (monitor_disk_temp))
		err = add_disk_nodes_and_props();

	/*
	 * We can safely call delete_xxx_nodes_and_props even
	 * if nodes were not added.
	 */

	if (err != PICL_SUCCESS) {
		delete_fan_nodes_and_props();
		delete_disk_nodes_and_props();
		delete_sensor_nodes_and_props();
		envd_log(LOG_CRIT, ENVD_PICL_SETUP_FAILED);
		return;
	}

	/*
	 * Parse the envmodel.conf file and populate the PICL tree
	 */
	if (get_envmodel_conf_file(fullfilename) < 0)
		envd_log(LOG_CRIT, ENVD_PICL_SETUP_FAILED);
	if (ptree_get_root(&rooth) != PICL_SUCCESS)
		envd_log(LOG_CRIT, ENVD_PICL_SETUP_FAILED);
	err = picld_pluginutil_parse_config_file(rooth, fullfilename);

	if (err != PICL_SUCCESS)
		envd_log(LOG_CRIT, ENVD_PICL_SETUP_FAILED);
}
