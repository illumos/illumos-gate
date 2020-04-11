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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * This file contains code for setting up environmental related nodes
 * and properties in the PICL tree.
 *
 * For each temperature-device class node, it does the following:
 *	- Create cpu and cpu-ambient temperautre-sensor class nodes.
 *	- Create "devfs-path" property under each temperature-sensor class node
 *	- Create "Temperature" volatile property under these nodes.
 *	- Create various temperature threshold properties under each node.
 *	- Create "Temperature" and "AmbientTemperature" volatile properties
 *	  under corresponding "cpu" class node.
 *
 * For the "fan-control" node, it does the following:
 *	- Create system-fan node
 *	- Create "devfs-path" property under "fan" class node
 *	- Create "Speed" volatile propery under each node.
 *	- Create "SpeedUnit" property under each node.
 *
 * Access to sensor/fan properties is protected by the envpicl_rwlock
 * readers/writer lock. This lock is held as a reader while trying to
 * access any volatile sensor/fan property, and held as a writer lock
 * while trying to create or destroy sensor/fan nodes and properties.
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <limits.h>
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

#define	PROP_FAN_SPEED_UNIT_VALUE	"%"

/*
 * PICL class path for CPU nodes
 */
#define	CPU0_PLAT_PATH		"_class:/gptwo/cpu?ID=0"
#define	CPU1_PLAT_PATH		"_class:/gptwo/cpu?ID=1"

/*
 * "UnitAddress" propval for various temperature devices (platform dependent)
 */
#define	CPU0_TEMPDEV_UNITADDR	"0,30"
#define	CPU1_TEMPDEV_UNITADDR	"0,98"

/*
 * Sensor node data structure
 */
typedef struct {
	char		*sensor_name;	/* sensor name */
	env_sensor_t	*sensorp;	/* sensor info */
	char		*unitaddr;	/* parent's UnitAddress propval */
	char		*sdev_node;	/* sensed device node name */
	char		*sdev_pname;	/* sensed device "temp" prop name */
	picl_nodehdl_t	nodeh;		/* sensor node handle */
	picl_prophdl_t	proph;		/* "Temperature" property handle */
	picl_prophdl_t	target_proph;	/* "TargetTemp" property handle */
	picl_prophdl_t	sdev_proph;	/* property handle for sensed dev */
} sensor_node_t;


/*
 * Sensor nodes array
 */
static sensor_node_t sensor_nodes[] = {
	{SENSOR_CPU0_DIE, NULL, CPU0_TEMPDEV_UNITADDR,
	    CPU0_PLAT_PATH, PICL_PROP_CPU_DIE_TEMP},

	{SENSOR_CPU0_AMB, NULL, CPU0_TEMPDEV_UNITADDR,
	    CPU0_PLAT_PATH, PICL_PROP_CPU_AMB_TEMP},

	{SENSOR_CPU1_DIE, NULL, CPU1_TEMPDEV_UNITADDR,
	    CPU1_PLAT_PATH, PICL_PROP_CPU_DIE_TEMP},

	{SENSOR_CPU1_AMB, NULL, CPU1_TEMPDEV_UNITADDR,
	    CPU1_PLAT_PATH, PICL_PROP_CPU_AMB_TEMP},

	{NULL, NULL, NULL, NULL, NULL}
};


/*
 * Fan node data structure
 */
typedef struct {
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
	{ENV_SYSTEM_FAN, NULL, PROP_FAN_SPEED_UNIT_VALUE},
	{ENV_CPU_FAN, NULL, PROP_FAN_SPEED_UNIT_VALUE},
	{ENV_PSUPPLY_FAN, NULL, PROP_FAN_SPEED_UNIT_VALUE},
	{NULL, NULL, NULL}
};


/*
 * Miscellaneous declarations
 */
typedef struct node_list {
	picl_nodehdl_t		nodeh;
	struct node_list	*next;
} node_list_t;

static void delete_sensor_nodes_and_props(void);
static void delete_fan_nodes_and_props(void);
static pthread_rwlock_t	envpicl_rwlock = PTHREAD_RWLOCK_INITIALIZER;


/*
 * Read function for volatile "Temperature" property
 */
static int
get_current_target_temp(ptree_rarg_t *parg, void *buf)
{
	picl_prophdl_t	proph;
	sensor_node_t	*snodep;
	env_sensor_t	*sensorp;

	/*
	 * Locate the sensor in our sensor_nodes table by matching the
	 * property handle and get its temperature.
	 */
	proph = parg->proph;
	(void) pthread_rwlock_rdlock(&envpicl_rwlock);
	for (snodep = &sensor_nodes[0]; snodep->sensor_name != NULL;
	    snodep++) {
		if (snodep->target_proph != proph)
			continue;

		if ((sensorp = snodep->sensorp) == NULL)
			break;
		(void) memcpy(buf, (caddr_t)&sensorp->target_temp,
		    sizeof (sensorp->target_temp));
		(void) pthread_rwlock_unlock(&envpicl_rwlock);
		return (PICL_SUCCESS);
	}
	(void) pthread_rwlock_unlock(&envpicl_rwlock);
	return (PICL_FAILURE);
}


/*
 * Read function for volatile "Temperature" property
 */
static int
get_current_temp(ptree_rarg_t *parg, void *buf)
{
	tempr_t		temp;
	picl_prophdl_t	proph;
	sensor_node_t	*snodep;

	/*
	 * Locate the sensor in our sensor_nodes table by matching the
	 * property handle and get its temperature.
	 */
	proph = parg->proph;
	(void) pthread_rwlock_rdlock(&envpicl_rwlock);
	for (snodep = &sensor_nodes[0]; snodep->sensor_name != NULL;
	    snodep++) {
		if (snodep->proph != proph &&
		    snodep->sdev_proph != proph)
			continue;

		if (get_temperature(snodep->sensorp, &temp) < 0)
			break;
		(void) memcpy(buf, (caddr_t)&temp, sizeof (tempr_t));
		(void) pthread_rwlock_unlock(&envpicl_rwlock);
		return (PICL_SUCCESS);
	}
	(void) pthread_rwlock_unlock(&envpicl_rwlock);
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

	/*
	 * Locate the fan in our fan_nodes table by matching the
	 * property handle and get fan speed.
	 */
	proph = parg->proph;
	(void) pthread_rwlock_rdlock(&envpicl_rwlock);
	for (fnodep = &fan_nodes[0]; fnodep->fan_name != NULL; fnodep++) {
		if (fnodep->proph != proph)
			continue;
		if (get_fan_speed(fnodep->fanp, &speed) < 0)
			break;
		speed = (fanspeed_t)(speed * 100/fnodep->fanp->speed_max);

		(void) memcpy(buf, (caddr_t)&speed, sizeof (speed));
		(void) pthread_rwlock_unlock(&envpicl_rwlock);
		return (PICL_SUCCESS);
	}
	(void) pthread_rwlock_unlock(&envpicl_rwlock);
	return (PICL_FAILURE);
}


static node_list_t *
add_node_to_list(picl_nodehdl_t nodeh, node_list_t *listp)
{
	node_list_t	*el;
	node_list_t	*tmp;

	el = malloc(sizeof (node_list_t));
	if (el == NULL)
		return (listp);
	el->nodeh = nodeh;
	el->next = NULL;
	if (listp == NULL) {
		listp = el;
		return (listp);
	}

	/*
	 * append to the end to preserve the order found
	 */
	tmp = listp;
	while (tmp->next != NULL)
		tmp = tmp->next;

	tmp->next = el;
	return (listp);
}



/*
 * Get a list of nodes of the specified classname under nodeh
 * Once a node of the specified class is found, it's children are not
 * searched.
 */
static node_list_t *
get_node_list_by_class(picl_nodehdl_t nodeh, const char *classname,
    node_list_t *listp)
{
	int		err;
	char		clname[PICL_CLASSNAMELEN_MAX+1];
	picl_nodehdl_t	chdh;

	/*
	 * go through the children
	 */
	err = ptree_get_propval_by_name(nodeh, PICL_PROP_CHILD, &chdh,
	    sizeof (picl_nodehdl_t));

	while (err == PICL_SUCCESS) {
		err = ptree_get_propval_by_name(chdh, PICL_PROP_CLASSNAME,
		    clname, strlen(classname) + 1);

		if ((err == PICL_SUCCESS) && (strcmp(clname, classname) == 0))
			listp = add_node_to_list(chdh, listp);
		else
			listp = get_node_list_by_class(chdh, classname, listp);

		err = ptree_get_propval_by_name(chdh, PICL_PROP_PEER, &chdh,
		    sizeof (picl_nodehdl_t));
	}
	return (listp);
}


/*
 * Free memory allocated to build the specified node list.
 */
static void
free_node_list(node_list_t *listp)
{
	node_list_t	*next;

	for (; listp != NULL; listp = next) {
		next = listp->next;
		free(listp);
	}
}

/*
 * Get PICL_PTYPE_CHARSTRING "UnitAddress" property
 */
static int
get_unit_address_prop(picl_nodehdl_t nodeh, void *buf, size_t len)
{
	int			err;
	picl_prophdl_t		proph;
	ptree_propinfo_t	pinfo;

	err = ptree_get_prop_by_name(nodeh, PICL_PROP_UNIT_ADDRESS, &proph);
	if (err == PICL_SUCCESS)
		err = ptree_get_propinfo(proph, &pinfo);

	if (err != PICL_SUCCESS)
		return (err);

	if (pinfo.piclinfo.type != PICL_PTYPE_CHARSTRING ||
	    pinfo.piclinfo.size > len)
		return (PICL_FAILURE);

	err = ptree_get_propval(proph, buf, pinfo.piclinfo.size);
	return (err);
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
add_sensor_thresh_props(picl_nodehdl_t nodeh, sensor_thresh_t *threshp)
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
 * Lookup "temperature-device" class nodes and create "temperature-sensor"
 * class nodes and relevant properties under those nodes.
 *
 * For each entry in sensor_nodes[] array, do the following:
 *	- Create specified (cpu-die or cpu-ambient) "temperautre-sensor" class
 *	  node.
 *	- Create "devfs-path" property under this node.
 *	- Create "Temperature" volatile property under this node.
 *	- Create various temperature threshold properties under this node.
 *	- Create specified ("Temperature" or "AmbientTemperature") volatile
 *	  temperature property under specified sdev_node node.
 */

static int
add_sensor_nodes_and_props(picl_nodehdl_t plath)
{
	int		err;
	char		*pname, *nodename, *refnode, *devfs_path;
	node_list_t	*node_list, *listp;
	sensor_node_t	*snodep;
	sensor_thresh_t *threshp;
	picl_nodehdl_t	nodeh, refnodeh, cnodeh;
	picl_prophdl_t	proph;
	char		unitaddr[PICL_UNITADDR_LEN_MAX];
	env_sensor_t	*sensorp;

	node_list =
	    get_node_list_by_class(plath, PICL_CLASS_TEMPERATURE_DEVICE, NULL);

	if (node_list == NULL)
		return (PICL_FAILURE);

	for (listp = node_list; listp != NULL; listp = listp->next) {
		/*
		 * Get "reg" property. Skip if no "reg" property found.
		 */
		nodeh = listp->nodeh;
		err = get_unit_address_prop(nodeh, (void *)unitaddr,
		    sizeof (unitaddr));
		if (err != PICL_SUCCESS)
			continue;

		for (snodep = sensor_nodes; snodep->sensor_name != NULL;
		    snodep++) {

			/* Match "UnitAddress" property */
			if (strcasecmp(unitaddr, snodep->unitaddr) != 0)
				continue;

			/*
			 * Skip if already initialized or no sensor info
			 */
			sensorp = snodep->sensorp;
			if (snodep->nodeh != 0 || sensorp == NULL)
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
			threshp = sensorp->temp_thresh;
			if (threshp && threshp->policy_type ==
			    POLICY_TARGET_TEMP) {
				/*
				 * Add volatile "TargetTemperature" property
				 */
				pname = PICL_PROP_TARGET_TEMPERATURE;
				err = add_volatile_prop(cnodeh, pname,
				    PICL_PTYPE_INT, PICL_READ,
				    sizeof (sensorp->target_temp),
				    get_current_target_temp, NULL, &proph);
				if (err != PICL_SUCCESS)
					break;
				snodep->target_proph = proph;
			}

			if (threshp != NULL)
				add_sensor_thresh_props(cnodeh, threshp);

			/*
			 * Finally create property in the sensed device
			 * (if one specified)
			 */
			refnode =  snodep->sdev_node;
			pname =  snodep->sdev_pname;
			if (refnode == NULL || pname == NULL)
				continue;

			err = ptree_get_node_by_path(refnode, &refnodeh);
			if (err == PICL_SUCCESS) {
				err = add_volatile_prop(refnodeh, pname,
				    PICL_PTYPE_INT, PICL_READ,
				    sizeof (tempr_t), get_current_temp,
				    NULL, &proph);
			}

			if (err != PICL_SUCCESS)
				break;

			/* Save prop handle */
			snodep->sdev_proph = proph;
		}
		if (err != PICL_SUCCESS) {
			delete_sensor_nodes_and_props();
			free_node_list(node_list);
			if (env_debug)
				envd_log(LOG_INFO,
				    "Can't create prop/node for sensor '%s'\n",
				    nodename);
			return (err);
		}
	}

	free_node_list(node_list);
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

	/*
	 * Delete/destroy any property created in the sensed device
	 * as well as the sensor node and all properties under it.
	 * Note that deleiing/destroying a node deletes/destroys
	 * all properties within that node.
	 */

	for (snodep = sensor_nodes; snodep->sensor_name != NULL; snodep++) {
		if (snodep->sdev_proph != 0) {
			(void) ptree_delete_prop(snodep->sdev_proph);
			(void) ptree_destroy_prop(snodep->sdev_proph);
			snodep->sdev_proph = 0;
		}

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
 * Lookup "fan-control" class node and create "fan" class nodes and
 * relevant properties under those nodes.
 *
 * For each entry in fan_nodes[] array, do the following:
 *	- Create specified "fan" class node.
 *	- Create "devfs-path" property under "fan" class node
 *	- Create "Speed" volatile propery under "fan" class node.
 *	- Create "SpeedUnit" property under "fan" class node.
 */

static int
add_fan_nodes_and_props(picl_nodehdl_t plath)
{
	int		err;
	char		*pname, *nodename, *devfs_path;
	env_fan_t	*fanp;
	fan_node_t	*fnodep;
	picl_nodehdl_t	nodeh, cnodeh;
	picl_prophdl_t	proph;
	node_list_t	*node_list, *listp;

	node_list =
	    get_node_list_by_class(plath, PICL_CLASS_FAN_CONTROL, NULL);

	if (node_list == NULL)
		return (PICL_FAILURE);

	for (listp = node_list; listp != NULL; listp = listp->next) {
		/*
		 * Add various fan nodes and properties
		 */
		nodeh = listp->nodeh;
		err = PICL_SUCCESS;
		for (fnodep = fan_nodes; fnodep->fan_name != NULL; fnodep++) {

			/* Skip if already initialized or no fan info */
			if (fnodep->nodeh != 0 || fnodep->fanp == NULL)
				continue;

			/*
			 * Create "fan" class node and save node handle
			 */
			nodename = fnodep->fan_name;
			err = ptree_create_and_add_node(nodeh, nodename,
			    PICL_CLASS_FAN, &cnodeh);
			if (env_debug)
				envd_log(LOG_INFO,
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
			err = add_volatile_prop(cnodeh, pname, PICL_PTYPE_INT,
			    PICL_READ, sizeof (fanspeed_t), get_current_speed,
			    NULL, &proph);

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
			free_node_list(node_list);
			if (env_debug)
				envd_log(LOG_WARNING,
				    "Can't create prop/node for fan '%s'\n",
				    nodename);
			return (err);
		}
	}

	free_node_list(node_list);
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

	/*
	 * Delete/destroy fan node and all properties under it.
	 * Note that deleiing/destroying a node deletes/destroys
	 * all properties within that node.
	 */

	for (fnodep = fan_nodes; fnodep->fan_name != NULL; fnodep++) {
		if (fnodep->nodeh != 0) {
			(void) ptree_delete_node(fnodep->nodeh);
			(void) ptree_destroy_node(fnodep->nodeh);
			fnodep->nodeh = 0;
		}
	}
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
		(void) strlcat(pname, ENVMODEL_CONF_FILE, PATH_MAX);
		if (access(pname, R_OK) == 0) {
			(void) strlcpy(outfilename, pname, PATH_MAX);
			return (0);
		}
	}

	if (sysinfo(SI_MACHINE, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, ENVMODEL_CONF_FILE, PATH_MAX);
		if (access(pname, R_OK) == 0) {
			(void) strlcpy(outfilename, pname, PATH_MAX);
			return (0);
		}
	}

	(void) snprintf(pname, PATH_MAX, "%s/%s", PICLD_COMMON_PLUGIN_DIR,
	    ENVMODEL_CONF_FILE);

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
	(void) pthread_rwlock_wrlock(&envpicl_rwlock);
	delete_fan_nodes_and_props();
	delete_sensor_nodes_and_props();
	(void) pthread_rwlock_unlock(&envpicl_rwlock);
}

void
env_picl_setup(void)
{
	int		err;
	sensor_node_t	*snodep;
	fan_node_t	*fnodep;
	picl_nodehdl_t	plath;
	char		fullfilename[PATH_MAX];
	picl_nodehdl_t  rooth;


	/*
	 * Initialize sensorp and other fields in the sensor_nodes[] array
	 */
	for (snodep = sensor_nodes; snodep->sensor_name != NULL; snodep++) {
		snodep->sensorp = sensor_lookup(snodep->sensor_name);
		snodep->nodeh = 0;
		snodep->proph = 0;
		snodep->target_proph = 0;
		snodep->sdev_proph = 0;
	}

	/*
	 * Initialize fanp and other fields in the fan_nodes[] array
	 */
	for (fnodep = fan_nodes; fnodep->fan_name != NULL; fnodep++) {
		fnodep->fanp = fan_lookup(fnodep->fan_name);
		fnodep->nodeh = 0;
		fnodep->proph = 0;
	}

	/*
	 * Get platform handle and populate PICL tree with environmental
	 * nodes and properties
	 */
	err = ptree_get_node_by_path("/platform", &plath);

	if (err == PICL_SUCCESS) {
		(void) pthread_rwlock_wrlock(&envpicl_rwlock);
		err = add_sensor_nodes_and_props(plath);
		if (err == PICL_SUCCESS)
			err = add_fan_nodes_and_props(plath);

		if (err != PICL_SUCCESS)
			delete_sensor_nodes_and_props();
		(void) pthread_rwlock_unlock(&envpicl_rwlock);
	}

	if (err != PICL_SUCCESS) {
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
