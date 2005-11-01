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
 * This plugin creates PICL nodes and properties for objects handled through
 * the blade support chip (BSC). The BSC Solaris land device driver exposes
 * information to the plugin and other clients through an existing LOM
 * (Lights Out Management) ioctl interface. The plugin only exercises
 * a subset of the interface which is known to be supported by the bsc.
 *
 * All the nodes which may be accessible through the BSC are included below
 * the SUNW,bscv node (class system-controller) in the /platform tree.
 * This plugin interrogates the BSC to determine which of
 * those nodes are actually available. Properties are added to such nodes and
 * in the case of volatile properties like temperature, a call-back function
 * is established for on-demand access to the current value.
 *
 * NOTE:
 * Depends on PICL devtree plugin.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <alloca.h>
#include <syslog.h>
#include <string.h>
#include <libintl.h>
#include <picl.h>
#include <picltree.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/obpdefs.h>
#include <sys/lom_io.h>
#include <sys/systeminfo.h>
#include <time.h>
#include <picldefs.h>
#include <picld_pluginutil.h>
#include "picllom.h"

static	void		picllom_register(void);
static	void		picllom_init(void);
static	void		picllom_fini(void);
static	node_el_t	*create_node_el(picl_nodehdl_t nodeh);
static	void		delete_node_el(node_el_t *pel);
static	node_list_t	*create_node_list();
static	void		delete_node_list_contents(node_list_t *pnl);
static	void		delete_node_list(node_list_t *pnl);
static	void		add_node_to_list(picl_nodehdl_t nodeh,
    node_list_t *listp);
static	void		get_node_list_by_class(picl_nodehdl_t nodeh,
    const char *classname, node_list_t *listp);
static	int		get_lom_node(picl_nodehdl_t *lominfh);
static	int		get_lom_device_path(picl_nodehdl_t *lominfh);
static int		get_node_by_name_and_class(picl_nodehdl_t srchnodeh,
    const char *nodename, const char *classname, picl_nodehdl_t *chdh);
static	int		add_regular_prop(picl_nodehdl_t nodeh, const char *name,
    int type, int access, int size, const void *valbuf, picl_prophdl_t *prophp);
static	int		add_volatile_prop(picl_nodehdl_t nodeh, char *name,
    int type, int access, int size, ptree_vol_rdfunc_t rdfunc,
    ptree_vol_wrfunc_t wrfunc, picl_prophdl_t *prophp);
static	int		open_lom_rd(int *lom_fd);
static	int		get_lom_temp(int index, tempr_t *temp_p);
static	int		update_voltage_stats();
static	int		get_lom_volts_status(int index, int *voltsStatus_p);
static	int		get_lom_volts_shutdown(int index, int *voltsShutdown_p);
static	int		update_fan_stats();
static	int		get_lom_fan_speed(int index, int *fan_speed);
static	int		read_vol_temp(ptree_rarg_t *parg, void *buf);
static	int		read_vol_volts_status(ptree_rarg_t *parg, void *buf);
static	int		read_vol_volts_shutdown(ptree_rarg_t *parg, void *buf);
static	int		read_fan_speed(ptree_rarg_t *parg, void *buf);
static	int		read_fan_status(ptree_rarg_t *parg, void *buf);
static	int		lookup_led_status(int8_t state, const char **string);
static	int		read_led_status(ptree_rarg_t *parg, void *buf);
static	void		convert_node_name(char *ptr);
static const char	*strcasestr(const char *s1, const char *s2);
static	int		add_temp_sensors(int lom_fd, picl_nodehdl_t lominfh);
static	int		add_voltage_monitors(int lom_fd,
    picl_nodehdl_t lominfh);
static	int		add_fan_nodes(int lom_fd, picl_nodehdl_t lominfh);
static	int		get_config_file(char *outfilename);

#pragma	init(picllom_register)

static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_NON_CRITICAL,
	"SUNW_picllom",
	picllom_init,
	picllom_fini
};

static const char str_OK[] = "OK";
static const char str_FAIL[] = "FAIL";
static const char str_On[] = "on";
static const char str_Off[] = "off";
static const char str_Enabled[] = "Enabled";
static const char str_Disabled[] = "Disabled";
static char lom_device_path[PATH_MAX];
static tempr_t high_warnings[MAX_TEMPS];
static tempr_t high_shutdowns[MAX_TEMPS];
static picl_prophdl_t temp_handles[MAX_TEMPS];
static	lom_fandata_t fandata;
static	picl_prophdl_t	fan_speed_handles[MAX_FANS];
static	picl_prophdl_t	fan_status_handles[MAX_FANS];
static	lom_volts_t	voltsdata;
static	picl_prophdl_t	volts_status_handles[MAX_VOLTS];
static	picl_prophdl_t	volts_shutdown_handles[MAX_VOLTS];
static	int		n_leds = 0;
static	int		max_state_size = 0;
static	picl_prophdl_t	*led_handles = NULL;
static	char		**led_labels = NULL;
static	lom2_info_t	info2data;
static	struct {
	int		size;
	char		*str_colour;
} colour_lkup[1 + LOM_LED_COLOUR_AMBER];

static	struct {
	int8_t		state;
	char		*str_ledstate;
} ledstate_lkup[] = {
	{	LOM_LED_OFF			},
	{	LOM_LED_ON			},
	{	LOM_LED_BLINKING		},
};

static node_el_t *
create_node_el(picl_nodehdl_t nodeh)
{
	node_el_t *ptr = malloc(sizeof (node_el_t));

	if (ptr != NULL) {
		ptr->nodeh = nodeh;
		ptr->next = NULL;
	}

	return (ptr);
}

static void
delete_node_el(node_el_t *pel)
{
	free(pel);
}

static node_list_t *
create_node_list()
{
	node_list_t *ptr = malloc(sizeof (node_list_t));

	if (ptr != NULL) {
		ptr->head = NULL;
		ptr->tail = NULL;
	}

	return (ptr);
}

static void
delete_node_list_contents(node_list_t *pnl)
{
	node_el_t	*pel;

	if (pnl == NULL)
		return;

	while ((pel = pnl->head) != NULL) {
		pnl->head = pel->next;
		delete_node_el(pel);
	}

	pnl->tail = NULL;
}

static void
delete_node_list(node_list_t *pnl)
{
	delete_node_list_contents(pnl);
	free(pnl);
}

/*
 * Get a linking element and add handle to end of chain
 */
static void
add_node_to_list(picl_nodehdl_t nodeh, node_list_t *listp)
{
	node_el_t	*pel = create_node_el(nodeh);

	if (pel != NULL) {
		if (listp->tail == NULL)
			listp->head = pel;
		else
			listp->tail->next = pel;

		listp->tail = pel;
	}
}

/*
 * Get a list of nodes of the specified classname under nodeh.
 * Once a node of the specified class is found, its children are not
 * searched.
 */
static void
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
			add_node_to_list(chdh, listp);
		else
			get_node_list_by_class(chdh, classname, listp);

		err = ptree_get_propval_by_name(chdh, PICL_PROP_PEER, &chdh,
		    sizeof (picl_nodehdl_t));
	}
}

static int
get_lom_node(picl_nodehdl_t *lominfh)
{
	int			err = PICL_SUCCESS;
	node_list_t		*listp;

	listp = create_node_list();

	if ((err = ptree_get_node_by_path(PICL_NODE_ROOT PICL_NODE_PLATFORM,
	    lominfh)) != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_MISSING_NODE,
		    PICL_NODE_ROOT PICL_NODE_PLATFORM);
		return (err);	/* no /platform ! */
	}

	get_node_list_by_class(*lominfh, PICL_CLASS_SERVICE_PROCESSOR, listp);

	if (listp->head == NULL) {
		*lominfh = 0;
		syslog(LOG_ERR, EM_MISSING_NODE, PICL_CLASS_SERVICE_PROCESSOR);
		err = PICL_NODENOTFOUND;
	} else {
		*lominfh = listp->head->nodeh;

		if (listp->head != listp->tail)
			syslog(LOG_ERR, EM_LOM_DUPLICATE);
	}

	delete_node_list(listp);
	return (err);
}

static int
get_lom_device_path(picl_nodehdl_t *lominfh)
{
	int err = PICL_SUCCESS;
	char devfs_path[PATH_MAX];
	char devices_path[PATH_MAX];

	err = ptree_get_propval_by_name(*lominfh, PICL_PROP_DEVFS_PATH,
		devfs_path, sizeof (devfs_path));

	/* Build up the full device path and set the global */
	strcpy(devices_path, "/devices");
	strcat(devices_path, devfs_path);
	strcat(devices_path, LOM_DEV_MINOR_NAME);
	strcpy(lom_device_path, devices_path);

	return (err);

}




/*
 * Look for a node of specified name and class
 * Confine search to nodes one level below that of supplied handle
 */
static int
get_node_by_name_and_class(picl_nodehdl_t srchnodeh, const char *nodename,
    const char *classname, picl_nodehdl_t *chdh)
{
	int			err;
	char			namebuf[PATH_MAX];

	err = ptree_get_propval_by_name(srchnodeh, PICL_PROP_CHILD, chdh,
	    sizeof (picl_nodehdl_t));

	while (err == PICL_SUCCESS) {
		err = ptree_get_propval_by_name(*chdh, PICL_PROP_NAME, namebuf,
		    sizeof (namebuf));
		if (err != PICL_SUCCESS)
			break;
		if (strcmp(namebuf, nodename) == 0) {
			err = ptree_get_propval_by_name(*chdh,
			    PICL_PROP_CLASSNAME, namebuf, sizeof (namebuf));
			if ((err == PICL_SUCCESS) &&
			    (strcmp(namebuf, classname) == 0))
				return (PICL_SUCCESS);
		}
		err = ptree_get_propval_by_name(*chdh, PICL_PROP_PEER, chdh,
		    sizeof (picl_nodehdl_t));
	}

	return (err);
}

/*
 * Create and add the specified regular property
 */

static int
add_regular_prop(picl_nodehdl_t nodeh, const char *name, int type, int access,
    int size, const void *valbuf, picl_prophdl_t *prophp)
{
	int			err;
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    type, access, size, (char *)name, NULL, NULL);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_and_add_prop(nodeh, &propinfo, (void *)valbuf,
	    &proph);
	if (err == PICL_SUCCESS && prophp)
		*prophp = proph;
	return (err);
}


/*
 * Create and add the specified volatile property
 */
static int
add_volatile_prop(picl_nodehdl_t nodeh, char *name, int type, int access,
    int size, ptree_vol_rdfunc_t rdfunc, ptree_vol_wrfunc_t wrfunc,
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
 * open LOM device to read
 */
static int
open_lom_rd(int *lom_fd)
{
	*lom_fd = open(lom_device_path, O_RDONLY);

	if (*lom_fd < 0)
		return (PICL_FAILURE);

	return (PICL_SUCCESS);
}

/*
 * Function to open LOM and read temperature sensor values.
 * The index to a specific sensor is supplied and that value returned.
 */
static int
get_lom_temp(int index, tempr_t *temp_p)
{
	lom_temp_t	lom_temp;
	int		lom_fd;
	int		err;
	int		res;

	err = open_lom_rd(&lom_fd);

	if (err == PICL_SUCCESS) {
		res = ioctl(lom_fd, LOMIOCTEMP, &lom_temp);
		(void) close(lom_fd);

		if (res == 0) {
			*temp_p = lom_temp.temp[index];
		} else {
			err = PICL_FAILURE;
		}
	}

	return (err);
}

/*
 * Function to open LOM and read voltage monitor values.
 * Called for each property, so only perform update if time has changed
 */
static int
update_voltage_stats()
{
	static time_t	then = 0;
	int		lom_fd;
	int		err;
	int		res;
	time_t		now = time(NULL);

	if (now == then)
		return (PICL_SUCCESS);

	then = now;
	err = open_lom_rd(&lom_fd);

	if (err == PICL_SUCCESS) {
		res = ioctl(lom_fd, LOMIOCVOLTS, &voltsdata);
		(void) close(lom_fd);
		if (res < 0) {
			err = PICL_FAILURE;
		}
	}

	return (err);
}

/*
 * Function to open LOM and read voltage monitor values.
 * The index to a specific voltage status is supplied and that value returned.
 */
static int
get_lom_volts_status(int index, int *voltsStatus_p)
{
	int res;

	if ((res = update_voltage_stats()) != PICL_SUCCESS)
		return (res);

	*voltsStatus_p = voltsdata.status[index];
	return (PICL_SUCCESS);
}

/*
 * Function to open LOM and read voltage monitor values.
 * The index to a specific shutdown flag is supplied and that value returned.
 */
static int
get_lom_volts_shutdown(int index, int *voltsShutdown_p)
{
	int res;

	if ((res = update_voltage_stats()) != PICL_SUCCESS)
		return (res);

	*voltsShutdown_p = voltsdata.shutdown_enabled[index];
	return (PICL_SUCCESS);
}



/*
 * Function to open LOM and read fan values.
 * Called for each property, so only perform update if time has changed
 */
static int
update_fan_stats()
{
	static time_t	then = 0;
	int		lom_fd;
	int		err;
	int		res;
	time_t		now = time(NULL);

	if (now == then)
		return (PICL_SUCCESS);

	then = now;
	err = open_lom_rd(&lom_fd);
	if (err == PICL_SUCCESS) {
		res = ioctl(lom_fd, LOMIOCFANSTATE, &fandata);
		(void) close(lom_fd);
		if (res < 0) {
			err = PICL_FAILURE;
		}
	}

	return (err);
}



/*
 * The index to a specific fan is supplied and its speed value returned.
 */
static int
get_lom_fan_speed(int index, int *fan_speed)
{
	int res;

	if ((res = update_fan_stats()) != PICL_SUCCESS)
		return (res);

	*fan_speed = fandata.speed[index];
	return (PICL_SUCCESS);
}


/*
 * Read function for volatile "Temperature" property via LOM
 */
static int
read_vol_temp(ptree_rarg_t *parg, void *buf)
{
	tempr_t 	temp;
	picl_prophdl_t	proph;
	int		index;

	/*
	 * get the sensor index from the displacement of the
	 * property handle and get its temperature.
	 */
	proph = parg->proph;
	for (index = 0; index < MAX_TEMPS; index++) {
		if (temp_handles[index] == proph)
			break;
	}

	if (index == MAX_TEMPS) {
		/*
		 * Handle not found. As this is a plugin, stale handles
		 * cannot occur, so just fail.
		 */
		return (PICL_FAILURE);
	}

	if (get_lom_temp(index, &temp) != PICL_SUCCESS)
			return (PICL_FAILURE);
	(void) memcpy(buf, (caddr_t)&temp, sizeof (tempr_t));
	return (PICL_SUCCESS);
}

/*
 * Read function for volatile "VoltageStatus" property via LOM
 */
static int
read_vol_volts_status(ptree_rarg_t *parg, void *buf)
{
	int		voltsStatus;
	picl_prophdl_t	proph;
	int		index;

	/*
	 * get the voltage monitor index from the displacement of the
	 * status property handle and get its status.
	 */
	proph = parg->proph;

	for (index = 0; index < MAX_VOLTS; index++) {
		if (volts_status_handles[index] == proph)
			break;
	}

	if (index == MAX_VOLTS)
		return (PICL_FAILURE);

	if (get_lom_volts_status(index, &voltsStatus) != PICL_SUCCESS)
		return (PICL_FAILURE);

	(void) strlcpy(buf, (voltsStatus == 0) ? str_OK : str_FAIL,
	    sizeof (str_FAIL));
	return (PICL_SUCCESS);
}

/*
 * Read function for volatile "VoltageShutdown" property via LOM
 */
static int
read_vol_volts_shutdown(ptree_rarg_t *parg, void *buf)
{
	int		voltsShutdown;
	picl_prophdl_t	proph;
	int		index;

	/*
	 * get the voltage monitor index from the displacement of the
	 * shutdown property handle and get its value.
	 */
	proph = parg->proph;

	for (index = 0; index < MAX_VOLTS; index++) {
		if (volts_shutdown_handles[index] == proph)
			break;
	}

	if (index == MAX_VOLTS)
		return (PICL_FAILURE);

	if (get_lom_volts_shutdown(index, &voltsShutdown) != PICL_SUCCESS)
		return (PICL_FAILURE);

	(void) strlcpy(buf, (voltsShutdown == 0) ? str_Disabled : str_Enabled,
	    sizeof (str_Disabled));
	return (PICL_SUCCESS);
}


/*
 * Read function for volatile fan speed property via LOM
 */
static int
read_fan_speed(ptree_rarg_t *parg, void *buf)
{
	int		fan_speed;
	picl_prophdl_t	proph;
	int		index;

	/*
	 * get the relevant fan from the displacement of its property handle
	 */
	proph = parg->proph;

	for (index = 0; index < MAX_FANS; index++) {
		if (fan_speed_handles[index] == proph)
			break;
	}

	if (index == MAX_FANS)
		return (PICL_FAILURE);

	if (get_lom_fan_speed(index, &fan_speed) != PICL_SUCCESS)
		return (PICL_FAILURE);

	(void) memcpy(buf, (caddr_t)&fan_speed, sizeof (fan_speed));
	return (PICL_SUCCESS);
}

/*
 * look up function to convert led status into string
 */
static int
lookup_led_status(int8_t state, const char **string)
{
	int	i;
	int	lim = sizeof (ledstate_lkup) / sizeof (ledstate_lkup[0]);

	for (i = 0; i < lim; i++) {
		if (ledstate_lkup[i].state == state) {
			*string = ledstate_lkup[i].str_ledstate;
			return (PICL_SUCCESS);
		}
	}

	*string = "";
	switch (state) {
	case LOM_LED_ACCESS_ERROR:
		return (PICL_PROPVALUNAVAILABLE);
	case LOM_LED_NOT_IMPLEMENTED:
	/*FALLTHROUGH*/
	case LOM_LED_OUTOFRANGE:
	/*FALLTHROUGH*/
	default:
		return (PICL_FAILURE);
	}
}

/*
 * Read function for volatile led status property.
 */
static int
read_led_status(ptree_rarg_t *parg, void *buf)
{
	lom_led_state_t	led_data;
	picl_prophdl_t	proph;
	int		index;
	int		lom_fd;
	int		res;
	const char	*string;

	/*
	 * get the relevant led from the displacement of its property handle
	 */
	proph = parg->proph;

	for (index = 0; index < n_leds; index++) {
		if (led_handles[index] == proph)
			break;
	}

	if (index == n_leds)
		return (PICL_FAILURE);

	res = open_lom_rd(&lom_fd);
	if (res != PICL_SUCCESS)
		return (res);
	/*
	 * The interface for reading LED status doesn't promise to maintain
	 * a constant mapping between LED index number and LED identity
	 * (as defined by its label). On the other hand, PICL does promise
	 * that whilst a handle remains valid the object it represents will
	 * remain constant. To reconcile these positions, we maintain
	 * tables of labels and handles linked by index value. We search
	 * for the handle with which we are presented and then locate its
	 * label. Then we request LED entries from the LOM and compare their
	 * labels with the one we seek. As an optimisation, we try the original
	 * index value first and then revert to a full search.
	 */
	(void) memset(&led_data, 0, sizeof (led_data));
	led_data.index = index;
	res = ioctl(lom_fd, LOMIOCLEDSTATE, &led_data);

	if (res != 0 || led_data.state == LOM_LED_NOT_IMPLEMENTED ||
	    strcmp(led_data.label, led_labels[index]) != 0) {
		/*
		 * full scan required (bet it doesn't work!)
		 * first re-establish the range to scan
		 */
		int	i;
		int	n;

		(void) memset(&led_data, 0, sizeof (led_data));
		led_data.index = -1;
		res = ioctl(lom_fd, LOMIOCLEDSTATE, &led_data);

		if (res != 0) {
			(void) close(lom_fd);
			return (PICL_PROPVALUNAVAILABLE);
		}

		if (led_data.state == LOM_LED_NOT_IMPLEMENTED ||
		    strcmp(led_data.label, led_labels[index]) != 0) {
			n = led_data.index;
			for (i = 0; i < n; i++) {
				(void) memset(&led_data, 0, sizeof (led_data));
				led_data.index = i;
				res = ioctl(lom_fd, LOMIOCLEDSTATE, &led_data);

				if (res == 0 &&
				    led_data.state != LOM_LED_NOT_IMPLEMENTED ||
				    strcmp(led_data.label, led_labels[index]) ==
				    0) {
					break;
				}
			}

			if (i == n) {
				(void) close(lom_fd);
				return (PICL_PROPVALUNAVAILABLE);
			}
		}
	}

	/*
	 * if we get here, then we found the right LED.
	 */
	(void) close(lom_fd);
	res = lookup_led_status(led_data.state, &string);
	(void) strlcpy(buf, string, max_state_size);
	return (res);
}

/*
 * Read function for volatile fan status property.
 * This is a synthesized property using speed and min speed properties
 */
static int
read_fan_status(ptree_rarg_t *parg, void *buf)
{
	int		fan_speed;
	picl_prophdl_t	proph;
	int		index;

	/*
	 * get the relevant fan from the displacement of its property handle
	 */
	proph = parg->proph;

	for (index = 0; index < MAX_FANS; index++) {
		if (fan_status_handles[index] == proph)
			break;
	}

	if (index == MAX_FANS)
		return (PICL_FAILURE);

	if (get_lom_fan_speed(index, &fan_speed) != PICL_SUCCESS)
		return (PICL_FAILURE);

	(void) strlcpy(buf,
	    fan_speed < fandata.minspeed[index] ? str_FAIL : str_OK,
	    sizeof (str_FAIL));
	return (PICL_SUCCESS);
}



/*
 * change to lower case and convert any spaces into hyphens
 */
static void
convert_node_name(char *ptr)
{
	char ch;

	for (ch = *ptr; ch != '\0'; ch = *++ptr) {
		if (isupper(ch)) {
			*ptr = tolower(ch);
		} else if (isspace(ch)) {
			*ptr = '-';
		}
	}
}

/*
 * find first occurrence of string s2 within string s1 (ignoring case)
 */
static const char *
strcasestr(const char *s1, const char *s2)
{
	int len1 = strlen(s1);
	int len2 = strlen(s2);
	int i;

	for (i = 0; i <= len1 - len2; i++) {
		if (strncasecmp(s1 + i, s2, len2) == 0)
			return (s1 + i);
	}

	return (NULL);
}

static int
add_temp_sensors(int lom_fd, picl_nodehdl_t lominfh)
{
	lom_temp_t	lom_temp;
	int		res;
	int		i;
	int		err = PICL_SUCCESS;
	const char	*cptr;

	res = ioctl(lom_fd, LOMIOCTEMP, &lom_temp);

	if ((res == 0) && (lom_temp.num > 0)) {
		/*
		 * for each temperature location add a sensor node
		 */
		for (i = 0; i < lom_temp.num; i++) {
			picl_nodehdl_t	tempsensh;
			picl_prophdl_t proph;

			high_warnings[i] = lom_temp.warning[i];
			high_shutdowns[i] = lom_temp.shutdown[i];

			convert_node_name(lom_temp.name[i]);

			err = ptree_create_node(lom_temp.name[i],
			    PICL_CLASS_TEMPERATURE_SENSOR, &tempsensh);
			if (err != PICL_SUCCESS)
				break;

			err = add_volatile_prop(tempsensh,
			    PICL_PROP_TEMPERATURE, PICL_PTYPE_INT, PICL_READ,
			    sizeof (tempr_t), read_vol_temp, NULL,
			    &temp_handles[i]);
			if (err != PICL_SUCCESS)
				break;

			if (high_warnings[i] != 0) {
				err = add_regular_prop(
				    tempsensh, PICL_PROP_HIGH_WARNING,
				    PICL_PTYPE_INT, PICL_READ,
				    sizeof (tempr_t), &high_warnings[i],
				    &proph);
				if (err != PICL_SUCCESS)
					break;
			}

			if (high_shutdowns[i] != 0) {
				err = add_regular_prop(
				    tempsensh, PICL_PROP_HIGH_SHUTDOWN,
				    PICL_PTYPE_INT, PICL_READ,
				    sizeof (tempr_t), &high_shutdowns[i],
				    &proph);
				if (err != PICL_SUCCESS)
					break;
			}

			/*
			 * for the benefit of prtdiag, add a label of
			 * either enclosure or die where appropriate
			 */
			if ((strcasestr(lom_temp.name[i], CPU_ENCLOSURE) !=
			    NULL) ||
			    (strcasestr(lom_temp.name[i], CPU_AMBIENT) !=
			    NULL)) {
				cptr = CPU_AMBIENT;
			} else if ((cptr = strcasestr(lom_temp.name[i],
			    CPU_DIE)) != NULL) {
				cptr = CPU_DIE;
			}

			if (cptr != NULL) {
				err = add_regular_prop(
				    tempsensh, PICL_PROP_LABEL,
				    PICL_PTYPE_CHARSTRING, PICL_READ,
				    strlen(cptr) + 1, cptr, &proph);

				if (err != PICL_SUCCESS) {
					break;
				}
			}

			err = ptree_add_node(lominfh, tempsensh);

			if (err != PICL_SUCCESS)
				break;
		}

		if (err != PICL_SUCCESS) {
			syslog(LOG_ERR, EM_LOMINFO_TREE_FAILED);
		}
	}

	return (err);
}

static int
add_voltage_monitors(int lom_fd, picl_nodehdl_t lominfh)
{
	int		res;
	int		i;
	int		err = PICL_SUCCESS;
	picl_prophdl_t	proph;

	res = ioctl(lom_fd, LOMIOCVOLTS, &voltsdata);

	if ((res == 0) && (voltsdata.num > 0)) {
		/*
		 * for each voltage monitor add a monitor node
		 */
		for (i = 0; i < voltsdata.num; i++) {
			picl_nodehdl_t	voltsmonh;

			convert_node_name(voltsdata.name[i]);

			err = ptree_create_node(voltsdata.name[i],
			    PICL_CLASS_VOLTAGE_INDICATOR, &voltsmonh);
			if (err != PICL_SUCCESS)
				break;

			err = add_regular_prop(voltsmonh, PICL_PROP_LABEL,
			    PICL_PTYPE_CHARSTRING, PICL_READ,
			    strlen(voltsdata.name[i]) + 1,
			    voltsdata.name[i], &proph);
			if (err != PICL_SUCCESS)
				break;

			err = add_volatile_prop(voltsmonh, PICL_VOLTS_SHUTDOWN,
			    PICL_PTYPE_CHARSTRING, PICL_READ,
			    sizeof (str_Disabled), read_vol_volts_shutdown,
			    NULL, &volts_shutdown_handles[i]);
			if (err != PICL_SUCCESS)
				break;

			err = add_volatile_prop(voltsmonh, PICL_PROP_CONDITION,
			    PICL_PTYPE_CHARSTRING, PICL_READ,
			    sizeof (str_FAIL), read_vol_volts_status, NULL,
			    &volts_status_handles[i]);
			if (err != PICL_SUCCESS)
				break;

			err = ptree_add_node(lominfh, voltsmonh);

			if (err != PICL_SUCCESS)
				break;
		}

		if (err != PICL_SUCCESS) {
			syslog(LOG_ERR, EM_LOMINFO_TREE_FAILED);
		}
	}

	return (err);
}

static void
add_led(const lom_led_state_t *led_state, picl_nodehdl_t lominfh)
{
	int		err;
	picl_nodehdl_t	ledh;
	picl_nodehdl_t	proph;

	if (((unsigned char)led_state->state == LOM_LED_STATE_NOT_PRESENT) ||
	    (led_state->label[0] == '\0')) {
		return;
	}

	err = ptree_create_node(led_state->label, PICL_CLASS_LED, &ledh);
	/*
	 * the led may exist already, e.g. Fault
	 */
	if (err != PICL_SUCCESS)
		return;

	/*
	 * Unlike LEDs derived from other interfaces, these are not
	 * writable. Establish a read-only volatile property.
	 */
	err = add_volatile_prop(ledh, PICL_PROP_STATE, PICL_PTYPE_CHARSTRING,
	    PICL_READ, max_state_size, read_led_status, NULL,
	    &led_handles[led_state->index]);
	if (err != PICL_SUCCESS)
		return;

	/*
	 * if colour was defined for this LED, add a colour property
	 */
	if ((led_state->colour != LOM_LED_COLOUR_NONE) &&
	    (led_state->colour != LOM_LED_COLOUR_ANY)) {
	    err = add_regular_prop(ledh, PICL_PROP_COLOR,
		PICL_PTYPE_CHARSTRING, PICL_READ,
		colour_lkup[led_state->index].size,
		colour_lkup[led_state->index].str_colour, &proph);
	}
	if (err != PICL_SUCCESS)
		return;

	err = add_regular_prop(ledh, PICL_PROP_LABEL,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(led_state->label) + 1,
	    led_state->label, &proph);
	if (err != PICL_SUCCESS)
		return;

	err = ptree_add_node(lominfh, ledh);

	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_LOMINFO_TREE_FAILED);
	}
}

static void
fixstate(uint8_t state, const char *string, int *max_len)
{
	int		i;
	int		len;

	for (i = 0; i < (sizeof (ledstate_lkup) / sizeof (ledstate_lkup[0]));
	    i++) {
		if (ledstate_lkup[i].state == state) {
			if (ledstate_lkup[i].str_ledstate != NULL)
				free(ledstate_lkup[i].str_ledstate);
			ledstate_lkup[i].str_ledstate = strdup(string);
			len = strlen(string);
			if (len >= *max_len)
				*max_len = len + 1;
			break;
		}
	}
}

static void
add_led_nodes(int lom_fd, picl_nodehdl_t lominfh)
{
	lom_led_state_t	led_data;
	picl_nodehdl_t	ledh;
	int		res;
	int		i;

	/*
	 * If the led state enquiry ioctl is supported, an enquiry on
	 * index -1 will return the state of the highest supported index
	 * value.
	 */
	(void) memset(&led_data, 0, sizeof (led_data));
	led_data.index = -1;
	res = ioctl(lom_fd, LOMIOCLEDSTATE, &led_data);

	if (res != 0)
		return;

	if (led_labels != NULL) {
		for (i = 0; i < n_leds; i++) {
			if (led_labels[i] != NULL) {
				free(led_labels[i]);
			}
		}

		free(led_labels);
		led_labels = NULL;
	}

	if (led_handles != NULL) {
		free(led_handles);
	}

	n_leds = 0;
	led_handles = calloc(led_data.index + 1, sizeof (picl_nodehdl_t));
	led_labels = calloc(led_data.index + 1, sizeof (char *));

	if ((led_labels == NULL) || (led_handles == NULL)) {
		if (led_labels != NULL)
			free(led_labels);
		if (led_handles != NULL)
			free(led_handles);
		led_labels = NULL;
		led_handles = NULL;
		syslog(LOG_ERR, EM_NO_LED_MEM);
		return;
	}

	n_leds = led_data.index + 1;

	/*
	 * For each LED with a valid state, add a node
	 * and because of the ludicrous API, stache a copy of its label too
	 */
	for (i = 0; i < n_leds; i++) {
		(void) memset(&led_data, 0, sizeof (led_data));
		led_data.index = i;
		res = ioctl(lom_fd, LOMIOCLEDSTATE, &led_data);

		if (res != 0)
			continue;

		if (led_data.state == LOM_LED_OUTOFRANGE ||
		    led_data.state == LOM_LED_NOT_IMPLEMENTED)
			continue;


		led_labels[i] = strdup(led_data.label);
		convert_node_name(led_data.label);

		if (get_node_by_name_and_class(lominfh, led_data.label,
		    "led", &ledh) != PICL_SUCCESS) {
			/*
			 * only add a new led node,
			 * if it's not already in place
			 */
			add_led(&led_data, lominfh);
		}
	}
}

static int
add_fan_nodes(int lom_fd, picl_nodehdl_t lominfh)
{
	int		res;
	int		i;
	int		err = PICL_SUCCESS;

	res = ioctl(lom_fd, LOMIOCFANSTATE, &fandata);

	if (res == 0) {
		/*
		 * fan data available through lom, remove any placeholder
		 * fan-unit nodes, they will be superseded via lom.conf
		 */
		char	path[80];
		int	slot;
		picl_nodehdl_t	fan_unit_h;

		for (slot = 0; slot < MAX_FANS; slot++) {
			(void) snprintf(path, sizeof (path),
			    "/frutree/chassis/fan-slot?Slot=%d/fan-unit", slot);
			if (ptree_get_node_by_path(path, &fan_unit_h) !=
			    PICL_SUCCESS)
				continue;
			if (ptree_delete_node(fan_unit_h) != PICL_SUCCESS)
				continue;
			(void) ptree_destroy_node(fan_unit_h);
		}
		/*
		 * see if fan names can be obtained
		 */
		(void) memset(&info2data, 0, sizeof (info2data));
		/*
		 * if LOMIOCINFO2 not supported, names area
		 * will remain empty
		 */
		(void) ioctl(lom_fd, LOMIOCINFO2, &info2data);

		/*
		 * for each fan which is present, add a fan node
		 */
		for (i = 0; i < MAX_FANS; i++) {
			char fanname[80];
			picl_nodehdl_t	fanh;
			picl_nodehdl_t	proph;

			if (fandata.fitted[i] == 0)
				continue;

			if (info2data.fan_names[i][0] == '\0') {
				(void) snprintf(fanname, sizeof (fanname),
				    "fan%d", i + 1);
			} else {
				(void) strlcpy(fanname, info2data.fan_names[i],
				    sizeof (fanname));
			}
			convert_node_name(fanname);
			err = ptree_create_node(fanname, PICL_CLASS_FAN, &fanh);
			if (err != PICL_SUCCESS)
				break;

			err = add_volatile_prop(fanh, PICL_PROP_FAN_SPEED,
			    PICL_PTYPE_INT, PICL_READ, sizeof (int),
			    read_fan_speed, NULL, &fan_speed_handles[i]);
			if (err != PICL_SUCCESS)
				break;

			err = add_regular_prop(fanh, PICL_PROP_LOW_WARNING,
			    PICL_PTYPE_INT, PICL_READ, sizeof (int),
			    &fandata.minspeed[i], &proph);
			if (err != PICL_SUCCESS)
				break;

			err = add_regular_prop(fanh, PICL_PROP_FAN_SPEED_UNIT,
			    PICL_PTYPE_CHARSTRING, PICL_READ, sizeof ("%"),
			    "%", &proph);
			if (err != PICL_SUCCESS)
				break;

			err = add_volatile_prop(fanh, PICL_PROP_CONDITION,
			    PICL_PTYPE_CHARSTRING, PICL_READ,
			    sizeof (str_FAIL), read_fan_status, NULL,
			    &fan_status_handles[i]);
			if (err != PICL_SUCCESS)
				break;

			/*
			 * add a label for prtdiag
			 */
			err = add_regular_prop(fanh, PICL_PROP_LABEL,
			    PICL_PTYPE_CHARSTRING, PICL_READ,
			    strlen(fanname) + 1, fanname, &proph);
			if (err != PICL_SUCCESS)
				break;

			err = ptree_add_node(lominfh, fanh);
			if (err != PICL_SUCCESS)
				break;
		}

		if (err != PICL_SUCCESS) {
			syslog(LOG_ERR, EM_LOMINFO_TREE_FAILED);
		}
	}

	return (err);
}

static void
setup_strings()
{
	/*
	 * initialise led colours lookup
	 */
	int i;
	int lim = sizeof (colour_lkup) / sizeof (colour_lkup[0]);

	for (i = 0; i < lim; i++) {
		if (colour_lkup[i].str_colour != NULL)
			free(colour_lkup[i].str_colour);
	}

	colour_lkup[LOM_LED_COLOUR_ANY].str_colour = strdup(gettext("any"));
	colour_lkup[LOM_LED_COLOUR_WHITE].str_colour = strdup(gettext("white"));
	colour_lkup[LOM_LED_COLOUR_BLUE].str_colour = strdup(gettext("blue"));
	colour_lkup[LOM_LED_COLOUR_GREEN].str_colour = strdup(gettext("green"));
	colour_lkup[LOM_LED_COLOUR_AMBER].str_colour = strdup(gettext("amber"));

	for (i = 0; i < lim; i++) {
		if (colour_lkup[i].str_colour != NULL)
			colour_lkup[i].size =
			    1 + strlen(colour_lkup[i].str_colour);
	}

	/*
	 * initialise led state lookup strings
	 */
	fixstate(LOM_LED_OFF, gettext("off"), &max_state_size);
	fixstate(LOM_LED_ON, gettext("on"), &max_state_size);
	fixstate(LOM_LED_BLINKING, gettext("blinking"), &max_state_size);
}

/*
 * The size of outfilename must be PATH_MAX
 */
static int
get_config_file(char *outfilename)
{
	char	nmbuf[SYS_NMLN];
	char	pname[PATH_MAX];

	if (sysinfo(SI_PLATFORM, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, LOM_CONFFILE_NAME, PATH_MAX);
		if (access(pname, R_OK) == 0) {
			(void) strlcpy(outfilename, pname, PATH_MAX);
			return (0);
		}
	}

	if (sysinfo(SI_MACHINE, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, LOM_CONFFILE_NAME, PATH_MAX);
		if (access(pname, R_OK) == 0) {
			(void) strlcpy(outfilename, pname, PATH_MAX);
			return (0);
		}
	}

	(void) snprintf(pname, PATH_MAX, "%s/%s", PICLD_COMMON_PLUGIN_DIR,
	    LOM_CONFFILE_NAME);

	if (access(pname, R_OK) == 0) {
		(void) strlcpy(outfilename, pname, PATH_MAX);
		return (0);
	}

	return (-1);
}



/*
 * executed as part of .init when the plugin is dlopen()ed
 */
static void
picllom_register(void)
{
	(void) picld_plugin_register(&my_reg_info);
}

/*
 * Init entry point of the plugin
 * Creates the PICL nodes and properties in the physical and logical aspects.
 */
static void
picllom_init(void)
{
	picl_nodehdl_t		rooth;
	picl_nodehdl_t		plfh;
	picl_nodehdl_t		lominfh;
	int			lom_fd;
	char			fullfilename[PATH_MAX];

	/*
	 * Get platform node
	 */
	if (ptree_get_node_by_path(PICL_NODE_ROOT PICL_NODE_PLATFORM, &plfh)
	    != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_MISSING_NODE, PICL_NODE_PLATFORM);
		syslog(LOG_ERR, EM_INIT_FAILED);
		return;
	}

	/*
	 * Get lom node
	 */
	if (get_lom_node(&lominfh) != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_LOM_NODE_MISSING);
		syslog(LOG_ERR, EM_INIT_FAILED);
		return;
	}

	/*
	 * Retrive the device path to open
	 */
	if (get_lom_device_path(&lominfh) < 0) {
		syslog(LOG_ERR, EM_INIT_FAILED);
		return;
	}

	/*
	 * Open LOM device and interrogate for devices it monitors
	 */
	if ((lom_fd = open(lom_device_path, O_RDONLY)) < 0) {
		syslog(LOG_ERR, EM_SYS_ERR, lom_device_path, strerror(errno));
		return;
	}

	setup_strings();
	(void) add_temp_sensors(lom_fd, lominfh);
	(void) add_voltage_monitors(lom_fd, lominfh);
	(void) add_fan_nodes(lom_fd, lominfh);
	add_led_nodes(lom_fd, lominfh);


	if (get_config_file(fullfilename) < 0) {
		(void) close(lom_fd);
		syslog(LOG_ERR, EM_NO_CONFIG);
		return;
	}

	if (ptree_get_root(&rooth) != PICL_SUCCESS) {
		(void) close(lom_fd);
		return;
	}

	if (picld_pluginutil_parse_config_file(rooth, fullfilename) !=
	    PICL_SUCCESS)
		syslog(LOG_ERR, EM_INIT_FAILED);

	(void) close(lom_fd);
}

/*
 * fini entry point of the plugin
 */
static void
picllom_fini(void)
{
}
