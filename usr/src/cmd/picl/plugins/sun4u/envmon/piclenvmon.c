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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This plugin creates PICL nodes and properties for objects handled through
 * the enhanced LOMV system-processor interface.
 *
 * All the nodes which may be accessible through the system-processor are
 * included below the service-processor node  in the /platform tree.
 * This plugin interrogates the system-processor to determine which of
 * those nodes are actually available. Properties are added to such nodes and
 * in the case of volatile properties like temperature, a call-back function
 * is established for on-demand access to the current value.
 * LEDs for which the system-processor provides write access are associated
 * with read/write volatile properties.
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
#include <libnvpair.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/obpdefs.h>
#include <sys/envmon.h>
#include <sys/systeminfo.h>
#include <dirent.h>
#include <time.h>
#include <picldefs.h>
#include <picld_pluginutil.h>
#include <libdevinfo.h>
#include "piclenvmon.h"

static void	piclenvmon_register(void);
static void	piclenvmon_init(void);
static void	piclenvmon_fini(void);
static node_el_t	*create_node_el(picl_nodehdl_t nodeh);
static void	delete_node_el(node_el_t *pel);
static node_list_t	*create_node_list();
static void	delete_node_list(node_list_t *pnl);
static void	add_node_to_list(picl_nodehdl_t nodeh, node_list_t *listp);
static void	get_node_list_by_class(picl_nodehdl_t nodeh,
    const char *classname, node_list_t *listp);
static int	get_envmon_limits(int envmon_fd, envmon_sysinfo_t *limits_p);
static void	create_arrays();
static int	get_envmon_node(picl_nodehdl_t *envmoninfh);
static char	*create_envmon_pathname(picl_nodehdl_t envmoninfh);
static int	get_child_by_name(picl_nodehdl_t nodeh, const char *name,
    picl_nodehdl_t *childh);
static int	add_regular_prop(picl_nodehdl_t nodeh, const char *name,
    int type, int access, int size, const void *valbuf, picl_prophdl_t *prophp);
static int	add_volatile_prop(picl_nodehdl_t nodeh, const char *name,
    int type, int access, int size, ptree_vol_rdfunc_t rdfunc,
    ptree_vol_wrfunc_t wrfunc, picl_prophdl_t *prophp);
static int	get_sensor_data(int envmon_fd, envmon_handle_t *id, int cmd,
    envmon_thresholds_t *lows, envmon_thresholds_t *highs, int16_t *value);
static int	get_indicator_data(int envmon_fd, envmon_handle_t *id, int cmd,
    int16_t *condition);
static int	get_fan_data(int envmon_fd, envmon_handle_t *id, int cmd,
    envmon_thresholds_t *lows, uint16_t *speed, char *units);
static int	get_led_data(int envmon_fd, envmon_handle_t *id, int cmd,
    int8_t *state, int8_t *colour);
static int	get_keyswitch_data(int envmon_fd, envmon_handle_t *id, int cmd,
    envmon_keysw_pos_t *key_state);
static void	convert_node_name(char *ptr);
static void	convert_label_name(char *ptr);
static int	add_value_prop(picl_nodehdl_t node_hdl, const char *prop_name,
    int fru_type, int16_t value);
static int	find_picl_handle(picl_prophdl_t proph);
static int	lookup_led_status(int8_t state, const char **string);
static int	lookup_key_posn(envmon_keysw_pos_t pos, const char **string);
static int	get_config_file(char *filename);
static int	read_vol_data(ptree_rarg_t *r_arg, void *buf);
static int	write_led_data(ptree_warg_t *w_arg, const void *buf);
static int	add_env_nodes(int envmon_fd, uint8_t fru_type,
    picl_nodehdl_t envmonh);
static void	fixstate(uint8_t state, const char *string, int *max_len);
static void	fixkeyposn(envmon_keysw_pos_t keyposn, const char *string,
    int *max_len);
static void	setup_strings();
static void	free_vol_prop(picl_prophdl_t proph);
static void	envmon_evhandler(const char *ename, const void *earg,
    size_t size, void *cookie);
static int	get_serial_num(int envmon_fd, envmon_handle_t *id, int cmd,
    envmon_chassis_t *chassis);

#pragma	init(piclenvmon_register)

static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_NON_CRITICAL,
	"SUNW_piclenvmon",
	piclenvmon_init,
	piclenvmon_fini
};

static	const char str_On[] = "on";
static	const char str_Off[] = "off";
static  const char str_Blinking[] = "blinking";
static  const char str_Flashing[] = "flashing";
static	const char str_SC[] = "SC";
static	char *envmon_device_name = NULL;
static	envmon_sysinfo_t	env_limits;
static	handle_array_t	handle_arr;
static	struct {
	int		size;
	char		*str_colour;
} colour_lkup[1 + ENVMON_LED_CLR_RED];

static	struct {
	int8_t		state;
	char		*str_ledstate;
} ledstate_lkup[] = {
	{	ENVMON_LED_OFF			},
	{	ENVMON_LED_ON			},
	{	ENVMON_LED_BLINKING		},
	{	ENVMON_LED_FLASHING		}
};

static	struct {
	envmon_keysw_pos_t	pos;
	char			*str_keyposn;
} keyposn_lkup[] = {
	{	ENVMON_KEYSW_POS_UNKNOWN	},
	{	ENVMON_KEYSW_POS_NORMAL		},
	{	ENVMON_KEYSW_POS_DIAG		},
	{	ENVMON_KEYSW_POS_LOCKED		},
	{	ENVMON_KEYSW_POS_OFF		}
};

/*
 * fru-type to ioctl cmd lookup
 */
int	fru_to_cmd[] = {
	ENVMONIOCVOLTSENSOR,
	ENVMONIOCVOLTIND,
	ENVMONIOCAMPSENSOR,
	ENVMONIOCAMPIND,
	ENVMONIOCTEMPSENSOR,
	ENVMONIOCTEMPIND,
	ENVMONIOCFAN,
	ENVMONIOCFANIND,
	ENVMONIOCGETLED,
	ENVMONIOCGETKEYSW,
	ENVMONIOCCHASSISSERIALNUM
};

/*
 * fru-type to PICL CLASS
 */
const char *fru_to_class[] = {
	PICL_CLASS_VOLTAGE_SENSOR,
	PICL_CLASS_VOLTAGE_INDICATOR,
	PICL_CLASS_CURRENT_SENSOR,
	PICL_CLASS_CURRENT_INDICATOR,
	PICL_CLASS_TEMPERATURE_SENSOR,
	PICL_CLASS_TEMPERATURE_INDICATOR,
	PICL_CLASS_FAN,
	PICL_CLASS_FAN,
	PICL_CLASS_LED,
	PICL_CLASS_KEYSWITCH,
	PICL_CLASS_CHASSIS_SERIAL_NUM
};

/*
 * fru-type to PICL PROPERTY for volatile data
 */
const char *fru_to_prop[] = {
	PICL_PROP_VOLTAGE,
	PICL_PROP_CONDITION,
	PICL_PROP_CURRENT,
	PICL_PROP_CONDITION,
	PICL_PROP_TEMPERATURE,
	PICL_PROP_CONDITION,
	PICL_PROP_FAN_SPEED,
	PICL_PROP_FAN_SPEED_UNIT,
	PICL_PROP_STATE,
	PICL_PROP_STATE,
	PICL_PROP_SERIAL_NUMBER
};

/*
 * fru-type to PICL PTYPE
 */
int	fru_to_ptype[] = {
	PICL_PTYPE_FLOAT,
	PICL_PTYPE_CHARSTRING,
	PICL_PTYPE_FLOAT,
	PICL_PTYPE_CHARSTRING,
	PICL_PTYPE_INT,
	PICL_PTYPE_CHARSTRING,
	PICL_PTYPE_UNSIGNED_INT,
	PICL_PTYPE_CHARSTRING,
	PICL_PTYPE_CHARSTRING,
	PICL_PTYPE_CHARSTRING,
	PICL_PTYPE_CHARSTRING
};

/*
 * condition strings
 */
static char *cond_okay;
static char *cond_failed;

/*
 * fru-type to size of volatile property
 * the -1's are replaced by the max size of a condition string
 */
int	fru_to_size[] = {
	4, -1, 4, -1, 2, -1, 2, -1, -1, -1, -1
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
delete_node_list(node_list_t *pnl)
{
	node_el_t	*pel;

	if (pnl == NULL)
		return;

	while ((pel = pnl->head) != NULL) {
		pnl->head = pel->next;
		delete_node_el(pel);
	}

	/*
	 * normally pnl->tail would be to NULL next,
	 * but as it is about to be freed, this step can be skipped.
	 */
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
get_envmon_limits(int envmon_fd, envmon_sysinfo_t *limits_p)
{
	return (ioctl(envmon_fd, ENVMONIOCSYSINFO, limits_p));
}

static int
re_create_arrays(int envmon_fd)
{
	envmon_sysinfo_t	new_limits;
	int			res;
	int			maxnum;
	uchar_t			*fru_types;
	envmon_handle_t		*envhandles;
	picl_prophdl_t		*piclprhdls;

	res = get_envmon_limits(envmon_fd, &new_limits);
	if (res != 0)
		return (res);

	maxnum = new_limits.maxVoltSens + new_limits.maxVoltInd +
	    new_limits.maxAmpSens + new_limits.maxAmpInd +
	    new_limits.maxTempSens + new_limits.maxTempInd +
	    new_limits.maxFanSens + new_limits.maxFanInd +
	    new_limits.maxLED + N_KEY_SWITCHES;

	if (maxnum != handle_arr.maxnum) {
		/*
		 * space requirements have changed
		 */
		fru_types = calloc(maxnum, sizeof (uchar_t));
		envhandles = calloc(maxnum, sizeof (envmon_handle_t));
		piclprhdls = calloc(maxnum, sizeof (picl_prophdl_t));
		if ((fru_types == NULL) || (envhandles == NULL) ||
		    (piclprhdls == NULL)) {
			free(fru_types);
			free(envhandles);
			free(piclprhdls);
			return (-1);
		}
		free(handle_arr.fru_types);
		handle_arr.fru_types = fru_types;
		free(handle_arr.envhandles);
		handle_arr.envhandles = envhandles;
		free(handle_arr.piclprhdls);
		handle_arr.piclprhdls = piclprhdls;
	} else {
		(void) memset(handle_arr.fru_types, 0,
		    maxnum * sizeof (uchar_t));
		(void) memset(handle_arr.envhandles, 0,
		    maxnum * sizeof (envmon_handle_t));
		(void) memset(handle_arr.piclprhdls, 0,
		    maxnum * sizeof (picl_prophdl_t));
	}

	handle_arr.num = 0;
	handle_arr.maxnum = maxnum;
	env_limits = new_limits;
	return (0);
}

static void
create_arrays()
{
	int maxnum = env_limits.maxVoltSens + env_limits.maxVoltInd +
	    env_limits.maxAmpSens + env_limits.maxAmpInd +
	    env_limits.maxTempSens + env_limits.maxTempInd +
	    env_limits.maxFanSens + env_limits.maxFanInd +
	    env_limits.maxLED + N_KEY_SWITCHES;
	handle_arr.maxnum = maxnum;
	handle_arr.num = 0;
	handle_arr.fru_types = calloc(maxnum, sizeof (uchar_t));
	handle_arr.envhandles = calloc(maxnum, sizeof (envmon_handle_t));
	handle_arr.piclprhdls = calloc(maxnum, sizeof (picl_prophdl_t));
}

static int
get_envmon_node(picl_nodehdl_t *envmoninfh)
{
	int			err = PICL_SUCCESS;
	node_list_t		*listp;

	listp = create_node_list();

	if ((err = ptree_get_node_by_path(PICL_NODE_ROOT PICL_NODE_PLATFORM,
	    envmoninfh)) != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_MISSING_NODE,
		    PICL_NODE_ROOT PICL_NODE_PLATFORM);
		return (err);	/* no /platform ! */
	}

	get_node_list_by_class(*envmoninfh, PICL_CLASS_SERVICE_PROCESSOR,
	    listp);

	if (listp->head == NULL) {
		*envmoninfh = 0;
		syslog(LOG_ERR, EM_MISSING_NODE, PICL_CLASS_SERVICE_PROCESSOR);
		err = PICL_NODENOTFOUND;
	} else {
		*envmoninfh = listp->head->nodeh;
	}

	delete_node_list(listp);
	return (err);
}

static char *
create_envmon_pathname(picl_nodehdl_t envmoninfh)
{
	char		*ptr;
	char		namebuf[PATH_MAX];
	size_t		len;
	DIR		*dirp;
	struct dirent	*dp;
	struct stat	statbuf;

	/* prefix devfs-path name with /devices */
	(void) strlcpy(namebuf, "/devices", PATH_MAX);

	/*
	 * append devfs-path property
	 */
	len = strlen(namebuf);
	if (ptree_get_propval_by_name(envmoninfh, PICL_PROP_DEVFS_PATH,
	    namebuf + len, sizeof (namebuf) - len) != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_SC_NODE_INCOMPLETE);
		return (NULL);
	}

	/* locate final component of name */
	ptr = strrchr(namebuf, '/');
	if (ptr == NULL)
		return (NULL);
	*ptr = '\0';		/* terminate at end of directory path */
	len = strlen(ptr + 1);	/* length of terminal name */
	dirp = opendir(namebuf);
	if (dirp == NULL) {
		syslog(LOG_ERR, EM_SC_NODE_MISSING);
		return (NULL);
	}
	*ptr++ = '/';		/* restore '/' and advance to final name */

	while ((dp = readdir(dirp)) != NULL) {
		/*
		 * look for a name which starts with the string at *ptr
		 */
		if (strlen(dp->d_name) < len)
			continue;	/* skip short names */
		if (strncmp(dp->d_name, ptr, len) == 0) {
			/*
			 * Got a match, restore full pathname and stat the
			 * entry. Reject if not a char device
			 */
			(void) strlcpy(ptr, dp->d_name,
			    sizeof (namebuf) - (ptr - namebuf));
			if (stat(namebuf, &statbuf) < 0)
				continue;	/* reject if can't stat it */
			if (!S_ISCHR(statbuf.st_mode))
				continue;	/* not a character device */
			/*
			 * go with this entry
			 */
			(void) closedir(dirp);
			return (strdup(namebuf));
		}
	}
	syslog(LOG_ERR, EM_SC_NODE_MISSING);
	(void) closedir(dirp);
	return (NULL);
}

/*
 * look for named node as child of supplied handle
 */
static int
get_child_by_name(picl_nodehdl_t nodeh, const char *name,
    picl_nodehdl_t *childh)
{
	int		err;
	char		node_name[ENVMON_MAXNAMELEN];

	if (strlen(name) >= ENVMON_MAXNAMELEN)
		return (PICL_NODENOTFOUND);
	err = ptree_get_propval_by_name(nodeh, PICL_PROP_CHILD, childh,
	    sizeof (*childh));
	while (err == PICL_SUCCESS) {
		err = ptree_get_propval_by_name(*childh, PICL_PROP_NAME,
		    node_name, sizeof (node_name));
		if ((err == PICL_SUCCESS) &&
		    (strncmp(name, node_name, ENVMON_MAXNAMELEN) == 0))
			return (PICL_SUCCESS);
		err = ptree_get_propval_by_name(*childh, PICL_PROP_PEER,
		    childh, sizeof (*childh));
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
add_volatile_prop(picl_nodehdl_t nodeh, const char *name, int type, int access,
    int size, ptree_vol_rdfunc_t rdfunc, ptree_vol_wrfunc_t wrfunc,
    picl_prophdl_t *prophp)
{
	int			err;
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    type, (access|PICL_VOLATILE), size, (char *)name, rdfunc, wrfunc);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_and_add_prop(nodeh, &propinfo, NULL, &proph);
	if (err == PICL_SUCCESS && prophp)
		*prophp = proph;
	return (err);
}

/*
 * There are 5 different structures used for reading environmental data
 * from the service-processor. A different function is used for each one.
 * Some functions cover several ioctls, so the desired ioctl is part of
 * the interface. In each case the id parameter is read/write, the
 * returned value being the next id for this fru type.
 */

/*
 * Function to read sensor data.
 */
static int
get_sensor_data(int envmon_fd, envmon_handle_t *id, int cmd,
    envmon_thresholds_t *lows, envmon_thresholds_t *highs, int16_t *value)
{
	int		res;
	envmon_sensor_t	data;

	(void) memset(&data, 0, sizeof (data));
	data.id = *id;
	res = ioctl(envmon_fd, cmd, &data);
	if (res < 0) {
		return (PICL_NOTREADABLE);
	}

	*id = data.next_id;

	if ((data.sensor_status & ENVMON_NOT_PRESENT) != 0)
		return (PICL_INVALIDHANDLE);

	/*
	 * it is assumed that threshold data will be available,
	 * even though the current sensor value may be inaccessible
	 */
	if (lows != NULL)
		*lows = data.lowthresholds;
	if (highs != NULL)
		*highs = data.highthresholds;

	if ((data.sensor_status & ENVMON_INACCESSIBLE) != 0) {
		if (value != NULL)
			*value = ENVMON_VAL_UNAVAILABLE;
		return (PICL_PROPVALUNAVAILABLE);
	}
	if (value != NULL)
		*value = data.value;
	return (PICL_SUCCESS);
}

/*
 * Function to read indicator data.
 */
static int
get_indicator_data(int envmon_fd, envmon_handle_t *id, int cmd,
    int16_t *condition)
{
	int			res;
	envmon_indicator_t	data;

	data.id = *id;
	res = ioctl(envmon_fd, cmd, &data);
	if (res < 0)
		return (PICL_NOTREADABLE);
	*id = data.next_id;
	if ((data.sensor_status & ENVMON_NOT_PRESENT) != 0)
		return (PICL_INVALIDHANDLE);
	if (condition != NULL)
		*condition = data.condition;
	if ((data.sensor_status & ENVMON_INACCESSIBLE) != 0) {
		return (PICL_PROPVALUNAVAILABLE);
	}
	return (PICL_SUCCESS);
}

/*
 * Function to read fan data.
 */
static int
get_fan_data(int envmon_fd, envmon_handle_t *id, int cmd,
    envmon_thresholds_t *lows, uint16_t *speed, char *units)
{
	int		res;
	envmon_fan_t	data;

	data.id = *id;
	res = ioctl(envmon_fd, cmd, &data);
	if (res < 0)
		return (PICL_NOTREADABLE);
	*id = data.next_id;
	if ((data.sensor_status & ENVMON_NOT_PRESENT) != 0)
		return (PICL_INVALIDHANDLE);
	if (lows != NULL)
		*lows = data.lowthresholds;
	if (units != NULL)
		(void) strlcpy(units, data.units, sizeof (data.units));

	if ((data.sensor_status & ENVMON_INACCESSIBLE) != 0) {
		if (speed != NULL)
			*speed = ENVMON_VAL_UNAVAILABLE;
		return (PICL_PROPVALUNAVAILABLE);
	}
	if (speed != NULL)
		*speed = data.speed;
	return (PICL_SUCCESS);
}

/*
 * Function to read LED data.
 */
static int
get_led_data(int envmon_fd, envmon_handle_t *id, int cmd,
    int8_t *state, int8_t *colour)
{
	int			res;
	envmon_led_info_t	data;

	data.id = *id;
	res = ioctl(envmon_fd, cmd, &data);
	if (res < 0)
		return (PICL_NOTREADABLE);
	*id = data.next_id;
	if ((data.sensor_status & ENVMON_NOT_PRESENT) != 0)
		return (PICL_INVALIDHANDLE);
	if (colour != NULL)
		*colour = data.led_color;
	if ((data.sensor_status & ENVMON_INACCESSIBLE) != 0) {
		return (PICL_PROPVALUNAVAILABLE);
	}
	if (state != NULL)
		*state = data.led_state;
	return (PICL_SUCCESS);
}

/*
 * Function to read key-switch position
 * Returns PICL_INVALIDHANDLE if ioctl not supported (or fails)
 */
static int
get_keyswitch_data(int envmon_fd, envmon_handle_t *id, int cmd,
    envmon_keysw_pos_t *key_state)
{
	int			res;

	if (id->name[0] == '\0') {
		(void) strlcpy(id->name, KEYSWITCH_NAME, sizeof (id->name));
		return (PICL_INVALIDHANDLE);
	} else if (strncmp(id->name, KEYSWITCH_NAME, sizeof (id->name)) != 0) {
		id->name[0] = '\0';
		return (PICL_INVALIDHANDLE);
	} else {
		res = ioctl(envmon_fd, cmd, key_state);
		id->name[0] = '\0';

		if (res < 0)
			return (PICL_INVALIDHANDLE);
		return (PICL_SUCCESS);
	}
}

/*
 * Function to read the chassis serial number
 * Returns PICL_INVALIDHANDLE if ioctl not supported (or fails)
 */
static int
get_serial_num(int envmon_fd, envmon_handle_t *id, int cmd,
    envmon_chassis_t *chassis)
{
	int			res;

	if (id->name[0] == '\0') {
		(void) strlcpy(id->name, CHASSIS_SERIAL_NUMBER,
		    sizeof (id->name));
		return (PICL_INVALIDHANDLE);
	} else if (strncmp(id->name, CHASSIS_SERIAL_NUMBER, sizeof (id->name))
	    != 0) {
		id->name[0] = '\0';
		return (PICL_INVALIDHANDLE);
	} else {
		res = ioctl(envmon_fd, cmd, chassis);
		id->name[0] = '\0';

		if (res < 0)
			return (PICL_INVALIDHANDLE);
		return (PICL_SUCCESS);
	}
}

/*
 * change to lower case and convert any spaces into hyphens,
 * and any dots or colons symbols into underscores
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
		} else if ((ch == '.') || (ch == ':')) {
			*ptr = '_';
		}
	}
}

/*
 * strip to the last '.' separator and keep the rest
 * change ':' to '/' within the last component
 */
static void
convert_label_name(char *name)
{
	const char	*cptr;
	char		ch;

	cptr = strrchr(name, '.');

	if (cptr == NULL)
		cptr = name;
	else
		cptr++;			/* skip the '.' */

	do {
		ch = *cptr++;

		if (ch == ':')
			ch = '/';

		*name++ = ch;
	} while (ch != '\0');
}

/*
 * add a value property
 */
static int
add_value_prop(picl_nodehdl_t node_hdl, const char *prop_name, int fru_type,
    int16_t value)
{
	int err;
	union {
		float		u_f;
		int16_t		u_i16;
	} val_buf;

	if (fru_to_ptype[fru_type] == PICL_PTYPE_FLOAT)
		val_buf.u_f = (float)((float)value / (float)1000.0);
	else
		val_buf.u_i16 = value;

	err = add_regular_prop(node_hdl, prop_name, fru_to_ptype[fru_type],
	    PICL_READ, fru_to_size[fru_type], &val_buf, NULL);
	return (err);
}

static int
find_picl_handle(picl_prophdl_t proph)
{
	int	index;

	for (index = 0; index < handle_arr.num; index++) {
		if (handle_arr.piclprhdls[index] == proph)
			return (index);
	}

	return (-1);
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
	return (PICL_PROPVALUNAVAILABLE);
}

static int
lookup_key_posn(envmon_keysw_pos_t pos, const char **string)
{
	int	i;
	int	lim = sizeof (keyposn_lkup) / sizeof (keyposn_lkup[0]);

	for (i = 0; i < lim; i++) {
		if (keyposn_lkup[i].pos == pos) {
			*string = keyposn_lkup[i].str_keyposn;
			return (PICL_SUCCESS);
		}
	}

	*string = "";
	return (PICL_PROPVALUNAVAILABLE);
}

/*
 * function to read volatile data associated with a PICL property handle
 */
static int
read_vol_data(ptree_rarg_t *r_arg, void *buf)
{
	picl_prophdl_t		proph;
	int			index;
	uint8_t			fru_type;
	envmon_handle_t		id;
	int16_t			sensor_data;
	int8_t			led_state;
	envmon_keysw_pos_t	key_posn;
	envmon_chassis_t	chassis;
	float			float_data;
	int			cmd;
	int			err;
	int			envmon_fd;
	const char		*cptr;

	proph = r_arg->proph;
	index = find_picl_handle(proph);
	if (index < 0)
		return (PICL_INVALIDHANDLE);
	fru_type = handle_arr.fru_types[index];
	id = handle_arr.envhandles[index];
	cmd = fru_to_cmd[fru_type];
	envmon_fd = open(envmon_device_name, O_RDONLY);
	if (envmon_fd < 0)
		return (PICL_NOTREADABLE);

	/*
	 * read environmental data according to type
	 */
	switch (fru_type) {
	case ENVMON_VOLT_SENS:
		/*FALLTHROUGH*/
	case ENVMON_AMP_SENS:
		/*FALLTHROUGH*/
	case ENVMON_TEMP_SENS:
		err = get_sensor_data(envmon_fd, &id, cmd, NULL, NULL,
		    &sensor_data);
		break;
	case ENVMON_VOLT_IND:
		/*FALLTHROUGH*/
	case ENVMON_AMP_IND:
		/*FALLTHROUGH*/
	case ENVMON_TEMP_IND:
		/*FALLTHROUGH*/
	case ENVMON_FAN_IND:
		err = get_indicator_data(envmon_fd, &id, cmd, &sensor_data);
		break;
	case ENVMON_FAN_SENS:
		err = get_fan_data(envmon_fd, &id, cmd, NULL,
		    (uint16_t *)&sensor_data, NULL);
		break;
	case ENVMON_LED_IND:
		err = get_led_data(envmon_fd, &id, cmd, &led_state, NULL);
		break;
	case ENVMON_KEY_SWITCH:
		err = get_keyswitch_data(envmon_fd, &id, cmd, &key_posn);
		break;
	case ENVMON_CHASSIS:
		err = get_serial_num(envmon_fd, &id, cmd, &chassis);
		break;
	default:
		err = PICL_FAILURE;
		break;
	}

	(void) close(envmon_fd);
	if (err != PICL_SUCCESS) {
		/*
		 * PICL_INVALIDHANDLE is used internally, but it upsets
		 * prtpicl; change it to PICL_PROPVALUNAVAILABLE
		 */
		if (err == PICL_INVALIDHANDLE)
			err = PICL_PROPVALUNAVAILABLE;
		return (err);
	}

	/*
	 * convert data and copy out
	 */
	switch (fru_type) {
	case ENVMON_VOLT_SENS:
		/*FALLTHROUGH*/
	case ENVMON_AMP_SENS:
		float_data = (float)((float)sensor_data / (float)1000.0);
		(void) memcpy(buf, &float_data, sizeof (float_data));
		break;

	case ENVMON_TEMP_SENS:
		/*FALLTHROUGH*/
	case ENVMON_FAN_SENS:
		(void) memcpy(buf, &sensor_data, sizeof (sensor_data));
		break;

	case ENVMON_VOLT_IND:
		/*FALLTHROUGH*/
	case ENVMON_AMP_IND:
		/*FALLTHROUGH*/
	case ENVMON_TEMP_IND:
		/*FALLTHROUGH*/
	case ENVMON_FAN_IND:
		(void) strlcpy(buf, sensor_data == 0 ? cond_okay : cond_failed,
		    fru_to_size[fru_type]);
		break;

	case ENVMON_LED_IND:
		err = lookup_led_status(led_state, &cptr);
		if (err != PICL_SUCCESS)
			return (err);
		(void) strlcpy(buf, cptr, fru_to_size[fru_type]);
		break;

	case ENVMON_KEY_SWITCH:
		err = lookup_key_posn(key_posn, &cptr);
		if (err != PICL_SUCCESS)
			return (err);
		(void) strlcpy(buf, cptr, fru_to_size[fru_type]);
		break;
	case ENVMON_CHASSIS:
		(void) memcpy(buf, chassis.serial_number,
		    sizeof (chassis.serial_number));
		break;

	default:
		return (PICL_FAILURE);
	}

	return (PICL_SUCCESS);
}

static int
write_led_data(ptree_warg_t *w_arg, const void *buf)
{
	picl_prophdl_t		proph;
	int			index;
	uint8_t			fru_type;
	int			err;
	int			envmon_fd;
	envmon_led_ctl_t	led_ctl;

	proph = w_arg->proph;
	index = find_picl_handle(proph);
	if (index < 0)
		return (PICL_INVALIDHANDLE);
	fru_type = handle_arr.fru_types[index];
	if (fru_type != ENVMON_LED_IND)
		return (PICL_INVALIDARG);
	if (w_arg->cred.dc_euid != SUPER_USER)
		return (PICL_PERMDENIED);

	/* see if the requested state is recognized */
	if (strcasecmp(str_Off, buf) == 0)
		led_ctl.led_state = ENVMON_LED_OFF;
	else if (strcasecmp(str_On, buf) == 0)
		led_ctl.led_state = ENVMON_LED_ON;
	else if (strcasecmp(str_Blinking, buf) == 0)
		led_ctl.led_state = ENVMON_LED_BLINKING;
	else if (strcasecmp(str_Flashing, buf) == 0)
		led_ctl.led_state = ENVMON_LED_FLASHING;
	else
		return (PICL_INVALIDARG);

	envmon_fd = open(envmon_device_name, O_RDWR);
	if (envmon_fd < 0)
		return (PICL_FAILURE);
	led_ctl.id = handle_arr.envhandles[index];
	err = ioctl(envmon_fd, ENVMONIOCSETLED, &led_ctl);
	(void) close(envmon_fd);
	if (err < 0)
		return (PICL_FAILURE);
	return (PICL_SUCCESS);
}

/*
 * if colour information is not supplied by the service processor,
 * try to determine led colour from the handle name.
 */
static void
fix_led_colour(int8_t *colour_p, const char *id)
{
	const char	*cptr = strrchr(id, '.');

	if ((*colour_p < ENVMON_LED_CLR_NONE) ||
	    (*colour_p > ENVMON_LED_CLR_RED))
		syslog(LOG_ERR, EM_INVALID_COLOR, *colour_p, id);
	if (cptr == NULL) {
		*colour_p = ENVMON_LED_CLR_NONE;
		return;
	}

	cptr++;		/* step over '.' */

	if (strcmp(cptr, LED_ACT) == 0)
		    *colour_p = ENVMON_LED_CLR_GREEN;
	else if (strcmp(cptr, LED_SERVICE) == 0)
		*colour_p = ENVMON_LED_CLR_AMBER;
	else if (strcmp(cptr, LED_LOCATE) == 0)
		*colour_p = ENVMON_LED_CLR_WHITE;
	else if (strcmp(cptr, LED_OK2RM) == 0)
		*colour_p = ENVMON_LED_CLR_BLUE;
	else
		*colour_p = ENVMON_LED_CLR_NONE;
}

/*
 * Add nodes for environmental devices of type fru_type
 * below the supplied node.
 */
static int
add_env_nodes(int envmon_fd, uint8_t fru_type, picl_nodehdl_t envmonh)
{
	envmon_handle_t		id;
	envmon_thresholds_t	lows;
	envmon_thresholds_t	highs;
	char			units[ENVMON_MAXNAMELEN];
	char			platform_tree_name[ENVMON_MAXNAMELEN];
	char			label_name[ENVMON_MAXNAMELEN];
	int16_t			sensor_data;
	int8_t			led_state;
	int8_t			colour;
	envmon_keysw_pos_t	key_state;
	envmon_chassis_t	chassis_num;
	int			cmd;
	int			err;
	int			index = handle_arr.num;
	picl_nodehdl_t		node_hdl;

	/*
	 * catch table is full at start
	 */
	if (index >= handle_arr.maxnum)
		return (PICL_FAILURE);

	cmd = fru_to_cmd[fru_type];
	id.name[0] = '\0';

	do {
		lows.warning = lows.shutdown = lows.poweroff =
		    ENVMON_VAL_UNAVAILABLE;
		highs.warning = highs.shutdown = highs.poweroff =
		    ENVMON_VAL_UNAVAILABLE;
		handle_arr.fru_types[index] = fru_type;
		/* must store id before reading data as it is then updated */
		handle_arr.envhandles[index] = id;
		/*
		 * read environmental data according to type
		 */
		switch (fru_type) {
		case ENVMON_VOLT_SENS:
			/*FALLTHROUGH*/
		case ENVMON_AMP_SENS:
			/*FALLTHROUGH*/
		case ENVMON_TEMP_SENS:
			err = get_sensor_data(envmon_fd, &id, cmd, &lows,
			    &highs, &sensor_data);
			break;
		case ENVMON_VOLT_IND:
			/*FALLTHROUGH*/
		case ENVMON_AMP_IND:
			/*FALLTHROUGH*/
		case ENVMON_TEMP_IND:
			/*FALLTHROUGH*/
		case ENVMON_FAN_IND:
			err = get_indicator_data(envmon_fd, &id, cmd,
			    &sensor_data);
			break;
		case ENVMON_FAN_SENS:
			err = get_fan_data(envmon_fd, &id, cmd, &lows,
			    (uint16_t *)&sensor_data, units);
			break;
		case ENVMON_LED_IND:
			err = get_led_data(envmon_fd, &id, cmd, &led_state,
			    &colour);
			break;
		case ENVMON_KEY_SWITCH:
			err = get_keyswitch_data(envmon_fd, &id, cmd,
			    &key_state);
			break;
		case ENVMON_CHASSIS:
			err = get_serial_num(envmon_fd, &id, cmd,
			    &chassis_num);
			break;
		default:
			return (PICL_FAILURE);
		}

		if (err == PICL_INVALIDHANDLE)
			continue;
		if ((err != PICL_SUCCESS) && (err != PICL_PROPVALUNAVAILABLE)) {
			syslog(LOG_ERR, EM_NODE_ACCESS, id, fru_type, err);
			continue;
		}

		/*
		 * successfully read environmental data, add to PICL
		 */
		(void) strlcpy(platform_tree_name,
		    handle_arr.envhandles[index].name,
		    sizeof (platform_tree_name));

		(void) strlcpy(label_name, platform_tree_name,
		    ENVMON_MAXNAMELEN);
		convert_label_name(label_name);
		convert_node_name(platform_tree_name);
		/*
		 * does this node already exist?
		 */
		err = get_child_by_name(envmonh, platform_tree_name, &node_hdl);
		if (err == PICL_SUCCESS) {
			/*
			 * skip over existing node
			 */
			continue;
		}
		err = ptree_create_node(platform_tree_name,
		    fru_to_class[fru_type], &node_hdl);
		if (err != PICL_SUCCESS) {
			break;
		}
		err = add_volatile_prop(node_hdl, fru_to_prop[fru_type],
		    fru_to_ptype[fru_type],
		    PICL_READ | (fru_type == ENVMON_LED_IND ? PICL_WRITE : 0),
		    fru_to_size[fru_type], read_vol_data,
		    fru_type == ENVMON_LED_IND ? write_led_data : NULL,
		    &handle_arr.piclprhdls[index]);
		if (err != PICL_SUCCESS) {
			break;
		}

		/*
		 * if any thresholds are defined add a property
		 */
		if (lows.warning != ENVMON_VAL_UNAVAILABLE) {
			err = add_value_prop(node_hdl, PICL_PROP_LOW_WARNING,
			    fru_type, lows.warning);
			if (err != PICL_SUCCESS) {
				break;
			}
		}
		if (lows.shutdown != ENVMON_VAL_UNAVAILABLE) {
			err = add_value_prop(node_hdl, PICL_PROP_LOW_SHUTDOWN,
			    fru_type, lows.shutdown);
			if (err != PICL_SUCCESS) {
				break;
			}
		}
		if (lows.poweroff != ENVMON_VAL_UNAVAILABLE) {
			err = add_value_prop(node_hdl, PICL_PROP_LOW_POWER_OFF,
			    fru_type, lows.poweroff);
			if (err != PICL_SUCCESS) {
				break;
			}
		}
		if (highs.warning != ENVMON_VAL_UNAVAILABLE) {
			err = add_value_prop(node_hdl, PICL_PROP_HIGH_WARNING,
			    fru_type, highs.warning);
			if (err != PICL_SUCCESS) {
				break;
			}
		}
		if (highs.shutdown != ENVMON_VAL_UNAVAILABLE) {
			err = add_value_prop(node_hdl, PICL_PROP_HIGH_SHUTDOWN,
			    fru_type, highs.shutdown);
			if (err != PICL_SUCCESS) {
				break;
			}
		}
		if (highs.poweroff != ENVMON_VAL_UNAVAILABLE) {
			err = add_value_prop(node_hdl, PICL_PROP_HIGH_POWER_OFF,
			    fru_type, highs.poweroff);
			if (err != PICL_SUCCESS) {
				break;
			}
		}

		/*
		 * if device is a fan sensor, add a speedunit property
		 */
		if (fru_type == ENVMON_FAN_SENS) {
			err = add_regular_prop(node_hdl,
			    PICL_PROP_FAN_SPEED_UNIT, PICL_PTYPE_CHARSTRING,
			    PICL_READ, 1 + strlen(units), units, NULL);
			if (err != PICL_SUCCESS) {
				break;
			}
		}
		/*
		 * If device is a LED indicator and returns a colour,
		 * add a colour property.
		 */
		if (fru_type == ENVMON_LED_IND) {
			if (colour < 0 || colour == ENVMON_LED_CLR_ANY ||
			    colour > ENVMON_LED_CLR_RED)
				fix_led_colour(&colour,
				    handle_arr.envhandles[index].name);
			if (colour != ENVMON_LED_CLR_NONE) {
				err = add_regular_prop(node_hdl,
				    PICL_PROP_COLOR, PICL_PTYPE_CHARSTRING,
				    PICL_READ, colour_lkup[colour].size,
				    colour_lkup[colour].str_colour, NULL);
				if (err != PICL_SUCCESS) {
					break;
				}
			}
		}
		/*
		 * add a label property unless it's a keyswitch or the
		 * chassis serial number. keyswitch and chassis serial
		 * number are labelled from a config file because the
		 * ALOM interface doesn't supply a name for it)
		 */
		if ((fru_type != ENVMON_KEY_SWITCH) &&
		    (fru_type != ENVMON_CHASSIS)) {
			err = add_regular_prop(node_hdl, PICL_PROP_LABEL,
			    PICL_PTYPE_CHARSTRING, PICL_READ,
			    1 + strlen(label_name), label_name, NULL);

			if (err != PICL_SUCCESS) {
				break;
			}
		}
		/*
		 * all properties added to this node, add the node below
		 * the supplied anchor point
		 */
		err = ptree_add_node(envmonh, node_hdl);

		if (err != PICL_SUCCESS) {
			break;
		}

		/*
		 * that node went in OK, advance index
		 */
		index++;

	} while ((id.name[0] != '\0') && (index < handle_arr.maxnum));

	handle_arr.num = index;
	return (err);
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
fixkeyposn(envmon_keysw_pos_t keyposn, const char *string, int *max_len)
{
	int		i;
	int		len;

	for (i = 0; i < (sizeof (keyposn_lkup) / sizeof (keyposn_lkup[0]));
	    i++) {
		if (keyposn_lkup[i].pos == keyposn) {
			if (keyposn_lkup[i].str_keyposn != NULL)
				free(keyposn_lkup[i].str_keyposn);
			keyposn_lkup[i].str_keyposn = strdup(string);
			len = strlen(string);
			if (len >= *max_len)
				*max_len = len + 1;
			break;
		}
	}
}

static void
setup_strings()
{
	int string_size;
	int i;
	int lim = sizeof (colour_lkup) / sizeof (colour_lkup[0]);

	/*
	 * initialise led colours lookup
	 */
	for (i = 0; i < lim; i++) {
		if (colour_lkup[i].str_colour != NULL)
			free(colour_lkup[i].str_colour);
	}

	colour_lkup[ENVMON_LED_CLR_ANY].str_colour = strdup(gettext("any"));
	colour_lkup[ENVMON_LED_CLR_WHITE].str_colour =
	    strdup(gettext("white"));
	colour_lkup[ENVMON_LED_CLR_BLUE].str_colour = strdup(gettext("blue"));
	colour_lkup[ENVMON_LED_CLR_GREEN].str_colour =
	    strdup(gettext("green"));
	colour_lkup[ENVMON_LED_CLR_AMBER].str_colour =
	    strdup(gettext("amber"));
	colour_lkup[ENVMON_LED_CLR_RED].str_colour =
	    strdup(gettext("red"));

	for (i = 0; i < lim; i++) {
		if (colour_lkup[i].str_colour != NULL)
			colour_lkup[i].size =
			    1 + strlen(colour_lkup[i].str_colour);
	}

	/*
	 * initialise condition strings and note longest
	 */
	string_size = 0;
	cond_okay = strdup(gettext("okay"));
	if (strlen(cond_okay) >= string_size)
		string_size = 1 + strlen(cond_okay);
	cond_failed = strdup(gettext("failed"));
	if (strlen(cond_failed) >= string_size)
		string_size = 1 + strlen(cond_failed);

	for (i = 0; i < sizeof (fru_to_size) / sizeof (fru_to_size[0]); i++)
		if (fru_to_size[i] == -1)
			fru_to_size[i] = string_size;

	/*
	 * initialise led state lookup strings
	 */
	string_size = 0;
	fixstate(ENVMON_LED_OFF, gettext("off"), &string_size);
	fixstate(ENVMON_LED_ON, gettext("on"), &string_size);
	fixstate(ENVMON_LED_BLINKING, gettext("blinking"), &string_size);
	fixstate(ENVMON_LED_FLASHING, gettext("flashing"), &string_size);
	fru_to_size[ENVMON_LED_IND] = string_size;

	/*
	 * initialise key position lookup strings
	 */
	string_size = 0;
	fixkeyposn(ENVMON_KEYSW_POS_UNKNOWN, gettext("UNKNOWN"), &string_size);
	fixkeyposn(ENVMON_KEYSW_POS_NORMAL, gettext("NORMAL"), &string_size);
	fixkeyposn(ENVMON_KEYSW_POS_DIAG, gettext("DIAG"), &string_size);
	fixkeyposn(ENVMON_KEYSW_POS_LOCKED, gettext("LOCKED"), &string_size);
	fixkeyposn(ENVMON_KEYSW_POS_OFF, gettext("STBY"), &string_size);
	fru_to_size[ENVMON_KEY_SWITCH] = string_size;

	/*
	 * initialise chassis serial number string
	 */
	fru_to_size[ENVMON_CHASSIS] = ENVMON_MAXNAMELEN;
}

/*
 * The size of outfilename must be PATH_MAX
 */
static int
get_config_file(char *filename)
{
	char	nmbuf[SYS_NMLN];
	char	pname[PATH_MAX];

	if (sysinfo(SI_PLATFORM, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, ENVMON_CONFFILE_NAME, PATH_MAX);
		if (access(pname, R_OK) == 0) {
			(void) strlcpy(filename, pname, PATH_MAX);
			return (0);
		}
	}

	if (sysinfo(SI_MACHINE, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, ENVMON_CONFFILE_NAME, PATH_MAX);
		if (access(pname, R_OK) == 0) {
			(void) strlcpy(filename, pname, PATH_MAX);
			return (0);
		}
	}

	(void) snprintf(pname, PATH_MAX, "%s/%s",
	    PICLD_COMMON_PLUGIN_DIR, ENVMON_CONFFILE_NAME);

	if (access(pname, R_OK) == 0) {
		(void) strlcpy(filename, pname, PATH_MAX);
		return (0);
	}

	return (-1);
}

static void
free_vol_prop(picl_prophdl_t proph)
{
	int	index;

	index = find_picl_handle(proph);
	if (index >= 0) {
		handle_arr.num--;
		if (index != handle_arr.num) {
			/* relocate last entry into hole just created */
			handle_arr.fru_types[index] =
			    handle_arr.fru_types[handle_arr.num];
			handle_arr.envhandles[index] =
			    handle_arr.envhandles[handle_arr.num];
			handle_arr.piclprhdls[index] =
			    handle_arr.piclprhdls[handle_arr.num];
		}
	}
}

/*
 * handle PICL FRU ADDED and FRU REMOVED events
 */
/*ARGSUSED*/
static void
envmon_evhandler(const char *ename, const void *earg, size_t size,
    void *cookie)
{
	char			path[MAXPATHLEN];
	picl_nodehdl_t		locnodeh;
	int			retval;
	picl_nodehdl_t		childh;
	picl_nodehdl_t		nodeh;
	picl_prophdl_t		tableh;
	picl_prophdl_t		tblh;
	picl_prophdl_t		proph;
	ptree_propinfo_t	pi;

	if (strcmp(ename, PICL_FRU_ADDED) == 0) {
		retval = nvlist_lookup_uint64((nvlist_t *)earg,
		    PICLEVENTARG_PARENTHANDLE, &locnodeh);

		if (retval != 0) {
			syslog(LOG_ERR, EM_EV_MISSING_ARG,
			    PICLEVENTARG_PARENTHANDLE);
			return;
		}
		retval = ptree_get_propval_by_name(locnodeh, PICL_PROP_NAME,
		    path, sizeof (path));
		if (retval == PICL_SUCCESS) {
			/*
			 * Open envmon device and interrogate
			 */
			int		envmon_fd;
			int		fru_type;
			picl_nodehdl_t	envmoninfh;

			if (get_envmon_node(&envmoninfh) != PICL_SUCCESS) {
				syslog(LOG_ERR, EM_SC_NODE_MISSING);
				return;
			}

			if ((envmon_fd = open(envmon_device_name, O_RDONLY)) <
			    0) {
				syslog(LOG_ERR, EM_SYS_ERR, envmon_device_name,
				    strerror(errno));
				return;
			}

			if (strcmp(str_SC, path) == 0) {
				/*
				 * SC state change - re-assess platform tree
				 */
				if (re_create_arrays(envmon_fd) != 0) {
					/*
					 * out of memory - make no changes
					 */
					return;
				}
				/*
				 * dropped memory of volatile prop handles
				 * so drop the nodes also, then rebuild for
				 * the newly loaded SC
				 */
				retval = ptree_get_propval_by_name(envmoninfh,
				    PICL_PROP_PARENT, &nodeh, sizeof (nodeh));
				if (retval != PICL_SUCCESS) {
					(void) close(envmon_fd);
					return;
				}
				retval = ptree_get_propval_by_name(envmoninfh,
				    PICL_PROP_NAME, path, sizeof (path));
				if (retval != PICL_SUCCESS) {
					(void) close(envmon_fd);
					return;
				}

				retval = ptree_delete_node(envmoninfh);
				if (retval == PICL_SUCCESS)
				    (void) ptree_destroy_node(envmoninfh);
				retval = ptree_create_node(path,
				    PICL_CLASS_SERVICE_PROCESSOR, &envmoninfh);
				if (retval != PICL_SUCCESS) {
					(void) close(envmon_fd);
					return;
				}
				retval = ptree_add_node(nodeh, envmoninfh);
				if (retval != PICL_SUCCESS) {
					(void) close(envmon_fd);
					return;
				}
			}

			for (fru_type = 0; fru_type < ENVMONTYPES;
			    fru_type++) {
				(void) add_env_nodes(envmon_fd, fru_type,
				    envmoninfh);
			}

			(void) close(envmon_fd);
		}
	} else if (strcmp(ename, PICL_FRU_REMOVED) == 0) {
		retval = nvlist_lookup_uint64((nvlist_t *)earg,
		    PICLEVENTARG_FRUHANDLE, &childh);

		if (retval != 0) {
			syslog(LOG_ERR, EM_EV_MISSING_ARG,
			    PICLEVENTARG_FRUHANDLE);
			return;
		}
		retval = ptree_get_propval_by_name(childh, PICL_PROP_NAME,
		    path, sizeof (path));
		if (retval == PICL_SUCCESS) {
			retval = ptree_get_prop_by_name(childh,
			    PICL_PROP_DEVICES, &tableh);

			if (retval != PICL_SUCCESS) {
				/* no Devices table, nothing to do */
				return;
			}

			/*
			 * follow all reference properties in the second
			 * column of the table and delete the referenced node
			 */
			retval = ptree_get_propval(tableh, &tblh,
			    sizeof (tblh));
			if (retval != PICL_SUCCESS) {
				/*
				 * can't get value of table property
				 */
				return;
			}
			/* get first col, first row */
			retval = ptree_get_next_by_col(tblh, &tblh);
			if (retval != PICL_SUCCESS) {
				/*
				 * no rows?
				 */
				return;
			}
			/*
			 * starting at next col, get every entry in the column
			 */
			for (retval = ptree_get_next_by_row(tblh, &tblh);
			    retval == PICL_SUCCESS;
			    retval = ptree_get_next_by_col(tblh, &tblh)) {
				/*
				 * should be a ref prop in our hands,
				 * get the target node handle
				 */
				retval = ptree_get_propval(tblh, &nodeh,
				    sizeof (nodeh));
				if (retval != PICL_SUCCESS) {
					continue;
				}
				/*
				 * got the referenced node, has it got a
				 * volatile property to clean up?
				 */
				retval = ptree_get_first_prop(nodeh, &proph);
				while (retval == PICL_SUCCESS) {
					retval = ptree_get_propinfo(proph, &pi);
					if ((retval == PICL_SUCCESS) &&
					    (pi.piclinfo.accessmode &
					    PICL_VOLATILE))
						free_vol_prop(proph);
					retval = ptree_get_next_prop(proph,
					    &proph);
				}
				/*
				 * all volatile properties gone, remove node
				 */
				retval = ptree_delete_node(nodeh);
				if (retval == PICL_SUCCESS)
				    (void) ptree_destroy_node(nodeh);
			}
		}
	}
}

/*
 * executed as part of .init when the plugin is dlopen()ed
 */
static void
piclenvmon_register(void)
{
	(void) picld_plugin_register(&my_reg_info);
}

/*
 * Init entry point of the plugin
 * Creates the PICL nodes and properties in the physical and logical aspects.
 */
static void
piclenvmon_init(void)
{
	picl_nodehdl_t		rooth;
	picl_nodehdl_t		plfh;
	picl_nodehdl_t		envmoninfh;
	int			res;
	int			envmon_fd;
	int			fru_type;
	char			pathname[PATH_MAX];

	/*
	 * locate and parse config file
	 */
	if (get_config_file(pathname) < 0)
		return;

	if ((ptree_get_root(&rooth) != PICL_SUCCESS) ||
	    (picld_pluginutil_parse_config_file(rooth, pathname) !=
	    PICL_SUCCESS)) {
		syslog(LOG_ERR, EM_INIT_FAILED);
	}

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
	 * Get service-processor node
	 */
	if (get_envmon_node(&envmoninfh) != PICL_SUCCESS)
		return;

	/*
	 * We may have been restarted, make sure we don't leak
	 */
	if (envmon_device_name != NULL) {
		free(envmon_device_name);
	}

	if ((envmon_device_name = create_envmon_pathname(envmoninfh)) == NULL)
		return;

	/*
	 * Open envmon device and interrogate for devices it monitors
	 */
	if ((envmon_fd = open(envmon_device_name, O_RDONLY)) < 0) {
		syslog(LOG_ERR, EM_SYS_ERR, envmon_device_name,
		    strerror(errno));
		return;
	}

	if (get_envmon_limits(envmon_fd, &env_limits) < 0)
		return;

	/*
	 * A set of arrays are used whose bounds are determined by the
	 * response to get_envmon_limits. Establish these arrays now.
	 */
	create_arrays();
	setup_strings();

	for (fru_type = 0; fru_type < ENVMONTYPES; fru_type++) {
		(void) add_env_nodes(envmon_fd, fru_type, envmoninfh);
	}

	(void) close(envmon_fd);

	res = ptree_register_handler(PICL_FRU_ADDED, envmon_evhandler, NULL);
	if (res != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_EVREG_FAILED, res);
	}
	res = ptree_register_handler(PICL_FRU_REMOVED, envmon_evhandler, NULL);
	if (res != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_EVREG_FAILED, res);
	}
}

/*
 * fini entry point of the plugin
 */
static void
piclenvmon_fini(void)
{
	if (envmon_device_name != NULL) {
		free(envmon_device_name);
		envmon_device_name = NULL;
	}
	(void) ptree_unregister_handler(PICL_FRU_ADDED,
	    envmon_evhandler, NULL);
	(void) ptree_unregister_handler(PICL_FRU_REMOVED,
	    envmon_evhandler, NULL);
}
