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
 * This file contains the environmental PICL plug-in module.
 */


/*
 * Excalibur system contains up to two CPU and two PCI MAX1617 temperature
 * devices, each consisting of two sensors: die and ambient. Each sensor is
 * represented as a different minor device and the current temperature is read
 * via an I2C_GET_TEMPERATURE ioctl call to the max1617 driver. Additionally,
 * the MAX1617 device supports both a low and high temperature limit, which
 * can trigger an alert condition, causing power supply to turn off.
 *
 * The environmental monitor defines the following thresholds per sensor:
 *
 *	high_power_off		high hard shutdown
 *	high_shutdown		high soft shutdown limit
 *	high_warning		high warning limit
 *	low_warning		low warning limit
 *	low_shutdown		low soft shutdown limit
 *	low_power_off		low hard shutdown limit
 *
 * Above mentioned threshold values can be changed via "piclenvd.conf"
 * configuration file.
 *
 * Environmental monitoring is done by the "envthr" thread. It periodically
 * monitors both CPU die and CPU ambient temperatures and takes appropriate
 * action depending upon the current temperature and threshold values for
 * that sensor. If the temperature reaches the high_shutdown limit or the
 * low_shutdown limit, and remains there for over shutdown_interval seconds,
 * it forces a graceful system shutdown via tuneable shutdown_cmd string
 * variable. Otherwise, if the temperature reaches the high_warning limit
 * or the low_warning limit, it logs and prints a message on the console.
 * This message will be printed at most at "warning_interval" seconds
 * interval, which is also a tuneable variable.
 *
 * Excalibur system contains three fans: cpu, system and power supply. The
 * cpu and system fans are under software control and their speed can be
 * set to a value in the range 0 through 63. However, the software has no
 * control over the power supply fan's speed (it's automatically controlled
 * by the hardware), but it can turn it ON or OFF. When in EStar mode (i.e.
 * the lowest power state), the environmental monitor turns off the power
 * supply fan.
 *
 * Each fan is represented as a different minor device and the fan speed
 * can be controlled by writing to the TDA8444 device driver. Note that
 * these devices are read only and the driver caches the last speed set
 * for each fan, thus allowing an interface to read the current fan speed
 * also.
 *
 * The policy to control fan speed depends upon the sensor. For CPU die
 * sensor, different policy is used depending upon whether the temperature
 * is rising, falling or steady state. In case of CPU ambient sensor, only
 * one policy (speed proportional to the current temperature) is used.
 *
 * The power state monitoring is done by the "pmthr" thread. It uses the
 * PM_GET_STATE_CHANGE and PM_GET_STATE_CHANGE_WAIT ioctl commands to pick
 * up any power state change events. It processes all queued power state
 * change events and determines the curret lowest power state and saves it
 * in cur_lpstate variable.
 *
 * Once the "envthr" and "pmthr" threads have been started, they are never
 * killed. This is desirable so that we can do environmental monitoring
 * during reinit process.  The "envd_rwlock" reader/writer lock is used
 * to protect initialization of global state during reinit process against
 * the "envthr" and "pmthr" trying to reference that state.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <limits.h>
#include <string.h>
#include <stdarg.h>
#include <alloca.h>
#include <unistd.h>
#include <sys/processor.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <picl.h>
#include <picltree.h>
#include <picldefs.h>
#include <pthread.h>
#include <signal.h>
#include <libdevinfo.h>
#include <sys/pm.h>
#include <sys/open.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/i2c/clients/max1617.h>
#include <sys/i2c/clients/i2c_client.h>
#include <sys/xcalwd.h>
#include "envd.h"

static pthread_rwlock_t	envd_rwlock = PTHREAD_RWLOCK_INITIALIZER;

/*
 * PICL plguin
 */
static void piclenvd_register(void);
static void piclenvd_init(void);
static void piclenvd_fini(void);
extern void env_picl_setup(void);
extern void env_picl_destroy(void);

#pragma	init(piclenvd_register)

static picld_plugin_reg_t my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_CRITICAL,
	"SUNW_piclenvd",
	piclenvd_init,
	piclenvd_fini,
};


/*
 * Default threshold values for CPU junction/die and ambient sensors
 */
static sensor_thresh_t cpu_die_thresh_default = {
	CPU_DIE_LOW_POWER_OFF, CPU_DIE_HIGH_POWER_OFF,
	CPU_DIE_LOW_SHUTDOWN, CPU_DIE_HIGH_SHUTDOWN,
	CPU_DIE_LOW_WARNING, CPU_DIE_HIGH_WARNING,
	MAX1617_MIN_TEMP, MAX1617_MAX_TEMP,
	POLICY_TARGET_TEMP, 2,
	CPU_DIE_NORMAL_TARGET, CPU_DIE_OTHER_TARGET,
	0, 0, 0, 0
};

static sensor_thresh_t cpu_amb_thresh_default = {
	CPU_AMB_LOW_POWER_OFF, CPU_AMB_HIGH_POWER_OFF,
	CPU_AMB_LOW_SHUTDOWN, CPU_AMB_HIGH_SHUTDOWN,
	CPU_AMB_LOW_WARNING, CPU_AMB_HIGH_WARNING,
	MAX1617_MIN_TEMP, MAX1617_MAX_TEMP,
	POLICY_LINEAR, 2,
	CPU_AMB_LOW_NOMINAL, CPU_AMB_HIGH_NOMINAL,
	0, 0, 0, 0
};


/*
 * Dummy sensor threshold data structure for processing threshold tuneables
 */
static sensor_thresh_t	dummy_thresh;

/*
 * Temperature related constants for fan speed adjustment
 */
#define	AVG_TEMP_HYSTERESIS	0.25
#define	RISING_TEMP_MARGIN	6
#define	FALLING_TEMP_MARGIN	3

/*
 * tuneable variables
 */
#define	FAN_SLOW_ADJUSTMENT	20		/* in percentage */
#define	FAN_INCREMENT_LIMIT	6		/* absolute value */
#define	FAN_DECREMENT_LIMIT	1		/* absolute value */
#define	DEVFSADM_CMD 		"/usr/sbin/devfsadm -i max1617"
#define	FRU_DEVFSADM_CMD 	"/usr/sbin/devfsadm -i seeprom"

int		env_debug;
static int	sensor_poll_interval;
static int	warning_interval;
static int	warning_duration;
static int	shutdown_interval;
static int	fan_slow_adjustment;
static int	fan_incr_limit;
static int	fan_decr_limit;
static int	disable_piclenvd;
static int	disable_warning;
static int	disable_power_off;
static int	disable_shutdown;

static char	shutdown_cmd[128];
static char	devfsadm_cmd[128];
static char	fru_devfsadm_cmd[128];
static sensor_thresh_t cpu0_die_thresh, cpu0_amb_thresh;
static sensor_thresh_t cpu1_die_thresh, cpu1_amb_thresh;

/*
 * Temperature sensors
 */

static env_sensor_t envd_sensors[] = {
	{ SENSOR_CPU0_DIE, CPU0_DIE_SENSOR_DEVFS, &cpu0_die_thresh,
	    CPU0_FRU_DEVFS, CPU_FRU_DIE_SENSOR,
	    SFLAG_TARGET_TEMP | SFLAG_CPU_DIE_SENSOR, -1},
	{ SENSOR_CPU0_AMB, CPU0_AMB_SENSOR_DEVFS, &cpu0_amb_thresh,
	    CPU0_FRU_DEVFS, CPU_FRU_AMB_SENSOR, SFLAG_CPU_AMB_SENSOR, -1},
	{ SENSOR_CPU1_DIE, CPU1_DIE_SENSOR_DEVFS, &cpu1_die_thresh,
	    CPU1_FRU_DEVFS, CPU_FRU_DIE_SENSOR,
	    SFLAG_TARGET_TEMP | SFLAG_CPU_DIE_SENSOR, -1},
	{ SENSOR_CPU1_AMB, CPU1_AMB_SENSOR_DEVFS, &cpu1_amb_thresh,
	    CPU1_FRU_DEVFS, CPU_FRU_AMB_SENSOR, SFLAG_CPU_AMB_SENSOR, -1},
	{ NULL, NULL, NULL, NULL, 0, 0, -1}
};


/*
 * Fan devices
 */
static env_fan_t envd_system_fan = {
	ENV_SYSTEM_FAN, ENV_SYSTEM_FAN_DEVFS,
	SYSTEM_FAN_SPEED_MIN, SYSTEM_FAN_SPEED_MAX, -1, -1,
};

static env_fan_t envd_cpu_fan = {
	ENV_CPU_FAN, ENV_CPU_FAN_DEVFS,
	CPU_FAN_SPEED_MIN, CPU_FAN_SPEED_MAX, -1, -1,
};

static env_fan_t envd_psupply_fan = {
	ENV_PSUPPLY_FAN, ENV_PSUPPLY_FAN_DEVFS,
	PSUPPLY_FAN_SPEED_MIN, PSUPPLY_FAN_SPEED_MAX, -1, -1,
};

static env_fan_t *envd_fans[] = {
	&envd_system_fan,
	&envd_cpu_fan,
	&envd_psupply_fan,
	NULL
};

/*
 * Linked list of devices advertising lpm-ranges
 */
static lpm_dev_t	*lpm_devices = NULL;

/*
 * Excalibur lpm to system-fan speed
 * lpm values must be monotonically increasing (avoid divide-by-zero)
 */
static point_t	excal_lpm_system_fan_tbl[] = {
	/* {lpm, fspeed} */
	{18, 12},
	{25, 20},
	{33, 26},
	{44, 32},
	{51, 39},
	{63, 52},
	{64, 63}
};

static table_t	lpm_fspeed = {
	sizeof (excal_lpm_system_fan_tbl)/ sizeof (point_t),
	excal_lpm_system_fan_tbl
};

/*
 * Sensor to fan map
 */
typedef struct {
	char	*sensor_name;
	char	*fan_name;
} sensor_fan_map_t;

static sensor_fan_map_t sensor_fan_map[] = {
	{SENSOR_CPU0_DIE, ENV_CPU_FAN},
	{SENSOR_CPU1_DIE, ENV_CPU_FAN},
	{SENSOR_CPU0_AMB, ENV_SYSTEM_FAN},
	{SENSOR_CPU1_AMB, ENV_SYSTEM_FAN},
	{NULL, NULL}
};

/*
 * Sensor to PM device map
 */
struct sensor_pmdev {
	int		sensor_id;
	char		*sensor_name;
	char		*pmdev_name;
	char		*speed_comp_name;
	int		speed_comp;
	int		full_power;
	int		cur_power;
	env_sensor_t	*sensorp;
	sensor_pmdev_t	*next;
};

#define	SPEED_COMPONENT_NAME	"CPU Speed"

static sensor_pmdev_t sensor_pmdevs[] = {
	{SENSOR_CPU0_ID, SENSOR_CPU0_DIE, NULL, SPEED_COMPONENT_NAME},
	{SENSOR_CPU1_ID, SENSOR_CPU1_DIE, NULL, SPEED_COMPONENT_NAME},
	{-1, NULL, NULL, NULL}
};

/*
 * Environmental thread variables
 */
static boolean_t	system_shutdown_started = B_FALSE;
static boolean_t	envthr_created = B_FALSE;	/* envthr created */
static pthread_t	envthr_tid;		/* envthr thread ID */
static pthread_attr_t	thr_attr;

/*
 * Power management thread (pmthr) variables
 */
static boolean_t	pmdev_names_init = B_FALSE;
static pthread_t	pmthr_tid;		/* pmthr thread ID */
static int		pmthr_exists = B_FALSE;	/* pmthr exists */
static int		pm_fd = -1;		/* PM device file descriptor */
static int		cur_lpstate;		/* cur low power state */

/*
 * Miscellaneous variables and declarations
 */
static int	fru_devfsadm_invoked = 0;
static int	devfsadm_invoked = 0;
static char	tokdel[] = " \t\n\r";
static uint_t	envd_sleep(uint_t);

/*
 * Tuneable data structure/array and processing functions
 */

typedef struct {
	char		*name;		/* keyword */
	int		(*func)(char *, char *, void *, int, char *, int);
					/* tuneable processing function */
	void		*arg1;		/* tuneable arg1 (memory address) */
	int		arg2;		/* tuneable arg2 (size or flags) */
} env_tuneable_t;

static int process_int_tuneable(char *keyword, char *buf, void *addr,
    int size, char *fname, int line);
static int process_string_tuneable(char *keyword, char *buf, void *addr,
    int size, char *fname, int line);
static int process_threshold_tuneable(char *keyword, char *buf, void *addr,
    int flags, char *fname, int line);
static void process_env_conf_file(void);

static env_tuneable_t env_tuneables[] = {
	{"low_power_off", process_threshold_tuneable,
	    &dummy_thresh.low_power_off, 0},
	{"low_shutdown", process_threshold_tuneable,
	    &dummy_thresh.low_shutdown, 0},
	{"low_warning", process_threshold_tuneable,
	    &dummy_thresh.low_warning, 0},
	{"high_power_off", process_threshold_tuneable,
	    &dummy_thresh.high_power_off, 0},
	{"high_shutdown", process_threshold_tuneable,
	    &dummy_thresh.high_shutdown, 0},
	{"high_warning", process_threshold_tuneable,
	    &dummy_thresh.high_warning, 0},
	{"force_cpu_fan", process_int_tuneable, &envd_cpu_fan.forced_speed,
	    sizeof (envd_cpu_fan.forced_speed)},
	{"force_system_fan", process_int_tuneable,
	    &envd_system_fan.forced_speed,
	    sizeof (envd_system_fan.forced_speed)},

	{"cpu_amb_low_power_off", process_threshold_tuneable,
	    &dummy_thresh.low_power_off, SFLAG_CPU_AMB_SENSOR},
	{"cpu_amb_low_shutdown", process_threshold_tuneable,
	    &dummy_thresh.low_shutdown, SFLAG_CPU_AMB_SENSOR},
	{"cpu_amb_low_warning", process_threshold_tuneable,
	    &dummy_thresh.low_warning, SFLAG_CPU_AMB_SENSOR},
	{"cpu_amb_low_nominal", process_threshold_tuneable,
	    &dummy_thresh.policy_data[LOW_NOMINAL_LOC], SFLAG_CPU_AMB_SENSOR},
	{"cpu_amb_high_power_off", process_threshold_tuneable,
	    &dummy_thresh.high_power_off, SFLAG_CPU_AMB_SENSOR},
	{"cpu_amb_high_shutdown", process_threshold_tuneable,
	    &dummy_thresh.high_shutdown, SFLAG_CPU_AMB_SENSOR},
	{"cpu_amb_high_warning", process_threshold_tuneable,
	    &dummy_thresh.high_warning, SFLAG_CPU_AMB_SENSOR},
	{"cpu_amb_high_nominal", process_threshold_tuneable,
	    &dummy_thresh.policy_data[HIGH_NOMINAL_LOC], SFLAG_CPU_AMB_SENSOR},

	{"cpu_die_low_power_off", process_threshold_tuneable,
	    &dummy_thresh.low_power_off, SFLAG_CPU_DIE_SENSOR},
	{"cpu_die_low_shutdown", process_threshold_tuneable,
	    &dummy_thresh.low_shutdown, SFLAG_CPU_DIE_SENSOR},
	{"cpu_die_low_warning", process_threshold_tuneable,
	    &dummy_thresh.low_warning, SFLAG_CPU_DIE_SENSOR},
	{"cpu_die_normal_target", process_threshold_tuneable,
	    &dummy_thresh.policy_data[0], SFLAG_CPU_DIE_SENSOR},
	{"cpu_die_high_power_off", process_threshold_tuneable,
	    &dummy_thresh.high_power_off, SFLAG_CPU_DIE_SENSOR},
	{"cpu_die_high_shutdown", process_threshold_tuneable,
	    &dummy_thresh.high_shutdown, SFLAG_CPU_DIE_SENSOR},
	{"cpu_die_high_warning", process_threshold_tuneable,
	    &dummy_thresh.high_warning, SFLAG_CPU_DIE_SENSOR},
	{"cpu_die_other_target", process_threshold_tuneable,
	    &dummy_thresh.policy_data[1], SFLAG_CPU_DIE_SENSOR},

	{"sensor_poll_interval", process_int_tuneable, &sensor_poll_interval,
	    sizeof (sensor_poll_interval)},
	{"warning_interval", process_int_tuneable, &warning_interval,
	    sizeof (warning_interval)},
	{"warning_duration", process_int_tuneable, &warning_duration,
	    sizeof (warning_duration)},
	{"disable_piclenvd", process_int_tuneable, &disable_piclenvd,
	    sizeof (disable_piclenvd)},
	{"disable_power_off", process_int_tuneable, &disable_power_off,
	    sizeof (disable_power_off)},
	{"disable_warning", process_int_tuneable, &disable_warning,
	    sizeof (disable_warning)},
	{"disable_shutdown", process_int_tuneable, &disable_shutdown,
	    sizeof (disable_shutdown)},
	{"shutdown_interval", process_int_tuneable, &shutdown_interval,
	    sizeof (shutdown_interval)},
	{"shutdown_cmd", process_string_tuneable, &shutdown_cmd[0],
	    sizeof (shutdown_cmd)},
	{"devfsadm_cmd", process_string_tuneable, &devfsadm_cmd[0],
	    sizeof (devfsadm_cmd)},
	{"fru_devfsadm_cmd", process_string_tuneable, &fru_devfsadm_cmd[0],
	    sizeof (fru_devfsadm_cmd)},
	{"fan_slow_adjustment", process_int_tuneable, &fan_slow_adjustment,
	    sizeof (fan_slow_adjustment)},
	{"fan_incr_limit", process_int_tuneable, &fan_incr_limit,
	    sizeof (fan_incr_limit)},
	{"fan_decr_limit", process_int_tuneable, &fan_decr_limit,
	    sizeof (fan_decr_limit)},
	{"env_debug", process_int_tuneable, &env_debug, sizeof (env_debug)},
	{ NULL, NULL, NULL, 0}
};

static void
fini_table(table_t *tblp)
{
	if (tblp == NULL)
		return;
	free(tblp->xymap);
	free(tblp);
}

static table_t *
init_table(int npoints)
{
	table_t		*tblp;
	point_t		*xy;

	if (npoints == 0)
		return (NULL);

	if ((tblp = malloc(sizeof (*tblp))) == NULL)
		return (NULL);

	if ((xy = malloc(sizeof (*xy) * npoints)) == NULL) {
		free(tblp);
		return (NULL);
	}

	tblp->nentries = npoints;
	tblp->xymap = xy;

	return (tblp);
}

/*
 * Temp-LPM Table format:
 * temp, lpm, temp, lpm, ...
 */
static table_t *
parse_lpm_ranges(uint32_t *bufp, size_t nbytes)
{
	int	nentries;
	table_t	*tblp = NULL;
	int	i;

	if (bufp == NULL)
		return (NULL);

	/*
	 * Table should have at least 2 points
	 * and all points should have x and y values
	 */
	if ((nbytes < (2 * sizeof (point_t))) ||
	    (nbytes & (sizeof (point_t) - 1))) {
		if (env_debug)
			envd_log(LOG_ERR, ENV_INVALID_PROPERTY_FORMAT,
			    LPM_RANGES_PROPERTY);
		return (NULL);
	}

	/* number of entries in the temp-lpm table */
	nentries = nbytes/sizeof (point_t);

	tblp = init_table(nentries);
	if (tblp == NULL)
		return (tblp);

	/* copy the tuples */
	tblp->xymap[0].x = (int)*bufp++;
	tblp->xymap[0].y = (int)*bufp++;
	for (i = 1; i < nentries; ++i) {
		tblp->xymap[i].x = (int)*bufp++;
		tblp->xymap[i].y = (int)*bufp++;
		if (tblp->xymap[i].x <= tblp->xymap[i - 1].x) {
			fini_table(tblp);
			if (env_debug)
				envd_log(LOG_ERR, ENV_INVALID_PROPERTY_FORMAT,
				    LPM_RANGES_PROPERTY);
			return (NULL);
		}
	}

	return (tblp);
}

/*
 * function: calculates y for a given x based on a table of points
 * for monotonically increasing x values.
 * 'tbl' specifies the table to use, 'val' specifies the 'x', returns 'y'
 */
static int
y_of_x(table_t *tbl, int xval)
{
	int		i;
	int		entries;
	point_t		*xymap;
	float		newval;
	float		dy, dx, slope;

	entries = tbl->nentries;
	xymap = tbl->xymap;
	if (xval <= xymap[0].x)
		return (xymap[0].y);
	else if (xval >= xymap[entries - 1].x)
		return (xymap[entries - 1].y);

	for (i = 1; i < entries - 1; i++) {
		if (xval == xymap[i].x)
			return (xymap[i].y);
		if (xval < xymap[i].x)
			break;
	}

	/*
	 * Use linear interpolation
	 */
	dy = (float)(xymap[i].y - xymap[i-1].y);
	dx = (float)(xymap[i].x - xymap[i-1].x);
	slope = dy/dx;
	newval = xymap[i - 1].y + slope * (xval - xymap[i - 1].x);
	return ((int)(newval + (newval >= 0 ? 0.5 : -0.5)));
}

static int
get_lpm_speed(lpm_dev_t *lpmdevs, int temp)
{
	lpm_dev_t	*devp;
	int		lpm;
	int		speed;
	int		maxspeed;

	if (lpmdevs == NULL)
		return (0);
	maxspeed = 0;
	for (devp = lpmdevs; devp != NULL; devp = devp->next) {
		if (devp->temp_lpm_tbl == NULL)
			continue;
		lpm = y_of_x(devp->temp_lpm_tbl, temp);
		if (env_debug)
			envd_log(LOG_INFO, "ambient %d lpm %d\n", temp, lpm);
		speed = y_of_x(&lpm_fspeed, lpm);
		maxspeed = maxspeed > speed ? maxspeed : speed;
		if (env_debug)
			envd_log(LOG_INFO, "lpm %d fanspeed %d\n", lpm, speed);
	}
	return (maxspeed);
}

/*
 * Callback function used by ptree_walk_tree_by_class
 */
static int
cb_lpm(picl_nodehdl_t nodeh, void *args)
{
	lpm_dev_t	**retp = (lpm_dev_t **)args;
	int		err;
	ptree_propinfo_t	pinfo;
	picl_prophdl_t		proph;
	size_t			psize;
	void			*bufp;
	table_t			*temp_lpm_tbl;
	lpm_dev_t		*newdev;

	err = ptree_get_prop_by_name(nodeh, LPM_RANGES_PROPERTY, &proph);
	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);

	err = ptree_get_propinfo(proph, &pinfo);
	if ((err != PICL_SUCCESS) ||
	    (pinfo.piclinfo.type != PICL_PTYPE_BYTEARRAY))
		return (PICL_WALK_CONTINUE);
	psize = pinfo.piclinfo.size;
	bufp = alloca(psize);

	err = ptree_get_propval(proph, bufp, psize);
	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);

	temp_lpm_tbl = parse_lpm_ranges(bufp, psize);
	if (temp_lpm_tbl == NULL) {
		return (PICL_WALK_CONTINUE);
	}

	newdev = malloc(sizeof (*newdev));
	if (newdev == NULL) {
		fini_table(temp_lpm_tbl);
		return (PICL_WALK_TERMINATE);
	}

	memset(newdev, 0, sizeof (*newdev));

	newdev->nodeh = nodeh;
	newdev->temp_lpm_tbl = temp_lpm_tbl;

	/* add newdev to the list */
	newdev->next = *retp;
	*retp = newdev;

	return (PICL_WALK_CONTINUE);
}

/*
 * Find all devices advertising "lpm-ranges" property, parse and store
 * the lpm tables for each device
 */
static int
setup_lpm_devices(lpm_dev_t **devpp)
{
	picl_nodehdl_t	plath;
	int		err;
	lpm_dev_t	*lpmp;

	err = ptree_get_node_by_path("/platform", &plath);
	if (err != PICL_SUCCESS)
		return (err);

	lpmp = NULL;
	err = ptree_walk_tree_by_class(plath, NULL, (void *)&lpmp, cb_lpm);
	if (err == PICL_SUCCESS)
		*devpp = lpmp;
	return (err);
}

/*
 * Remove all lpm_devices and their tables.
 */
static void
delete_lpm_devices(void)
{
	lpm_dev_t	*devp, *next;

	(void) pthread_rwlock_wrlock(&envd_rwlock);

	if (lpm_devices == NULL) {
		(void) pthread_rwlock_unlock(&envd_rwlock);
		return;
	}

	devp = lpm_devices;

	while (devp != NULL) {
		fini_table(devp->temp_lpm_tbl);
		next = devp->next;
		free(devp);
		devp = next;
	}

	lpm_devices = NULL;

	(void) pthread_rwlock_unlock(&envd_rwlock);
}

/*
 * Translate observed (measured) temperature into expected (correct)
 * temperature
 */
static int
xlate_obs2exp(env_sensor_t *sensorp, tempr_t temp)
{
	int		i, entries, new_temp, denominator;
	tempr_map_t	*map;
	float		ftemp;

	entries = sensorp->obs2exp_cnt;
	map = sensorp->obs2exp_map;
	if (entries < 2 || map == NULL)  {
		/* no map or can't map it */
		new_temp = temp;
	} else {
		/*
		 * Any point beyond the range specified by the map is
		 * extrapolated using either the first two or the last
		 * two entries in the map.
		 */
		for (i = 1; i < entries-1; i++)
			if (temp < map[i].observed)
				break;
		/*
		 * Interpolate/extrapolate the temperature using linear
		 * equation with map[i-1] and map[i] being the two ends
		 * of the line segment.
		 */
		denominator = map[i].observed - map[i-1].observed;
		if (denominator == 0) {
			/*
			 * Infinite slope. Since the temperature reading
			 * resolution is 1C, force denominator to 1 to
			 * avoid divide by zero.
			 */
			denominator = 1;
		}
		ftemp = map[i-1].expected +  (temp - map[i-1].observed) *
		    (float)(map[i].expected - map[i-1].expected)/denominator;
		new_temp = (int)(ftemp + (ftemp >= 0 ? 0.5 : -0.5));
	}

	return (new_temp);
}


/*
 * Translate expected (correct) temperature into observed (measured)
 * temperature
 */
static int
xlate_exp2obs(env_sensor_t *sensorp, tempr_t temp)
{
	int		i, entries, new_temp, denominator;
	tempr_map_t	*map;
	float		ftemp;
	sensor_thresh_t	*threshp = sensorp->temp_thresh;

	entries = sensorp->obs2exp_cnt;
	map = sensorp->obs2exp_map;
	if (entries < 2 || map == NULL)
		/* no map or can't map it */
		new_temp = temp;
	else {
		/*
		 * Any point beyond the range specified by the map is
		 * extrapolated using either the first two or the last
		 * two entries in the map.
		 */
		for (i = 1; i < entries-1; i++)
			if (temp < map[i].expected)
				break;

		/*
		 * Interpolate/extrapolate the temperature using linear
		 * equation with map[i-1] and map[i] being the two ends
		 * of the line segment.
		 */
		denominator = map[i].expected - map[i-1].expected;
		if (denominator == 0) {
			/*
			 * Infinite slope. Since the temperature reading
			 * resolution is 1C, force denominator to 1 to
			 * avoid divide by zero.
			 */
			denominator = 1;
		}
		ftemp = map[i-1].observed + (temp - map[i-1].expected) *
		    (float)(map[i].observed - map[i-1].observed)/denominator;
		new_temp = (int)(ftemp + (ftemp >= 0 ? 0.5 : -0.5));
	}

	if (threshp) {
		if (new_temp > threshp->max_limit)
			new_temp = threshp->max_limit;
		else if (new_temp < threshp->min_limit)
			new_temp = threshp->min_limit;
	}

	return (new_temp);
}


/*
 * Check if the specified FRU is present.
 * Returns 1 if present; 0 otherwise.
 */
static int
fru_present(char *path)
{
	char		*p, physpath[PATH_MAX];
	di_node_t	root_node;
	int		fru_present = 0;

	/*
	 * Construct FRU device path by stripping minor
	 * node name from the path and use di_init() to
	 * see if the node exists.
	 */
	(void) strlcpy(physpath, path, sizeof (physpath));
	p = strrchr(physpath, ':');
	if (p != NULL)
		*p = '\0';
	if ((root_node = di_init(physpath, DINFOMINOR)) != DI_NODE_NIL) {
		di_fini(root_node);
		fru_present = 1;
	}
	return (fru_present);
}


/*
 * Get environmental segment from the specified FRU SEEPROM
 */
static int
get_envseg(int fd, void **envsegp, int *envseglenp)
{
	int			i, segcnt, envseglen;
	section_layout_t	section;
	segment_layout_t	segment;
	uint8_t			*envseg;

	if (lseek(fd, (long)SECTION_HDR_OFFSET, 0) == -1L ||
	    read(fd, &section, sizeof (section)) != sizeof (section)) {
		return (EINVAL);
	}

	/*
	 * Verify we have the correct section and contents are valid
	 * For now, we don't verify the CRC.
	 */
	if (section.header_tag != SECTION_HDR_TAG ||
	    GET_UNALIGN16(&section.header_version[0]) != SECTION_HDR_VER) {
		if (env_debug)
			envd_log(LOG_INFO,
			    "Invalid section header tag:%x  version:%x\n",
			    section.header_tag,
			    GET_UNALIGN16(&section.header_version));
		return (EINVAL);
	}

	/*
	 * Locate our environmental segment
	 */
	segcnt = section.segment_count;
	for (i = 0; i < segcnt; i++) {
		if (read(fd, &segment, sizeof (segment)) != sizeof (segment)) {
			return (errno);
		}
		if (env_debug > 1)
			envd_log(LOG_INFO,
			    "Seg name: %x  desc:%x off:%x  len:%x\n",
			    GET_UNALIGN16(&segment.name),
			    GET_UNALIGN32(&segment.descriptor[0]),
			    GET_UNALIGN16(&segment.offset),
			    GET_UNALIGN16(&segment.length));

		if (GET_UNALIGN16(&segment.name) == ENVSEG_NAME)
			break;
	}

	if (i >= segcnt) {
		return (ENOENT);
	}

	/*
	 * Allocate memory to hold the environmental segment data.
	 */
	envseglen = GET_UNALIGN16(&segment.length);
	if ((envseg = malloc(envseglen)) == NULL) {
		return (ENOMEM);
	}

	if (lseek(fd, (long)GET_UNALIGN16(&segment.offset), 0) == -1L ||
	    read(fd, envseg, envseglen) != envseglen) {
		(void) free(envseg);
		return (EIO);
	}

	*envsegp = envseg;
	*envseglenp = envseglen;

	if (env_debug > 1) {
		char	msgbuf[256];
		for (i = 0; i < envseglen; i++) {
			(void) sprintf(&msgbuf[3*(i&0xf)], "%2x ", envseg[i]);
			if ((i & 0xf) == 0xf || i == (envseglen-1))
				envd_log(LOG_INFO, "envseg[%2x]: %s\n",
				    (i & ~0xf), msgbuf);
		}
	}

	return (0);
}


/*
 * Get all environmental segments
 */
static fruenvseg_t *
get_fru_envsegs(void)
{
	env_sensor_t		*sensorp;
	fruenvseg_t		*frup, *fruenvsegs;
	envseg_layout_t		*envsegp;
	void			*envsegbufp;
	int			fd, envseglen, hdrlen;
	char			path[PATH_MAX];

	fruenvsegs = NULL;
	for (sensorp = &envd_sensors[0]; sensorp->name != NULL; sensorp++) {
		if (sensorp->fru == NULL)
			continue;

		for (frup = fruenvsegs; frup != NULL; frup = frup->next)
			if (strcmp(frup->fru, sensorp->fru) == 0)
				break;

		if (frup != NULL)
			continue;

		frup = (fruenvseg_t *)malloc(sizeof (fruenvseg_t));
		if (frup == NULL)
			continue;

		/* add this FRU to our list */
		frup->fru = sensorp->fru;
		frup->envsegbufp = NULL;
		frup->envseglen = 0;
		frup->next = fruenvsegs;
		fruenvsegs = frup;

		/*
		 * Now get the environmental segment from this FRU
		 */
		(void) strcpy(path, "/devices");
		(void) strlcat(path, sensorp->fru, sizeof (path));
	retry:
		errno = 0;
		fd = open(path, O_RDONLY);
		if (env_debug > 1)
			envd_log(LOG_INFO,
			    "fru SEEPROM: %s fd: %d  errno:%d\n",
			    path, fd, errno);
		if (fd == -1 && errno == ENOENT && fru_present(frup->fru)) {
			if (fru_devfsadm_invoked ||
			    fru_devfsadm_cmd[0] == '\0') {
				envd_log(LOG_CRIT, ENV_FRU_OPEN_FAIL,
				    sensorp->fru, errno, strerror(errno));
				continue;

			}
			/*
			 * FRU is present but no path exists as
			 * someone rebooted the system without
			 * "-r" option. Let's invoke "devfsadm"
			 * once to create seeprom nodes and try
			 * again so that we can monitor all
			 * accessible sensors properly and prevent
			 * any CPU overheating.
			 */
			if (env_debug)
				envd_log(LOG_INFO,
				    "Invoking '%s' to create FRU nodes\n",
				    fru_devfsadm_cmd);
			fru_devfsadm_invoked = 1;
			(void) system(fru_devfsadm_cmd);
			goto retry;
		}

		/*
		 * Read environmental segment from this FRU SEEPROM
		 */
		if (get_envseg(fd, &envsegbufp, &envseglen) == 0) {
			/*
			 * Validate envseg version number and header length
			 */
			envsegp = (envseg_layout_t *)envsegbufp;
			hdrlen = sizeof (envseg_layout_t) -
			    sizeof (envseg_sensor_t) +
			    (envsegp->sensor_count) * sizeof (envseg_sensor_t);

			if (envsegp->version != ENVSEG_VERSION ||
			    envseglen < hdrlen) {
				/*
				 * version mismatch or header not big enough
				 */
				envd_log(LOG_CRIT, ENV_FRU_BAD_ENVSEG,
				    sensorp->fru, errno, strerror(errno));
				if (envsegbufp != NULL)
					(void) free(envsegbufp);
			} else {
				frup->envseglen = envseglen;
				frup->envsegbufp = envsegbufp;
			}
		}
		(void) close(fd);
	}
	return (fruenvsegs);
}

/*
 * Process environmental segment for all FRUs.
 */
static void
process_fru_envseg()
{
	env_sensor_t		*sensorp;
	sensor_thresh_t		*threshp;
	envseg_layout_t		*envsegp;
	envseg_sensor_data_t	*datap;
	fruenvseg_t		*frup, *fruenvsegs;
	int			i, envseglen, sensorcnt;
	uint_t			offset, length, mapentries;

	/*
	 * Lookup/read environmental segments from FRU SEEPROMs and
	 * process it. Note that we read each SEEPROM once as it's
	 * a slow device.
	 */
	fruenvsegs = get_fru_envsegs();

	for (sensorp = &envd_sensors[0]; sensorp->name != NULL; sensorp++) {
		if (sensorp->fru == NULL)
			continue;

		/*
		 * Locate our FRU environmental segment
		 */
		for (frup = fruenvsegs; frup != NULL; frup = frup->next)
			if (strcmp(frup->fru, sensorp->fru) == 0)
				break;
		if (frup == NULL || frup->envsegbufp == NULL)
			continue;

		envsegp = (envseg_layout_t *)frup->envsegbufp;
		envseglen = frup->envseglen;
		sensorcnt = envsegp->sensor_count;

		/*
		 * Locate our sensor data record entry
		 */
		for (i = 0; i < sensorcnt; i++) {
			uint32_t	id;

			id = GET_UNALIGN32(&envsegp->sensors[i].sensor_id[0]);
			if (env_debug > 1)
				envd_log(LOG_INFO, " sensor[%d]: id:%x\n",
				    i, id);
			if (id == sensorp->fru_sensor)
				break;
		}

		if (i >= sensorcnt)
			continue;

		/*
		 * Validate offset/length of our sensor data record
		 */
		offset = (uint_t)GET_UNALIGN16(&envsegp->sensors[i].offset);
		datap =  (envseg_sensor_data_t *)((intptr_t)frup->envsegbufp +
		    offset);
		mapentries =  GET_UNALIGN16(&datap->obs2exp_cnt);
		length = sizeof (envseg_sensor_data_t) - sizeof (envseg_map_t) +
		    mapentries * sizeof (envseg_map_t);

		if (env_debug > 1)
			envd_log(LOG_INFO, "Found sensor_id:%x idx:%x "
			"off:%x #maps:%x expected length:%x\n",
				sensorp->fru_sensor, i, offset,
				mapentries, length);

		if (offset >= envseglen || (offset+length) > envseglen) {
			/* corrupted sensor record */
			envd_log(LOG_CRIT, ENV_FRU_BAD_SENSOR_ENTRY,
			    sensorp->fru_sensor, sensorp->name, sensorp->fru);
			continue;
		}

		if (env_debug > 1) {
			/* print threshold values */
			envd_log(LOG_INFO,
			    "Thresholds: HPwrOff %d  HShutDn %d  HWarn %d\n",
			    datap->high_power_off, datap->high_shutdown,
			    datap->high_warning);
			envd_log(LOG_INFO,
			    "Thresholds: LWarn %d  LShutDn %d  LPwrOff %d\n",
			    datap->low_warning, datap->low_shutdown,
			    datap->low_power_off);

			/* print policy data */
			envd_log(LOG_INFO,
			    " Policy type: %d #%d data: %x %x %x %x %x %x\n",
			    datap->policy_type, datap->policy_entries,
			    datap->policy_data[0], datap->policy_data[1],
			    datap->policy_data[2], datap->policy_data[3],
			    datap->policy_data[4], datap->policy_data[5]);

			/* print map table */
			for (i = 0; i < mapentries; i++) {
				envd_log(LOG_INFO, " Map pair# %d: %d %d\n",
				    i, datap->obs2exp_map[i].observed,
				    datap->obs2exp_map[i].expected);
			}
		}


		/*
		 * Copy threshold values
		 */
		threshp = sensorp->temp_thresh;
		threshp->high_power_off = datap->high_power_off;
		threshp->high_shutdown = datap->high_shutdown;
		threshp->high_warning = datap->high_warning;
		threshp->low_warning = datap->low_warning;
		threshp->low_shutdown = datap->low_shutdown;
		threshp->low_power_off = datap->low_power_off;

		/*
		 * Copy policy data
		 */
		threshp->policy_type = datap->policy_type;
		threshp->policy_entries = datap->policy_entries;
		for (i = 0; i < MAX_POLICY_ENTRIES; i++)
			threshp->policy_data[i] =
			    (tempr_t)datap->policy_data[i];

		/*
		 * Copy temperature mapping info (discard duplicate entries)
		 */
		if (sensorp->obs2exp_map) {
			(void) free(sensorp->obs2exp_map);
			sensorp->obs2exp_map = NULL;
			sensorp->obs2exp_cnt = 0;
		}
		if (mapentries > 0) {
			tempr_map_t	*map;
			int		cnt;
			tempr_t		observed, expected;

			map = (tempr_map_t *)malloc(mapentries *
			    sizeof (tempr_map_t));

			if (map == NULL) {
				envd_log(LOG_CRIT, ENV_FRU_SENSOR_MAP_NOMEM,
				    sensorp->fru_sensor, sensorp->name,
				    sensorp->fru);
				continue;
			}

			for (i = 0, cnt = 0; i < mapentries; i++) {

				observed = (tempr_t)
				    datap->obs2exp_map[i].observed;
				expected = (tempr_t)
				    datap->obs2exp_map[i].expected;

				/* ignore if duplicate entry */
				if (cnt > 0 &&
				    observed == map[cnt-1].observed &&
				    expected == map[cnt-1].expected) {
					continue;
				}
				map[cnt].observed = observed;
				map[cnt].expected = expected;
				cnt++;
			}
			sensorp->obs2exp_cnt = cnt;
			sensorp->obs2exp_map = map;
		}

		if (env_debug > 2 && sensorp->obs2exp_cnt > 1) {
			char	msgbuf[256];

			envd_log(LOG_INFO,
			    "Measured --> Correct temperature table "
			    "for sensor: %s\n", sensorp->name);
			for (i = -128; i < 128; i++) {
				(void) sprintf(&msgbuf[6*(i&0x7)], "%6d",
				    xlate_obs2exp(sensorp, i));
				if ((i &0x7) == 0x7)
					envd_log(LOG_INFO,
					    "%8d: %s\n", (i & ~0x7), msgbuf);
			}
			if ((i & 0x7) != 0)
				(void) printf("%8d: %s\n", (i & ~0x7), msgbuf);

			envd_log(LOG_INFO,
			    "Correct --> Measured temperature table "
			    "for sensor: %s\n", sensorp->name);
			for (i = -128; i < 128; i++) {
				(void) sprintf(&msgbuf[6*(i&0x7)], "%6d",
				    xlate_exp2obs(sensorp, i));
				if ((i &0x7) == 0x7)
					envd_log(LOG_INFO,
					    "%8d: %s\n", (i & ~0x7), msgbuf);
			}
			if ((i & 0x7) != 0)
				envd_log(LOG_INFO,
				    "%8d: %s\n", (i & ~0x7), msgbuf);
		}
	}

	/*
	 * Deallocate environmental segment list
	 */
	while (fruenvsegs) {
		frup = fruenvsegs;
		fruenvsegs = frup->next;
		if (frup->envsegbufp != NULL)
			(void) free(frup->envsegbufp);
		(void) free(frup);
	}
}

/*
 * Lookup fan and return a pointer to env_fan_t data structure.
 */
env_fan_t *
fan_lookup(char *name)
{
	int		i;
	env_fan_t	*fanp;

	for (i = 0; (fanp = envd_fans[i]) != NULL; i++) {
		if (strcmp(fanp->name, name) == 0)
			return (fanp);
	}
	return (NULL);
}

/*
 * Lookup sensor and return a pointer to env_sensor_t data structure.
 */
env_sensor_t *
sensor_lookup(char *name)
{
	env_sensor_t	*sensorp;

	for (sensorp = &envd_sensors[0]; sensorp->name != NULL; sensorp++) {
		if (strcmp(sensorp->name, name) == 0)
			return (sensorp);
	}
	return (NULL);
}

/*
 * Get current temperature
 * Returns -1 on error, 0 if successful
 */
int
get_temperature(env_sensor_t *sensorp, tempr_t *temp)
{
	int	fd = sensorp->fd;
	int	retval = 0;
	int	expected_temp;

	if (fd == -1)
		retval = -1;
	else if (ioctl(fd, I2C_GET_TEMPERATURE, temp) == -1) {
		retval = -1;
		if (sensorp->error == 0) {
			sensorp->error = 1;
			envd_log(LOG_WARNING, ENV_SENSOR_ACCESS_FAIL,
			    sensorp->name, errno, strerror(errno));
		}
	} else if (sensorp->error != 0) {
		sensorp->error = 0;
		envd_log(LOG_WARNING, ENV_SENSOR_ACCESS_OK, sensorp->name);
	} else if (sensorp->obs2exp_map != NULL) {
		expected_temp = xlate_obs2exp(sensorp, (tempr_t)*temp);
		if (env_debug > 1)
			envd_log(LOG_INFO,
			    "sensor: %-13s temp:%d  CORRECED to %d\n",
			    sensorp->name, *temp, (tempr_t)expected_temp);
		*temp = (tempr_t)expected_temp;
	}

	return (retval);
}

/*
 * Get current fan speed
 * Returns -1 on error, 0 if successful
 */
int
get_fan_speed(env_fan_t *fanp, fanspeed_t *fanspeedp)
{
	int	fan_fd;
	int	retval = 0;

	fan_fd = fanp->fd;
	if (fan_fd == -1 || read(fan_fd, fanspeedp, sizeof (fanspeed_t)) !=
	    sizeof (fanspeed_t))
		retval = -1;
	return (retval);
}

/*
 * Set fan speed
 * Returns -1 on error, 0 if successful
 */
static int
set_fan_speed(env_fan_t *fanp, fanspeed_t fanspeed)
{
	int	fan_fd;
	int	retval = 0;

	fan_fd = fanp->fd;
	if (fan_fd == -1 || write(fan_fd, &fanspeed, sizeof (fanspeed)) !=
	    sizeof (fanspeed_t))
		retval = -1;
	return (retval);
}


/*
 * close all fan devices
 */
static void
envd_close_fans(void)
{
	int		i;
	env_fan_t	*fanp;

	for (i = 0; (fanp = envd_fans[i]) != NULL; i++) {
		if (fanp->fd != -1) {
			(void) close(fanp->fd);
			fanp->fd = -1;
		}
	}
}

/*
 * Close sensor devices
 */
static void
envd_close_sensors(void)
{
	env_sensor_t	*sensorp;

	for (sensorp = &envd_sensors[0]; sensorp->name != NULL; sensorp++) {
		if (sensorp->fd != -1) {
			(void) close(sensorp->fd);
			sensorp->fd = -1;
		}
	}
}

/*
 * Open PM device
 */
static void
envd_open_pm(void)
{
	pm_fd = open(PM_DEVICE, O_RDONLY);
	if (pm_fd != -1)
		(void) fcntl(pm_fd, F_SETFD, FD_CLOEXEC);
}

/*
 * Close PM device
 */
static void
envd_close_pm(void)
{
	if (pm_fd != -1) {
		(void) close(pm_fd);
		pm_fd = -1;
	}
}

/*
 * Open fan devices and initialize per fan data structure.
 * Returns #fans found.
 */
static int
envd_setup_fans(void)
{
	int		i, fd;
	fanspeed_t	speed;
	env_fan_t	*fanp;
	char		path[PATH_MAX];
	int		fancnt = 0;
	char		*fan_name;
	sensor_fan_map_t *sfmap;
	env_sensor_t	*sensorp;
	int		sensor_cnt;

	for (i = 0; (fanp = envd_fans[i]) != NULL; i++) {
		if (fanp->fd == -1) {
			fanp->sensor_cnt = 0;
			fanp->cur_speed = 0;
			fanp->prev_speed = 0;

			(void) strcpy(path, "/devices");
			(void) strlcat(path, fanp->devfs_path, sizeof (path));
			fd = open(path, O_RDWR);
			if (fd == -1) {
				envd_log(LOG_CRIT,
				    ENV_FAN_OPEN_FAIL, fanp->name,
				    fanp->devfs_path, errno, strerror(errno));
				fanp->present = B_FALSE;
				continue;
			}
			(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
			fanp->fd = fd;
			fanp->present = B_TRUE;
		}
		fancnt++;

		/*
		 * Set initial speed and update cur_speed/prev_speed
		 */
		if (fanp->forced_speed >= 0) {
			speed = (fanspeed_t)fanp->forced_speed;
			if (speed > fanp->speed_max)
				speed = fanp->speed_max;
			if (!disable_piclenvd)
				(void) set_fan_speed(fanp, speed);
		} else if (get_fan_speed(fanp, &speed) == -1) {
			/*
			 * The Fan driver does not know the current fan speed.
			 * Initialize all ON/OFF fans to ON state and all
			 * variable speed fans under software control to 50%
			 * of the max speed and reread the fan to get the
			 * current speed.
			 */
			speed = (fanp == &envd_psupply_fan) ?
				fanp->speed_max : fanp->speed_max/2;
			if (!disable_piclenvd) {
				(void) set_fan_speed(fanp, speed);
				if (get_fan_speed(fanp, &speed) == -1)
					continue;
			}
		}
		fanp->cur_speed = speed;
		fanp->prev_speed = speed;

		/*
		 * Process sensor_fan_map[] table and initialize sensors[]
		 * array for this fan.
		 */
		fan_name = fanp->name;
		for (sensor_cnt = 0, sfmap = &sensor_fan_map[0];
		    sfmap->sensor_name != NULL; sfmap++) {
			if (strcmp(sfmap->fan_name, fan_name) != 0)
				continue;
			sensorp = sensor_lookup(sfmap->sensor_name);
			if (sensorp != NULL && sensor_cnt < SENSORS_PER_FAN) {
				fanp->sensors[sensor_cnt] = sensorp;
				sensor_cnt++;
			}
		}
		fanp->sensor_cnt = sensor_cnt;
	}

	return (fancnt);
}


/*
 * Adjust specified sensor target temperature and fan adjustment rate
 */

static void
adjust_sensor_target(env_sensor_t *sensorp)
{
	int		target, index;
	sensor_pmdev_t	*pmdevp;
	sensor_thresh_t	*threshp;
	float		rate;

	/*
	 * Look at current power state of all power managed devices
	 * associated with this sensor and look up the desired target
	 * temperature and pick the lowest one of those values. Also,
	 * calculate the rate of change based upon whether one or more
	 * of the associated power managed devices are not running at
	 * full power mode.
	 */

	if (sensorp == NULL || (threshp = sensorp->temp_thresh) == NULL ||
	    threshp->policy_type != POLICY_TARGET_TEMP)
		return;

	target = threshp->policy_data[0];
	rate = 1.0;
	for (pmdevp = sensorp->pmdevp; pmdevp != NULL; pmdevp = pmdevp->next) {
		index = pmdevp->full_power - pmdevp->cur_power;
		if (index <= 0)
			continue;

		/* not running at full power */
		if (index >= threshp->policy_entries)
			index = threshp->policy_entries - 1;
		if (target > threshp->policy_data[index])
			target = threshp->policy_data[index];
		if (rate > (float)fan_slow_adjustment/100)
			rate = (float)fan_slow_adjustment/100;
		if (env_debug > 1)
			envd_log(LOG_INFO,
			    "pmdev: %-13s new_target:%d  cur:%d power:%d/%d\n",
			    pmdevp->pmdev_name, target, sensorp->target_temp,
			    pmdevp->cur_power, pmdevp->full_power);
	}

	if (env_debug)
		envd_log(LOG_INFO,
		    "sensor: %-13s new_target:%d  cur:%d power:%d/%d\n",
		    sensorp->name, target, sensorp->target_temp,
		    ((sensorp->pmdevp) ? sensorp->pmdevp->cur_power : -1),
		    ((sensorp->pmdevp) ? sensorp->pmdevp->full_power : -1));

	sensorp->fan_adjustment_rate = rate;
	sensorp->target_temp = target;
}

/*
 * Update current power level of all PM devices we are tracking and adjust
 * the target temperature associated with the corresponding sensor.
 *
 * Returns 1 if one or more pmdev power level was adjusted; 0 otherwise.
 */
static int
update_pmdev_power()
{
	sensor_pmdev_t	*pmdevp;
	pm_req_t	pmreq;
	int		cur_power;
	int		updated = 0;

	for (pmdevp = sensor_pmdevs; pmdevp->pmdev_name != NULL; pmdevp++) {
		pmreq.physpath = pmdevp->pmdev_name;
		pmreq.data = NULL;
		pmreq.datasize = 0;
		pmreq.component = pmdevp->speed_comp;
		cur_power = ioctl(pm_fd, PM_GET_CURRENT_POWER, &pmreq);
		if (pmdevp->cur_power != cur_power) {
			pmdevp->cur_power = cur_power;
			if (pmdevp->sensorp) {
				adjust_sensor_target(pmdevp->sensorp);
				updated = 1;
			}
		}
	}
	return (updated);
}

/*
 * Check if the specified sensor is present.
 * Returns 1 if present; 0 otherwise.
 *
 * Note that we don't use ptree_get_node_by_path() here to detect
 * if a temperature device is present as we don't want to make
 * "devtree" a critical plugin.
 */
static int
envd_sensor_present(env_sensor_t *sensorp)
{
	char		*p, physpath[PATH_MAX];
	di_node_t	root_node;
	int		sensor_present = 0;

	/*
	 * Construct temperature device path by stripping minor
	 * node name from the devfs_path and use di_init() to
	 * see if the node exists.
	 */
	(void) strcpy(physpath, sensorp->devfs_path);
	p = strrchr(physpath, ':');
	if (p != NULL)
		*p = '\0';
	if ((root_node = di_init(physpath, DINFOMINOR)) != DI_NODE_NIL) {
		di_fini(root_node);
		sensor_present = 1;
	}
	return (sensor_present);
}

/*
 * Open temperature sensor devices and initialize per sensor data structure.
 * Returns #sensors found.
 */
static int
envd_setup_sensors(void)
{
	tempr_t		temp;
	env_sensor_t	*sensorp;
	char		path[PATH_MAX];
	int		sensorcnt = 0;
	int		sensor_present;
	sensor_thresh_t	*threshp;
	sensor_pmdev_t	*pmdevp;

	for (sensorp = &envd_sensors[0]; sensorp->name != NULL; sensorp++) {
		if (sensorp->fd != -1) {
			/* Don't reinitialize opened sensor */
			threshp = sensorp->temp_thresh;
			sensorp->pmdevp = NULL;
		} else {
			/* Initialize sensor's initial state */
			sensorp->shutdown_initiated = B_FALSE;
			sensorp->warning_tstamp = 0;
			sensorp->warning_start = 0;
			sensorp->shutdown_tstamp = 0;
			sensorp->pmdevp = NULL;
			sensorp->fan_adjustment_rate = 1.0;

			threshp = sensorp->temp_thresh;
			temp = (threshp && threshp->policy_entries > 0) ?
			    threshp->policy_data[0] : 0;
			sensorp->target_temp = temp;
			sensorp->cur_temp = temp;
			sensorp->avg_temp = temp;
			sensorp->prev_avg_temp = temp;
			sensorp->error = 0;

			(void) strcpy(path, "/devices");
			(void) strlcat(path, sensorp->devfs_path,
			    sizeof (path));
		retry:
			sensorp->fd = open(path, O_RDWR);
			if (sensorp->fd == -1) {
				sensor_present = envd_sensor_present(sensorp);
				if (sensor_present && !devfsadm_invoked &&
				    devfsadm_cmd[0] != '\0') {
					/*
					 * Sensor is present but no path
					 * exists as someone rebooted the
					 * system without "-r" option. Let's
					 * invoke "devfsadm" once to create
					 * max1617 sensors paths in /devices
					 * subtree and try again so that we
					 * can monitor all accessible sensors
					 * and prevent any CPU overheating.
					 *
					 * Note that this routine is always
					 * called in main thread context and
					 * serialized with respect to other
					 * plugins' initialization. Hence, it's
					 * safe to use system(3C) call here.
					 */
					devfsadm_invoked = 1;
					(void) system(devfsadm_cmd);
					goto retry;
				}
				if (sensor_present)
					envd_log(LOG_CRIT,
					    ENV_SENSOR_OPEN_FAIL,
					    sensorp->name,
					    sensorp->devfs_path, errno,
					    strerror(errno));
				sensorp->present = B_FALSE;
				continue;
			}
			(void) fcntl(sensorp->fd, F_SETFD, FD_CLOEXEC);
			sensorp->present = B_TRUE;

			/*
			 * Set cur_temp field to the current temperature value
			 */
			if (get_temperature(sensorp, &temp) == 0) {
				sensorp->cur_temp = temp;
				sensorp->avg_temp = temp;
			}
		}
		sensorcnt++;

		/*
		 * Set low_power_off and high_power_off limits
		 */
		if (threshp && !disable_power_off) {
			temp = xlate_exp2obs(sensorp, threshp->low_power_off);
			if (env_debug > 1)
				envd_log(LOG_INFO, "sensor: %-13s low_power_"
				"off set to %d (real %d)\n", sensorp->name,
				    (int)temp, threshp->low_power_off);
			(void) ioctl(sensorp->fd, MAX1617_SET_LOW_LIMIT, &temp);

			temp = xlate_exp2obs(sensorp, threshp->high_power_off);
			if (env_debug > 1)
				envd_log(LOG_INFO, "sensor: %-13s high_power_"
				"off set to %d (real %d)\n", sensorp->name,
				    (int)temp, threshp->high_power_off);
			(void) ioctl(sensorp->fd, MAX1617_SET_HIGH_LIMIT,
			    &temp);
		}
	}

	/*
	 * Locate "CPU Speed" component for any PM devices associated with
	 * the sensors.
	 */
	for (pmdevp = sensor_pmdevs; pmdevp->sensor_name; pmdevp++) {
		int		i, ncomp;
		char		physpath[PATH_MAX];
		pm_req_t	pmreq;

		pmdevp->speed_comp = -1;
		pmdevp->full_power = -1;
		pmdevp->cur_power = -1;
		pmdevp->next = NULL;
		pmdevp->sensorp = sensorp = sensor_lookup(pmdevp->sensor_name);

		/*
		 * Lookup speed component and get full and current power
		 * level for that component.
		 */
		pmreq.physpath = pmdevp->pmdev_name;
		pmreq.data = physpath;
		pmreq.datasize = sizeof (physpath);

		ncomp = ioctl(pm_fd, PM_GET_NUM_COMPONENTS, &pmreq);
		for (i = 0; i < ncomp; i++) {
			pmreq.component = i;
			physpath[0] = '\0';
			if (ioctl(pm_fd, PM_GET_COMPONENT_NAME, &pmreq) <= 0)
				continue;
			if (strcasecmp(pmreq.data, pmdevp->speed_comp_name))
				continue;
			pmdevp->speed_comp = i;


			/*
			 * Get full power and current power level
			 */
			pmdevp->full_power = ioctl(pm_fd, PM_GET_FULL_POWER,
			    &pmreq);

			pmdevp->cur_power = ioctl(pm_fd, PM_GET_CURRENT_POWER,
			    &pmreq);

			if (sensorp) {
				pmdevp->next = sensorp->pmdevp;
				sensorp->pmdevp = pmdevp;
				adjust_sensor_target(sensorp);
			}
			break;
		}
		if (env_debug > 1)
			envd_log(LOG_INFO,
			    "sensor:%s %p pmdev:%s comp:%s %d power:%d/%d\n",
			    pmdevp->sensor_name, pmdevp->sensorp,
			    pmdevp->pmdev_name, pmdevp->speed_comp_name,
			    pmdevp->speed_comp, pmdevp->cur_power,
			    pmdevp->full_power);
	}
	return (sensorcnt);
}

/*
 * Read all temperature sensors and take appropriate action based
 * upon temperature threshols associated with each sensor. Possible
 * actions are:
 *
 *	temperature > high_shutdown
 *	temperature < low_shutdown
 *		Gracefully shutdown the system and log/print a message
 *		on the system console provided the temperature has been
 *		in shutdown range for "shutdown_interval" seconds.
 *
 *	high_warning < temperature <= high_shutdown
 *	low_warning  > temperature >= low_shutdown
 *		Log/print a warning message on the system console at most
 *		once every "warning_interval" seconds.
 *
 * Note that the current temperature is recorded in the "cur_temp" field
 * within each env_sensor_t structure.
 */
static void
monitor_sensors(void)
{
	tempr_t 	temp;
	env_sensor_t	*sensorp;
	sensor_thresh_t	*threshp;
	time_t		ct;
	char		msgbuf[BUFSIZ];
	char		syscmd[BUFSIZ];

	for (sensorp = &envd_sensors[0]; sensorp->name != NULL; sensorp++) {
		if (get_temperature(sensorp, &temp) < 0)
			continue;

		sensorp->prev_avg_temp = sensorp->avg_temp;
		sensorp->cur_temp = temp;
		sensorp->avg_temp = (sensorp->avg_temp + temp)/2;
		threshp = sensorp->temp_thresh;

		if (env_debug)
			envd_log(LOG_INFO,
			"sensor: %-13s temp  prev_avg:%6.2f  "
			"cur:%d avg_temp:%6.2f power:%d/%d target:%d\n",
			    sensorp->name, sensorp->prev_avg_temp,
			    temp, sensorp->avg_temp, ((sensorp->pmdevp) ?
			    sensorp->pmdevp->cur_power : -1),
			    ((sensorp->pmdevp) ? sensorp->pmdevp->full_power :
			    -1), sensorp->target_temp);


		/*
		 * If this sensor already triggered system shutdown, don't
		 * log any more shutdown/warning messages for it.
		 */
		if (sensorp->shutdown_initiated || threshp == NULL)
			continue;

		/*
		 * Check for the temperature in warning and shutdown range
		 * and take appropriate action.
		 */
		if (TEMP_IN_WARNING_RANGE(temp, threshp) && !disable_warning) {
			/*
			 * Check if the temperature has been in warning
			 * range during last warning_duration interval.
			 * If so, the temperature is truly in warning
			 * range and we need to log a warning message,
			 * but no more than once every warning_interval
			 * seconds.
			 */
			time_t	wtstamp = sensorp->warning_tstamp;

			ct = (time_t)(gethrtime() / NANOSEC);
			if (sensorp->warning_start == 0)
				sensorp->warning_start = ct;
			if (((ct - sensorp->warning_start) >=
			    warning_duration) && (wtstamp == 0 ||
			    (ct - wtstamp) >= warning_interval)) {
				envd_log(LOG_CRIT, ENV_WARNING_MSG,
				    sensorp->name, temp,
				    threshp->low_warning,
				    threshp->high_warning);
				sensorp->warning_tstamp = ct;
			}
		} else if (sensorp->warning_start != 0)
			sensorp->warning_start = 0;

		if (TEMP_IN_SHUTDOWN_RANGE(temp, threshp) &&
		    !disable_shutdown) {
			ct = (time_t)(gethrtime() / NANOSEC);
			if (sensorp->shutdown_tstamp == 0)
				sensorp->shutdown_tstamp = ct;

			/*
			 * Shutdown the system if the temperature remains
			 * in the shutdown range for over shutdown_interval
			 * seconds.
			 */
			if ((ct - sensorp->shutdown_tstamp) >=
			    shutdown_interval) {
				/* log error */
				sensorp->shutdown_initiated = B_TRUE;
				(void) snprintf(msgbuf, sizeof (msgbuf),
				    ENV_SHUTDOWN_MSG, sensorp->name,
				    temp, threshp->low_shutdown,
				    threshp->high_shutdown);
				envd_log(LOG_ALERT, msgbuf);

				/* shutdown the system (only once) */
				if (system_shutdown_started == B_FALSE) {
					(void) snprintf(syscmd, sizeof (syscmd),
					    "%s \"%s\"", shutdown_cmd, msgbuf);
					envd_log(LOG_ALERT, syscmd);
					system_shutdown_started = B_TRUE;
					(void) system(syscmd);
				}
			}
		} else if (sensorp->shutdown_tstamp != 0)
			sensorp->shutdown_tstamp = 0;
	}
}


/*
 * Adjust fan speed based upon the current temperature value of various
 * sensors affected by the specified fan.
 */
static int
adjust_fan_speed(env_fan_t *fanp, lpm_dev_t *devp)
{
	int		i;
	fanspeed_t	fanspeed;
	float		speed, cur_speed, new_speed, max_speed, min_speed;
	env_sensor_t	*sensorp;
	sensor_thresh_t	*threshp;
	tempr_t		temp;
	float		avg_temp, tempdiff, targetdiff;
	int		av_ambient;
	int		amb_cnt;


	/*
	 * Get current fan speed
	 */
	if (get_fan_speed(fanp, &fanspeed) < 0)
		return (-1);
	cur_speed = fanp->cur_speed;
	if (fanspeed != (int)cur_speed)
		cur_speed = (float)fanspeed;

	/*
	 * Calculate new fan speed for each sensor and pick the largest one.
	 */
	min_speed = fanp->speed_min;
	max_speed = fanp->speed_max;
	speed = 0;
	av_ambient = 0;
	amb_cnt = 0;

	for (i = 0; i < fanp->sensor_cnt; i++) {
		sensorp = fanp->sensors[i];
		if (sensorp == NULL || sensorp->fd == -1 ||
		    sensorp->temp_thresh == NULL)
			continue;

		temp = sensorp->cur_temp;
		avg_temp = sensorp->avg_temp;
		threshp = sensorp->temp_thresh;

		/*
		 * Note ambient temperatures to determine lpm for system fan
		 */
		if ((devp != NULL) &&
		    (sensorp->flags & SFLAG_CPU_AMB_SENSOR)) {
			av_ambient += temp;
			amb_cnt++;
		}

		/*
		 * If the current temperature is above the warning
		 * threshold, use max fan speed.
		 */
		if (temp >= threshp->high_warning) {
			speed = max_speed;
			break;
		} else if (temp <= threshp->low_warning) {
			speed = min_speed;
			break;
		}

		if (threshp->policy_type == POLICY_TARGET_TEMP) {
			/*
			 * Try to achieve the desired target temperature.
			 * Calculate new fan speed based upon whether the
			 * temperature is rising, falling or steady state.
			 * Also take into consideration the current fan
			 * speed as well as the desired target temperature.
			 */
			float	delta, speed_change;
			float	multiplier;

			targetdiff = avg_temp - sensorp->target_temp;
			tempdiff = avg_temp - sensorp->prev_avg_temp;

			if (tempdiff > AVG_TEMP_HYSTERESIS) {
				/*
				 * Temperature is rising. Increase fan
				 * speed 0.5% for every 1C above the
				 * (target - RISING_TEMP_MARGIN) limit.
				 * Also take into consideration temperature
				 * rising rate and the current fan speed.
				 */
				delta = max_speed * .005 *
				    (RISING_TEMP_MARGIN + targetdiff);
				if (delta <= 0)
					multiplier = 0;
				else
					multiplier = tempdiff/4 +
					    ((cur_speed < max_speed/2) ?
					    2 : 1);
			} else if (tempdiff < -AVG_TEMP_HYSTERESIS) {
				/*
				 * Temperature is falling. Decrease fan
				 * speed 0.5% for every 1C below the
				 * (target + FALLING_TEMP_MARGIN) limit.
				 * Also take into consideration temperature
				 * falling rate and the current fan speed.
				 */
				delta = -max_speed * .005 *
				    (FALLING_TEMP_MARGIN - targetdiff);
				if (delta >= 0)
					multiplier = 0;
				else
					multiplier = -tempdiff/4 +
					    ((cur_speed > max_speed/2) ?
					    2 : 1);
			} else {
				/*
				 * Temperature is changing very slowly.
				 * Adjust fan speed by 0.4% for every 1C
				 * below/above the target temperature.
				 */
				delta = max_speed * .004 * targetdiff;
				multiplier = 1.0;
			}


			/*
			 * Enforece some bounds on multiplier and the
			 * speed change.
			 */
			multiplier = MIN(multiplier, 3.0);
			speed_change = delta * multiplier *
			    sensorp->fan_adjustment_rate;
			speed_change = MIN(speed_change, fan_incr_limit);
			speed_change = MAX(speed_change, -fan_decr_limit);
			new_speed = cur_speed + speed_change;

			if (env_debug > 1)
				envd_log(LOG_INFO,
				"sensor: %-8s temp/diff:%d/%3.1f  "
				"target/diff:%d/%3.1f  change:%4.2f x "
				"%4.2f x %4.2f speed %5.2f -> %5.2f\n",
				    sensorp->name, temp, tempdiff,
				    sensorp->target_temp, targetdiff, delta,
				    multiplier, sensorp->fan_adjustment_rate,
				    cur_speed, new_speed);
		} else if (threshp->policy_type == POLICY_LINEAR) {
			/*
			 * Set fan speed linearly within the operating
			 * range specified by the policy_data[LOW_NOMINAL_LOC]
			 * and policy_data[HIGH_NOMINAL_LOC] threshold values.
			 * Fan speed is set to minimum value at LOW_NOMINAL
			 * and to maximum value at HIGH_NOMINAL value.
			 */
			new_speed = min_speed + (max_speed - min_speed) *
			    (avg_temp - threshp->policy_data[LOW_NOMINAL_LOC])/
			    (threshp->policy_data[HIGH_NOMINAL_LOC] -
			    threshp->policy_data[LOW_NOMINAL_LOC]);
			if (env_debug > 1)
				envd_log(LOG_INFO,
				"sensor: %-8s policy: linear, cur_speed %5.2f"\
				" new_speed: %5.2f\n", sensorp->name, cur_speed,
				    new_speed);
		} else {
			new_speed = cur_speed;
		}
		speed = MAX(speed, new_speed);
	}

	/*
	 * Adjust speed using lpm tables
	 */
	if (amb_cnt > 0) {
		av_ambient = (av_ambient >= 0 ?
			(int)(0.5 + (float)av_ambient/(float)amb_cnt):
			(int)(-0.5 + (float)av_ambient/(float)amb_cnt));
		speed = MAX(speed, (fanspeed_t)get_lpm_speed(devp, av_ambient));
	}

	speed = MIN(speed, max_speed);
	speed = MAX(speed, min_speed);

	/*
	 * Record and update fan speed, if different.
	 */
	fanp->prev_speed = fanp->cur_speed;
	fanp->cur_speed = speed;
	if ((fanspeed_t)speed != fanspeed) {
		fanspeed = (fanspeed_t)speed;
		(void) set_fan_speed(fanp, fanspeed);
	}
	if (env_debug)
		envd_log(LOG_INFO,
		    "fan: %-16s speed cur:%6.2f  new:%6.2f\n",
		    fanp->name, fanp->prev_speed, fanp->cur_speed);

	return (0);
}
/*
 * This is the environment thread, which monitors the current temperature
 * and power managed state and controls system fan speed.  Temperature is
 * polled every sensor-poll_interval seconds duration.
 */
/*ARGSUSED*/
static void *
envthr(void *args)
{
	env_sensor_t	*sensorp;
	fanspeed_t 	fan_speed;
	env_fan_t	*pmfanp = &envd_psupply_fan;
	int		to;
	int		xwd = -1;

	for (sensorp = &envd_sensors[0]; sensorp->name != NULL;
	    sensorp++) {
		if (sensorp->obs2exp_map)
			(void) free(sensorp->obs2exp_map);
		sensorp->obs2exp_map = NULL;
		sensorp->obs2exp_cnt = 0;
	}

	/*
	 * Process environmental segment data, if present,
	 * in the FRU SEEPROM.
	 */
	process_fru_envseg();

	/*
	 * Process tuneable parameters
	 */
	process_env_conf_file();

	/*
	 * Setup temperature sensors and fail if we can't open
	 * at least one sensor.
	 */
	if (envd_setup_sensors() <= 0) {
		envd_close_pm();
		return (NULL);
	}

	to = 3 * sensor_poll_interval + 1;
	xwd = open(XCALWD_DEVFS, O_RDONLY);
	if (xwd < 0) {
		envd_log(LOG_CRIT, ENV_WATCHDOG_INIT_FAIL, errno,
		    strerror(errno));
	} else if (ioctl(xwd, XCALWD_STOPWATCHDOG) < 0 ||
	    ioctl(xwd, XCALWD_STARTWATCHDOG, &to) < 0) {
		envd_log(LOG_CRIT, ENV_WATCHDOG_INIT_FAIL, errno,
		    strerror(errno));
		(void) close(xwd);
		xwd = -1;
	}

	/*
	 * Setup fan device (don't fail even if we can't access
	 * the fan as we can still monitor temeperature.
	 */
	(void) envd_setup_fans();

	for (;;) {
		(void) pthread_rwlock_rdlock(&envd_rwlock);

		/*
		 * If no "pmthr" thread, then we need to update the
		 * current power level for all power managed deviecs
		 * so that we can determine correct target temperature.
		 */
		if (pmthr_exists == B_FALSE)
			(void) update_pmdev_power();

		if (xwd >= 0)
			(void) ioctl(xwd, XCALWD_KEEPALIVE);

		if (!disable_piclenvd) {
			/*
			 * Monitor current temperature for all sensors
			 * (current temperature is recorded in the "cur_temp"
			 * field within each sensor data structure)
			 */
			monitor_sensors();

			/*
			 * Adjust CPU and system fan speed
			 */
			if (envd_cpu_fan.forced_speed < 0)
				(void) adjust_fan_speed(&envd_cpu_fan, NULL);
			if (envd_system_fan.forced_speed < 0)
				(void) adjust_fan_speed(&envd_system_fan,
					lpm_devices);

			/*
			 * Turn off power supply fan if in lowest power state.
			 */
			fan_speed = (cur_lpstate) ? pmfanp->speed_min :
			    pmfanp->speed_max;

			if (env_debug)
				envd_log(LOG_INFO,
				"fan: %-16s speed cur:%6.2f  new:%6.2f "
				"low-power:%d\n", pmfanp->name,
				    (float)pmfanp->cur_speed,
				    (float)fan_speed, cur_lpstate);

			if (fan_speed != (fanspeed_t)pmfanp->cur_speed &&
			    set_fan_speed(pmfanp, fan_speed) == 0)
				pmfanp->cur_speed = fan_speed;
		}
		(void) pthread_rwlock_unlock(&envd_rwlock);

		/*
		 * Wait for sensor_poll_interval seconds before polling
		 * again. Note that we use our own envd_sleep() routine
		 * as sleep() in POSIX thread library gets affected by
		 * the wall clock time being set back.
		 */
		(void) envd_sleep(sensor_poll_interval);
	}
	/*NOTREACHED*/
	return (NULL);
}

/*
 * This is the power management thread, which monitors all power state
 * change events and wakes up the "envthr" thread when the system enters
 * or exits the lowest power state.
 */
/*ARGSUSED*/
static void *
pmthr(void *args)
{
	pm_state_change_t	pmstate;
	char			physpath[PATH_MAX];

	pmstate.physpath = physpath;
	pmstate.size = sizeof (physpath);
	cur_lpstate = 0;

	for (;;) {
		/*
		 * Get PM state change events to check if the system
		 * is in lowest power state and wake up the "envthr"
		 * thread when the power state changes.
		 *
		 * To minimize polling, we use the blocking interface
		 * to get the power state change event here.
		 */
		if (ioctl(pm_fd, PM_GET_STATE_CHANGE_WAIT, &pmstate) != 0) {
			if (errno != EINTR)
				break;
			continue;
		}

		/*
		 * Extract the lowest power state from the last queued
		 * state change events. We pick up queued state change
		 * events using the non-blocking interface and wake up
		 * the "envthr" thread only after consuming all the
		 * state change events queued at that time.
		 */
		do {
			if (env_debug > 1)  {
				envd_log(LOG_INFO,
				"pmstate event:0x%x flags:%x comp:%d "
				"oldval:%d newval:%d path:%s\n",
				    pmstate.event, pmstate.flags,
				    pmstate.component, pmstate.old_level,
				    pmstate.new_level, pmstate.physpath);
			}
			cur_lpstate =
			    (pmstate.flags & PSC_ALL_LOWEST) ? 1 : 0;
		} while (ioctl(pm_fd, PM_GET_STATE_CHANGE, &pmstate) == 0);

		/*
		 * Update current PM state for the components we are
		 * tracking. In case of CPU devices, PM state change
		 * event can be generated even before the state change
		 * takes effect, hence we need to get the current state
		 * for all CPU devices every time and recalculate the
		 * target temperature. We do this once after consuming
		 * all the queued events.
		 */

		(void) pthread_rwlock_rdlock(&envd_rwlock);
		(void) update_pmdev_power();
		(void) pthread_rwlock_unlock(&envd_rwlock);
	}

	/*
	 * We won't be able to monitor lowest power state any longer,
	 * hence reset it.
	 */
	cur_lpstate = 0;
	envd_log(LOG_ERR, PM_THREAD_EXITING, errno, strerror(errno));
	pmthr_exists = B_FALSE;
	return (NULL);
}


/*
 * Process sensor threshold related tuneables
 */
static int
process_threshold_tuneable(char *keyword, char *buf, void *dummy_thresh_addr,
    int flags, char *fname, int line)
{
	int		retval = 0;
	long		val;
	void		*addr;
	char		*endp, *sname;
	env_sensor_t	*sensorp;

	/*
	 * Tuneable entry can be in one of the following formats:
	 *
	 *	threshold-keyword <int-value>
	 *	threshold-keyword <int-value> <sensor-name> ...
	 *
	 * Convert threshold value into integer value and check for
	 * optional sensor name. If no sensor name is specified, then
	 * the tuneable applies to all sensors specified by the "flags".
	 * Otherwise, it is applicable to the specified sensors.
	 *
	 * Note that the dummy_thresh_addr is the address of the threshold
	 * to be changed and is converted into offset by subtracting the
	 * base dummy_thresh address. This offset is added to the base
	 * address of the threshold structure to be update to determine
	 * the final memory address to be modified.
	 */

	errno = 0;
	val = strtol(buf, &endp, 0);
	sname = strtok(endp, tokdel);

	if (errno != 0 || val != (tempr_t)val) {
		retval = -1;
		envd_log(LOG_INFO, ENV_CONF_INT_EXPECTED, fname, line, keyword);
	} else if (flags == 0 && sname == NULL) {
		envd_log(LOG_INFO, "SUNW_piclenvd: file:%s line:%d SKIPPED"
		    " as no sensor specified.\n", fname, line, keyword);
		retval = -1;
	} else if (sname == NULL) {
		int	cnt = 0;

		for (sensorp = &envd_sensors[0]; sensorp->name; sensorp++) {
			if (sensorp->temp_thresh == NULL ||
			    (sensorp->flags & flags) == 0)
				continue;

			/*
			 * Convert dummy_thresh_addr into memory address
			 * for this sensor threshold values.
			 */
			addr = (char *)sensorp->temp_thresh +
			    (int)((char *)dummy_thresh_addr -
			    (char *)&dummy_thresh);

			*(tempr_t *)addr = (tempr_t)val;
			cnt++;
			if (env_debug)
				envd_log(LOG_INFO, "SUNW_piclenvd: file:%s "
				"line:%d %s = %d for sensor: '%s'\n",
				    fname, line, keyword, val, sensorp->name);
		}
		if (cnt == 0)
			envd_log(LOG_INFO, "SUNW_piclenvd: file:%s line:%d "
			"%s SKIPPED as no matching sensor found.\n",
			    fname, line, keyword);
	} else {
		/* apply threshold value to the specified sensors */
		do {
			sensorp = sensor_lookup(sname);
			if (sensorp == NULL || sensorp->temp_thresh == NULL ||
			    (flags && (sensorp->flags & flags) == 0)) {
				envd_log(LOG_INFO,
				"SUNW_piclenvd: file:%s line:%d %s SKIPPED"
				" for '%s' as not a valid sensor.\n",
				    fname, line, keyword, sname);
				continue;
			}
			/*
			 * Convert dummy_thresh_addr into memory address
			 * for this sensor threshold values.
			 */
			addr = (char *)sensorp->temp_thresh +
			    (int)((char *)dummy_thresh_addr -
			    (char *)&dummy_thresh);

			*(tempr_t *)addr = (tempr_t)val;
			if (env_debug)
				envd_log(LOG_INFO, "SUNW_piclenvd: file:%s "
				"line:%d %s = %d for sensor: '%s'\n",
				    fname, line, keyword, val, sensorp->name);
		} while ((sname = strtok(NULL, tokdel)) != NULL);
	}
	return (retval);
}


/*
 * Process integer tuneables
 */
static int
process_int_tuneable(char *keyword, char *buf, void *addr, int size,
    char *fname, int line)
{
	int	retval = 0;
	char	*endp;
	long	val;

	/*
	 * Convert input into integer value and ensure that there is
	 * no other token in the buffer.
	 */
	errno = 0;
	val = strtol(buf, &endp, 0);
	if (errno != 0 || strtok(endp, tokdel) != NULL)
		retval = -1;
	else {
		switch (size) {
		case 1:
			if (val != (int8_t)val)
				retval = -1;
			else
				*(int8_t *)addr = (int8_t)val;
			break;
		case 2:
			if (val != (short)val)
				retval = -1;
			else
				*(short *)addr = (short)val;
			break;
		case 4:
			*(int *)addr = (int)val;
			break;
		default:
			retval = -1;
		}
	}

	if (retval == -1)
		envd_log(LOG_INFO, ENV_CONF_INT_EXPECTED,
		    fname, line, keyword);
	else if (env_debug)
		envd_log(LOG_INFO, "SUNW_piclenvd: file:%s line:%d %s = %d\n",
		    fname, line, keyword, val);

	return (retval);
}


/*
 * Process string tuneables
 *
 * String value must be within double quotes.  Skip over initial white
 * spaces before looking for string value.
 */
static int
process_string_tuneable(char *keyword, char *buf, void *addr, int size,
    char *fname, int line)
{
	int	retval = 0;
	char	c, *p, *strend;

	/* Skip over white spaces */
	buf += strspn(buf, tokdel);

	/*
	 * Parse srting and locate string end (handling escaped double quotes
	 * and other characters)
	 */
	if (buf[0] != '"')
		strend = NULL;
	else {
		for (p = buf+1; (c = *p) != '\0'; p++)
			if (c == '"' || (c == '\\' && *++p == '\0'))
				break;
		strend = (*p == '"') ? p : NULL;
	}

	if (strend == NULL || (strend-buf) > size ||
	    strtok(strend+1, tokdel) != NULL) {
		envd_log(LOG_WARNING, ENV_CONF_STRING_EXPECTED,
		    fname, line, keyword, size);
		retval = -1;
	} else {
		*strend = '\0';
		(void) strcpy(addr, (caddr_t)buf+1);
		if (env_debug)
			envd_log(LOG_INFO, "SUNW_piclenvd: file:%s line:%d "
			    "%s = \"%s\"\n", fname, line, keyword, buf+1);
	}

	return (retval);
}


/*
 * Process configuration file
 */
static void
process_env_conf_file(void)
{
	int		line, len, toklen;
	char		buf[BUFSIZ];
	FILE		*fp;
	env_tuneable_t	*tunep;
	char		nmbuf[SYS_NMLN];
	char		fname[PATH_MAX];
	char		*tok, *valuep;
	int		skip_line = 0;

	if (sysinfo(SI_PLATFORM, nmbuf, sizeof (nmbuf)) == -1)
		return;

	(void) snprintf(fname, sizeof (fname), PICLD_PLAT_PLUGIN_DIRF, nmbuf);
	(void) strlcat(fname, ENV_CONF_FILE, sizeof (fname));
	fp = fopen(fname, "r");
	if (fp == NULL)
		return;

	/*
	 * Blank lines or lines starting with "#" or "*" in the first
	 * column are ignored. All other lines are assumed to contain
	 * input in the following format:
	 *
	 *	keyword value
	 *
	 * where the "value" can be a signed integer or string (in
	 * double quotes) depending upon the keyword.
	 */

	for (line = 1; fgets(buf, sizeof (buf), fp) != NULL; line++) {
		len = strlen(buf);
		if (len <= 0)
			continue;

		/* skip long lines */
		if (buf[len-1] != '\n') {
			skip_line = 1;
			continue;
		} else if (skip_line) {
			skip_line = 0;
			continue;
		} else
			buf[len-1] = '\0';

		/* skip comments */
		if (buf[0] == '*' || buf[0] == '#')
			continue;

		/*
		 * Skip over white space to get the keyword
		 */
		tok = buf + strspn(buf, tokdel);
		if (*tok == '\0')
			continue;			/* blank line */

		toklen = strcspn(tok, tokdel);
		tok[toklen] = '\0';

		/* Get possible location for value (within current line) */
		valuep = tok + toklen + 1;
		if (valuep > buf+len)
			valuep = buf + len;

		/*
		 * Lookup the keyword and process value accordingly
		 */
		for (tunep = &env_tuneables[0]; tunep->name != NULL; tunep++) {
			if (strcasecmp(tunep->name, tok) == 0) {
				(void) (*tunep->func)(tok, valuep,
				    tunep->arg1, tunep->arg2, fname, line);
				break;
			}
		}

		if (tunep->name == NULL)
			envd_log(LOG_INFO, ENV_CONF_UNSUPPORTED_KEYWORD,
			    fname, line, tok);
	}
	(void) fclose(fp);
}

/*
 * Setup envrionmental monitor state and start threads to monitor
 * temperature and power management state.
 * Returns -1 on error, 0 if successful.
 */

static int
envd_setup(void)
{
	char		*valp, *endp;
	int		val;
	int		err;

	if (pthread_attr_init(&thr_attr) != 0 ||
	    pthread_attr_setscope(&thr_attr, PTHREAD_SCOPE_SYSTEM) != 0)
		return (-1);

	if (pm_fd == -1)
		envd_open_pm();

	/*
	 * Setup lpm devices
	 */
	lpm_devices = NULL;
	if ((err = setup_lpm_devices(&lpm_devices)) != PICL_SUCCESS) {
		if (env_debug)
			envd_log(LOG_ERR, "setup_lpm_devices failed err = %d\n",
				err);
	}

	/*
	 * Initialize global state to initial startup values
	 */
	sensor_poll_interval = SENSOR_POLL_INTERVAL;
	fan_slow_adjustment = FAN_SLOW_ADJUSTMENT;
	fan_incr_limit = FAN_INCREMENT_LIMIT;
	fan_decr_limit = FAN_DECREMENT_LIMIT;
	warning_interval = WARNING_INTERVAL;
	warning_duration = WARNING_DURATION;
	shutdown_interval = SHUTDOWN_INTERVAL;
	disable_piclenvd = 0;
	disable_power_off = 0;
	disable_shutdown = 0;
	disable_warning = 0;

	(void) strlcpy(shutdown_cmd, SHUTDOWN_CMD, sizeof (shutdown_cmd));
	(void) strlcpy(devfsadm_cmd, DEVFSADM_CMD, sizeof (devfsadm_cmd));
	(void) strlcpy(fru_devfsadm_cmd, FRU_DEVFSADM_CMD,
	    sizeof (fru_devfsadm_cmd));
	envd_cpu_fan.forced_speed = -1;
	envd_system_fan.forced_speed = -1;

	(void) memcpy(&cpu0_die_thresh, &cpu_die_thresh_default,
	    sizeof (cpu_die_thresh_default));
	(void) memcpy(&cpu0_amb_thresh, &cpu_amb_thresh_default,
	    sizeof (cpu_amb_thresh_default));
	(void) memcpy(&cpu1_die_thresh, &cpu_die_thresh_default,
	    sizeof (cpu_die_thresh_default));
	(void) memcpy(&cpu1_amb_thresh, &cpu_amb_thresh_default,
	    sizeof (cpu_amb_thresh_default));

	if ((valp = getenv("SUNW_piclenvd_debug")) != NULL) {
		val = strtol(valp, &endp, 0);
		if (strtok(endp, tokdel) == NULL)
			env_debug = val;
	}

	/*
	 * Create a thread to monitor temperature and control fan
	 * speed.
	 */
	if (envthr_created == B_FALSE && pthread_create(&envthr_tid,
	    &thr_attr, envthr, (void *)NULL) != 0) {
		envd_close_fans();
		envd_close_sensors();
		envd_close_pm();
		envd_log(LOG_CRIT, ENV_THREAD_CREATE_FAILED);
		return (-1);
	}
	envthr_created = B_TRUE;

	/*
	 * Create a thread to monitor PM state
	 */
	if (pmthr_exists == B_FALSE) {
		if (pm_fd == -1 || pthread_create(&pmthr_tid, &thr_attr,
		    pmthr, (void *)NULL) != 0) {
			envd_log(LOG_CRIT, PM_THREAD_CREATE_FAILED);
		} else
			pmthr_exists = B_TRUE;
	}
	return (0);
}

/*
 * Callback function used by ptree_walk_tree_by_class for the cpu class
 */
static int
cb_cpu(picl_nodehdl_t nodeh, void *args)
{
	sensor_pmdev_t		*pmdevp;
	int			err;
	ptree_propinfo_t	pinfo;
	picl_prophdl_t		proph;
	size_t			psize;
	int			id;

	/* Get CPU's ID, it is an int */
	err = ptree_get_propval_by_name(nodeh, PICL_PROP_ID, &id, sizeof (int));
	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);

	/* Get the pmdevp for the CPU */
	pmdevp = sensor_pmdevs;
	while (pmdevp->sensor_id != -1) {
		if (id == pmdevp->sensor_id)
			break;
		pmdevp++;
	}

	/* Return if didn't find the pmdevp for the cpu id */
	if (pmdevp->sensor_id == -1)
		return (PICL_WALK_CONTINUE);

	/* Get the devfs-path property */
	err = ptree_get_prop_by_name(nodeh, PICL_PROP_DEVFS_PATH, &proph);
	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);

	err = ptree_get_propinfo(proph, &pinfo);
	if ((err != PICL_SUCCESS) ||
	    (pinfo.piclinfo.type != PICL_PTYPE_CHARSTRING))
		return (PICL_WALK_CONTINUE);

	psize = pinfo.piclinfo.size;
	pmdevp->pmdev_name = malloc(psize);
	if (pmdevp->pmdev_name == NULL)
		return (PICL_WALK_CONTINUE);

	err = ptree_get_propval(proph, pmdevp->pmdev_name, psize);
	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);

	return (PICL_WALK_CONTINUE);
}

/*
 * Find the CPU's in the picl tree, set the devfs-path for pmdev_name
 */
static void
setup_pmdev_names()
{
	picl_nodehdl_t	plath;
	int		err;

	err = ptree_get_node_by_path(PLATFORM_PATH, &plath);
	if (err != PICL_SUCCESS)
		return;

	err = ptree_walk_tree_by_class(plath, PICL_CLASS_CPU, NULL, cb_cpu);
}


static void
piclenvd_register(void)
{
	picld_plugin_register(&my_reg_info);
}

static void
piclenvd_init(void)
{
	/*
	 * Setup the names for the pm sensors, we do it just the first time
	 */
	if (pmdev_names_init == B_FALSE) {
		(void) setup_pmdev_names();
		pmdev_names_init = B_TRUE;
	}

	/*
	 * Start environmental monitor/threads
	 */
	(void) pthread_rwlock_wrlock(&envd_rwlock);
	if (envd_setup() != 0) {
		(void) pthread_rwlock_unlock(&envd_rwlock);
		envd_log(LOG_CRIT, ENVD_PLUGIN_INIT_FAILED);
		return;
	}
	(void) pthread_rwlock_unlock(&envd_rwlock);

	/*
	 * Now setup/populate PICL tree
	 */
	env_picl_setup();
}

static void
piclenvd_fini(void)
{
	/*
	 * Delete the lpm device list. After this the lpm information
	 * will not be used in determining the fan speed, till the lpm
	 * device information is initialized by setup_lpm_devices called
	 * by envd_setup.
	 */
	delete_lpm_devices();

	/*
	 * Invoke env_picl_destroy() to remove any PICL nodes/properties
	 * (including volatile properties) we created. Once this call
	 * returns, there can't be any more calls from the PICL framework
	 * to get current temperature or fan speed.
	 */
	env_picl_destroy();

	/*
	 * Since this is a critical plug-in, we know that it won't be
	 * unloaded and will be reinited again unless picld process is
	 * going away. Therefore, it's okay to let "envthr" and "pmthr"
	 * continue so that we can monitor the environment during SIGHUP
	 * handling also.
	 */
}

/*VARARGS2*/
void
envd_log(int pri, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

#ifdef __lint
/*
 * Redefine sigwait to posix style external declaration so that LINT
 * does not check against libc version of sigwait() and complain as
 * it uses different number of arguments.
 */
#define	sigwait	my_posix_sigwait
extern int my_posix_sigwait(const sigset_t *set, int *sig);
#endif

/*
 * sleep() in libpthread gets affected by time being set back, hence
 * can cause the "envthr" not to wakeup for extended duration. For
 * now, we implement our own sleep() routine below using alarm().
 * This will work only if SIGALRM is masked off in all other threads.
 * Note that SIGALRM signal is masked off in the main thread, hence
 * in all threads, including the envthr, the one calling this routine.
 *
 * Note that SIGALRM and alarm() can't be used by any other thread
 * in this manner.
 */

static unsigned int
envd_sleep(unsigned int sleep_tm)
{
	int  		sig;
	unsigned int	unslept;
	sigset_t	alrm_mask;

	if (sleep_tm == 0)
		return (0);

	(void) sigemptyset(&alrm_mask);
	(void) sigaddset(&alrm_mask, SIGALRM);

	(void) alarm(sleep_tm);
	(void) sigwait(&alrm_mask, &sig);

	unslept = alarm(0);
	return (unslept);
}
