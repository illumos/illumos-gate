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
 * This file contains the environmental PICL plug-in module.
 */

/*
 * This plugin sets up the PICLTREE for Chicago WS.
 * It provides functionality to get/set temperatures and
 * fan speeds.
 *
 * The environmental policy defaults to the auto mode
 * as programmed by OBP at boot time.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
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
#include <note.h>
#include <sys/pic16f747.h>
#include "envd.h"
#include <sys/scsi/scsi.h>
#include <sys/scsi/generic/commands.h>

int	debug_fd;
/*
 * PICL plugin entry points
 */
static void piclenvd_register(void);
static void piclenvd_init(void);
static void piclenvd_fini(void);

/*
 * Env setup routines
 */
extern void env_picl_setup(void);
extern void env_picl_destroy(void);
extern int env_picl_setup_tuneables(void);

static boolean_t has_fan_failed(env_fan_t *fanp);

/*
 * PSU fan fault handling
 */
static boolean_t has_psufan_failed(void);
static int psufan_last_status = FAN_OK;

#pragma init(piclenvd_register)

/*
 * Plugin registration information
 */
static picld_plugin_reg_t my_reg_info = {
	PICLD_PLUGIN_VERSION,
	PICLD_PLUGIN_CRITICAL,
	"SUNW_piclenvd",
	piclenvd_init,
	piclenvd_fini,
};

#define	REGISTER_INFORMATION_STRING_LENGTH	16
static char fan_rpm_string[REGISTER_INFORMATION_STRING_LENGTH] = {0};
static char fan_status_string[REGISTER_INFORMATION_STRING_LENGTH] = {0};

static int	scsi_log_sense(env_disk_t *diskp, uchar_t page_code,
			void *pagebuf, uint16_t pagelen, int page_control);
static int scsi_mode_select(env_disk_t *diskp, uchar_t page_code,
			uchar_t *pagebuf, uint16_t pagelen);

static int	get_disk_temp(env_disk_t *);

/*
 * ES Segment stuff
 */
static es_sensor_blk_t sensor_ctl[MAX_SENSORS];

/*
 * Default limits for sensors, in case ES segment is not present, or has
 * inconsistent information
 */
static es_sensor_blk_t sensor_default_ctl[MAX_SENSORS] = {
	{
	    CPU0_HIGH_POWER_OFF, CPU0_HIGH_SHUTDOWN, CPU0_HIGH_WARNING,
	    CPU0_LOW_WARNING, CPU0_LOW_SHUTDOWN, CPU0_LOW_POWER_OFF
	},
	{
	    CPU1_HIGH_POWER_OFF, CPU1_HIGH_SHUTDOWN, CPU1_HIGH_WARNING,
	    CPU1_LOW_WARNING, CPU1_LOW_SHUTDOWN, CPU1_LOW_POWER_OFF
	},
	{
	    ADT7462_HIGH_POWER_OFF, ADT7462_HIGH_SHUTDOWN, ADT7462_HIGH_WARNING,
	    ADT7462_LOW_WARNING, ADT7462_LOW_SHUTDOWN, ADT7462_LOW_POWER_OFF
	},
	{
	    MB_HIGH_POWER_OFF, MB_HIGH_SHUTDOWN, MB_HIGH_WARNING,
	    MB_LOW_WARNING, MB_LOW_SHUTDOWN, MB_LOW_POWER_OFF
	},
	{
	    LM95221_HIGH_POWER_OFF, LM95221_HIGH_SHUTDOWN, LM95221_HIGH_WARNING,
	    LM95221_LOW_WARNING, LM95221_LOW_SHUTDOWN, LM95221_LOW_POWER_OFF
	},
	{
	    FIRE_HIGH_POWER_OFF, FIRE_HIGH_SHUTDOWN, FIRE_HIGH_WARNING,
	    FIRE_LOW_WARNING, FIRE_LOW_SHUTDOWN, FIRE_LOW_POWER_OFF
	},
	{
	    LSI1064_HIGH_POWER_OFF, LSI1064_HIGH_SHUTDOWN, LSI1064_HIGH_WARNING,
	    LSI1064_LOW_WARNING, LSI1064_LOW_SHUTDOWN, LSI1064_LOW_POWER_OFF
	},
	{
	    FRONT_PANEL_HIGH_POWER_OFF, FRONT_PANEL_HIGH_SHUTDOWN,
	    FRONT_PANEL_HIGH_WARNING, FRONT_PANEL_LOW_WARNING,
	    FRONT_PANEL_LOW_SHUTDOWN, FRONT_PANEL_LOW_POWER_OFF
	},
	{
	    PSU_HIGH_POWER_OFF, PSU_HIGH_SHUTDOWN, PSU_HIGH_WARNING,
	    PSU_LOW_WARNING, PSU_LOW_SHUTDOWN, PSU_LOW_POWER_OFF
	}
};

/*
 * Env thread variables
 */
static boolean_t  system_shutdown_started = B_FALSE;
static boolean_t  system_temp_thr_created = B_FALSE;
static pthread_t  system_temp_thr_id;
static pthread_attr_t thr_attr;
static boolean_t  disk_temp_thr_created = B_FALSE;
static pthread_t  disk_temp_thr_id;
static boolean_t  fan_thr_created = B_FALSE;
static pthread_t  fan_thr_id;

/*
 * PM thread related variables
 */
static pthread_t	pmthr_tid;	/* pmthr thread ID */
static int		pm_fd = -1;	/* PM device file descriptor */
static boolean_t	pmthr_created = B_FALSE;
static int		cur_lpstate;	/* cur low power state */

/*
 * Envd plug-in verbose flag set by SUNW_PICLENVD_DEBUG environment var
 * Setting the verbose tuneable also enables debugging for better
 * control
 */
int	env_debug = 0;

/*
 * These are debug variables for keeping track of the total number
 * of Fan and Temp sensor retries over the lifetime of the plugin.
 */
static int total_fan_retries = 0;
static int total_temp_retries = 0;

/*
 * Fan devices
 */
static env_fan_t envd_system_fan0 = {
	ENV_SYSTEM_FAN0, ENV_SYSTEM_FAN0_DEVFS, SYSTEM_FAN0_ID,
	SYSTEM_FAN_SPEED_MIN, SYSTEM_FAN_SPEED_MAX, -1, -1,
};
static env_fan_t envd_system_fan1 = {
	ENV_SYSTEM_FAN1, ENV_SYSTEM_FAN1_DEVFS, SYSTEM_FAN1_ID,
	SYSTEM_FAN_SPEED_MIN, SYSTEM_FAN_SPEED_MAX, -1, -1,
};
static env_fan_t envd_system_fan2 = {
	ENV_SYSTEM_FAN2, ENV_SYSTEM_FAN2_DEVFS, SYSTEM_FAN2_ID,
	SYSTEM_FAN_SPEED_MIN, SYSTEM_FAN_SPEED_MAX, -1, -1,
};
static env_fan_t envd_system_fan3 = {
	ENV_SYSTEM_FAN3, ENV_SYSTEM_FAN3_DEVFS, SYSTEM_FAN3_ID,
	SYSTEM_FAN_SPEED_MIN, SYSTEM_FAN_SPEED_MAX, -1, -1,
};
static env_fan_t envd_system_fan4 = {
	ENV_SYSTEM_FAN4, ENV_SYSTEM_FAN4_DEVFS, SYSTEM_FAN4_ID,
	SYSTEM_FAN_SPEED_MIN, SYSTEM_FAN_SPEED_MAX, -1, -1,
};

/*
 * Disk devices
 */
static env_disk_t envd_disk0 = {
	ENV_DISK0, ENV_DISK0_DEVFS, DISK0_PHYSPATH, DISK0_NODE_PATH,
	DISK0_ID, -1,
};
static env_disk_t envd_disk1 = {
	ENV_DISK1, ENV_DISK1_DEVFS, DISK1_PHYSPATH, DISK1_NODE_PATH,
	DISK1_ID, -1,
};
static env_disk_t envd_disk2 = {
	ENV_DISK2, ENV_DISK2_DEVFS, DISK2_PHYSPATH, DISK2_NODE_PATH,
	DISK2_ID, -1,
};
static env_disk_t envd_disk3 = {
	ENV_DISK3, ENV_DISK3_DEVFS, DISK3_PHYSPATH, DISK3_NODE_PATH,
	DISK3_ID, -1,
};

/*
 * Sensors
 */
static env_sensor_t envd_sensor_cpu0 = {
	SENSOR_CPU0, SENSOR_CPU0_DEVFS, CPU0_SENSOR_ID, -1, NULL,
};
static env_sensor_t envd_sensor_cpu1 = {
	SENSOR_CPU1, SENSOR_CPU1_DEVFS, CPU1_SENSOR_ID, -1, NULL,
};
static env_sensor_t envd_sensor_adt7462 = {
	SENSOR_ADT7462, SENSOR_ADT7462_DEVFS, ADT7462_SENSOR_ID, -1, NULL,
};
static env_sensor_t envd_sensor_mb = {
	SENSOR_MB, SENSOR_MB_DEVFS, MB_SENSOR_ID, -1, NULL,
};
static env_sensor_t envd_sensor_lm95221 = {
	SENSOR_LM95221, SENSOR_LM95221_DEVFS, LM95221_SENSOR_ID, -1, NULL,
};
static env_sensor_t envd_sensor_fire = {
	SENSOR_FIRE, SENSOR_FIRE_DEVFS, FIRE_SENSOR_ID, -1, NULL,
};
static env_sensor_t envd_sensor_lsi1064 = {
	SENSOR_LSI1064, SENSOR_LSI1064_DEVFS, LSI1064_SENSOR_ID, -1, NULL,
};
static env_sensor_t envd_sensor_front_panel = {
	SENSOR_FRONT_PANEL, SENSOR_FRONT_PANEL_DEVFS, FRONT_PANEL_SENSOR_ID,
	-1, NULL,
};
static env_sensor_t envd_sensor_psu = {
	SENSOR_PSU, SENSOR_PSU_DEVFS, PSU_SENSOR_ID, -1, NULL,
};

/*
 * The vendor-id and device-id are the properties associated with
 * the SCSI controller. This is used to identify a particular controller
 * like LSI1064.
 */
#define	VENDOR_ID	"vendor-id"
#define	DEVICE_ID	"device-id"

/*
 * The implementation for SCSI disk drives to supply info. about
 * temperature is not mandatory. Hence we first determine if the
 * temperature page is supported. To do this we need to scan the list
 * of pages supported.
 */
#define	SUPPORTED_LPAGES	0
#define	TEMPERATURE_PAGE	0x0D
#define	LOGPAGEHDRSIZE	4

/*
 * NULL terminated array of fans
 */
static env_fan_t *envd_fans[] = {
	&envd_system_fan0,
	&envd_system_fan1,
	&envd_system_fan2,
	&envd_system_fan3,
	&envd_system_fan4,
	NULL
};

/*
 * NULL terminated array of disks
 */
static env_disk_t *envd_disks[] = {
	&envd_disk0,
	&envd_disk1,
	&envd_disk2,
	&envd_disk3,
	NULL
};

/*
 * NULL terminated array of temperature sensors
 */
#define	N_ENVD_SENSORS	9
static env_sensor_t *envd_sensors[] = {
	&envd_sensor_cpu0,
	&envd_sensor_cpu1,
	&envd_sensor_adt7462,
	&envd_sensor_mb,
	&envd_sensor_lm95221,
	&envd_sensor_fire,
	&envd_sensor_lsi1064,
	&envd_sensor_front_panel,
	&envd_sensor_psu,
	NULL
};

#define	NOT_AVAILABLE	"NA"

/*
 * Tuneables
 */
#define	ENABLE	1
#define	DISABLE	0

static	int	disk_high_warn_temperature	= DISK_HIGH_WARN_TEMPERATURE;
static	int	disk_low_warn_temperature	= DISK_LOW_WARN_TEMPERATURE;
static	int	disk_high_shutdown_temperature	=
						DISK_HIGH_SHUTDOWN_TEMPERATURE;
static	int	disk_low_shutdown_temperature	= DISK_LOW_SHUTDOWN_TEMPERATURE;

static	int	disk_scan_interval		= DISK_SCAN_INTERVAL;
static	int	sensor_scan_interval		= SENSOR_SCAN_INTERVAL;
static	int	fan_scan_interval		= FAN_SCAN_INTERVAL;

static int get_int_val(ptree_rarg_t *parg, void *buf);
static int set_int_val(ptree_warg_t *parg, const void *buf);
static int get_string_val(ptree_rarg_t *parg, void *buf);
static int set_string_val(ptree_warg_t *parg, const void *buf);

static int 	shutdown_override	= 0;
static int	sensor_warning_interval	= SENSOR_WARNING_INTERVAL;
static int	sensor_warning_duration	= SENSOR_WARNING_DURATION;
static int	sensor_shutdown_interval = SENSOR_SHUTDOWN_INTERVAL;
static int	disk_warning_interval	= DISK_WARNING_INTERVAL;
static int	disk_warning_duration	= DISK_WARNING_DURATION;
static int 	disk_shutdown_interval	= DISK_SHUTDOWN_INTERVAL;

static int	system_temp_monitor	= 1;	/* enabled */
static int	fan_monitor		= 1;	/* enabled */
static int	pm_monitor		= 1;	/* enabled */

/* Disable disk temperature monitoring until we have LSI fw support */
int		disk_temp_monitor	= 0;

static char	shutdown_cmd[] = SHUTDOWN_CMD;
const char	*iofru_devname = I2C_DEVFS "/" IOFRU_DEV;

env_tuneable_t tuneables[] = {
	{"system_temp-monitor", PICL_PTYPE_INT, &system_temp_monitor,
	    &get_int_val, &set_int_val, sizeof (int)},

	{"fan-monitor", PICL_PTYPE_INT, &fan_monitor,
	    &get_int_val, &set_int_val, sizeof (int)},

	{"pm-monitor", PICL_PTYPE_INT, &pm_monitor,
	    &get_int_val, &set_int_val, sizeof (int)},

	{"shutdown-override", PICL_PTYPE_INT, &shutdown_override,
	    &get_int_val, &set_int_val, sizeof (int)},

	{"sensor-warning-duration", PICL_PTYPE_INT,
	    &sensor_warning_duration,
	    &get_int_val, &set_int_val,
	    sizeof (int)},

	{"disk-scan-interval", PICL_PTYPE_INT,
	    &disk_scan_interval,
	    &get_int_val, &set_int_val,
	    sizeof (int)},

	{"fan-scan-interval", PICL_PTYPE_INT,
	    &fan_scan_interval,
	    &get_int_val, &set_int_val,
	    sizeof (int)},

	{"sensor-scan-interval", PICL_PTYPE_INT,
	    &sensor_scan_interval,
	    &get_int_val, &set_int_val,
	    sizeof (int)},

	{"sensor_warning-interval", PICL_PTYPE_INT, &sensor_warning_interval,
	    &get_int_val, &set_int_val,
	    sizeof (int)},

	{"sensor_shutdown-interval", PICL_PTYPE_INT, &sensor_shutdown_interval,
	    &get_int_val, &set_int_val,
	    sizeof (int)},

	{"disk_warning-interval", PICL_PTYPE_INT, &disk_warning_interval,
	    &get_int_val, &set_int_val,
	    sizeof (int)},

	{"disk_warning-duration", PICL_PTYPE_INT, &disk_warning_duration,
	    &get_int_val, &set_int_val,
	    sizeof (int)},

	{"disk_shutdown-interval", PICL_PTYPE_INT, &disk_shutdown_interval,
	    &get_int_val, &set_int_val,
	    sizeof (int)},

	{"shutdown-command", PICL_PTYPE_CHARSTRING, shutdown_cmd,
	    &get_string_val, &set_string_val,
	    sizeof (shutdown_cmd)},

	{"monitor-disk-temp", PICL_PTYPE_INT, &disk_temp_monitor,
	    &get_int_val, &set_int_val, sizeof (int)},

	{"disk-high-warn-temperature", PICL_PTYPE_INT,
	    &disk_high_warn_temperature, &get_int_val,
	    &set_int_val, sizeof (int)},

	{"disk-low-warn-temperature", PICL_PTYPE_INT,
	    &disk_low_warn_temperature, &get_int_val,
	    &set_int_val, sizeof (int)},

	{"disk-high-shutdown-temperature", PICL_PTYPE_INT,
	    &disk_high_shutdown_temperature, &get_int_val,
	    &set_int_val, sizeof (int)},

	{"disk-low-shutdown-temperature", PICL_PTYPE_INT,
	    &disk_low_shutdown_temperature, &get_int_val,
	    &set_int_val, sizeof (int)},

	{"verbose", PICL_PTYPE_INT, &env_debug,
	    &get_int_val, &set_int_val, sizeof (int)}
};

/*
 * We use this to figure out how many tuneables there are
 * This is variable because the publishing routine needs this info
 * in piclenvsetup.c
 */
int	ntuneables = (sizeof (tuneables)/sizeof (tuneables[0]));

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
	int		i;

	for (i = 0; i < N_ENVD_SENSORS; ++i) {
		sensorp = envd_sensors[i];
		if (strcmp(sensorp->name, name) == 0)
			return (sensorp);
	}
	return (NULL);
}

/*
 * Lookup disk and return a pointer to env_disk_t data structure.
 */
env_disk_t *
disk_lookup(char *name)
{
	int		i;
	env_disk_t	*diskp;

	for (i = 0; (diskp = envd_disks[i]) != NULL; i++) {
		if (strncmp(diskp->name, name, strlen(name)) == 0)
			return (diskp);
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

	if (fd == -1)
		retval = -1;
	else if (ioctl(fd, PIC_GET_TEMPERATURE, temp) != 0) {

		retval = -1;

		sensorp->error++;

		if (sensorp->error == MAX_SENSOR_RETRIES) {
			envd_log(LOG_WARNING, ENV_SENSOR_ACCESS_FAIL,
			    sensorp->name, errno, strerror(errno));
		}

		total_temp_retries++;
		(void) sleep(1);

	} else if (sensorp->error != 0) {
		if (sensorp->error >= MAX_SENSOR_RETRIES) {
			envd_log(LOG_WARNING, ENV_SENSOR_ACCESS_OK,
			    sensorp->name);
		}

		sensorp->error = 0;

		if (total_temp_retries && env_debug) {
			envd_log(LOG_WARNING,
			    "Total retries for sensors = %d",
			    total_temp_retries);
		}
	}

	return (retval);
}

/*
 * Get current disk temperature
 * Returns -1 on error, 0 if successful
 */
int
disk_temperature(env_disk_t *diskp, tempr_t *temp)
{
	int	retval = 0;

	if (diskp == NULL)
		retval = -1;
	else
		*temp = diskp->current_temp;

	return (retval);
}

/*
 * Get current fan speed
 * This function returns a RPM value for fanspeed
 * in fanspeedp.
 * Returns -1 on error, 0 if successful
 */
int
get_fan_speed(env_fan_t *fanp, fanspeed_t *fanspeedp)
{
	uint8_t tach;
	int	real_tach;
	int	retries;

	if (fanp->fd == -1)
		return (-1);

	if (has_fan_failed(fanp)) {
		*fanspeedp = 0;
		return (0);
	}

	/* try to read the fan information */
	for (retries = 0; retries < MAX_FAN_RETRIES; retries++) {
		if (ioctl(fanp->fd, PIC_GET_FAN_SPEED, &tach) == 0)
			break;
		(void) sleep(1);
	}

	total_fan_retries += retries;
	if (retries >= MAX_FAN_RETRIES)
		return (-1);

	if (total_fan_retries && env_debug) {
		envd_log(LOG_WARNING, "total retries for fan = %d",
		    total_fan_retries);
	}

	real_tach = tach << 8;
	*fanspeedp = TACH_TO_RPM(real_tach);
	return (0);
}

/*
 * Set fan speed
 * This function accepts a percentage of fan speed
 * from 0-100 and programs the HW monitor fans to the corresponding
 * fanspeed value.
 * Returns -1 on error, -2 on invalid args passed, 0 if successful
 */
int
set_fan_speed(env_fan_t *fanp, fanspeed_t fanspeed)
{
	uint8_t	speed;

	if (fanp->fd == -1)
		return (-1);

	if (fanspeed < 0 || fanspeed > 100)
		return (-2);

	speed = fanspeed;
	if (ioctl(fanp->fd, PIC_SET_FAN_SPEED, &speed) != 0)
		return (-1);

	return (0);
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
 * Close sensor devices and freeup resources
 */
static void
envd_close_sensors(void)
{
	env_sensor_t	*sensorp;
	int		i;

	for (i = 0; i < N_ENVD_SENSORS; ++i) {
		sensorp = envd_sensors[i];
		if (sensorp->fd != -1) {
			(void) close(sensorp->fd);
			sensorp->fd = -1;
		}
	}
}

/*
 * Open fan devices and initialize per fan data structure.
 */
static int
envd_setup_fans(void)
{
	int		i, fd;
	env_fan_t	*fanp;
	int		fancnt = 0;
	picl_nodehdl_t tnodeh;

	for (i = 0; (fanp = envd_fans[i]) != NULL; i++) {
		fanp->last_status = FAN_OK;

		/* Make sure cpu0/1 present for validating cpu fans */
		if (fanp->id == CPU0_FAN_ID) {
			if (ptree_get_node_by_path(CPU0_PATH, &tnodeh) !=
			    PICL_SUCCESS) {
					if (env_debug) {
						envd_log(LOG_ERR,
					"get node by path failed for %s\n",
						    CPU0_PATH);
					}
					fanp->present = B_FALSE;
					continue;
			}
		}
		if (fanp->id == CPU1_FAN_ID) {
			if (ptree_get_node_by_path(CPU1_PATH, &tnodeh) !=
			    PICL_SUCCESS) {
					if (env_debug) {
						envd_log(LOG_ERR,
				"get node by path failed for %s\n", CPU0_PATH);
					}
					fanp->present = B_FALSE;
					continue;
			}
		}
		if ((fd = open(fanp->devfs_path, O_RDWR)) == -1) {
			envd_log(LOG_CRIT,
			    ENV_FAN_OPEN_FAIL, fanp->name,
			    fanp->devfs_path, errno, strerror(errno));
			fanp->present = B_FALSE;
			continue;
		}
		fanp->fd = fd;
		fanp->present = B_TRUE;
		fancnt++;
	}

	if (fancnt == 0)
		return (-1);

	return (0);
}

static int
envd_setup_disks(void)
{
	int	ret, i, page_index, page_len;
	picl_nodehdl_t tnodeh;
	env_disk_t	*diskp;
	uint_t	vendor_id;
	uint_t	device_id;
	uchar_t	log_page[256];

	if (ptree_get_node_by_path(SCSI_CONTROLLER_NODE_PATH,
	    &tnodeh) != PICL_SUCCESS) {
		if (env_debug) {
			envd_log(LOG_ERR, "On-Board SCSI controller %s "
			    "not found in the system.\n",
			    SCSI_CONTROLLER_NODE_PATH);
		}
		return (-1);
	}

	if ((ret = ptree_get_propval_by_name(tnodeh, VENDOR_ID,
	    &vendor_id, sizeof (vendor_id))) != 0) {
		if (env_debug) {
			envd_log(LOG_ERR, "Error in getting vendor-id "
			    "for SCSI controller. ret = %d errno = 0x%d\n",
			    ret, errno);
		}
		return (-1);
	}
	if ((ret = ptree_get_propval_by_name(tnodeh, DEVICE_ID,
	    &device_id, sizeof (device_id))) != 0) {
		if (env_debug) {
			envd_log(LOG_ERR, "Error in getting device-id "
			    "for SCSI controller. ret = %d errno = 0x%d\n",
			    ret, errno);
		}
		return (-1);
	}

	/*
	 * We have found LSI1064 SCSi controller onboard.
	 */
	for (i = 0; (diskp = envd_disks[i]) != NULL; i++) {
		if (ptree_get_node_by_path(diskp->nodepath,
		    &tnodeh) != PICL_SUCCESS) {
			diskp->present = B_FALSE;
			if (env_debug) {
				envd_log(LOG_ERR,
				    "DISK %d: %s not found in the system.\n",
				    diskp->id, diskp->nodepath);
			}
			continue;
		}
		if ((diskp->fd = open(diskp->devfs_path, O_RDONLY)) == -1) {
			diskp->present = B_FALSE;
			if (env_debug) {
				envd_log(LOG_ERR,
				    "Error in opening %s errno = 0x%x\n",
				    diskp->devfs_path, errno);
			}
			continue;
		}
		diskp->present = B_TRUE;
		diskp->tpage_supported = B_FALSE;
		diskp->smart_supported = B_FALSE;
		diskp->warning_tstamp = 0;
		diskp->shutdown_tstamp = 0;
		diskp->high_warning = disk_high_warn_temperature;
		diskp->low_warning = disk_low_warn_temperature;
		diskp->high_shutdown = disk_high_shutdown_temperature;
		diskp->low_shutdown = disk_low_shutdown_temperature;
		/*
		 * Find out if the Temperature page is supported by the disk.
		 */
		if (scsi_log_sense(diskp, SUPPORTED_LPAGES, log_page,
		    sizeof (log_page), 1) == 0) {

			page_len = ((log_page[2] << 8) & 0xFF00) | log_page[3];

			for (page_index = LOGPAGEHDRSIZE;
			    page_index < page_len + LOGPAGEHDRSIZE;
			    page_index++) {
				if (log_page[page_index] != TEMPERATURE_PAGE)
					continue;

				diskp->tpage_supported = B_TRUE;
				if (env_debug) {
					envd_log(LOG_ERR,
					    "tpage supported for %s\n",
					    diskp->nodepath);
				}
			}
		}
		/*
		 * If the temp log page failed, we can check if this is
		 * a SATA drive and attempt to read the temperature
		 * using the SMART interface.
		 */
		if (diskp->tpage_supported != B_TRUE) {
			uchar_t iec_page[IEC_PAGE_SIZE];

			if (env_debug)
				envd_log(LOG_ERR, "Turning on SMART\n");

			(void) memset(iec_page, 0, sizeof (iec_page));
			iec_page[0] = IEC_PAGE;	/* SMART PAGE */
			iec_page[1] = 0xa;	/* length */
			/* Notification, only when requested */
			iec_page[3] = REPORT_ON_REQUEST;

			ret = scsi_mode_select(diskp, IEC_PAGE,
			    iec_page, sizeof (iec_page));

			/*
			 * Since we know this is a SMART capable
			 * drive, we will try to set the page and
			 * determine if the drive is not capable
			 * of reading the TEMP page when we
			 * try to read the temperature and disable
			 * it then. We do not fail when reading
			 * or writing this page because we will
			 * determine the SMART capabilities
			 * when reading the temperature.
			 */
			if ((ret != 0) && (env_debug)) {
				envd_log(LOG_ERR,
				    "Failed to set mode page");
			}

			diskp->smart_supported = B_TRUE;
			diskp->tpage_supported = B_TRUE;
		}

		if (get_disk_temp(diskp) < 0) {
			envd_log(LOG_ERR, " error reading temperature of:%s\n",
			    diskp->name);
		} else if (env_debug) {
			envd_log(LOG_ERR, "%s: temperature = %d\n",
			    diskp->name, diskp->current_temp);
		}

	}

	return (0);
}

static int
envd_es_setup(void)
{
	seeprom_scn_t	scn_hdr;
	seeprom_seg_t	seg_hdr;
	es_data_t	*envseg;
	es_sensor_t	*sensorp;
	int		i, fd, id;
	int		envseg_len, esd_len;
	char		*envsegp;

	/*
	 * Open the front io fru
	 */
	if ((fd = open(iofru_devname, O_RDONLY)) == -1) {
		envd_log(LOG_ERR, ENV_FRU_OPEN_FAIL, iofru_devname, errno);
		return (-1);
	}

	/*
	 * Read section header from the fru SEEPROM
	 */
	if (lseek(fd, SSCN_OFFSET, SEEK_SET) == (off_t)-1 ||
	    read(fd, &scn_hdr, sizeof (scn_hdr)) != sizeof (scn_hdr)) {
		envd_log(LOG_ERR, ENV_FRU_BAD_ENVSEG, iofru_devname);
		(void) close(fd);
		return (-1);
	}
	if ((scn_hdr.sscn_tag != SSCN_TAG) ||
	    (GET_UNALIGN16(&scn_hdr.sscn_ver) != SSCN_VER)) {
		envd_log(LOG_ERR, ENV_FRU_BAD_SCNHDR, scn_hdr.sscn_tag,
		    GET_UNALIGN16(&scn_hdr.sscn_ver));
		(void) close(fd);
		return (-1);
	}

	/*
	 * Locate environmental segment
	 */
	for (i = 0; i < scn_hdr.sscn_nsegs; i++) {
		if (read(fd, &seg_hdr, sizeof (seg_hdr)) != sizeof (seg_hdr)) {
			envd_log(LOG_ERR, ENV_FRU_BAD_ENVSEG, iofru_devname);
			(void) close(fd);
			return (-1);
		}

		if (env_debug) {
			envd_log(LOG_INFO,
			    "Seg name: %x off:%x len:%x\n",
			    GET_UNALIGN16(&seg_hdr.sseg_name),
			    GET_UNALIGN16(&seg_hdr.sseg_off),
			    GET_UNALIGN16(&seg_hdr.sseg_len));
		}

		if (GET_UNALIGN16(&seg_hdr.sseg_name) == ENVSEG_NAME)
			break;
	}
	if (i == scn_hdr.sscn_nsegs) {
		envd_log(LOG_ERR, ENV_FRU_BAD_ENVSEG, iofru_devname);
		(void) close(fd);
		return (-1);
	}

	/*
	 * Read environmental segment
	 */
	envseg_len = GET_UNALIGN16(&seg_hdr.sseg_len);
	if ((envseg = malloc(envseg_len)) == NULL) {
		envd_log(LOG_ERR, ENV_FRU_NOMEM_FOR_SEG, envseg_len);
		(void) close(fd);
		return (-1);
	}

	if (lseek(fd, (off_t)GET_UNALIGN16(&seg_hdr.sseg_off),
	    SEEK_SET) == (off_t)-1 ||
	    read(fd, envseg, envseg_len) != envseg_len) {
		envd_log(LOG_ERR, ENV_FRU_BAD_ENVSEG, iofru_devname);
		free(envseg);
		(void) close(fd);
		return (-1);
	}

	/*
	 * Check environmental segment data for consistency
	 */
	esd_len = sizeof (*envseg) +
	    (envseg->esd_nsensors - 1) * sizeof (envseg->esd_sensors[0]);
	if (envseg->esd_ver != ENVSEG_VERSION || envseg_len < esd_len) {
		envd_log(LOG_ERR, ENV_FRU_BAD_ENVSEG, iofru_devname);
		free(envseg);
		(void) close(fd);
		return (-1);
	}

	/*
	 * Process environmental segment data
	 */
	if (envseg->esd_nsensors > MAX_SENSORS) {
		envd_log(LOG_ERR, ENV_FRU_BAD_ENVSEG, iofru_devname);
		free(envseg);
		(void) close(fd);
		return (-1);
	}

	sensorp = &(envseg->esd_sensors[0]);
	envsegp = (char *)envseg;
	for (i = 0; i < envseg->esd_nsensors; i++) {
		uint32_t ess_id;

		(void) memcpy(&ess_id,
		    sensorp->ess_id, sizeof (sensorp->ess_id));

		if (env_debug) {
			envd_log(LOG_INFO, "\n Sensor Id %x offset %x",
			    ess_id, sensorp->ess_off);
		}
		if (ess_id >= MAX_SENSORS) {
			envd_log(LOG_ERR, ENV_FRU_BAD_ENVSEG, iofru_devname);
			free(envseg);
			(void) close(fd);
			return (-1);
		}
		(void) memcpy(&sensor_ctl[ess_id], &envsegp[sensorp->ess_off],
		    sizeof (es_sensor_blk_t));

		sensorp++;
	}

	/*
	 * Match sensor/ES id and point to correct data based on IDs
	 */
	for (i = 0; i < N_ENVD_SENSORS; i++) {
		id = envd_sensors[i]->id;
		envd_sensors[i]->es = &sensor_ctl[id];
	}

	/*
	 * Cleanup and return
	 */
	free(envseg);
	(void) close(fd);

	return (0);
}

static void
envd_es_default_setup(void)
{
	int	i, id;

	for (i = 0; i < N_ENVD_SENSORS; i++) {
		id = envd_sensors[i]->id;
		envd_sensors[i]->es = &sensor_default_ctl[id];
	}
}

/*
 * Open temperature sensor devices and initialize per sensor data structure.
 */
static int
envd_setup_sensors(void)
{
	env_sensor_t	*sensorp;
	int		sensorcnt = 0;
	int		i;
	picl_nodehdl_t	tnodeh;

	for (i = 0; i < N_ENVD_SENSORS; i++) {
		if (env_debug)
			envd_log(LOG_ERR, "scanning sensor %d\n", i);

		sensorp = envd_sensors[i];

		/* Initialize sensor's initial state */
		sensorp->shutdown_initiated = B_FALSE;
		sensorp->warning_tstamp = 0;
		sensorp->shutdown_tstamp = 0;
		sensorp->error = 0;

		/* Make sure cpu0/1 sensors are present */
		if (sensorp->id == CPU0_SENSOR_ID) {
			if (ptree_get_node_by_path(CPU0_PATH, &tnodeh) !=
			    PICL_SUCCESS) {
				if (env_debug) {
					envd_log(LOG_ERR,
					    "get node by path failed for %s\n",
					    CPU0_PATH);
				}
				sensorp->present = B_FALSE;
				continue;
			}
		}
		if (sensorp->id == CPU1_SENSOR_ID) {
			if (ptree_get_node_by_path(CPU1_PATH, &tnodeh) !=
			    PICL_SUCCESS) {
				if (env_debug) {
					envd_log(LOG_ERR,
					    "get node by path failed for %s\n",
					    CPU1_PATH);
				}
				sensorp->present = B_FALSE;
				continue;
			}
		}

		sensorp->fd = open(sensorp->devfs_path, O_RDWR);
		if (sensorp->fd == -1) {
			if (env_debug) {
				envd_log(LOG_ERR, ENV_SENSOR_OPEN_FAIL,
				    sensorp->name, sensorp->devfs_path,
				    errno, strerror(errno));
			}
			sensorp->present = B_FALSE;
			continue;
		}

		/*
		 * Determine if the front panel is attached, we want the
		 * information if it exists, but should not shut down
		 * the system if it is removed.
		 */
		if (sensorp->id == FRONT_PANEL_SENSOR_ID) {
			tempr_t temp;
			int	tries;

			for (tries = 0; tries < MAX_SENSOR_RETRIES; tries++) {
				if (ioctl(sensorp->fd, PIC_GET_TEMPERATURE,
				    &temp) == 0) {
					break;
				}
				(void) sleep(1);
			}
			if (tries == MAX_SENSOR_RETRIES)
				sensorp->present = B_FALSE;
		}

		sensorp->present = B_TRUE;
		sensorcnt++;
	}

	if (sensorcnt == 0)
		return (-1);

	return (0);
}

/* ARGSUSED */
static void *
pmthr(void *args)
{
	pm_state_change_t	pmstate;
	char			physpath[PATH_MAX];
	int			pre_lpstate;
	uint8_t			estar_state;
	int			env_monitor_fd;

	pmstate.physpath = physpath;
	pmstate.size = sizeof (physpath);
	cur_lpstate = 0;
	pre_lpstate = 1;

	pm_fd = open(PM_DEVICE, O_RDWR);
	if (pm_fd == -1) {
		envd_log(LOG_ERR, PM_THREAD_EXITING, errno, strerror(errno));
		return (NULL);
	}
	for (;;) {
		/*
		 * Get PM state change events to check if the system
		 * is in lowest power state and inform PIC which controls
		 * fan speeds.
		 *
		 * To minimize polling, we use the blocking interface
		 * to get the power state change event here.
		 */
		if (ioctl(pm_fd, PM_GET_STATE_CHANGE_WAIT, &pmstate) != 0) {
			if (errno != EINTR)
				break;
			continue;
		}

		do {
			if (env_debug)  {
				envd_log(LOG_INFO,
				"pmstate event:0x%x flags:%x"
				"comp:%d oldval:%d newval:%d path:%s\n",
				    pmstate.event, pmstate.flags,
				    pmstate.component,
				    pmstate.old_level,
				    pmstate.new_level,
				    pmstate.physpath);
			}
			cur_lpstate =
			    (pmstate.flags & PSC_ALL_LOWEST) ? 1 : 0;
		} while (ioctl(pm_fd, PM_GET_STATE_CHANGE, &pmstate) == 0);

		if (pre_lpstate != cur_lpstate) {
			pre_lpstate = cur_lpstate;
			estar_state = (cur_lpstate & 0x1);
			if (env_debug)
				envd_log(LOG_ERR,
				    "setting PIC ESTAR SATE to %x\n",
				    estar_state);

			env_monitor_fd = open(ENV_MONITOR_DEVFS, O_RDWR);
			if (env_monitor_fd != -1) {
				if (ioctl(env_monitor_fd, PIC_SET_ESTAR_MODE,
				    &estar_state) < 0) {
					if (env_debug)
						envd_log(LOG_ERR,
					"unable to set ESTAR_MODE in PIC\n");
				}
				(void) close(env_monitor_fd);
			} else {
				if (env_debug)
					envd_log(LOG_ERR,
				"Failed to open %s\n",
					    ENV_MONITOR_DEVFS);
			}
		}
	}

	/*NOTREACHED*/
	return (NULL);
}

/*
 * This is env thread which monitors the current temperature when
 * warning threshold is exceeded. The job is to make sure it does
 * not execced/decrease shutdown threshold. If it does it will start
 * forced shutdown to avoid reaching hardware poweroff via THERM interrupt.
 */
/*ARGSUSED*/
static void *
system_temp_thr(void *args)
{
	char syscmd[BUFSIZ];
	char msgbuf[BUFSIZ];
	timespec_t	to;
	int	ret, i;
	env_sensor_t	*sensorp;
	pthread_mutex_t	env_monitor_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t	env_monitor_cv = PTHREAD_COND_INITIALIZER;
	time_t	ct;
	tempr_t  temp;

	for (;;) {
		/*
		 * Sleep for specified seconds before issuing IOCTL
		 * again.
		 */
		(void) pthread_mutex_lock(&env_monitor_mutex);
		ret = pthread_cond_reltimedwait_np(&env_monitor_cv,
		    &env_monitor_mutex, &to);
		to.tv_sec = sensor_scan_interval;
		to.tv_nsec = 0;
		if (ret != ETIMEDOUT) {
			(void) pthread_mutex_unlock(&env_monitor_mutex);
			continue;
		}

		(void) pthread_mutex_unlock(&env_monitor_mutex);
		for (i = 0; i < N_ENVD_SENSORS; i++) {
			sensorp = envd_sensors[i];
			if (sensorp->present == B_FALSE)
				continue;
			if (get_temperature(sensorp, &temp) == -1)
				continue;

			sensorp->cur_temp = temp;
			if (env_debug) {
				envd_log(LOG_ERR,
				"%s temp = %d",
				    sensorp->name, sensorp->cur_temp);
			}

			/*
			 * If this sensor already triggered system shutdown,
			 * don't log any more shutdown/warning messages for it.
			 */
			if (sensorp->shutdown_initiated)
				continue;

			/*
			 * Check for the temperature in warning and shutdown
			 * range and take appropriate action.
			 */
			if (SENSOR_TEMP_IN_WARNING_RANGE(sensorp->cur_temp,
			    sensorp)) {
				/*
				 * Check if the temperature has been in
				 * warning range during last
				 * sensor_warning_duration interval. If so,
				 * the temperature is truly in warning range
				 * and we need to log a warning message, but
				 * no more than once every
				 * sensor_warning_interval seconds.
				 */
				time_t	wtstamp = sensorp->warning_tstamp;

				ct = (time_t)(gethrtime() / NANOSEC);
				if (sensorp->warning_start == 0)
					sensorp->warning_start = ct;
				if (((ct - sensorp->warning_start) >=
				    sensor_warning_duration) &&
				    (wtstamp == 0 || (ct - wtstamp) >=
				    sensor_warning_interval)) {
					envd_log(LOG_CRIT, ENV_WARNING_MSG,
					    sensorp->name, sensorp->cur_temp,
					    (int8_t)
					    sensorp->es->esb_low_warning,
					    (int8_t)
					    sensorp->es->esb_high_warning);

					sensorp->warning_tstamp = ct;
				}
			} else if (sensorp->warning_start != 0)
				sensorp->warning_start = 0;

			if (!shutdown_override &&
			    SENSOR_TEMP_IN_SHUTDOWN_RANGE(sensorp->cur_temp,
			    sensorp)) {
				ct = (time_t)(gethrtime() / NANOSEC);
				if (sensorp->shutdown_tstamp == 0)
					sensorp->shutdown_tstamp = ct;

				/*
				 * Shutdown the system if the temperature
				 * remains in the shutdown range for over
				 * sensor_shutdown_interval seconds.
				 */
				if ((ct - sensorp->shutdown_tstamp) >=
				    sensor_shutdown_interval) {
					/*
					 * Log error
					 */
					sensorp->shutdown_initiated = B_TRUE;

					(void) snprintf(msgbuf, sizeof (msgbuf),
					    ENV_SHUTDOWN_MSG, sensorp->name,
					    sensorp->cur_temp,
					    (int8_t)
					    sensorp->es->esb_low_shutdown,
					    (int8_t)
					    sensorp->es->esb_high_shutdown);

					envd_log(LOG_ALERT, msgbuf);

					/*
					 * Shutdown the system (only once)
					 */
					if (system_shutdown_started ==
					    B_FALSE) {
						(void) snprintf(syscmd,
						    sizeof (syscmd),
						    "%s \"%s\"", shutdown_cmd,
						    msgbuf);

						envd_log(LOG_ALERT, syscmd);
						system_shutdown_started =
						    B_TRUE;

						(void) system(syscmd);
					}
				}
			} else if (sensorp->shutdown_tstamp != 0)
				sensorp->shutdown_tstamp = 0;
		}
	}	/* end of forever loop */

	/*NOTREACHED*/
	return (NULL);
}

static int
scsi_log_sense(env_disk_t *diskp, uchar_t page_code, void *pagebuf,
		uint16_t pagelen, int page_control)
{
	struct uscsi_cmd	ucmd_buf;
	uchar_t		cdb_buf[CDB_GROUP1];
	struct	scsi_extended_sense	sense_buf;
	int	ret_val;

	bzero(&cdb_buf, sizeof (cdb_buf));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(&sense_buf, sizeof (sense_buf));

	cdb_buf[0] = SCMD_LOG_SENSE_G1;

	/*
	 * For SATA we need to have the current threshold value set.
	 * For SAS drives we can use the current cumulative value.
	 * This is set for non-SMART drives, by passing a non-zero
	 * page_control.
	 */
	if (page_control)
		cdb_buf[2] = (0x01 << 6) | page_code;
	else
		cdb_buf[2] = page_code;

	cdb_buf[7] = (uchar_t)((pagelen & 0xFF00) >> 8);
	cdb_buf[8] = (uchar_t)(pagelen  & 0x00FF);

	ucmd_buf.uscsi_cdb = (char *)cdb_buf;
	ucmd_buf.uscsi_cdblen = sizeof (cdb_buf);
	ucmd_buf.uscsi_bufaddr = (caddr_t)pagebuf;
	ucmd_buf.uscsi_buflen = pagelen;
	ucmd_buf.uscsi_rqbuf = (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen = sizeof (struct scsi_extended_sense);
	ucmd_buf.uscsi_flags = USCSI_RQENABLE | USCSI_READ | USCSI_SILENT;
	ucmd_buf.uscsi_timeout = DEFAULT_SCSI_TIMEOUT;

	ret_val = ioctl(diskp->fd, USCSICMD, ucmd_buf);
	if ((ret_val == 0) && (ucmd_buf.uscsi_status == 0)) {
		if (env_debug)
			envd_log(LOG_ERR,
		"log sense command for page_code 0x%x succeeded\n", page_code);
		return (ret_val);
	}
	if (env_debug)
		envd_log(LOG_ERR, "log sense command for %s failed. "
		    "page_code 0x%x ret_val = 0x%x "
		    "status = 0x%x errno = 0x%x\n", diskp->name, page_code,
		    ret_val, ucmd_buf.uscsi_status, errno);

	return (1);
}


static int
get_disk_temp(env_disk_t *diskp)
{
	int	ret;
	uchar_t	tpage[256];

	if (diskp->smart_supported == B_TRUE) {
		smart_structure	smartpage;
		smart_attribute	*temp_attrib = NULL;
		uint8_t		checksum;
		uint8_t		*index;
		int		i;

		bzero(&smartpage, sizeof (smartpage));

		ret = scsi_log_sense(diskp, GET_SMART_INFO,
		    &smartpage, sizeof (smartpage), 0);

		if (ret != 0) {
			diskp->current_temp = DISK_INVALID_TEMP;
			diskp->ref_temp = DISK_INVALID_TEMP;
			return (-1);
		}

		/*
		 * verify the checksum of the data. A 2's compliment
		 * of the result addition of the is stored in the
		 * last byte. The sum of all the checksum should be
		 * 0. If the checksum is bad, return an error for
		 * this iteration.
		 */
		index = (uint8_t *)&smartpage;

		for (i = checksum = 0; i < 512; i++)
			checksum += index[i];

		if ((checksum != 0) && env_debug) {
			envd_log(LOG_ERR,
			    "SMART checksum error! 0x%x\n", checksum);

			/*
			 * We got bad data back from the drive, fail this
			 * time around and picl will retry again. If this
			 * continues to fail picl will give this drive a
			 * failed status.
			 */
			diskp->current_temp = DISK_INVALID_TEMP;
			diskp->ref_temp = DISK_INVALID_TEMP;

			return (-1);
		}

		/*
		 * Scan through the various SMART data and look for
		 * the complete drive temp.
		 */

		for (i = 0; (i < SMART_FIELDS) &&
		    (smartpage.attribute[i].id != 0) &&
		    (temp_attrib == NULL); i++) {

			if (smartpage.attribute[i].id == HDA_TEMP) {
				temp_attrib = &smartpage.attribute[i];
			}
		}

		/*
		 * If we dont find any temp SMART attributes, this drive
		 * does not support this page, disable temp checking
		 * for this drive.
		 */
		if (temp_attrib == NULL) {

			/*
			 * If the checksum is valid, the temp. attributes are
			 * not supported, disable this drive from temp.
			 * checking.
			 */
			if (env_debug)
				envd_log(LOG_ERR,
				    "Temp ATTRIBUTE not supported\n");
			diskp->smart_supported = B_FALSE;
			diskp->tpage_supported = B_FALSE;
			diskp->current_temp = DISK_INVALID_TEMP;
			diskp->ref_temp = DISK_INVALID_TEMP;

			return (-1);
		}

		if (env_debug) {
			envd_log(LOG_ERR, "flags = 0x%x%x,curr = 0x%x,"
			    "data = 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
			    temp_attrib->flags[0], temp_attrib->flags[1],
			    temp_attrib->raw_data[0], temp_attrib->raw_data[1],
			    temp_attrib->raw_data[2], temp_attrib->raw_data[3],
			    temp_attrib->raw_data[4], temp_attrib->raw_data[5],
			    temp_attrib->raw_data[6], temp_attrib->raw_data[7]);
		}
		if (temp_attrib->raw_data[1] != 0xFF) {
			diskp->current_temp = temp_attrib->raw_data[2];
			diskp->ref_temp	= temp_attrib->raw_data[2];
		} else {
			diskp->ref_temp = DISK_INVALID_TEMP;
			diskp->current_temp = DISK_INVALID_TEMP;

			return (-1);
		}

	} else {
		ret = scsi_log_sense(diskp, TEMPERATURE_PAGE, tpage,
		    sizeof (tpage), 1);

		if (ret != 0) {
			diskp->current_temp = DISK_INVALID_TEMP;
			diskp->ref_temp = DISK_INVALID_TEMP;
			return (-1);
		}
		/*
		 * For the current temperature verify that the parameter
		 * length is 0x02 and the parameter code is 0x00
		 * Temperature value of 255(0xFF) is considered INVALID.
		 */
		if ((tpage[7] == 0x02) && (tpage[4] == 0x00) &&
		    (tpage[5] == 0x00)) {
			if (tpage[9] == 0xFF) {
				diskp->current_temp = DISK_INVALID_TEMP;
				return (-1);
			} else {
				diskp->current_temp = tpage[9];
			}
		}

		/*
		 * For the reference temperature verify that the parameter
		 * length is 0x02 and the parameter code is 0x01
		 * Temperature value of 255(0xFF) is considered INVALID.
		 */
		if ((tpage[13] == 0x02) && (tpage[10] == 0x00) &&
		    (tpage[11] == 0x01)) {
			if (tpage[15] == 0xFF) {
				diskp->ref_temp = DISK_INVALID_TEMP;
			} else {
				diskp->ref_temp = tpage[15];
			}
		}
	}
	return (0);
}

/* ARGSUSED */
static void *
disk_temp_thr(void *args)
{
	char syscmd[BUFSIZ];
	char msgbuf[BUFSIZ];
	timespec_t	to;
	int	ret, i;
	env_disk_t	*diskp;
	pthread_mutex_t	env_monitor_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t	env_monitor_cv = PTHREAD_COND_INITIALIZER;
	pm_state_change_t	pmstate;
	int	idle_time;
	int	disk_pm_fd;
	time_t	ct;

	if ((disk_pm_fd = open(PM_DEVICE, O_RDWR)) == -1) {
		envd_log(LOG_ERR, DISK_TEMP_THREAD_EXITING,
		    errno, strerror(errno));
		return (NULL);
	}

	for (;;) {
		/*
		 * Sleep for specified seconds before issuing IOCTL
		 * again.
		 */
		(void) pthread_mutex_lock(&env_monitor_mutex);
		ret = pthread_cond_reltimedwait_np(&env_monitor_cv,
		    &env_monitor_mutex, &to);

		to.tv_sec = disk_scan_interval;
		to.tv_nsec = 0;

		if (ret != ETIMEDOUT) {
			(void) pthread_mutex_unlock(
			    &env_monitor_mutex);
			continue;
		}
		(void) pthread_mutex_unlock(&env_monitor_mutex);

		for (i = 0; (diskp = envd_disks[i]) != NULL; i++) {
			if (diskp->present == B_FALSE)
				continue;
			if (diskp->tpage_supported == B_FALSE)
				continue;
		/*
		 * If the disk temperature is above the warning threshold
		 * continue monitoring until the temperature drops below
		 * warning threshold.
		 * if the temperature is in the NORMAL range monitor only
		 * when the disk is BUSY.
		 * We do not want to read the disk temperature if the disk is
		 * is idling. The reason for this is disk will never get into
		 * lowest power mode if we scan the disk temperature
		 * peridoically. To avoid this situation we first determine
		 * the idle_time of the disk. If the disk has been IDLE since
		 * we scanned the temperature last time we will not read the
		 * temperature.
		 */
		if (!DISK_TEMP_IN_WARNING_RANGE(diskp->current_temp, diskp)) {
			pmstate.physpath = diskp->physpath;
			pmstate.size = strlen(diskp->physpath);
			pmstate.component = 0;
			if ((idle_time =
			    ioctl(disk_pm_fd, PM_GET_TIME_IDLE,
			    &pmstate)) == -1) {

				if (errno != EINTR) {
					if (env_debug)
						envd_log(LOG_ERR,
			"ioctl PM_GET_TIME_IDLE failed for DISK0. errno=0x%x\n",
						    errno);
					continue;
				}
				continue;
			}
			if (idle_time >= (disk_scan_interval/2)) {
				if (env_debug) {
					envd_log(LOG_ERR, "%s idle time = %d\n",
					    diskp->name, idle_time);
				}
				continue;
			}
		}
		ret = get_disk_temp(diskp);
		if (ret != 0)
			continue;
		if (env_debug) {
			envd_log(LOG_ERR, "%s temp = %d ref. temp = %d\n",
			    diskp->name, diskp->current_temp, diskp->ref_temp);
		}
		/*
		 * If this disk already triggered system shutdown, don't
		 * log any more shutdown/warning messages for it.
		 */
		if (diskp->shutdown_initiated)
			continue;

		/*
		 * Check for the temperature in warning and shutdown range
		 * and take appropriate action.
		 */
		if (DISK_TEMP_IN_WARNING_RANGE(diskp->current_temp, diskp)) {
			/*
			 * Check if the temperature has been in warning
			 * range during last disk_warning_duration interval.
			 * If so, the temperature is truly in warning
			 * range and we need to log a warning message,
			 * but no more than once every disk_warning_interval
			 * seconds.
			 */
			time_t	wtstamp = diskp->warning_tstamp;

			ct = (time_t)(gethrtime() / NANOSEC);
			if (diskp->warning_start == 0)
				diskp->warning_start = ct;
			if (((ct - diskp->warning_start) >=
			    disk_warning_duration) && (wtstamp == 0 ||
			    (ct - wtstamp) >= disk_warning_interval)) {
				envd_log(LOG_CRIT, ENV_WARNING_MSG,
				    diskp->name, diskp->current_temp,
				    diskp->low_warning,
				    diskp->high_warning);
				diskp->warning_tstamp = ct;
			}
		} else if (diskp->warning_start != 0)
			diskp->warning_start = 0;

		if (!shutdown_override &&
		    DISK_TEMP_IN_SHUTDOWN_RANGE(diskp->current_temp, diskp)) {
			ct = (time_t)(gethrtime() / NANOSEC);
			if (diskp->shutdown_tstamp == 0)
				diskp->shutdown_tstamp = ct;

			/*
			 * Shutdown the system if the temperature remains
			 * in the shutdown range for over disk_shutdown_interval
			 * seconds.
			 */
			if ((ct - diskp->shutdown_tstamp) >=
			    disk_shutdown_interval) {
				/* log error */
				diskp->shutdown_initiated = B_TRUE;
				(void) snprintf(msgbuf, sizeof (msgbuf),
				    ENV_SHUTDOWN_MSG, diskp->name,
				    diskp->current_temp, diskp->low_shutdown,
				    diskp->high_shutdown);
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
		} else if (diskp->shutdown_tstamp != 0)
			diskp->shutdown_tstamp = 0;
		}
	} /* end of forever loop */
}

static void *
fan_thr(void *args)
{
	char msgbuf[BUFSIZ];
	timespec_t	to;
	int	ret, i;
	pthread_mutex_t	env_monitor_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t	env_monitor_cv = PTHREAD_COND_INITIALIZER;
	env_fan_t	*fanp;

#ifdef	__lint
	args = args;
#endif

	for (;;) {
		/*
		 * Sleep for specified seconds before issuing IOCTL
		 * again.
		 */
		(void) pthread_mutex_lock(&env_monitor_mutex);
		ret = pthread_cond_reltimedwait_np(&env_monitor_cv,
		    &env_monitor_mutex, &to);
		to.tv_sec = fan_scan_interval;
		to.tv_nsec = 0;
		if (ret != ETIMEDOUT) {
			(void) pthread_mutex_unlock(&env_monitor_mutex);
			continue;
		}
		(void) pthread_mutex_unlock(&env_monitor_mutex);

		for (i = 0; (fanp = envd_fans[i]) != NULL; i++) {
			if (fanp->present == B_FALSE)
				continue;

			if (has_fan_failed(fanp) == B_TRUE) {
				if (fanp->last_status == FAN_FAILED)
					continue;
				fanp->last_status = FAN_FAILED;
				(void) snprintf(msgbuf, sizeof (msgbuf),
				    ENV_FAN_FAILURE_WARNING_MSG, fanp->name,
				    fan_rpm_string, fan_status_string);
				envd_log(LOG_ALERT, msgbuf);
			} else {
				if (fanp->last_status == FAN_OK)
					continue;
				fanp->last_status = FAN_OK;
				(void) snprintf(msgbuf, sizeof (msgbuf),
				    ENV_FAN_OK_MSG, fanp->name);
				envd_log(LOG_ALERT, msgbuf);
			}
		}

		if (has_psufan_failed() == B_TRUE) {
			if (psufan_last_status == FAN_FAILED)
				continue;
			psufan_last_status = FAN_FAILED;
			(void) snprintf(msgbuf, sizeof (msgbuf),
			    ENV_FAN_FAILURE_WARNING_MSG, SENSOR_PSU,
			    fan_rpm_string, fan_status_string);
			envd_log(LOG_ALERT, msgbuf);
		} else {
			if (psufan_last_status == FAN_OK)
				continue;
			psufan_last_status = FAN_OK;
			(void) snprintf(msgbuf, sizeof (msgbuf),
			    ENV_FAN_OK_MSG, SENSOR_PSU);
			envd_log(LOG_ALERT, msgbuf);
		}
	}

	/*NOTREACHED*/
	return (NULL);
}

/*
 * Setup envrionmental monitor state and start threads to monitor
 * temperature, fan, disk and power management state.
 * Returns -1 on error, 0 if successful.
 */
static int
envd_setup(void)
{

	if (getenv("SUNW_piclenvd_debug") != NULL)
		env_debug = 1;

	if (pthread_attr_init(&thr_attr) != 0 ||
	    pthread_attr_setscope(&thr_attr, PTHREAD_SCOPE_SYSTEM) != 0) {
		return (-1);
	}

	/*
	 * If ES segment is not present or has inconsistent information, we
	 * use default values for sensor limits. For the sake of simplicity,
	 * we still store these limits internally in the 'es' member in the
	 * structure.
	 */
	if (envd_es_setup() < 0) {
		envd_log(LOG_WARNING, ENV_DEFAULT_LIMITS);
		envd_es_default_setup();
	}

	if (envd_setup_sensors() < 0) {
		if (env_debug)
			envd_log(LOG_ERR, "Failed to setup sensors\n");
		system_temp_monitor = 0;
	}

	if (envd_setup_fans() < 0) {
		if (env_debug)
			envd_log(LOG_ERR, "Failed to setup fans\n");
		fan_monitor = 0;
		pm_monitor = 0;
	}

	/*
	 * Disable disk temperature monitoring until we have
	 * LSI fw support to read SATA disk temperature
	 */
	if (disk_temp_monitor) {
		if (envd_setup_disks() < 0) {
			if (env_debug)
				envd_log(LOG_ERR, "Failed to setup disks\n");
			disk_temp_monitor = 0;
		}
	}

	/*
	 * Create a thread to monitor system temperatures
	 */
	if ((system_temp_monitor) && (system_temp_thr_created == B_FALSE)) {
		if (pthread_create(&system_temp_thr_id, &thr_attr,
		    system_temp_thr, NULL) != 0) {
			envd_log(LOG_ERR, ENVTHR_THREAD_CREATE_FAILED);
		} else {
			system_temp_thr_created = B_TRUE;
			if (env_debug)
				envd_log(LOG_ERR,
			"Created thread to monitor system temperatures\n");
		}
	}

	/*
	 * Create a thread to monitor fans
	 */
	if ((fan_monitor) && (fan_thr_created == B_FALSE)) {
		if (pthread_create(&fan_thr_id, &thr_attr, fan_thr, NULL) != 0)
			envd_log(LOG_ERR, ENVTHR_THREAD_CREATE_FAILED);
		else {
			fan_thr_created = B_TRUE;
			if (env_debug) {
				envd_log(LOG_ERR,
				    "Created thread to monitor system fans\n");
			}
		}
	}

	/*
	 * Create a thread to monitor PM state
	 */
	if ((pm_monitor) && (pmthr_created == B_FALSE)) {
		if (pthread_create(&pmthr_tid, &thr_attr, pmthr, NULL) != 0)
			envd_log(LOG_CRIT, PM_THREAD_CREATE_FAILED);
		else {
			pmthr_created = B_TRUE;
			if (env_debug)
				envd_log(LOG_ERR,
			"Created thread to monitor system power state\n");
		}
	}

	/*
	 * Create a thread to monitor disk temperature
	 */
	if ((disk_temp_monitor) && (disk_temp_thr_created == B_FALSE)) {
		if (pthread_create(&disk_temp_thr_id, &thr_attr,
		    disk_temp_thr, NULL) != 0) {
			envd_log(LOG_ERR, ENVTHR_THREAD_CREATE_FAILED);
		} else {
			disk_temp_thr_created = B_TRUE;
			if (env_debug)
				envd_log(LOG_ERR,
			"Created thread for disk temperatures\n");
		}
	}

	return (0);
}

static void
piclenvd_register(void)
{
	picld_plugin_register(&my_reg_info);
}

static void
piclenvd_init(void)
{

	(void) env_picl_setup_tuneables();

	/*
	 * Do not allow disk temperature monitoring to be enabled
	 * via tuneables. Disk temperature monitoring is disabled
	 * until we have LSI fw support to read the temperature of
	 * SATA disks
	 */
	disk_temp_monitor = 0;

	/*
	 * Setup the environmental data structures
	 */
	if (envd_setup() != 0) {
		envd_log(LOG_CRIT, ENVD_PLUGIN_INIT_FAILED);
		return;
	}

	/*
	 * Now setup/populate PICL tree
	 */
	env_picl_setup();
}

static void
piclenvd_fini(void)
{

	/*
	 * Invoke env_picl_destroy() to remove any PICL nodes/properties
	 * (including volatile properties) we created. Once this call
	 * returns, there can't be any more calls from the PICL framework
	 * to get current temperature or fan speed.
	 */
	env_picl_destroy();
	envd_close_sensors();
	envd_close_fans();
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

/*
 * Tunables support functions
 */
static env_tuneable_t *
tuneable_lookup(picl_prophdl_t proph)
{
	int i;
	env_tuneable_t	*tuneablep = NULL;

	for (i = 0; i < ntuneables; i++) {
		tuneablep = &tuneables[i];
		if (tuneablep->proph == proph)
			return (tuneablep);
	}

	return (NULL);
}

static int
get_string_val(ptree_rarg_t *parg, void *buf)
{
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;

	proph = parg->proph;

	tuneablep = tuneable_lookup(proph);

	if (tuneablep == NULL)
		return (PICL_FAILURE);

	(void) memcpy(buf, tuneablep->value, tuneablep->nbytes);

	return (PICL_SUCCESS);
}

static int
set_string_val(ptree_warg_t *parg, const void *buf)
{
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;

	if (parg->cred.dc_euid != 0)
		return (PICL_PERMDENIED);

	proph = parg->proph;

	tuneablep = tuneable_lookup(proph);

	if (tuneablep == NULL)
		return (PICL_FAILURE);

	(void) memcpy(tuneables->value, buf, tuneables->nbytes);


	return (PICL_SUCCESS);
}

static int
get_int_val(ptree_rarg_t *parg, void *buf)
{
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;

	proph = parg->proph;

	tuneablep = tuneable_lookup(proph);

	if (tuneablep == NULL)
		return (PICL_FAILURE);

	(void) memcpy(buf, tuneablep->value, tuneablep->nbytes);

	return (PICL_SUCCESS);
}

static int
set_int_val(ptree_warg_t *parg, const void *buf)
{
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;

	if (parg->cred.dc_euid != 0)
		return (PICL_PERMDENIED);

	proph = parg->proph;

	tuneablep = tuneable_lookup(proph);

	if (tuneablep == NULL)
		return (PICL_FAILURE);

	(void) memcpy(tuneablep->value, buf, tuneablep->nbytes);

	return (PICL_SUCCESS);
}

boolean_t
has_fan_failed(env_fan_t *fanp)
{
	fanspeed_t	fan_speed;
	uchar_t		status;
	uint8_t		tach;
	int		real_tach;
	int		ret, ntries;

	if (fanp->fd == -1)
		return (B_TRUE);

	/*
	 * Read RF_FAN_STATUS bit of the fan fault register, retry if
	 * the PIC is busy, with a 1 second delay to allow it to update.
	 */
	for (ntries = 0; ntries < MAX_RETRIES_FOR_FAN_FAULT; ntries++) {
		ret = ioctl(fanp->fd, PIC_GET_FAN_STATUS, &status);
		if ((ret == 0) && ((status & 0x1) == 0))
			break;
		(void) sleep(1);
	}

	if (ntries > 0) {
		if (env_debug) {
			envd_log(LOG_ERR,
			    "%d retries attempted in reading fan status.\n",
			    ntries);
		}
	}

	if (ntries == MAX_RETRIES_FOR_FAN_FAULT) {
		(void) strncpy(fan_status_string, NOT_AVAILABLE,
		    sizeof (fan_status_string));
		(void) strncpy(fan_rpm_string, NOT_AVAILABLE,
		    sizeof (fan_rpm_string));
		return (B_TRUE);
	}

	if (env_debug)
		envd_log(LOG_ERR, "fan status = 0x%x\n", status);

	/*
	 * ST_FFAULT bit isn't implemented yet and we're reading only
	 * individual fan status
	 */
	if (status & 0x1) {
		(void) snprintf(fan_status_string, sizeof (fan_status_string),
		    "0x%x", status);
		if (ioctl(fanp->fd, PIC_GET_FAN_SPEED, &tach) != 0) {
			(void) strncpy(fan_rpm_string, NOT_AVAILABLE,
			    sizeof (fan_rpm_string));
		} else {
			real_tach = tach << 8;
			fan_speed = TACH_TO_RPM(real_tach);
			(void) snprintf(fan_rpm_string, sizeof (fan_rpm_string),
			    "%d", fan_speed);
		}
		return (B_TRUE);
	}

	return (B_FALSE);
}

boolean_t
has_psufan_failed(void)
{
	uchar_t		status;
	int		ret, ntries;

	if (envd_sensor_psu.fd == -1)
		return (B_FALSE);

	/*
	 * For psu, only fan fault is visible, no fan speed
	 */
	(void) strncpy(fan_rpm_string, NOT_AVAILABLE, sizeof (fan_rpm_string));

	/*
	 * Read RF_FAN_STATUS bit of the fan fault register, retry if
	 * the PIC is busy, with a 1 second delay to allow it to update.
	 */
	for (ntries = 0; ntries < MAX_RETRIES_FOR_FAN_FAULT; ntries++) {
		ret = ioctl(envd_sensor_psu.fd, PIC_GET_FAN_STATUS, &status);
		if ((ret == 0) && ((status & 0x1) == 0))
			break;
		(void) sleep(1);
	}

	if (ntries > 0) {
		if (env_debug) {
			envd_log(LOG_ERR,
			    "%d retries attempted in reading fan status.\n",
			    ntries);
		}
	}

	if (ntries == MAX_RETRIES_FOR_FAN_FAULT) {
		(void) strncpy(fan_status_string, NOT_AVAILABLE,
		    sizeof (fan_status_string));
		return (B_TRUE);
	}

	if (env_debug)
		envd_log(LOG_ERR, "fan status = 0x%x\n", status);

	if (status & 0x1) {
		(void) snprintf(fan_status_string, sizeof (fan_status_string),
		    "0x%x", status);
		return (B_TRUE);
	}

	return (B_FALSE);
}

static int
scsi_mode_select(env_disk_t *diskp, uchar_t page_code, uchar_t *pagebuf,
    uint16_t pagelen)
{
	struct uscsi_cmd		ucmd_buf;
	uchar_t				cdb_buf[CDB_GROUP1];
	struct scsi_extended_sense	sense_buf;
	int				ret_val;

	bzero(&cdb_buf, sizeof (cdb_buf));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(&sense_buf, sizeof (sense_buf));

	cdb_buf[0] = SCMD_MODE_SELECT_G1;
	cdb_buf[1] = 1<<PAGE_FMT;

	cdb_buf[7] = (uchar_t)((pagelen & 0xFF00) >> 8);
	cdb_buf[8] = (uchar_t)(pagelen  & 0x00FF);

	ucmd_buf.uscsi_cdb = (char *)cdb_buf;
	ucmd_buf.uscsi_cdblen = sizeof (cdb_buf);
	ucmd_buf.uscsi_bufaddr = (caddr_t)pagebuf;
	ucmd_buf.uscsi_buflen = pagelen;
	ucmd_buf.uscsi_rqbuf = (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen = sizeof (struct scsi_extended_sense);
	ucmd_buf.uscsi_flags = USCSI_RQENABLE | USCSI_WRITE | USCSI_SILENT;
	ucmd_buf.uscsi_timeout = DEFAULT_SCSI_TIMEOUT;

	ret_val = ioctl(diskp->fd, USCSICMD, ucmd_buf);

	if (ret_val == 0 && ucmd_buf.uscsi_status == 0) {
		return (ret_val);
	}
	if (env_debug)
		envd_log(LOG_ERR, "mode select command for %s failed. "
		    "page_code 0x%x ret_val = 0x%x "
		    "status = 0x%x errno = 0x%x\n", diskp->name, page_code,
		    ret_val, ucmd_buf.uscsi_status, errno);

	return (1);

}
