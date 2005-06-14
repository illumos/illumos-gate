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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the environmental daemon module.
 */


/*
 * Grover system contains one temperature device, MAX1617, which consists
 * of two sensors: CPU die and CPU ambient. Each sensor is represented
 * as a different minor device and the current temperature is read via an
 * I2C_GET_TEMPERATURE ioctl call to the max1617 driver. Additionally, the
 * MAX1617 device supports both a low and high temperature limit, which
 * can trigger an alert condition, causing power supply to turn off.
 *
 * The environmental daemon defines the following thresholds per sensor:
 *
 *	high_power_off		high hard shutdown
 *	high_shutdown		high soft shutdown limit
 *	high_warning		high warning limit
 *	low_warning		low warning limit
 *	low_shutdown		low soft shutdown limit
 *	low_power_off		low hard shutdown limit
 *
 * Except for the low_power_off and high_power_off limits, all other threshold
 * values can be changed via "piclenvd.conf" configuration file.
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
 * Grover system also contains a fan, known as system fan, which can be turned
 * ON or OFF under software control. However, its speed is automatically
 * controlled by the hardware based upon the ambient temperature. When in EStar
 * mode (i.e. lowest power state), the environmental daemon will turn off this
 * fan provided the CPU die and ambient temperature is below the high warning
 * limits.
 *
 * The power state monitoring is done by the "pmthr" thread. It uses the
 * PM_GET_STATE_CHANGE and PM_GET_STATE_CHANGE_WAIT ioctl commands to pick
 * up any power state change events. It processes all queued power state
 * change events and determines the curret lowest power state and saves it
 * in cur_lpstate variable. Whenever this state changes from the previous
 * lowest power state (saved in prev_lpstate), it wakes up the "envtrh"
 * thread.
 *
 * The "lpstate_lock" mutex and "lpstate_cond" condition variables are used
 * to communicate power state change events from the "pmthr" to the "envthr"
 * thread.  The "envthr" thread uses the pthread_cond_timedwait() interface
 * to wait for any power state change notifications. The "pmthr" uses the
 * pthread_signal() interface to wake up the "envthr" thread.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <picl.h>
#include <picltree.h>
#include <pthread.h>
#include <sys/pm.h>
#include <sys/open.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/i2c/clients/max1617.h>
#include <sys/i2c/clients/i2c_client.h>
#include "envd.h"


/*
 * PICL plguin
 */
static void piclenvd_register(void);
static void piclenvd_init(void);
static void piclenvd_fini(void);
extern void env_picl_setup();

#pragma	init(piclenvd_register)

static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_CRITICAL,
	"SUNW_piclenvd",
	piclenvd_init,
	piclenvd_fini,
};

/*
 * tuneable variables
 */
int		env_debug;
static int	sensor_poll_interval = SENSOR_POLL_INTERVAL;
static int	warning_interval = WARNING_INTERVAL;
static int	shutdown_interval = SHUTDOWN_INTERVAL;
static char	shutdown_cmd[128] = SHUTDOWN_CMD;
static int	monitor_temperature = 0;

static sensor_thresh_t cpu_die_thresh = {
	CPU_DIE_LOW_POWER_OFF, CPU_DIE_HIGH_POWER_OFF,
	CPU_DIE_LOW_SHUTDOWN, CPU_DIE_HIGH_SHUTDOWN,
	CPU_DIE_LOW_WARNING, CPU_DIE_HIGH_WARNING,
	CPU_DIE_TARGET_TEMP
};

static sensor_thresh_t cpu_amb_thresh = {
	CPU_AMB_LOW_POWER_OFF, CPU_AMB_HIGH_POWER_OFF,
	CPU_AMB_LOW_SHUTDOWN, CPU_AMB_HIGH_SHUTDOWN,
	CPU_AMB_LOW_WARNING, CPU_AMB_HIGH_WARNING,
	CPU_AMB_TARGET_TEMP
};

/*
 * Temperature sensors
 */

static env_sensor_t cpu_die_sensor =
	{ SENSOR_CPU_DIE, CPU_DIE_SENSOR_DEVFS, &cpu_die_thresh};

static env_sensor_t cpu_amb_sensor =
	{ SENSOR_CPU_AMB, CPU_AMB_SENSOR_DEVFS, &cpu_amb_thresh};


static env_sensor_t *envd_sensors[] = {
	&cpu_die_sensor,
	&cpu_amb_sensor,
	NULL
};

/*
 * Fan devices
 */
static env_fan_t envd_system_fan = {
	ENV_SYSTEM_FAN, ENV_SYSTEM_FAN_DEVFS,
	SYSTEM_FAN_SPEED_MIN, SYSTEM_FAN_SPEED_MAX,
};

static env_fan_t *envd_fans[] =  {
	&envd_system_fan,
	NULL
};


/*
 * Environmental thread variables
 */
static boolean_t	envd_inited = B_FALSE;
static boolean_t	system_shutdown_started;
static boolean_t	envthr_created;		/* envthr created */
static pthread_t	envthr_tid;		/* envthr thread ID */
static pthread_attr_t	thr_attr;

/*
 * Power management thread (pmthr) variables
 */
static pthread_t	pmthr_tid;		/* pmthr thread ID */
static int		pmthr_created;		/* pmthr created */
static int		pm_fd;			/* PM device file descriptor */
static int		cur_lpstate;		/* cur low power state */

static pthread_mutex_t	lpstate_lock;		/* low power state lock */
static pthread_cond_t	lpstate_cond;		/* low power state condvar */


/*
 * Tuneable variables data structure/array
 */

typedef struct {
	char	*name;		/* keyword */
	void	*addr;		/* memory (variable) address */
	int	type;		/* keyword type */
	int	size;		/* variable size */
} env_tuneable_t;

/* keyword types */
#define	KTYPE_INT	1	/* signed int */
#define	KTYPE_STRING	2	/* string in double quotes */

static env_tuneable_t env_tuneables[] = {
	{"cpu_amb_low_shutdown", &cpu_amb_thresh.low_shutdown, KTYPE_INT,
	    sizeof (tempr_t)},
	{"cpu_amb_low_warning", &cpu_amb_thresh.low_warning, KTYPE_INT,
	    sizeof (tempr_t)},
	{"cpu_amb_target_temp", &cpu_amb_thresh.target_temp, KTYPE_INT,
	    sizeof (tempr_t)},
	{"cpu_amb_high_shutdown", &cpu_amb_thresh.high_shutdown, KTYPE_INT,
	    sizeof (tempr_t)},
	{"cpu_amb_high_warning", &cpu_amb_thresh.high_warning, KTYPE_INT,
	    sizeof (tempr_t)},
	{"cpu_die_low_shutdown", &cpu_die_thresh.low_shutdown, KTYPE_INT,
	    sizeof (tempr_t)},
	{"cpu_die_low_warning", &cpu_die_thresh.low_warning, KTYPE_INT,
	    sizeof (tempr_t)},
	{"cpu_die_target_temp", &cpu_die_thresh.target_temp, KTYPE_INT,
	    sizeof (tempr_t)},
	{"cpu_die_high_shutdown", &cpu_die_thresh.high_shutdown, KTYPE_INT,
	    sizeof (tempr_t)},
	{"cpu_die_high_warning", &cpu_die_thresh.high_warning, KTYPE_INT,
	    sizeof (tempr_t)},
	{"sensor_poll_interval", &sensor_poll_interval, KTYPE_INT,
	    sizeof (sensor_poll_interval)},
	{"monitor_temperature", &monitor_temperature, KTYPE_INT,
	    sizeof (monitor_temperature)},
	{"warning_interval", &warning_interval, KTYPE_INT,
	    sizeof (warning_interval)},
	{"shutdown_interval", &shutdown_interval, KTYPE_INT,
	    sizeof (shutdown_interval)},
	{"shutdown_cmd", &shutdown_cmd[0], KTYPE_STRING, sizeof (shutdown_cmd)},
	{"env_debug", &env_debug, KTYPE_INT, sizeof (env_debug)},
	{ NULL, NULL, 0, 0}
};

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
	int		i;
	env_sensor_t	*sensorp;

	for (i = 0; (sensorp = envd_sensors[i]) != NULL; i++) {
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
	int		i;
	env_sensor_t	*sensorp;

	for (i = 0; (sensorp = envd_sensors[i]) != NULL; i++) {
		if (sensorp->fd != -1) {
			(void) close(sensorp->fd);
			sensorp->fd = -1;
		}
	}
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
	char		path[FILENAME_MAX];
	int		fancnt = 0;

	for (i = 0; (fanp = envd_fans[i]) != NULL; i++) {
		fanp->fd = -1;
		fanp->cur_speed = 0;
		fanp->prev_speed = 0;

		(void) strcpy(path, "/devices");
		(void) strlcat(path, fanp->devfs_path, sizeof (path));
		fd = open(path, O_RDWR);
		if (fd == -1) {
			envd_log(LOG_WARNING, ENV_FAN_OPEN_FAIL, fanp->name,
			    fanp->devfs_path, errno, strerror(errno));
			fanp->present = B_FALSE;
			continue;
		}
		fanp->fd = fd;
		fanp->present = B_TRUE;
		fancnt++;

		/*
		 * Set cur_speed/prev_speed to current fan speed
		 */
		if (get_fan_speed(fanp, &speed) == -1) {
			/*
			 * The Fan driver does not know the current fan speed.
			 * Initialize it to 50% of the max speed and reread
			 * to get the current speed.
			 */
			speed = fanp->speed_max/2;
			(void) set_fan_speed(fanp, speed);
			if (get_fan_speed(fanp, &speed) == -1)
				continue;
		}
		fanp->cur_speed = speed;
		fanp->prev_speed = speed;
	}
	return (fancnt);
}

/*
 * Open temperature sensor devices and initialize per sensor data structure.
 * Returns #sensors found.
 */
static int
envd_setup_sensors(void)
{
	int		i;
	tempr_t		temp;
	env_sensor_t	*sensorp;
	char		path[FILENAME_MAX];
	int		sensorcnt = 0;
	sensor_thresh_t	*threshp;

	for (i = 0; (sensorp = envd_sensors[i]) != NULL; i++) {
		sensorp->fd = -1;
		sensorp->shutdown_initiated = B_FALSE;
		sensorp->warning_tstamp = 0;
		sensorp->shutdown_tstamp = 0;
		threshp = sensorp->temp_thresh;
		sensorp->cur_temp = threshp->target_temp;
		sensorp->error = 0;

		(void) strcpy(path, "/devices");
		(void) strlcat(path, sensorp->devfs_path, sizeof (path));
		sensorp->fd = open(path, O_RDWR);
		if (sensorp->fd == -1) {
			envd_log(LOG_WARNING, ENV_SENSOR_OPEN_FAIL,
			    sensorp->name, sensorp->devfs_path, errno,
			    strerror(errno));
			sensorp->present = B_FALSE;
			continue;
		}
		sensorp->present = B_TRUE;
		sensorcnt++;

		if (monitor_temperature) {
			/*
			 * Set low_power_off and high_power_off limits
			 */
			(void) ioctl(sensorp->fd, MAX1617_SET_LOW_LIMIT,
			    &threshp->low_power_off);
			(void) ioctl(sensorp->fd, MAX1617_SET_HIGH_LIMIT,
			    &threshp->high_power_off);
		}

		/*
		 * Set cur_temp field to the current temperature value
		 */
		if (get_temperature(sensorp, &temp) == 0) {
			sensorp->cur_temp = temp;
		}
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
	int		i;
	env_sensor_t	*sensorp;
	sensor_thresh_t	*threshp;
	struct timeval	ct;
	char		msgbuf[BUFSIZ];
	char		syscmd[BUFSIZ];

	for (i = 0; (sensorp = envd_sensors[i]) != NULL; i++) {
		if (get_temperature(sensorp, &temp) < 0)
			continue;

		sensorp->cur_temp = temp;

		if (env_debug)
			envd_log(LOG_INFO,
			    "sensor: %-13s temp  cur:%3d  target:%3d\n",
			    sensorp->name, temp,
			    sensorp->temp_thresh->target_temp);

		if (!monitor_temperature)
			continue;

		/*
		 * If this sensor already triggered system shutdown, don't
		 * log any more shutdown/warning messages for it.
		 */
		if (sensorp->shutdown_initiated)
			continue;

		/*
		 * Check for the temperature in warning and shutdown range
		 * and take appropriate action.
		 */
		threshp = sensorp->temp_thresh;
		if (TEMP_IN_WARNING_RANGE(temp, threshp)) {
			/*
			 * Log warning message at most once every
			 * warning_interval seconds.
			 */
			(void) gettimeofday(&ct, NULL);
			if ((ct.tv_sec - sensorp->warning_tstamp) >=
			    warning_interval) {
				envd_log(LOG_WARNING, ENV_WARNING_MSG,
				    sensorp->name, temp,
				    threshp->low_warning,
				    threshp->high_warning);
				sensorp->warning_tstamp = ct.tv_sec;
			}
		}

		if (TEMP_IN_SHUTDOWN_RANGE(temp, threshp)) {
			(void) gettimeofday(&ct, NULL);
			if (sensorp->shutdown_tstamp == 0)
				sensorp->shutdown_tstamp = ct.tv_sec;

			/*
			 * Shutdown the system if the temperature remains
			 * in the shutdown range for over shutdown_interval
			 * seconds.
			 */
			if ((ct.tv_sec - sensorp->shutdown_tstamp) >=
			    shutdown_interval) {
				/* log error */
				sensorp->shutdown_initiated = B_TRUE;
				(void) snprintf(msgbuf, sizeof (msgbuf),
				    ENV_SHUTDOWN_MSG, sensorp->name,
				    temp, threshp->low_shutdown,
				    threshp->high_shutdown);
				envd_log(LOG_CRIT, msgbuf);

				/* shutdown the system (only once) */
				if (system_shutdown_started == B_FALSE) {
					(void) snprintf(syscmd, sizeof (syscmd),
					    "%s \"%s\"", shutdown_cmd, msgbuf);
					envd_log(LOG_CRIT, syscmd);
					system_shutdown_started = B_TRUE;
					(void) system(syscmd);
				}
			}
		} else if (sensorp->shutdown_tstamp != 0)
			sensorp->shutdown_tstamp = 0;
	}
}


/*
 * This is the environment thread, which monitors the current temperature
 * and power managed state and controls system fan speed.  Temperature is
 * polled every sensor-poll_interval seconds duration.
 */
static void *
envthr(void *args)
{
	int		err;
	fanspeed_t 	fan_speed;
	struct timeval	ct;
	struct timespec	to;
	env_fan_t	*pmfanp = &envd_system_fan;
	tempr_t		cpu_amb_temp, cpu_die_temp;
	tempr_t		cpu_amb_warning, cpu_die_warning;

	(void) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	(void) pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	cpu_amb_warning = cpu_amb_sensor.temp_thresh->high_warning;
	cpu_die_warning = cpu_die_sensor.temp_thresh->high_warning;

	for (;;) {
		(void) gettimeofday(&ct, NULL);

		/*
		 * Monitor current temperature for all sensors
		 * (current temperature is recorded in the "cur_temp"
		 * field within each sensor data structure)
		 */
		monitor_sensors();

		cpu_amb_temp =  cpu_amb_sensor.cur_temp;
		cpu_die_temp =  cpu_die_sensor.cur_temp;

		/*
		 * Process any PM state change events while waiting until
		 * time to poll sensors again (i.e. sensor_poll_interval
		 * seconds from the last time).
		 */
		to.tv_sec = ct.tv_sec + sensor_poll_interval;
		to.tv_nsec = 0;
		for (;;) {
			/*
			 * Turn off system fan if in lowest power state
			 * and both CPU die and ambient temperatures are
			 * below corresponding high warning temperatures.
			 */
			fan_speed = pmfanp->speed_max;
			if (cur_lpstate && cpu_amb_temp < cpu_amb_warning &&
			    cpu_die_temp < cpu_die_warning)
				fan_speed = pmfanp->speed_min;

			if (env_debug)
				envd_log(LOG_INFO,
				    "fan: %-16s speed cur:%3d  new:%3d "
				    "low-power:%d\n", pmfanp->name,
				    (uint_t)pmfanp->cur_speed,
				    (uint_t)fan_speed, cur_lpstate);

			if (fan_speed != pmfanp->cur_speed &&
			    set_fan_speed(pmfanp, fan_speed) == 0)
				pmfanp->cur_speed = fan_speed;

			/* wait for power state change or time to poll */
			pthread_mutex_lock(&lpstate_lock);
			err = pthread_cond_timedwait(&lpstate_cond,
			    &lpstate_lock, &to);
			pthread_mutex_unlock(&lpstate_lock);
			if (err == ETIMEDOUT)
				break;
		}
	}
	/*NOTREACHED*/
	return (NULL);
}

/*
 * This is the power management thread, which monitors all power state
 * change events and wakes up the "envthr" thread when the system enters
 * or exits the lowest power state.
 */
static void *
pmthr(void *args)
{
	pm_state_change_t	pmstate;
	char			physpath[PATH_MAX];
	int			prev_lpstate;

	(void) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	(void) pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	pmstate.physpath = physpath;
	pmstate.size = sizeof (physpath);
	cur_lpstate = 0;
	prev_lpstate = 0;

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

		if (cur_lpstate != prev_lpstate) {
			prev_lpstate = cur_lpstate;
			pthread_mutex_lock(&lpstate_lock);
			pthread_cond_signal(&lpstate_cond);
			pthread_mutex_unlock(&lpstate_lock);
		}
	}

	/*
	 * We won't be able to monitor lowest power state any longer,
	 * hence reset it and wakeup the "envthr".
	 */
	if (cur_lpstate != 0) {
		prev_lpstate = cur_lpstate;
		cur_lpstate = 0;
		pthread_mutex_lock(&lpstate_lock);
		pthread_cond_signal(&lpstate_cond);
		pthread_mutex_unlock(&lpstate_lock);
	}
	envd_log(LOG_ERR, PM_THREAD_EXITING, errno, strerror(errno));
	return (NULL);
}


/*
 * Parse string value (handling escaped double quotes and other characters)
 * and return string end pointer.
 */

static char *
parse_string_val(char *buf)
{
	char	*p, c;

	if (buf[0] != '"')
		return (NULL);

	for (p = buf+1; (c = *p) != '\0'; p++)
		if (c == '"' || (c == '\\' && *++p == '\0'))
			break;

	return ((*p == '"') ? p : NULL);
}


/*
 * Process configuration file
 */
static void
process_env_conf_file(void)
{
	int		line, len, val, toklen;
	char		buf[BUFSIZ];
	FILE		*fp;
	env_tuneable_t	*tunep;
	char		nmbuf[SYS_NMLN];
	char		fname[PATH_MAX];
	char		*tok, *valuep, *strend;
	char		tokdel[] = " \t\n\r";
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
			if (strcmp(tunep->name, tok) != 0)
				continue;

			switch (tunep->type) {
			case KTYPE_INT:
				errno = 0;
				val = strtol(valuep, &valuep, 0);

				/* Check for invalid value or extra tokens */
				if (errno != 0 || strtok(valuep, tokdel)) {
					envd_log(LOG_INFO,
					    ENV_CONF_INT_EXPECTED,
					    fname, line, tok);
					break;
				}

				/* Update only if value within range */
				if (tunep->size == sizeof (int8_t) &&
				    val == (int8_t)val)
					*(int8_t *)tunep->addr = (int8_t)val;
				else if (tunep->size == sizeof (short) &&
				    val == (short)val)
					*(short *)tunep->addr = (short)val;
				else if (tunep->size == sizeof (int))
					*(int *)tunep->addr = (int)val;
				else {
					envd_log(LOG_INFO,
					    ENV_CONF_INT_EXPECTED,
					    fname, line, tok);
					break;
				}
				if (env_debug)
					envd_log(LOG_INFO, "SUNW_piclenvd: "
					    "file:%s line:%d %s = %d\n",
					    fname, line, tok, val);
				break;

			case KTYPE_STRING:
				/*
				 * String value must be within double quotes.
				 * Skip over initial white spaces before
				 * looking for value.
				 */
				valuep += strspn(valuep, tokdel);
				strend = parse_string_val(valuep);

				if (strend == NULL || *valuep != '"' ||
				    strtok(strend+1, tokdel) != NULL ||
				    (strend-valuep) > tunep->size) {
					envd_log(LOG_INFO,
					    ENV_CONF_STRING_EXPECTED,
					    fname, line, tok,
					    tunep->size);
					break;
				}
				*strend = '\0';
				if (env_debug)
					envd_log(LOG_INFO, "piclenvd: file:%s"
					    " line:%d %s = \"%s\"\n",
					    fname, line, tok, valuep+1);
				(void) strcpy(tunep->addr, (caddr_t)valuep+1);
				break;

			default:
				envd_log(LOG_INFO,
				    ENV_CONF_UNSUPPORTED_TYPE,
				    fname, line,
				    tunep->type, tunep->name);
			}
			break;
		}

		if (tunep->name == NULL)
			envd_log(LOG_INFO, ENV_CONF_UNSUPPORTED_KEYWORD,
			    fname, line, tok);
	}
	(void) fclose(fp);
}

/*
 * Setup envrionmental daemon state and start threads to monitor
 * temperature and power management state.
 * Returns -1 on error, 0 if successful.
 */

static int
envd_setup(void)
{
	if (envd_inited == B_FALSE) {
		/*
		 * Initialize global state
		 */
		system_shutdown_started = B_FALSE;
		envthr_created = B_FALSE;
		pmthr_created = B_FALSE;

		if (pthread_attr_init(&thr_attr) != 0 ||
		    pthread_attr_setscope(&thr_attr, PTHREAD_SCOPE_SYSTEM) != 0)
			return (-1);

		if (pthread_mutex_init(&lpstate_lock, NULL) != 0 ||
		    pthread_cond_init(&lpstate_cond, NULL) != 0)
			return (-1);

		/*
		 * Process tuneable parameters
		 */
		process_env_conf_file();

		/*
		 * Setup temperature sensors and fail if we can't open
		 * at least one sensor.
		 */
		if (envd_setup_sensors() <= 0)
			return (-1);

		/*
		 * Setup fan device (don't fail even if we can't access
		 * the fan as we can still monitor temeperature.
		 */
		(void) envd_setup_fans();

		/*
		 * Create a thread to monitor temperature and control fan
		 * speed.
		 */
		if (envthr_created == B_FALSE && pthread_create(&envthr_tid,
		    &thr_attr, envthr, (void *)NULL) != 0) {
			envd_close_fans();
			envd_close_sensors();
			envd_log(LOG_CRIT, ENV_THREAD_CREATE_FAILED);
			return (-1);
		}
		envthr_created = B_TRUE;
	}
	envd_inited = B_TRUE;

	/*
	 * Create a thread to monitor PM state
	 */
	if (pmthr_created == B_FALSE) {
		pm_fd = open(PM_DEVICE, O_RDONLY);
		if (pm_fd == -1 || pthread_create(&pmthr_tid, &thr_attr,
		    pmthr, (void *)NULL) != 0) {
			envd_close_pm();
			envd_log(LOG_CRIT, PM_THREAD_CREATE_FAILED);
		} else
			pmthr_created = B_TRUE;
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
	/*
	 * Start environmental daemon/threads
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
	void	*exitval;

	/*
	 * Kill both "envthr" and "pmthr" threads.
	 */
	if (envthr_created) {
		(void) pthread_cancel(envthr_tid);
		(void) pthread_join(envthr_tid, &exitval);
		envthr_created = B_FALSE;
	}

	if (pmthr_created) {
		(void) pthread_cancel(pmthr_tid);
		(void) pthread_join(pmthr_tid, &exitval);
		pmthr_created = B_FALSE;
	}

	/*
	 * close all sensors, fans and the power management device
	 */
	envd_close_pm();
	envd_close_fans();
	envd_close_sensors();
	envd_inited = B_FALSE;
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
