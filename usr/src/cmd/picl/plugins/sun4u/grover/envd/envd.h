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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ENVD_H
#define	_ENVD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <libintl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SENSOR_POLL_INTERVAL 	4			/* in seconds */
#define	WARNING_INTERVAL	30			/* in seconds */
#define	SHUTDOWN_INTERVAL	20			/* in seconds */
#define	ENV_CONF_FILE		"piclenvd.conf"
#define	ENVMODEL_CONF_FILE	"envmodel.conf"
#define	PM_DEVICE		"/dev/pm"
#define	SHUTDOWN_CMD		"/usr/sbin/shutdown -y -g 60 -i 5"

/*
 * devfs-path for various fans and their min/max speeds
 */
#define	ENV_CPU_FAN_DEVFS	\
	"/pci@1f,0/pmu@3/fan-control@0,c8:cpu_fan"
#define	ENV_SYSTEM_FAN_DEVFS	\
	"/pci@1f,0/pmu@3/fan-control@0,c8:sys_fan"

#define	SYSTEM_FAN_SPEED_MIN	0
#define	SYSTEM_FAN_SPEED_MAX	100


/*
 * devfs-path for various temperature sensors and CPU platform path
 */
#define	CPU_DIE_SENSOR_DEVFS	\
	"/pci@1f,0/pmu@3/i2c@0,0/temperature@30:die_temp"
#define	CPU_AMB_SENSOR_DEVFS	\
	"/pci@1f,0/pmu@3/i2c@0,0/temperature@30:amb_temp"

/*
 * Temperature thresholds structure
 */
typedef int16_t tempr_t;

typedef struct {
	tempr_t	low_power_off;		/* low power-off temperature */
	tempr_t	high_power_off;		/* high power-off temperature */
	tempr_t	low_shutdown;		/* low shutdown temperature */
	tempr_t	high_shutdown;		/* high shutdown temperature */
	tempr_t	low_warning;		/* low warning temperature */
	tempr_t	high_warning;		/* high warning temperature */
	tempr_t	target_temp;		/* target temperature */
} sensor_thresh_t;

#define	TEMP_IN_SHUTDOWN_RANGE(val, threshp)	\
	((val) > (threshp)->high_shutdown || (val) < (threshp)->low_shutdown)

#define	TEMP_IN_WARNING_RANGE(val, threshp)	\
	((val) > (threshp)->high_warning || (val) < (threshp)->low_warning)


/*
 * CPU "die" temperature thresholds
 */
#define	CPU_DIE_HIGH_POWER_OFF	125
#define	CPU_DIE_HIGH_SHUTDOWN	90
#define	CPU_DIE_HIGH_WARNING	85
#define	CPU_DIE_TARGET_TEMP	80
#define	CPU_DIE_LOW_WARNING	0
#define	CPU_DIE_LOW_SHUTDOWN	-10
#define	CPU_DIE_LOW_POWER_OFF	-20

/*
 * CPU ambient temperature thresholds
 */
#define	CPU_AMB_HIGH_POWER_OFF	70
#define	CPU_AMB_HIGH_SHUTDOWN	60
#define	CPU_AMB_HIGH_WARNING	40
#define	CPU_AMB_TARGET_TEMP	32
#define	CPU_AMB_LOW_WARNING	0
#define	CPU_AMB_LOW_SHUTDOWN	-10
#define	CPU_AMB_LOW_POWER_OFF	-20


/*
 * Fan names
 */
#define	ENV_SYSTEM_FAN		"system"

/*
 * Sensor names
 */
#define	SENSOR_CPU_DIE		"cpu"
#define	SENSOR_CPU_AMB		"cpu-ambient"

/*
 * Temperature sensor related data structure
 */
typedef struct env_sensor {
	char		*name;			/* sensor name */
	char		*devfs_path;		/* sensor device devfs path */
	sensor_thresh_t	*temp_thresh;		/* sensor temp threshold */
	int		fd;			/* device file descriptor */
	int		error;			/* error flag */
	boolean_t 	present;		/* sensor present */
	tempr_t		cur_temp;		/* current temperature */
	time_t		warning_tstamp;		/* last warning time in secs */
	time_t		shutdown_tstamp;	/* shutdown temp time (secs) */
	boolean_t 	shutdown_initiated;	/* shutdown initated */
} env_sensor_t;

extern	env_sensor_t *sensor_lookup(char *sensor_name);
extern	int get_temperature(env_sensor_t *, tempr_t *);

/*
 * Fan information data structure
 */
typedef uint8_t fanspeed_t;

typedef struct env_fan {
	char		*name;			/* fan name */
	char		*devfs_path;		/* fan device devfs path */
	fanspeed_t	speed_min;		/* minimum speed */
	fanspeed_t	speed_max;		/* maximum speed */
	int		fd;			/* device file descriptor */
	boolean_t	present;		/* fan present */
	fanspeed_t	cur_speed;		/* current fan speed */
	fanspeed_t	prev_speed;		/* previous fan speed */
} env_fan_t;


extern	env_fan_t *fan_lookup(char *fan_name);
extern	int get_fan_speed(env_fan_t *, fanspeed_t *);

extern int env_debug;
extern void envd_log(int pri, const char *fmt, ...);

/*
 * Various messages
 */
#define	ENVD_PLUGIN_INIT_FAILED		\
	gettext("SUNW_piclenvd: initialization failed!\n")

#define	ENVD_PICL_SETUP_FAILED		\
	gettext("SUNW_piclenvd: PICL setup failed!\n")

#define	PM_THREAD_CREATE_FAILED		\
	gettext("SUNW_piclenvd: pmthr thread creation failed!\n")

#define	PM_THREAD_EXITING		\
	gettext("SUNW_piclenvd: pmthr exiting! errno:%d %s\n")

#define	ENV_THREAD_CREATE_FAILED	\
	gettext("SUNW_piclenvd: envthr thread creation failed!\n")

#define	ENV_SHUTDOWN_MSG		\
	gettext("SUNW_piclenvd: '%s' sensor temperature %d outside safe " \
	"limits (%d...%d). Shutting down the system.\n")

#define	ENV_WARNING_MSG			\
	gettext("SUNW_piclenvd: '%s' sensor temperature %d outside safe " \
	"operating limits (%d...%d).\n")

#define	ENV_FAN_OPEN_FAIL		\
	gettext("SUNW_piclenvd: can't open '%s' fan path:%s errno:%d %s\n")

#define	ENV_SENSOR_OPEN_FAIL		\
	gettext("SUNW_piclenvd: can't open '%s' sensor path:%s errno:%d %s\n")

#define	ENV_SENSOR_ACCESS_FAIL		\
	gettext("SUNW_piclenvd: can't access '%s' sensor errno:%d %s\n")

#define	ENV_SENSOR_ACCESS_OK		\
	gettext("SUNW_piclenvd: '%s' sensor is accessible now.\n")

#define	ENV_CONF_INT_EXPECTED		\
	gettext("SUNW_piclenvd: file:%s line:%d Invalid syntax or integer " \
	"value outside range for keyword '%s'.\n")

#define	ENV_CONF_STRING_EXPECTED	\
	gettext("SUNW_piclenvd: file:%s line:%d Invalid syntax for keyword " \
	"'%s'. Expecting string in double quotes (length < %d).\n")

#define	ENV_CONF_UNSUPPORTED_TYPE	\
	gettext("SUNW_piclenvd: file:%s line:%d Unsupported type:%d for " \
	"keyword '%s'.\n")

#define	ENV_CONF_UNSUPPORTED_KEYWORD	\
	gettext("SUNW_piclenvd: file:%s line:%d Unsupported keyword '%s'.\n")

#ifdef	__cplusplus
}
#endif

#endif	/* _ENVD_H */
