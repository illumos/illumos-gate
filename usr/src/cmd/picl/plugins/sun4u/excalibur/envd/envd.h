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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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
#define	WARNING_DURATION	28			/* in seconds */
#define	SHUTDOWN_INTERVAL	60			/* in seconds */
#define	ENV_CONF_FILE		"piclenvd.conf"
#define	PM_DEVICE		"/dev/pm"
#define	SHUTDOWN_CMD		"/usr/sbin/shutdown -y -g 60 -i 5"
#define	ENVMODEL_CONF_FILE	"envmodel.conf"

/*
 * Macros to fetch 16 and 32 bit data from unaligned address
 */
#define	GET_UNALIGN16(addr)	\
	(((*(uint8_t *)addr) << 8) | *((uint8_t *)addr+1))

#define	GET_UNALIGN32(addr)	\
	(((*(uint8_t *)addr) << 24) | (*((uint8_t *)addr+1) << 16) | \
	((*((uint8_t *)addr+2)) << 8) | (*((uint8_t *)addr+3)))


/*
 * SEEPROM section header layout and location
 */
typedef struct {
	uint8_t		header_tag;		/* section header tag */
	uint8_t		header_version[2];	/* header version (msb) */
	uint8_t		header_length;		/* header length */
	uint8_t		header_crc8;		/* crc8 */
	uint8_t		segment_count;		/* total number of segments */
} section_layout_t;

#define	SECTION_HDR_OFFSET	0x1800
#define	SECTION_HDR_TAG		0x08
#define	SECTION_HDR_VER		0x0001
#define	SECTION_HDR_LENGTH	0x06


/*
 * SEEPROM segment header layout
 */
typedef struct {
	uint16_t	name;		/* segment name */
	uint16_t	descriptor[2];	/* descriptor (msb) */
	uint16_t	offset;		/* segment data offset */
	uint16_t	length;		/* segment length */
} segment_layout_t;

#define	ENVSEG_NAME		0x4553	/* environmental segment name */
#define	ENVSEG_VERSION		1	/* environmental segment version */


/*
 * SEEPROM environmental segment header layout
 */
typedef struct {
	uint16_t	sensor_id[2];	/* unique sensor ID (on this FRU) */
	uint16_t	offset;		/* sensor data record offset */
} envseg_sensor_t;

typedef struct {
	uint8_t		version;	/* envseg version */
	uint8_t		sensor_count;	/* total number of sensor records */
	envseg_sensor_t	sensors[1];	/* sensor table (variable length) */
} envseg_layout_t;


/*
 * SEEPROM environmental segment sensor data layout
 */
#define	MAX_POLICY_ENTRIES	6	/* max # policy data entries */

typedef struct {
	int8_t		observed;	/* observed (measured) temperature */
	int8_t		expected;	/* expected (correct) temperature */
} envseg_map_t;

typedef struct {
	int8_t		high_power_off;	/* high power off threshold */
	int8_t		high_shutdown;	/* high shutdown threshold */
	int8_t		high_warning;	/* high warning threshold */
	int8_t		low_warning;	/* low warning threshold */
	int8_t		low_shutdown;	/* low shutdown threshold */
	int8_t		low_power_off;	/* low power off threshold */
	int8_t		policy_type;	/* policy type */
	int8_t		policy_entries;	/* #valid entries in policy_data[] */
	int8_t		policy_data[MAX_POLICY_ENTRIES];
	uint16_t	obs2exp_cnt;	/* map entries count */
	envseg_map_t	obs2exp_map[1];	/* variable length map table */
} envseg_sensor_data_t;

/* policy_type */
#define	POLICY_TARGET_TEMP	1
#define	POLICY_LINEAR		2

/* linear policy data indices */
#define	LOW_NOMINAL_LOC		0	/* linear policy: lower temp index */
#define	HIGH_NOMINAL_LOC	1	/* linear policy: higher temp index */


/*
 * FRU envseg list
 */
typedef struct fruenvseg {
	struct fruenvseg	*next;		/* next entry */
	char			*fru;		/* FRU SEEPROM path */
	void			*envsegbufp;	/* envseg data buffer */
	int			envseglen;	/* envseg length */
} fruenvseg_t;


/*
 * devfs-path and sensor IDs for CPU FRUs
 */
#define	CPU0_FRU_DEVFS	"/pci@8,700000/ebus@5/i2c@1,30/cpu-fru@0,a0:cpu-fru"
#define	CPU1_FRU_DEVFS	"/pci@8,700000/ebus@5/i2c@1,30/cpu-fru@0,a2:cpu-fru"

#define	CPU_FRU_AMB_SENSOR	1
#define	CPU_FRU_DIE_SENSOR	2

/*
 * devfs-path for various fans and their min/max speeds
 */
#define	ENV_CPU_FAN_DEVFS	\
	"/pci@8,700000/ebus@5/i2c@1,30/fan-control@0,48:2"
#define	ENV_SYSTEM_FAN_DEVFS	\
	"/pci@8,700000/ebus@5/i2c@1,30/fan-control@0,48:0"
#define	ENV_PSUPPLY_FAN_DEVFS	\
	"/pci@8,700000/ebus@5/i2c@1,30/fan-control@0,48:4"

/*
 * devfs-path for xcalwd watchdog
 */
#define	XCALWD_DEVFS	"/devices/pseudo/xcalwd@0:xcalwd"

#define	CPU_FAN_SPEED_MIN	12
#define	CPU_FAN_SPEED_MAX	63

#define	SYSTEM_FAN_SPEED_MIN	12
#define	SYSTEM_FAN_SPEED_MAX	63

#define	PSUPPLY_FAN_SPEED_MIN	0
#define	PSUPPLY_FAN_SPEED_MAX	31


/*
 * devfs-path for various temperature sensors and CPU platform path
 */
#define	CPU0_DIE_SENSOR_DEVFS	\
	"/pci@8,700000/ebus@5/i2c@1,30/temperature@0,30:die_temp"
#define	CPU0_AMB_SENSOR_DEVFS	\
	"/pci@8,700000/ebus@5/i2c@1,30/temperature@0,30:amb_temp"

#define	CPU1_DIE_SENSOR_DEVFS	\
	"/pci@8,700000/ebus@5/i2c@1,30/temperature@0,98:die_temp"
#define	CPU1_AMB_SENSOR_DEVFS	\
	"/pci@8,700000/ebus@5/i2c@1,30/temperature@0,98:amb_temp"

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
	tempr_t	min_limit;		/* sensor minimum temperature limit */
	tempr_t	max_limit;		/* sensor maximum temperature limit */
	short	policy_type;		/* temperature policy */
	short	policy_entries;		/* # entries in policy_data */
	tempr_t	policy_data[MAX_POLICY_ENTRIES];
} sensor_thresh_t;



#define	TEMP_IN_SHUTDOWN_RANGE(val, threshp)	\
	((val) > (threshp)->high_shutdown || (val) < (threshp)->low_shutdown)

#define	TEMP_IN_WARNING_RANGE(val, threshp)	\
	((val) > (threshp)->high_warning || (val) < (threshp)->low_warning)


/*
 * MAX1617 sensor min/max temperature limits
 */
#define	MAX1617_MIN_TEMP	-65
#define	MAX1617_MAX_TEMP	127

/*
 * CPU "die" temperature thresholds
 */
#define	CPU_DIE_HIGH_POWER_OFF	110
#define	CPU_DIE_HIGH_SHUTDOWN	90
#define	CPU_DIE_HIGH_WARNING	88
#define	CPU_DIE_NORMAL_TARGET	80
#define	CPU_DIE_OTHER_TARGET	65
#define	CPU_DIE_LOW_WARNING	0
#define	CPU_DIE_LOW_SHUTDOWN	-10
#define	CPU_DIE_LOW_POWER_OFF	-20

/*
 * CPU ambient temperature thresholds
 */
#define	CPU_AMB_HIGH_POWER_OFF	70
#define	CPU_AMB_HIGH_SHUTDOWN	60
#define	CPU_AMB_HIGH_WARNING	40
#define	CPU_AMB_HIGH_NOMINAL	40
#define	CPU_AMB_LOW_NOMINAL	25
#define	CPU_AMB_LOW_WARNING	0
#define	CPU_AMB_LOW_SHUTDOWN	-10
#define	CPU_AMB_LOW_POWER_OFF	-20


/*
 * Fan names
 */
#define	ENV_SYSTEM_FAN		"system"
#define	ENV_CPU_FAN		"cpu"
#define	ENV_PSUPPLY_FAN		"power-supply"

/*
 * Sensor ids & names
 */
#define	SENSOR_CPU0_ID		0
#define	SENSOR_CPU0_DIE		"cpu0"
#define	SENSOR_CPU0_AMB		"cpu0-ambient"
#define	SENSOR_CPU1_ID		1
#define	SENSOR_CPU1_DIE		"cpu1"
#define	SENSOR_CPU1_AMB		"cpu1-ambient"

/*
 * Temperature correction/map strucutre
 */
typedef struct {
	tempr_t		observed;		/* observed temperature */
	tempr_t		expected;		/* expected temperature */
} tempr_map_t;

/*
 * Temperature sensor related data structure
 */
typedef struct sensor_pmdev sensor_pmdev_t;

typedef struct env_sensor {
	char		*name;			/* sensor name */
	char		*devfs_path;		/* sensor device devfs path */
	sensor_thresh_t	*temp_thresh;		/* sensor temp threshold */
	char		*fru;			/* FRU seeprom pathname */
	int		fru_sensor;		/* FRU sensor ID */
	int		flags;			/* flags (see below) */
	int		fd;			/* device file descriptor */
	int		error;			/* error flag */
	boolean_t 	present;		/* sensor present */
	tempr_t		cur_temp;		/* current temperature */
	tempr_t		target_temp;		/* target temperature */
	float		avg_temp;		/* average temperature */
	float		prev_avg_temp;		/* prev average temperature */
	time_t		warning_tstamp;		/* last warning time (secs) */
	time_t		shutdown_tstamp;	/* shutdown temp time (secs) */
	boolean_t 	shutdown_initiated;	/* shutdown initated */
	sensor_pmdev_t	*pmdevp;		/* power managed device info */
	float		fan_adjustment_rate;	/* fan adjustment rate */
	uint_t		obs2exp_cnt;		/* # mapping entries */
	tempr_map_t	*obs2exp_map;		/* temperature map entries */
	time_t		warning_start;		/* warning start time (secs) */
} env_sensor_t;

/*
 * Sensor flags
 */
#define	SFLAG_TARGET_TEMP	0x01		/* track target temperature */
#define	SFLAG_CPU_AMB_SENSOR	0x10		/* CPU ambient sensor */
#define	SFLAG_CPU_DIE_SENSOR	0x20		/* CPU die snesor */

extern	env_sensor_t *sensor_lookup(char *sensor_name);
extern	int get_temperature(env_sensor_t *, tempr_t *);

/*
 * Fan information data structure
 */
#define	SENSORS_PER_FAN	8		/* max sensors per fan */
typedef uint8_t fanspeed_t;

typedef struct env_fan {
	char		*name;			/* fan name */
	char		*devfs_path;		/* fan device devfs path */
	fanspeed_t	speed_min;		/* minimum speed */
	fanspeed_t	speed_max;		/* maximum speed */
	int		forced_speed;		/* forced (fixed) speed */
	int		fd;			/* device file descriptor */
	boolean_t	present;		/* fan present */
	float		cur_speed;		/* current fan speed */
	float		prev_speed;		/* previous fan speed */
	int		sensor_cnt;		/* #sensors in sensors[] */
	env_sensor_t	*sensors[SENSORS_PER_FAN]; /* array of sensors */
} env_fan_t;

/*
 * LPM/Table data structures
 */
#define	LPM_RANGES_PROPERTY	"sunw,lpm-ranges"

typedef struct {
	int32_t	x;
	int32_t	y;
} point_t;

typedef struct {
	int	nentries;
	point_t	*xymap;
} table_t;

struct lpm_dev {
	picl_nodehdl_t	nodeh;
	table_t		*temp_lpm_tbl;
	struct lpm_dev *next;
};
typedef struct lpm_dev lpm_dev_t;

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

#define	ENV_WATCHDOG_INIT_FAIL		\
	gettext("SUNW_piclenvd: failed to initialize the watchdog timer " \
	"errno:%d %s\n")

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

#define	ENV_FRU_OPEN_FAIL		\
	gettext("SUNW_piclenvd: can't open FRU SEEPROM path:%s errno:%d %s\n")

#define	ENV_FRU_BAD_ENVSEG		\
	gettext("SUNW_piclenvd: version mismatch or environmental segment " \
	"header too short in FRU SEEPROM %s\n")

#define	ENV_FRU_BAD_SENSOR_ENTRY	\
	gettext("SUNW_piclenvd: discarding bad sensor entry (sensor_id " \
	"%x sensor '%s') in FRU SEEPROM %s\n")

#define	ENV_FRU_SENSOR_MAP_NOMEM	\
	gettext("SUNW_piclenvd: out of memory, discarding sensor map for " \
	"sensor_id %x (sensor '%s') in FRU SEEPROM %s\n")

#define	ENV_INVALID_PROPERTY_FORMAT	\
	gettext("SUNW_piclenvd: ignoring %s property (invalid format)")

#ifdef	__cplusplus
}
#endif

#endif	/* _ENVD_H */
