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

#ifndef	_ENVD_H
#define	_ENVD_H

#include <sys/types.h>
#include <libintl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Chicago Platform Details
 */
#define	MAX_SENSORS		9
#define	MAX_FANS		6

/*
 * Fan names and ids
 */
#define	ENV_SYSTEM_FAN0		"system-fan0"
#define	ENV_SYSTEM_FAN1		"system-fan1"
#define	ENV_SYSTEM_FAN2		"system-fan2"
#define	ENV_SYSTEM_FAN3		"system-fan3"
#define	ENV_SYSTEM_FAN4		"system-fan4"

#define	SYSTEM_FAN0_ID		0
#define	SYSTEM_FAN1_ID		1
#define	SYSTEM_FAN2_ID		2
#define	SYSTEM_FAN3_ID		3
#define	SYSTEM_FAN4_ID		4

#define	CPU0_FAN_ID		SYSTEM_FAN0_ID
#define	CPU1_FAN_ID		SYSTEM_FAN1_ID

/*
 * Sensor names and ids
 */
#define	SENSOR_CPU0		"cpu0"
#define	SENSOR_CPU1		"cpu1"
#define	SENSOR_MB		"MotherBoard"
#define	SENSOR_ADT7462		"ADT7462"
#define	SENSOR_LM95221		"LM95221"
#define	SENSOR_FIRE		"FireASIC"
#define	SENSOR_LSI1064		"LSI1064"
#define	SENSOR_FRONT_PANEL	"Front_panel"
#define	SENSOR_PSU		"PSU"

#define	CPU0_SENSOR_ID		0
#define	CPU1_SENSOR_ID		1
#define	ADT7462_SENSOR_ID	2
#define	MB_SENSOR_ID		3
#define	LM95221_SENSOR_ID	4
#define	FIRE_SENSOR_ID		5
#define	LSI1064_SENSOR_ID	6
#define	FRONT_PANEL_SENSOR_ID	7
#define	PSU_SENSOR_ID		8

/*
 * Hard disk sensor names and ids
 */
#define	ENV_DISK0		"hard-disk0"
#define	ENV_DISK1		"hard-disk1"
#define	ENV_DISK2		"hard-disk2"
#define	ENV_DISK3		"hard-disk3"

#define	DISK0_ID		0
#define	DISK1_ID		1
#define	DISK2_ID		2
#define	DISK3_ID		3

/*
 * Thresholds and other constants
 */
#define	DISK_SCAN_INTERVAL		10
#define	DISK_HIGH_WARN_TEMPERATURE	55
#define	DISK_LOW_WARN_TEMPERATURE	5
#define	DISK_HIGH_SHUTDOWN_TEMPERATURE	60
#define	DISK_LOW_SHUTDOWN_TEMPERATURE	0
#define	DISK_INVALID_TEMP		0xFFFF
#define	LSI1064_VENDOR_ID		0x1000
#define	LSI1064_DEVICE_ID		0x50
#define	FAN_SCAN_INTERVAL		10
#define	SENSOR_SCAN_INTERVAL		2
#define	SENSOR_WARNING_DURATION		4
#define	SENSOR_WARNING_INTERVAL		30
#define	DISK_WARNING_INTERVAL		30
#define	DISK_WARNING_DURATION		20
#define	SENSOR_SHUTDOWN_INTERVAL	60
#define	DISK_SHUTDOWN_INTERVAL		30
#define	ENV_CONF_FILE			"envmodel.conf"
#define	TUNABLE_CONF_FILE		"piclenvd.conf"
#define	PM_DEVICE			"/dev/pm"
#define	SHUTDOWN_CMD			"/usr/sbin/shutdown -y -g 60 -i 5"
#define	PICL_PLUGINS_NODE		"plugins"
#define	PICL_ENVIRONMENTAL_NODE		"environmental"

#define	MAX_RETRIES_FOR_FAN_FAULT	10
#define	MAX_FAN_RETRIES			14
#define	MAX_SENSOR_RETRIES		14

#define	TACH_TO_RPM(tach)	(((tach) == 0) ? 0 : (90000 * 60)/(tach))

/*
 * constants used for retrieving SMART data
 */
#define	DEFAULT_SCSI_TIMEOUT		60
#define	IEC_PAGE			0x1C
#define	HDA_TEMP			0xc2
#define	DRIVE_TEMP			0xe7
#define	GET_SMART_INFO			0x31
#define	SMART_FIELDS			30
#define	REPORT_ON_REQUEST		0x6
#define	PAGE_FMT			4
#define	IEC_PAGE_SIZE			12
#define	SMART_FLAG_SIZE			2
#define	ATTRIBUTE_DATA_SIZE		8
#define	VENDOR_ATTR_SIZE		131
#define	SMART_RESERVED_SIZE		10
#define	COLLECTION_DATA_SIZE		6

#define	DISK0_PHYSPATH	\
	"/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1/sd@0,0"

#define	DISK1_PHYSPATH	\
	"/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1/sd@1,0"

#define	DISK2_PHYSPATH  \
	"/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1/sd@2,0"

#define	DISK3_PHYSPATH  \
	"/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1/sd@3,0"

#define	ENV_DISK0_DEVFS	\
"/devices/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1/sd@0,0:a,raw"

#define	ENV_DISK1_DEVFS	\
"/devices/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1/sd@1,0:a,raw"

#define	ENV_DISK2_DEVFS \
"/devices/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1/sd@2,0:a,raw"

#define	ENV_DISK3_DEVFS \
"/devices/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1/sd@3,0:a,raw"

#define	DISK0_NODE_PATH	\
"name:/platform/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1/sd@0,0"

#define	DISK1_NODE_PATH	\
"name:/platform/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1/sd@1,0"

#define	DISK2_NODE_PATH \
"name:/platform/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1/sd@2,0"

#define	DISK3_NODE_PATH \
"name:/platform/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1/sd@3,0"

#define	SCSI_CONTROLLER_NODE_PATH	\
	"name:/platform/pci@1e,600000/pci@0/pci@9/pci@0/scsi@1"

/* CPU Path Names */
#define	CPU0_PATH		"_class:/jbus/cpu?ID=0"
#define	CPU1_PATH		"_class:/jbus/cpu?ID=1"

#define	ENV_MONITOR_DEVFS	"/devices/ebus@1f,464000/env-monitor@3,0"


/*
 * devfs-path for various fans and their min/max speeds
 */
#define	ENV_SYSTEM_FAN0_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:fan_0"
#define	ENV_SYSTEM_FAN1_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:fan_1"
#define	ENV_SYSTEM_FAN2_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:fan_2"
#define	ENV_SYSTEM_FAN3_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:fan_3"
#define	ENV_SYSTEM_FAN4_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:fan_4"

/* MIN and MAX SPEED are in RPM units */

#define	CPU_FAN_SPEED_MIN	250
#define	CPU_FAN_SPEED_MAX	5000

#define	SYSTEM_FAN_SPEED_MIN	250
#define	SYSTEM_FAN_SPEED_MAX	5000

/*
 * devfs-path for various temperature sensors and CPU platform path
 */
#define	SENSOR_CPU0_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:cpu_0"
#define	SENSOR_CPU1_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:cpu_1"
#define	SENSOR_MB_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:mb"
#define	SENSOR_ADT7462_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:adt7462"
#define	SENSOR_LM95221_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:lm95221"
#define	SENSOR_FIRE_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:fire"
#define	SENSOR_LSI1064_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:lsi1064"
#define	SENSOR_FRONT_PANEL_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:front_panel"
#define	SENSOR_PSU_DEVFS	\
	"/devices/ebus@1f,464000/env-monitor@3,0:psu"

/*
 * Temperature type
 */
typedef int16_t tempr_t;

/*
 *				SEEPROM LAYOUT
 *
 *      The layout of environmental segment in the SEEPROM in Chicago is as
 *      shown below. Note that this is a stripped-down version of the Envseg
 *      Definition v2.0 (but compatible). In particular, piclenvd in Chicago
 *      does not use the #FanEntries and the list of FANn_ID/FANn_DOFF
 *      pairs, and it doesn't use the SensorPolicy and the list of
 *      Measured/Corrected pairs for the temperature sensor values either.
 *
 *
 *                   0         1         2         3         4         5
 *		+---------+------------------+----------+---------+---------+
 *	0x1800:	| HDR_TAG |      HDR_VER     |  HDR_LEN | HDR_CRC |  N_SEGS |
 *		+---------+---------+--------+----------+---------+---------+
 *	0x1806:	|     SEG1_NAME	    |	            SEG1_DESC               |
 *		+-------------------+-------------------+-------------------+
 *	0x180C:	|     SEG1_OFF	    |	  SEG1_LEN	|      SEG2_NAME    |
 *		+-------------------+-------------------+-------------------+
 *		~							    ~
 *		.							    .
 *		~							    ~
 *		+-------------------+-------------------+-------------------+
 *	0xXXXX:	|     SEGn_OFF	    |	  SEGn_LEN	|
 *		+-------------------+-------------------+
 *
 *
 *              +---------+---------+---------------------------------------+
 *  ENVSEG_OFF:	| ESEG_VER| N_SNSRS |            SENSOR1_ID                 |
 *              +---------+---------+---------------------------------------+
 *	        |    SNSR1_DOFF     |            SENSOR2_ID                 |
 *              +-------------------+---------------------------------------+
 *		~							    ~
 *		~							    ~
 *		+-------------------+---------------------------------------+
 *	        |    SNSRm_DOFF     |
 *              +-------------------+
 *
 *
 *		+---------+---------+--------+----------+---------+---------+
 * SNSRk_DOFF:	| HI_POFF | HI_SHUT | HI_WARN| LO_WARN  | LO_SHUT | LO_POFF |
 *              +-------------------+--------+----------+---------+---------+
 */

#define	I2C_DEVFS		"/devices/ebus@1f,464000/i2c@3,80"
#define	IOFRU_DEV		"front-io-fru-prom@0,a4:front-io-fru-prom"
#define	FRU_SEEPROM_NAME	"front-io-fru-prom"

/*
 * SEEPROM section header
 */
#define	SSCN_TAG	0x08
#define	SSCN_VER	0x0001
#define	SSCN_OFFSET	0x1800
typedef struct {
	uint8_t sscn_tag;		/* section header tag */
	uint8_t sscn_ver[2];		/* section header version */
	uint8_t sscn_len;		/* section header length */
	uint8_t sscn_crc;		/* unused */
	uint8_t sscn_nsegs;		/* total number of segments */
} seeprom_scn_t;

/*
 * SEEPROM segment header
 */
typedef struct {
	uint16_t sseg_name;		/* segment name */
	uint16_t sseg_desc[2];		/* segment descriptor */
	uint16_t sseg_off;		/* segment data offset */
	uint16_t sseg_len;		/* segment length */
} seeprom_seg_t;
#define	ENVSEG_NAME	0x4553		/* "ES" */

/*
 * Envseg layout V2 (stripped-down version)
 */
typedef struct {
	uint8_t esb_high_power_off;
	uint8_t esb_high_shutdown;
	uint8_t esb_high_warning;
	uint8_t esb_low_warning;
	uint8_t esb_low_shutdown;
	uint8_t esb_low_power_off;
} es_sensor_blk_t;

typedef struct {
	uint16_t ess_id[2];		/* unique sensor id (on this FRU) */
	uint16_t ess_off;		/* sensor data blk offset */
} es_sensor_t;

#define	ENVSEG_VERSION	2
typedef struct {
	uint8_t esd_ver;		/* envseg version */
	uint8_t esd_nsensors;		/* envseg total number of sensor blks */
	es_sensor_t esd_sensors[1];	/* sensor table (variable length) */
} es_data_t;

/*
 * Macros to fetch 16 and 32 bit msb-to-lsb data from unaligned addresses
 */
#define	GET_UNALIGN16(addr)	\
	(((*(uint8_t *)addr) << 8) | *((uint8_t *)addr + 1))
#define	GET_UNALIGN32(addr)	\
	(GET_UNALIGN16(addr) << 16) | GET_UNALIGN16((uint8_t *)addr + 2)

/*
 * Macros to check sensor/disk temperatures
 */
#define	SENSOR_TEMP_IN_WARNING_RANGE(val, sensorp) \
	((val) > (sensorp)->es->esb_high_warning || \
	(val) < (char)((sensorp)->es->esb_low_warning))

#define	SENSOR_TEMP_IN_SHUTDOWN_RANGE(val, sensorp) \
	((val) > (sensorp)->es->esb_high_shutdown || \
	(val) < (char)((sensorp)->es->esb_low_shutdown))

#define	DISK_TEMP_IN_WARNING_RANGE(val, diskp) \
	((val) > (diskp)->high_warning || \
	(val) < (char)((diskp)->low_warning))

#define	DISK_TEMP_IN_SHUTDOWN_RANGE(val, diskp) \
	((val) > (diskp)->high_shutdown || \
	(val) < (char)((diskp)->low_shutdown))

#define	SENSOR_WARN		1
#define	SENSOR_OK		0

#define	FAN_FAILED		1
#define	FAN_OK			0

/*
 * Default limits for sensors in case environmental segment is absent
 */
#define	CPU0_HIGH_POWER_OFF		105
#define	CPU0_HIGH_SHUTDOWN		100
#define	CPU0_HIGH_WARNING		95
#define	CPU0_LOW_WARNING		5
#define	CPU0_LOW_SHUTDOWN		0
#define	CPU0_LOW_POWER_OFF		0

#define	CPU1_HIGH_POWER_OFF		105
#define	CPU1_HIGH_SHUTDOWN		100
#define	CPU1_HIGH_WARNING		95
#define	CPU1_LOW_WARNING		5
#define	CPU1_LOW_SHUTDOWN		0
#define	CPU1_LOW_POWER_OFF		0

#define	ADT7462_HIGH_POWER_OFF		80
#define	ADT7462_HIGH_SHUTDOWN		75
#define	ADT7462_HIGH_WARNING		70
#define	ADT7462_LOW_WARNING		5
#define	ADT7462_LOW_SHUTDOWN		0
#define	ADT7462_LOW_POWER_OFF		0

#define	MB_HIGH_POWER_OFF		80
#define	MB_HIGH_SHUTDOWN		75
#define	MB_HIGH_WARNING			70
#define	MB_LOW_WARNING			5
#define	MB_LOW_SHUTDOWN			0
#define	MB_LOW_POWER_OFF		0

#define	LM95221_HIGH_POWER_OFF		80
#define	LM95221_HIGH_SHUTDOWN		75
#define	LM95221_HIGH_WARNING		70
#define	LM95221_LOW_WARNING		5
#define	LM95221_LOW_SHUTDOWN		0
#define	LM95221_LOW_POWER_OFF		0

#define	FIRE_HIGH_POWER_OFF		105
#define	FIRE_HIGH_SHUTDOWN		100
#define	FIRE_HIGH_WARNING		95
#define	FIRE_LOW_WARNING		5
#define	FIRE_LOW_SHUTDOWN		0
#define	FIRE_LOW_POWER_OFF		0

#define	LSI1064_HIGH_POWER_OFF		105
#define	LSI1064_HIGH_SHUTDOWN		100
#define	LSI1064_HIGH_WARNING		95
#define	LSI1064_LOW_WARNING		5
#define	LSI1064_LOW_SHUTDOWN		0
#define	LSI1064_LOW_POWER_OFF		0

#define	FRONT_PANEL_HIGH_POWER_OFF	75
#define	FRONT_PANEL_HIGH_SHUTDOWN	70
#define	FRONT_PANEL_HIGH_WARNING	60
#define	FRONT_PANEL_LOW_WARNING		5
#define	FRONT_PANEL_LOW_SHUTDOWN	0
#define	FRONT_PANEL_LOW_POWER_OFF	0

#define	PSU_HIGH_POWER_OFF		95
#define	PSU_HIGH_SHUTDOWN		85
#define	PSU_HIGH_WARNING		75
#define	PSU_LOW_WARNING			5
#define	PSU_LOW_SHUTDOWN		0
#define	PSU_LOW_POWER_OFF		0

/*
 * Temperature sensor related data structure
 */
typedef struct env_sensor {
	char		*name;			/* sensor name */
	char		*devfs_path;		/* sensor device devfs path */
	int		id;
	int		fd;			/* device file descriptor */
	es_sensor_blk_t	*es;
	int		error;			/* error flag */
	boolean_t 	present;		/* sensor present */
	tempr_t		cur_temp;		/* current temperature */
	time_t		warning_start;		/* warning start time (secs) */
	time_t		warning_tstamp;		/* last warning time (secs) */
	time_t		shutdown_tstamp;	/* shutdown temp time (secs) */
	boolean_t 	shutdown_initiated;	/* shutdown initated */
} env_sensor_t;

extern	env_sensor_t *sensor_lookup(char *sensor_name);
extern	int get_temperature(env_sensor_t *, tempr_t *);

typedef struct env_disk {
	char		*name;			/* disk name */
	char		*devfs_path;	/* disk device devfs path */
	char		*physpath;	/* used to be probe for IDLW TIME */
	char		*nodepath;	/* used to detect presence of disk */
	uchar_t		id;
	int		fd;		/* device file descriptor */
	boolean_t	present;	/* disk present */
	boolean_t	tpage_supported;	/* Temperature page */
	boolean_t	smart_supported;
	int		current_temp;
	int		ref_temp;
	int		reliability_temp;
	uchar_t  	high_shutdown;
	uchar_t  	high_warning;
	uchar_t  	low_warning;
	uchar_t  	low_shutdown;
	time_t		warning_start;		/* warning start time (secs) */
	time_t		warning_tstamp;		/* last warning time (secs) */
	time_t		shutdown_tstamp;	/* shutdown temp time (secs) */
	boolean_t 	shutdown_initiated;	/* shutdown initated */
} env_disk_t;

extern	env_disk_t *disk_lookup(char *disk_name);
extern	int disk_temperature(env_disk_t *, tempr_t *);

/*
 * Fan information data structure
 */
typedef int fanspeed_t;

typedef struct env_fan {
	char		*name;			/* fan name */
	char		*devfs_path;		/* fan device devfs path */
	uchar_t		id;
	fanspeed_t	speed_min;		/* minimum speed */
	fanspeed_t	speed_max;		/* maximum speed */
	int		forced_speed;		/* forced (fixed) speed */
	int		fd;			/* device file descriptor */
	boolean_t	present;		/* fan present */
	int		last_status;		/* Fan status */
	uint8_t		cspeed;			/* Current speed (tach) */
	uint8_t		lspeed;			/* Last speed (tach) */
} env_fan_t;

/*
 * Tuneables
 */
typedef struct env_tuneable {
	char		*name;
	char		type;
	void		*value;
	int		(*rfunc)(ptree_rarg_t *, void *);
	int		(*wfunc)(ptree_warg_t *, const void *);
	int		nbytes;
	picl_prophdl_t proph;
} env_tuneable_t;

/*
 * Smart structures
 */

typedef	struct smart_field {
	uint8_t id;
	uint8_t flags[SMART_FLAG_SIZE];
	uint8_t raw_data[ATTRIBUTE_DATA_SIZE];
	uint8_t	reserved;
} smart_attribute;

typedef struct smart_struct {
	uint16_t	revision;		/* SMART version # */
	struct smart_field attribute[SMART_FIELDS];
			/* offline collection information */
	uint8_t		collection_status[COLLECTION_DATA_SIZE];
	uint16_t	capability;		/* SMART capability */
	uint8_t		reserved[SMART_RESERVED_SIZE];
	uint8_t		vendor_specific[VENDOR_ATTR_SIZE];
	uint8_t		checksum;		/* page checksum */
} smart_structure;

extern	env_fan_t *fan_lookup(char *fan_name);
extern	int get_fan_speed(env_fan_t *, fanspeed_t *);
extern	int set_fan_speed(env_fan_t *, fanspeed_t);

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

#define	DISK_TEMP_THREAD_EXITING		\
	gettext("SUNW_piclenvd: Disk temp thread exiting."	\
	" Disk temperature will not be monitored. errno:%d %s\n")

#define	ENVTHR_THREAD_CREATE_FAILED	\
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

#define	ENV_FAN_FAILURE_WARNING_MSG		\
	gettext("SUNW_piclenvd: %s has Failed.\n"	\
	"(rpm = %s status = %s)\n")

#define	ENV_FAN_OK_MSG		\
	gettext("SUNW_piclenvd: %s is OKAY.\n")

#define	ENV_FRU_OPEN_FAIL		\
	gettext("SUNW_piclenvd: can't open FRU SEEPROM path:%s errno:%d\n")

#define	ENV_FRU_BAD_ENVSEG		\
	gettext("SUNW_piclenvd: version mismatch or environmental segment " \
		"header too short in FRU SEEPROM %s\n")

#define	ENV_FRU_BAD_SCNHDR		\
	gettext("SUNW_piclenvd: invalid section header tag:%x version:%x\n")

#define	ENV_FRU_NOMEM_FOR_SEG		\
	gettext("SUNW_piclenvd: cannot allocate %d bytes for env seg memory\n")

#define	ENV_DEFAULT_LIMITS		\
	gettext("SUNW_piclenvd: error reading ES segment, using defaults\n")

#ifdef	__cplusplus
}
#endif

#endif	/* _ENVD_H */
