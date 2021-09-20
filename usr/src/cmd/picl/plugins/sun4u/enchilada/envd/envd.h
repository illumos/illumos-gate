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

#ifndef	_ENVD_H
#define	_ENVD_H

#include <sys/types.h>
#include <libintl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DISK_SCAN_INTERVAL	10
#define	DISK_HIGH_WARN_TEMPERATURE	55
#define	DISK_LOW_WARN_TEMPERATURE	5
#define	DISK_HIGH_SHUTDOWN_TEMPERATURE	60
#define	DISK_LOW_SHUTDOWN_TEMPERATURE	0
#define	DISK_INVALID_TEMP	0xFFFF
#define	LSI1030_VENDOR_ID	0x1000
#define	LSI1030_DEVICE_ID	0x30
#define	SENSORPOLL_INTERVAL	4
#define	INTERRUPTPOLL_INTERVAL	2
#define	WARNING_INTERVAL	30
#define	DISK_WARNING_INTERVAL	30
#define	DISK_WARNING_DURATION	20
#define	SHUTDOWN_INTERVAL	60
#define	DISK_SHUTDOWN_INTERVAL	30
#define	ENV_CONF_FILE		"envmodel.conf"
#define	TUNABLE_CONF_FILE	"piclenvd.conf"
#define	PM_DEVICE		"/dev/pm"
#define	SHUTDOWN_CMD		"/usr/sbin/shutdown -y -g 60 -i 5"
#define	PICL_PLUGINS_NODE	"plugins"
#define	PICL_ENVIRONMENTAL_NODE	"environmental"

/*
 * ADC Sample of ADM in Khz, currently 11.2 KHz
 */
#define	ADCSAMPLE		11250

/*
 * Enchilada Platform Details
 */
#define	MAX_SENSORS	6
#define	MAX_FANS	4
#define	MAX_HWMS	2

/*
 * ADM1031 Hardware Monitor IDs
 * Used as index into arrays
 */
#define	CPU_HWM_ID	0
#define	SYS_HWM_ID	1

#define	CPU_HWM_DEVFS	\
	"/devices/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,58:control"
#define	SYS_HWM_DEVFS	\
	"/devices/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,5c:control"

#define	DISK0_PHYSPATH	\
	"/pci@1d,700000/scsi@4/sd@0,0"

#define	DISK1_PHYSPATH	\
	"/pci@1d,700000/scsi@4/sd@1,0"

#define	ENV_DISK0_DEVFS	\
	"/devices/pci@1d,700000/scsi@4/sd@0,0:a,raw"

#define	ENV_DISK1_DEVFS	\
	"/devices/pci@1d,700000/scsi@4/sd@1,0:a,raw"

#define	DISK0_NODE_PATH	\
	"name:/platform/pci@1d,700000/scsi@4/sd@0,0"

#define	DISK1_NODE_PATH	\
	"name:/platform/pci@1d,700000/scsi@4/sd@1,0"


#define	SCSI_CONTROLLER_NODE_PATH	\
	"name:/platform/pci@1d,700000/scsi@4"

#define	HWM_FAN1	0
#define	HWM_FAN2	1

/*
 * Enchilada sensor IDs as used in FRUID segment
 */
#define	CPU0_SENSOR_ID		0
#define	CPU1_SENSOR_ID		1
#define	INT_AMB0_SENSOR_ID	5
#define	SYS_OUT_SENSOR_ID	3
#define	INT_AMB1_SENSOR_ID	4
#define	SYS_IN_SENSOR_ID	2
#define	MAX_SENSOR_ID		5

/*
 * Enchilada fan IDs used in FRUID segment
 */
#define	CPU0_FAN_ID		0
#define	CPU1_FAN_ID		1
#define	SYSTEM_OUT_FAN_ID	2
#define	SYSTEM_INTAKE_FAN_ID	3
#define	DIMM_FAN_ID		4

#define	DISK0_ID		0
#define	DISK1_ID		1


/* CPU Path Names */
#define	CPU0_PATH		"_class:/jbus/cpu?ID=0"
#define	CPU1_PATH		"_class:/jbus/cpu?ID=1"

/* DIMM Fan controller path Name */
#define	DIMM_FAN_CONTROLLER_PATH	\
	"name:/platform/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,52"
/*
 * devfs-path for various fans and their min/max speeds
 */
#define	ENV_CPU0_FAN_DEVFS	\
	"/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,58:fan_1"
#define	ENV_CPU1_FAN_DEVFS	\
	"/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,58:fan_2"
#define	ENV_SYSTEM_INTAKE_FAN_DEVFS	\
	"/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,5c:fan_1"
#define	ENV_SYSTEM_OUT_FAN_DEVFS	\
	"/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,5c:fan_2"
#define	ENV_DIMM_FAN_DEVFS	\
	"/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,52:fan_1"

#define	FAN_RANGE_DEFAULT	4
#define	CPU_FAN_SPEED_MIN	14
#define	CPU_FAN_SPEED_MAX	100

#define	SYSTEM_OUT_FAN_SPEED_MIN	14
#define	SYSTEM_OUT_FAN_SPEED_MAX	100

#define	SYSTEM_INTAKE_FAN_SPEED_MIN	14
#define	SYSTEM_INTAKE_FAN_SPEED_MAX	100


/*
 * devfs-path for various temperature sensors and CPU platform path
 */
#define	SENSOR_CPU0_DIE_DEVFS	\
	"/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,58:remote_1"
#define	SENSOR_CPU1_DIE_DEVFS	\
	"/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,58:remote_2"
#define	SENSOR_INT_AMB_0_DEVFS	\
	"/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,58:local"

#define	SENSOR_SYS_IN_DEVFS	\
	"/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,5c:remote_1"
#define	SENSOR_SYS_OUT_DEVFS	\
	"/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,5c:remote_2"
#define	SENSOR_INT_AMB_1_DEVFS	\
	"/pci@1e,600000/isa@7/i2c@0,320/hardware-monitor@0,5c:local"

/*
 * Temperature type
 */
typedef int16_t tempr_t;


/*
 * Fan names
 */
#define	ENV_SYSTEM_OUT_FAN	"outtake-fan"
#define	ENV_CPU0_FAN		"cpu0-fan"
#define	ENV_SYSTEM_INTAKE_FAN	"intake-fan"
#define	ENV_CPU1_FAN		"cpu1-fan"
#define	ENV_DIMM_FAN		"dimm-fan"

#define	ENV_DISK0		"hard-disk0"
#define	ENV_DISK1		"hard-disk1"
/*
 * Sensor names
 */
#define	SENSOR_CPU0_DIE		"cpu0"
#define	SENSOR_CPU1_DIE		"cpu1"
#define	SENSOR_INT_AMB_0	"int-amb0"
#define	SENSOR_SYS_IN		"sys-in"
#define	SENSOR_SYS_OUT		"sys-out"
#define	SENSOR_INT_AMB_1	"int-amb1"

/* Bit Map of ADM 1031 Status 1/2 Registers */
typedef enum adm1031 {
	FANFAULT = 0x2,
	REMOTEHIGH = 0x4,
	REMOTELOW = 0x8,
	REMOTETHERN = 0x10,
	LHIGH = 0x40,
	LLOW  = 0x80
} adm1031_t;

/* ADM Stat 1/2 Mask */
typedef enum adm1031Mask {
	STAT1MASK = 0xdc,
	STAT2MASK = 0x1c
} adm1031Mask_t;

/*
 * ES segment related structures
 */
typedef struct id_off {
	uint_t id;
	ushort_t offset;
} id_off_t;

typedef struct fan_ctl_pair {
	uchar_t tMin;
	uchar_t tRange;
} fan_ctl_pair_t;

typedef struct Correction_Pair {
	uchar_t measured;
	uchar_t corrected;
} Correction_Pair_t;

#define	ES_SENSOR_POLICY_LEN	8
#define	ES_CORRECTION_PAIRS	12

typedef struct sensor_ctrl_blk {
	uchar_t  high_power_off;
	uchar_t  high_shutdown;
	uchar_t  high_warning;
	uchar_t  low_warning;
	uchar_t  low_shutdown;
	uchar_t  low_power_off;
	uchar_t  sensorPolicy[ES_SENSOR_POLICY_LEN];
	ushort_t correctionEntries;
	Correction_Pair_t correctionPair[ES_CORRECTION_PAIRS];
} sensor_ctrl_blk_t;


#define	ES_FAN_CTL_PAIRS	4

typedef struct fan_ctrl_blk {
	uchar_t  tSpinUp;
	uchar_t  minFanSpeed;
	ushort_t setPoint;
	ushort_t loopGain;
	ushort_t loopBias;
	ushort_t hysteresis;
	ushort_t fanViabTestInt;
	ushort_t fanViabTestThresh;
	ushort_t grossFanThresh;
	uchar_t no_ctl_pairs;
	fan_ctl_pair_t fan_ctl_pairs[ES_FAN_CTL_PAIRS];
} fan_ctrl_blk_t;

#define	TEMP_IN_WARNING_RANGE(val, sensorp) \
	((val) > (sensorp)->es_ptr->high_warning || \
	(val) < (char)((sensorp)->es_ptr->low_warning))

#define	TEMP_IN_SHUTDOWN_RANGE(val, sensorp) \
	((val) > (sensorp)->es_ptr->high_shutdown || \
	(val) < (char)((sensorp)->es_ptr->low_shutdown))

#define	DISK_TEMP_IN_WARNING_RANGE(val, diskp) \
	((val) > (diskp)->high_warning || \
	(val) < (char)((diskp)->low_warning))

#define	DISK_TEMP_IN_SHUTDOWN_RANGE(val, diskp) \
	((val) > (diskp)->high_shutdown || \
	(val) < (char)((diskp)->low_shutdown))

/*
 * Macros to fetch 16 and 32 bit data from unaligned address
 */
#define	GET_UNALIGN16(addr)	\
	(((*(uint8_t *)addr) << 8) | *((uint8_t *)addr + 1))

#define	GET_UNALIGN32(addr)	\
	(((*(uint8_t *)addr) << 24) | (*((uint8_t *)addr + 1) << 16) | \
	((*((uint8_t *)addr + 2)) << 8) | (*((uint8_t *)addr + 3)))


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
#define	ENVSEG_VERSION		2	/* environmental segment version */

#define	SENSOR_WARN		1
#define	SENSOR_OK		0

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
 * FRU envseg list
 */
typedef struct fruenvseg {
	struct fruenvseg	*next;		/* next entry */
	char			*fru;		/* FRU SEEPROM path */
	void			*envsegbufp;	/* envseg data buffer */
	int			envseglen;	/* envseg length */
} fruenvseg_t;

#define	I2C_DEVFS	"/devices/pci@1e,600000/isa@7/i2c@0,320"
#define	MBFRU_DEV	"/motherboard-fru-prom@0,a2:motherboard-fru-prom"
#define	FRU_SEEPROM_NAME	"motherboard-fru-prom"

/*
 * Table data structures
 */

typedef struct {
	int32_t	x;
	int32_t	y;
} point_t;

typedef struct {
	int	nentries;
	point_t	*xymap;
} table_t;

/*
 * Temperature sensor related data structure
 */
typedef struct env_sensor {
	char		*name;			/* sensor name */
	char		*devfs_path;		/* sensor device devfs path */
	sensor_ctrl_blk_t	*es_ptr;
	int		id;
	int		hwm_id;
	void		*fanp;
	int		fd;			/* device file descriptor */
	int		error;			/* error flag */
	boolean_t	present;		/* sensor present */
	tempr_t		cur_temp;		/* current temperature */
	time_t		warning_tstamp;		/* last warning time (secs) */
	time_t		shutdown_tstamp;	/* shutdown temp time (secs) */
	boolean_t	shutdown_initiated;	/* shutdown initated */
	table_t		*crtbl;			/* Correction Table */
	tempr_t		tmin;
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
	int		current_temp;
	int		ref_temp;
	int		reliability_temp;
	uchar_t		high_shutdown;
	uchar_t		high_warning;
	uchar_t		low_warning;
	uchar_t		low_shutdown;
	time_t		warning_start;		/* warning start time (secs) */
	time_t		warning_tstamp;		/* last warning time (secs) */
	time_t		shutdown_tstamp;	/* shutdown temp time (secs) */
	boolean_t	shutdown_initiated;	/* shutdown initated */
} env_disk_t;

extern	env_disk_t *disk_lookup(char *disk_name);
extern	int disk_temperature(env_disk_t *, tempr_t *);

/*
 * Fan information data structure
 */
typedef int fanspeed_t;

typedef struct env_fan {
	char		*name;			/* fan name */
	char		*devfs_path;	/* fan device devfs path */
	fan_ctrl_blk_t	*es_ptr;
	uchar_t		id;
	fanspeed_t	speed_min;		/* minimum speed */
	fanspeed_t	speed_max;		/* maximum speed */
	int		forced_speed;		/* forced (fixed) speed */
	int		fd;			/* device file descriptor */
	boolean_t	present;		/* fan present */
	int		speedrange;		/* speed range N */
	int		fanstat;		/* Fan status */
	uint8_t		cspeed;			/* Current speed (tach) */
	uint8_t		lspeed;			/* Last speed (tach) */
	int		conccnt;		/* Concurrent tach count */
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

#define	ENV_DIMM_FAN_FAILURE_SHUTDOWN_MSG		\
	gettext("SUNW_piclenvd: %s has Failed.\n"	\
	"(rpm = %s status = %s command = %s debug = %s).\n" \
	"Shutting down the system to protect the memory modules.\n")

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

#define	ENV_ADM_OPEN_FAIL		\
	gettext("SUNW_piclenvd: can't open hwm path:%s errno:%d %s\n")

#define	ENV_ADM_MANUAL_MODE \
	gettext("SUNW_piclenvd: Cannot change the ADM Chip to Manual mode")

#define	ENV_ADM_AUTO_MODE \
	gettext("SUNW_piclenvd: Cannot change the ADM Chip to Auto mode")

#define	ENV_FAN_FAULT \
	gettext("SUNW_piclenvd: ADM %s, Fan %s Fault")

#ifdef	__cplusplus
}
#endif

#endif	/* _ENVD_H */
