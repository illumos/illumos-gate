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

/*
 * This file contains the environmental PICL plug-in module.
 */

/*
 * This plugin sets up the PICLTREE for Enchilada WS.
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
#include <sys/i2c/clients/i2c_client.h>
#include <sys/i2c/clients/adm1031.h>
#include <sys/i2c/clients/pic16f819_reg.h>
#include "envd.h"
#include <sys/scsi/scsi.h>
#include <sys/scsi/generic/commands.h>


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

/*
 * Sleep routine used for polling
 */
static int get_dimm_fan_speed(int, fanspeed_t *);
static int is_dimm_fan_failed(void);

#pragma	init(piclenvd_register)

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
static char dimm_fan_rpm_string[REGISTER_INFORMATION_STRING_LENGTH] = {0};
static char dimm_fan_status_string[REGISTER_INFORMATION_STRING_LENGTH] = {0};
static char dimm_fan_command_string[REGISTER_INFORMATION_STRING_LENGTH] = {0};
static char dimm_fan_debug_string[REGISTER_INFORMATION_STRING_LENGTH] = {0};

static int	scsi_log_sense(int fd, uchar_t page_code, uchar_t *pagebuf,
			uint16_t pagelen);
static int	get_disk_temp(env_disk_t *);
/*
 * ES Segment data structures
 */
static sensor_ctrl_blk_t	sensor_ctrl[MAX_SENSORS];
static fan_ctrl_blk_t		fan_ctrl[MAX_FANS];
static fruenvseg_t		*envfru = NULL;

/*
 * Env thread variables
 */
static boolean_t  system_shutdown_started = B_FALSE;
static boolean_t  ovtemp_thr1_created = B_FALSE;
static pthread_t  ovtemp_thr1_id;
static pthread_attr_t thr_attr;
static boolean_t  ovtemp_thr2_created = B_FALSE;
static pthread_t  ovtemp_thr2_id;
static boolean_t  dimm_fan_thr_created = B_FALSE;
static pthread_t  dimm_fan_thr_id;
static boolean_t  disk_temp_thr_created = B_FALSE;
static pthread_t  disk_temp_thr_id;

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
 * Fan devices
 */
static env_fan_t envd_sys_out_fan = {
	ENV_SYSTEM_OUT_FAN, ENV_SYSTEM_OUT_FAN_DEVFS, NULL,
	SYSTEM_OUT_FAN_ID, SYSTEM_OUT_FAN_SPEED_MIN, SYSTEM_OUT_FAN_SPEED_MAX,
	-1, -1,
};

static env_fan_t envd_sys_in_fan = {
	ENV_SYSTEM_INTAKE_FAN, ENV_SYSTEM_INTAKE_FAN_DEVFS, NULL,
	SYSTEM_INTAKE_FAN_ID, SYSTEM_INTAKE_FAN_SPEED_MIN,
	SYSTEM_INTAKE_FAN_SPEED_MAX, -1, -1,
};

static env_fan_t envd_cpu0_fan = {
	ENV_CPU0_FAN, ENV_CPU0_FAN_DEVFS, NULL,
	CPU0_FAN_ID, CPU_FAN_SPEED_MIN, CPU_FAN_SPEED_MAX, -1, -1,
};

static env_fan_t envd_cpu1_fan = {
	ENV_CPU1_FAN, ENV_CPU1_FAN_DEVFS, NULL,
	CPU1_FAN_ID, CPU_FAN_SPEED_MIN, CPU_FAN_SPEED_MAX, -1, -1,
};

static env_fan_t envd_dimm_fan = {
	ENV_DIMM_FAN, ENV_DIMM_FAN_DEVFS, NULL,
	DIMM_FAN_ID, 100, 100, -1, -1,
};

static env_disk_t envd_disk0 = {
	ENV_DISK0, ENV_DISK0_DEVFS, DISK0_PHYSPATH, DISK0_NODE_PATH,
	DISK0_ID, -1, -1,
};

static env_disk_t envd_disk1 = {
	ENV_DISK1, ENV_DISK1_DEVFS, DISK1_PHYSPATH, DISK1_NODE_PATH,
	DISK1_ID, -1, -1,
};

/*
 * The vendor-id and device-id are the properties associated with
 * the SCSI controller. This is used to identify a particular controller
 * like LSI1030.
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
	&envd_cpu0_fan,
	&envd_cpu1_fan,
	&envd_sys_out_fan,
	&envd_sys_in_fan,
	&envd_dimm_fan,
	NULL
};

static	env_disk_t	*envd_disks[] = {
	&envd_disk0,
	&envd_disk1,
	NULL
};

/*
 * ADM1031 speedrange map is indexed by a 2-bit value
 */
static int	adm_speedrange_map[] = {1, 2, 4, 8};

/*
 * ADM1031 devices
 */
static char	*hwm_devs[] = {
	CPU_HWM_DEVFS,	/* CPU_HWM_ID */
	SYS_HWM_DEVFS	/* SYS_HWM_ID */
};

/*
 * Fan names associated with each ADM1031 hwms - used to
 * print fault messages.
 */
static char	*hwm_fans[MAX_HWMS][2] = {
	{ENV_CPU0_FAN, ENV_CPU1_FAN},
	{ENV_SYSTEM_INTAKE_FAN, ENV_SYSTEM_OUT_FAN}
};

/*
 * Temperature sensors
 */
static env_sensor_t envd_sensors[] = {
	{ SENSOR_CPU0_DIE, SENSOR_CPU0_DIE_DEVFS, NULL,
	    CPU0_SENSOR_ID, CPU_HWM_ID, (void *)&envd_cpu0_fan, -1},
	{ SENSOR_CPU1_DIE, SENSOR_CPU1_DIE_DEVFS, NULL,
	    CPU1_SENSOR_ID, CPU_HWM_ID, (void *)&envd_cpu1_fan, -1},
	{ SENSOR_INT_AMB_0, SENSOR_INT_AMB_0_DEVFS, NULL,
	    INT_AMB0_SENSOR_ID, CPU_HWM_ID, NULL, -1},
	{ SENSOR_SYS_OUT, SENSOR_SYS_OUT_DEVFS, NULL,
	    SYS_OUT_SENSOR_ID, SYS_HWM_ID, (void *)&envd_sys_out_fan, -1},
	{ SENSOR_INT_AMB_1, SENSOR_INT_AMB_1_DEVFS, NULL,
	    INT_AMB1_SENSOR_ID, SYS_HWM_ID, NULL, -1},
	{ SENSOR_SYS_IN, SENSOR_SYS_IN_DEVFS, NULL,
	    SYS_IN_SENSOR_ID, SYS_HWM_ID, (void *)&envd_sys_in_fan, -1},
};
#define	N_ENVD_SENSORS	(sizeof (envd_sensors)/sizeof (envd_sensors[0]))

#define	NOT_AVAILABLE	"NA"

/*
 * ADM1031 macros
 */
#define	TACH_UNKNOWN	255
#define	FAN_OUT_OF_RANGE	(TACH_UNKNOWN)
#define	ADM_HYSTERISIS	5
#define	N_SEQ_TACH	15

#define	TMIN_MASK	(0xF8)
#define	TMIN_SHIFT	(3)
#define	TMIN_UNITS	(4)	/* increments of 4 degrees celsius */
#define	TRANGE_MASK	(0x7)

#define	TMIN(regval)	(((regval & TMIN_MASK) >> TMIN_SHIFT) * TMIN_UNITS)
#define	TRANGE(regval)	(regval & TRANGE_MASK)

#define	GET_TMIN_RANGE(tmin, trange) \
	((((tmin / TMIN_UNITS) & TMIN_MASK) << TMIN_SHIFT) | \
	(trange & TRANGE_MASK))

#define	TACH_ENABLE_MASK		(0x0C)
#define	ADM_SETFANSPEED_CONV(speed)	(15 * speed / 100)

/*
 * Tuneables
 */
#define	ENABLE	1
#define	DISABLE	0

int	monitor_disk_temp	= 1;	/* enabled */
static	int	disk_high_warn_temperature	= DISK_HIGH_WARN_TEMPERATURE;
static	int	disk_low_warn_temperature	= DISK_LOW_WARN_TEMPERATURE;
static	int	disk_high_shutdown_temperature	=
						DISK_HIGH_SHUTDOWN_TEMPERATURE;
static	int	disk_low_shutdown_temperature	= DISK_LOW_SHUTDOWN_TEMPERATURE;
static	int	disk_scan_interval		= DISK_SCAN_INTERVAL;

static int get_monitor_cpu_mode(ptree_rarg_t *parg, void *buf);
static int set_monitor_cpu_mode(ptree_warg_t *parg, const void *buf);
static int get_monitor_sys_mode(ptree_rarg_t *parg, void *buf);
static int set_monitor_sys_mode(ptree_warg_t *parg, const void *buf);
static int get_int_val(ptree_rarg_t *parg, void *buf);
static int set_int_val(ptree_warg_t *parg, const void *buf);
static int get_string_val(ptree_rarg_t *parg, void *buf);
static int set_string_val(ptree_warg_t *parg, const void *buf);
static int get_cpu_tach(ptree_rarg_t *parg, void *buf);
static int set_cpu_tach(ptree_warg_t *parg, const void *buf);
static int get_sys_tach(ptree_rarg_t *parg, void *buf);
static int set_sys_tach(ptree_warg_t *parg, const void *buf);

static int	shutdown_override	= 0;
static int	sensor_poll_interval	= SENSORPOLL_INTERVAL;
static int	warning_interval	= WARNING_INTERVAL;
static int	disk_warning_interval	= DISK_WARNING_INTERVAL;
static int	disk_warning_duration	= DISK_WARNING_DURATION;
static int	shutdown_interval	= SHUTDOWN_INTERVAL;
static int	disk_shutdown_interval	= DISK_SHUTDOWN_INTERVAL;
static int	ovtemp_monitor		= 1;	/* enabled */
static int	pm_monitor		= 1;	/* enabled */
static int	mon_fanstat		= 1;	/* enabled */

static int	cpu_mode;
static int	sys_mode;
static int	cpu_tach;
static int	sys_tach;
static char	shutdown_cmd[] = SHUTDOWN_CMD;

env_tuneable_t tuneables[] = {
	{"ovtemp-monitor", PICL_PTYPE_INT, &ovtemp_monitor,
	    &get_int_val, &set_int_val, sizeof (int)},

	{"pm-monitor", PICL_PTYPE_INT, &pm_monitor,
	    &get_int_val, &set_int_val, sizeof (int)},

	{"shutdown-override", PICL_PTYPE_INT, &shutdown_override,
	    &get_int_val, &set_int_val, sizeof (int)},

	{"cpu-hm-automode-enable", PICL_PTYPE_INT, &cpu_mode,
	    &get_monitor_cpu_mode, &set_monitor_cpu_mode,
	    sizeof (int)},

	{"sys-hm-automode-enable", PICL_PTYPE_INT, &sys_mode,
	    &get_monitor_sys_mode, &set_monitor_sys_mode,
	    sizeof (int)},

	{"sensor-poll-interval", PICL_PTYPE_INT,
	    &sensor_poll_interval,
	    &get_int_val, &set_int_val,
	    sizeof (int)},

	{"disk-scan-interval", PICL_PTYPE_INT,
	    &disk_scan_interval,
	    &get_int_val, &set_int_val,
	    sizeof (int)},

	{"warning-interval", PICL_PTYPE_INT, &warning_interval,
	    &get_int_val, &set_int_val,
	    sizeof (int)},

	{"shutdown-interval", PICL_PTYPE_INT, &shutdown_interval,
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

	{"cpu-tach-enable", PICL_PTYPE_INT, &cpu_tach,
	    &get_cpu_tach, &set_cpu_tach,
	    sizeof (int)},

	{"sys-tach-enable", PICL_PTYPE_INT, &sys_tach,
	    &get_sys_tach, &set_sys_tach,
	    sizeof (int)},

	{"monitor-fanstat", PICL_PTYPE_INT, &mon_fanstat,
	    &get_int_val, &set_int_val, sizeof (int)},

	{"monitor-disk-temp", PICL_PTYPE_INT, &monitor_disk_temp,
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
	    &get_int_val, &set_int_val, sizeof (int)},


};

/*
 * We use this to figure out how many tuneables there are
 * This is variable because the publishing routine needs this info
 * in piclenvsetup.c
 */
int	ntuneables = (sizeof (tuneables)/sizeof (tuneables[0]));

/*
 * Table Handling Code
 */
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
	/*
	 * If the temperature is outside the correction table
	 * then simply return the original value.
	 */
	if ((xval < xymap[0].x) || (xval > xymap[entries - 1].x))
		return (xval);
	if (xval == xymap[0].x)
		return (xymap[0].y);
	if (xval == xymap[entries - 1].x)
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
			return (EINVAL);
		}
		if (env_debug)
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
	return (0);
}

/*
 * Get all environmental segments
 * Return NULL on error
 */
static fruenvseg_t *
get_fru_envsegs(void)
{
	fruenvseg_t		*fruenvsegs;
	envseg_layout_t		*envsegp;
	void			*envsegbufp;
	int			fd, envseglen, hdrlen;
	char			path[PATH_MAX];

	fruenvsegs = NULL;
	fruenvsegs = malloc(sizeof (*fruenvsegs));
	if (fruenvsegs == NULL) {
		return (NULL);
	}

	/*
	 * Now get the environmental segment from this FRU
	 */
	(void) snprintf(path, sizeof (path), "%s%s", I2C_DEVFS, MBFRU_DEV);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		envd_log(LOG_ERR, ENV_FRU_OPEN_FAIL, errno, path);
		free(fruenvsegs);
		return (NULL);
	}

	/*
	 * Read environmental segment from this FRU SEEPROM
	 */
	if (get_envseg(fd, &envsegbufp, &envseglen) != 0) {
		envd_log(LOG_ERR, ENV_FRU_BAD_ENVSEG, path);
		free(fruenvsegs);
		(void) close(fd);
		return (NULL);
	}

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
		envd_log(LOG_CRIT, ENV_FRU_BAD_ENVSEG, FRU_SEEPROM_NAME);
		if (envsegbufp != NULL)
			(void) free(envsegbufp);
		free(fruenvsegs);
		(void) close(fd);
		return (NULL);
	}

	fruenvsegs->envseglen = envseglen;
	fruenvsegs->envsegbufp = envsegbufp;
	(void) close(fd);
	return (fruenvsegs);
}

static int
process_fru_seeprom(unsigned char *buff)
{
	id_off_t id;
	int  i;
	int  id_offset = 0;
	int  nsensors;
	int  nfans;
	env_fan_t *fnodep;
	env_sensor_t *snodep;

#define	NSENSOR_OFFSET	1
#define	ID_OFF_SIZE	6
#define	NFANS_OFFSET(x)	((x * ID_OFF_SIZE) + 2)

	nsensors = (int)buff[NSENSOR_OFFSET];
	if (nsensors != MAX_SENSORS) {
		envd_log(LOG_CRIT, ENV_FRU_BAD_ENVSEG, FRU_SEEPROM_NAME);
		return (-1);
	}

	nfans = (int)buff[NFANS_OFFSET(nsensors)];
	if (nfans != MAX_FANS) {
		envd_log(LOG_CRIT, ENV_FRU_BAD_ENVSEG, FRU_SEEPROM_NAME);
		return (-1);
	}

	while (nsensors > 0) {
		(void) memcpy((char *)&id,
		    (char *)&buff[id_offset + 2],
		    ID_OFF_SIZE);

		if (env_debug)
			envd_log(LOG_ERR, "\n Sensor Id %x offset %x",
			    id.id, id.offset);

		if (id.id > MAX_SENSOR_ID) {
			envd_log(LOG_CRIT, ENV_FRU_BAD_ENVSEG,
			    FRU_SEEPROM_NAME);
			return (-1);
		}

		/*
		 * Copy into the sensor control block array according to the
		 * sensor ID
		 */
		(void) memcpy((char *)&sensor_ctrl[id.id],
		    (char *)&buff[id.offset],
		    sizeof (sensor_ctrl_blk_t));
		nsensors--;
		id_offset += ID_OFF_SIZE;
	}

	/*
	 * Skip past no of Fan entry(single byte)
	 */
	id_offset++;
	while (nfans > 0) {
		(void) memcpy((char *)&id, (char *)&buff[id_offset + 2],
		    ID_OFF_SIZE);

		if (env_debug)
			envd_log(LOG_ERR, "\n Fan Id %x offset %x", id.id,
			    id.offset);

		if (id.id > 3) {
			envd_log(LOG_CRIT, ENV_FRU_BAD_ENVSEG,
			    FRU_SEEPROM_NAME);
			return (-1);
		}

		(void) memcpy((char *)&fan_ctrl[id.id],
		    (char *)&buff[id.offset], sizeof (fan_ctrl_blk_t));

		nfans--;
		id_offset += ID_OFF_SIZE;
	}

	/*
	 * Match Sensor/ES ID and point correct data
	 * based on IDs
	 */
	for (i = 0; i < N_ENVD_SENSORS; i++) {
		snodep = &envd_sensors[i];
		snodep->es_ptr = &sensor_ctrl[snodep->id];
	}

	/*
	 * Match Fan/ES ID and point to correct ES Data
	 * based on IDs
	 */
	for (i = 0; (fnodep = envd_fans[i]) != NULL; i++)
		fnodep->es_ptr = &fan_ctrl[fnodep->id];

	return (0);
}

static int
envd_es_setup(void)
{
	envfru = get_fru_envsegs();
	if (envfru == NULL) {
		envd_log(LOG_CRIT, ENV_FRU_BAD_ENVSEG, FRU_SEEPROM_NAME);
		return (-1);
	}
	return (process_fru_seeprom((uchar_t *)envfru->envsegbufp));
}

static void
envd_es_destroy(void)
{
	if (envfru != NULL)
		free(envfru->envsegbufp);
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
	int		i;

	for (i = 0; i < N_ENVD_SENSORS; ++i) {
		sensorp = &envd_sensors[i];
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
	if (sensorp->crtbl != NULL) {
		*temp = (tempr_t)y_of_x(sensorp->crtbl, *temp);
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
	else  {
		*temp = diskp->current_temp;
	}
	return (retval);
}

/*
 * Get uncorrected current temperature
 * Returns -1 on error, 0 if successful
 */
static int
get_raw_temperature(env_sensor_t *sensorp, tempr_t *temp)
{
	int	fd = sensorp->fd;
	int	retval = 0;

	if (fd == -1)
		retval = -1;
	else if (ioctl(fd, I2C_GET_TEMPERATURE, temp) == -1) {
		retval = -1;
	}

	return (retval);
}

/*
 * Return Fan RPM given N & tach
 * count and N are retrived from the
 * ADM1031 chip.
 */
static int
tach_to_rpm(int n, uint8_t tach)
{
	if (n * tach == 0)
		return (0);
	return ((ADCSAMPLE * 60) / (n * tach));
}

static int
get_raw_fan_speed(env_fan_t *fanp, uint8_t *fanspeedp)
{
	int	fan_fd;
	int	retval = 0;

	fan_fd = fanp->fd;

	if (fan_fd == -1)
		retval = -1;
	else if (ioctl(fan_fd, I2C_GET_FAN_SPEED, fanspeedp) == -1) {
		retval = -1;
	}


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
	int	fan_fd;
	uint8_t tach;

	fan_fd = fanp->fd;

	if (fan_fd == -1)
		return (-1);
	if (fanp->id == DIMM_FAN_ID) {
		return (get_dimm_fan_speed(fan_fd, fanspeedp));
	}
	if (ioctl(fan_fd, I2C_GET_FAN_SPEED, &tach) == -1) {
		return (-1);
	}

	/*
	 * Fanspeeds are reported as 0
	 * if the tach is out of range or fan status is off
	 * and if monitoring fan status is enabled.
	 */
	if (mon_fanstat && (!fanp->fanstat || tach == FAN_OUT_OF_RANGE)) {
		*fanspeedp = 0;
	} else {
		*fanspeedp =
		    tach_to_rpm(fanp->speedrange, tach);
	}

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
	int	fan_fd;
	int	retval = 0;
	uint8_t	speed;

	fan_fd = fanp->fd;
	if (fan_fd == -1)
		return (-1);

	if (fanspeed < 0 || fanspeed > 100)
		return (-2);

	speed = (uint8_t)ADM_SETFANSPEED_CONV(fanspeed);

	if (ioctl(fan_fd, I2C_SET_FAN_SPEED, &speed) == -1) {
		retval = -1;
	}
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
 * Close sensor devices and freeup resources
 */
static void
envd_close_sensors(void)
{
	env_sensor_t	*sensorp;
	int		i;

	for (i = 0; i < N_ENVD_SENSORS; ++i) {
		sensorp = &envd_sensors[i];
		if (sensorp->fd != -1) {
			(void) close(sensorp->fd);
			sensorp->fd = -1;
		}
		if (sensorp->crtbl != NULL)
			fini_table(sensorp->crtbl);
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
	env_fan_t	*fanp;
	char		path[PATH_MAX];
	int		fancnt = 0;
	uint8_t		n = 0;
	picl_nodehdl_t tnodeh;
	i2c_reg_t	i2c_reg;

	for (i = 0; (fanp = envd_fans[i]) != NULL; i++) {
		/* make sure cpu0/1 present for validating cpu fans */
		if (fanp->id == CPU0_FAN_ID) {
			if (ptree_get_node_by_path(CPU0_PATH, &tnodeh) !=
			    PICL_SUCCESS) {
				fanp->present = B_FALSE;
				continue;
			}
		}
		if (fanp->id == CPU1_FAN_ID) {
			if (ptree_get_node_by_path(CPU1_PATH, &tnodeh) !=
			    PICL_SUCCESS) {
				fanp->present = B_FALSE;
				continue;
			}
		}
		if (fanp->id == DIMM_FAN_ID) {
			if (ptree_get_node_by_path(DIMM_FAN_CONTROLLER_PATH,
			    &tnodeh) != PICL_SUCCESS) {
				if (env_debug)
					envd_log(LOG_ERR,
					    "dimm Fan not found in the "
					    "system.\n");
				fanp->present = B_FALSE;
				continue;
			}
		}
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
		fanp->fd = fd;
		if (fanp->id == DIMM_FAN_ID) {
			/*
			 * set the SW aware bit in command register.
			 * Clear the Fan fault latch bit.
			 */
			i2c_reg.reg_num = PIC16F819_COMMAND_REGISTER;
			i2c_reg.reg_value = (PIC16F819_SW_AWARE_MODE |
			    PIC16F819_FAN_FAULT_CLEAR);
			if (ioctl(fd, I2C_SET_REG, &i2c_reg) == -1) {
				if (env_debug)
					envd_log(LOG_ERR,
					    "Error in writing to COMMAND reg. "
					    "of DIMM FAN controller\n");
			}
		} else {
			/* Get speed range value */
			if (ioctl(fd, ADM1031_GET_FAN_FEATURE, &n) != -1) {
				fanp->speedrange =
				    adm_speedrange_map[(n >> 6) & 0x03];
			} else {
				fanp->speedrange = FAN_RANGE_DEFAULT;
			}
		}
		fanp->present = B_TRUE;
		fanp->fanstat = 0;
		fanp->cspeed = TACH_UNKNOWN;
		fanp->lspeed = TACH_UNKNOWN;
		fanp->conccnt = 0;
		fancnt++;
	}
	return (fancnt);
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

	/*
	 * Check if the SCSi controller on the system is 1010 or 1030
	 */

	if (ptree_get_node_by_path(SCSI_CONTROLLER_NODE_PATH,
	    &tnodeh) != PICL_SUCCESS) {
		if (env_debug)
			envd_log(LOG_ERR,
			    "On-Board SCSI controller not found "
			    "in the system.\n");
		monitor_disk_temp = 0;
		return (-1);
	}

	if ((ret = ptree_get_propval_by_name(tnodeh, VENDOR_ID,
	    &vendor_id, sizeof (vendor_id))) != 0) {
		if (env_debug)
			envd_log(LOG_ERR,
			    "Error in getting vendor-id for SCSI controller. "
			    "ret = %d errno = 0x%d\n",
			    ret, errno);
		monitor_disk_temp = 0;
		return (-1);
	}
	if ((ret = ptree_get_propval_by_name(tnodeh, DEVICE_ID,
	    &device_id, sizeof (device_id))) != 0) {
		if (env_debug)
			envd_log(LOG_ERR,
			    "Error in getting device-id for SCSI controller. "
			    "ret = %d errno = 0x%d\n", ret, errno);
		monitor_disk_temp = 0;
		return (-1);
	}
	if (env_debug)
		envd_log(LOG_ERR, "vendor-id=0x%x device-id=0x%x\n",
		    vendor_id, device_id);
	if ((vendor_id != LSI1030_VENDOR_ID) ||
	    (device_id != LSI1030_DEVICE_ID)) {
		monitor_disk_temp = 0;
		return (-1);
	}
	/*
	 * We have found LSI1030 SCSi controller onboard.
	 */

	for (i = 0; (diskp = envd_disks[i]) != NULL; i++) {

		if (ptree_get_node_by_path(diskp->nodepath,
		    &tnodeh) != PICL_SUCCESS) {
			diskp->present = B_FALSE;
			if (env_debug)
				envd_log(LOG_ERR,
				    "DISK %d not found in the system.\n",
				    diskp->id);
			continue;
		}
		diskp->fd = open(diskp->devfs_path, O_RDONLY);
		if (diskp->fd == -1) {
			diskp->present = B_FALSE;
			envd_log(LOG_ERR,
			    "Error in opening %s errno = 0x%x\n",
			    diskp->devfs_path, errno);
			continue;
		}
		diskp->present = B_TRUE;
		diskp->tpage_supported = B_FALSE;
		/*
		 * Find out if the Temperature page is supported by the disk.
		 */
		ret = scsi_log_sense(diskp->fd, SUPPORTED_LPAGES,
		    log_page, sizeof (log_page));
		if (ret != 0) {
			continue;
		}
		page_len = ((log_page[2] << 8) & 0xFF00) | log_page[3];

		for (page_index = LOGPAGEHDRSIZE;
		    page_index < page_len + LOGPAGEHDRSIZE; page_index++) {
			switch (log_page[page_index]) {
			case TEMPERATURE_PAGE:
				diskp->tpage_supported = B_TRUE;
				if (env_debug)
					envd_log(LOG_ERR,
					    "tpage supported for %s\n",
					    diskp->nodepath);
			default:
				break;
			}
		}
		diskp->warning_tstamp = 0;
		diskp->shutdown_tstamp = 0;
		diskp->high_warning = disk_high_warn_temperature;
		diskp->low_warning = disk_low_warn_temperature;
		diskp->high_shutdown = disk_high_shutdown_temperature;
		diskp->low_shutdown = disk_low_shutdown_temperature;
		ret = get_disk_temp(diskp);
	}
	return (0);
}

/*
 * Open temperature sensor devices and initialize per sensor data structure.
 * Returns #sensors found.
 */
static int
envd_setup_sensors(void)
{
	env_sensor_t	*sensorp;
	sensor_ctrl_blk_t *es_ptr;
	table_t		*tblp;
	char		path[PATH_MAX];
	int		sensorcnt = 0;
	int		i, j, nentries;
	int16_t		tmin = 0;
	picl_nodehdl_t tnodeh;

	for (i = 0; i < N_ENVD_SENSORS; ++i) {
		sensorp = &envd_sensors[i];
		/* Initialize sensor's initial state */
		sensorp->shutdown_initiated = B_FALSE;
		sensorp->warning_tstamp = 0;
		sensorp->shutdown_tstamp = 0;
		sensorp->error = 0;
		sensorp->crtbl = NULL;
		/* make sure cpu0/1 sensors are present */
		if (sensorp->id == CPU0_SENSOR_ID) {
			if (ptree_get_node_by_path(CPU0_PATH, &tnodeh) !=
			    PICL_SUCCESS) {
				sensorp->present = B_FALSE;
				continue;
			}
		}
		if (sensorp->id == CPU1_SENSOR_ID) {
			if (ptree_get_node_by_path(CPU1_PATH, &tnodeh) !=
			    PICL_SUCCESS) {
				sensorp->present = B_FALSE;
				continue;
			}
		}
		(void) strcpy(path, "/devices");
		(void) strlcat(path, sensorp->devfs_path,
		    sizeof (path));
		sensorp->fd = open(path, O_RDWR);
		if (sensorp->fd == -1) {
			envd_log(LOG_ERR, ENV_SENSOR_OPEN_FAIL,
			    sensorp->name, sensorp->devfs_path,
			    errno, strerror(errno));
			sensorp->present = B_FALSE;
			continue;
		}
		sensorp->present = B_TRUE;
		sensorcnt++;

		/*
		 * Get Tmin
		 */

		if (ioctl(sensorp->fd, ADM1031_GET_TEMP_MIN_RANGE,
		    &tmin) != -1) {
			sensorp->tmin = TMIN(tmin);
		} else {
			sensorp->tmin = -1;
		}
		if (env_debug)
			envd_log(LOG_ERR, "Sensor %s tmin %d",
			    sensorp->name, sensorp->tmin);

		/*
		 * Create a correction table
		 * if correction pairs are present in es
		 * segment.
		 */
		es_ptr = sensorp->es_ptr;

		if (es_ptr == NULL) {
			continue;
		}
		nentries = es_ptr->correctionEntries;

		if (nentries <= 2) {
			if (env_debug)
				envd_log(LOG_CRIT, "sensor correction <2");
			continue;
		}

		sensorp->crtbl = init_table(nentries);
		if (sensorp->crtbl == NULL)
			continue;
		tblp = sensorp->crtbl;
		tblp->xymap[0].x =
		    (char)es_ptr->correctionPair[0].measured;
		tblp->xymap[0].y =
		    (char)es_ptr->correctionPair[0].corrected;

		for (j = 1; j < nentries; ++j) {
			tblp->xymap[j].x =
			    (char)es_ptr->correctionPair[j].measured;
			tblp->xymap[j].y =
			    (char)es_ptr->correctionPair[j].corrected;

			if (tblp->xymap[j].x <= tblp->xymap[j - 1].x) {
				fini_table(tblp);
				sensorp->crtbl = NULL;
				envd_log(LOG_CRIT, ENV_FRU_BAD_ENVSEG,
				    FRU_SEEPROM_NAME);
				break;
			}
		}

		if (env_debug) {
			envd_log(LOG_CRIT, "Sensor correction  %s",
			    sensorp->name);
			for (j = 0; j < nentries; j++)
				envd_log(LOG_CRIT, " %d	%d",
				    tblp->xymap[j].x, tblp->xymap[j].y);
		}
	}
	return (sensorcnt);
}

/*
 * Modify ADM Tmin/ranges depending what power level
 * we are from.
 */
static void
updateadm_ranges(char *name, uchar_t cur_lpstate)
{
	env_sensor_t *sensorp;
	fan_ctrl_blk_t *fanctl;
	uchar_t tmin;
	uchar_t trange;
	uint16_t tdata;
	int sysfd;
	uchar_t sys_id = SYS_HWM_ID;
	uint8_t mode;
	static uint16_t tsave[2] = {0, 0};
	/* Index of saved Tmin/Trange for two sensors */
	uint16_t tindex = 0;

	sensorp = sensor_lookup(name);
	if (sensorp == NULL)
		return;

	/*
	 * If there is only one Control pairs then return
	 */
	fanctl = ((env_fan_t *)sensorp->fanp)->es_ptr;

	if (fanctl != NULL && fanctl->no_ctl_pairs <= 1)
		return;

	/*
	 * if fan control specifies that ranges are same then
	 * we skip re-programming adm chip.
	 */

	tmin = fanctl->fan_ctl_pairs[0].tMin;
	trange = fanctl->fan_ctl_pairs[0].tRange;
	if ((tmin == fanctl->fan_ctl_pairs[1].tMin) &&
	    (trange == fanctl->fan_ctl_pairs[1].tRange))
			return;

	sysfd = open(hwm_devs[sys_id], O_RDWR);
	if (sysfd == -1) {
		if (env_debug)
			envd_log(LOG_ERR, ENV_ADM_OPEN_FAIL, hwm_devs[sys_id],
			    errno, strerror(errno));
		return;
	}
	tindex = ((strcmp(name, SENSOR_SYS_IN) == 0) ? 0 : 1);

	/* Read ADM default value only for the first time */
	if (tsave[tindex] == 0) {
		if (ioctl(sensorp->fd, ADM1031_GET_TEMP_MIN_RANGE,
		    &tsave[tindex]) == -1) {
			if (env_debug)
				envd_log(LOG_ERR,
				    "read tminrange ioctl failed");
			(void) close(sysfd);
			return;
		}
	}
	/*
	 * Need to reinit ADM to manual mode for Tmin range to be
	 * effective.
	 */
	mode = ADM1031_MANUAL_MODE;
	if (ioctl(sysfd, ADM1031_SET_MONITOR_MODE, &mode) == -1) {
		if (env_debug)
			envd_log(LOG_ERR, ENV_ADM_MANUAL_MODE);
		(void) close(sysfd);
		return;
	}

	if (cur_lpstate == 1) {
		/*
		 * ADM 1031 Tmin/Trange register need to be reprogrammed.
		 */
		tdata = ((fanctl->fan_ctl_pairs[cur_lpstate].tMin / TMIN_UNITS)
		    << TMIN_SHIFT);
		/* Need to pack tRange in ADM bits 2:0 */
		switch (fanctl->fan_ctl_pairs[cur_lpstate].tRange) {
		case 5:
			break;

		case 10:
			tdata |= 1;
			break;

		case 20:
			tdata |= 2;
			break;

		case 40:
			tdata |= 3;
			break;

		case 80:
			tdata |= 4;
			break;
		}
	} else
		tdata = tsave[tindex];

	if (ioctl(sensorp->fd, ADM1031_SET_TEMP_MIN_RANGE,
	    &tdata) != -1)
		sensorp->tmin = TMIN(tdata);

	mode = ADM1031_AUTO_MODE;
	if (ioctl(sysfd, ADM1031_SET_MONITOR_MODE, &mode) == -1) {
		if (env_debug)
			envd_log(LOG_ERR, ENV_ADM_AUTO_MODE);
	}
	(void) close(sysfd);
}

/* ARGSUSED */
static void *
pmthr(void *args)
{
	pm_state_change_t	pmstate;
	char			physpath[PATH_MAX];
	int				pre_lpstate;

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
		 * is in lowest power state and adjust ADM hardware
		 * monitor's fan speed settings.
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
		/*
		 * Change ADM ranges as per E* Requirements. Update
		 * happens only for valid state changes.
		 */
		if (pre_lpstate != cur_lpstate) {
			pre_lpstate = cur_lpstate;
			updateadm_ranges(SENSOR_SYS_OUT, cur_lpstate);
			updateadm_ranges(SENSOR_SYS_IN, cur_lpstate);
		}
	}
	/* Not reached */
	return (NULL);
}

/*
 * This function is used to reasonably predict the
 * state of the fan (ON/OFF) using tmin and current temperature.
 *
 * We know the fan is on  if temp >= tmin and fan is off if
 * temp < (Tmin - Hysterisis).
 *
 * When the temperature is in between we don't know if the fan is on/off
 * because the temperature could be decreasing and not have crossed
 * Tmin - hysterisis and vice a versa.
 *
 *			FAN ON
 * Tmin
 *	-------------------------------------------
 *
 *			FAN ON/OFF
 *
 *	--------------------------------------------
 * Tmin - Hysterisis
 *			FAN OFF
 *
 * To solve the problem of finding out if the fan is on/off in our gray region
 * we keep track of the last read tach and the current read tach. From
 * experimentation and from discussions with analog devices it is unlikely that
 * if the fans are on we will get a constant tach reading  more than 5 times in
 * a row. This is not but the most fool proof approach but the  best we can do.
 *
 * This routine implements the above logic for a sensor with an
 * associated fan. The caller garauntees sensorp and fanp are not null.
 */

static void
check_fanstat(env_sensor_t *sensorp)
{
	env_fan_t *fanp = sensorp->fanp;
	tempr_t	temp;
	uint8_t fanspeed;

	if (get_raw_temperature(sensorp, &temp) == -1)
		return;

	if (temp < (sensorp->tmin - ADM_HYSTERISIS)) {

		fanp->fanstat = 0;		/* Fan off */
		fanp->lspeed = TACH_UNKNOWN;	/* Reset Last read tach */
		fanp->conccnt = 0;

	} else if (temp >= sensorp->tmin) {

		fanp->fanstat = 1;		/* Fan on */
		fanp->lspeed = TACH_UNKNOWN;
		fanp->conccnt = 0;

	} else {
		if (get_raw_fan_speed(fanp, &fanspeed) == -1)
			return;

		fanp->cspeed = fanspeed;
		/*
		 * First time in the gray area
		 * set last read speed to current speed
		 */
		if (fanp->lspeed == TACH_UNKNOWN) {
			fanp->lspeed = fanspeed;
		} else {
			if (fanp->lspeed != fanp->cspeed) {
				fanp->conccnt = 0;
				fanp->fanstat = 1;
			} else {
				fanp->conccnt++;

				if (fanp->conccnt >= N_SEQ_TACH)
					fanp->fanstat = 0;
			}
			fanp->lspeed = fanp->cspeed;
		}
	}
}
/*
 * There is an issue with the ADM1031 chip that causes the chip
 * to not update the tach register in case the fan stops. The
 * fans stop when the temperature measured (temp) drops below
 * Tmin - Hysterisis  and turn on when the temp >= Tmin.
 *
 * Since the tach registers don't update and remain stuck at the
 * last read tach value our get_fan_speed function always returns
 * a non-zero RPM reading.
 *
 * To fix this we need to figure out when the fans will be on/off
 * depending on the current temperature. Currently we poll for
 * interrupts, we can use that loop to determine what the current
 * temperature is and if the fans should be on/off.
 *
 * We get current temperature and check the fans.
 */
static void
monitor_fanstat(void)
{
	env_sensor_t *sensorp;
	env_fan_t *fanp;
	int i;

	for (i = 0; i < N_ENVD_SENSORS; i++) {
		sensorp = &envd_sensors[i];

		if (!sensorp)
			continue;

		fanp = sensorp->fanp;

		if (!(fanp && fanp->present))
			continue;

		if (sensorp->tmin != -1) {
			check_fanstat(sensorp);
		} else {
			fanp->fanstat = 1;
		}

	}
}

static int
handle_overtemp_interrupt(int hwm_id)
{
	env_sensor_t *sensorp;
	tempr_t  temp;
	uchar_t smap[MAX_SENSORS];
	time_t  ct;
	uchar_t i;
	char msgbuf[BUFSIZ];
	char syscmd[BUFSIZ];
	boolean_t return_flag;
	int	ret;
	timespec_t	to;
	pthread_mutex_t	env_monitor_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t	env_monitor_cv = PTHREAD_COND_INITIALIZER;

	/* Clear Map of Sensor Entries */
	(void) memset(smap, SENSOR_OK, sizeof (smap));

	for (;;) {
		for (i = 0; i < N_ENVD_SENSORS; i++) {
			sensorp = &envd_sensors[i];

			/*
			 * Check whether the sensor belongs to the
			 * interrupting ADM hardware monitor
			 */
			if (sensorp->hwm_id != hwm_id)
				continue;

			if (sensorp->present == B_FALSE)
				continue;
			/*
			 * if shutdown is initiated then we simply loop
			 * through the sensors until shutdown
			 */
			if (sensorp->shutdown_initiated == B_TRUE)
				continue;

			/* get current temp for this sensor */
			if (get_temperature(sensorp, &temp) == -1)
				continue;

			sensorp->cur_temp = temp;

			if (env_debug)
				envd_log(LOG_ERR,
				    "sensor name %s, cur temp %d, "
				    "HW %d LW %d SD %d LS %d\n",
				    sensorp->name, temp,
				    sensorp->es_ptr->high_warning,
				    (int)sensorp->es_ptr->low_warning,
				    sensorp->es_ptr->high_shutdown,
				    (int)sensorp->es_ptr->low_shutdown);

			if (TEMP_IN_WARNING_RANGE(sensorp->cur_temp, sensorp)) {
				/*
				 * Log on warning atmost one second
				 */
				ct = (time_t)(gethrtime() / NANOSEC);
				if ((ct - sensorp->warning_tstamp) >=
				    warning_interval) {
					envd_log(LOG_CRIT,
					    ENV_WARNING_MSG, sensorp->name,
					    temp,
					    sensorp->es_ptr->low_warning,
					    sensorp->es_ptr->high_warning);
					sensorp->warning_tstamp = ct;
				}
				smap[i] = SENSOR_WARN;
			} else {
				/*
				 * We will fall in this caterory only if
				 * Temperature drops/increases from warning
				 * threshold. If so we set sensor map to
				 * OK so that we can exit the loop if
				 * shutdown not initiated.
				 */
				smap[i] = SENSOR_OK;
			}

			if (TEMP_IN_SHUTDOWN_RANGE(temp, sensorp) &&
			    !shutdown_override) {
				ct = (time_t)(gethrtime() / NANOSEC);
				if (sensorp->shutdown_tstamp == 0)
					sensorp->shutdown_tstamp = ct;
				if ((ct - sensorp->shutdown_tstamp) >=
				    shutdown_interval) {
					sensorp->shutdown_initiated = B_TRUE;
					(void) snprintf(msgbuf, sizeof (msgbuf),
					    ENV_SHUTDOWN_MSG, sensorp->name,
					    temp,
					    sensorp->es_ptr->low_shutdown,
					    sensorp->es_ptr->high_shutdown);
					envd_log(LOG_ALERT, msgbuf);
				}
				if (system_shutdown_started == B_FALSE) {
					(void) snprintf(syscmd, sizeof (syscmd),
					    "%s \"%s\"", SHUTDOWN_CMD, msgbuf);
					envd_log(LOG_ALERT, syscmd);
					system_shutdown_started = B_TRUE;
					(void) system(syscmd);
				}
			} else if (sensorp->shutdown_tstamp != 0)
				sensorp->shutdown_tstamp = 0;
		}

		/*
		 * Sweep thorugh Sensor Map and if warnings OR shutdown
		 * are not logged then return to caller.
		 */
		return_flag = B_TRUE;
		for (i = 0; i < N_ENVD_SENSORS; i++)
			if (smap[i] == SENSOR_WARN)
				return_flag = B_FALSE;

		if ((return_flag == B_TRUE) &&
		    (system_shutdown_started == B_FALSE)) {
			return (1);
		}

wait_till_timeout:
		/*
		 * We use pthread_cond_reltimedwait_np to sleep for
		 * fixed interval of time.
		 * earlier implementation used alarm() call which
		 * fails in Multi threaded environment. If multiple
		 * threads call alarm() only one of the threads is
		 * sent the SIGALRM signal.
		 */
		(void) pthread_mutex_lock(&env_monitor_mutex);
		ret = pthread_cond_reltimedwait_np(&env_monitor_cv,
		    &env_monitor_mutex, &to);
		to.tv_sec = SENSORPOLL_INTERVAL;
		to.tv_nsec = 0;
		if (ret != ETIMEDOUT) {
			(void) pthread_mutex_unlock(&env_monitor_mutex);
			goto wait_till_timeout;
		}
		(void) pthread_mutex_unlock(&env_monitor_mutex);
	}
}

/*
 * This is env thread which monitors the current temperature when
 * warning threshold is exceeded. The job is to make sure it does
 * not execced/decrease shutdown threshold. If it does it will start
 * forced shutdown to avoid reaching hardware poweroff via THERM interrupt.
 * For Enchilada there will be two threads, one for each ADM chip.
 */
static void *
ovtemp_thr(void *args)
{
	int	fd;
	uint8_t stat[2];
	int	hwm_id = (int)args;
	int    err;
	env_fan_t *fanp;
	timespec_t	to;
	int	ret;
	pthread_mutex_t	env_monitor_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t	env_monitor_cv = PTHREAD_COND_INITIALIZER;

	fd = open(hwm_devs[hwm_id], O_RDWR);
	if (fd == -1) {
		envd_log(LOG_ERR, ENV_ADM_OPEN_FAIL, hwm_devs[hwm_id],
		    errno, strerror(errno));
		return (NULL);
	}
	if (env_debug)
		envd_log(LOG_ERR, "ovtemp thread for %s running...\n",
		    hwm_devs[hwm_id]);

	for (;;) {
		/*
		 * Sleep for specified seconds before issuing IOCTL
		 * again.
		 */

		/*
		 * We use pthread_cond_reltimedwait_np to sleep for
		 * fixed interval of time.
		 * earlier implementation used alarm() call which
		 * fails in Multi threaded environment. If multiple
		 * threads call alarm() only one of the threads is
		 * sent the SIGALRM signal.
		 */
		(void) pthread_mutex_lock(&env_monitor_mutex);
		ret = pthread_cond_reltimedwait_np(&env_monitor_cv,
		    &env_monitor_mutex, &to);
		to.tv_sec = INTERRUPTPOLL_INTERVAL;
		to.tv_nsec = 0;
		if (ret != ETIMEDOUT) {
			(void) pthread_mutex_unlock(&env_monitor_mutex);
			continue;
		}
		(void) pthread_mutex_unlock(&env_monitor_mutex);
		/*
		 * Monitor the sensors to update fan status
		 */
		if (mon_fanstat)
			monitor_fanstat();

		/*
		 * Read ADM1031 two Status Registers to determine source
		 * of Interrupts.
		 */

		if ((err = ioctl(fd, ADM1031_GET_STATUS_1, &stat[0])) != -1)
			err = ioctl(fd, ADM1031_GET_STATUS_2, &stat[1]);

		if (err == -1) {
			if (env_debug)
				envd_log(LOG_ERR,
				    "OverTemp: Status Error");
			continue;
		}

		if (env_debug)
			envd_log(LOG_ERR, "INTR %s, Stat1 %x, Stat2 %x",
			    hwm_devs[hwm_id], stat[0], stat[1]);

		if (stat[0] & FANFAULT) {
			fanp = fan_lookup(hwm_fans[hwm_id][HWM_FAN1]);
			if (fanp && fanp->present)
				envd_log(LOG_ERR, ENV_FAN_FAULT,
				    hwm_devs[hwm_id],
				    hwm_fans[hwm_id][HWM_FAN1]);
		}
		if (stat[1] & FANFAULT) {
			fanp = fan_lookup(hwm_fans[hwm_id][HWM_FAN2]);
			if (fanp && fanp->present)
				envd_log(LOG_ERR, ENV_FAN_FAULT,
				    hwm_devs[hwm_id],
				    hwm_fans[hwm_id][HWM_FAN2]);
		}
		/*
		 * Check respective Remote/Local High, Low before start
		 * manual monitoring
		 */
		if ((stat[0] & STAT1MASK) || (stat[1] & STAT2MASK))
			(void) handle_overtemp_interrupt(hwm_id);

	}	/* end of for ever loop */
	/*NOTREACHED*/
	return (NULL);
}

static void *
dimm_fan_thr(void *args)
{
	char syscmd[BUFSIZ];
	char msgbuf[BUFSIZ];
	i2c_reg_t	i2c_reg;
	timespec_t	to;
	int	ret;
	pthread_mutex_t	env_monitor_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t	env_monitor_cv = PTHREAD_COND_INITIALIZER;

	for (;;) {
		/*
		 * Sleep for specified seconds before issuing IOCTL
		 * again.
		 */
		(void) pthread_mutex_lock(&env_monitor_mutex);
		ret = pthread_cond_reltimedwait_np(&env_monitor_cv,
		    &env_monitor_mutex, &to);
		to.tv_sec = INTERRUPTPOLL_INTERVAL;
		to.tv_nsec = 0;
		if (ret != ETIMEDOUT) {
			(void) pthread_mutex_unlock(&env_monitor_mutex);
			continue;
		}
		(void) pthread_mutex_unlock(&env_monitor_mutex);
		/*
		 * We write to the comand register periodically
		 * to inform the PIC firmware that Solaris is
		 * Monitoring the dimm fan periodically.
		 */
		i2c_reg.reg_num = PIC16F819_COMMAND_REGISTER;
		i2c_reg.reg_value = PIC16F819_SW_AWARE_MODE;
		if (ioctl(envd_dimm_fan.fd,
		    I2C_SET_REG, &i2c_reg) == -1) {
			if (env_debug)
				envd_log(LOG_ERR,
				    "Error in writing to COMMAND reg. "
				    "of DIMM FAN controller\n");
		}
		/*
		 * We initiate shutdown if fan status indicates
		 * failure.
		 */
		if (is_dimm_fan_failed() != 0) {
			/*
			 * Mark Dimm fan present as False so that we
			 * do not WARN the user of the Fan failure
			 * repeatedly.
			 */
			envd_dimm_fan.present = B_FALSE;
			(void) snprintf(msgbuf, sizeof (msgbuf),
			    ENV_DIMM_FAN_FAILURE_SHUTDOWN_MSG,
			    ENV_DIMM_FAN,
			    dimm_fan_rpm_string, dimm_fan_status_string,
			    dimm_fan_command_string,
			    dimm_fan_debug_string);
			envd_log(LOG_ALERT, msgbuf);

			if (system_shutdown_started == B_FALSE) {
				system_shutdown_started = B_TRUE;
				(void) snprintf(syscmd, sizeof (syscmd),
				    "%s \"%s\"",
				    SHUTDOWN_CMD,
				    msgbuf);
				envd_log(LOG_ALERT, syscmd);
				(void) system(syscmd);
			}
		}
	}
	/*NOTREACHED*/
	return (NULL);
}
static int
scsi_log_sense(int fd, uchar_t page_code, uchar_t *pagebuf, uint16_t pagelen)
{
	struct uscsi_cmd	ucmd_buf;
	uchar_t		cdb_buf[CDB_GROUP1];
	struct	scsi_extended_sense	sense_buf;
	int	ret_val;

	bzero((void *)&cdb_buf, sizeof (cdb_buf));
	bzero((void *)&ucmd_buf, sizeof (ucmd_buf));
	bzero((void *)&sense_buf, sizeof (sense_buf));

	cdb_buf[0] = SCMD_LOG_SENSE_G1;
	cdb_buf[2] = (0x01 << 6) | page_code;
	cdb_buf[7] = (uchar_t)((pagelen & 0xFF00) >> 8);
	cdb_buf[8] = (uchar_t)(pagelen  & 0x00FF);

	ucmd_buf.uscsi_cdb = (char *)cdb_buf;
	ucmd_buf.uscsi_cdblen = sizeof (cdb_buf);
	ucmd_buf.uscsi_bufaddr = (caddr_t)pagebuf;
	ucmd_buf.uscsi_buflen = pagelen;
	ucmd_buf.uscsi_rqbuf = (caddr_t)&sense_buf;
	ucmd_buf.uscsi_rqlen = sizeof (struct scsi_extended_sense);
	ucmd_buf.uscsi_flags = USCSI_RQENABLE | USCSI_READ | USCSI_SILENT;
	ucmd_buf.uscsi_timeout = 60;

	ret_val = ioctl(fd, USCSICMD, ucmd_buf);
	if (ret_val == 0 && ucmd_buf.uscsi_status == 0) {
		if (env_debug)
			envd_log(LOG_ERR,
			    "log sense command for page_code 0x%x succeeded\n",
			    page_code);
		return (ret_val);
	}
	if (env_debug)
		envd_log(LOG_ERR,
		    "log sense command failed.ret_val = 0x%x status = 0x%x "
		    "errno = 0x%x\n",
		    ret_val, ucmd_buf.uscsi_status, errno);
	return (1);
}

static int
get_disk_temp(env_disk_t *diskp)
{
	int	ret;
	uchar_t	tpage[256];

	ret = scsi_log_sense(diskp->fd,
	    TEMPERATURE_PAGE,
	    tpage, sizeof (tpage));
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

	disk_pm_fd = open(PM_DEVICE, O_RDWR);
	if (disk_pm_fd == -1) {
		envd_log(LOG_ERR,
		    DISK_TEMP_THREAD_EXITING,
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
			(void) pthread_mutex_unlock(&env_monitor_mutex);
			continue;
		}
		(void) pthread_mutex_unlock(&env_monitor_mutex);
		for (i = 0; (diskp = envd_disks[i]) != NULL; i++) {
			if (diskp->present == B_FALSE)
				continue;
			if (diskp->tpage_supported == B_FALSE)
				continue;
			/*
			 * If the disk temperature is above the warning
			 * threshold continue monitoring until the temperature
			 * drops below warning threshold.
			 * If the temperature is in the NORMAL range monitor
			 * only when the disk is BUSY.
			 * We do not want to read the disk temperature if the
			 * disk is is idling. The reason for this is disk will
			 * never get into lowest power mode if we scan the disk
			 * temperature peridoically.
			 * To avoid this situation we first determine
			 * the idle_time of the disk. If the disk has been
			 * IDLE since we scanned the temperature last time
			 * we will not read the temperature.
			 */
			if (!DISK_TEMP_IN_WARNING_RANGE(diskp->current_temp,
			    diskp)) {
				pmstate.physpath = diskp->physpath;
				pmstate.size = strlen(diskp->physpath);
				pmstate.component = 0;
				if ((idle_time =
				    ioctl(disk_pm_fd,
				    PM_GET_TIME_IDLE, &pmstate)) == -1) {
					if (errno != EINTR) {
						if (env_debug) {
							envd_log(LOG_ERR,
							    "ioctl "
							    "PM_GET_TIME_IDLE "
							    "failed for DISK0."
							    " errno=0x%x\n",
							    errno);
						}
						continue;
					}
					continue;
				}
				if (idle_time >= (disk_scan_interval/2)) {
					if (env_debug) {
						envd_log(LOG_ERR,
						    "%s idle time = %d\n",
						    diskp->name, idle_time);
					}
					continue;
				}
			}
			ret = get_disk_temp(diskp);
			if (ret != 0)
				continue;
			if (env_debug) {
				envd_log(LOG_ERR,
				    "%s temp = %d ref. temp = %d\n",
				    diskp->name, diskp->current_temp,
				    diskp->ref_temp);
			}
			/*
			 * If this disk already triggered system shutdown, don't
			 * log any more shutdown/warning messages for it.
			 */
			if (diskp->shutdown_initiated)
				continue;

			/*
			 * Check for the temperature in warning and shutdown
			 * range and take appropriate action.
			 */
			if (DISK_TEMP_IN_WARNING_RANGE(diskp->current_temp,
			    diskp)) {
				/*
				 * Check if the temperature has been in warning
				 * range during last disk_warning_duration
				 * interval.
				 * If so, the temperature is truly in warning
				 * range and we need to log a warning message,
				 * but no more than once every
				 * disk_warning_interval seconds.
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
			    DISK_TEMP_IN_SHUTDOWN_RANGE(diskp->current_temp,
			    diskp)) {
				ct = (time_t)(gethrtime() / NANOSEC);
				if (diskp->shutdown_tstamp == 0)
					diskp->shutdown_tstamp = ct;

				/*
				 * Shutdown the system if the temperature
				 * remains in the shutdown range for over
				 * disk_shutdown_interval seconds.
				 */
				if ((ct - diskp->shutdown_tstamp) >=
				    disk_shutdown_interval) {
					/* log error */
					diskp->shutdown_initiated = B_TRUE;
					(void) snprintf(msgbuf, sizeof (msgbuf),
					    ENV_SHUTDOWN_MSG, diskp->name,
					    diskp->current_temp,
					    diskp->low_shutdown,
					    diskp->high_shutdown);
					envd_log(LOG_ALERT, msgbuf);

					/* shutdown the system (only once) */
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
			} else if (diskp->shutdown_tstamp != 0)
				diskp->shutdown_tstamp = 0;

		}
	}	/* end of forever loop */
}

/*
 * Setup envrionmental monitor state and start threads to monitor
 * temperature and power management state.
 * Returns -1 on error, 0 if successful.
 */
static int
envd_setup(void)
{
	int	ret;

	if (getenv("SUNW_piclenvd_debug") != NULL)
			env_debug = 1;

	if (pthread_attr_init(&thr_attr) != 0 ||
	    pthread_attr_setscope(&thr_attr, PTHREAD_SCOPE_SYSTEM) != 0) {
		return (-1);
	}

	ret = envd_es_setup();
	if (ret < 0) {
		ovtemp_monitor = 0;
		pm_monitor = 0;
	}

	/*
	 * Setup temperature sensors and fail if we can't open
	 * at least one sensor.
	 */
	if (envd_setup_sensors() <= 0) {
		return (0);
	}

	/*
	 * Setup fan device (don't fail even if we can't access
	 * the fan as we can still monitor temeperature.
	 */
	(void) envd_setup_fans();

	(void) envd_setup_disks();

	/* If ES Segment setup failed,don't create  thread */

	if (ovtemp_monitor && ovtemp_thr1_created == B_FALSE) {
		if (pthread_create(&ovtemp_thr1_id, &thr_attr, ovtemp_thr,
		    (void *)CPU_HWM_ID) != 0)
			envd_log(LOG_ERR, ENVTHR_THREAD_CREATE_FAILED);
		else
			ovtemp_thr1_created = B_TRUE;
	}

	if (ovtemp_monitor && ovtemp_thr2_created == B_FALSE) {
		if (pthread_create(&ovtemp_thr2_id, &thr_attr, ovtemp_thr,
		    (void *)SYS_HWM_ID) != 0)
			envd_log(LOG_ERR, ENVTHR_THREAD_CREATE_FAILED);
		else
			ovtemp_thr2_created = B_TRUE;
	}

	if (envd_dimm_fan.present) {
		if (dimm_fan_thr_created == B_FALSE) {
			if (pthread_create(&dimm_fan_thr_id, &thr_attr,
			    dimm_fan_thr, NULL) != 0)
				envd_log(LOG_ERR, ENVTHR_THREAD_CREATE_FAILED);
			else
				dimm_fan_thr_created = B_TRUE;
		}
	}

	/*
	 * Create a thread to monitor PM state
	 */
	if (pm_monitor && pmthr_created == B_FALSE) {
		if (pthread_create(&pmthr_tid, &thr_attr, pmthr,
		    NULL) != 0)
			envd_log(LOG_CRIT, PM_THREAD_CREATE_FAILED);
		else
			pmthr_created = B_TRUE;
	}
	if (monitor_disk_temp) {
		if (disk_temp_thr_created == B_FALSE) {
			if (pthread_create(&disk_temp_thr_id, &thr_attr,
			    disk_temp_thr, NULL) != 0)
				envd_log(LOG_ERR, ENVTHR_THREAD_CREATE_FAILED);
			else
				disk_temp_thr_created = B_TRUE;
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
	envd_es_destroy();
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
get_cpu_tach(ptree_rarg_t *parg, void *buf)
{
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;
	int		fd;
	int8_t		cfg;

	proph = parg->proph;

	tuneablep = tuneable_lookup(proph);

	if (tuneablep == NULL)
		return (PICL_FAILURE);

	fd = open(CPU_HWM_DEVFS, O_RDWR);

	if (fd == -1) {
		return (PICL_FAILURE);
	}

	if (ioctl(fd, ADM1031_GET_CONFIG_2, &cfg) == -1) {
		return (PICL_FAILURE);
	}

	if ((cfg & TACH_ENABLE_MASK) == TACH_ENABLE_MASK) {
		*((int *)tuneablep->value) = ENABLE;
	} else {
		*((int *)tuneablep->value) = DISABLE;
	}

	(void) memcpy(buf, tuneablep->value,
	    tuneablep->nbytes);

	(void) close(fd);
	return (PICL_SUCCESS);
}

static int
set_cpu_tach(ptree_warg_t *parg, const void *buf)
{
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;
	int		 fd, val;
	int8_t		 cfg;

	if (parg->cred.dc_euid != 0)
		return (PICL_PERMDENIED);

	proph = parg->proph;

	tuneablep = tuneable_lookup(proph);

	if (tuneablep == NULL)
		return (PICL_FAILURE);


	fd = open(CPU_HWM_DEVFS, O_RDWR);

	if (fd == -1) {
		return (PICL_FAILURE);
	}

	if (ioctl(fd, ADM1031_GET_CONFIG_2, &cfg) == -1) {
		return (PICL_FAILURE);
	}

	(void) memcpy(&val, (caddr_t)buf, sizeof (val));

	if (val == ENABLE) {
		cfg |= TACH_ENABLE_MASK;
	} else if (val == DISABLE) {
		cfg &= ~TACH_ENABLE_MASK;
	}


	if (ioctl(fd, ADM1031_SET_CONFIG_2, &cfg) == -1) {
		return (PICL_FAILURE);
	}

	(void) close(fd);
	return (PICL_SUCCESS);
}

static int
get_sys_tach(ptree_rarg_t *parg, void *buf)
{
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;
	int		fd;
	int8_t		cfg;

	proph = parg->proph;

	tuneablep = tuneable_lookup(proph);

	if (tuneablep == NULL)
		return (PICL_FAILURE);

	fd = open(SYS_HWM_DEVFS, O_RDWR);

	if (fd == -1) {
		return (PICL_FAILURE);
	}

	if (ioctl(fd, ADM1031_GET_CONFIG_2, &cfg) == -1) {
		return (PICL_FAILURE);
	}

	if ((cfg & TACH_ENABLE_MASK) == TACH_ENABLE_MASK) {
		*((int *)tuneablep->value) = ENABLE;
	} else {
		*((int *)tuneablep->value) = DISABLE;
	}

	(void) memcpy(buf, tuneablep->value,
	    tuneablep->nbytes);

	(void) close(fd);
	return (PICL_SUCCESS);
}

static int
set_sys_tach(ptree_warg_t *parg, const void *buf)
{
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;
	int		fd, val;
	int8_t		cfg;

	if (parg->cred.dc_euid != 0)
		return (PICL_PERMDENIED);

	proph = parg->proph;

	tuneablep = tuneable_lookup(proph);

	if (tuneablep == NULL)
		return (PICL_FAILURE);


	fd = open(SYS_HWM_DEVFS, O_RDWR);

	if (fd == -1) {
		return (PICL_FAILURE);
	}

	if (ioctl(fd, ADM1031_GET_CONFIG_2, &cfg) == -1) {
		return (PICL_FAILURE);
	}

	(void) memcpy(&val, buf, sizeof (val));

	if (val == ENABLE) {
		cfg |= TACH_ENABLE_MASK;
	} else if (val == DISABLE) {
		cfg &= ~TACH_ENABLE_MASK;
	}


	if (ioctl(fd, ADM1031_SET_CONFIG_2, &cfg) == -1) {
		return (PICL_FAILURE);
	}

	(void) close(fd);
	return (PICL_SUCCESS);
}

static int
get_monitor_cpu_mode(ptree_rarg_t *parg, void *buf)
{
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;
	int		fd;
	int8_t		mmode;

	proph = parg->proph;

	tuneablep = tuneable_lookup(proph);

	if (tuneablep == NULL)
		return (PICL_FAILURE);

	fd = open(CPU_HWM_DEVFS, O_RDWR);

	if (fd == -1) {
		return (PICL_FAILURE);
	}

	if (ioctl(fd, ADM1031_GET_MONITOR_MODE, &mmode) == -1) {
		return (PICL_FAILURE);
	}

	if (mmode == ADM1031_AUTO_MODE) {
		*((int *)tuneablep->value) = ENABLE;
	} else {
		*((int *)tuneablep->value) = DISABLE;
	}

	(void) memcpy(buf, tuneablep->value,
	    tuneablep->nbytes);

	(void) close(fd);
	return (PICL_SUCCESS);
}

static int
set_monitor_cpu_mode(ptree_warg_t *parg, const void *buf)
{
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;
	int		fd, val;
	int8_t		mmode;

	if (parg->cred.dc_euid != 0)
		return (PICL_PERMDENIED);

	proph = parg->proph;

	tuneablep = tuneable_lookup(proph);

	if (tuneablep == NULL)
		return (PICL_FAILURE);

	fd = open(CPU_HWM_DEVFS, O_RDWR);

	if (fd == -1) {
		return (PICL_FAILURE);
	}

	(void) memcpy(&val, buf, sizeof (val));

	if (val == ENABLE) {
		mmode = ADM1031_AUTO_MODE;
	} else if (val == DISABLE) {
		mmode = ADM1031_MANUAL_MODE;
	}

	if (ioctl(fd, ADM1031_SET_MONITOR_MODE, &mmode) == -1) {
		return (PICL_FAILURE);
	}

	(void) close(fd);
	return (PICL_SUCCESS);
}

static int
get_monitor_sys_mode(ptree_rarg_t *parg, void *buf)
{
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;
	int		fd;
	int8_t		mmode;

	proph = parg->proph;

	tuneablep = tuneable_lookup(proph);

	if (tuneablep == NULL)
		return (PICL_FAILURE);

	fd = open(SYS_HWM_DEVFS, O_RDWR);

	if (fd == -1) {
		return (PICL_FAILURE);
	}

	if (ioctl(fd, ADM1031_GET_MONITOR_MODE, &mmode) == -1) {
		return (PICL_FAILURE);
	}

	if (mmode == ADM1031_AUTO_MODE) {
		*((int *)tuneablep->value) = ENABLE;
	} else {
		*((int *)tuneablep->value) = DISABLE;
	}

	(void) memcpy(buf, tuneablep->value,
	    tuneablep->nbytes);

	(void) close(fd);
	return (PICL_SUCCESS);
}

static int
set_monitor_sys_mode(ptree_warg_t *parg, const void *buf)
{
	picl_prophdl_t	proph;
	env_tuneable_t	*tuneablep;
	int		fd, val;
	int8_t		mmode;

	if (parg->cred.dc_euid != 0)
		return (PICL_PERMDENIED);

	proph = parg->proph;

	tuneablep = tuneable_lookup(proph);

	if (tuneablep == NULL)
		return (PICL_FAILURE);

	fd = open(SYS_HWM_DEVFS, O_RDWR);

	if (fd == -1) {
		return (PICL_FAILURE);
	}

	(void) memcpy(&val, buf, sizeof (val));

	if (val == ENABLE) {
		mmode = ADM1031_AUTO_MODE;
	} else if (val == DISABLE) {
		mmode = ADM1031_MANUAL_MODE;
	}

	if (ioctl(fd, ADM1031_SET_MONITOR_MODE, &mmode) == -1) {
		return (PICL_FAILURE);
	}

	(void) close(fd);
	return (PICL_SUCCESS);
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

	(void) memcpy(buf, (caddr_t)tuneablep->value,
	    tuneablep->nbytes);

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

	(void) memcpy((caddr_t)tuneables->value, (caddr_t)buf,
	    tuneables->nbytes);


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

	(void) memcpy((int *)buf, (int *)tuneablep->value,
	    tuneablep->nbytes);

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

	(void) memcpy((int *)tuneablep->value, (int *)buf,
	    tuneablep->nbytes);

	return (PICL_SUCCESS);
}

int
get_dimm_fan_speed(int fan_fd, fanspeed_t *fanspeedp)
{
	int16_t	dimm_fan_period;
	i2c_reg_t	i2c_reg;

	/*
	 * The dimm fan period is 16 bit value and we need to read
	 * registers 2 and 3 to get the LSB and MSB values.
	 */
	i2c_reg.reg_num = PIC16F819_FAN_PERIOD_MSB_REGISTER;
	if (ioctl(fan_fd, I2C_GET_REG, &i2c_reg) == -1) {
		if (env_debug)
			envd_log(LOG_ERR,
			"Error in reading FAN_PERIOD MSB REGISTER\n");
		return (-1);
	}
	dimm_fan_period = (i2c_reg.reg_value << 8);
	i2c_reg.reg_num = PIC16F819_FAN_PERIOD_LSB_REGISTER;
	if (ioctl(fan_fd, I2C_GET_REG, &i2c_reg) == -1) {
		if (env_debug)
			envd_log(LOG_ERR,
			"Error in reading FAN_PERIOD LSB REGISTER\n");
		return (-1);
	}
	dimm_fan_period |= i2c_reg.reg_value;
	if (env_debug)
		envd_log(LOG_ERR,
		" dimm fan tach period is 0x%x\n", dimm_fan_period);
	if (dimm_fan_period == 0) {
		if (env_debug)
			envd_log(LOG_ERR,
			"dimm fan tach period read as zero. Illegal value.\n");
		return (-1);
	}
	*fanspeedp = PIC16F819_FAN_TACH_TO_RPM(dimm_fan_period);
	return (0);
}

int
is_dimm_fan_failed(void)
{
	i2c_reg_t	i2c_reg;
	fanspeed_t	fan_speed;
	int		retry_count;

	if (envd_dimm_fan.fd == -1)
		return (-1);
	/*
	 * read register 1 to look at Fan fault bit.
	 */
	i2c_reg.reg_num = PIC16F819_STATUS_REGISTER;
	retry_count = MAX_RETRIES_FOR_PIC16F819_REG_READ;
	while (retry_count > 0) {
		if (ioctl(envd_dimm_fan.fd, I2C_GET_REG, &i2c_reg) == -1) {
			retry_count--;
			continue;
		} else break;
	}
	if (retry_count != MAX_RETRIES_FOR_PIC16F819_REG_READ) {
		if (env_debug)
			envd_log(LOG_ERR,
			    "%d retries attempted in reading STATUS "
			    "register.\n",
			    (MAX_RETRIES_FOR_PIC16F819_REG_READ - retry_count));
	}
	if (retry_count == 0) {
		(void) strncpy(dimm_fan_status_string, NOT_AVAILABLE,
		    sizeof (dimm_fan_status_string));
		(void) strncpy(dimm_fan_command_string, NOT_AVAILABLE,
		    sizeof (dimm_fan_command_string));
		(void) strncpy(dimm_fan_debug_string, NOT_AVAILABLE,
		    sizeof (dimm_fan_debug_string));
		(void) strncpy(dimm_fan_rpm_string, NOT_AVAILABLE,
		    sizeof (dimm_fan_rpm_string));
		return (-1);
	}
	if (env_debug)
		envd_log(LOG_ERR,
		"DIMM FAN STATUS reg = 0x%x\n", i2c_reg.reg_value);
	if (i2c_reg.reg_value & PIC16F819_FAN_FAILED) {
		(void) snprintf(dimm_fan_status_string,
		    sizeof (dimm_fan_status_string), "0x%x",
		    i2c_reg.reg_value);
		i2c_reg.reg_num = PIC16F819_DEBUG_REGISTER;
		if (ioctl(envd_dimm_fan.fd, I2C_GET_REG, &i2c_reg) == -1) {
			(void) strncpy(dimm_fan_debug_string, NOT_AVAILABLE,
			    sizeof (dimm_fan_debug_string));
		} else {
			(void) snprintf(dimm_fan_debug_string,
			    sizeof (dimm_fan_debug_string),
			    "0x%x", i2c_reg.reg_value);
		}
		i2c_reg.reg_num = PIC16F819_COMMAND_REGISTER;
		if (ioctl(envd_dimm_fan.fd, I2C_GET_REG, &i2c_reg) == -1) {
			(void) strncpy(dimm_fan_command_string, NOT_AVAILABLE,
			    sizeof (dimm_fan_command_string));
		} else {
			(void) snprintf(dimm_fan_command_string,
			    sizeof (dimm_fan_command_string),
			    "0x%x", i2c_reg.reg_value);
		}
		if (get_dimm_fan_speed(envd_dimm_fan.fd, &fan_speed) == -1) {
			(void) strncpy(dimm_fan_rpm_string, NOT_AVAILABLE,
			    sizeof (dimm_fan_rpm_string));
		} else {
			(void) snprintf(dimm_fan_rpm_string,
			    sizeof (dimm_fan_rpm_string),
			    "%d", fan_speed);
		}
		return (1);
	} else return (0);
}
