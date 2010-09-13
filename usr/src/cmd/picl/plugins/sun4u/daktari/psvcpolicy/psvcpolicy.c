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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Daktari platform platform specific environment monitoring policies
 */
#include	<poll.h>
#include	<syslog.h>
#include	<unistd.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<errno.h>
#include	<fcntl.h>
#include	<strings.h>
#include	<libintl.h>
#include	<sys/types.h>
#include	<sys/param.h>
#include	<config_admin.h>
#include	<libdevice.h>
#include	<picl.h>
#include	<picltree.h>
#include	<psvc_objects.h>
#include	<sys/i2c/clients/i2c_client.h>
#include	<sys/daktari.h>
#include	<sys/hpc3130_events.h>
#include	<assert.h>
#include	<limits.h>
#include	<sys/systeminfo.h>

/*LINTLIBRARY*/

/* resides in libcfgadm */
extern cfga_err_t config_change_state(cfga_cmd_t, int, char *const *,
	const char *, struct cfga_confirm *, struct cfga_msg *, char **,
	cfga_flags_t);
/* Local Routine */
static int32_t update_gen_fault_led(psvc_opaque_t, char *);
static void shutdown_routine(void);
static int32_t update_thresholds(psvc_opaque_t hdlp, char *id, int offset);


#ifdef DEBUG

static int dak_policy_debug = 0;

#define	D1SYS_ERR(ARGS) if (dak_policy_debug & 0x1) syslog ARGS;
#define	D2SYS_ERR(ARGS) if (dak_policy_debug & 0x2) syslog ARGS;

#else

#define	D1SYS_ERR(ARGS)
#define	D2SYS_ERR(ARGS)

#endif

#define	I2C_PATH	"/devices/pci@9,700000/ebus@1/i2c@1,30"
#define	I2C_NODE	I2C_PATH ":devctl"
#define	PCF8574		I2C_PATH "/ioexp@0,%x:pcf8574"
#define	PCF8591		I2C_PATH "/adio@0,%x:port_0"
#define	FRU		I2C_PATH "/fru@0,%x:fru"
#define	HPC3130_DEV	I2C_PATH "/hotplug-controller@0,%2x:port_%1x"
#define	GEN_FAULT_LED	"FSP_GEN_FAULT_LED"
#define	EMPTY_STRING	"EMPTY"
#define	DEVICE_FAILURE_MSG	gettext("WARNING: Device %s failure detected")
#define	DEVICE_INSERTED_MSG	gettext("Device %s inserted")
#define	DEVICE_REMOVED_MSG	gettext("Device %s removed")
#define	PS_UNPLUGGED_MSG	gettext("Device %s unplugged")
#define	PS_PLUGGED_MSG		gettext("Device %s Plugged in")
#define	DEVICE_OK_MSG		gettext("Device %s OK")
#define	SET_LED_FAILED_MSG		\
	gettext("Failed to set LED state, id = %s, errno = %d\n")
#define	GET_PRESENCE_FAILED_MSG		\
	gettext("Failed to get presence attribute, id = %s, errno = %d\n")
#define	GET_SENSOR_FAILED_MSG		\
	gettext("Failed to get sensor value, id = %s, errno = %d\n")
#define	ADD_PS_MSG			\
gettext("WARNING: Only 1 Power Supply in system. ADD a 2nd Power Supply.\n")
#define	REMOVE_LOAD_MSG			\
	gettext("WARNING: Power Supply at 95%% current. Remove some load.\n")
#define	PS_OVER_CURRENT_MSG		\
	gettext("WARNING: Power Supply overcurrent detected\n")
#define	PS_UNDER_CURRENT_MSG		\
	gettext("WARNING: PS%d Undercurrent on one or more DC lines\n")
#define	DEVICE_UNKNOWN_MSG	gettext("Unknown device %s instance %d\n")
#define	DEVICE_HANDLE_FAIL_MSG		\
	gettext("Failed to get device handle for %s, errno = %d\n")
#define	DEVTREE_NODE_CREATE_FAILED	\
	gettext("psvc PICL plugin: Failed to create node for %s, errno = %d")
#define	DEVTREE_NODE_DELETE_FAILED	\
	gettext("psvc PICL plugin: Failed to delete node for %s, errno = %d")
#define	DISK_FAULT_MSG		gettext("%s: Error Reported\n")
#define	DISK_OK_MSG		gettext("%s: Error Cleared\n")
#define	SET_FANSPEED_FAILED_MSG		\
	gettext("Failed to set fan speed, id = %s, errno = %d\n")
#define	GET_ATTR_FRU_FAILED_MSG	gettext("Failed psvc_get_attr for FRU info\n")
#define	NO_FRU_INFO_MSG			\
	gettext("No FRU Information for %s using default module card\n")

#define	DAKTARI_MAX_PS	3
#define	DAK_MAX_PS_I_SENSORS 4
#define	DAK_MAX_DISKS	12
#define	DAK_MAX_CPU_MOD	4
#define	DAK_MAX_FAULT_SENSORS 3
#define	DAK_MAX_FANS 10

static int co_ps = 0;
static char *shutdown_string = "shutdown -y -g 60 -i 5 \"OVERTEMP condition\"";

typedef struct i2c_hp {
	int32_t		addr[2];
	char		name[256];
	char		compatible[256];
} i2c_hp_t;

typedef struct seg_desc {
	int32_t segdesc;
	int16_t segoffset;
	int16_t seglength;
} seg_desc_t;

static int32_t threshold_names[] = {
	PSVC_HW_LO_SHUT_ATTR,
	PSVC_LO_SHUT_ATTR,
	PSVC_LO_WARN_ATTR,
	PSVC_NOT_USED,			/* LOW MODE which is not used */
	PSVC_OPTIMAL_TEMP_ATTR,
	PSVC_HI_WARN_ATTR,
	PSVC_HI_SHUT_ATTR,
	PSVC_HW_HI_SHUT_ATTR
};

/*
 * The I2C bus is noisy, and the state may be incorrectly reported as
 * having changed.  When the state changes, we attempt to confirm by
 * retrying.  If any retries indicate that the state has not changed, we
 * assume the state change(s) were incorrect and the state has not changed.
 * The following variables are used to store the tuneable values read in
 * from the optional i2cparam.conf file for this shared object library.
 */
static int n_retry_pshp_status = PSVC_NUM_OF_RETRIES;
static int retry_sleep_pshp_status = 1;
static int n_read_overcurrent = PSVC_THRESHOLD_COUNTER;
static int n_read_undercurrent = PSVC_THRESHOLD_COUNTER;
static int n_retry_devicefail = PSVC_NUM_OF_RETRIES;
static int retry_sleep_devicefail = 1;
static int n_read_fanfault = PSVC_THRESHOLD_COUNTER;
static int n_retry_pshp = PSVC_NUM_OF_RETRIES;
static int retry_sleep_pshp = 1;
static int n_retry_diskfault = PSVC_NUM_OF_RETRIES;
static int retry_sleep_diskfault = 1;
static int n_retry_temp_shutdown = PSVC_NUM_OF_RETRIES;
static int retry_sleep_temp_shutdown = 1;

typedef struct {
	int *pvar;
	char *texttag;
} i2c_noise_param_t;

static i2c_noise_param_t i2cparams[] = {
	&n_retry_pshp_status, "n_retry_pshp_status",
	&retry_sleep_pshp_status, "retry_sleep_pshp_status",
	&n_read_overcurrent, "n_read_overcurrent",
	&n_read_undercurrent, "n_read_undercurrent",
	&n_retry_devicefail, "n_retry_devicefail",
	&retry_sleep_devicefail, "retry_sleep_devicefail",
	&n_read_fanfault, "n_read_fanfault",
	&n_retry_pshp, "n_retry_pshp",
	&retry_sleep_pshp, "retry_sleep_pshp",
	&n_retry_diskfault, "n_retry_diskfault",
	&retry_sleep_diskfault, "retry_sleep_diskfault",
	&n_retry_temp_shutdown, "n_retry_temp_shutdown",
	&retry_sleep_temp_shutdown, "retry_sleep_temp_shutdown",
	NULL, NULL
};

#pragma init(i2cparams_load)

static void
i2cparams_debug(i2c_noise_param_t *pi2cparams, char *platform,
	int usingDefaults)
{
	char s[128];
	i2c_noise_param_t *p;

	if (!usingDefaults) {
		(void) snprintf(s, sizeof (s),
		    "# Values from /usr/platform/%s/lib/i2cparam.conf\n",
		    platform);
		syslog(LOG_WARNING, "%s", s);
	} else {
		/* no file - we're using the defaults */
		(void) snprintf(s, sizeof (s),
"# No /usr/platform/%s/lib/i2cparam.conf file, using defaults\n",
		    platform);
	}
	(void) fputs(s, stdout);
	p = pi2cparams;
	while (p->pvar != NULL) {
		(void) snprintf(s, sizeof (s), "%s %d\n", p->texttag,
		    *(p->pvar));
		if (!usingDefaults)
			syslog(LOG_WARNING, "%s", s);
		(void) fputs(s, stdout);
		p++;
	}
}

static void
i2cparams_load(void)
{
	FILE *fp;
	char filename[PATH_MAX];
	char platform[64];
	char s[128];
	char var[128];
	int val;
	i2c_noise_param_t *p;

	if (sysinfo(SI_PLATFORM, platform, sizeof (platform)) == -1) {
		syslog(LOG_ERR, "sysinfo error %s\n", strerror(errno));
		return;
	}
	(void) snprintf(filename, sizeof (filename),
	    "/usr/platform/%s/lib/i2cparam.conf", platform);
	/* read thru the i2cparam.conf file and set variables */
	if ((fp = fopen(filename, "r")) != NULL) {
		while (fgets(s, sizeof (s), fp) != NULL) {
			if (s[0] == '#') /* skip comment lines */
				continue;
			/* try to find a string match and get the value */
			if (sscanf(s, "%127s %d", var, &val) != 2)
				continue;
			if (val < 1)
				val = 1;  /* clamp min value */
			p = &(i2cparams[0]);
			while (p->pvar != NULL) {
				if (strncmp(p->texttag, var, sizeof (var)) ==
				    0) {
					*(p->pvar) = val;
					break;
				}
				p++;
			}
		}
		(void) fclose(fp);
	}
	/* output the values of the parameters */
	i2cparams_debug(&(i2cparams[0]), platform, ((fp == NULL)? 1 : 0));
}

int32_t
psvc_MB_update_thresholds_0(psvc_opaque_t hdlp, char *id, int offset)
{
	int IO_offset = 0xd;
	int32_t err;

	err = update_thresholds(hdlp, id, IO_offset);

	return (err);
}

int32_t
psvc_IO_update_thresholds_0(psvc_opaque_t hdlp, char *id, int offset)
{
	int IO_offset = 0x8;
	int32_t err;

	err = update_thresholds(hdlp, id, IO_offset);

	return (err);
}

int32_t
psvc_DBP_update_thresholds_0(psvc_opaque_t hdlp, char *id, int offset)
{
	int IO_offset = 0x7;
	int32_t err;

	err = update_thresholds(hdlp, id, IO_offset);

	return (err);
}

/*
 * used to determine if a change of state occured. valid when states
 * are strings.
 */
static int8_t
change_of_state_str(char *state1, char *check1, char *state2, char *check2)
{
	int change = 0;

	if ((strcmp(state1, check1) == 0) && (strcmp(state2, check2) != 0))
		change = 1;
	if ((strcmp(state1, check1) != 0) && (strcmp(state2, check2) == 0))
		change = 1;

	return (change);
}

/*
 * Update thresholds tries to read the temperature thresholds from the FRU
 * SEEproms and then updates the thresholds in the object by overriding the
 * hardcoded thresholds.  For Daktari it is an Error if the FRU does not
 * contain the segment that had the temperature thresholds.
 */
static int32_t
update_thresholds(psvc_opaque_t hdlp, char *id, int offset)
{
	int32_t status = PSVC_SUCCESS;
	fru_info_t fru_data;
	char *fru, seg_name[2];
	int8_t seg_count, temp_array[8];
	int32_t match_count, i, j, seg_desc_start = 0x1806, temp_address;
	int32_t seg_found, temp;
	boolean_t present;
	seg_desc_t segment;

	status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &present);
	if ((status != PSVC_SUCCESS) || (present != PSVC_PRESENT))
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &match_count,
	    PSVC_FRU);
	if (status == PSVC_FAILURE)
		return (status);

	for (i = 0; i < match_count; i++) {
		seg_found = 0;
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
		    &fru, PSVC_FRU, i);
		if (status != PSVC_SUCCESS)
			return (status);

		fru_data.buf_start = 0x1805;
		fru_data.buf = (char *)&seg_count;
		fru_data.read_size = 1;

		status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
		    &fru_data);
		if (status != PSVC_SUCCESS) {
			return (status);
		}
		for (j = 0; (j < seg_count) && (!seg_found); j++) {
			fru_data.buf_start = seg_desc_start;
			fru_data.buf = seg_name;
			fru_data.read_size = 2;

			status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
			    &fru_data);

			seg_desc_start = seg_desc_start + 2;
			fru_data.buf_start = seg_desc_start;
			fru_data.buf = (char *)&segment;
			fru_data.read_size = sizeof (seg_desc_t);

			status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
			    &fru_data);
			if (status != PSVC_SUCCESS) {
				syslog(LOG_ERR,
				    "Failed psvc_get_attr for FRU info\n");
				return (status);
			}
			seg_desc_start = seg_desc_start + sizeof (seg_desc_t);
			if (memcmp(seg_name, "SC", 2) == 0)
				seg_found = 1;
		}
		if (seg_found) {
			temp_address = segment.segoffset + offset;
			fru_data.buf_start = temp_address;
			fru_data.buf = (char *)&temp_array;
			fru_data.read_size = sizeof (temp_array);
			status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
			    &fru_data);
			if (status != PSVC_SUCCESS) {
				syslog(LOG_ERR,
				    "Failed psvc_get_attr for FRU info\n");
				return (status);
			} else {
				for (j = 0; j < sizeof (temp_array); j++) {
					if (threshold_names[j] ==
					    PSVC_NOT_USED)
						continue;
					temp = temp_array[j];
					status = psvc_set_attr(hdlp, id,
					    threshold_names[j], &temp);
					if (status != PSVC_SUCCESS) {
						return (status);
					}
				}
			}
		} else {
			syslog(LOG_ERR, "No FRU Information for %s"
			    " using default temperatures\n", id);
		}
	}
	return (status);
}

int32_t
psvc_fan_init_speed_0(psvc_opaque_t hdlp, char *id)
{
	int32_t status = PSVC_SUCCESS;
	boolean_t present;
	char *control_id;
	int32_t init_speed = 0;

	status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &present);
	if ((status != PSVC_SUCCESS) || (present != PSVC_PRESENT))
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR, &control_id,
	    PSVC_FAN_DRIVE_CONTROL, 0);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_set_attr(hdlp, control_id, PSVC_CONTROL_VALUE_ATTR,
	    &init_speed);
	if (status == PSVC_FAILURE) {
		syslog(LOG_ERR, SET_FANSPEED_FAILED_MSG, control_id, errno);
		return (status);
	}

	return (status);
}

int32_t
psvc_update_setpoint_0(psvc_opaque_t hdlp, char *id)
{
	int32_t status = PSVC_SUCCESS;
	char *temp_sensor;
	int32_t match_count, i, temp;
	int16_t lowest_temp = 500;
	boolean_t present;

	status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &present);
	if ((status != PSVC_SUCCESS) || (present != PSVC_PRESENT))
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &match_count,
	    PSVC_DEV_TEMP_SENSOR);
	if (status == PSVC_FAILURE)
		return (status);

	for (i = 0; i < match_count; i++) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
		    &temp_sensor, PSVC_DEV_TEMP_SENSOR, i);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_get_attr(hdlp, temp_sensor,
		    PSVC_OPTIMAL_TEMP_ATTR, &temp);
		if (status != PSVC_SUCCESS) {
			syslog(LOG_ERR, "Failed to get Optimal temp for %s\n",
			    temp_sensor);
			return (status);
		}
		if (temp < lowest_temp)
			lowest_temp = temp;
	}
	status = psvc_set_attr(hdlp, id, PSVC_SETPOINT_ATTR, &lowest_temp);
	if (status == PSVC_FAILURE) {
		syslog(LOG_ERR, "Failed to change setpoint for %s\n", id);
		return (status);
	}
	return (status);
}

int32_t
psvc_remove_missing_nodes_0(psvc_opaque_t hdlp, char *id)
{
	int32_t status = PSVC_SUCCESS;
	char state[32];
	char *physical_dev;
	int32_t i, device_count;
	char parent_path[256];
	picl_nodehdl_t child_node;
	boolean_t present;

	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR,
	    &device_count, PSVC_PHYSICAL_DEVICE);
	if (status == PSVC_FAILURE)
		return (status);

	for (i = 0; i < device_count; i++) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
		    &physical_dev, PSVC_PHYSICAL_DEVICE, i);
		if (status != PSVC_SUCCESS)
			return (status);
		if (strncmp(physical_dev, "LTC1427", 7) == 0)
			continue;
		status = psvc_get_attr(hdlp, physical_dev,
		    PSVC_PROBE_RESULT_ATTR, state);
		if (status != PSVC_SUCCESS)
			continue;
		status = psvc_get_attr(hdlp, physical_dev, PSVC_PRESENCE_ATTR,
		    &present);
		if (status == PSVC_FAILURE) {
			syslog(LOG_ERR, GET_PRESENCE_FAILED_MSG, physical_dev,
			    errno);
			return (status);
		}

		if ((strcmp(state, PSVC_ERROR) == 0) &&
		    (present == PSVC_PRESENT)) {
			/* convert name to node, and parent path */
			psvcplugin_lookup(physical_dev, parent_path,
			    &child_node);
			/* Device removed */
			ptree_delete_node(child_node);
		}
	}
	return (status);
}

int32_t
psvc_check_ps_hotplug_status_0(psvc_opaque_t hdlp, char *id)
{
	char		fail_valid_switch_id[PICL_PROPNAMELEN_MAX];
	int32_t		status = PSVC_SUCCESS;
	char		valid_switch_state[32];
	char		state[32], fault[32];
	int32_t		led_count, j;
	char		*led_id;
	char		led_state[32];
	boolean_t	present;
	static int8_t	hotplug_failed_count = 0;
	static int	unplugged_ps = 0;
	int	retry;
	char		*unplugged_id;

	status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &present);
	if (status == PSVC_FAILURE) {
		syslog(LOG_ERR, GET_PRESENCE_FAILED_MSG, id, errno);
		return (status);
	}

	if (present == PSVC_ABSENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	snprintf(fail_valid_switch_id, sizeof (fail_valid_switch_id), "%s%s",
	    id, "_SENSOR_VALID_SWITCH");

	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_pshp_status);
		status = psvc_get_attr(hdlp, fail_valid_switch_id,
		    PSVC_STATE_ATTR, valid_switch_state);
		if (status == PSVC_FAILURE) {
			if (hotplug_failed_count == 0) {
				/*
				 * First time the get_attr call failed
				 * set count so that if we fail again
				 * we will know
				 */
				hotplug_failed_count = 1;
				/*
				 * We probably failed because the power
				 * supply was just insterted or removed
				 * before the get_attr call. We then
				 * return from this policy successfully
				 * knowing it will be run again shortly
				 * with the right PS state.
				 */
				return (PSVC_SUCCESS);
			} else {
				/*
				 * We have failed before and so this
				 * we will consider a hardware problem
				 * and it should be reported
				 */
				syslog(LOG_ERR,
				    "Failed getting %s State: ",
				    "ps_hotplug_status_0\n",
				    fail_valid_switch_id);
				return (status);
			}
		}
		/*
		 * Because we have successfully gotten a value from
		 * the i2c device on the PS we will set the
		 * failed_count to 0
		 */
		hotplug_failed_count = 0;

		status = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, state);
		if (status == PSVC_FAILURE)
			return (status);
		retry++;
		/*
		 * check to see if we need to retry. the conditions are:
		 *
		 * valid_switch_state	state			retry
		 * --------------------------------------------------
		 *	PSVC_OFF	!PSVC_HOTPLUGGED	yes
		 *	PSVC_ON		PSVC_HOTPLUGGED		yes
		 *	PSVC_OFF	PSVC_HOTPLUGGED		no
		 *	PSVC_ON		!PSVC_HOTPLUGGED	no
		 */
	} while ((retry < n_retry_pshp_status) &&
	    change_of_state_str(valid_switch_state, PSVC_OFF,
	    state, PSVC_HOTPLUGGED));

	if ((strcmp(valid_switch_state, PSVC_OFF) == 0) &&
	    (strcmp(state, PSVC_HOTPLUGGED) != 0)) {
		strcpy(state, PSVC_HOTPLUGGED);
		strcpy(fault, PSVC_NO_FAULT);
		strcpy(led_state, PSVC_LED_OFF);
		status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR,
		    state);
		if (status == PSVC_FAILURE)
			return (status);
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR,
		    &led_count, PSVC_DEV_FAULT_LED);
		if (status == PSVC_FAILURE)
			return (status);

		for (j = 0; j < led_count; j++) {

			status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
			    &led_id, PSVC_DEV_FAULT_LED, j);
			if (status != PSVC_SUCCESS)
				return (status);

			status = psvc_set_attr(hdlp, led_id,
			    PSVC_LED_STATE_ATTR, led_state);
			if (status != PSVC_SUCCESS) {
				syslog(LOG_ERR, SET_LED_FAILED_MSG, led_id,
				    errno);
				return (status);
			}

		}
		strcpy(led_state, PSVC_LED_ON);
		status = psvc_set_attr(hdlp, "FSP_POWER_FAULT_LED",
		    PSVC_LED_STATE_ATTR, led_state);
		if (status != PSVC_SUCCESS) {
			syslog(LOG_ERR, SET_LED_FAILED_MSG, led_id, errno);
			return (status);
		}
		unplugged_id = id + 2;
		unplugged_ps = unplugged_ps | (1 << (int)strtol(unplugged_id,
		    (char **)NULL, 10));
		status = update_gen_fault_led(hdlp, GEN_FAULT_LED);
		syslog(LOG_ERR, PS_UNPLUGGED_MSG, id);
		return (status);
	}

	if ((strcmp(valid_switch_state, PSVC_ON) == 0) &&
	    (strcmp(state, PSVC_HOTPLUGGED) == 0)) {
		strcpy(state, PSVC_OK);
		strcpy(fault, PSVC_NO_FAULT);
		status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, state);
		if (status == PSVC_FAILURE)
			return (status);
		unplugged_id = id + 2;
		unplugged_ps = unplugged_ps ^ (1 << (int)strtol(unplugged_id,
		    (char **)NULL, 10));
		if (unplugged_ps == 0) {
			strcpy(led_state, PSVC_LED_OFF);
			status = psvc_set_attr(hdlp, "FSP_POWER_FAULT_LED",
			    PSVC_LED_STATE_ATTR, led_state);
			if (status != PSVC_SUCCESS) {
				syslog(LOG_ERR, SET_LED_FAILED_MSG, led_id,
				    errno);
				return (status);
			}
			status = update_gen_fault_led(hdlp, GEN_FAULT_LED);
		}
		syslog(LOG_ERR, PS_PLUGGED_MSG, id);
	}

	return (status);
}

int32_t
psvc_ps_overcurrent_check_policy_0(psvc_opaque_t hdlp, char *system)
{
	int32_t status = PSVC_SUCCESS;
	boolean_t present;
	static char *sensor_id[DAKTARI_MAX_PS][DAK_MAX_PS_I_SENSORS];
	static char *power_supply_id[DAKTARI_MAX_PS] = {NULL};
	int32_t i, j;
	int32_t amps, oc_flag = 0, ps_present = 0;
	static int32_t hi_warn[DAKTARI_MAX_PS][DAK_MAX_PS_I_SENSORS];
	char state[32];
	static int8_t overcurrent_failed_check = 0;
	static int threshold_counter = 0;

	if (power_supply_id[0] == NULL) {
		for (i = 0; i < DAKTARI_MAX_PS; i++) {
			status = psvc_get_attr(hdlp, system,
			    PSVC_ASSOC_ID_ATTR, &(power_supply_id[i]),
			    PSVC_PS, i);
			if (status != PSVC_SUCCESS)
				return (status);
			for (j = 0; j < DAK_MAX_PS_I_SENSORS; ++j) {
				status = psvc_get_attr(hdlp,
				    power_supply_id[i], PSVC_ASSOC_ID_ATTR,
				    &(sensor_id[i][j]), PSVC_PS_I_SENSOR, j);
				if (status != PSVC_SUCCESS)
					return (status);
				status = psvc_get_attr(hdlp, sensor_id[i][j],
				    PSVC_HI_WARN_ATTR, &(hi_warn[i][j]));
				if (status != PSVC_SUCCESS)
					return (status);
			}
		}
	}

	for (i = 0; i < DAKTARI_MAX_PS; i++) {
		status = psvc_get_attr(hdlp, power_supply_id[i],
		    PSVC_PRESENCE_ATTR, &present);
		if (status == PSVC_FAILURE) {
			syslog(LOG_ERR, GET_PRESENCE_FAILED_MSG,
			    power_supply_id[i], errno);
			return (status);
		}

		if (present == PSVC_ABSENT) {
			continue;
		}

		status = psvc_check_ps_hotplug_status_0(hdlp,
		    power_supply_id[i]);
		if (status == PSVC_FAILURE)
			return (status);

		status = psvc_get_attr(hdlp, power_supply_id[i],
		    PSVC_STATE_ATTR, state);
		if (status == PSVC_FAILURE)
			return (status);

		if (strcmp(state, PSVC_HOTPLUGGED) == 0) {
			continue;
		} else {
			ps_present++;
		}

		for (j = 0; j < DAK_MAX_PS_I_SENSORS; ++j) {
			status = psvc_get_attr(hdlp, sensor_id[i][j],
			    PSVC_SENSOR_VALUE_ATTR, &amps);
			if (status != PSVC_SUCCESS) {
				if (overcurrent_failed_check == 0) {
					/*
					 * First time the get_attr call
					 * failed  set count so that if we
					 * fail again we will know
					 */
					overcurrent_failed_check = 1;
					/*
					 * We probably failed because the power
					 * supply was just insterted or removed
					 * before the get_attr call. We then
					 * return from this policy successfully
					 * knowing it will be run again shortly
					 * with the right PS state.
					 */
					return (PSVC_SUCCESS);
				} else {
					/*
					 * We have failed before and so this we
					 * will consider a hardware problem and
					 * it should be reported.
					 */
					syslog(LOG_ERR,
					    "Failed getting %s sensor value",
					    sensor_id[i][j]);
					return (status);
				}
			}
			/*
			 * Because we have successfully gotten a value from the
			 * i2c device on the PS we will set the failed_count
			 * to 0.
			 */
			overcurrent_failed_check = 0;

			if (amps >= hi_warn[i][j]) {
				oc_flag = 1;
			}
		}
	}

	if (oc_flag) {
		/*
		 * Because we observed an overcurrent
		 * condition, we increment threshold_counter.
		 * Once threshold_counter reaches the value
		 * of n_read_overcurrent we log the event.
		 */
		threshold_counter++;
		if (threshold_counter == n_read_overcurrent) {
			threshold_counter = 0;
			if (ps_present == 1) {
				syslog(LOG_ERR, PS_OVER_CURRENT_MSG);
				syslog(LOG_ERR, ADD_PS_MSG);
			} else {
				syslog(LOG_ERR, PS_OVER_CURRENT_MSG);
				syslog(LOG_ERR, REMOVE_LOAD_MSG);
			}
		}
	} else {
		threshold_counter = 0;
	}

	return (PSVC_SUCCESS);
}

int32_t
psvc_ps_undercurrent_check(psvc_opaque_t hdlp, char *id, int32_t *uc_flag)
{
	int32_t status = PSVC_SUCCESS;
	boolean_t present;
	static char *sensor_id[DAK_MAX_PS_I_SENSORS];
	int32_t j;
	int32_t amps;
	static int32_t lo_warn[DAK_MAX_PS_I_SENSORS];
	static int8_t undercurrent_failed_check = 0;

	status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &present);
	if (status == PSVC_FAILURE) {
		syslog(LOG_ERR, GET_PRESENCE_FAILED_MSG, id, errno);
		return (status);
	}

	if (present == PSVC_ABSENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	for (j = 0; j < DAK_MAX_PS_I_SENSORS; ++j) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
		    &(sensor_id[j]), PSVC_PS_I_SENSOR, j);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_get_attr(hdlp, sensor_id[j],
		    PSVC_LO_WARN_ATTR, &(lo_warn[j]));
		if (status != PSVC_SUCCESS)
			return (status);
	}

	*uc_flag = 0;
	for (j = 0; j < DAK_MAX_PS_I_SENSORS; ++j) {
		status = psvc_get_attr(hdlp, sensor_id[j],
		    PSVC_SENSOR_VALUE_ATTR, &amps);
		if (status != PSVC_SUCCESS) {
			if (undercurrent_failed_check == 0) {
				/*
				 * First time the get_attr call
				 * failed  set count so that if we
				 * fail again we will know.
				 */
				undercurrent_failed_check = 1;
				/*
				 * We probably failed because the power
				 * supply was just inserted or removed
				 * before the get_attr call. We then
				 * return from this policy successfully
				 * knowing it will be run again shortly
				 * with the right PS state.
				 */
				return (PSVC_SUCCESS);
			} else {
				/*
				 * Repeated failures are logged.
				 */
				syslog(LOG_ERR,
				    "Failed getting %s sensor value",
				    sensor_id[j]);
				return (status);
			}
		}
		/*
		 * Because we have successfully gotten a value from the
		 * i2c device on the PS we will set the failed_count
		 * to 0.
		 */
		undercurrent_failed_check = 0;

		if (amps <= lo_warn[j]) {
			*uc_flag = 1;
			return (PSVC_SUCCESS);
		}
	}

	return (PSVC_SUCCESS);
}

int32_t
psvc_ps_device_fail_notifier_policy_0(psvc_opaque_t hdlp, char *system)
{
	static char *ps_id[DAKTARI_MAX_PS] = {NULL};
	static char *sensor_id[DAKTARI_MAX_PS][DAK_MAX_FAULT_SENSORS];
	char *led_id = "FSP_POWER_FAULT_LED";
	int i, j, uc_flag;
	char state[32], fault[32], previous_state[32], past_state[32];
	char led_state[32];
	char bad_sensors[DAK_MAX_FAULT_SENSORS][256];
	static int threshold_counter[DAKTARI_MAX_PS];
	int32_t status = PSVC_SUCCESS;
	boolean_t present;
	int fail_state;
	static int8_t device_fail_failed_check = 0;
	int retry, should_retry;

	if (ps_id[0] == NULL) {
		for (i = 0; i < DAKTARI_MAX_PS; i++) {
			status = psvc_get_attr(hdlp, system,
			    PSVC_ASSOC_ID_ATTR, &(ps_id[i]), PSVC_PS, i);
			if (status != PSVC_SUCCESS)
				return (status);
			for (j = 0; j < DAK_MAX_FAULT_SENSORS; j++) {
				status = psvc_get_attr(hdlp, ps_id[i],
				    PSVC_ASSOC_ID_ATTR, &(sensor_id[i][j]),
				    PSVC_DEV_FAULT_SENSOR, j);
				if (status != PSVC_SUCCESS)
					return (status);
			}
		}
	}

	for (i = 0; i < DAKTARI_MAX_PS; i++) {
		fail_state = 0;
		status = psvc_get_attr(hdlp, ps_id[i], PSVC_PRESENCE_ATTR,
		    &present);
		if (status == PSVC_FAILURE)
			return (status);

		if (present == PSVC_ABSENT) {
			errno = ENODEV;
			return (PSVC_FAILURE);
		}

		status = psvc_check_ps_hotplug_status_0(hdlp, ps_id[i]);
		if (status == PSVC_FAILURE)
			return (status);

		status = psvc_get_attr(hdlp, ps_id[i], PSVC_STATE_ATTR,
		    past_state);
		if (status == PSVC_FAILURE)
			return (status);

		if (strcmp(past_state, PSVC_HOTPLUGGED) == 0) {
			return (PICL_SUCCESS);
		}

		retry = 0;
		do {
			if (retry)
				(void) sleep(retry_sleep_devicefail);
			fail_state = 0;
			should_retry = 0;
			for (j = 0; j < DAK_MAX_FAULT_SENSORS; ++j) {
				status = psvc_get_attr(hdlp, sensor_id[i][j],
				    PSVC_SWITCH_STATE_ATTR, state);
				if (status != PSVC_SUCCESS) {
					if (device_fail_failed_check == 0) {
						/*
						 * First time the get_attr call
						 * failed  set count so that
						 * if we fail again we will know
						 */
						device_fail_failed_check = 1;
						/*
						 * We probably failed because
						 * the power supply was just
						 * insterted or removed before
						 * the get_attr call. We then
						 * return from this policy
						 * successfully knowing it will
						 * be run again shortly
						 * with the right PS state.
						 */
						return (PSVC_SUCCESS);
					} else {
						/*
						 * We have failed before and
						 * so this we will consider a
						 * hardware problem and
						 * it should be reported.
						 */
						syslog(LOG_ERR, "Failed in "
						    "getting sensor state for "
						    "%s\n", sensor_id[i][j]);

						return (status);
					}
				}

				/*
				 * Because we have successfully gotten
				 * a value from the i2c device on the
				 * PS we will set the failed_count to 0.
				 */
				device_fail_failed_check = 0;

				/*
				 * If we find that the sensor is on we
				 * fill in the name of the sensor in
				 * the bad_sensor array. If the sensor
				 * is off we use EMPTY_STRING as a check
				 * later on as to when NOT to print out
				 * what is in bad_sensor[].
				 */
				if (strcmp(state, PSVC_SWITCH_ON) == 0) {
					fail_state++;
					strlcpy(bad_sensors[j], sensor_id[i][j],
					    sizeof (bad_sensors[j]));
				} else {
					strcpy(bad_sensors[j], EMPTY_STRING);
				}
			}
			retry++;
			/*
			 * check to see if we need to retry. the conditions are:
			 *
			 * fail_state		past_state		retry
			 * --------------------------------------------------
			 *	+		PSVC_OK			yes
			 *	0		PSVC_ERROR		yes
			 *	+		PSVC_ERROR		no
			 *	0		PSVC_OK			no
			 */
			if ((fail_state > 0) &&
			    (strcmp(past_state, PSVC_OK) == 0)) {
				should_retry = 1;
			} else if ((fail_state == 0) &&
			    (strcmp(past_state, PSVC_ERROR) == 0)) {
				should_retry = 1;
			}
		} while ((retry < n_retry_devicefail) && should_retry);

		/* Under current check */
		status = psvc_ps_undercurrent_check(hdlp, ps_id[i], &uc_flag);

		if (status != PSVC_FAILURE) {
			if (uc_flag) {
				/*
				 * Because we observed an undercurrent
				 * condition, we increment threshold counter.
				 * Once threshold counter reaches the value
				 * of n_read_undercurrent we log the event.
				 */
				threshold_counter[i]++;
				if (threshold_counter[i] >=
				    n_read_undercurrent) {
					fail_state++;
					syslog(LOG_ERR, PS_UNDER_CURRENT_MSG,
					    i);
				}
			} else {
				threshold_counter[i] = 0;
			}
		}

		if (fail_state != 0) {
			strcpy(state, PSVC_ERROR);
			strcpy(fault, PSVC_GEN_FAULT);
		} else {
			strcpy(state, PSVC_OK);
			strcpy(fault, PSVC_NO_FAULT);
		}

		status = psvc_set_attr(hdlp, ps_id[i], PSVC_STATE_ATTR, state);
		if (status != PSVC_SUCCESS)
			return (status);

		status = psvc_set_attr(hdlp, ps_id[i], PSVC_FAULTID_ATTR,
		    fault);
		if (status != PSVC_SUCCESS)
			return (status);

		status = psvc_get_attr(hdlp, ps_id[i], PSVC_PREV_STATE_ATTR,
		    previous_state);
		if (status != PSVC_SUCCESS)
			return (status);

		if (strcmp(state, previous_state) != 0) {
			char dev_label[32];

			psvc_get_attr(hdlp, ps_id[i], PSVC_LABEL_ATTR,
			    dev_label);

			if (strcmp(state, PSVC_ERROR) == 0) {
				syslog(LOG_ERR, DEVICE_FAILURE_MSG, dev_label);
				for (j = 0; j < DAK_MAX_FAULT_SENSORS; ++j) {
					if (strcmp(bad_sensors[j],
					    EMPTY_STRING) != 0)
						syslog(LOG_ERR, "%s\n",
						    bad_sensors[j]);
				}
				strcpy(led_state, PSVC_LED_ON);
			} else {
				syslog(LOG_ERR, DEVICE_OK_MSG, dev_label);
				strcpy(led_state, PSVC_LED_OFF);
			}

			status = psvc_set_attr(hdlp, led_id,
			    PSVC_LED_STATE_ATTR, led_state);
			if (status != PSVC_SUCCESS) {
				syslog(LOG_ERR, SET_LED_FAILED_MSG, led_id,
				    errno);
				return (status);
			}
		}
	}

	return (PSVC_SUCCESS);
}

int32_t
psvc_ps_check_and_disable_dr_policy_0(psvc_opaque_t hdlp, char *id)
{
	char		state[32];
	static char	*name[DAKTARI_MAX_PS] = {NULL};
	int		ps_cnt = 0;
	int		i, j;
	int		dr_conf;
	int		fd, rv;
	boolean_t	present;
	char		dev_path[sizeof (HPC3130_DEV)+8];
	unsigned char	controller_names[HPC3130_CONTROLLERS] =
		{ 0xe2, 0xe6, 0xe8, 0xec };

	if (name[0] == NULL) {
		for (i = 0; i < DAKTARI_MAX_PS; i++) {
			rv = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
			    &(name[i]), PSVC_PS, i);
			if (rv != PSVC_SUCCESS)
				return (rv);
		}
	}

	/*
	 * Go through the power supplies to make sure they're present
	 * and OK.
	 */
	ps_cnt = DAKTARI_MAX_PS;
	for (i = 0; i < DAKTARI_MAX_PS; i++) {
		rv = psvc_get_attr(hdlp, name[i], PSVC_PRESENCE_ATTR,
		    &present);
		if (rv != PSVC_SUCCESS)
			return (rv);

		if (present != PSVC_PRESENT) {
			ps_cnt--;
			continue;
		} else {
			rv = psvc_get_attr(hdlp, name[i], PSVC_STATE_ATTR,
			    state);
			if (rv != PSVC_SUCCESS)
				return (rv);

			if (strcmp(state, PSVC_OK))
				ps_cnt--;
		}
	}

	/*
	 * No change in DR configuration is needed if the new power supply
	 * count equals the current count.
	 */
	if (ps_cnt == co_ps)
		return (PSVC_SUCCESS);

	/*
	 * Disable DR when hotplugged down to 1 power supply; enable DR when
	 * hotplugged up from 1 supply.
	 */
	assert(ps_cnt);
	if ((co_ps == 0 || co_ps > 1) && ps_cnt != 1) {
		co_ps = ps_cnt;
		return (PSVC_SUCCESS);
	}
	dr_conf = (ps_cnt == 1 ? HPC3130_DR_DISABLE : HPC3130_DR_ENABLE);
	co_ps = ps_cnt;

	for (i = 0; i < HPC3130_CONTROLLERS; i++) {
		for (j = 0; j < HPC3130_SLOTS; j++) {
			(void) snprintf(dev_path, sizeof (dev_path),
			    HPC3130_DEV, controller_names[i], j);
			fd = open(dev_path, O_RDWR);
			if (fd == -1)
				return (PSVC_FAILURE);

			rv = ioctl(fd, HPC3130_CONF_DR, &dr_conf);
			close(fd);
			if (rv == -1)
				return (PSVC_FAILURE);
		}
	}

	return (PSVC_SUCCESS);
}

int32_t
psvc_fan_blast_shutoff_policy_0(psvc_opaque_t hdlp, char *id)
{
	char		switch_status[32];
	int32_t		status = PSVC_SUCCESS;

	status = psvc_get_attr(hdlp, id, PSVC_SWITCH_STATE_ATTR, switch_status);
	if (status != PSVC_SUCCESS)
		return (status);
	status = psvc_set_attr(hdlp, id, PSVC_SWITCH_STATE_ATTR,
	    PSVC_SWITCH_OFF);
	if (status != PSVC_SUCCESS)
		return (status);
	status = psvc_set_attr(hdlp, id, PSVC_SWITCH_STATE_ATTR,
	    PSVC_SWITCH_ON);
	if (status != PSVC_SUCCESS)
		return (status);
	status = psvc_set_attr(hdlp, id, PSVC_SWITCH_STATE_ATTR,
	    PSVC_SWITCH_OFF);

	return (status);
}

int32_t
psvc_fan_fault_check_policy_0(psvc_opaque_t hdlp, char *system)
{
	static char *fan_id[DAK_MAX_FANS] = {NULL};
	boolean_t enabled;
	int32_t speed;
	int32_t status = PSVC_SUCCESS;
	int r;
	static int threshold_counter = 0;

	if (fan_id[0] == NULL) {
		for (r = 0; r < DAK_MAX_FANS; r++) {
			status = psvc_get_attr(hdlp, system,
			    PSVC_ASSOC_ID_ATTR, &(fan_id[r]), PSVC_FAN, r);
			if (status != PSVC_SUCCESS)
				return (status);
		}
	}

	for (r = 0; r < DAK_MAX_FANS; r++) {
		status = psvc_get_attr(hdlp, fan_id[r], PSVC_ENABLE_ATTR,
		    &enabled);
		if (status != PSVC_SUCCESS)
			return (status);

		if (enabled == PSVC_ENABLED) {
			uint64_t features;
			char *switch_id;
			char switch_state[32], fan_state[32];
			int fan_count, fans;
			char *other_fan_id;
			char fstate[32], ffault[32];

			/*
			 * If any other fan on the fan tray has an ERROR state,
			 * mark this fan bad and return
			 */
			psvc_get_attr(hdlp, fan_id[r], PSVC_ASSOC_MATCHES_ATTR,
			    &fan_count, PSVC_FAN_TRAY_FANS);
			for (fans = 0; fans < fan_count; ++fans) {
				status = psvc_get_attr(hdlp, fan_id[r],
				    PSVC_ASSOC_ID_ATTR, &other_fan_id,
				    PSVC_FAN_TRAY_FANS, fans);
				if (status == PSVC_FAILURE)
					return (status);
				status = psvc_get_attr(hdlp, other_fan_id,
				    PSVC_STATE_ATTR, fan_state);
				if (status != PSVC_SUCCESS)
					return (status);

				if (strcmp(fan_state, PSVC_ERROR) == 0) {
					strlcpy(ffault, PSVC_GEN_FAULT,
					    sizeof (ffault));
					status = psvc_set_attr(hdlp, fan_id[r],
					    PSVC_FAULTID_ATTR, ffault);
					if (status != PSVC_SUCCESS)
						return (status);

					strlcpy(fstate, PSVC_ERROR,
					    sizeof (fstate));
					status = psvc_set_attr(hdlp, fan_id[r],
					    PSVC_STATE_ATTR, fstate);

					return (status);
				}
			}

			/*
			 * Select tachometer for IO or CPU primary/secondary
			 * fans.
			 */
			pthread_mutex_lock(&fan_mutex);

			status = psvc_get_attr(hdlp, fan_id[r],
			    PSVC_ASSOC_ID_ATTR, &switch_id,
			    PSVC_FAN_PRIM_SEC_SELECTOR, 0);

			if (status != PSVC_FAILURE) {
				status = psvc_get_attr(hdlp, fan_id[r],
				    PSVC_FEATURES_ATTR,	&features);
				if (status == PSVC_FAILURE) {
					pthread_mutex_unlock(&fan_mutex);
					return (status);
				}

				if (features & PSVC_DEV_PRIMARY)
					strlcpy(switch_state, PSVC_SWITCH_ON,
					    sizeof (switch_state));
				else
					strlcpy(switch_state, PSVC_SWITCH_OFF,
					    sizeof (switch_state));
				status = psvc_set_attr(hdlp, switch_id,
				    PSVC_SWITCH_STATE_ATTR, switch_state);
				if (status == PSVC_FAILURE) {
					pthread_mutex_unlock(&fan_mutex);
					return (status);
				}

				/* allow time for speed to be determined */
				(void) poll(NULL, 0, 250);
			}

			status = psvc_get_attr(hdlp, fan_id[r],
			    PSVC_SENSOR_VALUE_ATTR, &speed);
			if (status != PSVC_SUCCESS) {
				pthread_mutex_unlock(&fan_mutex);
				return (status);
			}

			pthread_mutex_unlock(&fan_mutex);

			if (speed == 0) {
				threshold_counter++;
				if (threshold_counter ==
				    n_read_fanfault) {
					int32_t i;
					int32_t led_count;
					char led_state[32];
					char *led_id;
					char *slot_id;
					char label[32];
					char state[32], fault[32];

					threshold_counter = 0;
					strlcpy(fault, PSVC_GEN_FAULT,
					    sizeof (fault));
					status = psvc_set_attr(hdlp, fan_id[r],
					    PSVC_FAULTID_ATTR, fault);
					if (status != PSVC_SUCCESS)
						return (status);

					strlcpy(state, PSVC_ERROR,
					    sizeof (state));
					status = psvc_set_attr(hdlp, fan_id[r],
					    PSVC_STATE_ATTR, state);
					if (status != PSVC_SUCCESS)
						return (status);

					status = psvc_get_attr(hdlp, fan_id[r],
					    PSVC_LABEL_ATTR, label);
					if (status != PSVC_SUCCESS)
						return (status);

					syslog(LOG_ERR, DEVICE_FAILURE_MSG,
					    label);

					/* turn on fault LEDs */
					psvc_get_attr(hdlp, fan_id[r],
					    PSVC_ASSOC_MATCHES_ATTR, &led_count,
					    PSVC_DEV_FAULT_LED);
					strlcpy(led_state, PSVC_LED_ON,
					    sizeof (led_state));
					for (i = 0; i < led_count; ++i) {
						status = psvc_get_attr(hdlp,
						    fan_id[r],
						    PSVC_ASSOC_ID_ATTR, &led_id,
						    PSVC_DEV_FAULT_LED, i);
						if (status == PSVC_FAILURE)
							return (status);

						status = psvc_set_attr(hdlp,
						    led_id, PSVC_LED_STATE_ATTR,
						    led_state);
						if (status == PSVC_FAILURE)
							return (status);
					}

					/* turn on OK to remove LEDs */

					status = psvc_get_attr(hdlp, fan_id[r],
					    PSVC_ASSOC_ID_ATTR, &slot_id,
					    PSVC_PARENT, 0);
					if (status != PSVC_SUCCESS)
						return (status);

					psvc_get_attr(hdlp, slot_id,
					    PSVC_ASSOC_MATCHES_ATTR, &led_count,
					    PSVC_SLOT_REMOVE_LED);
					strlcpy(led_state, PSVC_LED_ON,
					    sizeof (led_state));
					for (i = 0; i < led_count; ++i) {
						status = psvc_get_attr(hdlp,
						    slot_id,
						    PSVC_ASSOC_ID_ATTR, &led_id,
						    PSVC_SLOT_REMOVE_LED, i);
						if (status == PSVC_FAILURE)
							return (status);

						status = psvc_set_attr(hdlp,
						    led_id, PSVC_LED_STATE_ATTR,
						    led_state);
						if (status == PSVC_FAILURE)
							return (status);
					}
				}
			}
		}
	}

	return (PSVC_SUCCESS);
}

/*
 * This routine takes in the PSVC handle pointer, the PS name, and the
 * instance number (0, 1, or 2). It simply make a psvc_get call to get the
 * presence of each of the children under the PS. This call will set the
 * presence state of the child device if it was not there when the system
 * was booted.
 */
static int
handle_ps_hotplug_children_presence(psvc_opaque_t hdlp, char *id)
{
	char *sensor_id;
	char fail_valid_switch_id[PICL_PROPNAMELEN_MAX];
	int32_t	status = PSVC_SUCCESS;
	boolean_t presence;
	int j;

	/* Get the Sensor Valid Switch presence */
	snprintf(fail_valid_switch_id, sizeof (fail_valid_switch_id), "%s%s",
	    id, "_SENSOR_VALID_SWITCH");

	status = psvc_get_attr(hdlp, fail_valid_switch_id, PSVC_PRESENCE_ATTR,
	    &presence);
	if (status != PSVC_SUCCESS)
		return (status);

	/* Go through each PS's fault sensors */
	for (j = 0; j < DAK_MAX_FAULT_SENSORS; j++) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
		    &(sensor_id), PSVC_DEV_FAULT_SENSOR, j);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_get_attr(hdlp, sensor_id, PSVC_PRESENCE_ATTR,
		    &presence);
		if (status != PSVC_SUCCESS)
			return (status);
	}

	/* Go through each PS's current sensors */
	for (j = 0; j < DAK_MAX_PS_I_SENSORS; ++j) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
		    &(sensor_id), PSVC_PS_I_SENSOR, j);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_get_attr(hdlp, sensor_id, PSVC_PRESENCE_ATTR,
		    &presence);
		if (status != PSVC_SUCCESS)
			return (status);

	}

	/* Go through each PS's onboard i2c hardware */
	for (j = 0; j < 3; j++) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
		    &(sensor_id), PSVC_PHYSICAL_DEVICE, j);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_get_attr(hdlp, sensor_id, PSVC_PRESENCE_ATTR,
		    &presence);
		if (status != PSVC_SUCCESS)
			return (status);
	}

	return (status);
}

static i2c_hp_t devices[3][3] = {
{{{0, 0x90}, "adio", "i2c-pcf8591"}, {{0, 0x70}, "ioexp", "i2c-pcf8574"},
	{{0, 0xa0}, "fru", "i2c-at24c64"}},
{{{0, 0x92}, "adio", "i2c-pcf8591"}, {{0, 0x72}, "ioexp", "i2c-pcf8574"},
	{{0, 0xa2}, "fru", "i2c-at24c64"}},
{{{0, 0x94}, "adio", "i2c-pcf8591"}, {{0, 0x74}, "ioexp", "i2c-pcf8574"},
	{{0, 0xa4}, "fru", "i2c-at24c64"}},
};

int32_t
psvc_ps_hotplug_policy_0(psvc_opaque_t hdlp, char *id)
{
	boolean_t presence, previous_presence;
	int32_t status = PSVC_SUCCESS;
	char label[32], state[32], fault[32];
	int32_t ps_instance, led_count;
	char *switch_id, *led_id;
	int i;
	picl_nodehdl_t parent_node;
	char parent_path[256], ps_path[256];
	picl_nodehdl_t child_node;
	devctl_hdl_t bus_handle, dev_handle;
	devctl_ddef_t ddef_hdl;
	char pcf8574_devpath[256], pcf8591_devpath[256], fru_devpath[256];
	int retry;

	status = psvc_get_attr(hdlp, id, PSVC_PREV_PRESENCE_ATTR,
	    &previous_presence);
	if (status != PSVC_SUCCESS)
		return (status);

	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_pshp);

		status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &presence);
		if (status != PSVC_SUCCESS)
			return (status);
		retry++;
	} while ((retry < n_retry_pshp) &&
	    (presence != previous_presence));

	if (presence == previous_presence) {
		/* No change */
		return (status);
	}

	status = psvc_get_attr(hdlp, id, PSVC_LABEL_ATTR, label);
	if (status != PSVC_SUCCESS)
		return (status);

	/* convert name to node, and parent path */
	psvcplugin_lookup(id, parent_path, &child_node);

	if (presence == PSVC_PRESENT) {
		/*
		 * Run this code if Power Supply was just added into the
		 * System.  This code toggles hotplug switch and adds the
		 * PS and it's children to the picl tree. We then goto adding
		 * device drivers at bottom of the routine.
		 */
		int32_t switch_count;
		char state[32], fault[32];
		char switch_state[32];

		/* may detect presence before all connections are made */
		(void) poll(NULL, 0, 500);

		/* Device added */
		syslog(LOG_ERR, DEVICE_INSERTED_MSG, label);

		strcpy(state, PSVC_OK);
		status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, state);
		if (status != PSVC_SUCCESS)
			return (status);

		strcpy(fault, PSVC_NO_FAULT);
		status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR, fault);
		if (status != PSVC_SUCCESS)
			return (status);

		/* Enable i2c bus */
		psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR,
		    &switch_count, PSVC_HOTPLUG_ENABLE_SWITCH);
		for (i = 0; i < switch_count; ++i) {
			status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
			    &switch_id, PSVC_HOTPLUG_ENABLE_SWITCH, i);
			if (status == PSVC_FAILURE)
				return (status);

			strcpy(switch_state, PSVC_SWITCH_OFF);
			status = psvc_set_attr(hdlp, switch_id,
			    PSVC_SWITCH_STATE_ATTR, switch_state);
			if (status == PSVC_FAILURE)
				return (status);

			strcpy(switch_state, PSVC_SWITCH_ON);
			status = psvc_set_attr(hdlp, switch_id,
			    PSVC_SWITCH_STATE_ATTR, switch_state);
			if (status == PSVC_FAILURE)
				return (status);
		}
		ptree_get_node_by_path(parent_path, &parent_node);
		ptree_add_node(parent_node, child_node);
		snprintf(ps_path, sizeof (ps_path), "%s/%s", parent_path, id);
		psvcplugin_add_children(ps_path);
	} else {
		/*
		 * Run this code if PS was just removed from the system. We
		 * delete the device from the picl tree and then shut off
		 * all fault lights associated with the PS.  We also set the
		 * device state to PSVC_REMOVED so that if we hit overcurrent
		 * or fault checking code we can do a psvc call to see that
		 * the device has not offically been added into the system.
		 * We then will drop to code lower in the routine to remove
		 * the device drivers for this PS.
		 */

		/* Device removed */
		syslog(LOG_ERR, DEVICE_REMOVED_MSG, label);
		ptree_delete_node(child_node);
		psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &led_count,
		    PSVC_DEV_FAULT_LED);

		for (i = 0; i < led_count; i++) {
			status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
			    &led_id, PSVC_DEV_FAULT_LED, i);
			if (status != PSVC_SUCCESS) {
				return (status);
			}

			status = psvc_set_attr(hdlp, led_id,
			    PSVC_LED_STATE_ATTR, PSVC_OFF);
			if (status != PSVC_SUCCESS) {
				syslog(LOG_ERR, SET_LED_FAILED_MSG, led_id,
				    errno);
				return (status);
			}

		}

		strcpy(state, PSVC_OK);
		strcpy(fault, PSVC_NO_FAULT);

		status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, state);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR, fault);
		if (status != PSVC_SUCCESS)
			return (status);
	}

	status = psvc_set_attr(hdlp, id, PSVC_PREV_PRESENCE_ATTR, &presence);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_INSTANCE_ATTR, &ps_instance);
	if (status != PSVC_SUCCESS)
		return (status);

	if (presence != PSVC_PRESENT) {
		/*
		 * This is the additional code needed to remove the PS from
		 * the system.  It removes the device drivers from the
		 * device tree.
		 */
		snprintf(pcf8574_devpath, sizeof (pcf8574_devpath), PCF8574,
		    devices[ps_instance][1].addr[1]);
		snprintf(pcf8591_devpath, sizeof (pcf8591_devpath), PCF8591,
		    devices[ps_instance][0].addr[1]);
		snprintf(fru_devpath, sizeof (fru_devpath), FRU,
		    devices[ps_instance][2].addr[1]);

		dev_handle = devctl_device_acquire(pcf8591_devpath, 0);
		if (dev_handle == NULL) {
			syslog(LOG_ERR, DEVICE_HANDLE_FAIL_MSG,
			    pcf8591_devpath, errno);
			devctl_release(dev_handle);
			return (PSVC_FAILURE);
		} else if ((devctl_device_remove(dev_handle)) &&
		    (errno != ENXIO)) {
				syslog(LOG_ERR, DEVTREE_NODE_DELETE_FAILED,
				    pcf8591_devpath, errno);
				devctl_release(dev_handle);
				return (PSVC_FAILURE);
			} else {
				devctl_release(dev_handle);
				status = PSVC_SUCCESS;
			}

		dev_handle = devctl_device_acquire(pcf8574_devpath, 0);
		if (dev_handle == NULL) {
			syslog(LOG_ERR, DEVICE_HANDLE_FAIL_MSG,
			    pcf8574_devpath, errno);
			devctl_release(dev_handle);
			return (PSVC_FAILURE);
		} else if ((devctl_device_remove(dev_handle)) &&
		    (errno != ENXIO)) {
				syslog(LOG_ERR, DEVTREE_NODE_DELETE_FAILED,
				    pcf8574_devpath, errno);
				devctl_release(dev_handle);
				return (PSVC_FAILURE);
			} else {
				devctl_release(dev_handle);
				status = PSVC_SUCCESS;
			}

		dev_handle = devctl_device_acquire(fru_devpath, 0);
		if (dev_handle == NULL) {
			syslog(LOG_ERR, DEVICE_HANDLE_FAIL_MSG,
			    fru_devpath, errno);
			devctl_release(dev_handle);
			return (PSVC_FAILURE);
		} else if ((devctl_device_remove(dev_handle)) &&
		    (errno != ENXIO)) {
				syslog(LOG_ERR, DEVTREE_NODE_DELETE_FAILED,
				    fru_devpath, errno);
				devctl_release(dev_handle);
				return (PSVC_FAILURE);
			} else {
				devctl_release(dev_handle);
				status = PSVC_SUCCESS;
			}

		return (status);
	}

	/*
	 * This code is to update the presences of power supply child
	 * devices in the event that picld was started without a power
	 * supply present.  This call makes the devices available
	 * after that initial insertion.
	 */
	status = handle_ps_hotplug_children_presence(hdlp, id);
	if (status == PSVC_FAILURE) {
		return (status);
	}

	/*
	 * We fall through to here if the device has been inserted.
	 * Add the devinfo tree node entry for the seeprom and attach
	 * the i2c seeprom driver
	 */

	bus_handle = devctl_bus_acquire(I2C_NODE, 0);
	if (bus_handle == NULL) {
		syslog(LOG_ERR, DEVICE_HANDLE_FAIL_MSG, I2C_NODE, errno);
		return (PSVC_FAILURE);
	}
	/* Create the deivce nodes for all 3 i2c parts on the PS */
	for (i = 0; i < 3; i++) {
		ddef_hdl = devctl_ddef_alloc(devices[ps_instance][i].name, 0);
		if (ddef_hdl == NULL) {
			syslog(LOG_ERR, DEVICE_HANDLE_FAIL_MSG,
			    devices[ps_instance][i].name, errno);
			return (PSVC_FAILURE);
		}
		status = devctl_ddef_string(ddef_hdl, "compatible",
		    devices[ps_instance][i].compatible);
		if (status == -1) {
			syslog(LOG_ERR, DEVICE_HANDLE_FAIL_MSG,
			    devices[ps_instance][i].name, errno);
			return (PSVC_FAILURE);
		}
		status = devctl_ddef_int_array(ddef_hdl, "reg", 2,
		    devices[ps_instance][i].addr);
		if (status == -1) {
			syslog(LOG_ERR, DEVICE_HANDLE_FAIL_MSG,
			    devices[ps_instance][i].name, errno);
			return (PSVC_FAILURE);
		}
		if (devctl_bus_dev_create(bus_handle, ddef_hdl, 0,
		    &dev_handle)) {
			syslog(LOG_ERR, DEVTREE_NODE_CREATE_FAILED,
			    devices[ps_instance][i].name, errno);
			return (PSVC_FAILURE);
		} else
			devctl_release(dev_handle);
		devctl_ddef_free(ddef_hdl);
	}
	devctl_release(bus_handle);

	return (status);
}

static void
shutdown_routine()
{
	static boolean_t shutdown_flag = 0;

	if (!(shutdown_flag)) {
		system(shutdown_string);
		shutdown_flag = 1;
	}
}

/*
 * This policy checks temperature sensors to see if the fault attribute
 * is set to either High or Low Shutdown. If so then it shuts the system
 * down with a 1 minute warning period
 */
int32_t
psvc_shutdown_policy(psvc_opaque_t hdlp, char *id)
{
	int32_t	status;
	char	fault[32] = {0};
	boolean_t	pr;
	int	retry;

	status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &pr);
	if ((status != PSVC_SUCCESS) || (pr != PSVC_PRESENT)) {
		return (status);
	}

	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_temp_shutdown);
		status = psvc_get_attr(hdlp, id, PSVC_FAULTID_ATTR, fault);
		if (status != PSVC_SUCCESS)
			return (status);
		retry++;
	} while (((strcmp(fault, PSVC_TEMP_LO_SHUT) == 0) ||
	    (strcmp(fault, PSVC_TEMP_HI_SHUT) == 0)) &&
	    (retry < n_retry_temp_shutdown));
	if ((strcmp(fault, PSVC_TEMP_LO_SHUT) == 0) ||
	    (strcmp(fault, PSVC_TEMP_HI_SHUT) == 0)) {
		shutdown_routine();
	}

	return (PSVC_SUCCESS);
}

int32_t
psvc_check_disk_fault_policy_0(psvc_opaque_t hdlp, char *id)
{
	int32_t		status = PSVC_SUCCESS;
	int32_t		i;
	char		curr_state[32], prev_state[32], led_state[32];
	char		disk_fault[32], disk_state[32];
	static char	*disk_id[DAK_MAX_DISKS] = {NULL};
	static char	*led_id[DAK_MAX_DISKS] = {NULL};
	static char	*parent_id[DAK_MAX_DISKS] = {NULL};
	boolean_t	present;
	int		retry;

	/*
	 * Check which disk faulted, now get the disks.
	 * We are now going to get disk, disk parent,
	 * parent's leds, and check to see if parent's leds are on
	 */

	if (disk_id[0] == NULL) {
		for (i = 0; i < DAK_MAX_DISKS; i++) {
			status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
			    &(disk_id[i]), PSVC_DISK, i);
			if (status != PSVC_SUCCESS)
				return (status);
			status = psvc_get_attr(hdlp, disk_id[i],
			    PSVC_ASSOC_ID_ATTR, &(parent_id[i]),
			    PSVC_PARENT, 0);
			if (status != PSVC_SUCCESS)
				return (status);
			status = psvc_get_attr(hdlp, parent_id[i],
			    PSVC_ASSOC_ID_ATTR, &(led_id[i]),
			    PSVC_SLOT_FAULT_LED, 0);
			if (status != PSVC_SUCCESS)
				return (status);

		}
	}

	for (i = 0; i < DAK_MAX_DISKS; i++) {
		curr_state[0] = 0;
		prev_state[0] = 0;

		status = psvc_get_attr(hdlp, disk_id[i], PSVC_PRESENCE_ATTR,
		    &present);
		if (status != PSVC_SUCCESS)
			return (status);

		if (present == PSVC_ABSENT)
			continue;

		/*
		 * Check if whether or not the led is on.
		 * If so, then this disk has a problem and
		 * set its fault and error states to bad.
		 * If not, then set fault and error states to good.
		 * If the disk underwent a change in state, then
		 * print out what state it's now in.
		 */

		status = psvc_get_attr(hdlp, disk_id[i], PSVC_STATE_ATTR,
		    prev_state);
		if (status != PSVC_SUCCESS)
			return (status);

		retry = 0;
		do {
			if (retry)
				(void) sleep(retry_sleep_diskfault);
			status = psvc_get_attr(hdlp, led_id[i], PSVC_STATE_ATTR,
			    led_state);
			if (status != PSVC_SUCCESS)
				return (status);
			retry++;
			/*
			 * check to see if we need to retry. the conditions are:
			 *
			 * prev_state		led_state		retry
			 * --------------------------------------------------
			 * PSVC_ERROR		PSVC_LED_ON		yes
			 * PSVC_OK		PSVC_LED_OFF		yes
			 * PSVC_ERROR		PSVC_LED_OFF		no
			 * PSVC_OK		PSVC_LED_ON		no
			 */
		} while ((retry < n_retry_diskfault) &&
		    change_of_state_str(prev_state, PSVC_OK,
		    led_state, PSVC_LED_ON));

		/*
		 * Set the disk's state and fault id according to
		 * what we found the disk fault sensor (disk_slot_fault_led)
		 * to be.
		 */
		if (strcmp(led_state, PSVC_LED_ON) == 0) {
			strcpy(disk_fault, PSVC_GEN_FAULT);
			strcpy(disk_state, PSVC_ERROR);
		} else {
			strcpy(disk_fault, PSVC_NO_FAULT);
			strcpy(disk_state, PSVC_OK);
		}
		status = psvc_set_attr(hdlp, disk_id[i], PSVC_STATE_ATTR,
		    disk_state);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_set_attr(hdlp, disk_id[i], PSVC_FAULTID_ATTR,
		    disk_fault);
		if (status != PSVC_SUCCESS)
			return (status);
		/*
		 * Check disk states.  If they differ, then print out
		 * the current state of the disk
		 */
		status = psvc_get_attr(hdlp, disk_id[i], PSVC_PREV_STATE_ATTR,
		    prev_state);
		if (status != PSVC_SUCCESS)
			return (status);

		if (strcmp(disk_state, prev_state) != 0) {
			if (strcmp(disk_state, PSVC_ERROR) == 0) {
				syslog(LOG_ERR, DISK_FAULT_MSG, disk_id[i]);
			} else {
				syslog(LOG_ERR, DISK_OK_MSG, disk_id[i]);
			}
		}
	}
	return (PSVC_SUCCESS);
}

int32_t
psvc_update_FSP_fault_led_policy_0(psvc_opaque_t hdlp, char *id)
{
	int32_t status = PSVC_SUCCESS;
	int32_t i;
	int32_t dev_count, fault_state = 0;
	char	*dev_id;
	char	dev_state[32], led_state[32];
	boolean_t	present;

	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &dev_count,
	    PSVC_DEV_FAULT_SENSOR);
	if (status != PSVC_SUCCESS)
		return (status);

	fault_state = 0;

	for (i = 0; i < dev_count; i++) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
		    &dev_id, PSVC_DEV_FAULT_SENSOR, i);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_get_attr(hdlp, dev_id, PSVC_PRESENCE_ATTR,
		    &present);
		if (status != PSVC_SUCCESS)
			return (status);

		if (present == PSVC_ABSENT)
			continue;

		status = psvc_get_attr(hdlp, dev_id, PSVC_STATE_ATTR,
		    dev_state);
		if (status != PSVC_SUCCESS)
			return (status);

		if (strcmp(dev_state, PSVC_ERROR) == 0) {
			fault_state = 1;
		}
	}
	if (fault_state == 1) {
		status = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, led_state);
		if (status != PSVC_SUCCESS)
			return (status);
		if (strcmp(led_state, PSVC_OFF) == 0) {
			status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR,
			    PSVC_ON);
			if (status != PSVC_SUCCESS)
				return (status);
		}
	} else {
		status = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, led_state);
		if (status != PSVC_SUCCESS)
			return (status);
		if (strcmp(led_state, PSVC_ON) == 0) {
			status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR,
			    PSVC_OFF);
			if (status != PSVC_SUCCESS)
				return (status);
		}
	}
	status = update_gen_fault_led(hdlp, GEN_FAULT_LED);

	return (status);
}

int32_t
update_gen_fault_led(psvc_opaque_t hdlp, char *id)
{
	int32_t status = PSVC_SUCCESS;
	int32_t i;
	int32_t led_count, fault_state;
	char	*led_id;
	char	led_state[32];

	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &led_count,
	    PSVC_DEV_FAULT_SENSOR);
	if (status != PSVC_SUCCESS)
		return (status);

	fault_state = 0;

	for (i = 0; i < led_count; i++) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
		    &led_id, PSVC_DEV_FAULT_SENSOR, i);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_get_attr(hdlp, led_id, PSVC_STATE_ATTR,
		    led_state);
		if (status != PSVC_SUCCESS)
			return (status);

		if (strcmp(led_state, PSVC_ON) == 0) {
			fault_state = 1;
		}
	}

	if (fault_state == 1) {
		status = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, led_state);
		if (status != PSVC_SUCCESS)
			return (status);
		if (strcmp(led_state, PSVC_OFF) == 0) {
			status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR,
			    PSVC_ON);
			if (status != PSVC_SUCCESS)
				return (status);
		}
	} else {
		status = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, led_state);
		if (status != PSVC_SUCCESS)
			return (status);
		if (strcmp(led_state, PSVC_ON) == 0) {
			status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR,
			    PSVC_OFF);
			if (status != PSVC_SUCCESS)
				return (status);
		}
	}

	return (status);
}


/*
 * This function detects whether the module present in the dakatari's
 * CPU slot is a CPU module or a Zulu (XVR-4000).
 * Based on this detection it also sets the appropriate temperature sensors
 * to HOTPLUGGED, so that it works properly with check_temp() function
 */
#define	MAX_MODULE_SIZE		20
#define	MAX_TEMP_SENSOR_SIZE	30

int32_t
psvc_update_cpu_module_card_node_0(psvc_opaque_t hdlp, char *id)
{
	int32_t	set_temp_sensor_properties(psvc_opaque_t, char *);
	int32_t	remove_module_node(psvc_opaque_t, char *);
	int32_t status = PSVC_SUCCESS;
	fru_info_t fru_data;
	char *fru, seg_name[2];
	int8_t seg_count, module_card;
	int32_t match_count, i, j, seg_desc_start = 0x1806, module_address;
	int32_t seg_found;
	boolean_t present;
	seg_desc_t segment;
	char other_module_id[MAX_MODULE_SIZE];
	char cpu_temp_sensor1[MAX_TEMP_SENSOR_SIZE];
	char cpu_temp_sensor2[MAX_TEMP_SENSOR_SIZE];
	char zulu_temp_sensor1[MAX_TEMP_SENSOR_SIZE];
	char zulu_temp_sensor2[MAX_TEMP_SENSOR_SIZE];
	int offset = 0x7;

	status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &present);
	if ((status != PSVC_SUCCESS) || (present != PSVC_PRESENT)) {
		return (status);
	}

	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &match_count,
	    PSVC_FRU);
	if (status == PSVC_FAILURE) {
		return (status);
	}

	for (i = 0; i < match_count; i++) {
		seg_found = 0;
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR, &fru,
		    PSVC_FRU, i);
		if (status != PSVC_SUCCESS)
			return (status);

		fru_data.buf_start = 0x1805;
		fru_data.buf = (char *)&seg_count;
		fru_data.read_size = 1;

		status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
		    &fru_data);
		if (status != PSVC_SUCCESS) {
			return (status);
		}

		for (j = 0; (j < seg_count) && (!seg_found); j++) {
			fru_data.buf_start = seg_desc_start;
			fru_data.buf = seg_name;
			fru_data.read_size = 2;

			status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
			    &fru_data);
			if (status != PSVC_SUCCESS) {
				syslog(LOG_ERR, GET_ATTR_FRU_FAILED_MSG);
				return (status);
			}

			seg_desc_start = seg_desc_start + 2;
			fru_data.buf_start = seg_desc_start;
			fru_data.buf = (char *)&segment;
			fru_data.read_size = sizeof (seg_desc_t);

			status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
			    &fru_data);
			if (status != PSVC_SUCCESS) {
				syslog(LOG_ERR, GET_ATTR_FRU_FAILED_MSG);
				return (status);
			}
			seg_desc_start = seg_desc_start + sizeof (seg_desc_t);
			if (memcmp(seg_name, "SC", 2) == 0)
				seg_found = 1;
		}

		if (seg_found) {
			module_address = segment.segoffset + offset;
			fru_data.buf_start = module_address;
			fru_data.buf = (char *)&module_card;
			fru_data.read_size = 1;
			status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
			    &fru_data);
			if (status != PSVC_SUCCESS) {
				syslog(LOG_ERR, GET_ATTR_FRU_FAILED_MSG);
				return (status);
			}
		} else {
			syslog(LOG_ERR, NO_FRU_INFO_MSG, id);
		}
	}

	if (strcmp(id, "ZULU_1_3_MOD_CARD") == 0) {
		strlcpy(other_module_id, "CPU_1_3_MOD_CARD", MAX_MODULE_SIZE);

		strlcpy(cpu_temp_sensor1, "CPU1_DIE_TEMPERATURE_SENSOR",
		    MAX_TEMP_SENSOR_SIZE);
		strlcpy(cpu_temp_sensor2, "CPU3_DIE_TEMPERATURE_SENSOR",
		    MAX_TEMP_SENSOR_SIZE);

		strlcpy(zulu_temp_sensor1, "ZULU1_DIE_TEMPERATURE_SENSOR",
		    MAX_TEMP_SENSOR_SIZE);
		strlcpy(zulu_temp_sensor2, "ZULU3_DIE_TEMPERATURE_SENSOR",
		    MAX_TEMP_SENSOR_SIZE);
	}

	if (strcmp(id, "ZULU_4_6_MOD_CARD") == 0) {
		strlcpy(other_module_id, "CPU_4_6_MOD_CARD", MAX_MODULE_SIZE);

		strlcpy(cpu_temp_sensor1, "CPU4_DIE_TEMPERATURE_SENSOR",
		    MAX_TEMP_SENSOR_SIZE);
		strlcpy(cpu_temp_sensor2, "CPU6_DIE_TEMPERATURE_SENSOR",
		    MAX_TEMP_SENSOR_SIZE);

		strlcpy(zulu_temp_sensor1, "ZULU4_DIE_TEMPERATURE_SENSOR",
		    MAX_TEMP_SENSOR_SIZE);
		strlcpy(zulu_temp_sensor2, "ZULU6_DIE_TEMPERATURE_SENSOR",
		    MAX_TEMP_SENSOR_SIZE);
	}


	/*
	 * If the module in the CPU slot is a Zulu (XVR-4000), then
	 * location 0x1EB0 in its FRUid prom has a value 0xFB.
	 * If Zulu (XVR-4000) is detected, delete the CPU node, otherwise
	 * delete the Zulu node. Also set the temperature sensor value to
	 * HOTPLUGGED for absent temperature sensors.
	 */
	if ((module_card & 0xff) == 0xfb) {
		status = set_temp_sensor_properties(hdlp, cpu_temp_sensor1);
		if (status == PSVC_FAILURE) {
			return (status);
		}

		status = set_temp_sensor_properties(hdlp, cpu_temp_sensor2);
		if (status == PSVC_FAILURE) {
			return (status);
		}

		/*
		 * Remove CPU node
		 */
		status = remove_module_node(hdlp, other_module_id);
		if (status == PSVC_FAILURE) {
			return (status);
		}
	} else {
		status = set_temp_sensor_properties(hdlp, zulu_temp_sensor1);
		if (status == PSVC_FAILURE) {
			return (status);
		}
		status = set_temp_sensor_properties(hdlp, zulu_temp_sensor2);
		if (status == PSVC_FAILURE) {
			return (status);
		}

		/*
		 * Remove Zulu (XVR-4000) node
		 */
		status = remove_module_node(hdlp, id);
		if (status == PSVC_FAILURE) {
			return (status);
		}
	}

	return (PSVC_SUCCESS);
}


/*
 * Remove the CPU slot's module node
 */
int32_t
remove_module_node(psvc_opaque_t hdlp, char *id)
{
	char parent_path[256];
	picl_nodehdl_t child_node;

	/* convert name to node, and parent path */
	psvcplugin_lookup(id, parent_path, &child_node);
	/* Device removed */
	ptree_delete_node(child_node);

	return (PSVC_SUCCESS);
}


/*
 * Set absent temperature sensor values to HOTPLUGGED
 */
int32_t
set_temp_sensor_properties(psvc_opaque_t hdlp, char *id)
{
	char state[32];
	int32_t status = PSVC_SUCCESS;

	status = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, state);
	if (status == PSVC_FAILURE) {
		return (status);
	}

	if (strcmp(state, PSVC_HOTPLUGGED) != 0) {
		strcpy(state, PSVC_HOTPLUGGED);

		status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, state);
		if (status == PSVC_FAILURE) {
			return (status);
		}
	}

	return (PSVC_SUCCESS);
}
