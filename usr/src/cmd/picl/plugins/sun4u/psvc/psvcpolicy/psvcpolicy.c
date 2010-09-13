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
 *
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains routines to support the Platform Services Plugin
 * These routines implement the platform independent environment monitoring
 * and control policies that may be invoked by a daemon thread within
 * the plugin
 */

#include <syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <libintl.h>
#include <sys/types.h>
#include <string.h>
#include <limits.h>
#include <picl.h>
#include <picltree.h>
#include <sys/types.h>
#include <string.h>
#include <psvc_objects.h>

#define	LOWTEMP_CRITICAL_MSG		\
	gettext("CRITICAL : LOW TEMPERATURE DETECTED %d, %s")
#define	LOWTEMP_WARNING_MSG		\
	gettext("WARNING : LOW TEMPERATURE DETECTED %d, %s")
#define	HIGHTEMP_CRITICAL_MSG		\
	gettext("CRITICAL : HIGH TEMPERATURE DETECTED %d, %s")
#define	HIGHTEMP_WARNING_MSG		\
	gettext("WARNING : HIGH TEMPERATURE DETECTED %d, %s")
#define	DEVICE_INSERTED_MSG	gettext("Device %s inserted")
#define	DEVICE_REMOVED_MSG	gettext("Device %s removed")
#define	DEVICE_FAILURE_MSG		\
	gettext("CRITICAL: Device %s failure detected by sensor %s\n")
#define	DEVICE_OK_MSG	gettext("Device %s OK")
#define	SECONDARY_FAN_FAIL_MSG	gettext("Secondary fan failure, device %s")
#define	KEYSWITCH_POS_READ_FAILED_MSG	\
	gettext("Keyswitch position could not be determined")
#define	KEYSWITCH_POS_CHANGED_MSG gettext("Keyswitch position changed to %s")
#define	GET_PRESENCE_FAILED_MSG		\
	gettext("Failed to get presence attribute, id = %s, errno = %d\n")
#define	GET_SENSOR_FAILED_MSG		\
	gettext("Failed to get sensor value, id = %s, errno = %d\n")
#define	PS_OVER_CURRENT_MSG		\
	gettext("WARNING: Power Supply overcurrent detected for %s\n")
#define	SET_LED_FAILED_MSG		\
	gettext("Failed to set LED state, id = %s, errno = %d\n")
#define	SET_FANSPEED_FAILED_MSG		\
	gettext("Failed to set fan speed, id = %s, errno = %d\n")
#define	FAN_MISSING_MSG			\
	gettext("WARNING: Fan missing, id = %s\n")
#define	TEMP_SENSOR_FAULT		\
	gettext("WARNING: Temperature Sensor %s returning faulty temp\n")
#define	TEMP_OFFSET	17

static char *shutdown_string = "shutdown -y -g 60 -i 5 \"OVERTEMP condition\"";

static int cpus_online = 0;

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
static int n_read_temp = PSVC_THRESHOLD_COUNTER;
static int n_retry_keyswitch = PSVC_NUM_OF_RETRIES;
static int retry_sleep_keyswitch = 1;
static int n_retry_hotplug = PSVC_NUM_OF_RETRIES;
static int retry_sleep_hotplug = 1;
static int n_retry_fan_hotplug = PSVC_NUM_OF_RETRIES;
static int retry_sleep_fan_hotplug = 1;
static int n_retry_fan_present = PSVC_NUM_OF_RETRIES;
static int retry_sleep_fan_present = 1;

typedef struct {
	int *pvar;
	char *texttag;
} i2c_noise_param_t;

static i2c_noise_param_t i2cparams_sun4u[] = {
	&n_read_temp, "n_read_temp",
	&n_retry_keyswitch, "n_retry_keyswitch",
	&retry_sleep_keyswitch, "retry_sleep_keyswitch",
	&n_retry_hotplug, "n_retry_hotplug",
	&retry_sleep_hotplug, "retry_sleep_hotplug",
	&n_retry_fan_hotplug, "n_retry_fan_hotplug",
	&retry_sleep_fan_hotplug, "retry_sleep_fan_hotplug",
	&n_retry_fan_present, "n_retry_fan_present",
	&retry_sleep_fan_present, "retry_sleep_fan_present",
	NULL, NULL
};

#pragma init(i2cparams_sun4u_load)

static void
i2cparams_sun4u_debug(i2c_noise_param_t *pi2cparams, int usingDefaults)
{
	char s[128];
	i2c_noise_param_t *p;

	if (!usingDefaults) {
		(void) strncpy(s,
		    "# Values from /usr/platform/sun4u/lib/i2cparam.conf\n",
			sizeof (s) - 1);
		syslog(LOG_WARNING, "%s", s);
	} else {
		/* no file - we're using the defaults */
		(void) strncpy(s,
"# No /usr/platform/sun4u/lib/i2cparam.conf file, using defaults\n",
			sizeof (s) - 1);
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
i2cparams_sun4u_load(void)
{
	FILE *fp;
	char *filename = "/usr/platform/sun4u/lib/i2cparam.conf";
	char s[128];
	char var[128];
	int val;
	i2c_noise_param_t *p;

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
			p = &(i2cparams_sun4u[0]);
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
	i2cparams_sun4u_debug(&(i2cparams_sun4u[0]), ((fp == NULL)? 1 : 0));
}


int32_t
psvc_update_thresholds_0(psvc_opaque_t hdlp, char *id)
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
			temp_address = segment.segoffset + TEMP_OFFSET;
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
					if (threshold_names[j] == PSVC_NOT_USED)
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

#define	MAX_TEMP_SENSORS	256

static int32_t
check_temp(psvc_opaque_t hdlp, char *id, int32_t silent)
{
	int32_t		lo_warn, hi_warn, lo_shut, hi_shut;
	uint64_t	features;
	int32_t		temp;
	char		previous_state[32];
	char		led_state[32];
	char		state[32];
	char		fault[32];
	char		label[32];
	boolean_t	pr;
	int32_t		status = PSVC_SUCCESS;
	int8_t		fail = 0;
	static int	threshold_low_shut[MAX_TEMP_SENSORS] = {0};
	static int	threshold_high_shut[MAX_TEMP_SENSORS] = {0};
	static int	threshold_low_warn[MAX_TEMP_SENSORS] = {0};
	static int	threshold_high_warn[MAX_TEMP_SENSORS] = {0};
	int32_t		instance;

	status = psvc_get_attr(hdlp, id, PSVC_INSTANCE_ATTR, &instance);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &pr);
	if ((status != PSVC_SUCCESS) || (pr != PSVC_PRESENT)) {
		return (status);
	}

	status = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, state);
	if (status == PSVC_FAILURE)
		return (status);

	if ((strcmp(state, PSVC_HOTPLUGGED) == 0)) {
		return (PSVC_SUCCESS);
	}

	status = psvc_get_attr(hdlp, id, PSVC_FEATURES_ATTR, &features);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_LO_WARN_ATTR, &lo_warn);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_LO_SHUT_ATTR, &lo_shut);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_HI_WARN_ATTR, &hi_warn);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_HI_SHUT_ATTR, &hi_shut);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_SENSOR_VALUE_ATTR, &temp);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	/*
	 * The following code is to check to see if the temp sensor is
	 * returning a faulty reading due to it either being bad or the
	 * CPU being powered off for some reason. Is so we will alert the user
	 * and just label the sensor bad but not the WHOLE CPU module.
	 */
	if ((temp == 127) && (strcmp(state, PSVC_ERROR) != 0)) {
		status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, PSVC_ERROR);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR,
		    PSVC_GEN_FAULT);
		if (status != PSVC_SUCCESS)
			return (status);
		syslog(LOG_ERR, TEMP_SENSOR_FAULT, id);
		return (status);
	}

	status = psvc_get_attr(hdlp, id, PSVC_LABEL_ATTR, label);
	if (status != PSVC_SUCCESS)
		return (status);

	/*
	 * if any of the four temperature states (lo_shut, lo_warn,
	 * hi_shut, hi_warn) is detected we will not take an action
	 * until the number of similar back-to-back readings equals
	 * 'n_read_temp' (default is PSVC_THRESHOLD_COUNTER).
	 */
	if ((features & PSVC_LOW_SHUT) && temp < lo_shut) {
		/*
		 * once we are in one state, clear all the
		 * counters for the other three states since
		 * back-to-back readings of these other three
		 * states could not happen anymore.
		 */
		threshold_low_warn[instance] = 0;
		threshold_high_shut[instance] = 0;
		threshold_high_warn[instance] = 0;
		threshold_low_shut[instance]++;
		if (threshold_low_shut[instance] == n_read_temp) {
			threshold_low_shut[instance] = 0;
			fail = 1;
			strcpy(state, PSVC_ERROR);
			strcpy(fault, PSVC_TEMP_LO_SHUT);
			strcpy(led_state, PSVC_LED_ON);
			if (silent == 0)
				syslog(LOG_ERR, LOWTEMP_CRITICAL_MSG,
				    temp, label);
		} else { /* Threshold for showing error not reached */
			return (PSVC_SUCCESS);
		}
	} else if ((features & PSVC_LOW_WARN) && temp < lo_warn) {
		threshold_low_shut[instance] = 0;
		threshold_high_shut[instance] = 0;
		threshold_high_warn[instance] = 0;
		threshold_low_warn[instance]++;
		if (threshold_low_warn[instance] == n_read_temp) {
			threshold_low_warn[instance] = 0;
			fail = 1;
			strcpy(state, PSVC_ERROR);
			strcpy(fault, PSVC_TEMP_LO_WARN);
			strcpy(led_state, PSVC_LED_ON);
			if (silent == 0)
				syslog(LOG_ERR, LOWTEMP_WARNING_MSG,
				    temp, label);
		} else { /* Threshold for showing error not reached */
			return (PSVC_SUCCESS);
		}
	} else if ((features & PSVC_HIGH_SHUT) && temp > hi_shut) {
		threshold_low_warn[instance] = 0;
		threshold_low_shut[instance] = 0;
		threshold_high_warn[instance] = 0;
		threshold_high_shut[instance]++;
		if (threshold_high_shut[instance] == n_read_temp) {
			threshold_high_shut[instance] = 0;
			fail = 1;
			strcpy(state, PSVC_ERROR);
			strcpy(fault, PSVC_TEMP_HI_SHUT);
			strcpy(led_state, PSVC_LED_ON);
			if (silent == 0)
				syslog(LOG_ERR, HIGHTEMP_CRITICAL_MSG,
				    temp, label);
		} else { /* Threshold for showing error not reached */
			return (PSVC_SUCCESS);
		}
	} else if ((features & PSVC_HIGH_WARN) && temp > hi_warn) {
		threshold_low_warn[instance] = 0;
		threshold_low_shut[instance] = 0;
		threshold_high_shut[instance] = 0;
		threshold_high_warn[instance]++;
		if (threshold_high_warn[instance] == n_read_temp) {
			threshold_high_warn[instance] = 0;
			fail = 1;
			strcpy(state, PSVC_ERROR);
			strcpy(fault, PSVC_TEMP_HI_WARN);
			strcpy(led_state, PSVC_LED_ON);
			if (silent == 0)
				syslog(LOG_ERR, HIGHTEMP_WARNING_MSG,
				    temp, label);
		} else { /* Threshold for showing error not reached */
			return (PSVC_SUCCESS);
		}
	}

	/*
	 * If we reached this point then that means that we are either
	 * okay, or we have showed error n_read_temp times.
	 */
	if (fail != 1) {
		/* within limits */
		strcpy(state, PSVC_OK);
		strcpy(fault, PSVC_NO_FAULT);
		strcpy(led_state, PSVC_LED_OFF);
	}

	status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, state);
	if (status != PSVC_SUCCESS)
		return (status);
	status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR, fault);
	if (status != PSVC_SUCCESS)
		return (status);
	status = psvc_get_attr(hdlp, id, PSVC_PREV_STATE_ATTR,
		previous_state);
	if (status != PSVC_SUCCESS)
		return (status);

	if (strcmp(previous_state, state) != 0) {
		char *led_id;
		int32_t led_count;
		int32_t i;

		/* change state of fault LEDs */
		psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &led_count,
			PSVC_TS_OVERTEMP_LED);
		for (i = 0; i < led_count; ++i) {
			status = psvc_get_attr(hdlp, id,
				PSVC_ASSOC_ID_ATTR, &led_id,
				PSVC_TS_OVERTEMP_LED, i);
			if (status == PSVC_FAILURE)
				return (status);
			status = psvc_set_attr(hdlp, led_id,
				PSVC_LED_STATE_ATTR, led_state);
			if (status == PSVC_FAILURE)
				return (status);
		}
	}

	return (PSVC_SUCCESS);
}

int32_t
psvc_check_temperature_policy_0(psvc_opaque_t hdlp, char *id)
{
	return (check_temp(hdlp, id, 0));
}

int32_t
psvc_check_temperature_silent_policy_0(psvc_opaque_t hdlp, char *id)
{
	return (check_temp(hdlp, id, 1));
}

int32_t
psvc_fan_enable_disable_policy_0(psvc_opaque_t hdlp, char *id)
{
	char state[32], previous_state[32];
	char *backup_fan;
	int32_t status = PSVC_SUCCESS;
	uint64_t features;
	char label[32];
	boolean_t presence;
	boolean_t enable;
	int retry;

	status = psvc_get_attr(hdlp, id, PSVC_FEATURES_ATTR, &features);
	if (status != PSVC_SUCCESS)
		return (status);

	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_fan_present);

		status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &presence);
		if (status != PSVC_SUCCESS)
			return (status);
		retry++;
	} while ((retry < n_retry_fan_present) && (presence == PSVC_ABSENT));

	if (presence == PSVC_ABSENT) {
		status = psvc_get_attr(hdlp, id, PSVC_LABEL_ATTR, label);
		if (status != PSVC_SUCCESS)
			return (status);

		status = psvc_get_attr(hdlp, id, PSVC_ENABLE_ATTR, &enable);
		if (status != PSVC_SUCCESS)
			return (status);

		if (features & PSVC_DEV_PRIMARY) {
			status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
				&backup_fan, PSVC_ALTERNATE, 0);
			if (status != PSVC_SUCCESS)
				return (status);

			enable = PSVC_DISABLED;
			status = psvc_set_attr(hdlp, id, PSVC_ENABLE_ATTR,
				&enable);
			if (status != PSVC_SUCCESS)
				return (status);

			enable = PSVC_ENABLED;
			status = psvc_set_attr(hdlp, backup_fan,
				PSVC_ENABLE_ATTR, &enable);
			if (status != PSVC_SUCCESS)
				return (status);
		} else {
			enable = PSVC_DISABLED;
			status = psvc_set_attr(hdlp, id, PSVC_ENABLE_ATTR,
				&enable);
			if (status != PSVC_SUCCESS)
				return (status);
		}
		return (PSVC_SUCCESS);
	}

	/* device was present */
	status = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, state);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_PREV_STATE_ATTR, previous_state);
	if (status != PSVC_SUCCESS)
		return (status);

	if (features & PSVC_DEV_PRIMARY) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
			&backup_fan, PSVC_ALTERNATE, 0);
		if (status != PSVC_SUCCESS)
			return (status);

		if (strcmp(state, PSVC_OK) == 0) {
			enable = PSVC_ENABLED;
			status = psvc_set_attr(hdlp, id, PSVC_ENABLE_ATTR,
				&enable);
			if (status != PSVC_SUCCESS)
				return (status);

			enable = PSVC_DISABLED;
			status = psvc_set_attr(hdlp, backup_fan,
				PSVC_ENABLE_ATTR, &enable);
			if (status != PSVC_SUCCESS)
				return (status);
		}
		if ((strcmp(state, PSVC_ERROR) == 0) &&
			(strcmp(previous_state, PSVC_ERROR) != 0)) {
			enable = PSVC_DISABLED;
			status = psvc_set_attr(hdlp, id, PSVC_ENABLE_ATTR,
				&enable);
			if (status != PSVC_SUCCESS)
				return (status);

			enable = PSVC_ENABLED;
			status = psvc_set_attr(hdlp, backup_fan,
				PSVC_ENABLE_ATTR, &enable);
			if (status != PSVC_SUCCESS)
				return (status);
		}
	} else {
		if ((strcmp(state, PSVC_ERROR) == 0) &&
			(strcmp(previous_state, PSVC_ERROR) != 0)) {
			status = psvc_get_attr(hdlp, id, PSVC_LABEL_ATTR,
				label);
			if (status != PSVC_SUCCESS)
				return (status);
			syslog(LOG_ERR, SECONDARY_FAN_FAIL_MSG, label);
		}
	}
	return (status);
}

/*
 * psvc_switch_fan_onoff_policy_0
 * Turn a fan on if it is enabled, turn it off if it is disabled.
 */
int32_t
psvc_switch_fan_onoff_policy_0(psvc_opaque_t hdlp, char *id)
{
	boolean_t enable;
	char *switchid;
	char state[32];
	int32_t status = PSVC_SUCCESS;

	status = psvc_get_attr(hdlp, id, PSVC_ENABLE_ATTR, &enable);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR, &switchid,
		PSVC_FAN_ONOFF_SENSOR, 0);
	if (status != PSVC_SUCCESS)
		return (status);

	if (enable == PSVC_DISABLED) {
		strcpy(state, PSVC_SWITCH_OFF);
	} else {
		strcpy(state, PSVC_SWITCH_ON);
	}

	status = psvc_set_attr(hdlp, switchid, PSVC_SWITCH_STATE_ATTR, state);
	return (status);
}

static int32_t
check_cpu_temp_fault(psvc_opaque_t hdlp, char *cpu, int32_t cpu_count)
{
	char *sensorid;
	int32_t sensor_count;
	int32_t status = PSVC_SUCCESS;
	int32_t i;
	uint64_t features;
	char fault[32];

	status = psvc_get_attr(hdlp, cpu, PSVC_FEATURES_ATTR, &features);
	if (status == PSVC_FAILURE)
		return (status);

	psvc_get_attr(hdlp, cpu, PSVC_ASSOC_MATCHES_ATTR, &sensor_count,
		PSVC_DEV_TEMP_SENSOR);
	for (i = 0; i < sensor_count; ++i) {
		status = psvc_get_attr(hdlp, cpu, PSVC_ASSOC_ID_ATTR,
			&sensorid, PSVC_DEV_TEMP_SENSOR, i);
		if (status == PSVC_FAILURE)
			return (status);

		status = psvc_get_attr(hdlp, sensorid, PSVC_FAULTID_ATTR,
			fault);
		if (status == PSVC_FAILURE)
			return (status);

		if ((strcmp(fault, PSVC_TEMP_HI_SHUT) == 0) ||
			(strcmp(fault, PSVC_TEMP_LO_SHUT) == 0)) {
			if (cpu_count == 1 || cpus_online == 1 ||
			    !(features & PSVC_DEV_HOTPLUG)) {
				system(shutdown_string);
			} else {
				/* FIX offline cpu */
				--cpus_online;
			}
		}
	}

	return (status);
}

int32_t
psvc_shutdown_policy_0(psvc_opaque_t hdlp, char *id)
{
	int32_t cpu_count;
	char *cpuid;
	int32_t i;
	boolean_t present;
	int32_t status = PSVC_SUCCESS;

	if (cpus_online == 0) {
		/* obviously, zero isn't correct, count present cpu's */
		psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &cpu_count,
			PSVC_CPU);
		for (i = 0; i < cpu_count; ++i) {
			status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
				&cpuid, PSVC_CPU, i);
			if (status == PSVC_FAILURE)
				return (status);

			status = psvc_get_attr(hdlp, cpuid,
				PSVC_PRESENCE_ATTR, &present);
			if (status == PSVC_FAILURE && present == PSVC_PRESENT)
				return (status);
			if (present == PSVC_PRESENT)
				++cpus_online;
		}
	}
	psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &cpu_count,
		PSVC_CPU);
	for (i = 0; i < cpu_count; ++i) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR, &cpuid,
			PSVC_CPU, i);
		if (status == PSVC_FAILURE)
			return (status);
		status = check_cpu_temp_fault(hdlp, cpuid, cpu_count);
		if (status == PSVC_FAILURE && errno != ENODEV)
			return (status);
	}

	return (PSVC_SUCCESS);
}

/*
 * psvc_keyswitch_position_policy_0
 * Checks the state of the keyswitch sensors.
 * If a keyswitch position sensor's state is on, the position
 * of the key is written to syslog.  If none of the sensors
 * are on (keyswitch is not at one of the detents), a message is sent
 * to syslog stating that the position is unknown.
 */
int32_t
psvc_keyswitch_position_policy_0(psvc_opaque_t hdlp, char *id)
{
	char position[32];
	int32_t status = PSVC_SUCCESS;
	static int error_reported = 0;
	static char local_previous_position[32];
	static int32_t first_time = 1;
	int retry;

	if (first_time) {
		first_time = 0;
		status = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR,
		    local_previous_position);
		if (status != PSVC_SUCCESS)
			return (status);
	}

	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_keyswitch);

		status = psvc_get_attr(hdlp, id, PSVC_SWITCH_STATE_ATTR,
		    position);
		if (status != PSVC_SUCCESS)
			return (status);

		if (strcmp(position, PSVC_ERROR) == 0) {
			if ((errno == EINVAL) && (!(error_reported))) {
				syslog(LOG_ERR,
				    KEYSWITCH_POS_READ_FAILED_MSG);
				error_reported = 1;
				return (PSVC_SUCCESS);
			}
		}
		retry++;
	} while ((retry < n_retry_keyswitch) &&
	    (strcmp(position, local_previous_position) != 0));

	status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, position);
	if (status != PSVC_SUCCESS)
		return (status);

	if (strcmp(position, local_previous_position) != 0) {
		error_reported = 0;
		strcpy(local_previous_position, position);
		syslog(LOG_ERR, KEYSWITCH_POS_CHANGED_MSG, position);
	}

	return (status);
}

int32_t
psvc_hotplug_notifier_policy_0(psvc_opaque_t hdlp, char *id)
{
	boolean_t presence, previous_presence;
	int32_t status = PSVC_SUCCESS;
	char label[32];
	int retry;

	status = psvc_get_attr(hdlp, id, PSVC_PREV_PRESENCE_ATTR,
		&previous_presence);
	if (status != PSVC_SUCCESS)
		return (status);

	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_hotplug);
		status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &presence);
		if (status != PSVC_SUCCESS)
			return (status);
		retry++;
	} while ((retry < n_retry_hotplug) &&
	    (presence != previous_presence));


	if (presence != previous_presence) {
		char parent_path[256];
		picl_nodehdl_t child_node;

		status = psvc_get_attr(hdlp, id, PSVC_LABEL_ATTR, label);
		if (status != PSVC_SUCCESS)
			return (status);

		/* return parent path and node for an object */
		psvcplugin_lookup(id, parent_path, &child_node);

		if (presence == PSVC_PRESENT) {
			char state[32], fault[32];
			picl_nodehdl_t parent_node;

			syslog(LOG_ERR, DEVICE_INSERTED_MSG, label);
			strcpy(state, PSVC_OK);
			status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR,
				state);
			if (status != PSVC_SUCCESS)
				return (status);
			strcpy(fault, PSVC_NO_FAULT);
			status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR,
				fault);
			if (status != PSVC_SUCCESS) {
				return (status);
			}

			status = ptree_get_node_by_path(parent_path,
				&parent_node);
			if (status != 0)
				return (PSVC_FAILURE);
			status = ptree_add_node(parent_node, child_node);
			if (status != 0)
				return (PSVC_FAILURE);
		} else {
			syslog(LOG_ERR, DEVICE_REMOVED_MSG, label);

			ptree_delete_node(child_node);

		}
	}

	status = psvc_set_attr(hdlp, id, PSVC_PREV_PRESENCE_ATTR, &presence);
	if (status != PSVC_SUCCESS)
		return (status);

	return (status);
}

int32_t
psvc_fan_hotplug_policy_0(psvc_opaque_t hdlp, char *id)
{
	boolean_t presence, previous_presence;
	int32_t status = PSVC_SUCCESS;
	char label[32];
	int retry;

	status = psvc_get_attr(hdlp, id, PSVC_PREV_PRESENCE_ATTR,
		&previous_presence);
	if (status != PSVC_SUCCESS)
		return (status);

	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_fan_hotplug);

		status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &presence);
		if (status != PSVC_SUCCESS)
			return (status);
		retry++;
	} while ((retry < n_retry_fan_hotplug) &&
	    (presence != previous_presence));


	if (presence != previous_presence) {
		char parent_path[256];
		picl_nodehdl_t child_node;

		status = psvc_get_attr(hdlp, id, PSVC_LABEL_ATTR, label);
		if (status != PSVC_SUCCESS)
			return (status);

		/* return parent path and node for an object */
		psvcplugin_lookup(id, parent_path, &child_node);

		if (presence == PSVC_PRESENT) {
			char state[32], fault[32];
			char *slot_id;
			char *led_id;
			int32_t i, led_count;
			char led_state[32];
			picl_nodehdl_t parent_node;

			syslog(LOG_ERR, DEVICE_INSERTED_MSG, label);

			strcpy(state, PSVC_OK);
			status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR,
				state);
			if (status != PSVC_SUCCESS)
				return (status);
			strcpy(fault, PSVC_NO_FAULT);
			status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR,
				fault);
			if (status != PSVC_SUCCESS)
				return (status);

			/* turn off fault LEDs */
			psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR,
				&led_count, PSVC_DEV_FAULT_LED);
			strcpy(led_state, PSVC_LED_OFF);
			for (i = 0; i < led_count; ++i) {
				status = psvc_get_attr(hdlp, id,
					PSVC_ASSOC_ID_ATTR, &led_id,
					PSVC_DEV_FAULT_LED, i);
				if (status == PSVC_FAILURE)
					return (status);
				status = psvc_set_attr(hdlp, led_id,
					PSVC_LED_STATE_ATTR, led_state);
				if (status == PSVC_FAILURE)
					return (status);
			}

			/* turn off OK to remove LEDs */
			status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
				&slot_id, PSVC_PARENT, 0);
			if (status != PSVC_SUCCESS)
				return (status);

			psvc_get_attr(hdlp, slot_id, PSVC_ASSOC_MATCHES_ATTR,
				&led_count, PSVC_SLOT_REMOVE_LED);
			strcpy(led_state, PSVC_LED_OFF);
			for (i = 0; i < led_count; ++i) {
				status = psvc_get_attr(hdlp, slot_id,
					PSVC_ASSOC_ID_ATTR, &led_id,
					PSVC_SLOT_REMOVE_LED, i);
				if (status == PSVC_FAILURE)
					return (status);

				status = psvc_set_attr(hdlp, led_id,
					PSVC_LED_STATE_ATTR, led_state);
				if (status == PSVC_FAILURE)
					return (status);
			}

			ptree_get_node_by_path(parent_path, &parent_node);
			ptree_add_node(parent_node, child_node);
		} else {
			syslog(LOG_ERR, DEVICE_REMOVED_MSG, label);
			ptree_delete_node(child_node);
		}
	}

	status = psvc_set_attr(hdlp, id, PSVC_PREV_PRESENCE_ATTR, &presence);
	if (status != PSVC_SUCCESS)
		return (status);

	return (status);
}

int32_t
psvc_init_led_policy_0(psvc_opaque_t hdlp, char *id)
{
	int32_t status;

	status = psvc_set_attr(hdlp, id, PSVC_LED_STATE_ATTR, PSVC_LED_OFF);
	return (status);
}

int32_t
psvc_init_state_policy_0(psvc_opaque_t hdlp, char *id)
{
	int32_t status;

	status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, PSVC_OK);
	status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR, PSVC_NO_FAULT);
	return (status);
}

int32_t
psvc_ps_overcurrent_check_policy_0(psvc_opaque_t hdlp, char *power_supply_id)
{
	int32_t status = PSVC_SUCCESS;
	boolean_t present;
	char *sensor_id;
	int32_t sensor_count;
	int32_t i;
	int32_t amps, hi_warn;

	status = psvc_get_attr(hdlp, power_supply_id, PSVC_PRESENCE_ATTR,
		&present);
	if (status == PSVC_FAILURE) {
		syslog(LOG_ERR, GET_PRESENCE_FAILED_MSG, power_supply_id,
			errno);
		return (status);
	}

	if (present == PSVC_ABSENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	psvc_get_attr(hdlp, power_supply_id, PSVC_ASSOC_MATCHES_ATTR,
		&sensor_count, PSVC_PS_I_SENSOR);
	for (i = 0; i < sensor_count; ++i) {
		status = psvc_get_attr(hdlp, power_supply_id,
			PSVC_ASSOC_ID_ATTR, &sensor_id, PSVC_PS_I_SENSOR, i);
		if (status != PSVC_SUCCESS)
			return (status);

		status = psvc_get_attr(hdlp, sensor_id, PSVC_HI_WARN_ATTR,
			&hi_warn);
		if (status != PSVC_SUCCESS)
			return (status);

		status = psvc_get_attr(hdlp, sensor_id,
			PSVC_SENSOR_VALUE_ATTR, &amps);
		if (status != PSVC_SUCCESS) {
			syslog(LOG_ERR, GET_SENSOR_FAILED_MSG, sensor_id,
				errno);
			return (status);
		}

		if (amps >= hi_warn) {
			char label[32];

			status = psvc_get_attr(hdlp, power_supply_id,
				PSVC_LABEL_ATTR, &label);
			if (status != PSVC_SUCCESS)
				return (status);

			syslog(LOG_ERR, PS_OVER_CURRENT_MSG, label);
		}
	}

	return (PSVC_SUCCESS);

}

int32_t
psvc_device_fail_notifier_policy_0(psvc_opaque_t hdlp, char *id)
{
	int32_t led_count, sensor_count;
	char *led_id, *sensor_id;
	int i;
	char state[32], fault[32], previous_state[32];
	char led_state[32];
	int32_t status = PSVC_SUCCESS;
	boolean_t present;

	status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &present);
	if (status == PSVC_FAILURE)
		return (status);

	if (present == PSVC_ABSENT) {
		errno = ENODEV;
		return (PSVC_FAILURE);
	}

	psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &sensor_count,
		PSVC_DEV_FAULT_SENSOR);
	for (i = 0; i < sensor_count; ++i) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
			&sensor_id, PSVC_DEV_FAULT_SENSOR, i);
		if (status != PSVC_SUCCESS)
			return (status);

		status = psvc_get_attr(hdlp, sensor_id,
			PSVC_SWITCH_STATE_ATTR, state);
		if (status != PSVC_SUCCESS)
			return (status);

		if (strcmp(state, PSVC_SWITCH_ON) == 0) {
			strcpy(state, PSVC_ERROR);
			strcpy(fault, PSVC_GEN_FAULT);
		} else {
			strcpy(state, PSVC_OK);
			strcpy(fault, PSVC_NO_FAULT);
		}

		status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, state);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR, fault);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_get_attr(hdlp, id, PSVC_PREV_STATE_ATTR,
			previous_state);
		if (status != PSVC_SUCCESS)
			return (status);

		if (strcmp(state, previous_state) != 0) {
			char sensor_label[32];
			char dev_label[32];
			int32_t j;

			psvc_get_attr(hdlp, id, PSVC_LABEL_ATTR, dev_label);
			psvc_get_attr(hdlp, sensor_id, PSVC_LABEL_ATTR,
				sensor_label);

			if (strcmp(state, PSVC_ERROR) == 0) {
				syslog(LOG_ERR, DEVICE_FAILURE_MSG, dev_label,
					sensor_label);
				strcpy(led_state, PSVC_LED_ON);
			} else {
				syslog(LOG_ERR, DEVICE_OK_MSG, dev_label);
				strcpy(led_state, PSVC_LED_OFF);
			}

			psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR,
				&led_count, PSVC_DEV_FAULT_LED);
			for (j = 0; j < led_count; j++) {
				status = psvc_get_attr(hdlp, id,
					PSVC_ASSOC_ID_ATTR, &led_id,
					PSVC_DEV_FAULT_LED, j);
				if (status != PSVC_SUCCESS)
					return (status);
				status = psvc_set_attr(hdlp, led_id,
					PSVC_LED_STATE_ATTR, led_state);
				if (status != PSVC_SUCCESS) {
					syslog(LOG_ERR, SET_LED_FAILED_MSG,
						led_id, errno);
					return (status);
				}
			}
		}
	}

	return (PSVC_SUCCESS);
}

static float
get_filtered_error(float *last_errors, int current_error)
{
	float error;
	float adder;
	int i = 0;

	adder = last_errors[0];
	for (i = 1; i < PSVC_MAXERRORS; i++) {
		adder = adder + last_errors[i];
	}
	adder = adder + current_error;
	error = adder/(PSVC_MAXERRORS+1);

	return (error);
}

static int32_t
change_cpu_fans(psvc_opaque_t hdlp, char *fan_id, int32_t fan_speed)
{
	int err = PSVC_SUCCESS;
	int i;
	int32_t control_count;
	char *control_id;
	int32_t old_fan_speed;

	psvc_get_attr(hdlp, fan_id, PSVC_ASSOC_MATCHES_ATTR, &control_count,
		PSVC_FAN_DRIVE_CONTROL);
	if (control_count == 0)
		return (PSVC_SUCCESS);

	err = psvc_get_attr(hdlp, fan_id, PSVC_ASSOC_ID_ATTR, &control_id,
		PSVC_FAN_DRIVE_CONTROL, 0);
	if (err != PSVC_SUCCESS)
		return (err);

	/*
	 * this call will return PSVC_FAILURE on the first pass,
	 * because no value has been set.
	 */
	err = psvc_get_attr(hdlp, control_id, PSVC_CONTROL_VALUE_ATTR,
		&old_fan_speed);
	if (err == PSVC_SUCCESS && old_fan_speed == fan_speed)
		return (PSVC_SUCCESS);

	for (i = 0; i < control_count; i++) {
		err = psvc_get_attr(hdlp, fan_id, PSVC_ASSOC_ID_ATTR,
			&control_id, PSVC_FAN_DRIVE_CONTROL, i);
		if (err != PSVC_SUCCESS)
			return (err);

		err = psvc_set_attr(hdlp, control_id, PSVC_CONTROL_VALUE_ATTR,
			&fan_speed);
		if (err == PSVC_FAILURE) {
			syslog(LOG_ERR, SET_FANSPEED_FAILED_MSG, control_id,
				errno);
			return (err);
		}
	}
	return (err);
}

static int32_t
device_temp_check(psvc_opaque_t hdlp, char *fan_id, int32_t *hot_device)
{
	int i;
	int32_t err = PSVC_SUCCESS;
	char *sensor_id;
	int32_t sensor_count;
	int32_t temp;

	*hot_device = 0;

	psvc_get_attr(hdlp, fan_id, PSVC_ASSOC_MATCHES_ATTR, &sensor_count,
		PSVC_DEV_TEMP_SENSOR);
	for (i = 0; i < sensor_count; i++) {
		err = psvc_get_attr(hdlp, fan_id, PSVC_ASSOC_ID_ATTR,
			&sensor_id, PSVC_DEV_TEMP_SENSOR, i);
		if (err == PSVC_FAILURE)
			return (err);
		err = psvc_get_attr(hdlp, sensor_id, PSVC_SENSOR_VALUE_ATTR,
			&temp);
		if (err == PSVC_FAILURE) {
			if (errno == ENODEV) {
				temp = 0;
			} else {
				syslog(LOG_ERR, GET_SENSOR_FAILED_MSG,
				    sensor_id, errno);
				return (err);
			}
		}

		if (*hot_device < temp)
			*hot_device = temp;
	}
	return (PSVC_SUCCESS);
}

int32_t
psvc_fan_control_policy_0(psvc_opaque_t hdlp, char *fan_id)
{
	boolean_t is_enabled;
	int32_t err = PSVC_SUCCESS;
	int16_t setpoint, hysteresis, loopgain, loopbias;
	int current_error;		/* Holds current error */
					/* Signal before signaling */
	float filtered_error;		/* Holds the filtered error signal */
	int ampout;			/* output of loop amplifier */
	int hot_device;

	int16_t error_number;
	float last_errors[PSVC_MAXERRORS];	/* Holds the filtered error */
						/* from the last n iterations */

	psvc_get_attr(hdlp, fan_id, PSVC_ENABLE_ATTR, &is_enabled);
	if (is_enabled == PSVC_DISABLED)
		return (PSVC_SUCCESS);

	err = psvc_get_attr(hdlp, fan_id, PSVC_SETPOINT_ATTR, &setpoint);
	if (err != PSVC_SUCCESS)
		return (err);

	err = psvc_get_attr(hdlp, fan_id, PSVC_HYSTERESIS_ATTR,
		&hysteresis);
	if (err != PSVC_SUCCESS)
		return (err);

	err = psvc_get_attr(hdlp, fan_id, PSVC_LOOPGAIN_ATTR, &loopgain);
	if (err != PSVC_SUCCESS)
		return (err);

	err = psvc_get_attr(hdlp, fan_id, PSVC_LOOPBIAS_ATTR, &loopbias);
	if (err != PSVC_SUCCESS)
		return (err);

	err = psvc_get_attr(hdlp, fan_id, PSVC_TEMP_DIFFERENTIAL_ATTR,
		last_errors);
	if (err != PSVC_SUCCESS)
		return (err);

	err = psvc_get_attr(hdlp, fan_id, PSVC_TEMP_DIFFERENTIAL_INDEX_ATTR,
		&error_number);
	if (err != PSVC_SUCCESS)
		return (err);

	err = device_temp_check(hdlp, fan_id, &hot_device);
	if (err != PSVC_SUCCESS) {
		printf("psvc_fan_control failure in device_temp_check\n");
		return (err);
	}
	current_error = setpoint - hot_device;
	filtered_error = get_filtered_error(last_errors, current_error);
	if (filtered_error <= 0 || filtered_error > hysteresis) {
		ampout = (int)((filtered_error * loopgain) + loopbias);
		if (ampout < 0)
			ampout = 0;
		if (ampout > 1023)
			ampout = 1023;
		err = change_cpu_fans(hdlp, fan_id, ampout);
		if (err != PSVC_SUCCESS)
			return (err);
	}
	last_errors[error_number++] = current_error;
	if (error_number == PSVC_MAXERRORS)
		error_number = 0;

	err = psvc_set_attr(hdlp, fan_id, PSVC_TEMP_DIFFERENTIAL_ATTR,
		last_errors);
	if (err != PSVC_SUCCESS)
		return (err);

	err = psvc_set_attr(hdlp, fan_id, PSVC_TEMP_DIFFERENTIAL_INDEX_ATTR,
		&error_number);
	if (err != PSVC_SUCCESS)
		return (err);

	return (PSVC_SUCCESS);
}

int32_t
psvc_fan_present_policy_0(psvc_opaque_t hdlp, char *id)
{
	int32_t		status = PSVC_SUCCESS;
	boolean_t	presence;
	int fd;
	FILE *fp;
	int retry;

	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_fan_present);

		status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &presence);
		if (status != PSVC_SUCCESS)
			return (status);
		retry++;
	} while ((retry < n_retry_fan_present) && (presence == PSVC_ABSENT));

	if (presence == PSVC_ABSENT) {
		/*
		 * We make this open, write, close, call because picld
		 * starts in rcS.d while print services does not start
		 * until later (either rc2.d or rc3.d)
		 */
		fd = open("/dev/console", O_WRONLY | O_NOCTTY);
		if (fd != -1) {
			fp = fdopen(fd, "w+");
			if (fp != NULL) {
				fprintf(fp, FAN_MISSING_MSG, id);
				fclose(fp);
			}
			close(fd);
		}
		syslog(LOG_ERR, FAN_MISSING_MSG, id);
	}
	return (status);
}
