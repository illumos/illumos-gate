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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Cherrystone platform specific environment monitoring policies
 */

#include	<syslog.h>
#include	<unistd.h>
#include	<stdio.h>
#include 	<libintl.h>
#include	<string.h>
#include	<stdlib.h>
#include	<errno.h>
#include	<fcntl.h>
#include	<sys/types.h>
#include	<sys/time.h>
#include	<sys/time_impl.h>
#include	<sys/signal.h>
#include	<sys/devctl.h>
#include	<libdevinfo.h>
#include	<libdevice.h>
#include	<picl.h>
#include	<picltree.h>
#include	<sys/i2c/clients/i2c_client.h>
#include	<hbaapi.h>
#include	<limits.h>
#include	<sys/systeminfo.h>

#include	<psvc_objects.h>

/* Device paths for power supply hotplug handling */
#define	SEG5_ADDR		0x30
#define	EBUS_DEV_NAME		"/devices/pci@9,700000/ebus@1/"
#define	SEG5_DEV_NAME		EBUS_DEV_NAME "i2c@1,30/"
#define	SEG5_ADDR_DEV_FMT	EBUS_DEV_NAME "i2c@1,%x:devctl"

#define	QLC_NODE		 "/pci@9,600000/SUNW,qlc@2"

#define	DISK_DRV  "ssd"
#define	MAX_DISKS 2
#define	WWN_SIZE 8
#define	ONBOARD_CONTR	"../../devices/pci@9,600000/SUNW,qlc@2/fp@0,0:fc"

/* Bit masks so we don't "wedge" the inputs */
#define	PCF8574_BIT_WRITE_VALUE(byte, bit, value)\
				((value << bit) | (byte & (~(0x01 << bit))))

#define	PDB_MUST_BE_1		0xBF
#define	PSU_MUST_BE_1		0x7F
#define	DISKBP_MUST_BE_1	0x0F

/*LINTLIBRARY*/

#define	PSVC_MAX_STR_LEN	32

#define	PS_MAX_FAULT_SENSORS 3

/*
 * Keep track of the power supply's fail status for reporting if/when
 * they go good.
 * ID's:
 * O	PSx_FAULT_SENSOR
 * 1	Doesn't matter	-- only need 0 to be PSx_FAULT_SENSOR
 * 2	Doesn't matter
 */
static char	*ps_prev_id[2][3] =
		{{NULL, NULL, NULL}, {NULL, NULL, NULL}};
static int	ps_prev_failed[2][3] = {{0, 0, 0}, {0, 0, 0}};

/*
 * Keep track of the power supply's previous presence
 * because PSVC doesn't do that for us.
 */
static boolean_t ps_prev_present[2];
static boolean_t ps_present[2];

/* Local Routines for the environmental policies */
static int ac_unplugged(psvc_opaque_t, char *);
static int ac_power_check(psvc_opaque_t, char *, char *);

/*
 * The I2C bus is noisy, and the state may be incorrectly reported as
 * having changed.  When the state changes, we attempt to confirm by
 * retrying.  If any retries indicate that the state has not changed, we
 * assume the state change(s) were incorrect and the state has not changed.
 * The following variables are used to store the tuneable values read in
 * from the optional i2cparam.conf file for this shared object library.
 */
static int n_retry_fan = PSVC_NUM_OF_RETRIES;
static int retry_sleep_fan = 1;
static int n_retry_ps_status = PSVC_NUM_OF_RETRIES;
static int retry_sleep_ps_status = 1;
static int n_retry_pshp = PSVC_NUM_OF_RETRIES;
static int retry_sleep_pshp = 1;
static int n_retry_diskhp = PSVC_NUM_OF_RETRIES;
static int retry_sleep_diskhp = 1;
static int n_retry_temp_shutdown = PSVC_NUM_OF_RETRIES;
static int retry_sleep_temp_shutdown = 1;
static int n_retry_fsp_fault = PSVC_NUM_OF_RETRIES;
static int retry_sleep_fsp_fault = 1;

typedef struct {
	int *pvar;
	char *texttag;
} i2c_noise_param_t;

static i2c_noise_param_t i2cparams[] = {
	&n_retry_fan, "n_retry_fan",
	&retry_sleep_fan, "retry_sleep_fan",
	&n_retry_ps_status, "n_retry_ps_status",
	&retry_sleep_ps_status, "retry_sleep_ps_status",
	&n_retry_pshp, "n_retry_pshp",
	&retry_sleep_pshp, "retry_sleep_pshp",
	&n_retry_diskhp, "n_retry_diskhp",
	&retry_sleep_diskhp, "retry_sleep_diskhp",
	&n_retry_temp_shutdown, "n_retry_temp_shutdown",
	&retry_sleep_temp_shutdown, "retry_sleep_temp_shutdown",
	&n_retry_fsp_fault, "n_retry_fsp_fault",
	&retry_sleep_fsp_fault, "retry_sleep_fsp_fault",
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

/*
 * Create an I2C device node.
 */
static int
create_i2c_node(char *nd_name, char *nd_compat, int nd_nexi, int *nd_reg)
{
	devctl_ddef_t	ddef_hdl = NULL;
	devctl_hdl_t	bus_hdl = NULL;
	devctl_hdl_t	dev_hdl = NULL;
	char		buf[MAXPATHLEN];
	char		dev_path[MAXPATHLEN];
	int		rv = PSVC_FAILURE;

	(void) snprintf(buf, sizeof (buf), SEG5_ADDR_DEV_FMT, nd_nexi);
	bus_hdl = devctl_bus_acquire(buf, 0);
	if (bus_hdl == NULL)
		goto bad;

	/* device definition properties */
	ddef_hdl = devctl_ddef_alloc(nd_name, 0);
	(void) devctl_ddef_string(ddef_hdl, "compatible", nd_compat);
	(void) devctl_ddef_int_array(ddef_hdl, "reg", 2, nd_reg);

	/* create the device node */
	if (devctl_bus_dev_create(bus_hdl, ddef_hdl, 0, &dev_hdl))
		goto bad;

	if (devctl_get_pathname(dev_hdl, dev_path, MAXPATHLEN) == NULL)
		goto bad;

#ifdef DEBUG
	syslog(LOG_ERR, "PSVC: create_i2c_node: Device node created: (%s)",
		dev_path);
#endif
	rv = PSVC_SUCCESS;
bad:
	if (dev_hdl)  devctl_release(dev_hdl);
	if (ddef_hdl) devctl_ddef_free(ddef_hdl);
	if (bus_hdl)  devctl_release(bus_hdl);
	return (rv);
}

/*
 * Delete an I2C device node given the device path.
 */
static void
delete_i2c_node(char *nd)
{
	int		rv;
	devctl_hdl_t	dev_hdl;

	dev_hdl = devctl_device_acquire(nd, 0);
	if (dev_hdl == NULL) {
		return;
	}

	rv = devctl_device_remove(dev_hdl);
	if (rv != DDI_SUCCESS)
		perror(nd);
#ifdef DEBUG
	else
		syslog(LOG_ERR, "Device node deleted: (%s)", nd);
#endif
	devctl_release(dev_hdl);
}


/* PCF8574 Reset Function */
static int
send_pcf8574_reset(psvc_opaque_t hdlp, char *reset_dev)
{
	int	err;
	uint8_t reset_bits[2] = {0x7F, 0xFF};
	int	i;
	for (i = 0; i < 2; i++) {
		err = psvc_set_attr(hdlp, reset_dev, PSVC_GPIO_VALUE_ATTR,
			&reset_bits[i]);
		if (err != PSVC_SUCCESS) {
#ifdef DEBUG
			syslog(LOG_ERR,
				gettext("Reset to %s with 0x%x failed"),
				reset_dev, reset_bits[i]);
#endif
			return (err);
		}
	}
	/* Need to give u-code a chance to update */
	sleep(3);
	return (err);
}

static int
pcf8574_write_bit(psvc_opaque_t hdlp, char *id, uint8_t bit_num,
	uint8_t bit_val, uint8_t write_must_be_1)
{
	int	rv = PSVC_FAILURE;
	uint8_t	byte;

	rv = psvc_get_attr(hdlp, id, PSVC_GPIO_VALUE_ATTR, &byte);
	if (rv != PSVC_SUCCESS)
		return (rv);

	byte = PCF8574_BIT_WRITE_VALUE(byte, bit_num, bit_val);
	byte |= write_must_be_1;
	rv = psvc_set_attr(hdlp, id, PSVC_GPIO_VALUE_ATTR, &byte);
	return (rv);
}

/*
 * To enable the i2c bus, we must toggle bit 6 on the PDB's
 * PCF8574 (0x4C) high->low->high
 */
static int
pdb_enable_i2c(psvc_opaque_t hdlp)
{
	int		rv = PSVC_SUCCESS, i;
	int		bit_vals[3] = {1, 0, 1};
	int		bit_num = 6;

	for (i = 0; i < 3; i++) {
		rv = pcf8574_write_bit(hdlp, "PDB_PORT", bit_num, bit_vals[i],
			PDB_MUST_BE_1);
		if (rv != PSVC_SUCCESS) {
			goto bad;
		}
	}
	return (rv);
bad:
#ifdef DEBUG
	syslog(LOG_ERR, gettext("PDB I2C Bus Enabling Failed"));
#endif
	return (rv);
}

int32_t
psvc_init_disk_bp_policy_0(psvc_opaque_t hdlp, char *id)
{
	uint8_t	reset = 0xFF;
	return (psvc_set_attr(hdlp, id, PSVC_GPIO_VALUE_ATTR,
		&reset));
}

int32_t
pcf8574_init_policy_0(psvc_opaque_t hdlp, char *id)
{
	return (send_pcf8574_reset(hdlp, id));
}

static int32_t
check_fan(psvc_opaque_t hdlp, char *tray_id, char *fan_id, boolean_t *fault_on)
{
	int		status;
	int		speed;
	int		low_thresh;
	boolean_t	have_fault = 0;
	char		*tach_id;
	char		state[PSVC_MAX_STR_LEN];
	char		prev_state[PSVC_MAX_STR_LEN];
	char		fault_state[PSVC_MAX_STR_LEN];
	int		retry;

	/* Get this fan object's corresponding fan tach */
	status = psvc_get_attr(hdlp, fan_id, PSVC_ASSOC_ID_ATTR,
		&tach_id, PSVC_FAN_SPEED_TACHOMETER, 0);
	if (status != PSVC_SUCCESS)
		return (status);

	/* Get the low fan speed threshold */
	status = psvc_get_attr(hdlp, tach_id, PSVC_LO_WARN_ATTR, &low_thresh);
	if (status != PSVC_SUCCESS)
		return (status);

	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_fan);
		/* Get the fan speed */
		status = psvc_get_attr(hdlp, tach_id, PSVC_SENSOR_VALUE_ATTR,
		    &speed);
		if (status != PSVC_SUCCESS)
		return (status);

		if (speed <= low_thresh) { /* We see a fault */
			strlcpy(fault_state, "DEVICE_FAIL",
			    sizeof (fault_state));
			strlcpy(state, PSVC_ERROR, sizeof (state));
			have_fault = 1;
		} else { /* Fault gone? */
			strlcpy(fault_state, PSVC_NO_FAULT,
			    sizeof (fault_state));
			strlcpy(state, PSVC_OK, sizeof (state));
			have_fault = 0;
		}
		retry++;
	} while ((retry < n_retry_fan) && (speed <= low_thresh));

	/* Assign new states to the fan object */
	status = psvc_set_attr(hdlp, fan_id, PSVC_FAULTID_ATTR, fault_state);
	if (status != PSVC_SUCCESS)
		return (status);
	status = psvc_set_attr(hdlp, fan_id, PSVC_STATE_ATTR, state);
	if (status != PSVC_SUCCESS)
		return (status);

	/* Get state and previous state */
	status = psvc_get_attr(hdlp, fan_id, PSVC_STATE_ATTR, state);
	if (status != PSVC_SUCCESS)
		return (status);
	status = psvc_get_attr(hdlp, fan_id, PSVC_PREV_STATE_ATTR, prev_state);
	if (status != PSVC_SUCCESS)
		return (status);

	/* Display notices */
	if (strcmp(state, PSVC_OK) != 0) {
		syslog(LOG_ERR,	gettext("WARNING: %s (%s) failure detected"),
			tray_id, fan_id);
	} else {
		if (strcmp(state, prev_state) != 0) {
		syslog(LOG_ERR,	gettext("NOTICE: Device %s (%s) OK"),
			tray_id, fan_id);
		}
	}

	*fault_on |= have_fault;
	return (PSVC_SUCCESS);
}

/*
 * This policy acts on fan trays.  It looks at each of its fans
 * and checks the speeds.  If the fan speed is less than the threshold,
 * then indicate:  console, log, LED.
 */
int32_t
psvc_fan_fault_check_policy_0(psvc_opaque_t hdlp, char *id)
{
	int		fan_count;
	int		led_count;
	int		err, i;
	char		*led_id;
	char		*fan_id;
	char		led_state[PSVC_MAX_STR_LEN];
	char		state[PSVC_MAX_STR_LEN];
	char		prev_state[PSVC_MAX_STR_LEN];
	boolean_t	fault_on = 0;

	/* Get the number of fans associated with this fan tray. */
	err = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &fan_count,
		PSVC_FAN_TRAY_FANS);
	if (err != PSVC_SUCCESS)
		return (err);

	for (i = 0; i < fan_count; i++) {
		err = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
			&fan_id, PSVC_FAN_TRAY_FANS, i);
		if (err != PSVC_SUCCESS)
			return (err);

		err = check_fan(hdlp, id, fan_id, &fault_on);
		if (err != PSVC_SUCCESS)
			return (err);
	}

	if (fault_on) {
		strlcpy(led_state, PSVC_LED_ON, sizeof (led_state));
		err = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, PSVC_ERROR);
		if (err != PSVC_SUCCESS)
			return (err);

	} else {
		strlcpy(led_state, PSVC_LED_OFF, sizeof (led_state));
		err = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, PSVC_OK);
		if (err != PSVC_SUCCESS)
			return (err);
	}

	err = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, state);
	if (err != PSVC_SUCCESS)
		return (err);
	err = psvc_get_attr(hdlp, id, PSVC_PREV_STATE_ATTR, prev_state);
	if (err != PSVC_SUCCESS)
		return (err);

	/*
	 * Set leds according to the fan tray's states.
	 * (we only do this if there is a change of state in order
	 *  to reduce i2c traffic)
	 */
	if (strcmp(state, prev_state) != 0) {
		err = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR,
			&led_count, PSVC_DEV_FAULT_LED);
		if (err != PSVC_SUCCESS)
			return (err);
		for (i = 0; i < led_count; i++) {
			err = psvc_get_attr(hdlp, id,
				PSVC_ASSOC_ID_ATTR, &led_id,
				PSVC_DEV_FAULT_LED, i);
			if (err != PSVC_SUCCESS)
				return (err);
			err = psvc_set_attr(hdlp, led_id,
				PSVC_LED_STATE_ATTR, led_state);
			if (err != PSVC_SUCCESS)
				return (err);
			err = psvc_get_attr(hdlp, led_id,
				PSVC_LED_STATE_ATTR, led_state);
			if (err != PSVC_SUCCESS)
				return (err);
		}
	}
	return (err);
}

static int32_t
check_cpu_temp_fault(psvc_opaque_t hdlp, char *cpu, int32_t cpu_count)
{
	char *sensorid;
	int32_t sensor_count;
	int32_t status = PSVC_SUCCESS;
	int32_t i;
	char fault[PSVC_MAX_STR_LEN];
	int		retry;

	psvc_get_attr(hdlp, cpu, PSVC_ASSOC_MATCHES_ATTR, &sensor_count,
		PSVC_DEV_TEMP_SENSOR);
	for (i = 0; i < sensor_count; ++i) {
		status = psvc_get_attr(hdlp, cpu, PSVC_ASSOC_ID_ATTR,
			&sensorid, PSVC_DEV_TEMP_SENSOR, i);
		if (status == PSVC_FAILURE)
			return (status);

		retry = 0;
		do {
			if (retry)
				(void) sleep(retry_sleep_temp_shutdown);
			status = psvc_get_attr(hdlp, sensorid,
			    PSVC_FAULTID_ATTR, fault);
			if (status == PSVC_FAILURE)
				return (status);
			retry++;
		} while (((strcmp(fault, PSVC_TEMP_LO_SHUT) == 0) ||
		    (strcmp(fault, PSVC_TEMP_HI_SHUT) == 0)) &&
		    (retry < n_retry_temp_shutdown));

		if ((strcmp(fault, PSVC_TEMP_HI_SHUT) == 0) ||
			(strcmp(fault, PSVC_TEMP_LO_SHUT) == 0)) {
			system("shutdown -y -g 60 -i 5 \"OVERTEMP condition\"");
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

	psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &cpu_count,
		PSVC_CPU);
	for (i = 0; i < cpu_count; ++i) {

		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR, &cpuid,
			PSVC_CPU, i);
		if (status == PSVC_FAILURE)
			return (status);

		status = psvc_get_attr(hdlp, cpuid,
			PSVC_PRESENCE_ATTR, &present);
		if (status == PSVC_FAILURE && present == PSVC_PRESENT)
			return (status);
		if (present == PSVC_PRESENT) {
			status = check_cpu_temp_fault(hdlp, cpuid, cpu_count);
			if (status == PSVC_FAILURE && errno != ENODEV)
				return (status);
		}
	}

	return (PSVC_SUCCESS);
}

/*
 * Checks device specified by the PSVC_DEV_FAULT_SENSOR association
 * for errors, and if there is, then report and turn on the FSP Fault
 * Led.
 */
int32_t
psvc_fsp_device_fault_check_policy_0(psvc_opaque_t hdlp, char *id)
{
	int32_t	status;
	int32_t	i;
	int32_t	device_count = 0;
	char	device_state[PSVC_MAX_STR_LEN];
	char	*device_id;
	int32_t	failed_count = 0;
	static int32_t led_on = 0;
	int		retry;

	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR,
		&device_count, PSVC_DEV_FAULT_SENSOR);
	if (status != PSVC_SUCCESS)
		return (status);

	for (i = 0; i < device_count; i++) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
			&device_id, PSVC_DEV_FAULT_SENSOR, i);
		if (status != PSVC_SUCCESS)
			return (status);

		retry = 0;
		do {
			if (retry)
				(void) sleep(retry_sleep_fsp_fault);
			status = psvc_get_attr(hdlp, device_id, PSVC_STATE_ATTR,
			    device_state);
			if (status != PSVC_SUCCESS)
				return (status);

			if (strcmp(device_state, PSVC_OK) != 0 &&
			    strcmp(device_state, PSVC_HOTPLUGGED) != 0 &&
			    strcmp(device_state, "NO AC POWER") != 0 &&
			    strlen(device_state) != 0) {
			    failed_count++;
			}
			retry++;
		} while ((retry < n_retry_fsp_fault) && (failed_count));
	}
	if (failed_count == 0 && led_on) {
		syslog(LOG_ERR, gettext("%s has turned OFF"), id);
		status = psvc_set_attr(hdlp, id, PSVC_LED_STATE_ATTR,
			PSVC_LED_OFF);
		led_on = 0;
	}

	if (failed_count > 0 && ! led_on) {
		syslog(LOG_ERR,
			gettext("%s has turned ON"), id);
		status = psvc_set_attr(hdlp, id, PSVC_LED_STATE_ATTR,
			PSVC_LED_ON);
		led_on = 1;
	}

	return (PSVC_SUCCESS);
}

/* Power Supply Policy Helper and Worker Functions */
static void
ps_reset_prev_failed(int index)
{
	int	i;
	/* Reset the power supply's failure information */
	for (i = 0; i < 3; i++) {
		ps_prev_id[index][i] = NULL;
		ps_prev_failed[index][i] = 0;
	}

}
static int
check_i2c_access(psvc_opaque_t hdlp, char *id)
{
	int		rv;
	char		state[PSVC_MAX_STR_LEN];
	char		ps_fault_sensor[PSVC_MAX_STR_LEN];

	snprintf(ps_fault_sensor, sizeof (ps_fault_sensor),
		"%s_FAULT_SENSOR", id);

	rv = psvc_get_attr(hdlp, ps_fault_sensor, PSVC_SWITCH_STATE_ATTR,
		&state);
	return (rv);
}

/*
 * This routine takes in the PSVC handle pointer, the PS name, and the
 * instance number (0 or 1). It simply make a psvc_get call to get the
 * presence of each of the children under the PS. This call will set the
 * presence state of the child device if it was not there when the system
 * was booted.
 */
static int
handle_ps_hotplug_children_presence(psvc_opaque_t hdlp, char *id)
{
	char *child_add_on[4] = {"_RESET", "_LOGICAL_STATE", "_AC_IN_SENSOR",
				"_FAULT_SENSOR"};
	int add_ons = 4;
	char addon_id[PICL_PROPNAMELEN_MAX];
	char *sensor_id;
	int32_t	status = PSVC_SUCCESS;
	boolean_t presence;
	int j;

	/* Go through the add on list and set presence */
	for (j = 0; j < add_ons; j++) {
		snprintf(addon_id, sizeof (addon_id), "%s%s", id,
		    child_add_on[j]);
		status = psvc_get_attr(hdlp, addon_id, PSVC_PRESENCE_ATTR,
		    &presence);
		if (status != PSVC_SUCCESS)
			return (status);
	}

	/* Go through each PS's fault sensors */
	for (j = 0; j < PS_MAX_FAULT_SENSORS; j++) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
		    &(sensor_id), PSVC_DEV_FAULT_SENSOR, j);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_get_attr(hdlp, sensor_id, PSVC_PRESENCE_ATTR,
		    &presence);
		if (status != PSVC_SUCCESS)
			return (status);
	}

	/* Go through each PS's onboard i2c hardware */
	for (j = 0; j < 2; j++) {
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

static int
handle_ps_hotplug(psvc_opaque_t hdlp, char *id, boolean_t present)
{
	int32_t		status = PSVC_SUCCESS;
	int32_t		instance;
	picl_nodehdl_t	parent_node;
	picl_nodehdl_t	child_node;
	char		info[PSVC_MAX_STR_LEN];
	char		ps_logical_state[PICL_PROPNAMELEN_MAX];
	char		parent_path[PICL_PROPNAMELEN_MAX];
	char		ps_path[PICL_PROPNAMELEN_MAX];
	static int	fruprom_addr[2][2] = { {0, 0xa2}, {0, 0xa0} };
	static int	pcf8574_addr[2][2] = { {0, 0x72}, {0, 0x70} };
	char		dev_path[MAXPATHLEN];

	/* Convert name to node and parent path */
	psvcplugin_lookup(id, parent_path, &child_node);

	/*
	 * Get the power supply's instance.
	 * Used to index the xxx_addr arrays
	 */
	status = psvc_get_attr(hdlp, id, PSVC_INSTANCE_ATTR, &instance);
	if (status != PSVC_SUCCESS)
		return (status);

	if (present == PSVC_PRESENT && !ps_prev_present[instance]) {
		/* Service Power Supply Insertion */
		syslog(LOG_ERR, gettext("Device %s inserted"), id);

		/* PICL Tree Maintenance */
		ptree_get_node_by_path(parent_path, &parent_node);
		ptree_add_node(parent_node, child_node);
		snprintf(ps_path, sizeof (ps_path), "%s/%s", parent_path, id);
		psvcplugin_add_children(ps_path);

		/*
		 * This code to update the presences of power supply
		 * child devices in the event that picld was started
		 * without a power supply present.  This call makes
		 * the devices available after that initial insertion.
		 */
		status = handle_ps_hotplug_children_presence(hdlp, id);

		/*
		 * Device Tree Maintenance
		 * Add the devinfo tree node entry for the pcf8574 and seeprom
		 * and attach their drivers.
		 */
		status |= create_i2c_node("ioexp", "i2c-pcf8574", SEG5_ADDR,
			pcf8574_addr[instance]);
		status |= create_i2c_node("fru", "i2c-at24c64", SEG5_ADDR,
			fruprom_addr[instance]);
	} else {
		/* Service Power Supply Removal */
		syslog(LOG_ERR, gettext("Device %s removed"), id);

		/* Reset the power supply's failure information */
		ps_reset_prev_failed(instance);

		/* PICL Tree Maintenance */
		if (ptree_delete_node(child_node) != PICL_SUCCESS)
			syslog(LOG_ERR, "ptree_delete_node failed!");

		/*
		 * The hardcoded subscript in pcf8574_add[instance][1]
		 * refers to the address.  We are appending the address to
		 * device path.  Both elements are used when creating
		 * the i2c node (above).
		 */
		snprintf(dev_path, sizeof (dev_path),
			SEG5_DEV_NAME"ioexp@0,%x:pcf8574",
			pcf8574_addr[instance][1]);
		delete_i2c_node(dev_path);

		snprintf(dev_path, sizeof (dev_path),
			SEG5_DEV_NAME"fru@0,%x:fru", fruprom_addr[instance][1]);
			delete_i2c_node(dev_path);
	}

	snprintf(ps_logical_state, sizeof (ps_logical_state),
		"%s_LOGICAL_STATE", id);

	strlcpy(info, PSVC_OK, sizeof (info));
	status |= psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, info);
	status |= psvc_set_attr(hdlp, ps_logical_state,	PSVC_STATE_ATTR, info);

	strlcpy(info, PSVC_NO_FAULT, sizeof (info));
	status |= psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR, info);

	/* Enable the i2c connection to the power supply */
	status |= pdb_enable_i2c(hdlp);
	return (status);
}

/*
 * check_ps_state() Checks for:
 *
 * - Failure bits:
 *	Power Supply Fan Failure
 *	Power Supply Temperature Failure
 *	Power Supply Generic Fault
 *	Power Supply AC Cord Plugged In
 *
 * - If we see a "bad" state we will report an error.
 *
 * - "Bad" states:
 *	Fault bit shows fault.
 *	Temperature fault shows fault.
 *	Fan fault shows fault.
 *	AC power NOT okay to supply.
 *
 * - If we see that the AC Cord is not plugged in, then the the other
 *   failure bits are invalid.
 *
 * - Send pcf8574_reset at the end of the policy if we see
 *   any "bad" states.
 */
static int32_t
check_ps_state(psvc_opaque_t hdlp, char *id)
{
	int32_t		sensor_count;
	int32_t		status = PSVC_SUCCESS;
	int32_t		i;
	int32_t		fault_on = 0;
	char		*sensor_id;
	char		ps_ok_sensor[PICL_PROPNAMELEN_MAX];
	char		ps_logical_state[PICL_PROPNAMELEN_MAX];
	char		ps_reset[PICL_PROPNAMELEN_MAX];
	char		previous_state[PSVC_MAX_STR_LEN];
	char		state[PSVC_MAX_STR_LEN];
	char		fault[PSVC_MAX_STR_LEN];
	int		ps_okay = 1;	/* Keep track of the PDB PS OK Bit */
	int		instance;
	int		retry;

	/* Logical state id */
	snprintf(ps_logical_state, sizeof (ps_logical_state),
		"%s_LOGICAL_STATE", id);

	/*
	 * ac_power_check updates the Power Supply state with "NO AC POWER" if
	 * the power cord is out OR PSVC_OK if the power cord is in.
	 */
	status = ac_power_check(hdlp, id, ps_logical_state);
	if (status == PSVC_FAILURE)
		return (status);

	/*
	 * After running ac_power_check we now need to get the current state
	 * of the PS.  If the power supply state is "NO AC POWER" then we do
	 * not need to check for failures and we return.
	 */
	status = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, state);
	if (status != PSVC_SUCCESS)
		return (status);

	if (strcmp(state, "NO AC POWER") == 0)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_PREV_STATE_ATTR, previous_state);
	if (status != PSVC_SUCCESS)
		return (status);

	snprintf(ps_ok_sensor, sizeof (ps_ok_sensor), "%s_OK_SENSOR", id);
	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_ps_status);
		/* Handle the PDB P/S OK Bit */
		status = psvc_get_attr(hdlp, ps_ok_sensor,
		    PSVC_SWITCH_STATE_ATTR, state);
		if (status != PSVC_SUCCESS)
			return (status);
		retry++;
	} while ((retry < n_retry_ps_status) &&
	    (strcmp(previous_state, state)));


	/*
	 * If there is a change of state (current state differs from
	 * previous state, then assign the error values.
	 */
	if (strcmp(previous_state, state) != 0) {
		if (strcmp(state, PSVC_SWITCH_OFF) == 0) {
			strlcpy(state, PSVC_ERROR, sizeof (state));
			strlcpy(fault, "DEVICE_FAIL", sizeof (fault));
			fault_on = 1;
			syslog(LOG_ERR,	gettext(
				"Device %s: Failure Detected -- %s "
				"shutdown!"), id, id);
			ps_okay = 0;
		} else {
			strlcpy(state, PSVC_OK, sizeof (state));
			strlcpy(fault, PSVC_NO_FAULT, sizeof (fault));
		}

		status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, state);
		if (status != PSVC_SUCCESS)
			return (status);

		status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR, fault);
		if (status != PSVC_SUCCESS)
			return (status);
	}

	status = psvc_get_attr(hdlp, id, PSVC_INSTANCE_ATTR, &instance);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &sensor_count,
		PSVC_DEV_FAULT_SENSOR);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	/* Handle the power supply fail bits. */
	for (i = 0; i < sensor_count; i++) {
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
			&sensor_id, PSVC_DEV_FAULT_SENSOR, i);
		if (status != PSVC_SUCCESS)
			return (status);

		retry = 0;
		do {
			if (retry)
				(void) sleep(retry_sleep_ps_status);
			status = psvc_get_attr(hdlp, sensor_id,
			    PSVC_SWITCH_STATE_ATTR, state);
			if (status != PSVC_SUCCESS)
				return (status);
			retry++;
		} while ((retry < n_retry_ps_status) &&
		    (strcmp(state, PSVC_SWITCH_ON) == 0));

		if (strcmp(state, PSVC_SWITCH_ON) == 0) {
			if (ps_prev_id[instance][i] == NULL)
				ps_prev_id[instance][i] = sensor_id;

			if (ps_prev_failed[instance][i] != 1)
				ps_prev_failed[instance][i] = 1;
			fault_on = 1;
			/*
			 * The first sensor in the list is:
			 * PSx_DEV_FAULT_SENSOR.  If this is on, we do not
			 * want to merely report that it's on, but rather
			 * report that there was a fault detected, thus
			 * improving diagnosability.
			 */
			if (i == 0) {
				/*
				 * Don't notify if the PDB PS OKAY Bit is
				 * "0"
				 */
				if (ps_okay)
					syslog(LOG_ERR, gettext(
						"Device %s: Fault Detected"),
							id);
			} else {
				syslog(LOG_ERR, gettext("Warning %s: %s is ON"),
					id, sensor_id);
			}
		}
	}

	status = psvc_get_attr(hdlp, ps_logical_state,
		PSVC_STATE_ATTR, state);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, ps_logical_state,
		PSVC_PREV_STATE_ATTR, previous_state);
	if (status != PSVC_SUCCESS)
		return (status);

	/*
	 * If we encountered a fault of any kind (something before
	 * has set 'fault_on' to '1') then we want to send the reset
	 * signal to the power supply's PCF8574 and also set
	 * 'ps_logical_state' to "ERROR" so that the FSP General Fault
	 * LED will light.
	 */
	if (fault_on) {
		if (ps_okay) {
			status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR,
				PSVC_GEN_FAULT);
			if (status != PSVC_SUCCESS)
				return (status);
		}
		status = psvc_set_attr(hdlp, ps_logical_state,
			PSVC_STATE_ATTR, PSVC_ERROR);
		if (status != PSVC_SUCCESS)
			return (status);
		/*
		 * "id" is in the form of "PSx", We need to make it
		 * PSx_RESET.
		 */
		snprintf(ps_reset, sizeof (ps_reset), "%s_RESET", id);
		status = send_pcf8574_reset(hdlp, ps_reset);
		return (status);
	}

	/*
	 * There was no fault encountered so we want to
	 * set 'ps_logical_state' to "OK"
	 */
	if (strcmp(state, PSVC_OK) != 0) {
		for (i = 0; i < 3; i++) {
			char	*sensor = ps_prev_id[instance][i];
			int	*prev_failed = &ps_prev_failed[instance][i];
			if (sensor == NULL)
				continue;
			if (*prev_failed == 0)
				continue;
			*prev_failed = 0;
			if (i == 0) {
				/*
				 * Don't notifiy if we have a power supply
				 * failure (PDB PS OKAY == 0
				 */
				if (ps_okay)
					syslog(LOG_ERR, gettext(
						"Notice %s: Fault Cleared"),
							id);
			} else {
				syslog(LOG_ERR, gettext("Notice %s: %s is OFF"),
					id, sensor);
			}
		}

		status = psvc_set_attr(hdlp, ps_logical_state,
			PSVC_STATE_ATTR, PSVC_OK);
		if (status != PSVC_SUCCESS)
			return (status);
		syslog(LOG_ERR, gettext("Device %s Okay"), id);
	}

	return (PSVC_SUCCESS);
}

/*
 * This routine takes in a handle pointer and a Power Supply id. It then gets
 * the switch state for the PSx_AC_IN_SENSOR. If the switch is OFF the cord is
 * unplugged and we return a true (1). If the switch is ON then the cord is
 * plugged in and we return a false (0). If the get_attr call fails we return
 * PSVC_FAILURE (-1).
 */
static int
ac_unplugged(psvc_opaque_t hdlp, char *id)
{
	int32_t		status = PSVC_SUCCESS;
	char		ac_sensor_id[PICL_PROPNAMELEN_MAX];
	char		ac_switch_state[PSVC_MAX_STR_LEN];

	snprintf(ac_sensor_id, sizeof (ac_sensor_id), "%s_AC_IN_SENSOR", id);

	status = psvc_get_attr(hdlp, ac_sensor_id, PSVC_SWITCH_STATE_ATTR,
		ac_switch_state);
	if (status == PSVC_FAILURE) {
		return (status);
	}

	if (strcmp(ac_switch_state, PSVC_SWITCH_OFF) == 0) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * This routine expects a handle pointer, a Power Supply ID, and a PS logical
 * state switch ID.  It check to see if the power cord has been removed from or
 * inserted to the power supply. It then updates the PS state accordingly.
 */
static int
ac_power_check(psvc_opaque_t hdlp, char *id, char *ps_logical_state)
{
	int32_t		status = PSVC_SUCCESS;
	int32_t		sensor_count;
	char		*sensor_id;
	char		state[PSVC_MAX_STR_LEN];
	int		unplugged, i;

	status = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, state);
	if (status != PSVC_SUCCESS)
		return (status);

	/*
	 * Check for AC Power Cord. ac_unplugged will return true if the PS is
	 * unplugged, a false is the PS is plugged in, and PSVC_FAILURE if the
	 * call to get the state fails.
	 */
	unplugged = ac_unplugged(hdlp, id);
	if (status == PSVC_FAILURE) {
		return (status);
	}

	/*
	 * If power cord is not in, then we set the fault and error
	 * states to "".
	 * If power cord is in, then we check the devices.
	 */
	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &sensor_count,
		PSVC_DEV_FAULT_SENSOR);
	if (status != PSVC_SUCCESS) {
		return (status);
	}

	if ((unplugged) && (strcmp(state, "NO AC POWER") != 0)) {
		/* set id's state to "NO AC POWER" */
		status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR,
		    "NO AC POWER");
		if (status != PSVC_SUCCESS)
			return (status);
		/*
		 * Set this state so that the FSP Fault LED lights
		 * when there is no AC Power to the power supply.
		 */
		status = psvc_set_attr(hdlp, ps_logical_state, PSVC_STATE_ATTR,
		    PSVC_ERROR);
		if (status != PSVC_SUCCESS)
			return (status);

		status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR,
		    "NO AC POWER");
		if (status != PSVC_SUCCESS)
			return (status);

		syslog(LOG_ERR, gettext("Device %s AC UNAVAILABLE"), id);

		/* Set fault sensor states to "" */
		for (i = 0; i < sensor_count; ++i) {
			status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
				&sensor_id, PSVC_DEV_FAULT_SENSOR, i);
			if (status != PSVC_SUCCESS)
				return (status);

			status = psvc_set_attr(hdlp, sensor_id,
				PSVC_FAULTID_ATTR, "");
			if (status != PSVC_SUCCESS)
				return (status);
		}
	}

	/* Power cord is plugged in */
	if ((!unplugged) && (strcmp(state, "NO AC POWER") == 0)) {
		/* Default the state to "OK" */
		status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR,
			PSVC_OK);
		if (status != PSVC_SUCCESS)
			return (status);
		/* Default the PS_LOGICAL_STATE to "OK" */
		status = psvc_set_attr(hdlp, ps_logical_state, PSVC_STATE_ATTR,
			PSVC_OK);
		if (status != PSVC_SUCCESS)
			return (status);
		/* Display message */
		syslog(LOG_ERR, gettext("Device %s AC AVAILABLE"), id);
	}

	return (status);
}

int32_t
psvc_init_ps_presence(psvc_opaque_t hdlp, char *id)
{
	int		err;
	int		instance;
	boolean_t	presence;

	err = psvc_get_attr(hdlp, id, PSVC_INSTANCE_ATTR, &instance);
	err |= psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &presence);
	ps_prev_present[instance] = ps_present[instance] = presence;
	return (err);
}

int32_t
psvc_ps_monitor_policy_0(psvc_opaque_t hdlp, char *id)
{
	int		err;
	int		instance;
	static	int	failed_last_time[2] = {0, 0};
	int	retry;

	err = psvc_get_attr(hdlp, id, PSVC_INSTANCE_ATTR, &instance);
	if (err != PSVC_SUCCESS)
		return (err);

	/* copy current presence to previous presence */
	ps_prev_present[instance] = ps_present[instance];

	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_pshp);
		/* Get new presence */
		err = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR,
		    &ps_present[instance]);
		if (err != PSVC_SUCCESS)
			goto out;
		retry++;
	} while ((retry < n_retry_pshp) &&
	    (ps_present[instance] != ps_prev_present[instance]));

	/* Sustained Hotplug detected */
	if (ps_present[instance] != ps_prev_present[instance]) {
		err = handle_ps_hotplug(hdlp, id, ps_present[instance]);
		return (err);
	}

	/* If our power supply is not present, we're done */
	if (!ps_present[instance])
		return (PSVC_SUCCESS);

	err = check_i2c_access(hdlp, id);
	if (err != PSVC_SUCCESS) {
		/* Quickie hotplug */
		if (ps_present[instance] == PSVC_PRESENT &&
		    ps_prev_present[instance] == PSVC_PRESENT) {
			syslog(LOG_ERR, "Device %s removed", id);
			/* Reset prev_failed information */
			ps_reset_prev_failed(instance);
			ps_prev_present[instance] = 0;
			handle_ps_hotplug(hdlp, id, ps_present[instance]);
			/* We ignore the error on a quickie hotplug */
			return (PSVC_SUCCESS);
		}
		/* There was an actual i2c access error */
		goto out;
	}

	err = check_ps_state(hdlp, id);
	if (err != PSVC_SUCCESS)
		goto out;

	failed_last_time[instance] = 0;
	return (err);

out:
	if (! failed_last_time[instance]) {
		/*
		 * We ignore the error condition the first time thru
		 * because the PS could have been removed after (or
		 * during) our call to check_ps_hotplug().
		 *
		 * If the problem is still there the next time, then
		 * we'll raise a flag.
		 *
		 * The instance determines which power supply the policy
		 * errored on.  For instance PS0 might have failed and then
		 * PS1 might have failed, but we'll display a warning
		 * even though there might not be anything actually wrong.
		 * The instance keeps track of which failure occurred so
		 * we warn on the corresponding occurrence of errors.
		 */
		failed_last_time[instance] = 1;
		return (PSVC_SUCCESS);
	}
	return (err);
}

static int
light_disk_fault_leds(psvc_opaque_t hdlp, char *id, boolean_t disk_presence)
{
	int		err;
	int		bit_nums[MAX_DISKS] = {6, 7};
	uint8_t		led_masks[MAX_DISKS] = {0x40, 0x80};
	int		instance;
	int		bit_value;
	char		state[PSVC_MAX_STR_LEN];
	uint8_t		byte;

	if (disk_presence != PSVC_PRESENT)
		return (PSVC_SUCCESS);

	err = psvc_get_attr(hdlp, id, PSVC_INSTANCE_ATTR, &instance);
	if (err != PSVC_SUCCESS)
		return (err);

	err = psvc_get_attr(hdlp, "DISK_PORT", PSVC_GPIO_VALUE_ATTR,
		&byte);
	if (err != PSVC_SUCCESS)
		return (err);

	err = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, state);
	if (err != PSVC_SUCCESS)
		return (err);
	if (strcmp(state, PSVC_OK) == 0 || strcmp(state, "") == 0) { /* OK */
		if (byte & led_masks[instance]) { /* Led is OFF */
			return (err); /* Done. */
		} else { /* Led is ON, Turn if OFF */
			bit_value = 1;	/* Active Low */
			err = pcf8574_write_bit(hdlp, "DISK_PORT",
				bit_nums[instance], bit_value,
				DISKBP_MUST_BE_1);
			if (err != PSVC_SUCCESS)
				return (err);
		}
	} else { /* Disk is NOT OK */
		if (byte & led_masks[instance]) { /* Led is OFF, Turn it ON */
			bit_value = 0;	/* Active Low */
			err = pcf8574_write_bit(hdlp, "DISK_PORT",
				bit_nums[instance], bit_value,
				DISKBP_MUST_BE_1);
			if (err != PSVC_SUCCESS)
				return (err);
		} else {
			return (err); /* Done. */
		}
	}
	return (err);
}

int
verify_disk_wwn(char *wwn)
{
	HBA_PORTATTRIBUTES	hbaPortAttrs, discPortAttrs;
	HBA_HANDLE	handle;
	HBA_STATUS	status;
	HBA_ADAPTERATTRIBUTES	hbaAttrs;
	HBA_UINT32	numberOfAdapters, hbaCount, hbaPort, discPort;
	char	adaptername[256];
	char	vwwn[WWN_SIZE * 2];
	char	OSDeviceName[PATH_MAX + 1];
	int	count, linksize;

	/* Load common lib */
	status = HBA_LoadLibrary();
	if (status != HBA_STATUS_OK) {
		(void) HBA_FreeLibrary();
		return (HBA_STATUS_ERROR);
	}

	/*
	 * Since devfs can store multiple instances
	 * of a target the validity of the WWN of a disk is
	 * verified with an actual probe of internal disks
	 */

	/* Cycle through FC-AL Adapters and search for WWN */
	numberOfAdapters = HBA_GetNumberOfAdapters();
	for (hbaCount = 0; hbaCount < numberOfAdapters; hbaCount++) {
		if ((status = HBA_GetAdapterName(hbaCount, adaptername)) !=
		    HBA_STATUS_OK)
			continue;

		handle = HBA_OpenAdapter(adaptername);
		if (handle == 0)
			continue;

		/* Get Adapter Attributes */
		if ((status = HBA_GetAdapterAttributes(handle,
		    &hbaAttrs)) != HBA_STATUS_OK) {
			HBA_CloseAdapter(handle);
			continue;
		}

		/* Get Adapter's Port Attributes */
		for (hbaPort = 0;
		    hbaPort < hbaAttrs.NumberOfPorts; hbaPort++) {
			if ((status = HBA_GetAdapterPortAttributes(handle,
			    hbaPort, &hbaPortAttrs)) != HBA_STATUS_OK)
				continue;

			/*
			 * Verify whether this is onboard controller.
			 * HBAAPI provides path of symbol link to
			 * to the qlc node therefore readlink() is
			 * needed to obtain hard link
			 */
			linksize = readlink(hbaPortAttrs.OSDeviceName,
			    OSDeviceName, PATH_MAX);

			/*
			 * If readlink does not return size of onboard
			 * controller than don't bother checking device
			 */
			if ((linksize + 1) != sizeof (ONBOARD_CONTR))
				continue;

			OSDeviceName[linksize] = '\0';
			if (strcmp(OSDeviceName, ONBOARD_CONTR) != 0)
				continue;

			/* Get Discovered Port Attributes */
			for (discPort = 0;
			    discPort < hbaPortAttrs.NumberofDiscoveredPorts;
			    discPort++) {
				status = HBA_GetDiscoveredPortAttributes(
					handle, hbaPort, discPort,
						&discPortAttrs);
				if (status != HBA_STATUS_OK)
					continue;

				/* Get target info */
				for (count = 0; count < WWN_SIZE; count++)
					(void) sprintf(&vwwn[count * 2],
					    "%2.2x",
					    discPortAttrs.NodeWWN.wwn[count]);

				if (strcmp(wwn, vwwn) == 0) {
					HBA_CloseAdapter(handle);
					(void) HBA_FreeLibrary();
					return (HBA_STATUS_OK);
				}

			}
		}
		HBA_CloseAdapter(handle);
	}
	(void) HBA_FreeLibrary();
	return (HBA_STATUS_ERROR_ILLEGAL_WWN);
}

static int
light_disk_ok2remove_leds(psvc_opaque_t hdlp, boolean_t *disk_present)
{
	di_node_t	node;
	di_node_t	root_node;
	di_minor_t	min_node;
	int		*prop;
	int		n;
	int		target;
	int		rv;
	int		disk_online = 0;
	static int	prev_online[MAX_DISKS] = {-1, -1};
	int		bit_nums[MAX_DISKS] = {4, 5};
	int		bit_val;
	int		count;
	char		*dev_path;
	char		wwn[WWN_SIZE * 2];
	uchar_t		*prop_wwn;

	root_node = di_init("/", DINFOCPYALL);
	if (root_node == DI_NODE_NIL)
		return (PSVC_FAILURE);

	for (node = di_drv_first_node(DISK_DRV, root_node);
		node != DI_NODE_NIL;
		node = di_drv_next_node(node)) {
		n = di_prop_lookup_ints(DDI_DEV_T_ANY, node, "target", &prop);
		if (n == -1)
			continue;
		target = *prop;
		if (target < 0 || target > 1)
			continue;

		if (! disk_present[target])
			continue;

		dev_path = di_devfs_path(node);
		if (memcmp(dev_path, QLC_NODE, (sizeof (QLC_NODE) - 1)) != 0) {
			/*
			 * This isn't our FC-AL controller, so this
			 * must be an external disk on Loop B.  Skip it.
			 */
			di_devfs_path_free(dev_path);
			continue;
		}
		di_devfs_path_free(dev_path);

		/*
		 * Verify if disk is valid by checking WWN
		 * because devfs retains stale data.
		 */
		n = di_prop_lookup_bytes(DDI_DEV_T_ANY, node,
		    "node-wwn", &prop_wwn);
		if (n == -1)
			continue;

		for (count = 0; count < WWN_SIZE; count++)
			(void) sprintf(&wwn[count * 2], "%2.2x",
			    prop_wwn[count]);

		n = verify_disk_wwn(wwn);
		if (n == HBA_STATUS_ERROR_ILLEGAL_WWN)
			continue;

		min_node = di_minor_next(node, DI_MINOR_NIL);
		disk_online = (min_node != DI_MINOR_NIL);
		if ((disk_online == 0) && (prev_online[target] == 1)) {
			/* Light Led */
			bit_val = 0;
			rv = pcf8574_write_bit(hdlp, "DISK_PORT",
				bit_nums[target], bit_val, DISKBP_MUST_BE_1);
			if (rv != PSVC_SUCCESS)
				goto done;
		} else if ((prev_online[target] == 0) && (disk_online == 1)) {
			/* Unlight Led */
			bit_val = 1;
			rv = pcf8574_write_bit(hdlp, "DISK_PORT",
				bit_nums[target], bit_val, DISKBP_MUST_BE_1);
			if (rv != PSVC_SUCCESS)
				goto done;
		}
		if (disk_online != prev_online[target])
			prev_online[target] = disk_online;
	}
done:
	di_fini(root_node);
	return (rv);
}

static int
check_disk_fault(psvc_opaque_t hdlp, char *id, boolean_t disk_presence)
{
	int32_t		status = PSVC_SUCCESS;
	int32_t		fault_on = 0;
	char		*sensor_id;
	char		disk_state[PSVC_MAX_STR_LEN];
	char		state[PSVC_MAX_STR_LEN];
	char		fault[PSVC_MAX_STR_LEN];
	boolean_t	change_of_state = 0;

	if (disk_presence != PSVC_PRESENT)
		return (PSVC_SUCCESS);

	status = psvc_get_attr(hdlp, id, PSVC_STATE_ATTR, disk_state);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
		&sensor_id, PSVC_DEV_FAULT_SENSOR, 0);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, sensor_id, PSVC_SWITCH_STATE_ATTR, state);
	if (status != PSVC_SUCCESS)
		return (status);

	/* Fault detected */
	if (strcmp(state, PSVC_SWITCH_ON) == 0) {
		strlcpy(state, PSVC_ERROR, sizeof (state));
		strlcpy(fault, PSVC_GEN_FAULT, sizeof (fault));
		fault_on = 1;
	} else { /* No fault detected */
		if (strcmp(disk_state, PSVC_OK) != 0)
			change_of_state = 1;
		strlcpy(state, PSVC_OK, sizeof (state));
		strlcpy(fault, PSVC_NO_FAULT, sizeof (fault));
	}

	status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, state);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR, fault);
	if (status != PSVC_SUCCESS)
		return (status);

	if (fault_on) {
		syslog(LOG_ERR, gettext("Fault detected: %s"), id);

	} else {
		if (change_of_state)
			syslog(LOG_ERR, gettext("Notice: %s okay"), id);
	}
	return (PSVC_SUCCESS);
}

static int
check_disk_hotplug(psvc_opaque_t hdlp, char *id, boolean_t *disk_presence,
	int disk_instance)
{
	boolean_t	presence;
	boolean_t	previous_presence;
	int32_t		status = PSVC_SUCCESS;
	char		label[PSVC_MAX_STR_LEN];
	uint8_t		disk_leds[MAX_DISKS][2] = {{4, 6}, {5, 7}};
	int	retry;

	status = psvc_get_attr(hdlp, id, PSVC_PREV_PRESENCE_ATTR,
		&previous_presence);
	if (status != PSVC_SUCCESS)
		return (status);

	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_diskhp);
		status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR,
		    &presence);
		if (status != PSVC_SUCCESS)
			return (status);
		retry++;
	} while ((retry < n_retry_diskhp) &&
	    (presence != previous_presence));

	*disk_presence = presence;

	if (presence != previous_presence) {
		char		parent_path[PICL_PROPNAMELEN_MAX];
		picl_nodehdl_t	child_node;

		status = psvc_get_attr(hdlp, id, PSVC_LABEL_ATTR, label);
		if (status != PSVC_SUCCESS)
			return (status);

		/* return parent path and node for an object */
		psvcplugin_lookup(id, parent_path, &child_node);

		if (presence == PSVC_PRESENT) {
			picl_nodehdl_t	parent_node;
			char		state[PSVC_MAX_STR_LEN];
			char		fault[PSVC_MAX_STR_LEN];

			syslog(LOG_ERR, gettext("Device %s inserted"), label);
			strlcpy(state, PSVC_OK, sizeof (state));
			status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR,
				state);
			if (status != PSVC_SUCCESS)
				return (status);

			strlcpy(fault, PSVC_NO_FAULT, sizeof (fault));
			status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR,
				fault);
			if (status != PSVC_SUCCESS) {
				return (status);
			}

			status = ptree_get_node_by_path(parent_path,
				&parent_node);
			if (status != PICL_SUCCESS)
				return (PSVC_FAILURE);
			status = ptree_add_node(parent_node, child_node);
			if (status != PICL_SUCCESS)
				return (PSVC_FAILURE);
		} else {
			/*
			 * Disk Removed so we need to turn off these LEDs:
			 * DISKx_FLT_LED
			 * DISKx_REMOVE_LED
			 */
			int i;
			int bit_val = 1;  /* Active Low */
			for (i = 0; i < 2; i++) {
				status = pcf8574_write_bit(hdlp, "DISK_PORT",
					disk_leds[disk_instance][i], bit_val,
					DISKBP_MUST_BE_1);
				if (status != PSVC_SUCCESS)
					syslog(LOG_ERR, "Failed in turning off"
						" %d's LEDs", id);
			}
			syslog(LOG_ERR, gettext("Device %s removed"), label);
			ptree_delete_node(child_node);
		}
	}

	status = psvc_set_attr(hdlp, id, PSVC_PREV_PRESENCE_ATTR, &presence);
	if (status != PSVC_SUCCESS)
		return (status);

	return (status);
}

int32_t
psvc_disk_monitor_policy_0(psvc_opaque_t hdlp, char *id)
{
	int		rv, err, i;
	char		*disks[MAX_DISKS] = {"DISK0", "DISK1"};
	int		saved_errno = 0;
	boolean_t	disk_present[MAX_DISKS] = {0, 0};

	for (i = 0; i < MAX_DISKS; i++) {
		err = check_disk_hotplug(hdlp, disks[i], &disk_present[i], i);
		if (err) saved_errno = errno;
		rv = err;

		err = check_disk_fault(hdlp, disks[i], disk_present[i]);
		if (err) saved_errno = errno;
		rv |= err;

		err |= light_disk_fault_leds(hdlp, disks[i], disk_present[i]);
		if (err) saved_errno = errno;
		rv |= err;
	}

	err = light_disk_ok2remove_leds(hdlp, disk_present);
	if (err) saved_errno = errno;
	rv |= err;

	errno = saved_errno;
	return (rv);
}

/*
 * Read in temperature thresholds from FRU Prom and update the
 * default values.
 */

#define	START_OFFSET		0x1800	/* Last 2K of SEEPROM */
#define	NUM_SEG_OFFSET		0x1805	/* Number of segments */
#define	SEG_TABLE_OFFSET	0x1806	/* Segment description tables */

static int32_t
read_sc_segment(psvc_opaque_t hdlp, char *id, char *fru_id, int offset)
{
	static int thresh_names[] = {
		PSVC_HW_LO_SHUT_ATTR,
		PSVC_LO_SHUT_ATTR,
		PSVC_LO_WARN_ATTR,
		PSVC_NOT_USED,			/* LOW MODE  */
		PSVC_OPTIMAL_TEMP_ATTR,
		PSVC_HI_WARN_ATTR,
		PSVC_HI_SHUT_ATTR,
		PSVC_HW_HI_SHUT_ATTR
	};
	int8_t		amb_temp_array[8];
	int		i;
	fru_info_t	fru_info;
	int		err;

	fru_info.buf_start = offset + 8;
	fru_info.buf = amb_temp_array;
	fru_info.read_size = 8;

	err = psvc_get_attr(hdlp, fru_id, PSVC_FRU_INFO_ATTR, &fru_info);
	if (err != PSVC_SUCCESS)
		return (err);

	for (i = 0; i < 8; i++) {
		int32_t temp = amb_temp_array[i];
		if (thresh_names[i] == PSVC_NOT_USED)
			continue;
		err = psvc_set_attr(hdlp, id, thresh_names[i], &temp);
		if (err != PSVC_SUCCESS)
			return (err);
	}
	return (PSVC_SUCCESS);
}

int32_t
update_disk_bp_temp_thresholds(psvc_opaque_t hdlp, char *id)
{

	char		*fru;
	fru_info_t	fru_info;
	int16_t		seg_offset;
	int8_t		byte;
	int8_t		seg_count;
	char		seg_name[2];
	int		current_offset, i, err;

	err = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR, &fru, PSVC_FRU, 0);
	if (err != PSVC_SUCCESS)
		return (err);

	/* Sanity Check */
	fru_info.buf_start = START_OFFSET;
	fru_info.buf = &byte;
	fru_info.read_size = 1;

	err = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR, &fru_info);
	if (err != PSVC_SUCCESS)
		return (err);
	if (*fru_info.buf != 8) {
		syslog(LOG_ERR, "Notice: FRU Prom %s not programmed", fru);
	}
	/* Should do CRC Check on fru */

	/* Get Segment Count */
	fru_info.buf_start = NUM_SEG_OFFSET;
	fru_info.buf = &seg_count;
	fru_info.read_size = 1;

	err = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR, &fru_info);
	if (err != PSVC_SUCCESS)
		return (err);

	current_offset = SEG_TABLE_OFFSET;
	for (i = 0; i < seg_count; i++) {
		fru_info.buf_start = current_offset;
		fru_info.buf = seg_name;
		fru_info.read_size = 2;
		err = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR, &fru_info);
		if (err != PSVC_SUCCESS)
			return (err);

		if (memcmp(seg_name, "SC", 2) == 0) {
			current_offset += 6;	/* Skip over description */
			fru_info.buf_start = current_offset;
			fru_info.buf = (char *)&seg_offset;
			fru_info.read_size = 2;
			psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
				&fru_info);
			return (read_sc_segment(hdlp, id, fru, seg_offset));
		}
		current_offset += 10;
	}

	return (PSVC_SUCCESS);
}
