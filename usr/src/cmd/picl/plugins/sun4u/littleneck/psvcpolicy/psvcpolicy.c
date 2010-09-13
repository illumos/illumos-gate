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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Littleneck platform specific environment monitoring policies
 */

#include	<syslog.h>
#include	<unistd.h>
#include	<stdio.h>
#include 	<libintl.h>
#include	<string.h>
#include	<stdlib.h>
#include	<errno.h>
#include	<sys/types.h>
#include	<fcntl.h>
#include	<sys/time.h>
#include	<sys/time_impl.h>
#include	<sys/signal.h>
#include	<sys/devctl.h>
#include	<libdevinfo.h>
#include	<libdevice.h>
#include	<picl.h>
#include	<picltree.h>
#include	<limits.h>
#include	<sys/systeminfo.h>
#include	<psvc_objects.h>

/*LINTLIBRARY*/

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
#define	PS_TYPE_MSG			\
	gettext("WARNING: Incorrect type power supply inserted, device %s")
#define	DEVICE_FAILURE_MSG		\
	gettext("WARNING: Device %s failure detected by sensor %s\n")
#define	DEVICE_OK_MSG	gettext("Device %s OK")
#define	DEVTREE_NODE_CREATE_FAILED	\
	gettext("psvc PICL plugin: Failed to create node for %s, errno = %d")
#define	DEVTREE_NODE_DELETE_FAILED	\
	gettext("psvc PICL plugin: Failed to delete node for %s, errno = %d")
#define	NO_FRU_INFO			\
	gettext("No FRU Information for %s using default temperatures\n")

static char *shutdown_string = "shutdown -y -g 60 -i 5 \"OVERTEMP condition\"";

typedef struct seg_desc {
	int32_t segdesc;
	int16_t segoffset;
	int16_t seglength;
} seg_desc_t;

static int32_t find_segment(psvc_opaque_t hdlp, char *fru, seg_desc_t *segment,
    char *seg_to_find);

static int temp_attr[] = {
	PSVC_HW_HI_SHUT_ATTR, PSVC_HI_SHUT_ATTR, PSVC_HI_WARN_ATTR,
	PSVC_LO_WARN_ATTR, PSVC_LO_SHUT_ATTR, PSVC_HW_LO_SHUT_ATTR
};

#define	MAX_TEMP_ATTR	(sizeof (temp_attr)/sizeof (temp_attr[0]))
#define	TEMP_OFFSET	12
#define	PART_NO_OFFSET	152
#define	NUM_OF_SEG_ADDR	0x1805
#define	SEG_DESC_START 	0x1806
#define	PSVC_NO_DEVICE 	-2

/*
 * The I2C bus is noisy, and the state may be incorrectly reported as
 * having changed.  When the state changes, we attempt to confirm by
 * retrying.  If any retries indicate that the state has not changed, we
 * assume the state change(s) were incorrect and the state has not changed.
 * The following variables are used to store the tuneable values read in
 * from the optional i2cparam.conf file for this shared object library.
 */
static int n_retry_temp = PSVC_THRESHOLD_COUNTER;
static int retry_sleep_temp = 1;
static int n_retry_hotplug = PSVC_NUM_OF_RETRIES;
static int retry_sleep_hotplug = 1;
static int n_retry_temp_shutdown = PSVC_NUM_OF_RETRIES;
static int retry_sleep_temp_shutdown = 1;

typedef struct {
	int *pvar;
	char *texttag;
} i2c_noise_param_t;

static i2c_noise_param_t i2cparams[] = {
	&n_retry_temp, "n_retry_temp",
	&retry_sleep_temp, "retry_sleep_temp",
	&n_retry_hotplug, "n_retry_hotplug",
	&retry_sleep_hotplug, "retry_sleep_hotplug",
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
find_segment(psvc_opaque_t hdlp, char *fru, seg_desc_t *segment,
    char seg_to_find[2])
{
	int32_t seg_found = 0, status;
	int32_t seg_desc_start = SEG_DESC_START, j;
	int8_t seg_count;
	char seg_name[2];
	fru_info_t fru_data;

	/*
	 * Read the number of segments in the Read Only section
	 */
	fru_data.buf_start = NUM_OF_SEG_ADDR;
	fru_data.buf = (char *)&seg_count;
	fru_data.read_size = 1;

	status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
	    &fru_data);
	/*
	 * We test for ENOENT and ENXIO because Littleneck does not
	 * have actual presence sensors and so the only way to see
	 * if a part is there or not is to actually make a call to
	 * that part.
	 */
	if (status != PSVC_SUCCESS) {
		if ((errno == ENOENT) || (errno == ENXIO))
			return (PSVC_NO_DEVICE);
		else
			return (PSVC_FAILURE);
	}
	/*
	 * Read in each segment to find the segment we are looking for
	 */
	for (j = 0; (j < seg_count) && (!(seg_found)); j++) {
		fru_data.buf_start = seg_desc_start;
		fru_data.buf = seg_name;
		fru_data.read_size = 2;

		status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
		    &fru_data);

		seg_desc_start = seg_desc_start + 2;
		fru_data.buf_start = seg_desc_start;
		fru_data.buf = (char *)segment;
		fru_data.read_size = sizeof (seg_desc_t);

		status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
		    &fru_data);
		if (status != PSVC_SUCCESS) {
			syslog(LOG_ERR,
			    "Failed psvc_get_attr for FRU info\n");
			return (PSVC_FAILURE);
		}
		seg_desc_start = seg_desc_start + sizeof (seg_desc_t);
		if (memcmp(seg_name, seg_to_find, 2) == 0) {
			seg_found = 1;
		}
	}
	return (seg_found);
}

int32_t
psvc_update_thresholds_0(psvc_opaque_t hdlp, char *id)
{
	int32_t status = PSVC_SUCCESS;
	fru_info_t fru_data;
	char *fru, part_no[7];
	int16_t data_offset;
	int32_t fru_count, i, j, temp_address;
	int32_t seg_found, temp;
	seg_desc_t segment;
	int8_t temps[MAX_TEMP_ATTR];
	int32_t num_of_parts = 2;
	char fruless_parts[2][7] = {"5015988", "5015675"};
	int fd;
	FILE *fp;

	status = psvc_get_attr(hdlp, id, PSVC_ASSOC_MATCHES_ATTR, &fru_count,
	    PSVC_FRU);
	if (status == PSVC_FAILURE)
		return (status);

	for (i = 0; i < fru_count; i++) {
		seg_found = 0;
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
		    &fru, PSVC_FRU, i);
		if (status != PSVC_SUCCESS)
			return (status);
		seg_found = find_segment(hdlp, fru, &segment, "ES");
		if (seg_found == PSVC_FAILURE)
			return (PSVC_FAILURE);
		else if (seg_found == PSVC_NO_DEVICE)
			return (PSVC_SUCCESS);
		if (seg_found) {
			/*
			 * For Littleneck we need to read the offset of the
			 * die-sensor data record
			 */
			temp_address = segment.segoffset + TEMP_OFFSET;
			fru_data.buf_start = temp_address;
			fru_data.buf = (char *)&data_offset;
			fru_data.read_size = sizeof (data_offset);
			status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
			    &fru_data);
			if (status != PSVC_SUCCESS) {
				syslog(LOG_ERR,
				    "Failed psvc_get_attr for FRU info\n");
				return (status);
			}

			/*
			 * Now go and get the new temperature settings
			 */
			temp_address = segment.segoffset + data_offset;
			fru_data.buf_start = temp_address;
			fru_data.buf = (char *)&temps;
			fru_data.read_size = sizeof (temps);
			status = psvc_get_attr(hdlp, fru, PSVC_FRU_INFO_ATTR,
			    &fru_data);
			if (status != PSVC_SUCCESS) {
				syslog(LOG_ERR,
				    "Failed psvc_get_attr for FRU info\n");
				return (status);
			} else {
				/*
				 * Now set the updated Thresholds
				 */
				for (j = 0; j < MAX_TEMP_ATTR; j++) {
					temp = temps[j];
					status = psvc_set_attr(hdlp, id,
					    temp_attr[j], &temp);
				}
			}
		} else {
			/*
			 * For Littleneck only we need to check for the part
			 * number of the CPU as there are parts that do not
			 * have the ES segment programmed.
			 */
			seg_found = find_segment(hdlp, fru, &segment, "SD");
			if (seg_found == PSVC_FAILURE)
				return (PSVC_FAILURE);
			if (seg_found) {
				/*
				 * We now goto the SD segment to get the part
				 * number.
				 */
				fru_data.buf_start =
				    segment.segoffset + PART_NO_OFFSET;
				fru_data.buf = part_no;
				fru_data.read_size = sizeof (part_no);
				status = psvc_get_attr(hdlp, fru,
				    PSVC_FRU_INFO_ATTR, &fru_data);
				if (status != PSVC_SUCCESS) {
					syslog(LOG_ERR, "Failed psvc_get_attr"
					    "for FRU info\n");
					return (status);
				}
				/*
				 * We are go through the parts list to see
				 * if the part number from the FRU is in
				 * this list.  If it is we simply return
				 * as the FRU is not programmed.
				 */
				for (j = 0; j < num_of_parts; j++) {
					if (memcmp(fruless_parts[j], part_no,
						7) == 0) {
					return (status);
					}
				}
			}

			/*
			 * If the Part is not in the Part list and we
			 * get to here this means that the FRU is
			 * considered broken (no ES segment found)
			 * and we need to report this.
			 */
			/*
			 * We make this open, write, close, call
			 * because picld starts in rcS.d while print
			 * services does not start until later
			 * (either rc2.d or rc3.d).
			 */
			fd = open("/dev/console", O_WRONLY | O_NOCTTY);
			if (fd != -1) {
				fp = fdopen(fd, "w+");
				if (fp != NULL) {
					fprintf(fp, NO_FRU_INFO, id);
					fclose(fp);
				}
				close(fd);
			}
			syslog(LOG_NOTICE, NO_FRU_INFO, id);
		}
	}
	return (status);
}

int32_t
psvc_check_temperature_policy_0(psvc_opaque_t hdlp, char *id)
{
	int32_t lo_warn, hi_warn, lo_shut, hi_shut;
	uint64_t features;
	int32_t temp;
	char previous_state[32];
	char state[32];
	char fault[32];
	char label[32];
	boolean_t pr;
	int32_t status = PSVC_SUCCESS;
	int retry;
	int8_t temp_oor;

	status = psvc_get_attr(hdlp, id, PSVC_PRESENCE_ATTR, &pr);
	if ((status != PSVC_SUCCESS) || (pr != PSVC_PRESENT)) {
		return (status);
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

	status = psvc_get_attr(hdlp, id, PSVC_LABEL_ATTR, label);
	if (status != PSVC_SUCCESS)
		return (status);

	retry = 0;
	do {
		if (retry)
			(void) sleep(retry_sleep_temp);
		status = psvc_get_attr(hdlp, id, PSVC_SENSOR_VALUE_ATTR, &temp);
		if (status != PSVC_SUCCESS) {
			if ((errno == ENOENT) || (errno == ENXIO))
				return (PSVC_SUCCESS);
			else
				return (PSVC_FAILURE);
		}
		temp_oor = 0;
		if (((features & PSVC_LOW_SHUT) && temp <= lo_shut) ||
		    ((features & PSVC_LOW_WARN) && temp <= lo_warn) ||
		    ((features & PSVC_HIGH_SHUT) && temp >= hi_shut) ||
		    ((features & PSVC_HIGH_WARN) && temp >= hi_warn))
			temp_oor = 1;
		retry++;
	} while ((retry < n_retry_temp) && temp_oor);

	if ((features & PSVC_LOW_SHUT) && temp <= lo_shut) {
		strcpy(state, PSVC_ERROR);
		strcpy(fault, PSVC_TEMP_LO_SHUT);
		syslog(LOG_ERR, LOWTEMP_CRITICAL_MSG, temp, label);
	} else if ((features & PSVC_LOW_WARN) && temp <= lo_warn) {
		strcpy(state, PSVC_ERROR);
		strcpy(fault, PSVC_TEMP_LO_WARN);
		syslog(LOG_ERR, LOWTEMP_WARNING_MSG, temp, label);
	} else if ((features & PSVC_HIGH_SHUT) && temp >= hi_shut) {
		strcpy(state, PSVC_ERROR);
		strcpy(fault, PSVC_TEMP_HI_SHUT);
		syslog(LOG_ERR, HIGHTEMP_CRITICAL_MSG,  temp, label);
	} else if ((features & PSVC_HIGH_WARN) && temp >= hi_warn) {
		strcpy(state, PSVC_ERROR);
		strcpy(fault, PSVC_TEMP_HI_WARN);
		syslog(LOG_ERR, HIGHTEMP_WARNING_MSG, temp, label);
	} else {
		/* within limits */
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

	if (strcmp(previous_state, state) != 0) {
		char *led_id;
		uint8_t _8bit_val;

		led_id = "SYSTEM_FAULT_LED_WR";

		status = psvc_get_attr(hdlp, led_id,
			PSVC_GPIO_VALUE_ATTR, &_8bit_val);
		if (status != PSVC_SUCCESS)
			return (status);
		if (strcmp(state, PSVC_ERROR) == 0)
			_8bit_val &= 0xef;  /* clear bit 4 */
		else
			_8bit_val |= 0x10;  /* set bit 4 */
		_8bit_val |= 0xe4;  /* set bits 3, 5, 6, 7 */

		status = psvc_set_attr(hdlp, led_id,
			PSVC_GPIO_VALUE_ATTR, &_8bit_val);
		if (status != PSVC_SUCCESS)
			return (status);

	}

	return (PSVC_SUCCESS);
}

static int32_t ps0_addr[] = {0, 0xac};
static int32_t ps1_addr[] = {0, 0xae};

int32_t
psvc_ps_hotplug_policy_0(psvc_opaque_t hdlp, char *id)
{
	boolean_t presence, previous_presence;
	int32_t status = PSVC_SUCCESS;
	char label[32];
	int i;
	int32_t led_count;
	char state[32], fault[32];
	boolean_t ps_type;
	char *sensor_id, *led_id;
	char led_state[32];
	picl_nodehdl_t parent_node;
	char parent_path[256];
	picl_nodehdl_t child_node;
	int ps_instance;
	devctl_hdl_t bus_handle, dev_handle;
	devctl_ddef_t ddef_hdl;
	char devpath[256];
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
	} while ((retry < n_retry_hotplug) && (presence != previous_presence));

	if (presence == previous_presence) {
		/* No change */
		return (status);
	}

	status = psvc_get_attr(hdlp, id, PSVC_LABEL_ATTR, label);
	if (status != PSVC_SUCCESS)
		return (status);

	/* Convert name to node and parent path */
	psvcplugin_lookup(id, parent_path, &child_node);

	if (presence == PSVC_PRESENT) {

		/* may detect presence before all connections are made */
		sleep(1);

		/* Device added */
		syslog(LOG_ERR, DEVICE_INSERTED_MSG, label);


		/* Verify P/S is correct type */
		status = psvc_get_attr(hdlp, id, PSVC_ASSOC_ID_ATTR,
			&sensor_id, PSVC_DEV_TYPE_SENSOR, 0);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_get_attr(hdlp, sensor_id,
			PSVC_GPIO_VALUE_ATTR, &ps_type);
		if (status != PSVC_SUCCESS)
			return (status);

		if (ps_type ==  1) {	/* correct p/s */
			strcpy(state, PSVC_OK);
			strcpy(fault, PSVC_NO_FAULT);
			strcpy(led_state, PSVC_LED_OFF);
		} else {		/* wrong type */
			strcpy(state, PSVC_ERROR);
			strcpy(fault, PSVC_PS_TYPE_FLT);
			strcpy(led_state, PSVC_LED_ON);
			syslog(LOG_ERR, PS_TYPE_MSG, label);

		}
		status = psvc_set_attr(hdlp, id, PSVC_STATE_ATTR, state);
		if (status != PSVC_SUCCESS)
			return (status);
		status = psvc_set_attr(hdlp, id, PSVC_FAULTID_ATTR, fault);
		if (status != PSVC_SUCCESS)
			return (status);

		/* Set state of fault LEDs */
		status = psvc_get_attr(hdlp, sensor_id, PSVC_ASSOC_MATCHES_ATTR,
			&led_count, PSVC_DEV_FAULT_LED);
		if (status != PSVC_SUCCESS) {
			syslog(LOG_ERR,
				gettext("Failed for PSVC_DEV_FAULT_LED\n"));
			return (status);
		}
		for (i = 0; i < led_count; ++i) {
			status = psvc_get_attr(hdlp, sensor_id,
				PSVC_ASSOC_ID_ATTR, &led_id,
				PSVC_DEV_FAULT_LED, i);
			if (status != PSVC_SUCCESS)
				return (status);
			status = psvc_set_attr(hdlp, led_id,
				PSVC_LED_STATE_ATTR, led_state);
			if (status != PSVC_SUCCESS)
				return (status);
		}
		ptree_get_node_by_path(parent_path, &parent_node);
		ptree_add_node(parent_node, child_node);
	} else {
		/* Device removed */
		syslog(LOG_ERR, DEVICE_REMOVED_MSG, label);
		ptree_delete_node(child_node);
	}

	status = psvc_set_attr(hdlp, id, PSVC_PREV_PRESENCE_ATTR, &presence);
	if (status != PSVC_SUCCESS)
		return (status);

	status = psvc_get_attr(hdlp, id, PSVC_INSTANCE_ATTR, &ps_instance);
	if (status != PSVC_SUCCESS)
		return (status);

	if (presence != PSVC_PRESENT) {
		if (ps_instance == 0)
			strcpy(devpath,
	"/devices/pci@8,700000/ebus@5/i2c@1,30/power-supply@0,ac:power-supply");
		else
			strcpy(devpath,
	"/devices/pci@8,700000/ebus@5/i2c@1,30/power-supply@0,ae:power-supply");

		dev_handle = devctl_device_acquire(devpath, 0);

		if (devctl_device_remove(dev_handle)) {
			syslog(LOG_ERR, DEVTREE_NODE_DELETE_FAILED, label,
				errno);
			status = PSVC_FAILURE;
		} else {
			devctl_release(dev_handle);
			status = PSVC_SUCCESS;
		}
		return (status);
	}

	/*
	 * We fall through to here if the device has been inserted.
	 * Add the devinfo tree node entry for the seeprom and attach
	 * the i2c seeprom driver
	 */
	ddef_hdl = devctl_ddef_alloc("power-supply", 0);
	(void) devctl_ddef_string(ddef_hdl, "compatible", "i2c-at24c64");
	if (ps_instance == 0) {
		(void) devctl_ddef_int_array(ddef_hdl, "reg", 2, ps0_addr);
	} else {
		(void) devctl_ddef_int_array(ddef_hdl, "reg", 2, ps1_addr);
	}

	bus_handle = devctl_bus_acquire(
			"/devices/pci@8,700000/ebus@5/i2c@1,30:i2c", 0);
	if (devctl_bus_dev_create(bus_handle, ddef_hdl, 0, &dev_handle)) {
		syslog(LOG_ERR, DEVTREE_NODE_CREATE_FAILED, label, errno);
		status = PSVC_FAILURE;
	} else
		devctl_release(dev_handle);

	devctl_release(bus_handle);
	devctl_ddef_free(ddef_hdl);

	return (status);
}

int32_t
psvc_device_fail_notifier_policy_0(psvc_opaque_t hdlp, char *id)
{
	int32_t sensor_count;
	char *led_id, *sensor_id;
	int i;
	char state[32], fault[32], previous_state[32];
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
			uint8_t _8bit_val;

			psvc_get_attr(hdlp, id, PSVC_LABEL_ATTR, dev_label);
			psvc_get_attr(hdlp, sensor_id, PSVC_LABEL_ATTR,
			    sensor_label);
			if (strcmp(state, PSVC_ERROR) == 0)
				syslog(LOG_ERR, DEVICE_FAILURE_MSG, dev_label,
					sensor_label);
			else
				syslog(LOG_ERR, DEVICE_OK_MSG, dev_label);

			led_id = "SYSTEM_FAULT_LED_WR";

			status = psvc_get_attr(hdlp, led_id,
				PSVC_GPIO_VALUE_ATTR, &_8bit_val);
			if (status != PSVC_SUCCESS)
				return (status);

			if (strcmp(state, PSVC_ERROR) == 0)
				_8bit_val &= 0xef;  /* clear bit 4 */
			else
				_8bit_val |= 0x10;  /* set bit 4 */
			_8bit_val |= 0xe4;  /* set bits 3, 5, 6, 7 */

			status = psvc_set_attr(hdlp, led_id,
				PSVC_GPIO_VALUE_ATTR, &_8bit_val);
			if (status != PSVC_SUCCESS)
				return (status);

		}
	}

	return (PSVC_SUCCESS);
}

int32_t
psvc_init_led_policy_0(psvc_opaque_t hdlp, char *id)
{
	int32_t status = PSVC_SUCCESS;
	uint8_t _8bit_val;

	status = psvc_get_attr(hdlp, id,
		PSVC_GPIO_VALUE_ATTR, &_8bit_val);
	if (status != PSVC_SUCCESS)
		return (status);

	_8bit_val &= 0xef;  /* clear bit 4 */
	_8bit_val |= 0xf4;  /* set bits 3, 5, 6, 7 */

	status = psvc_set_attr(hdlp, id,
		PSVC_GPIO_VALUE_ATTR, &_8bit_val);
	if (status != PSVC_SUCCESS)
		return (status);

	return (status);
}

static int32_t
check_cpu_temp_fault(psvc_opaque_t hdlp, char *cpu, int32_t cpu_count)
{
	char *sensorid;
	int32_t sensor_count;
	int32_t status = PSVC_SUCCESS;
	int32_t i;
	char fault[32];
	int retry;
	int8_t temp_oor;

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
			temp_oor = 0;
			if ((strcmp(fault, PSVC_TEMP_HI_SHUT) == 0) ||
			    (strcmp(fault, PSVC_TEMP_LO_SHUT) == 0)) {
				temp_oor = 1;
			}
			retry++;
		} while ((retry < n_retry_temp_shutdown) && temp_oor);

		if (temp_oor) {
			system(shutdown_string);
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
