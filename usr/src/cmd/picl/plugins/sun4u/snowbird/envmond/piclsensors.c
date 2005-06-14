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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines in this file are used to manage CPU temperature sensor
 */

#include <stdio.h>
#include <unistd.h>
#include <smclib.h>
#include <libintl.h>
#include <syslog.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <picl.h>
#include <picltree.h>
#include <picldefs.h>
#include <pthread.h>
#include <errno.h>
#include <stropts.h>
#include "piclenvmond.h"
#include "piclsensors.h"

#define	NULLREAD	(int (*)(ptree_rarg_t *, void *))0
#define	NULLWRITE	(int (*)(ptree_warg_t *, const void *))0
#define	POLL_TIMEOUT	5000
#define	BUF_SIZE	50

/* packet lengths */
#define	ENV_GET_THRESHOLD_PKT_LEN	1
#define	ENV_SET_THRESHOLD_PKT_LEN	8
#define	ENV_READ_SENSOR_PKT_LEN		1
#define	ENV_SENSOR_EVENT_ENABLE_PKT_LEN	2

/* req pkt data */
#define	ENV_SENSOR_EVENT_ENABLE_MASK	0x80

/* ptree wrapper to create property */
extern picl_errno_t env_create_property(int ptype, int pmode,
	size_t psize, char *pname, int (*readfn)(ptree_rarg_t *, void *),
	int (*writefn)(ptree_warg_t *, const void *),
	picl_nodehdl_t nodeh, picl_prophdl_t *propp, void *vbuf);
extern int post_sensor_event(picl_nodehdl_t, char *, uint8_t);
extern int env_open_smc(void);
extern int env_debug;

/* globals */
int sensor_fd = -1;
picl_nodehdl_t	sensorh = 0;
pthread_t env_temp_thr_tid;

/* local vars */
static env_temp_sensor_t temp_sensor;
static pthread_mutex_t sensor_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t env_temp_monitor_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t env_temp_monitor_cv = PTHREAD_COND_INITIALIZER;
static env_temp_threshold_t env_curr_state = NORMAL_THRESHOLD;
static char *env_thresholds[] = {
	PICL_PROP_LOW_WARNING,
	PICL_PROP_LOW_SHUTDOWN,
	PICL_PROP_LOW_POWER_OFF,
	PICL_PROP_HIGH_WARNING,
	PICL_PROP_HIGH_SHUTDOWN,
	PICL_PROP_HIGH_POWER_OFF
};
static int cpu_sensor_geo_addr = 0;

/* local func prototypes */
static void *env_temp_monitor(void *args);

/*
 * Reads the threshold value from hardware
 */
static picl_errno_t
env_get_temp_threshold(int sensor_no, int threshold_no,
	int8_t *threshold_reading)
{
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t rsp_pkt;
	smc_errno_t rc =  SMC_SUCCESS;
	uint8_t size = 0;

	if (threshold_no < 1 || threshold_no > 6) {
		return (PICL_INVALIDARG);
	}

	req_pkt.data[0] = sensor_no;
	size = ENV_GET_THRESHOLD_PKT_LEN;
	/* initialize the request packet */
	(void) smc_init_smc_msg(&req_pkt, SMC_SENSOR_THRESHOLD_GET,
		DEFAULT_SEQN, size);

	/* make a call to smc library to send cmd */
	if ((rc = smc_send_msg(DEFAULT_FD, &req_pkt, &rsp_pkt,
		POLL_TIMEOUT)) != SMC_SUCCESS) {
		syslog(LOG_ERR,	SMC_GET_SENSOR_THRES_FAILED,
			sensor_no, rc);
		return (PICL_FAILURE);
	}

	switch (threshold_no) {
	case LOW_WARNING_THRESHOLD:
		if (LOW_WARNING_BIT(rsp_pkt.data[0])) {
			*threshold_reading = rsp_pkt.data[1];
		} else {
			return (PICL_PERMDENIED);
		}
		break;
	case LOW_SHUTDOWN_THRESHOLD:
		if (LOW_SHUTDOWN_BIT(rsp_pkt.data[0])) {
			*threshold_reading = rsp_pkt.data[2];
		} else {
			return (PICL_PERMDENIED);
		}
		break;
	case LOW_POWEROFF_THRESHOLD:
		if (LOW_POWEROFF_BIT(rsp_pkt.data[0])) {
			*threshold_reading = rsp_pkt.data[3];
		} else {
			return (PICL_PERMDENIED);
		}
		break;
	case HIGH_WARNING_THRESHOLD:
		if (HIGH_WARNING_BIT(rsp_pkt.data[0])) {
			*threshold_reading = rsp_pkt.data[4];
		} else {
			return (PICL_PERMDENIED);
		}
		break;
	case HIGH_SHUTDOWN_THRESHOLD:
		if (HIGH_SHUTDOWN_BIT(rsp_pkt.data[0])) {
			*threshold_reading = rsp_pkt.data[5];
		} else {
			return (PICL_PERMDENIED);
		}
		break;
	case HIGH_POWEROFF_THRESHOLD:
		if (HIGH_POWEROFF_BIT(rsp_pkt.data[0])) {
			*threshold_reading = rsp_pkt.data[6];
		} else {
			return (PICL_PERMDENIED);
		}
		break;
	default:
		return (PICL_INVALIDARG);
	}
	return (PICL_SUCCESS);
}

/*
 * Sets the threshold temperature specified in given sensor number
 */
static picl_errno_t
env_set_temp_threshold(int sensor_no, int threshold_no,
	int8_t set_value)
{
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t rsp_pkt;
	smc_errno_t rc;
	uint8_t size = 0;

	if (threshold_no < 1 || threshold_no > 6) {
		return (PICL_INVALIDARG);
	}

	req_pkt.data[0] = (int8_t)sensor_no;
	req_pkt.data[1] = 0x01 << (threshold_no - 1);	/* set the bit mask */
	req_pkt.data[1 + threshold_no] = set_value;
	size = ENV_SET_THRESHOLD_PKT_LEN;

	/* initialize the request packet */
	(void) smc_init_smc_msg(&req_pkt, SMC_SENSOR_THRESHOLD_SET,
		DEFAULT_SEQN, size);

	/* make a call to smc library to send cmd */
	if ((rc = smc_send_msg(sensor_fd, &req_pkt, &rsp_pkt,
		POLL_TIMEOUT)) != SMC_SUCCESS) {
		syslog(LOG_ERR,	SMC_SET_SENSOR_THRES_FAILED,
			sensor_no, rc);
		return (PICL_FAILURE);
	}
	return (PICL_SUCCESS);
}

/*
 * returns the sensor reading of the SMC sensor specified in sensor_no
 */
static picl_errno_t
env_get_sensor_reading(uint8_t sensor_no, int8_t *sensor_reading)
{
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t rsp_pkt;
	smc_errno_t rc =  SMC_SUCCESS;
	uint8_t size = 0;

	req_pkt.data[0] = sensor_no;
	/* initialize the request packet */
	size = ENV_READ_SENSOR_PKT_LEN;
	(void) smc_init_smc_msg(&req_pkt, SMC_SENSOR_READING_GET,
		DEFAULT_SEQN, size);

	/* make a call to smc library to send cmd */
	if ((rc = smc_send_msg(DEFAULT_FD, &req_pkt, &rsp_pkt,
		POLL_TIMEOUT)) != SMC_SUCCESS) {
		syslog(LOG_ERR,	SMC_GET_SENSOR_READING_FAILED,
			sensor_no, rc);
		return (PICL_FAILURE);
	}
	*sensor_reading = rsp_pkt.data[0];
	return (PICL_SUCCESS);
}

/*
 * volatile call back function to read the current temparature
 */
static int
get_curr_temp(ptree_rarg_t *argp, void	*bufp)
{
	uint8_t	sensor_no;
	int8_t	sensor_reading;
	picl_errno_t rc;

	if ((rc = ptree_get_propval_by_name(argp->nodeh,
		PICL_PROP_GEO_ADDR, &sensor_no, sizeof (sensor_no))) !=
		PICL_SUCCESS) {
		return (rc);
	}

	/* read the temp from SMC f/w */
	if ((rc = env_get_sensor_reading(sensor_no, &sensor_reading)) !=
		PICL_SUCCESS) {
		return (rc);
	}
	*(int8_t *)bufp = sensor_reading;

	/* update the internal cache */
	(void) pthread_mutex_lock(&sensor_mutex);
	temp_sensor.curr_temp = sensor_reading;
	(void) pthread_mutex_unlock(&sensor_mutex);

	return (PICL_SUCCESS);
}

/*
 * volatile function that returns the state of sensor
 */
static int
get_sensor_condition(ptree_rarg_t *argp, void *bufp)
{
	uint8_t	sensor_no;
	picl_errno_t rc =  PICL_SUCCESS;
	int8_t		sensor_reading;

	if ((rc = ptree_get_propval_by_name(argp->nodeh,
		PICL_PROP_GEO_ADDR, &sensor_no, sizeof (sensor_no))) !=
		PICL_SUCCESS) {
		return (rc);
	}

	/* read the curr temp from SMC f/w */
	if ((rc = env_get_sensor_reading(sensor_no, &sensor_reading)) !=
		PICL_SUCCESS) {
		(void) pthread_mutex_lock(&sensor_mutex);
		(void) strncpy(temp_sensor.state, PICLEVENTARGVAL_UNKNOWN,
			sizeof (temp_sensor.state));
		(void) strncpy((char *)bufp, PICLEVENTARGVAL_UNKNOWN,
			PICL_PROPNAMELEN_MAX);
		(void) pthread_mutex_unlock(&sensor_mutex);
		return (PICL_SUCCESS);
	}

	(void) pthread_mutex_lock(&sensor_mutex);

	if (sensor_reading > temp_sensor.hi_shutdown ||
		sensor_reading < temp_sensor.lo_shutdown)
		(void) strncpy(temp_sensor.state,
			PICLEVENTARGVAL_SENSOR_COND_SHUTDOWN,
			sizeof (temp_sensor.state));
	else if (sensor_reading > temp_sensor.hi_warning ||
		sensor_reading < temp_sensor.lo_warning)
		(void) strncpy(temp_sensor.state,
			PICLEVENTARGVAL_SENSOR_COND_WARNING,
			sizeof (temp_sensor.state));
	else
		(void) strncpy(temp_sensor.state, PICLEVENTARGVAL_OK,
			sizeof (temp_sensor.state));
	(void) strncpy((char *)bufp, temp_sensor.state,
		PICL_PROPNAMELEN_MAX);

	(void) pthread_mutex_unlock(&sensor_mutex);
	return (PICL_SUCCESS);
}

/*
 * volatile property to read sensor thresholds
 */
static int
get_sensor_thr(ptree_rarg_t *argp, void *bufp)
{
	picl_errno_t rc = PICL_SUCCESS;
	ptree_propinfo_t pi;
	char prop_name[PICL_PROPNAMELEN_MAX];

	if ((rc = ptree_get_propinfo(argp->proph, &pi)) != PICL_SUCCESS) {
		return (rc);
	}
	(void) strncpy(prop_name, pi.piclinfo.name, sizeof (prop_name));

	(void) pthread_mutex_lock(&sensor_mutex);

	if (strcmp(prop_name, PICL_PROP_LOW_WARNING) == 0) {
		*(int8_t *)bufp = temp_sensor.lo_warning;
	} else if (strcmp(prop_name, PICL_PROP_LOW_SHUTDOWN) == 0) {
		*(int8_t *)bufp = temp_sensor.lo_shutdown;
	} else if (strcmp(prop_name, PICL_PROP_LOW_POWER_OFF) == 0) {
		*(int8_t *)bufp = temp_sensor.lo_poweroff;
	} else if (strcmp(prop_name, PICL_PROP_HIGH_WARNING) == 0) {
		*(int8_t *)bufp = temp_sensor.hi_warning;
	} else if (strcmp(prop_name, PICL_PROP_HIGH_SHUTDOWN) == 0) {
		*(int8_t *)bufp = temp_sensor.hi_shutdown;
	} else if (strcmp(prop_name, PICL_PROP_HIGH_POWER_OFF) == 0) {
		*(int8_t *)bufp = temp_sensor.hi_poweroff;
	} else {
		rc = PICL_INVALIDARG;
	}

	(void) pthread_mutex_unlock(&sensor_mutex);
	return (rc);
}

/*
 * volatile callback function to set the temp thresholds
 */
static int
set_sensor_thr(ptree_warg_t *argp, const void *bufp)
{
	picl_errno_t rc = PICL_SUCCESS;
	ptree_propinfo_t pi;
	int threshold_no = 0;
	int8_t	temp = *(int8_t *)bufp;
	char	cmd[BUF_SIZE];
	char prop_name[PICL_PROPNAMELEN_MAX];

	if ((rc = ptree_get_propinfo(argp->proph, &pi)) != PICL_SUCCESS) {
		return (rc);
	}
	(void) strncpy(prop_name, pi.piclinfo.name, sizeof (prop_name));
	cmd[0] = '\0';

	(void) pthread_mutex_lock(&sensor_mutex);

	if (strcmp(prop_name, PICL_PROP_LOW_WARNING) == 0) {
		/* warning cannot be less than shutdown threshold */
		if (temp <= temp_sensor.lo_shutdown) {
			(void) pthread_mutex_unlock(&sensor_mutex);
			return (PICL_INVALIDARG);
		}
		threshold_no = LOW_WARNING_THRESHOLD;
	} else if (strcmp(prop_name, PICL_PROP_LOW_SHUTDOWN) == 0) {
		/* shutdown cannot be greater than warning threshold */
		if (temp >= temp_sensor.lo_warning) {
			(void) pthread_mutex_unlock(&sensor_mutex);
			return (PICL_INVALIDARG);
		}
		threshold_no = LOW_SHUTDOWN_THRESHOLD;
	} else if (strcmp(prop_name, PICL_PROP_LOW_POWER_OFF) == 0) {
		(void) pthread_mutex_unlock(&sensor_mutex);
		return (PICL_PERMDENIED);
	} else if (strcmp(prop_name, PICL_PROP_HIGH_WARNING) == 0) {
		if ((temp + 5) > temp_sensor.hi_shutdown) {
			(void) pthread_mutex_unlock(&sensor_mutex);
			return (PICL_INVALIDARG);
		}
		/* change the OBP nvram property */
		(void) snprintf(cmd, sizeof (cmd),
			EEPROM_WARNING_CMD, temp);
		threshold_no = HIGH_WARNING_THRESHOLD;
	} else if (strcmp(prop_name, PICL_PROP_HIGH_SHUTDOWN) == 0) {
		if ((temp - 5) < temp_sensor.hi_warning) {
			(void) pthread_mutex_unlock(&sensor_mutex);
			return (PICL_INVALIDARG);
		}
		/* change the OBP nvram property */
		(void) snprintf(cmd, sizeof (cmd),
			EEPROM_SHUTDOWN_CMD, temp);
		threshold_no = HIGH_SHUTDOWN_THRESHOLD;
	} else if (strcmp(prop_name, PICL_PROP_HIGH_POWER_OFF) == 0) {
		if (temp > MAX_POWEROFF_TEMP ||
			(temp - 5) < temp_sensor.hi_shutdown) {
			(void) pthread_mutex_unlock(&sensor_mutex);
			return (PICL_INVALIDARG);
		}
		/* change the OBP nvram property */
		threshold_no = HIGH_POWEROFF_THRESHOLD;
		(void) snprintf(cmd, sizeof (cmd),
			EEPROM_POWEROFF_CMD, temp);
	} else {
		(void) pthread_mutex_unlock(&sensor_mutex);
		return (PICL_INVALIDARG);
	}
	(void) pthread_mutex_unlock(&sensor_mutex);

	if ((rc = env_set_temp_threshold(cpu_sensor_geo_addr,
		threshold_no, temp)) != PICL_SUCCESS) {
		return (rc);
	}

	(void) pthread_mutex_lock(&sensor_mutex);
	switch (threshold_no) {
	case LOW_WARNING_THRESHOLD:
		temp_sensor.lo_warning = temp;
		break;
	case LOW_SHUTDOWN_THRESHOLD:
		temp_sensor.lo_shutdown = temp;
		break;
	case LOW_POWEROFF_THRESHOLD:
		temp_sensor.lo_poweroff = temp;
		break;
	case HIGH_WARNING_THRESHOLD:
		temp_sensor.hi_warning = temp;
		break;
	case HIGH_SHUTDOWN_THRESHOLD:
		temp_sensor.hi_shutdown = temp;
		break;
	case HIGH_POWEROFF_THRESHOLD:
		temp_sensor.hi_poweroff = temp;
		break;
	}
	(void) pthread_mutex_unlock(&sensor_mutex);

	/* execute the cmd to change OBP nvram property */
	if (cmd[0]) {
		(void) pclose(popen(cmd, "w"));
	}
	return (PICL_SUCCESS);
}

/*
 * this routine reads the hardware state and initialises the internal
 * cache for temperature thresholds
 */
static picl_errno_t
env_init_temp_sensor_values(int sensor_no, env_temp_sensor_t *sensor)
{
	if (env_get_sensor_reading(sensor_no, &sensor->curr_temp) !=
		PICL_SUCCESS) {
		return (PICL_FAILURE);
	}

	if (env_get_temp_threshold(sensor_no, LOW_WARNING_THRESHOLD,
		&sensor->lo_warning) != PICL_SUCCESS) {
		syslog(LOG_ERR, SMC_GET_LWT_FAILED);
		return (PICL_FAILURE);
	}

	if (env_get_temp_threshold(sensor_no, LOW_SHUTDOWN_THRESHOLD,
		&sensor->lo_shutdown) != PICL_SUCCESS) {
		syslog(LOG_ERR, SMC_GET_LST_FAILED);
		return (PICL_FAILURE);
	}

	if (env_get_temp_threshold(sensor_no, LOW_POWEROFF_THRESHOLD,
		&sensor->lo_poweroff) != PICL_SUCCESS) {
		syslog(LOG_ERR, SMC_GET_LPT_FAILED);
		return (PICL_FAILURE);
	}

	if (env_get_temp_threshold(sensor_no, HIGH_WARNING_THRESHOLD,
		&sensor->hi_warning) != PICL_SUCCESS) {
		syslog(LOG_ERR, SMC_SET_LWT_FAILED);
		return (PICL_FAILURE);
	}

	if (env_get_temp_threshold(sensor_no, HIGH_SHUTDOWN_THRESHOLD,
		&sensor->hi_shutdown) != PICL_SUCCESS) {
		syslog(LOG_ERR, SMC_SET_LST_FAILED);
		return (PICL_FAILURE);
	}

	if (env_get_temp_threshold(sensor_no, HIGH_POWEROFF_THRESHOLD,
		&sensor->hi_poweroff) != PICL_SUCCESS) {
		syslog(LOG_ERR, SMC_SET_LPT_FAILED);
		return (PICL_FAILURE);
	}

	if (sensor->curr_temp > sensor->hi_shutdown ||
		sensor->curr_temp < sensor->lo_shutdown) {
		(void) strncpy(sensor->state,
			PICLEVENTARGVAL_SENSOR_COND_SHUTDOWN,
			sizeof (sensor->state));
	} else if (sensor->curr_temp > sensor->hi_warning ||
		sensor->curr_temp < sensor->lo_warning) {
		(void) strncpy(sensor->state,
			PICLEVENTARGVAL_SENSOR_COND_WARNING,
			sizeof (sensor->state));
	} else {
		(void) strncpy(sensor->state, PICLEVENTARGVAL_OK,
			sizeof (sensor->state));
	}
	return (PICL_SUCCESS);
}

/*
 * sensor_event_enable_set: enables or disables Event Message generation
 * from a sensor specified by sensor_no
 */
static int
sensor_event_enable_set(uint8_t	sensor_no, boolean_t enable)
{
	smc_errno_t rc = SMC_SUCCESS;
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t rsp_pkt;
	uint8_t size = 0;

	req_pkt.data[0] = sensor_no;
	req_pkt.data[1] = 0;
	if (enable) {
		req_pkt.data[1] |= ENV_SENSOR_EVENT_ENABLE_MASK;
	}
	size = ENV_SENSOR_EVENT_ENABLE_PKT_LEN;

	(void) smc_init_smc_msg(&req_pkt, SMC_SENSOR_EVENT_ENABLE_SET,
		DEFAULT_SEQN, size);

	/* make a call to smc library to send cmd */
	if ((rc = smc_send_msg(DEFAULT_FD, &req_pkt, &rsp_pkt,
		POLL_TIMEOUT)) != SMC_SUCCESS) {
		syslog(LOG_ERR,	SMC_ENABLE_SENSOR_EVENT_FAILED, rc);
		return (PICL_FAILURE);
	}
	return (PICL_SUCCESS);
}

/*
 * creates temperature sensor node and all of its properties
 */
picl_errno_t
env_create_temp_sensor_node(picl_nodehdl_t parenth, uint8_t sensor_no)
{
	int i = 0;
	picl_errno_t rc = PICL_SUCCESS;
	int8_t	sensor_reading = 0;
	struct strioctl	strio;
	sc_cmdspec_t	set;

	sensor_fd = env_open_smc();
	if (sensor_fd < 0) {
		syslog(LOG_ERR, gettext("SUNW_envmond:Error in "
			"opening SMC(failed to create sensor nodes)"));
		return (PICL_FAILURE);
	}

	/* grab exclusive access to set the thresholds */
	set.args[0]	= SMC_SENSOR_THRESHOLD_SET;
	set.attribute	= SC_ATTR_EXCLUSIVE;
	strio.ic_cmd	= SCIOC_MSG_SPEC;
	strio.ic_timout	= 0;
	strio.ic_len	= 2;
	strio.ic_dp	= (char *)&set;
	if (ioctl(sensor_fd, I_STR, &strio) < 0) {
		syslog(LOG_ERR, SMC_GET_EXCLUSIVE_ERR);
		(void) close(sensor_fd);
		return (PICL_FAILURE);
	}

	cpu_sensor_geo_addr = sensor_no;
	/* create temperature sensor node */
	if ((rc = ptree_create_and_add_node(parenth, CPU_SENSOR,
		PICL_CLASS_TEMPERATURE_SENSOR, &sensorh)) !=
		PICL_SUCCESS) {
		(void) close(sensor_fd);
		return (rc);
	}

	/* create Label prop. */
	if ((rc = env_create_property(PICL_PTYPE_CHARSTRING, PICL_READ,
		PICL_PROPNAMELEN_MAX, PICL_PROP_LABEL, NULLREAD,
		NULLWRITE, sensorh, (picl_prophdl_t *)NULL,
		(char *)PICL_PROPVAL_LABEL_AMBIENT)) != PICL_SUCCESS) {
		(void) ptree_delete_node(sensorh);
		(void) ptree_destroy_node(sensorh);
		(void) close(sensor_fd);
		return (rc);
	}

	/* create the geo-addr property */
	if ((rc = env_create_property(PICL_PTYPE_UNSIGNED_INT,
		PICL_READ, sizeof (sensor_no), PICL_PROP_GEO_ADDR,
		NULLREAD, NULLWRITE, sensorh, (picl_prophdl_t *)NULL,
		&sensor_no)) != PICL_SUCCESS) {
		(void) ptree_delete_node(sensorh);
		(void) ptree_destroy_node(sensorh);
		(void) close(sensor_fd);
		return (rc);
	}

	/* read the current temp from hardware */
	if (env_get_sensor_reading(sensor_no, &sensor_reading) !=
		PICL_SUCCESS) {
		(void) ptree_delete_node(sensorh);
		(void) ptree_destroy_node(sensorh);
		(void) close(sensor_fd);
		return (PICL_FAILURE);
	}

	/* create temperature prop. */
	if ((rc = env_create_property(PICL_PTYPE_INT,
		PICL_READ + PICL_VOLATILE, sizeof (sensor_reading),
		PICL_PROP_TEMPERATURE, get_curr_temp,
		NULLWRITE, sensorh, (picl_prophdl_t *)NULL,
		&sensor_reading)) != PICL_SUCCESS) {
		(void) ptree_delete_node(sensorh);
		(void) ptree_destroy_node(sensorh);
		(void) close(sensor_fd);
		return (rc);
	}

	/* create the threshold properties */
	for (i = 0; i < NUM_OF_THRESHOLDS; i++) {
		if ((rc = env_create_property(PICL_PTYPE_INT,
			PICL_READ + PICL_WRITE + PICL_VOLATILE,
			sizeof (uint8_t), env_thresholds[i],
			get_sensor_thr, set_sensor_thr,
			sensorh, (picl_prophdl_t *)NULL,
			(void *)NULL)) != PICL_SUCCESS) {
			(void) ptree_delete_node(sensorh);
			(void) ptree_destroy_node(sensorh);
			(void) close(sensor_fd);
			return (rc);
		}
	}

	/* intialise the internal cache */
	if (env_init_temp_sensor_values(cpu_sensor_geo_addr,
		&temp_sensor) != PICL_SUCCESS) {
		(void) ptree_delete_node(sensorh);
		(void) ptree_destroy_node(sensorh);
		(void) close(sensor_fd);
		return (PICL_FAILURE);
	}

	/* create STATE prop. */
	if ((rc = env_create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ + PICL_VOLATILE, PICL_PROPNAMELEN_MAX,
		PICL_PROP_CONDITION, get_sensor_condition, NULLWRITE,
		sensorh, (picl_prophdl_t *)NULL,
		temp_sensor.state)) != PICL_SUCCESS) {
		(void) ptree_delete_node(sensorh);
		(void) ptree_destroy_node(sensorh);
		(void) close(sensor_fd);
		return (rc);
	}

	/* start temperature monitoring thread */
	if (pthread_create(&env_temp_thr_tid, NULL,
		&env_temp_monitor, NULL) != 0) {
		syslog(LOG_ERR, gettext("SUNW_envmond:Error in "
			"creating temperature monitor thread"));
	}

	/* enable sensor-event */
	(void) sensor_event_enable_set(sensor_no, B_TRUE);
	return (PICL_SUCCESS);
}

/*
 * handles the sensor events (post corresponding Condition picl event)
 */
void
env_handle_sensor_event(void *res_datap)
{
	uint8_t	offset;
	char sensor_cond[BUF_SIZE];

	if (BYTE_4(res_datap) != cpu_sensor_geo_addr) {
		return;
	}

	if (BYTE_5(res_datap) != THRESHOLD_TYPE) {
		return;
	}

	if (env_debug & DEBUG) {
		syslog(LOG_INFO, "Temperature = %d\n", BYTE_7(res_datap));
		syslog(LOG_INFO,
			"Threshold changed to %d\n", BYTE_8(res_datap));
	}

	/* Threshold event */
	offset = BYTE_6(res_datap) & 0x0F; 	/* first 4 bits */
	switch (offset) {
	case 0:
		(void) pthread_mutex_lock(&env_temp_monitor_mutex);
		if (env_curr_state == LOW_WARNING_THRESHOLD) {
			(void) pthread_cond_signal(&env_temp_monitor_cv);
			(void) pthread_mutex_unlock(&env_temp_monitor_mutex);
			return;
		}
		env_curr_state = LOW_WARNING_THRESHOLD;
		(void) pthread_cond_signal(&env_temp_monitor_cv);
		(void) pthread_mutex_unlock(&env_temp_monitor_mutex);
		(void) strncpy(sensor_cond,
			PICLEVENTARGVAL_SENSOR_COND_WARNING,
			sizeof (sensor_cond));
		syslog(LOG_CRIT, gettext("SUNW_envmond:current temperature (%d)"
			" is below lower warning temperature (%d).\n"),
				BYTE_7(res_datap), BYTE_8(res_datap));
		break;
	case 2:
		(void) pthread_mutex_lock(&env_temp_monitor_mutex);
		if (env_curr_state == LOW_SHUTDOWN_THRESHOLD) {
			(void) pthread_cond_signal(&env_temp_monitor_cv);
			(void) pthread_mutex_unlock(&env_temp_monitor_mutex);
			return;
		}
		env_curr_state = LOW_SHUTDOWN_THRESHOLD;
		(void) pthread_cond_signal(&env_temp_monitor_cv);
		(void) pthread_mutex_unlock(&env_temp_monitor_mutex);
		(void) strncpy(sensor_cond,
			PICLEVENTARGVAL_SENSOR_COND_SHUTDOWN,
			sizeof (sensor_cond));
		syslog(LOG_CRIT, gettext("SUNW_envmond:current temperature (%d)"
			" is below lower critical temperature (%d).\n"),
				BYTE_7(res_datap), BYTE_8(res_datap));
		break;
	case 7:
		(void) pthread_mutex_lock(&env_temp_monitor_mutex);
		if (env_curr_state == HIGH_WARNING_THRESHOLD) {
			(void) pthread_cond_signal(&env_temp_monitor_cv);
			(void) pthread_mutex_unlock(&env_temp_monitor_mutex);
			return;
		}
		env_curr_state = HIGH_WARNING_THRESHOLD;
		(void) pthread_cond_signal(&env_temp_monitor_cv);
		(void) pthread_mutex_unlock(&env_temp_monitor_mutex);
		(void) strncpy(sensor_cond,
			PICLEVENTARGVAL_SENSOR_COND_WARNING,
			sizeof (sensor_cond));
		syslog(LOG_CRIT, gettext("SUNW_envmond:current temperature (%d)"
			" exceeds upper warning temperature (%d).\n"),
				BYTE_7(res_datap), BYTE_8(res_datap));
		break;
	case 9:
		(void) pthread_mutex_lock(&env_temp_monitor_mutex);
		if (env_curr_state == HIGH_SHUTDOWN_THRESHOLD) {
			(void) pthread_cond_signal(&env_temp_monitor_cv);
			(void) pthread_mutex_unlock(&env_temp_monitor_mutex);
			return;
		}
		env_curr_state = HIGH_SHUTDOWN_THRESHOLD;
		(void) pthread_cond_signal(&env_temp_monitor_cv);
		(void) pthread_mutex_unlock(&env_temp_monitor_mutex);
		(void) strncpy(sensor_cond,
			PICLEVENTARGVAL_SENSOR_COND_SHUTDOWN,
			sizeof (sensor_cond));
		syslog(LOG_CRIT, gettext("SUNW_envmond:current temperature (%d)"
			" exceeds upper critical temperature (%d).\n"),
				BYTE_7(res_datap), BYTE_8(res_datap));
		break;
	default:
		(void) strncpy(sensor_cond, PICLEVENTARGVAL_UNKNOWN,
			sizeof (sensor_cond));
		break;
	}

	if (post_sensor_event(sensorh, sensor_cond, NO_COND_TIMEDWAIT)
		!= PICL_SUCCESS) {
		syslog(LOG_ERR, gettext("SUNW_envmond:Error in posting "
			"%s event"), PICLEVENT_CONDITION_CHANGE);
	}
}

/*
 * this thread monitors the temperature when the current temperature
 * raises above high warning threshold
 */
/*ARGSUSED*/
static void *
env_temp_monitor(void *args)
{
	int ret;
	timespec_t to;
	int8_t sensor_reading;
	char sensor_cond[BUF_SIZE];

	(void) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	(void) pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	for (;;) {
		(void) pthread_mutex_lock(&env_temp_monitor_mutex);
		if (env_curr_state == NORMAL_THRESHOLD) {
			pthread_cond_wait(&env_temp_monitor_cv,
				&env_temp_monitor_mutex);
		}

		/* check until temp drops below warning threshold */
		to.tv_sec = ENV_TEMP_MONITOR_TIME;
		to.tv_nsec = 0;
		ret = pthread_cond_reltimedwait_np(&env_temp_monitor_cv,
			&env_temp_monitor_mutex, &to);
		if (ret != ETIMEDOUT) {
			(void) pthread_mutex_unlock(&env_temp_monitor_mutex);
			continue;
		}

		/* read the present temperature */
		if (env_get_sensor_reading(cpu_sensor_geo_addr,
			&sensor_reading) != PICL_SUCCESS) {
			(void) pthread_mutex_unlock(&env_temp_monitor_mutex);
			continue;
		}

		(void) pthread_mutex_lock(&sensor_mutex);
		if (sensor_reading < temp_sensor.hi_warning &&
			sensor_reading > temp_sensor.lo_warning) {
			/* temperature is ok now */
			(void) strncpy(sensor_cond, PICLEVENTARGVAL_OK,
				sizeof (sensor_cond));
			env_curr_state = NORMAL_THRESHOLD;
		}
		(void) pthread_mutex_unlock(&sensor_mutex);

		if (env_curr_state == NORMAL_THRESHOLD) {
			syslog(LOG_NOTICE, gettext("SUNW_envmond:Current "
				"temperature is ok now"));
			if (post_sensor_event(sensorh, sensor_cond,
				NO_COND_TIMEDWAIT) != PICL_SUCCESS) {
				syslog(LOG_ERR, gettext("SUNW_envmond:Error in"
					" posting %s event"),
						PICLEVENT_CONDITION_CHANGE);
			}
		}
		(void) pthread_mutex_unlock(&env_temp_monitor_mutex);
	}
	/*NOTREACHED*/
	return (NULL);
}
