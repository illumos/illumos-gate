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

#ifndef	_PICLSENSORS_H
#define	_PICLSENSORS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	CPU_SENSOR		"CPU-sensor"
#define	EEPROM_WARNING_CMD 	"eeprom warning-temperature=%d"
#define	EEPROM_SHUTDOWN_CMD	"eeprom critical-temperature=%d"
#define	EEPROM_POWEROFF_CMD	"eeprom shutdown-temperature=%d"

#define	ENV_TEMP_MONITOR_TIME	60	/* 60 secs */

#define	NUM_OF_THRESHOLDS	6
#define	MAX_POWEROFF_TEMP	84

typedef struct {
uint8_t sensor_no;
	int8_t  curr_temp;
	int8_t  hi_poweroff;
	int8_t  hi_shutdown;
	int8_t  hi_warning;
	int8_t  lo_poweroff;
	int8_t  lo_shutdown;
	int8_t  lo_warning;
	char    state[20];
} env_temp_sensor_t;

typedef enum {
	NORMAL_THRESHOLD = 0x0,		/* temp is within thresholds */
	LOW_WARNING_THRESHOLD = 0x1,
	LOW_SHUTDOWN_THRESHOLD = 0x2,
	LOW_POWEROFF_THRESHOLD = 0x3,
	HIGH_WARNING_THRESHOLD = 0x4,
	HIGH_SHUTDOWN_THRESHOLD = 0x5,
	HIGH_POWEROFF_THRESHOLD = 0x6
} env_temp_threshold_t;

#define	LOW_WARNING_BIT(_X)		(BIT_0(_X))
#define	LOW_SHUTDOWN_BIT(_X)		(BIT_1(_X))
#define	LOW_POWEROFF_BIT(_X)		(BIT_2(_X))
#define	HIGH_WARNING_BIT(_X)		(BIT_3(_X))
#define	HIGH_SHUTDOWN_BIT(_X)		(BIT_4(_X))
#define	HIGH_POWEROFF_BIT(_X)		(BIT_5(_X))

#define	THRESHOLD_TYPE			0x1

#define	SMC_GET_SENSOR_READING_FAILED \
	gettext("SUNW_envmond: Error in getting sensor reading, "\
	"sensor = %d, errno = %d\n")
#define	SMC_GET_SENSOR_THRES_FAILED \
	gettext("SUNW_envmond: Error in getting sensor threshold, "\
	"sensor = %d, errno = %d\n")
#define	SMC_SET_SENSOR_THRES_FAILED \
	gettext("SUNW_envmond: Error in setting sensor threshold, "\
	"sensor = %d, errno = %d\n")
#define	SMC_GET_LWT_FAILED \
	gettext("SUNW_envmond: Error in getting low warning threshold")
#define	SMC_GET_LST_FAILED \
	gettext("SUNW_envmond: Error in getting low shutdown threshold")
#define	SMC_GET_LPT_FAILED \
	gettext("SUNW_envmond: Error in getting low poweroff threshold")
#define	SMC_GET_HWT_FAILED \
	gettext("SUNW_envmond: Error in getting high warning threshold")
#define	SMC_GET_HST_FAILED \
	gettext("SUNW_envmond: Error in getting high shutdown threshold")
#define	SMC_GET_HPT_FAILED \
	gettext("SUNW_envmond: Error in getting high poweroff threshold")
#define	SMC_SET_LWT_FAILED \
	gettext("SUNW_envmond: Error in setting low warning threshold")
#define	SMC_SET_LST_FAILED \
	gettext("SUNW_envmond: Error in setting low shutdown threshold")
#define	SMC_SET_LPT_FAILED \
	gettext("SUNW_envmond: Error in setting low poweroff threshold")
#define	SMC_SET_HWT_FAILED \
	gettext("SUNW_envmond: Error in setting high warning threshold")
#define	SMC_SET_HST_FAILED \
	gettext("SUNW_envmond: Error in setting high shutdown threshold")
#define	SMC_SET_HPT_FAILED \
	gettext("SUNW_envmond: Error in setting high poweroff threshold")
#define	SMC_ENABLE_SENSOR_EVENT_FAILED \
	gettext("SUNW_envmond: Error in enabling sesnor events, error = %d")
#define	SMC_GET_EXCLUSIVE_ERR \
	gettext("SUNW_envmond:Error in getting exclusive access to set "\
		"temperature sensor thresholds")
#ifdef	__cplusplus
}
#endif

#endif	/* _PICLSENSORS_H */
