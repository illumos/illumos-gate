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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SGENV_H
#define	_SYS_SGENV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * sgenv.h - Serengeti Environmental Driver
 *
 * This header file contains the environmental definitions for
 * the Serengeti platform.
 *
 * It contains all the information necessary to obtain the required
 * data from the kstats which export the environmental data. The
 * following information is exported.
 *
 *	o Board status information
 *	o Keyswitch position
 *	o Environmental Readings
 */

#include <sys/time.h>		/* hrtime_t */
#include <sys/sgenv_tag.h>	/* TagID information */
#include <sys/sgfrutypes.h>	/* HPU type information */
#include <sys/serengeti.h>

#define	SGENV_DRV_NAME		"sgenv"

/*
 * Board Status Information
 * ========================
 */

/* name of kstat returning board status info */
#define	SG_BOARD_STATUS_KSTAT_NAME	"sg_board_status"

/* Masks to determine which LEDs are on */
#define	SG_HOTPLUG_LED_MASK	0x1
#define	SG_FAULT_LED_MASK	0x2
#define	SG_POWER_LED_MASK	0x4

/*
 * Calculate the number of boards, who's info readings that were
 * returned by this kstat
 */
#define	SGENV_NUM_BOARD_READINGS(ksp)	((ksp)->ks_data_size /	\
						(sizeof (sg_board_info_t)))

typedef union sg_led {
	struct {
		int	_pad	:29,	/* MSB */
			power	:1,
			fault	:1,
			hotplug	:1;	/* LSB */
	} status;

	int led_status;

} sg_led_t;

typedef struct sg_board_info {
	int	node_id;
	int	board_num;

	int	condition;	/* see <sbd_cond_t> in <sbdp_ioctl.h> */
	int	assigned;
	int	claimed;
	int	present;	/* 1 if board is present in Domain */

	sg_led_t	led;

} sg_board_info_t;


/*
 * Keyswitch Information
 * =====================
 */

/* name of kstat returning keyswitch info */
#define	SG_KEYSWITCH_KSTAT_NAME		"sg_keyswitch"

/*
 * Kstat structure used to pass Keyswitch data to userland.
 *
 * The position is stored in the 32-bit integer value of the
 * kstat_named_t union <keyswitch_position>.
 *
 * (i.e.  to get the position - read keyswitch_position.value.ui32)
 */
typedef struct {
	kstat_named_t	keyswitch_position;	/* position */

} sg_keyswitch_kstat_t;


/*
 * Environmental Information
 * =========================
 *
 * the environmental kstat exports an array of env_sensor_t structs
 */

#define	SG_ENV_INFO_KSTAT_NAME		"sg_env_info"


/*
 * sd_infostamp access macros and return values
 *
 * N.b.	None of the values need shifting.  This means the
 *	UTC time in nanoseconds since The Epoch has, at best,
 *	a resolution of c.256 nanoseconds (since the lo-order
 *	c.8-bits are overlaid with other information).
 */

#define	SG_INFO_TIMESTATUS(info)	((int)((info) & _SG_INFO_TIMSTSMSK))
#define	SG_INFO_VALUESTATUS(info)	((int)((info) & _SG_INFO_VALSTSMSK))
#define	SG_INFO_NANOSECONDS(info) ((hrtime_t)((info) & _SG_INFO_TIMVALMSK))

#define	_SG_INFO_TIMSTSMSK		((sensor_status_t)0x0F)
#define	SG_INFO_TIME_OK			0x00  /* always 0 */
#define	SG_INFO_TIME_NOT_KNOWN		0x01
#define	SG_INFO_TIME_NOT_AVAILABLE	0x02

#define	_SG_INFO_VALSTSMSK		((sensor_status_t)0xF0)
#define	SG_INFO_VALUE_OK		0x00  /* always 0 */
#define	SG_INFO_VALUE_NOT_POSSIBLE	0x10
#define	SG_INFO_VALUE_NOT_AVAILABLE	0x20

#define	_SG_INFO_TIMVALMSK  \
		(((hrtime_t)~0) & ~(_SG_INFO_TIMSTSMSK | _SG_INFO_VALSTSMSK))


/* Calculate the number of sensor readings that were returned by this kstat */
#define	SGENV_NUM_ENV_READINGS(ksp)	((ksp)->ks_data_size /	\
						(sizeof (env_sensor_t)))

/* used to calculate the status of a sensor reading from <sd_status> */
#define	SG_STATUS_SHIFT				16
#define	SG_STATUS_MASK				0xFFFF
#define	SG_PREV_STATUS_MASK			0xFFFF0000

#define	SG_GET_SENSOR_STATUS(status)		((status) & SG_STATUS_MASK)
#define	SG_GET_PREV_SENSOR_STATUS(status)	((status) >> SG_STATUS_SHIFT)

#define	SG_SET_SENSOR_STATUS(status, value) \
		status &= ~SG_STATUS_MASK; \
		status |= ((value) & SG_STATUS_MASK)

#define	SG_SET_PREV_SENSOR_STATUS(status, value) \
		status &= ~SG_PREV_STATUS_MASK; \
		status |= (((value) & SG_STATUS_MASK) << SG_STATUS_SHIFT)


typedef int32_t		sensor_data_t;
typedef hrtime_t	sensor_status_t;

/*
 * The possible states a sensor reading can be in.
 */
typedef enum env_sensor_status {
	SG_SENSOR_STATUS_OK		= 0x01,
	SG_SENSOR_STATUS_LO_WARN	= 0x02,
	SG_SENSOR_STATUS_HI_WARN	= 0x04,
	SG_SENSOR_STATUS_LO_DANGER	= 0x08,
	SG_SENSOR_STATUS_HI_DANGER	= 0x10,
	SG_SENSOR_STATUS_FAN_OFF	= 0x100,
	SG_SENSOR_STATUS_FAN_LOW	= 0x200,
	SG_SENSOR_STATUS_FAN_HIGH	= 0x400,
	SG_SENSOR_STATUS_FAN_FAIL	= 0x800,
	SG_SENSOR_STATUS_UNKNOWN	= 0x1000

} env_sensor_status_t;


/*
 * The raw env. info. kstat is made up of an array of these structures.
 */
typedef struct env_sensor {
	sensor_id_t		sd_id;		/* defined in sensor_tag.h */
	sensor_data_t		sd_value;
	sensor_data_t		sd_lo;
	sensor_data_t		sd_hi;
	sensor_data_t		sd_lo_warn;
	sensor_data_t		sd_hi_warn;
	sensor_status_t		sd_infostamp;
	env_sensor_status_t	sd_status;

} env_sensor_t;


/*
 * Events Information
 * ==================
 */
#define	SGENV_FAN_SPEED_UNKNOWN		(-1)
#define	SGENV_FAN_SPEED_OFF		0
#define	SGENV_FAN_SPEED_LOW		1
#define	SGENV_FAN_SPEED_HIGH		2

#define	SGENV_FAN_SPEED_UNKNOWN_STR	"Unknown"
#define	SGENV_FAN_SPEED_OFF_STR		"Off"
#define	SGENV_FAN_SPEED_LOW_STR		"Low"
#define	SGENV_FAN_SPEED_HIGH_STR	"High"

#define	SGENV_EVENT_MSG_OK		"returned to the normal operating range"
#define	SGENV_EVENT_MSG_LO_WARN		"dropped below low warning threshold"
#define	SGENV_EVENT_MSG_HI_WARN		"exceeded high warning threshold"
#define	SGENV_EVENT_MSG_LO_DANGER	"dropped below low warning limit"
#define	SGENV_EVENT_MSG_HI_DANGER	"exceeded high warning limit"
#define	SGENV_EVENT_MSG_UNKNOWN		"changed to an unknown status"


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SGENV_H */
