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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ENVMON_H
#define	_SYS_ENVMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ioccom.h>

/*
 * environmental monitoring ioctls
 *
 * there are two types of environmental monitor:
 * sensors	- these provide a value for the environmental property
 * indicators	- these provide a status of "within range" or "out of range"
 *
 * for any given environmental property, a particular platform is likely
 * to support either a sensor or an indicator
 *
 * a reserved value is used to signify that a particular sensor value is
 * not available
 */

/* reserved values to signify "value unavailable" */
#define	ENVMON_VAL_UNAVAILABLE	((int16_t)(-32768))

/*
 * The ability of a sensor or indicator to deliver a value is encapsulated
 * in the sensor_status field.
 * The following sensor_status bit fields are defined
 */
#define	ENVMON_SENSOR_OK	0	/* this one's a value */
#define	ENVMON_NOT_PRESENT	1
#define	ENVMON_INACCESSIBLE	2	/* e.g. i2c bus problem */

/*
 * Some drivers may implement the older lomv interface in addition to
 * the ioctls defined here. To avoid a clash with values from older
 * interfaces, ioctls defined here start high in the available range.
 */
#define	ENVMON_BASE		200

#define	ENVMONIOCSYSINFO	_IOR('a',  ENVMON_BASE + 0, envmon_sysinfo_t)
#define	ENVMONIOCVOLTSENSOR	_IOWR('a', ENVMON_BASE + 1, envmon_sensor_t)
#define	ENVMONIOCAMPSENSOR	_IOWR('a', ENVMON_BASE + 2, envmon_sensor_t)
#define	ENVMONIOCTEMPSENSOR	_IOWR('a', ENVMON_BASE + 3, envmon_sensor_t)
#define	ENVMONIOCFAN		_IOWR('a', ENVMON_BASE + 4, envmon_fan_t)
#define	ENVMONIOCVOLTIND	_IOWR('a', ENVMON_BASE + 5, envmon_indicator_t)
#define	ENVMONIOCAMPIND		_IOWR('a', ENVMON_BASE + 6, envmon_indicator_t)
#define	ENVMONIOCTEMPIND	_IOWR('a', ENVMON_BASE + 7, envmon_indicator_t)
#define	ENVMONIOCFANIND		_IOWR('a', ENVMON_BASE + 8, envmon_indicator_t)
#define	ENVMONIOCGETLED		_IOWR('a', ENVMON_BASE + 9, envmon_led_info_t)
#define	ENVMONIOCSETLED		_IOW('a',  ENVMON_BASE + 10, envmon_led_ctl_t)
#define	ENVMONIOCHPU		_IOWR('a', ENVMON_BASE + 11, envmon_hpu_t)
#define	ENVMONIOCGETKEYSW	_IOR('a',  ENVMON_BASE + 12, envmon_keysw_pos_t)
#define	ENVMONIOCGETALARM	\
		_IOWR('a', ENVMON_BASE + 13, envmon_alarm_info_t)
#define	ENVMONIOCSETALARM	_IOWR('a', ENVMON_BASE + 14, envmon_alarm_ctl_t)
#define	ENVMONIOCCHASSISSERIALNUM	\
		_IOR('a', ENVMON_BASE + 15, envmon_chassis_t)

/* field length for text identifiers */
#define	ENVMON_MAXNAMELEN	32

typedef struct {
	char			name[ENVMON_MAXNAMELEN];
} envmon_handle_t;

/*
 * Some structures include threshold fields.
 * Where a particular threshold is not defined for a given sensor,
 * the reserved value ENVMON_VAL_UNAVAILABLE is returned.
 */
typedef struct {
	int16_t			warning;
	int16_t			shutdown;
	int16_t			poweroff;
} envmon_thresholds_t;

/*
 * id identifies the fru to be accessed.
 * next_id returns the id for the next component of the type implied by
 * the ioctl command. If there are no more frus in this sequence,
 * next_id is set to an empty string.
 * If id is set to an empty string on entry, next_id returns the first id.
 * In this case, sensor_status will be returned as ENVMON_NOT_PRESENT.
 */
typedef struct {
	envmon_handle_t		id;
	uint16_t		sensor_status;
	int16_t			value;		/* sensor reading */
	envmon_thresholds_t	lowthresholds;
	envmon_thresholds_t	highthresholds;
	envmon_handle_t		next_id;
} envmon_sensor_t;

typedef struct {
	envmon_handle_t	id;
	uint16_t		sensor_status;
	uint16_t		condition;	/* 0 = within limits */
	envmon_handle_t	next_id;
} envmon_indicator_t;

typedef struct {
	envmon_handle_t	id;
	uint16_t		sensor_status;
	uint16_t		speed;
	char			units[ENVMON_MAXNAMELEN];
	envmon_thresholds_t	lowthresholds;
	envmon_handle_t		next_id;
} envmon_fan_t;

/*
 * Values for led_state
 */
#define	ENVMON_LED_OFF		0
#define	ENVMON_LED_ON		1
#define	ENVMON_LED_BLINKING	2
#define	ENVMON_LED_FLASHING	3

/*
 * Values for the hue of the leds
 */
#define	ENVMON_LED_CLR_NONE	((int8_t)(-1))
#define	ENVMON_LED_CLR_ANY	0
#define	ENVMON_LED_CLR_WHITE	1
#define	ENVMON_LED_CLR_BLUE	2
#define	ENVMON_LED_CLR_GREEN	3
#define	ENVMON_LED_CLR_AMBER	4
#define	ENVMON_LED_CLR_RED	5

typedef struct {
	envmon_handle_t		id;
	uint16_t		sensor_status;
	int8_t			led_state;
	int8_t			led_color;
	envmon_handle_t		next_id;
} envmon_led_info_t;

typedef struct {
	envmon_handle_t		id;
	int8_t			led_state;
} envmon_led_ctl_t;

/*
 * Values for alarm_state
 */
#define	ENVMON_ALARM_OFF	0
#define	ENVMON_ALARM_ON		1

typedef struct {
	envmon_handle_t		id;
	uint16_t		sensor_status;
	int8_t			alarm_state;
	envmon_handle_t		next_id;
} envmon_alarm_info_t;

typedef struct {
	envmon_handle_t		id;
	int8_t			alarm_state;
} envmon_alarm_ctl_t;

/*
 * Values for fru_status
 */
#define	ENVMON_FRU_NOT_PRESENT	0
#define	ENVMON_FRU_PRESENT	1
#define	ENVMON_FRU_FAULT	2
#define	ENVMON_FRU_DOWNLOAD	3	/* flash update or download active */

typedef struct {
	envmon_handle_t		id;
	uint8_t			sensor_status;
	uint8_t			fru_status;
	envmon_handle_t		next_id;
} envmon_hpu_t;

/*
 * env_sysinto_t is used to return limits on various item types
 */
typedef struct {
	uint16_t	maxVoltSens;	/* max number of voltage sensors */
	uint16_t	maxVoltInd;	/* max number of voltage indicators */
	uint16_t	maxAmpSens;	/* max number of current sensors */
	uint16_t	maxAmpInd;	/* max number of circuit breakers */
	uint16_t	maxTempSens;	/* max number of temperature sensors */
	uint16_t	maxTempInd;	/* max number of temp'r indicators */
	uint16_t	maxFanSens;	/* max number of fan speed sensors */
	uint16_t	maxFanInd;	/* max number of fan indicators */
	uint16_t	maxLED;		/* max number of LEDs */
	uint16_t	maxHPU;		/* max number of Hot Pluggable Units */
} envmon_sysinfo_t;

/*
 * envmon_keysw_t is used to return the current value of the
 * keyswitch (if fitted)
 */
typedef enum envmon_keysw_pos {
	ENVMON_KEYSW_POS_UNKNOWN	= 0,
	ENVMON_KEYSW_POS_NORMAL,
	ENVMON_KEYSW_POS_DIAG,
	ENVMON_KEYSW_POS_LOCKED,
	ENVMON_KEYSW_POS_OFF
} envmon_keysw_pos_t;

/*
 * envmon_chassis_t is used to retuen the chassis serial number
 */
typedef struct {
	char		serial_number[ENVMON_MAXNAMELEN];
} envmon_chassis_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ENVMON_H */
