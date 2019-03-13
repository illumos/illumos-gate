/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019, Joyent, Inc.
 */

#ifndef _SYS_SENSORS_H
#define	_SYS_SENSORS_H

/*
 * Consolidated sensor ioctls for various parts of the operating system. These
 * interfaces should not be relied on at all. They are evolving and will change
 * as we add more to the system for this. This may eventually become a larger
 * framework, though it's more likely we'll consolidate that in userland.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * List of different possible kinds of sensors.
 */
#define	SENSOR_KIND_UNKNOWN		0x00
#define	SENSOR_KIND_TEMPERATURE		0x01

/*
 * Lists of units that senors may have.
 */
#define	SENSOR_UNIT_UNKNOWN		0x00
#define	SENSOR_UNIT_CELSIUS		0x01
#define	SENSOR_UNIT_FAHRENHEIT		0x02
#define	SENSOR_UNIT_KELVIN		0x03

#define	SENSOR_IOCTL	(('s' << 24) | ('e' << 16) | ('n' << 8))

/*
 * Ask the sensor what kind of sensor it is.
 */
#define	SENSOR_IOCTL_TYPE	(SENSOR_IOCTL | 0x01)

typedef struct sensor_ioctl_kind {
	uint64_t	sik_kind;
} sensor_ioctl_kind_t;

/*
 * Ask the sensor for a temperature measurement. The sensor is responsible for
 * returning the units it's in.  A temperature measurement is broken down into a
 * signed value and a notion of its granularity. The sit_gran member indicates
 * the granularity: the number of increments per degree in the temperature
 * measurement (the sit_temp member). sit_gran is signed and the sign indicates
 * whether one needs to multiply or divide the granularity. For example, a
 * value that set sit_gran to 10 would mean that the value in sit_temp was in
 * 10ths of a degree and that to get the actual value in degrees, one would
 * divide by 10. On the other hand, a negative value means that we effectively
 * have to multiply to get there. For example, a value of -2 would indicate that
 * each value in sit_temp indicated two degrees and to get the temperature in
 * degrees you would multiply sit_temp by two.
 */
#define	SENSOR_IOCTL_TEMPERATURE	(SENSOR_IOCTL | 0x02)

typedef struct sensor_ioctl_temperature {
	uint32_t	sit_unit;
	int32_t		sit_gran;
	int64_t		sit_temp;
} sensor_ioctl_temperature_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SENSORS_H */
