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
 * Copyright 2024 Oxide Computer Company
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
#define	SENSOR_KIND_VOLTAGE		0x02
#define	SENSOR_KIND_CURRENT		0x03
#define	SENSOR_KIND_SYNTHETIC		0x04

/*
 * Lists of units that sensors may have. The none type is intended for unitless
 * sensors such as general control sensors. These sensors are generally derived
 * from a secondary unit. A prime example is AMD's CPU control temperature,
 * which is a unitless measure that is derived from temperature.
 */
#define	SENSOR_UNIT_UNKNOWN		0x00
#define	SENSOR_UNIT_CELSIUS		0x01
#define	SENSOR_UNIT_FAHRENHEIT		0x02
#define	SENSOR_UNIT_KELVIN		0x03
#define	SENSOR_UNIT_VOLTS		0x04
#define	SENSOR_UNIT_AMPS		0x05
#define	SENSOR_UNIT_NONE		0x06

#define	SENSOR_IOCTL	(('s' << 24) | ('e' << 16) | ('n' << 8))

/*
 * Ask the sensor what kind of sensor it is.
 */
#define	SENSOR_IOCTL_KIND	(SENSOR_IOCTL | 0x01)

typedef struct sensor_ioctl_kind {
	uint64_t	sik_kind;
	uint64_t	sik_derive;
} sensor_ioctl_kind_t;

/*
 * Ask the sensor for a scalar measurement. The sensor is responsible for
 * returning the units it's in.  A scalar measurement is broken down into a
 * signed value and a notion of its granularity. The sit_gran member indicates
 * the granularity: the number of increments per unit in the measurement (the
 * sit_value member). sit_gran is signed and the sign indicates whether one
 * needs to multiply or divide the granularity. The sit_prec member describes a
 * +/- value (taking sit_gran into account) that describes the precision of the
 * sensor.
 *
 * For example, consider a temperature sensor that set sit_gran to 10. This
 * would mean that the value in sit_value was in 10ths of a degree and that to
 * get the actual value in degrees, one would divide by 10. On the other hand, a
 * negative value means that we effectively have to multiply to get there. For
 * example, a value of -2 would indicate that each value in sit_value indicated
 * two degrees and to get the temperature in degrees you would multiply
 * sit_value * by two.
 */
#define	SENSOR_IOCTL_SCALAR	(SENSOR_IOCTL | 0x02)

typedef struct sensor_ioctl_scalar {
	uint32_t	sis_unit;
	int32_t		sis_gran;
	uint32_t	sis_prec;
	uint32_t	sis_pad;
	int64_t		sis_value;
} sensor_ioctl_scalar_t;

#ifdef	_KERNEL
typedef int (*ksensor_kind_f)(void *, sensor_ioctl_kind_t *);
typedef int (*ksensor_scalar_f)(void *, sensor_ioctl_scalar_t *);

typedef struct {
	ksensor_kind_f		kso_kind;
	ksensor_scalar_f	kso_scalar;
} ksensor_ops_t;

extern int ksensor_kind_temperature(void *, sensor_ioctl_kind_t *);
extern int ksensor_kind_voltage(void *, sensor_ioctl_kind_t *);
extern int ksensor_kind_current(void *, sensor_ioctl_kind_t *);

/*
 * Create a sensor where the class and name is supplied.
 */
extern int ksensor_create(dev_info_t *, const ksensor_ops_t *, void *,
    const char *, const char *, id_t *);

/*
 * Create a scalar sensor for a PCI device. If this is not a device-wide
 * (e.g. per-function) sensor, this should not be used.
 */
extern int ksensor_create_scalar_pcidev(dev_info_t *, uint64_t,
    const ksensor_ops_t *, void *, const char *, id_t *);

/*
 * Remove a named or all sensors from this driver.
 */
#define	KSENSOR_ALL_IDS	INT_MIN
extern int ksensor_remove(dev_info_t *, id_t);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SENSORS_H */
