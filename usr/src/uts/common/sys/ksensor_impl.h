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
 * Copyright 2020 Oxide Computer Company
 */

#ifndef _SYS_KSENSOR_IMPL_H
#define	_SYS_KSENSOR_IMPL_H

/*
 * ksensor implementation glue.
 */

#include <sys/sensors.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Routine for the kernel to initalize the subsystem.
 */
extern void ksensor_init(void);

/*
 * Operations vectors.
 */
extern int ksensor_op_kind(id_t, sensor_ioctl_kind_t *);
extern int ksensor_op_temperature(id_t, sensor_ioctl_temperature_t *);

/*
 * Registration callbacks.
 */
typedef int (*ksensor_create_f)(id_t, const char *, const char *);
typedef void (*ksensor_remove_f)(id_t, const char *);
extern int ksensor_register(dev_info_t *, ksensor_create_f, ksensor_remove_f);
extern void ksensor_unregister(dev_info_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KSENSOR_IMPL_H */
