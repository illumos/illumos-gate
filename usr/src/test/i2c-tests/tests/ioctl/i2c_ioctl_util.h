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
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _I2C_IOCTL_UTIL_H
#define	_I2C_IOCTL_UTIL_H

/*
 * Misc. utility functions to aid our ioctl tests
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint16_t ba_type;
	uint16_t ba_addr;
	i2c_errno_t ba_error;
} bad_addr_t;

extern const bad_addr_t bad_addrs[];
extern const size_t nbad_addrs;

typedef enum {
	I2C_D_CTRL,
	I2C_D_PORT,
	I2C_D_MUX,
	I2C_D_DEVICE,
	/*
	 * This is meant just for internal uses in the enumeration. Don't use it
	 * explicitly.
	 */
	I2C_D_OTHER
} i2c_dev_t;

extern int i2c_ioctl_test_get_fd(i2c_dev_t, const char *, int);

/*
 * Path for di_init() to the i2csim driver.
 */
extern const char *i2c_sim_dipath;

#ifdef __cplusplus
}
#endif

#endif /* _I2C_IOCTL_UTIL_H */
