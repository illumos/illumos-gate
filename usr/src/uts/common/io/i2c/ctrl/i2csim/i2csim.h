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

#ifndef _I2CSIM_H
#define	_I2CSIM_H

/*
 * Definitions for accesss to the I2C Simulation driver.
 */

#include <sys/i2c/i2c.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	I2CSIM_IOCTL	(('i' << 24) | ('s' << 16) | ('m' << 8))

typedef struct i2csim_req {
	uint64_t i2csim_seq;
	uint32_t i2csim_ctrl;
	uint32_t i2csim_port;
	i2c_ctrl_type_t i2csim_type;
	i2c_req_t i2csim_i2c;
	smbus_req_t i2csim_smbus;
} i2csim_req_t;

#define	I2CSIM_REQUEST	(I2CSIM_IOCTL | 0)
#define	I2CSIM_REPLY	(I2CSIM_IOCTL | 1)

#ifdef __cplusplus
}
#endif

#endif /* _I2CSIM_H */
