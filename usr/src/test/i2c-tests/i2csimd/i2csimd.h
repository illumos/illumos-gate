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

#ifndef _I2CSIMD_H
#define	_I2CSIMD_H

/*
 * Definitions for the i2c simulator daemon.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <i2csim.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct i2csimd_ops {
	bool (*sop_write)(void *, uint32_t, const uint8_t *);
	bool (*sop_read)(void *, uint32_t, uint8_t *);
} i2csimd_ops_t;

typedef struct i2csimd_dev {
	uint8_t dev_addr;
	const char *dev_name;
	void *dev_arg;
	const i2csimd_ops_t *dev_ops;
} i2csimd_dev_t;

typedef struct i2csimd_port {
	uint32_t port_ctrl;
	uint32_t port_num;
	i2csimd_dev_t *port_devs[1 << 7];
} i2csimd_port_t;

typedef struct i2csimd {
	int simd_fd;
	i2csim_req_t simd_req;
	i2csimd_port_t simd_ports[1];
} i2csimd_t;

extern i2csimd_dev_t *i2csimd_make_at24cXX(uint8_t, const char *, size_t);
extern i2csimd_dev_t *i2csimd_make_at24c32(uint8_t, const char *, size_t);
extern i2csimd_dev_t *i2csimd_make_ts5111(uint8_t, uint16_t);
extern i2csimd_dev_t *i2csimd_make_pca9548(uint8_t, i2csimd_port_t *,
    i2csimd_port_t [8]);

#ifdef __cplusplus
}
#endif

#endif /* _I2CSIMD_H */
