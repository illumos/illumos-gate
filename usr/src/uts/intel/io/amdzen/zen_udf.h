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

#ifndef _ZEN_UDF_H
#define	_ZEN_UDF_H

/*
 * Private ioctls for interfacing with the zen_udf driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	ZEN_UDF_IOCTL	(('u' << 24) | ('d' << 16) | ('f' << 8))

#define	ZEN_UDF_READ	(ZEN_UDF_IOCTL | 0x01)

typedef enum zen_udf_flags {
	/*
	 * Perform a broadcast rather than per-instance read. This is
	 * effectively an OR of the result across all instances.
	 */
	ZEN_UDF_F_BCAST		= 1 << 0,
	/*
	 * Treat the given register as 64-bits wide rather than 32-bits.
	 */
	ZEN_UDF_F_64		= 1 << 1

} zen_udf_flags_t;

typedef struct zen_udf_io {
	zen_udf_flags_t	zui_flags;
	uint8_t		zui_inst;
	uint8_t		zui_func;
	uint16_t	zui_reg;
	uint64_t	zui_data;
} zen_udf_io_t;

#ifdef __cplusplus
}
#endif

#endif /* _ZEN_UDF_H */
