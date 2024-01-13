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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SYS_NVME_MICRON_74X0_H
#define	_SYS_NVME_MICRON_74X0_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * This header contains all of the current vendor-specific entries for known
 * Micron devices as well as common structures and definitions that are shared
 * across multiple device families.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	MICRON_7400_PRO_DID	0x51c0
#define	MICRON_7400_MAX_DID	0x51c1
#define	MICRON_7450_PRO_DID	0x51c3
#define	MICRON_7450_MAX_DID	0x51c4

typedef enum {
	MICRON_74x0_LOG_EXT_SMART	= 0xe1
} micron_74x0_vul_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_MICRON_74X0_H */
