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

#ifndef _SYS_NVME_MICRON_X500_H
#define	_SYS_NVME_MICRON_X500_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * This covers the Micron 6500 and 7500 series devices.
 */

#include <sys/debug.h>
#include <sys/stddef.h>
#include <sys/nvme/ocp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MICRON_6500_ION_DID	0x51b9
#define	MICRON_7500_PRO_DID	0x51b7
#define	MICRON_7500_MAX_DID	0x51b8

typedef enum {
	MICRON_x500_LOG_OCP_SMART	= OCP_LOG_DSSD_SMART,
	MICRON_x500_LOG_OCP_ERRREC	= OCP_LOG_DSSD_ERROR_REC,
	MICRON_x500_LOG_OCP_FWACT	= OCP_LOG_DSSD_FWACT,
	MICRON_x500_LOG_OCP_LATENCY	= OCP_LOG_DSSD_LATENCY,
	MICRON_x500_LOG_OCP_DEV_CAP	= OCP_LOG_DSSD_DEV_CAP,
	MICRON_x500_LOG_OCP_UNSUP	= OCP_LOG_DSSD_UNSUP_REQ,
} micron_x500_vul_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_MICRON_X500_H */
