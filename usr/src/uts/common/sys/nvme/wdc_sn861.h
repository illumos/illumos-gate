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

#ifndef _SYS_NVME_WDC_SN861_H
#define	_SYS_NVME_WDC_SN861_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * Vendor-specific definitions for the WDC SN861 NVMe device.
 */

#include <sys/debug.h>
#include <sys/stdint.h>
#include <sys/nvme/ocp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	WDC_SN861_DID	0x2751

typedef enum {
	WDC_SN861_LOG_OCP_SMART		= OCP_LOG_DSSD_SMART,
	WDC_SN861_LOG_OCP_ERRREC	= OCP_LOG_DSSD_ERROR_REC,
	WDC_SN861_LOG_OCP_FWACT		= OCP_LOG_DSSD_FWACT,
	WDC_SN861_LOG_OCP_LATENCY	= OCP_LOG_DSSD_LATENCY,
	WDC_SN861_LOG_OCP_DEV_CAP	= OCP_LOG_DSSD_DEV_CAP,
	WDC_SN861_LOG_OCP_UNSUP		= OCP_LOG_DSSD_UNSUP_REQ
} wdc_sn861_vul_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_WDC_SN861_H */
