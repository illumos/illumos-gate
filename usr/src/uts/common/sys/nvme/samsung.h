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

#ifndef _SYS_NVME_SAMSUNG_H
#define	_SYS_NVME_SAMSUNG_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * This header contains all of the current vendor-specific entries for known
 * Phison devices as well as common structures and definitions that are shared
 * across multiple device families.
 */

#include <sys/nvme/ocp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	SAMSUNG_PCI_VID		0x144d
#define	SAMSUNG_PM9D3_DID	0xa900

typedef enum {
	SAMSUNG_PM9D3_LOG_OCP_SMART	= OCP_LOG_DSSD_SMART,
	SAMSUNG_PM9D3_LOG_OCP_ERRREC	= OCP_LOG_DSSD_ERROR_REC,
	SAMSUNG_PM9D3_LOG_OCP_FWACT	= OCP_LOG_DSSD_FWACT,
	SAMSUNG_PM9D3_LOG_OCP_LATENCY	= OCP_LOG_DSSD_LATENCY,
	SAMSUNG_PM9D3_LOG_OCP_DEV_CAP	= OCP_LOG_DSSD_DEV_CAP,
	SAMSUNG_PM9D3_LOG_OCP_UNSUP	= OCP_LOG_DSSD_UNSUP_REQ,
	SAMSUNG_PM9D3_LOG_OCP_TCG	= OCP_LOG_DSSD_TCG,
	SAMSUNG_PM9D3_LOG_OCP_TELEMETRY	= OCP_LOG_DSSD_TELEMETRY,
} samsung_pm9d3_vul_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_SAMSUNG_H */
