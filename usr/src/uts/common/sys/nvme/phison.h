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

#ifndef _SYS_NVME_PHISON_H
#define	_SYS_NVME_PHISON_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * This header contains all of the current vendor-specific entries for known
 * Phison devices as well as common structures and definitions that are shared
 * across multiple device families.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/nvme/ocp.h>

#define	PHISON_PCI_VID	0x1987
#define	PHISON_X200_DID	0x5302

typedef enum {
	PHISON_X200_LOG_OCP_SMART	= OCP_LOG_DSSD_SMART,
	PHISON_X200_LOG_OCP_ERRREC	= OCP_LOG_DSSD_ERROR_REC,
	PHISON_X200_LOG_OCP_FWACT	= OCP_LOG_DSSD_FWACT,
	PHISON_X200_LOG_OCP_LATENCY	= OCP_LOG_DSSD_LATENCY,
	PHISON_X200_LOG_OCP_DEV_CAP	= OCP_LOG_DSSD_DEV_CAP,
	PHISON_X200_LOG_OCP_UNSUP	= OCP_LOG_DSSD_UNSUP_REQ
} phison_x200_vul_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_PHISON_H */
