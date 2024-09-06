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

#ifndef _SYS_NVME_SOLIDIGM_PS10X0_H
#define	_SYS_NVME_SOLIDIGM_PS10X0_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * Vendor-specific definitions for the Solidigm (nee Intel) PS1010 and PS1030.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	SOLIDIGM_PS10X0_DID	0x2B59
#define	SOLIDIGM_PS1010_U2_SDID	0x0008
#define	SOLIDIGM_PS1010_E3_SDID	0x0019
#define	SOLIDIGM_PS1030_U2_SDID	0x0108
#define	SOLIDIGM_PS1030_E3_SDID	0x0119

typedef enum {
	SOLIDIGM_PS10x0_LOG_OCP_SMART	= OCP_LOG_DSSD_SMART,
	SOLIDIGM_PS10x0_LOG_OCP_ERRREC	= OCP_LOG_DSSD_ERROR_REC,
	SOLIDIGM_PS10x0_LOG_OCP_FWACT	= OCP_LOG_DSSD_FWACT,
	SOLIDIGM_PS10x0_LOG_OCP_LATENCY	= OCP_LOG_DSSD_LATENCY,
	SOLIDIGM_PS10x0_LOG_OCP_DEV_CAP	= OCP_LOG_DSSD_DEV_CAP,
	SOLIDIGM_PS10x0_LOG_OCP_UNSUP	= OCP_LOG_DSSD_UNSUP_REQ,
	/*
	 * Uses the solidigm_vul_smart_log_t. The maximum number of entries is
	 * always grabbed, but there may be holes.
	 */
	SOLIDIGM_PS10x0_LOG_SMART	= 0xca,
	/*
	 * Uses the solidigm_vul_temp_t.
	 */
	SOLIDIGM_PS10x0_LOG_TEMP	= 0xd5
} solidigm_ps10x0_vul_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_SOLIDIGM_PS10X0_H */
