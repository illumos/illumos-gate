/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _BMC_FE_H
#define	_BMC_FE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	BMC_NODENAME		"bmc"
#define	BMC_MINOR		0

#define	BMC_DEBUG_LEVEL_0	0
#define	BMC_DEBUG_LEVEL_1	1
#define	BMC_DEBUG_LEVEL_2	2
#define	BMC_DEBUG_LEVEL_3	3
#define	BMC_DEBUG_LEVEL_4	4

void dprintf(int, const char *, ...);

typedef struct  ipmi_dev {
	uint8_t		bmcversion;	/* IPMI Version */
	kmutex_t	if_mutex;	/* Interface lock */
	kcondvar_t	if_cv;		/* Interface condition variable */
	boolean_t	if_busy;	/* Busy Bit */
	timeout_id_t	timer_handle;	/* timer handle */
	boolean_t	timedout;	/* timeout flag */
} ipmi_dev_t;

typedef struct ipmi_stat {
	dev_info_t *ipmi_dip;		/* driver's device pointer */
	ipmi_dev_t ipmi_dev_ext;	/* controlling the BMC interface */
} ipmi_state_t;

/* transfer time limit */
#define	DEFAULT_MSG_TIMEOUT (5 * 1000000) /* 5 seconds */

int vc_init(dev_info_t *);
void vc_uninit(void);
int do_vc2bmc(ipmi_dev_t *, bmc_req_t *, bmc_rsp_t *, boolean_t, boolean_t *);
int bmc_vc_max_response_payload_size(void);
int bmc_vc_max_request_payload_size(void);

#ifdef __cplusplus
}
#endif

#endif /* _BMC_FE_H */
