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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_CONTRACT_DEVICE_H
#define	_SYS_CONTRACT_DEVICE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/contract.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ctmpl_device ctmpl_device_t;
typedef struct cont_device cont_device_t;

/*
 * ct_ev_* flags
 */
#define	CT_DEV_EV_ONLINE	0x1	/* device is moving to online state */
#define	CT_DEV_EV_DEGRADED	0x2	/* device is moving to degraded state */
#define	CT_DEV_EV_OFFLINE	0x4	/* device is moving to offline state */
#define	CT_DEV_ALLEVENT		0x7

/*
 * ctp_id values
 */
#define	CTDP_ACCEPT		0x1	/* the acceptable set term */
#define	CTDP_NONEG		0x2	/* the non-negotiable term */
#define	CTDP_MINOR		0x4	/* the minor path term */
#define	CTDP_ALLPARAMS		0x7

#define	CTDP_NONEG_CLEAR	0x0	/* clear the noneg flag */
#define	CTDP_NONEG_SET		0x1	/* set noneg */

/*
 * Status fields
 */
#define	CTDS_STATE		"ctds_state"
#define	CTDS_ASET		"ctds_aset"
#define	CTDS_NONEG		"ctds_noneg"
#define	CTDS_MINOR		"ctds_minor"

/*
 * Max Time allowed for synchronous acknowledgement of a negotiation event
 */
#define	CT_DEV_ACKTIME	60	/* 60 seconds */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONTRACT_DEVICE_H */
