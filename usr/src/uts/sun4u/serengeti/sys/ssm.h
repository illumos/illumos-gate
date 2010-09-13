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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SSM_H
#define	_SYS_SSM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>		/* needed by <sys/dditypes.h> */
#include <sys/dditypes.h>	/* needed for definition of dev_info_t */
#include <sys/mutex.h>

/*
 * ssm soft state macros: IIIIMMMM
 *                 instance-minor no
 */
#define	SSM_INSTANCE_SHIFT	4
#define	SSM_BOARD_MASK		0xff


struct ssm_soft_state {
	dev_info_t	*dip;		/* own dev info */
	int		ssm_nodeid;	/* node id */
	dev_info_t	*top_node;
	int		initialized;	/* instance has been initialized */
	kmutex_t	ssm_sft_lock;	/* protects this struct */
	ddi_iblock_cookie_t ssm_fm_ibc; /* returned ibc from our parent */
	int		ssm_fm_cap;	/* our fm capability */
};

typedef struct {
	int	instance;	/* instance for this wildcat node */
	int	wnode;		/* node num */
} ssm_sbdp_info_t;

/*
 * useful debugging stuff
 */
#define	SSM_ATTACH_DEBUG	0x0002
#define	SSM_CTLOPS_DEBUG	0x0004
#define	SSM_EVENT_DEBUG		0x0008

#define	_SSM_IOCTL		(('m' << 16) | ('p' << 8))
#define	SSM_TEARDOWN_SBD	(_SSM_IOCTL | 0x1)

#ifdef DEBUG
#define	CMD2EVNT(m)	((m) == SGDR_BD_ABSENT	? SG_EVT_BOARD_ABSENT :	\
			    (m) == SGDR_BD_PRESENT ? SG_EVT_BOARD_PRESENT :\
			    (m) == SGDR_UNASSIGN ? SG_EVT_UNASSIGN : 	\
			    (m) == SGDR_ASSIGN ? SG_EVT_ASSIGN :	\
			    (m) == SGDR_UNAVAILABLE ? SG_EVT_UNAVAILABLE :\
			    (m) == SGDR_AVAILABLE ? SG_EVT_AVAILABLE : 	\
			    (m) == SGDR_POWER_OFF ? SG_EVT_POWER_OFF : 	\
			    (m) == SGDR_POWER_ON ? SG_EVT_POWER_ON :	\
			    (m) == SGDR_PASSED_TEST ? SG_EVT_PASSED_TEST :\
			    (m) == SGDR_FAILED_TEST ? SG_EVT_FAILED_TEST :\
			    0)

#define	EVNT2STR(c)	((c) == SG_EVT_BOARD_ABSENT ? "board_absent" :\
			    (c) == SG_EVT_BOARD_PRESENT ? "board_present" :\
			    (c) == SG_EVT_UNASSIGN ? "unassign" :	\
			    (c) == SG_EVT_ASSIGN ? "assign" :		\
			    (c) == SG_EVT_UNAVAILABLE ? "unavailable" :	\
			    (c) == SG_EVT_AVAILABLE ? "available" :	\
			    (c) == SG_EVT_POWER_OFF ? "power_off" :	\
			    (c) == SG_EVT_POWER_ON	? "power_on" :	\
			    (c) == SG_EVT_PASSED_TEST ? "passed_test" :	\
			    (c) == SG_EVT_FAILED_TEST ? "failed_test" :	\
			    NULL)
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SSM_H */
