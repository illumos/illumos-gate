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

#ifndef	_SYS_CONTRACT_H
#define	_SYS_CONTRACT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef uint64_t	ctevid_t;

/*
 * Contract parameter maximum size, in bytes
 */
#define	CT_PARAM_MAX_SIZE	8192

/*
 * Common event types
 */
#define	CT_EV_NEGEND	0

/*
 * Level of status detail requested
 */
#define	CTD_COMMON	0	/* No additional detail */
#define	CTD_FIXED	1	/* O(1) info */
#define	CTD_ALL		2	/* O(n) info */

/*
 * Values for ctev_flags.
 */
#define	CTE_ACK		0x1
#define	CTE_INFO	0x2
#define	CTE_NEG		0x4

#define	CTP_EV_CRITICAL	100
#define	CTP_EV_INFO	101
#define	CTP_COOKIE	102

#define	CTS_NEWCT	"cts_newct"
#define	CTS_NEVID	"cts_nevid"

typedef enum ctstate {
	CTS_OWNED,	/* contract is owned by a process */
	CTS_INHERITED,	/* contract has been inherited by its parent */
	CTS_ORPHAN,	/* contract has no parent */
	CTS_DEAD	/* contract has been destroyed */
} ctstate_t;

typedef enum ct_typeid {
	CTT_PROCESS,	/* process contract */
	CTT_DEVICE,	/* device contract */
	CTT_MAXTYPE
} ct_typeid_t;

typedef struct ct_event {
	ctid_t	ctev_id;
	uint32_t ctev_pad1;
	ctevid_t ctev_evid;
	ct_typeid_t ctev_cttype;
	uint32_t ctev_flags;
	uint32_t ctev_type;
	uint32_t ctev_nbytes;
	uint32_t ctev_goffset;
	uint32_t ctev_pad2;
	char	*ctev_buffer;
} ct_event_t;

typedef struct ct_status {
	ctid_t	ctst_id;
	zoneid_t ctst_zoneid;
	ct_typeid_t ctst_type;
	pid_t	ctst_holder;
	ctstate_t ctst_state;
	int	ctst_nevents;
	int	ctst_ntime;
	int	ctst_qtime;
	uint64_t ctst_nevid;
	uint_t	ctst_detail;
	size_t	ctst_nbytes;
	uint_t	ctst_critical;
	uint_t	ctst_informative;
	uint64_t ctst_cookie;
	char	*ctst_buffer;
} ct_status_t;

typedef struct ct_param {
	uint32_t ctpm_id;
	uint32_t ctpm_size;
	void	 *ctpm_value;
} ct_param_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONTRACT_H */
