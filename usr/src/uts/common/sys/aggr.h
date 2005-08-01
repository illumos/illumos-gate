/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_AGGR_H
#define	_SYS_AGGR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/param.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* control interface name */
#define	AGGR_DEVNAME_CTL	"ctl"

/*
 * Transmit load balancing policies.
 */

#define	AGGR_POLICY_L2		0x01
#define	AGGR_POLICY_L3		0x02
#define	AGGR_POLICY_L4		0x04

/*
 * LACP mode and timer.
 */

typedef enum {
	AGGR_LACP_OFF		= 0,
	AGGR_LACP_ACTIVE	= 1,
	AGGR_LACP_PASSIVE	= 2
} aggr_lacp_mode_t;

typedef enum {
	AGGR_LACP_TIMER_LONG	= 0,
	AGGR_LACP_TIMER_SHORT	= 1
} aggr_lacp_timer_t;

/*
 * MAC port state.
 */
typedef enum {
	AGGR_PORT_STATE_STANDBY = 1,
	AGGR_PORT_STATE_ATTACHED = 2
} aggr_port_state_t;

/* Maximum number of ports per aggregation. */
#define	AGGR_MAX_PORTS	256

/*
 * LACP port state.
 */
typedef union {
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint8_t expired:	1;
		uint8_t defaulted:	1;
		uint8_t distributing:	1;
		uint8_t collecting:	1;
		uint8_t sync:	1;
		uint8_t aggregation:	1;
		uint8_t timeout:	1;
		uint8_t	activity:	1;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t	activity:	1;
		uint8_t timeout:	1;
		uint8_t aggregation:	1;
		uint8_t sync:	1;
		uint8_t collecting:	1;
		uint8_t distributing:	1;
		uint8_t defaulted:	1;
		uint8_t expired:	1;
#else
#error "unknown bit fields ordering"
#endif
	} bit;
	uint8_t state;
} aggr_lacp_state_t;

#define	LAIOC(x)		(('l' << 24) | ('a' << 16) | ('m' << 8) | (x))

/* one of the ports of a link aggregation group */
typedef struct laioc_port {
	char		lp_devname[MAXNAMELEN + 1];
	uint_t		lp_port;
} laioc_port_t;

#define	LAIOC_CREATE		LAIOC(1)

typedef struct laioc_create {
	uint32_t	lc_key;
	uint32_t	lc_nports;
	uint32_t	lc_policy;
	uchar_t		lc_mac[ETHERADDRL];
	boolean_t	lc_mac_fixed;
	aggr_lacp_mode_t lc_lacp_mode;
	aggr_lacp_timer_t lc_lacp_timer;
} laioc_create_t;

#ifdef _SYSCALL32

typedef struct laioc_create32 {
	uint32_t	lc_key;
	uint32_t	lc_nports;
	uint32_t	lc_policy;
	uchar_t		lc_mac[ETHERADDRL];
	boolean_t	lc_mac_fixed;
	aggr_lacp_mode_t lc_lacp_mode;
	aggr_lacp_timer_t lc_lacp_timer;
} laioc_create32_t;

#endif /* _SYSCALL32 */

#define	LAIOC_DELETE		LAIOC(2)

typedef struct laioc_delete {
	uint32_t	ld_key;
} laioc_delete_t;

#ifdef _SYSCALL32

typedef struct laioc_delete32 {
	uint32_t	ld_key;
} laioc_delete32_t;

#endif /* _SYSCALL32 */

#define	LAIOC_INFO		LAIOC(3)

typedef enum aggr_link_duplex {
	AGGR_LINK_DUPLEX_FULL = 1,
	AGGR_LINK_DUPLEX_HALF = 2,
	AGGR_LINK_DUPLEX_UNKNOWN = 3
} aggr_link_duplex_t;

typedef enum aggr_link_state {
	AGGR_LINK_STATE_UP = 1,
	AGGR_LINK_STATE_DOWN = 2,
	AGGR_LINK_STATE_UNKNOWN = 3
} aggr_link_state_t;

typedef struct laioc_info_port {
	char		lp_devname[MAXNAMELEN + 1];
	uint32_t	lp_port;
	uchar_t		lp_mac[ETHERADDRL];
	aggr_port_state_t lp_state;
	aggr_lacp_state_t lp_lacp_state;
} laioc_info_port_t;

typedef struct laioc_info_group {
	uint32_t	lg_key;
	uchar_t		lg_mac[ETHERADDRL];
	boolean_t	lg_mac_fixed;
	uint32_t	lg_policy;
	uint32_t	lg_nports;
	aggr_lacp_mode_t lg_lacp_mode;
	aggr_lacp_timer_t lg_lacp_timer;
} laioc_info_group_t;

typedef struct laioc_info {
	uint32_t	li_ngroups;
	uint32_t	li_group_key;	/* 0 returns all */
} laioc_info_t;

#define	LAIOC_ADD		LAIOC(4)
#define	LAIOC_REMOVE		LAIOC(5)

typedef struct laioc_add_rem {
	uint32_t	la_key;
	uint32_t	la_nports;
} laioc_add_rem_t;

#ifdef _SYSCALL32

typedef struct laioc_add_rem32 {
	uint32_t	la_key;
	uint32_t	la_nports;
} laioc_add_rem32_t;

#endif /* _SYSCALL32 */

#define	LAIOC_MODIFY			LAIOC(6)

#define	LAIOC_MODIFY_POLICY		0x01
#define	LAIOC_MODIFY_MAC		0x02
#define	LAIOC_MODIFY_LACP_MODE		0x04
#define	LAIOC_MODIFY_LACP_TIMER		0x08

typedef struct laioc_modify {
	uint32_t	lu_key;
	uint8_t		lu_modify_mask;
	uint32_t	lu_policy;
	uchar_t		lu_mac[ETHERADDRL];
	boolean_t	lu_mac_fixed;
	aggr_lacp_mode_t lu_lacp_mode;
	aggr_lacp_timer_t lu_lacp_timer;
} laioc_modify_t;

#ifdef _SYSCALL32

typedef struct laioc_modify32 {
	uint32_t	lu_key;
	uint8_t		lu_modify_mask;
	uint32_t	lu_policy;
	uchar_t		lu_mac[ETHERADDRL];
	boolean_t	lu_mac_fixed;
	aggr_lacp_mode_t lu_lacp_mode;
	aggr_lacp_timer_t lu_lacp_timer;
} laioc_modify32_t;

#endif /* _SYSCALL32 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AGGR_H */
