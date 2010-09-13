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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NET_BRIDGE_H
#define	_NET_BRIDGE_H

/*
 * Private communication interface between bridging related daemons and kernel
 * layer-two (Ethernet) bridging module.
 */

#include <sys/param.h>
#include <sys/dld.h>
#include <sys/ethernet.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Specified by IEEE 802.1d */
#define	BRIDGE_GROUP_ADDRESS	{ 0x01, 0x80, 0xC2, 0, 0, 0 }

/* The constant below is "BRG" in hex. */
#define	_BRIOC(n)	(0x42524700 + (n))

#define	BRIOC_NEWBRIDGE	_BRIOC(1)	/* Create bridge; bridge_newbridge_t */
#define	BRIOC_ADDLINK	_BRIOC(2)	/* Add link to bridge; linkid+name */
#define	BRIOC_REMLINK	_BRIOC(3)	/* Remove link from bridge; linkid */
#define	BRIOC_SETSTATE	_BRIOC(4)	/* bridge_setstate_t */
#define	BRIOC_SETPVID	_BRIOC(5)	/* bridge_setpvid_t */
#define	BRIOC_VLANENAB	_BRIOC(6)	/* bridge_vlanenab_t */
#define	BRIOC_FLUSHFWD	_BRIOC(7)	/* bridge_flushfwd_t */
#define	BRIOC_LISTFWD	_BRIOC(8)	/* bridge_listfwd_t */
#define	BRIOC_TABLEMAX	_BRIOC(8)	/* uint32_t */

#define	BRIDGE_CTL	"bridgectl"
#define	BRIDGE_CTLPATH	"/dev/" BRIDGE_CTL

typedef struct bridge_newbridge_s {
	datalink_id_t	bnb_linkid;		/* bridge link ID */
	char		bnb_name[MAXNAMELEN];	/* bridge name */
} bridge_newbridge_t;

typedef enum bridge_state_e {
	BLS_BLOCKLISTEN,		/* blocking or listening state */
	BLS_LEARNING,			/* learning state */
	BLS_FORWARDING			/* forwarding state */
} bridge_state_t;

typedef struct bridge_setstate_s {
	datalink_id_t	bss_linkid;
	bridge_state_t	bss_state;
} bridge_setstate_t;

typedef struct bridge_setpvid_s {
	datalink_id_t	bsv_linkid;
	uint_t		bsv_vlan;
} bridge_setpvid_t;

typedef struct bridge_vlanenab_s {
	datalink_id_t	bve_linkid;
	uint_t		bve_vlan;
	boolean_t	bve_onoff;
} bridge_vlanenab_t;

typedef struct bridge_flushfwd_s {
	datalink_id_t	bff_linkid;
	boolean_t	bff_exclude;
} bridge_flushfwd_t;

typedef struct bridge_listfwd_s {
	char		blf_name[MAXNAMELEN];	/* bridge name */
	ether_addr_t	blf_dest;
	uint16_t	blf_trill_nick;
	uint_t		blf_ms_age;
	boolean_t	blf_is_local;
	datalink_id_t	blf_linkid;
} bridge_listfwd_t;

/* Upward control messages */
typedef struct bridge_ctl_s {
	datalink_id_t	bc_linkid;
	boolean_t	bc_failed;	/* Max SDU mismatch */
} bridge_ctl_t;

/* GLDv3 control ioctls used by Bridging */
#define	BRIDGE_IOC_LISTFWD	BRIDGEIOC(1)

#ifdef __cplusplus
}
#endif

#endif /* _NET_BRIDGE_H */
