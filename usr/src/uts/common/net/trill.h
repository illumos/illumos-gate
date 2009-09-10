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

#ifndef _NET_TRILL_H
#define	_NET_TRILL_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ethernet.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Various well-known Ethernet addresses used by TRILL */
#define	ALL_RBRIDGES		{ 0x01, 0x80, 0xC2, 0x00, 0x02, 0x00 }
#define	ALL_ISIS_RBRIDGES	{ 0x01, 0x80, 0xC2, 0x00, 0x02, 0x01 }
#define	ALL_ESADI_RBRIDGES	{ 0x01, 0x80, 0xC2, 0x00, 0x02, 0x02 }

#define	TRILL_PROTOCOL_VERS 0	/* th_version */
#define	TRILL_DEFAULT_HOPS 21	/* th_hopcount */

/* Nickname range */
#define	RBRIDGE_NICKNAME_MIN		0x0000
#define	RBRIDGE_NICKNAME_MAX		0xFFFF

/* Define well-known nicknames */
#define	RBRIDGE_NICKNAME_NONE		RBRIDGE_NICKNAME_MIN
#define	RBRIDGE_NICKNAME_MINRES		0xFFC0
#define	RBRIDGE_NICKNAME_MAXRES		(RBRIDGE_NICKNAME_MAX - 1)
#define	RBRIDGE_NICKNAME_UNUSED		RBRIDGE_NICKNAME_MAX

#define	MIN_RBRIDGE_RANDOM_NICKNAME	(RBRIDGE_NICKNAME_NONE + 1)
#define	MAX_RBRIDGE_RANDOM_NICKNAME	(RBRIDGE_NICKNAME_MINRES - 1)

/* AF_TRILL IOCTL codes */
#define	TRILL_BASE	(0x54524c00)	/* base (TRL in hex) */
#define	TRILL_SETNICK	(TRILL_BASE + 0)    /* trill_node_t */
#define	TRILL_GETNICK	(TRILL_BASE + 1)    /* uint16_t */
#define	TRILL_ADDNICK	(TRILL_BASE + 2)    /* trill_node_t */
#define	TRILL_DELNICK	(TRILL_BASE + 3)    /* uint16_t */
#define	TRILL_DELALL	(TRILL_BASE + 4)    /* void */
#define	TRILL_HWADDR	(TRILL_BASE + 5)    /* uint8_t[ETHERADDRL] */
#define	TRILL_TREEROOT	(TRILL_BASE + 6)    /* uint16_t */
#define	TRILL_NEWBRIDGE	(TRILL_BASE + 7)    /* char[MAXLINKNAMELEN] */
#define	TRILL_VLANFWDER	(TRILL_BASE + 8)    /* uint8_t[TRILL_VLANS_ARRSIZE] */
#define	TRILL_DESIGVLAN (TRILL_BASE + 9)    /* uint16_t */
#define	TRILL_LISTNICK	(TRILL_BASE + 10)   /* trill_listnick_t */
#define	TRILL_GETBRIDGE	(TRILL_BASE + 11)   /* char[MAXLINKNAMELEN] */
#define	TRILL_PORTFLUSH	(TRILL_BASE + 12)   /* uint16_t */
#define	TRILL_NICKFLUSH	(TRILL_BASE + 13)   /* uint16_t */
#define	TRILL_GETMTU	(TRILL_BASE + 14)   /* uint_t * */

typedef struct trill_header {
#ifdef	_BIT_FIELDS_HTOL
	uint8_t th_version : 2;
	uint8_t th_reserved : 2;
	uint8_t th_multidest : 1;
	uint8_t th_optslen_hi : 3;
#else
	uint8_t th_optslen_hi : 3;
	uint8_t th_multidest : 1;
	uint8_t th_reserved : 2;
	uint8_t th_version : 2;
#endif

#ifdef	_BIT_FIELDS_HTOL
	uint8_t th_optslen_lo : 2;
	uint8_t th_hopcount : 6;
#else
	uint8_t th_hopcount : 6;
	uint8_t th_optslen_lo : 2;
#endif
	uint16_t th_egressnick;
	uint16_t th_ingressnick;
} trill_header_t;

#define	TRILL_HDR_ALIGN		(sizeof (uint16_t))

#define	SET_TRILL_OPTS_LEN(hdr_p, val) \
	do { \
		(hdr_p)->th_optslen_lo = (val)&0x03;	\
		(hdr_p)->th_optslen_hi = (val)>>2;	\
		_NOTE(CONSTANTCONDITION)		\
	} while (0)

#define	GET_TRILL_OPTS_LEN(hdr_p) \
	((hdr_p)->th_optslen_lo|((hdr_p)->th_optslen_hi<<2))

/* RBridge nick and tree information (*variable* size) */
typedef struct trill_nickinfo_s {
	/* Nickname of the RBridge */
	uint16_t	tni_nick;
	/* Next-hop SNPA address to reach this RBridge */
	ether_addr_t	tni_adjsnpa;
	/* Link on our system to use to reach next-hop */
	datalink_id_t	tni_linkid;
	/* Num of *our* adjacencies on a tree rooted at this RBridge */
	uint16_t	tni_adjcount;
	/* Num of distribution tree root nicks chosen by this RBridge */
	uint16_t	tni_dtrootcount;
	/*
	 * Variable size bytes to store adjacency nicks, distribution
	 * tree roots and VLAN filter lists. Adjacency nicks and
	 * distribution tree roots are 16-bit fields.
	 *
	 * Number of VLAN filter lists is equal to tni_adjcount as
	 * the VLAN filter list is one per adjacency in each DT.
	 * VLAN filter list is a 512 byte bitmap with the set of VLANs
	 * that are reachable downstream via the adjacency.
	 */
} trill_nickinfo_t;

typedef struct trill_listnick_s {
	uint16_t	tln_nick;
	ether_addr_t	tln_nexthop;
	datalink_id_t	tln_linkid;
	boolean_t	tln_ours;
} trill_listnick_t;

/* Access the adjacency nick list at the end of trill_nickinfo_t */
#define	TNI_ADJNICKSPTR(v) ((uint16_t *)((trill_nickinfo_t *)(v)+1))
#define	TNI_ADJNICK(v, n) (TNI_ADJNICKSPTR(v)[(n)])

/* Access the DT root nick list in trill_nickinfo_t after adjacency nicks */
#define	TNI_DTROOTNICKSPTR(v) (TNI_ADJNICKSPTR(v)+(v)->tni_adjcount)
#define	TNI_DTROOTNICK(v, n) (TNI_DTROOTNICKSPTR(v)[(n)])

/* Access the VLAN filter list in trill_nickinfo_t after DT Roots */
#define	TNI_VLANFILTERSPTR(v) (TNI_DTROOTNICKSPTR(v)+(v)->tni_dtrootcount)
#define	TNI_VLANFILTERMAP(v, n) \
	(((uint8_t *)(TNI_VLANFILTERSPTR(v)))+((n)*((1<<12)/NBBY)))

#define	TNI_TOTALSIZE(v) (sizeof (trill_nickinfo_t) + \
	(sizeof (uint16_t) * (v)->tni_adjcount) + \
	(sizeof (uint16_t) * (v)->tni_dtrootcount) + \
	(((1<<12)/NBBY) * (v)->tni_adjcount))

/*
 * This is a special value used in the sockaddr_dl "selector" field to denote
 * that the packet represents a Bridging PDU.  The core STP instance is not
 * defined on a VLAN, so this overload is safe.  All other selector values are
 * used for TRILL IS-IS PDUs to indicate VLAN ID.
 */
#define	TRILL_TCI_BPDU	0xFFFF

#ifdef __cplusplus
}
#endif

#endif /* _NET_TRILL_H */
