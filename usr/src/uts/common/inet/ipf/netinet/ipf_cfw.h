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
 * Copyright 2019 Joyent, Inc.
 */

#ifndef	__IPF_CFW_H__
#define	__IPF_CFW_H__

#include <sys/types.h>
#include <inet/ip6.h>
#include <sys/uuid.h>

/* Because ipf compiles this kernel file in userland testing... */
#ifndef ASSERT3U
#define	ASSERT3U(a, b, c) ASSERT(a ## b ## c);
#endif	/* ASSERT3U */

/*
 * CFW Event, which is emitted to a global-zone listener. The global-zone
 * listener solves the one-fd-per-zone problem of using each zone's ipmon.
 *
 * These must be 64-bit aligned because they form an array in-kernel. There
 * might be reserved fields to ensure that alignment.
 */
#define	CFWEV_BLOCK	1
#define	CFWEV_BEGIN	2
#define	CFWEV_END	3
#define	CFWDIR_IN	1
#define	CFWDIR_OUT	2

typedef struct cfwev_s {
	uint16_t cfwev_type;	/* BEGIN, END, BLOCK */
	uint16_t cfwev_length;	/* in bytes, so capped to 65535 bytes */
	zoneid_t cfwev_zonedid;	/* Pullable from ipf_stack_t. */

	uint32_t cfwev_ruleid;	/* Pullable from fr_info_t. */
	uint16_t cfwev_sport;	/* Source port (network order) */
	uint16_t cfwev_dport;	/* Dest. port (network order) */

	uint8_t cfwev_protocol;	/* IPPROTO_* */
	/* "direction" informs if src/dst are local/remote or remote/local. */
	uint8_t cfwev_direction;
	uint8_t cfwev_reserved[6];	/* Ensures 64-bit alignment. */

	in6_addr_t cfwev_saddr;	/* IPv4 addresses are V4MAPPED. */
	in6_addr_t cfwev_daddr;

	/*
	 * Because of 'struct timeval' being different between 32-bit and
	 * 64-bit ABIs, this interface is only usable by 64-bit binaries.
	 */
	struct timeval cfwev_tstamp;

	uuid_t cfwev_ruleuuid;	/* Pullable from fr_info_t. */
} cfwev_t;



#endif	/* __IPF_CFW_H__ */
