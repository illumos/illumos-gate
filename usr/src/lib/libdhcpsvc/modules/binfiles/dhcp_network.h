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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _DHCP_NETWORK_H
#define	_DHCP_NETWORK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation-specific data structures and constants for the binary
 * files dhcp_network container.  These structures are subject to change at
 * any time.
 */

#include <sys/types.h>
#include <dhcp_svc_public.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The client id hash size is based on the idea that, given a perfect hash,
 * the hash chain length shouldn't be more than the number of buckets.
 * Given a worst case network with 2^24 addresses, that means we should
 * have 4096 buckets; we shrink this by a bit to make the dn_header_t size
 * be a power of two (32768 bytes).  Note that we assert that a header is
 * this size in open_dn().
 */
#define	DN_CIDHASHSZ	4056
#define	DN_MAGIC	0x0d6c92e4	/* "dhcpnet" in hexadecimal world */
#define	DN_NOIMAGE	0x80		/* image field not in use */
#define	DN_NOREC	0x00000000	/* "no record" id value, must be zero */
#define	DN_TEMPREC	0xffffffff	/* "temp record" id value */
#define	DN_HASHHEAD	0xfffffffe	/* "hash chain head" id value */

typedef uint32_t dn_recid_t;		/* record id type */

/*
 * Macros to compute the record id for a record with address `addr' in a
 * container with netmask `mask', and to convert a record id `recid' to its
 * starting file offset within its container.  Note that we reserve the
 * record id value of 0 for DN_NOREC for reasons explained in open_dn().
 */
#define	RECID(addr, mask)	((dn_recid_t)(((addr) & ~(mask)) + 1))
#define	RECID2OFFSET(recid)						\
	(((recid) == DN_TEMPREC) ? offsetof(dn_header_t, dnh_temp) :	\
	(sizeof (dn_header_t) + ((off_t)sizeof (dn_filerec_t) * ((recid) - 1))))

/*
 * What each dn_rec_t looks like on-disk -- contains the dn_rec_t, pointers
 * to the previous and next dn_rec_t's on its client id hash.  See the big
 * theory statement in dhcp_network.c for a discussion on the redundant
 * dn_recid_t's.
 */
typedef struct dn_filerec {
	dn_recid_t	rec_next[2];	/* id of next record in cidhash */
	dn_recid_t	rec_prev[2];	/* id of prev record in cidhash */
	dn_rec_t	rec_dn;		/* actual dn_rec_t */
} dn_filerec_t;

/*
 * Header atop each dhcp_network container -- contains some basic
 * information about the container and an array of buckets to chain client
 * id hashes from.  See the big theory statement in dhcp_network.c for a
 * discussion on the redundant dn_recid_t's and the concept of "images".
 */
typedef struct dn_header {
	unsigned char	dnh_version;	/* container version */
	unsigned char	dnh_dirty;	/* container might be dirty */
	unsigned char 	dnh_image;	/* container's active image */
	unsigned char	dnh_tempimage; 	/* temporary record's image */
	uint32_t	dnh_magic;	/* container magic */
	ipaddr_t	dnh_network;	/* network number of table */
	ipaddr_t	dnh_netmask;	/* netmask of network number */
	dn_filerec_t	dnh_temp;	/* temporary record used in modify_dn */
	uint32_t	dnh_checks;	/* number of check_dn full runs */
	uint32_t	dnh_errors;	/* number of errors caught */
	uint32_t	dnh_pad[4];	/* for future use */

	/*
	 * Note: read_header() assumes that dnh_cidhash is the last member.
	 */
	dn_recid_t	dnh_cidhash[DN_CIDHASHSZ][2]; /* cid hash buckets */
} dn_header_t;

/*
 * Per-instance state for each handle returned from open_dn.
 */
typedef struct dn_handle {
	int		dh_fd; 		/* fd for open file pointer */
	unsigned int	dh_oflags;	/* flags passed into open_dn */
	ipaddr_t	dh_netmask;	/* cached netmask of container */
} dn_handle_t;

#ifdef __cplusplus
}
#endif

#endif /* _DHCP_NETWORK_H */
