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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * mac_impl.h contains internal MAC layer independent definttions
 */

#ifndef _MAC_IMPL_H
#define	_MAC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern boolean_t	initialized;	/* TRUE if network device initialized */
extern int	arp_index;	/* current arp table index */

struct mac_type {
	int		mac_type;	/* if_types.h */
	int		mac_dev;
	int		mac_mtu;
	caddr_t		mac_buf;	/* MTU sized buffer */
	uint8_t		*mac_addr_buf;
	uint32_t	mac_arp_timeout;
	uint32_t	mac_in_timeout;
	uint32_t	mac_in_timeo_incr;
	int		mac_addr_len;
	int		(*mac_arp)(struct in_addr *, void *, uint32_t);
	void		(*mac_rarp)(void);
	int		(*mac_header_len)(struct inetgram *);
	int		(*mac_input)(int);
	int		(*mac_output)(int, struct inetgram *);
};

#define	ARP_TABLE_SIZE		(3)	/* size of ARP table */
#define	HW_ADDR_SIZE		(128)	/* max size of hardware address */
#define	MAC_IN_TIMEOUT		(10)	/* collect IP grams for X mseconds. */
#define	MAC_IN_TIMEO_MULT	(8)	/* Multiplier to arrive at maximum */

/* format of an arp table entry */
struct	arptable {
	struct in_addr	ia;
	uchar_t		ha[HW_ADDR_SIZE];
	int		hl;
};

extern void	mac_set_arp(struct in_addr *, void *, int);
extern void	mac_socket_init(struct inetboot_socket *);

#ifdef	__cplusplus
}
#endif

#endif /* _MAC_IMPL_H */
