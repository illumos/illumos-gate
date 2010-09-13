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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * mac.h contains MAC layer independent definttions
 */

#ifndef _MAC_H
#define	_MAC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern int 	mac_call_arp(struct in_addr *, void *, uint32_t);
extern void	mac_call_rarp(void);
extern void	mac_init(char *);	/* initialize MAC layer */
extern void	mac_fini(void);		/* tear down MAC layer */
extern uint8_t	*mac_get_addr_buf(void);
extern int	mac_get_addr_len(void);
extern int	mac_get_arp_timeout(void);
extern int	mac_get_hdr_len(void);
extern int	mac_get_mtu(void);
extern int	mac_get_type(void);
extern int	mac_get_arp(struct in_addr *, void *, int, uint32_t);
extern int	mac_get_dev(void);
extern uint8_t	mac_arp_type(uint8_t);
extern void	mac_set_arp_timeout(unsigned int);
extern struct mac_type mac_state;	/* in mac.c */

#ifdef	__cplusplus
}
#endif

#endif /* _MAC_H */
