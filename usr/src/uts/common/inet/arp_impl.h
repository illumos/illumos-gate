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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ARP_IMPL_H
#define	_ARP_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/stream.h>

/* ARL Structure, one per link level device */
typedef struct arl_s {
	struct arl_s	*arl_next;		/* ARL chain at arl_g_head */
	queue_t		*arl_rq;		/* Read queue pointer */
	queue_t		*arl_wq;		/* Write queue pointer */
	t_uscalar_t	arl_ppa;		/* DL_ATTACH parameter */
	t_scalar_t	arl_mac_sap;
	uchar_t		*arl_arp_addr;		/* multicast address to use */
	uchar_t		*arl_hw_addr;		/* Our hardware address */
	uint32_t	arl_hw_addr_length;
	uint32_t	arl_arp_hw_type;	/* Our hardware type */
	t_scalar_t	arl_sap_length;
	uchar_t		arl_name[LIFNAMSIZ];	/* Lower level name */
	uint32_t	arl_name_length;
	mblk_t		*arl_xmit_template;	/* DL_UNITDATA_REQ template */
	t_uscalar_t	arl_xmit_template_addr_offset;
	t_uscalar_t	arl_xmit_template_sap_offset;
	mblk_t		*arl_unbind_mp;
	mblk_t		*arl_detach_mp;
	t_uscalar_t	arl_provider_style;	/* From DL_INFO_ACK */
	mblk_t		*arl_dlpiop_done;	/* DLPI opertion done */
	queue_t		*arl_ip_pending_queue;	/* Pending queue */
	mblk_t		*arl_queue;		/* Queued commands head */
	mblk_t		*arl_queue_tail;	/* Queued commands tail */
	uint32_t	arl_flags;	/* Used for IFF_NOARP */
	t_uscalar_t	arl_dlpi_pending;	/* pending DLPI request */
	mblk_t		*arl_dlpi_deferred;	/* Deferred DLPI messages */
	uint_t		arl_state;		/* lower interface state */
	char		*arl_data;		/* address data pointer */
	uint32_t	arl_closing : 1;
} arl_t;

#define	ARL_F_NOARP	0x01

#define	ARL_S_DOWN	0x00
#define	ARL_S_PENDING	0x01
#define	ARL_S_UP	0x02

/* AR Structure, one per upper stream */
typedef struct ar_s {
	queue_t		*ar_rq;	/* Read queue pointer */
	queue_t		*ar_wq;	/* Write queue pointer */
	arl_t		*ar_arl;	/* Associated arl */
	cred_t		*ar_credp;	/* Credentials associated w/ open */
	struct ar_s	*ar_arl_ip_assoc;	/* ARL - IP association */
	uint32_t	ar_ip_acked_close : 1;	/* IP has acked the close */
} ar_t;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _ARP_IMPL_H */
