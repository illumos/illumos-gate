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
#include <net/if.h>

/* ARP kernel hash size; used for mdb support */
#define	ARP_HASH_SIZE	256

/* ARL Structure, one per link level device */
typedef struct arl_s {
	struct arl_s	*arl_next;		/* ARL chain at arl_g_head */
	queue_t		*arl_rq;		/* Read queue pointer */
	queue_t		*arl_wq;		/* Write queue pointer */
	t_uscalar_t	arl_ppa;		/* DL_ATTACH parameter */
	uchar_t		*arl_arp_addr;		/* multicast address to use */
	uchar_t		*arl_hw_addr;		/* Our hardware address */
	uint32_t	arl_hw_addr_length;
	uint32_t	arl_arp_hw_type;	/* Our hardware type */
	t_scalar_t	arl_sap_length;
	char		arl_name[LIFNAMSIZ];	/* Lower level name */
	mblk_t		*arl_xmit_template;	/* DL_UNITDATA_REQ template */
	t_uscalar_t	arl_xmit_template_addr_offset;
	t_uscalar_t	arl_xmit_template_sap_offset;
	mblk_t		*arl_unbind_mp;
	mblk_t		*arl_detach_mp;
	t_uscalar_t	arl_provider_style;	/* From DL_INFO_ACK */
	mblk_t		*arl_queue;		/* Queued commands head */
	mblk_t		*arl_queue_tail;	/* Queued commands tail */
	uint32_t	arl_flags;	/* Used for IFF_NOARP */
	t_uscalar_t	arl_dlpi_pending;	/* pending DLPI request */
	mblk_t		*arl_dlpi_deferred;	/* Deferred DLPI messages */
	uint_t		arl_state;		/* lower interface state */
	char		*arl_data;		/* address data pointer */
	clock_t		arl_defend_start;	/* start of 1-hour period */
	uint_t		arl_defend_count;	/* # of unbidden broadcasts */
	uint_t
			arl_closing : 1,	/* stream is closing */
			arl_notifies : 1,	/* handles DL_NOTE_LINK */
			arl_link_up : 1;	/* DL_NOTE status */
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
	uint32_t
			ar_ip_acked_close : 1,	/* IP has acked the close */
			ar_on_ill_stream : 1;	/* Module below is IP */
} ar_t;

/* ARP Cache Entry */
typedef struct ace_s {
	struct ace_s	*ace_next;	/* Hash chain next pointer */
	struct ace_s	**ace_ptpn;	/* Pointer to previous next */
	struct arl_s	*ace_arl;	/* Associated arl */
	uint32_t	ace_proto;	/* Protocol for this ace */
	uint32_t	ace_flags;
	uchar_t		*ace_proto_addr;
	uint32_t	ace_proto_addr_length;
	uchar_t		*ace_proto_mask; /* Mask for matching addr */
	uchar_t		*ace_proto_extract_mask; /* For mappings */
	uchar_t		*ace_hw_addr;
	uint32_t	ace_hw_addr_length;
	uint32_t	ace_hw_extract_start;	/* For mappings */
	mblk_t		*ace_mp;		/* mblk we are in */
	mblk_t		*ace_query_mp;		/* outstanding query chain */
	clock_t		ace_last_bcast;		/* last broadcast Response */
	clock_t		ace_xmit_interval;
	int		ace_xmit_count;
} ace_t;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _ARP_IMPL_H */
