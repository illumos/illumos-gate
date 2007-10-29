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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_VNET_MAILBOX_H
#define	_SYS_VNET_MAILBOX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/vio_mailbox.h>
#include <sys/ethernet.h>

/*
 * VNET specific Control envelopes: 0x0100 - 0x01FF
 *	type == VIO_TYPE_CTRL
 *	subtype == VIO_SUBTYPE_{INFO|ACK|NACK}
 */
#define	VNET_MCAST_INFO		0x0101

/*
 * Vnet/Vswitch device attributes information message.
 *
 * tag.msgtype == VIO_TYPE_CTRL
 * tag.submsgtype = VIO_SUBTYPE_{INFO|ACK|NACK}
 * tag.subtype_env == VIO_ATTR_INFO
 */

/* Value for 'addr_type' in vnet attribute message */
#define	ADDR_TYPE_MAC		0x1

typedef struct vnet_attr_msg {
	/* Common tag */
	vio_msg_tag_t		tag;

	/* attributes specific payload */
	uint8_t			xfer_mode;	/* data transfer mode */
	uint8_t			addr_type;	/* device address type */
	uint16_t		ack_freq;	/* ack after rcving # of pkts */
	uint32_t		resv1;		/* padding */

	uint64_t		addr;		/* device address */
	uint64_t		mtu;		/* maximum data xfer unit */

	/* padding to align things */
	uint64_t		resv2[3];

} vnet_attr_msg_t;

/*
 * Vnet/Vswitch enable/disable multicast address msg
 *
 * tag.msgtype == VIO_TYPE_CTRL
 * tag.subtype == VIO_SUBTYPE_{INFO|ACK|NACK}
 * tag.subtype_env == VNET_MCAST_INFO
 */
#define	VNET_NUM_MCAST	7	/* max # of multicast addresses in the msg */

typedef struct vnet_mcast_msg {
	/* Common tag */
	vio_msg_tag_t		tag;

	/* multicast address information */
	uint8_t			set;	/* add if set to 1, else remove */
	uint8_t			count;	/* number of addrs in the msg */
	struct ether_addr	mca[VNET_NUM_MCAST];	/* mcast addrs */
	uint32_t		resv1;	/* padding */
} vnet_mcast_msg_t;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_VNET_MAILBOX_H */
