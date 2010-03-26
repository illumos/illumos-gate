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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_VNET_MAILBOX_H
#define	_SYS_VNET_MAILBOX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/vio_mailbox.h>
#include <sys/dds.h>
#include <sys/ethernet.h>

/*
 * VNET specific Control envelopes: 0x0100 - 0x01FF
 *	type == VIO_TYPE_CTRL
 *	subtype == VIO_SUBTYPE_{INFO|ACK|NACK}
 */
#define	VNET_MCAST_INFO		0x0101
#define	VNET_DDS_INFO		0x0102
#define	VNET_PHYSLINK_INFO	0x0103	/* Physical Link Information */

/*
 * Vnet/Vswitch device attributes information message.
 *
 * tag.msgtype == VIO_TYPE_CTRL
 * tag.submsgtype = VIO_SUBTYPE_{INFO|ACK|NACK}
 * tag.subtype_env == VIO_ATTR_INFO
 */

/* Value for 'addr_type' in vnet attribute message */
#define	ADDR_TYPE_MAC		0x1

/*
 * Physical link property updates to be negotiated as part of attribute message
 * exchange, in protocol versions >= 1.5. This is only valid between a vnet
 * client and the corresponding vswitch service; and not between peer vnets. A
 * vnet device could negotiate with vswitch to obtain updates about certain
 * physical link properties. Only 'physical link status' updates are supported
 * for now. A vnet device that desires to get physical link status updates,
 * sets the appropriate bit(s) in its ATTR/INFO message to the vswitch; the
 * vswitch sets the relevant ack/nack bits in its response message. Whenever
 * there is a change in the physical link props for which the vnet device has
 * negotiated, vswitch updates it by sending a message with updated values
 * of the relevant physical link properties (see vnet_physlink_msg_t below).
 */
enum {
	PHYSLINK_UPDATE_NONE = 0,
	PHYSLINK_UPDATE_STATE = 0x1,
	PHYSLINK_UPDATE_STATE_ACK = 0x2,
	PHYSLINK_UPDATE_STATE_NACK = 0x3
};

#define	PHYSLINK_UPDATE_STATE_MASK	0x3

typedef struct vnet_attr_msg {
	/* Common tag */
	vio_msg_tag_t		tag;

	/* attributes specific payload */
	uint8_t			xfer_mode;	/* data transfer mode */
	uint8_t			addr_type;	/* device address type */
	uint16_t		ack_freq;	/* ack after rcving # of pkts */
	uint8_t			physlink_update; /* physlink updates(s)? */
	uint8_t			options;	/* options - dring mode */
	uint16_t		resv2;		/* reserved */

	uint64_t		addr;		/* device address */
	uint64_t		mtu;		/* maximum data xfer unit */

	/* padding to align things */
	uint64_t		resv3[3];

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

/*
 * Values of the various physical link properties. We
 * support only 'link state' property updates for now.
 */
enum {
	VNET_PHYSLINK_STATE_DOWN = 0x1,
	VNET_PHYSLINK_STATE_UP = 0x2,
	VNET_PHYSLINK_STATE_UNKNOWN = 0x3
};

#define	VNET_PHYSLINK_STATE_MASK	0x3

/*
 * Vnet/Vswitch physical link info message.
 * We only support link state information for now.
 *
 * tag.msgtype == VIO_TYPE_CTRL
 * tag.subtype == VIO_SUBTYPE_{INFO|ACK|NACK}
 * tag.subtype_env == VNET_PHYSLINK_INFO
 */
typedef struct vnet_physlink_msg {
	/* Common tag */
	vio_msg_tag_t		tag;

	/* physical link information */
	uint32_t		physlink_info;

	/* padding to align things */
	uint32_t		resv1;
	uint64_t		resv2[5];
} vnet_physlink_msg_t;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_VNET_MAILBOX_H */
