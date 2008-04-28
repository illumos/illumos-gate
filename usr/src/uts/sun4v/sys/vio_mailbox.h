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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_VIO_MAILBOX_H
#define	_SYS_VIO_MAILBOX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ldc.h>

/* Message types */
#define		VIO_TYPE_CTRL	0x1
#define		VIO_TYPE_DATA	0x2
#define		VIO_TYPE_ERR	0x4

/* Message sub-types */
#define		VIO_SUBTYPE_INFO	0x1
#define		VIO_SUBTYPE_ACK		0x2
#define		VIO_SUBTYPE_NACK	0x4

/*
 * VIO specific control envelopes:  0x0000 - 0x00FF
 * VNET specific control envelopes: 0x0100 - 0x01FF
 * VDSK specific control envelopes: 0x0200 - 0x02FF
 * UNUSED envelopes:                0x0300 - 0x0FFF
 */

/*
 * Generic Control Subtype Envelopes:
 * 	type == VIO_TYPE_CTRL
 *	subtype == VIO_SUBTYPE_{INFO|ACK|NACK}
 *
 * 	0x0000 - 0x003F
 */
#define	VIO_VER_INFO		0x0001
#define	VIO_ATTR_INFO		0x0002
#define	VIO_DRING_REG		0x0003
#define	VIO_DRING_UNREG		0x0004
#define	VIO_RDX			0x0005
#define	VIO_DDS_INFO		0x0006

/*
 * Generic subtype Data envelopes
 * 	type == VIO_TYPE_DATA
 * 	subtype == VIO_SUBTYPE_{INFO|ACK|NACK}
 *
 * 	0x0040 - 0x007F
 */
#define	VIO_PKT_DATA		0x0040
#define	VIO_DESC_DATA		0x0041
#define	VIO_DRING_DATA		0x0042


/*
 * Generic subtype Error envelopes
 * 	type == VIO_TYPE_ERR
 * 	subtype == VIO_SUBTYPE_{INFO|ACK|NACK}
 *
 * 	0x0080 - 0x00FF
 *
 * Currently unused
 */

/*
 * Supported Device Types
 */
#define	VDEV_NETWORK		0x1
#define	VDEV_NETWORK_SWITCH	0x2
#define	VDEV_DISK		0x3
#define	VDEV_DISK_SERVER	0x4

/*
 * VIO data transfer mode
 */
#define	VIO_PKT_MODE	0x1
#define	VIO_DESC_MODE	0x2
#define	VIO_DRING_MODE_V1_0	0x3
#define	VIO_DRING_MODE_V1_2	0x4

/*
 * VIO Descriptor Ring registration options
 * (intended use for Descriptor Ring)
 */
#define	VIO_TX_DRING	0x1
#define	VIO_RX_DRING	0x2

/*
 * Size of message payload
 */
#define	VIO_MSGTAG_SZ		(sizeof (vio_msg_tag_t))	/* bytes */
#define	VIO_PAYLOAD_SZ		(LDC_PAYLOAD_SIZE_UNRELIABLE - VIO_MSGTAG_SZ)
#define	VIO_PAYLOAD_ELEMS	(VIO_PAYLOAD_SZ / LDC_ELEM_SIZE) /* num words */

/*
 * Peer dring processing state. Either actively processing dring
 * or stopped.
 */
#define	VIO_DP_ACTIVE		1
#define	VIO_DP_STOPPED		2

/*
 * VIO device message tag.
 *
 * These 64 bits are used as a common header for all VIO message types.
 */
typedef union vio_msg_tag {
	struct {
		uint8_t		_msgtype;
		uint8_t		_subtype;
		uint16_t	_subtype_env;
		uint32_t	_sid;		/* session id */
	} _hdr;
	uint64_t	tagword;
} vio_msg_tag_t;

#define	vio_msgtype		_hdr._msgtype
#define	vio_subtype		_hdr._subtype
#define	vio_subtype_env		_hdr._subtype_env
#define	vio_sid			_hdr._sid

/*
 * VIO version negotation message.
 *
 * tag.msgtype == VIO_TYPE_CTRL
 * tag.submsgtype = VIO_SUBTYPE_{INFO|ACK|NACK}
 * tag.subtype_env == VIO_VER_INFO
 */

/* Structure to store a version tuple */
typedef struct vio_ver {
	uint16_t		major;		/* major version number */
	uint16_t		minor;		/* minor version number */
} vio_ver_t;

typedef struct vio_ver_msg {
	/* Common tag */
	vio_msg_tag_t		tag;

	/* version specific payload */
	uint16_t		ver_major;	/* major version number */
	uint16_t		ver_minor;	/* minor version number */

	uint8_t			dev_class;	/* type of device */

	/* padding */
	uint8_t			resv1;
	uint16_t		resv2;
	uint64_t		resv3[VIO_PAYLOAD_ELEMS - 1];
} vio_ver_msg_t;

/*
 * VIO Descriptor Ring Register message.
 *
 * tag.msgtype == VIO_TYPE_CTRL
 * tag.submsgtype = VIO_SUBTYPE_{INFO|ACK|NACK}
 * tag.subtype_env == VIO_DRING_REG
 */
typedef struct vio_dring_reg_msg {
	/* Common tag */
	vio_msg_tag_t		tag;

	/* Descriptor ring information */
	uint64_t		dring_ident;	/* =0 for SUBTYPE_INFO msg */
	uint32_t		num_descriptors; /* # of desc in the ring */
	uint32_t		descriptor_size; /* size of each entry */
	uint16_t		options;	/* intended use */
	uint16_t		resv;		/* padding */
	uint32_t		ncookies;	/* # cookies exporting ring */

	/*
	 * cookie is a variable sized array.  If the number of cookies is 1,
	 * the message can be sent by LDC without fragmentation.
	 */
	ldc_mem_cookie_t	cookie[1];
} vio_dring_reg_msg_t;

/*
 * VIO Descriptor Ring Unregister message.
 *
 * tag.msgtype == VIO_TYPE_CTRL
 * tag.submsgtype = VIO_SUBTYPE_{INFO|ACK|NACK}
 * tag.subtype_env == VIO_DRING_UNREG
 */
typedef struct vio_dring_unreg_msg {
	/* Common tag */
	vio_msg_tag_t	tag;

	/* Descriptor ring information */
	uint64_t	dring_ident;
	uint64_t	resv[VIO_PAYLOAD_ELEMS - 1];
} vio_dring_unreg_msg_t;


/*
 * Definition of a generic VIO message (with no payload) which can be cast
 * to other message types.
 */
typedef struct vio_msg {
	/* Common tag */
	vio_msg_tag_t		tag;

	/* no payload */
	uint64_t		resv[VIO_PAYLOAD_ELEMS];
} vio_msg_t;

/*
 * VIO Ready to Receive message.
 *
 * tag.msgtype == VIO_TYPE_CTRL
 * tag.submsgtype = VIO_SUBTYPE_{INFO|ACK}
 * tag.subtype_env == VIO_RDX
 */
typedef vio_msg_t	vio_rdx_msg_t;

/*
 * VIO error message.
 *
 * tag.msgtype == VIO_TYPE_ERR
 * tag.subtype == VIO_SUBTYPE_{INFO|ACK|NACK}
 * tag.subtype_env == TBD
 */
typedef vio_msg_t	vio_err_msg_t;

/*
 * VIO descriptor ring data message.
 *
 * tag.msgtype == VIO_TYPE_DATA
 * tag.subtype == VIO_SUBTYPE_{INFO|ACK|NACK}
 * tag.subtype_env == VIO_DRING_DATA
 */
typedef struct vio_dring_msg {
	/* Common message tag */
	vio_msg_tag_t		tag;

	/* Data dring info */
	uint64_t		seq_num;
	uint64_t		dring_ident;	/* ident of modified DRing */
	uint32_t		start_idx;	/* Indx of first updated elem */
	int32_t			end_idx;	/* Indx of last updated elem */

	uint8_t			dring_process_state;	/* Processing state */

	/*
	 * Padding.
	 */
	uint8_t			resv1;
	uint16_t		resv2;
	uint32_t		resv3;
	uint64_t		resv4[VIO_PAYLOAD_ELEMS - 4];
} vio_dring_msg_t;

/*
 * VIO Common header for inband descriptor messages.
 *
 * Clients will then combine this header with a device specific payload.
 */
typedef struct vio_inband_desc_msg_hdr {
	/* Common message tag */
	vio_msg_tag_t		tag;

	uint64_t		seq_num;	/* sequence number */
	uint64_t		desc_handle;	/* opaque descriptor handle */
} vio_inband_desc_msg_hdr_t;

/*
 * VIO raw data message.
 *
 * tag.msgtype == VIO_TYPE_DATA
 * tag.subtype == VIO_SUBTYPE_{INFO|ACK|NACK}
 * tag.subtype_env == VIO_PKT_DATA
 *
 * Note the data payload is so small to keep this message
 * within the size LDC can cope with without fragmentation.
 * If it turns out in the future that we are not concerned
 * with fragmentation then we can increase the size of this
 * field.
 */
typedef struct vio_raw_data_msg {
	/* Common message tag */
	vio_msg_tag_t		tag;

	/* Raw data packet payload */
	uint64_t		seq_num;	/* sequence number */
	uint64_t		data[VIO_PAYLOAD_ELEMS - 1];
} vio_raw_data_msg_t;

#define	VIO_PKT_DATA_HDRSIZE	\
	(sizeof (vio_msg_tag_t) + sizeof (uint64_t))

/*
 * Definitions of the valid states a Descriptor can be in.
 */
#define	VIO_DESC_FREE		0x1
#define	VIO_DESC_READY		0x2
#define	VIO_DESC_ACCEPTED	0x3
#define	VIO_DESC_DONE		0x4
#define	VIO_DESC_MASK		0xf

/* Macro to populate the generic fields of the DRing data msg */
#define	VIO_INIT_DRING_DATA_TAG(dmsg)	\
		dmsg.tag.vio_msgtype = VIO_TYPE_DATA;	\
		dmsg.tag.vio_subtype = VIO_SUBTYPE_INFO;	\
		dmsg.tag.vio_subtype_env = VIO_DRING_DATA;


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_VIO_MAILBOX_H */
