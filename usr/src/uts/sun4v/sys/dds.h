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

#ifndef _DDS_H
#define	_DDS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DDS class values
 *	DDS_GENERIC_XXX		0x0 - 0xf
 *	DDS_VNET_XXX		0x10 - 0x1f
 *	DDS_VDSK_XXX		0x20 - 0x2f
 *	reserved		0x30 - 0xff
 */

#define	DDS_VNET_NIU	0x10	/* NIU vNet class */


/*
 * Subclasses for DDS_VNET_NIU class
 */
#define	DDS_VNET_ADD_SHARE	0x01	/* Add a share */
#define	DDS_VNET_DEL_SHARE	0x02	/* Delete a share */
#define	DDS_VNET_REL_SHARE	0x03	/* Release a share */
#define	DDS_VNET_MOD_SHARE	0x04	/* Modify a share */

/*
 * The following structure is used for the following class/subclass messages.
 *	DDS_VNET_NIU/DDS_VNET_ADD_SHARE
 *	DDS_VNET_NIU/DDS_VNET_DEL_SHARE
 *	DDS_VNET_NIU/DDS_VNET_REL_SHARE
 */
typedef struct dds_share_msg {
	/*
	 * MAC-address to which this resource belongs to.
	 * It is stored in the following fashion:
	 *	Bytes:	7   6   5    4    3    2    1    0
	 *		X   X   M0   M1   M2   M3   M4   M5
	 */
	uint64_t	macaddr;

	/*
	 * A 64 bit cookie. It consists two pars:
	 *	Low 32bits == HV cookie
	 *	High 32bits == config_hdl of NIU
	 */
	uint64_t	cookie;
} dds_share_msg_t;

/*
 * The following structure is used as a response for all DDS_VNET_NIU
 * messages.
 */
typedef struct dds_share_resp_msg {
	/*
	 * When the response is NACK, resp_val can be used optionally
	 * to provide additional information regarding failure.
	 */
	uint64_t	status;
} dds_share_resp_msg_t;

/*
 * status values
 */
#define	DDS_VNET_SUCCESS	0x0	/* Operation success */
#define	DDS_VNET_FAIL		0x1	/* Operation failed */

/*
 * The following structure is used for the following class/subclass messages.
 *	DDS_VNET_NIU/DDS_VNET_MODIFY_SHARE
 */
typedef struct dds_share_modify_msg {
	uint64_t	macaddr;
	uint64_t	cookie;

	/*
	 * rx_res_map -- Intended modification to RX resources
	 *		 indicated as a map.
	 * tx_res_map -- Intended modification to TX resources
	 *		 indicated as a map.
	 */
	uint64_t	rx_res_map;
	uint64_t	tx_res_map;
} dds_share_modify_msg_t;

/*
 * VIO DDS Info message.
 *
 * tag.msgtype == VIO_TYPE_CTRL
 * tag.submsgtype = VIO_SUBTYPE_{INFO|ACK|NACK}
 * tag.subtype_env == VIO_DDS_INFO
 */
typedef struct vio_dds_msg {
	/* Common tag */
	vio_msg_tag_t		tag;
	uint8_t			dds_class;
	uint8_t			dds_subclass;
	uint16_t		resv;
	uint32_t		dds_req_id;
	union {
		struct dds_share_msg		share_msg;
		struct dds_share_resp_msg	share_resp_msg;
		struct dds_share_modify_msg	share_mod_msg;
		uint64_t			pad2[5];
	} msg;
} vio_dds_msg_t;


#ifdef __cplusplus
}
#endif

#endif	/* _DDS_H */
