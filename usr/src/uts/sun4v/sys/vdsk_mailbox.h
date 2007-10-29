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

#ifndef	_VDSK_MAILBOX_H
#define	_VDSK_MAILBOX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header file contains the private LDoms Virtual Disk (vDisk) mailbox
 * definitions common to both the server (vds) and the client (vdc)
 */

#include <sys/vio_mailbox.h>
#include <sys/vio_common.h>
#include <sys/vdsk_common.h>

/*
 * Definition of the various states the vDisk state machine can
 * be in during the handshake between vdc and vds.
 */
typedef enum vd_state {
	VD_STATE_INIT = 0,
	VD_STATE_VER,
	VD_STATE_ATTR,
	VD_STATE_DRING,
	VD_STATE_RDX,
	VD_STATE_DATA
} vd_state_t;

#define	VD_VER_MAJOR		0x1
#define	VD_VER_MINOR		0x0

/*
 * Definition of the various types of media that can be exported by
 * the vDisk server. If we cannot work out what the media type is
 * we default to calling it VD_MEDIA_FIXED.
 */
typedef enum vd_media {
	VD_MEDIA_FIXED = 1,		/* default */
	VD_MEDIA_CD,
	VD_MEDIA_DVD
} vd_media_t;

/*
 * vDisk device attributes information message.
 *
 * tag.msgtype == VIO_TYPE_CTRL
 * tag.submsgtype = VIO_SUBTYPE_{INFO|ACK|NACK}
 * tag.subtype_env == VIO_ATTR_INFO
 */
typedef struct vd_attr_msg {
	/* Common tag */
	vio_msg_tag_t 	tag;

	/* vdisk-attribute-specific payload */
	uint8_t		xfer_mode;	/* data exchange method. */
	uint8_t		vdisk_type;	/* disk, slice, read-only, etc. */
	uint8_t		vdisk_media;	/* info about physical media */
	uint8_t		resv1;		/* padding */
	uint32_t	vdisk_block_size;	/* bytes per disk block */
	uint64_t	operations;	/* bit-field of server supported ops */
	uint64_t	vdisk_size;	/* size for Nblocks property. */
	uint64_t	max_xfer_sz;	/* maximum block transfer size */

	uint64_t	resv2[VIO_PAYLOAD_ELEMS - 4];	/* padding */
} vd_attr_msg_t;

/*
 * vDisk inband descriptor message.
 *
 * For clients that do not use descriptor rings, the descriptor contents
 * are sent as part of an inband message.
 */
typedef struct vd_dring_inband_msg {
	vio_inband_desc_msg_hdr_t	hdr;
	vd_dring_payload_t		payload;
} vd_dring_inband_msg_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _VDSK_MAILBOX_H */
