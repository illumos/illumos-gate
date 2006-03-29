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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SGFRU_MBOX_H
#define	_SGFRU_MBOX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sgfru_priv.h>
#include <sys/conf.h>
#include <sys/ddi_impldefs.h>

/*
 * Max time sgfru waits for mailbox to respond before
 * it decides to timeout. (measured in seconds)
 */
#define	SGFRU_DEFAULT_MAX_MBOX_WAIT_TIME	86400

/*
 *  FRU Mailbox Definitions
 *
 *	Request (from Solaris to SC):
 *		msg_len = CONTAINER_HDL_SIZE
 *  		msg_buf = pointer to unpadded container_hdl_t
 *  	Response (from SC to Solaris):
 *		msg_len = FRU_CNT_SIZE
 *  		msg_buf = pointer to unpadded fru_cnt_t
 *  		msg_status = return value, see below.
 *  Error Notes:
 */
#define	SGFRU_MBOX_GETNUMSECTIONS		0x7001
/*
 *	Request (from Solaris to SC):
 *		msg_len = FRU_INFO_SIZE
 *  		msg_buf = pointer to unpadded fru_info_t containing:
 *		    parent container_hdl_t and max fru_cnt_t (in #sections)
 *  	Response (from SC to Solaris):
 *		msg_len = FRU_INFO_SIZE + (SECTION_SIZE * max fru_cnt_t)
 *              msg_buf = caddr_t of msg_len, contains:
 *		    unpadded container_hdl_t and actual fru_cnt_t
 *		    unpadded section_t array
 *  		msg_status = return value, see below.
 *  Error Notes:
 *  Please return SG_MBOX_STATUS_NO_MEMORY if the buffer is not big enough.
 */
#define	SGFRU_MBOX_GETSECTIONS			0x7002
/*
 *	Request (from Solaris to SC):
 *		msg_len = SECTION_HDL_SIZE
 *  		msg_buf = pointer to unpadded section_hdl_t
 *  	Response (from SC to Solaris):
 *		msg_len = FRU_CNT_SIZE
 *  		msg_buf = pointer to unpadded fru_cnt_t
 *  		msg_status = return value, see below.
 *  Error Notes:
 */
#define	SGFRU_MBOX_GETNUMSEGMENTS		0x7003
/*
 * FRU  Mailbox definitions
 *
 *	Request (from Solaris to SC):
 *		msg_len = FRU_INFO_SIZE
 *  		msg_buf = pointer to unpadded fru_info_t containing:
 *		    parent section_hdl_t and max fru_cnt_t (in #segments)
 *  	Response (from SC to Solaris):
 *		msg_len = FRU_INFO_SIZE + (SEGMENT_SIZE * max fru_cnt_t)
 *              msg_buf = caddr_t of msg_len, contains:
 *		    unpadded parent section_hdl_t and actual fru_cnt_t
 *		    unpadded segment_t array
 *  		msg_status = return value, see below.
 *  Error Notes:
 *  Please return SG_MBOX_STATUS_NO_MEMORY if the buffer is not big enough.
 */
#define	SGFRU_MBOX_GETSEGMENTS			0x7004
/*
 *	Request (from Solaris to SC):
 *		msg_len = SECTION_HDL_SIZE + SEGMENT_SIZE
 *  		msg_buf = caddr_t of msg_len, contains:
 *		    unpadded parent section_hdl_t
 *		    unpadded segment_t
 *  	Response (from SC to Solaris):
 *  		msg_len = SEGMENT_HDL_SIZE
 *              msg_buf = pointer to:
 *		    segment_hdl_t of newly created segment
 *		    updated parent section_hdl_t
 *  		msg_status = return value, see below.
 *  Error Notes:
 *  Please return SG_MBOX_STATUS_STALE_OBJECT if the section_hdl_t is stale.
 *  Please return SG_MBOX_STATUS_NO_SEPROM_SPACE if the seprom is out of space
 */
#define	SGFRU_MBOX_ADDSEGMENT			0x7005
/*
 *	Request (from Solaris to SC):
 *		msg_len = SEGMENT_HDL_SIZE
 *  		msg_buf = pointer to segment_hdl_t of segment to be deleted
 *  	Response (from SC to Solaris):
 *		msg_len = SECTION_HDL_SIZE
 *  		msg_buf = pointer to updated section_hdl_t of deleted segment
 *  		msg_status = return value, see below
 *  Error Notes:
 */
#define	SGFRU_MBOX_DELETESEGMENT		0x7006
/*
 *	Request (from Solaris to SC):
 *		msg_len = FRU_INFO_SIZE
 *  		msg_buf = caddr_t of msg_len, contains:
 *		    unpadded fru_info_t: segment_hdl_t and max count in bytes
 *  	Response (from SC to Solaris):
 *		msg_len = FRU_INFO_SIZE
 *              msg_buf = caddr_t of msg_len, contains:
 *		    unpadded fru_info_t: segment_hdl_t and actual count in bytes
 *		    unpadded data of actual fru_cnt_t bytes
 *  		msg_status = return value, see below.
 *  Error Notes:
 *  Please return SG_MBOX_STATUS_NO_MEMORY if the buffer is not big enough.
 */
#define	SGFRU_MBOX_READRAWSEGMENT		0x7007
/*
 *	Request (from Solaris to SC):
 *		msg_len = FRU_INFO_SIZE + fru_cnt_t bytes
 *  		msg_buf = caddr_t of msg_len, contains:
 *		    unpadded fru_info_t: segment_hdl_t and count in bytes
 *		    unpadded data of fru_cnt_t bytes
 *  	Response (from SC to Solaris):
 *		msg_len = FRU_INFO_SIZE
 *              msg_buf = caddr_t of msg_len, contains:
 *		    unpadded fru_info_t: segment_hdl_t and count in bytes
 *  		msg_status = return value, see below.
 *  Error Notes:
 *  Please return SG_MBOX_STATUS_ILLEGAL_PARAMETER if it's
 *  	not an opaque segment.
 */
#define	SGFRU_MBOX_WRITERAWSEGMENT		0x7008
/*
 *	Request (from Solaris to SC):
 *		msg_len = SEGMENT_HDL_SIZE
 *  		msg_buf = pointer to unpadded segment_hdl_t
 *  	Response (from SC to Solaris):
 *		msg_len = FRU_CNT_SIZE
 *  		msg_buf = pointer to unpadded fru_cnt_t
 *  		msg_status = return value, see below.
 *  Error Notes:
 */
#define	SGFRU_MBOX_GETNUMPACKETS		0x7009
/*
 *	Request (from Solaris to SC):
 *		msg_len = FRU_INFO_SIZE
 *  		msg_buf = pointer to unpadded fru_info_t, containing:
 *		    unpadded segment_hdl_t plus max fru_cnt_t in bytes
 *  	Response (from SC to Solaris):
 *		msg_len = FRU_INFO_SIZE + (PACKET_SIZE * max fru_cnt_t)
 *              msg_buf = caddr_t of msg_len, contains:
 *		    unpadded parent segment_hdl_t and actual fru_cnt_t
 *		    unpadded packet_t array
 *  		msg_status = return value, see below.
 *  Error Notes:
 *  Please return SG_MBOX_STATUS_NO_MEMORY if the buffer is not big enough.
 */
#define	SGFRU_MBOX_GETPACKETS			0x700a
/*
 *	Request (from Solaris to SC):
 *		msg_len = FRU_INFO_SIZE + PACKET_SIZE + fru_cnt_t size
 *  		msg_buf = caddr_t of msg_len, contains:
 *		    unpadded fru_info_t with parent segment_hdl_t and fru_cnt_t
 *		    unpadded packet_t
 *		    unpadded data of size fru_cnt_t (in bytes)
 *  	Response (from SC to Solaris):
 *  		msg_len = SEGMENT_HDL_SIZE + PACKET_HDL_SIZE
 *              msg_buf = pointer to:
 *		    packet_hdl_t of newly created packet
 *		    updated parent segment_hdl_t
 *  		msg_status = return value, see below.
 *  Error Notes:
 *  Please return SG_MBOX_STATUS_NO_SEPROM_SPACE if the seprom is out of space
 */
#define	SGFRU_MBOX_APPENDPACKET			0x700b
/*
 *	Request (from Solaris to SC):
 *		msg_len = PACKET_HDL_SIZE
 *  		msg_buf = pointer to packet_hdl_t of packet to be deleted
 *  	Response (from SC to Solaris):
 *		msg_len = SEGMENT_HDL_SIZE
 *  		msg_buf = pointer to updated segment_hdl_t of deleted packet
 *  		msg_status = return value, see below
 *  Error Notes:
 */
#define	SGFRU_MBOX_DELETEPACKET			0x700c
/*
 *	Request (from Solaris to SC):
 *		msg_len = FRU_INFO_SIZE
 *              msg_buf = caddr_t of msg_len, contains:
 *		    unpadded fru_info_t with packet_hdl_t and max fru_cnt_t
 *  	Response (from SC to Solaris):
 *		msg_len = FRU_INFO_SIZE + max fru_cnt_t
 *              msg_buf = caddr_t of msg_len, contains:
 *		    unpadded fru_info_t with packet_hdl_t and actual fru_cnt_t
 *		    unpadded data of size fru_cnt_t (in bytes)
 *  		msg_status = return value, see below.
 *  Error Notes:
 *  Please return SG_MBOX_STATUS_NO_MEMORY if the buffer is not big enough.
 */
#define	SGFRU_MBOX_GETPAYLOAD			0x700d
/*
 *	Request (from Solaris to SC):
 *		msg_len = FRU_INFO_SIZE + fru_cnt_t size
 *              msg_buf = caddr_t of msg_len, contains:
 *		    unpadded fru_info_t with packet_hdl_t and actual count
 *		    unpadded payload data buf of fru_cnt_t size (in bytes)
 *  	Response (from SC to Solaris):
 *		msg_len = FRU_INFO_SIZE
 *  		msg_buf = caddr_t of msg_len, contains:
 *		    unpadded fru_hdl_t with updated handle
 *		    unpadded data of size fru_cnt_t (in bytes)
 *  		msg_status = return value, see below.
 *  Error Notes:
 *  Please return SG_MBOX_STATUS_NO_SEPROM_SPACE if the seprom is out of space
 */
#define	SGFRU_MBOX_UPDATEPAYLOAD		0x700e
/*
 *  FRU Mailbox Definitions
 *
 *      Request (from Solaris to SC):
 *              msg_len = FRU_INFO_SIZE
 *              msg_buf = pointer to unpadded fru_info_t containing:
 *                  parent fru_hdl_t and max fru_cnt_t (in node_t's)
 *      Response (from SC to Solaris):
 *              msg_len = NODE_SIZE * max fru_cnt_t (in node_t's)
 *              msg_buf = caddr_t of msg_len, contains:
 *                  unpadded fru_hdl_t and actual fru_cnt_t
 *                  unpadded node_t array
 *              msg_status = return value, see below.
 *  Error Notes:
 */
#define	SGFRU_MBOX_GETCHILDLIST			0x700f
/*
 *  FRU Mailbox Definitions
 *
 *      Request (from Solaris to SC):
 *              msg_len = FRU_INFO_SIZE
 *              msg_buf = pointer to unpadded fru_info_t containing:
 *                  parent fru_hdl_t and max fru_cnt_t (in fru_hdl_t's)
 *      Response (from SC to Solaris):
 *              msg_len = FRU_HDL_SIZE * max fru_cnt_t (in fru_hdl_t's)
 *              msg_buf = caddr_t of msg_len, contains:
 *                  unpadded fru_hdl_t and actual fru_cnt_t
 *                  unpadded fru_hdl_t array
 *              msg_status = return value, see below.
 *  Error Notes:
 */
#define	SGFRU_MBOX_GETCHILDHANDLES		0x7010
/*
 *      Request (from Solaris to SC):
 *              msg_len = FRU_INFO_SIZE
 *              msg_buf = pointer to unpadded fru_hdl_t
 *      Response (from SC to Solaris):
 *              msg_len = NODE_SIZE
 *              msg_buf = caddr_t of msg_len, contains:
 *                  unpadded node_t
 *              msg_status = return value, see below.
 *  Error Notes:
 */
#define	SGFRU_MBOX_GETNODEINFO			0x7020


/*
 * The defines below are used for translating padded (C) to non-padded (Java),
 * and must directly correspond to the structures defined in fru_data_access.h
 * and sgfru.h.
 */
#define	FRU_HDL_SIZE		sizeof (fru_hdl_t)
#define	CONTAINER_HDL_SIZE	FRU_HDL_SIZE
#define	SECTION_HDL_SIZE	FRU_HDL_SIZE
#define	SEGMENT_HDL_SIZE	FRU_HDL_SIZE
#define	PACKET_HDL_SIZE		FRU_HDL_SIZE
#define	FRU_CNT_SIZE		sizeof (fru_cnt_t)
#define	NAME_SIZE		sizeof (char[SEG_NAME_LEN])
#define	OFFSET_SIZE		sizeof (uint32_t)
#define	LENGTH_SIZE		sizeof (uint32_t)
#define	PROTECTED_SIZE		sizeof (uint32_t)
#define	VERSION_SIZE		sizeof (uint32_t)
#define	DESCRIPTOR_SIZE		sizeof (uint32_t)
#define	TAG_SIZE		sizeof (tag_t)
#define	NODENAME_SIZE		sizeof (char[MAX_NODE_NAME])
#define	HASCHILDREN_SIZE	sizeof (uint16_t)
#define	CLASS_SIZE		sizeof (uint16_t)
#define	CLASS_INFO_SIZE		sizeof (union class_info)
#define	SLOT_SIZE		sizeof (uint16_t)
#define	LABEL_SIZE		sizeof (char[MAX_NODE_NAME])

#define	FRU_INFO_SIZE		(FRU_HDL_SIZE + FRU_CNT_SIZE)
#define	SECTION_SIZE		(SECTION_HDL_SIZE + OFFSET_SIZE +\
				    LENGTH_SIZE + PROTECTED_SIZE + VERSION_SIZE)
#define	SEGMENT_SIZE		(SEGMENT_HDL_SIZE + NAME_SIZE +\
				    DESCRIPTOR_SIZE + OFFSET_SIZE + LENGTH_SIZE)
#define	PACKET_SIZE		(PACKET_HDL_SIZE + TAG_SIZE)
#define	NODE_SIZE		(FRU_HDL_SIZE + NODENAME_SIZE +\
				    HASCHILDREN_SIZE + CLASS_SIZE +\
				    CLASS_INFO_SIZE)

static int sgfru_mbox(const int cmd, char *datap, const size_t size,
    fru_info_t *fru);

static caddr_t sgfru_fru_pad(const caddr_t datap, fru_info_t *fru);
static int sgfru_node_pad(const caddr_t datap, const int max_cnt,
    fru_info_t *fru, node_t *nodep);
static int sgfru_section_pad(const caddr_t datap, const int max_cnt,
    fru_info_t *fru, section_t *sectp);
static int sgfru_segment_pad(const caddr_t datap, const int max_cnt,
    fru_info_t *fru, segment_t *segp);
static int sgfru_packet_pad(const caddr_t datap, const int max_cnt,
    fru_info_t *fru, packet_t *packp);

static caddr_t sgfru_fru_unpad(const fru_info_t *fru, caddr_t datap);
static void sgfru_segment_unpad(const fru_info_t *fru, const segment_t *segp,
    caddr_t datap);
static caddr_t sgfru_packet_unpad(const fru_info_t *fru, const packet_t *packp,
    caddr_t datap);

#ifdef	__cplusplus
}
#endif

#endif	/* _SGFRU_MBOX_H */
