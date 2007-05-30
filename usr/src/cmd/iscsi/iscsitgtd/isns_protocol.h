
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

#ifndef	_ISNS_PROTOCOL_H
#define	_ISNS_PROTOCOL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#define	ISNSP_VERSION			(0x01)

#define	ISNS_DEFAULT_SERVER_PORT	(3205)

#define	ISNSP_HEADER_SIZE		(12)
#define	ISNSP_MAX_PAYLOAD_SIZE		(65532)
#define	ISNSP_MAX_PDU_SIZE		(ISNSP_HEADER_SIZE + \
					ISNSP_MAX_PAYLOAD_SIZE)

#define	ISNS_TLV_ATTR_ID_LEN		(4)
#define	ISNS_TLV_ATTR_LEN_LEN		(4)
#define	MAX_ISNS_MESG_ATTR_ENTRIES	(8)
#define	MAX_ISNS_OPER_ATTR_ENTRIES	(32)

/* iSNS Entity Protocol, iSNS Draft - section 6.2.2. */
#define	ISNS_ENTITY_PROTOCOL_NO		(1)
#define	ISNS_ENTITY_PROTOCOL_ISCSI	(2)
#define	ISNS_ENTITY_PROTOCOL_FCP	(3)

/* iSNS Function IDs, iSNS Draft - section 4.1.3. */
#define	ISNS_DEV_ATTR_REG		(0x0001)
#define	ISNS_DEV_ATTR_QRY		(0x0002)
#define	ISNS_DEV_GET_NEXT		(0x0003)
#define	ISNS_DEV_DEREG			(0x0004)
#define	ISNS_SCN_REG			(0x0005)
#define	ISNS_SCN_DEREG			(0x0006)
#define	ISNS_SCN			(0x0008)
#define	ISNS_ESI			(0x000D)
#define	ISNS_HEARTBEAT			(0x000E)
#define	ISNS_DEV_ATTR_REG_RSP		(0x8001)
#define	ISNS_DEV_ATTR_QRY_RSP		(0x8002)
#define	ISNS_DEV_DEREG_RSP		(0x8004)
#define	ISNS_SCN_REG_RSP		(0x8005)
#define	ISNS_SCN_DEREG_RSP		(0x8006)
#define	ISNS_SCN_RSP			(0x8008)
#define	ISNS_ESI_RSP			(0x800D)

/* iSNS Flags, iSNS Draft - section 5.1.4. */
#define	ISNS_FLAG_FIRST_PDU		(0x0400)
#define	ISNS_FLAG_LAST_PDU		(0x0800)
#define	ISNS_FLAG_REPLACE_REG		(0x1000)
#define	ISNS_FLAG_AUTH_BLK_PRESENTED	(0x2000)
#define	ISNS_FLAG_SERVER		(0x4000)
#define	ISNS_FLAG_CLIENT		(0x8000)

/* iSNS Response Status, iSNS Draft - section 5.4 */
#define	ISNS_RSP_SUCCESSFUL		(0x0000)
#define	ISNS_RSP_UNKNOWN_ERROR		(0x0001)
#define	ISNS_RSP_MSG_FORMAT_ERROR	(0x0002)
#define	ISNS_RSP_INVALID_REGIS		(0x0003)
#define	ISNS_RSP_INVALID_QRY		(0x0005)
#define	ISNS_RSP_SRC_UNKNOWN		(0x0006)
#define	ISNS_RSP_SRC_ABSENT		(0x0007)
#define	ISNS_RSP_SRC_UNAUTHORIZED	(0x0008)
#define	ISNS_RSP_NO_SUCH_ENTRY		(0x0009)
#define	ISNS_RSP_VER_NOT_SUPPORTED	(0X0010)
#define	ISNS_RSP_INTERNAL_ERROR		(0x0011)
#define	ISNS_RSP_BUSY			(0x0012)
#define	ISNS_RSP_OPTION_NOT_UNDERSTOOD	(0x0013)
#define	ISNS_RSP_INVALID_UPDATE		(0x0014)
#define	ISNS_RSP_MSG_NOT_SUPPORTED	(0x0015)
#define	ISNS_RSP_SCN_EVENT_REJECTED	(0X0016)
#define	ISNS_RSP_SCN_REGIS_REJECTED	(0x0017)
#define	ISNS_RSP_ATTR_NOT_IMPL		(0x0018)
#define	ISNS_RSP_ESI_NOT_AVAILABLE	(0x0021)
#define	ISNS_RSP_INVALID_DEREGIS	(0x0022)
#define	ISNS_RSP_REGIS_NOT_SUPPORTED	(0x0023)

/* iSCSI Node Type, iSNS Draft - section 6.4.2. */
#define	ISNS_TARGET_NODE_TYPE		(0x0001)
#define	ISNS_INITIATOR_NODE_TYPE	(0x0002)
#define	ISNS_CONTROL_NODE_TYPE		(0x0004)

/* iSCSI Node SCN Bitmap, iSNS Draft - section 6.4.4. */
#define	ISNS_INIT_SELF_INFO_ONLY	(0x0080)	/* Bit 24 */
#define	ISNS_TARGET_SELF_INFO_ONLY	(0x0040)	/* Bit 25 */
#define	ISNS_MGMT_REG			(0x0020)	/* Bit 26 */
#define	ISNS_OBJ_REMOVED		(0x0010)	/* Bit 27 */
#define	ISNS_OBJ_ADDED			(0x0008)	/* Bit 28 */
#define	ISNS_OBJ_UPDATED		(0x0004)	/* Bit 29 */
#define	ISNS_OBJ_MEMBER_REMOVED		(0x0002)	/* Bit 30 */
#define	ISNS_OBJ_MEMBER_ADDED		(0x0001)	/* Bit 31 */

/* iSNS Attribute IDs, iSNS Draft - section 6.1. */
#define	ISNS_DELIMITER_ATTR_ID		(0)
#define	ISNS_EID_ATTR_ID		(1)
#define	ISNS_ENTITY_PROTOCOL_ATTR_ID	(2)
#define	ISNS_TIMESTAMP_ATTR_ID		(4)
#define	ISNS_PORTAL_IP_ADDR_ATTR_ID	(16)
#define	ISNS_PORTAL_PORT_ATTR_ID	(17)
#define	ISNS_PORTAL_NAME_ATTR_ID	(18)
#define	ISNS_ESI_INTERVAL_ATTR_ID	(19)
#define	ISNS_ESI_PORT_ATTR_ID		(20)
#define	ISNS_SCN_PORT_ATTR_ID		(23)
#define	ISNS_ISCSI_NAME_ATTR_ID		(32)
#define	ISNS_ISCSI_NODE_TYPE_ATTR_ID	(33)
#define	ISNS_ISCSI_ALIAS_ATTR_ID	(34)
#define	ISNS_ISCSI_SCN_BITMAP_ATTR_ID	(35)
#define	ISNS_PG_ISCSI_NAME_ATTR_ID	(48)
#define	ISNS_PG_PORTAL_IP_ADDR_ATTR_ID	(49)
#define	ISNS_PG_PORTAL_PORT_ATTR_ID	(50)
#define	ISNS_PG_TAG_ATTR_ID		(51)
#define	ISNS_PG_INDEX_ATTR_ID		(52)

/* iSNS Defaults */
#define	ISNS_DEFAULT_SERVER_PORT	(3205)

typedef struct isns_tlv {
	uint32_t attr_id;
	uint32_t attr_len;
	uint8_t attr_value[1];
} isns_tlv_t;

typedef struct isns_packet_data {
	uint16_t version;
	uint16_t func_id;
	uint16_t payload_len;
	uint16_t flags;
	uint16_t xid;
	uint16_t seq;

	int num_of_tlvs;
	isns_tlv_t tlvs[MAX_ISNS_OPER_ATTR_ENTRIES];
} isns_packet_data_t;

typedef struct isns_reg_mesg {
	isns_tlv_t src_attr;
	int num_of_mesg_attrs;
	isns_tlv_t *mesg_attrs[MAX_ISNS_MESG_ATTR_ENTRIES];
	isns_tlv_t delimiter_attr;
	isns_tlv_t *operating_attrs[MAX_ISNS_OPER_ATTR_ENTRIES];
} isns_reg_mesg_t;

typedef struct isns_resp_mesg {
	uint8_t	status[4];
	isns_tlv_t messages_attrs[MAX_ISNS_MESG_ATTR_ENTRIES];
	isns_tlv_t delimiter_attr;
	isns_tlv_t operating_attrs[MAX_ISNS_OPER_ATTR_ENTRIES];
} isns_resp_mesg_t;

typedef struct isns_pdu {
	uint16_t version;
	uint16_t func_id;
	uint16_t payload_len;
	uint16_t flags;
	uint16_t xid;
	uint16_t seq;
	uint8_t payload[1];
} isns_pdu_t;

typedef struct isns_resp {
	uint32_t status;
	uint8_t data[1];
} isns_resp_t;

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_PROTOCOL_H */
