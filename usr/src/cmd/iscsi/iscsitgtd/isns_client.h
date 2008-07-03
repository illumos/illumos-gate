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

#ifndef	_ISNS_CLIENT_H
#define	_ISNS_CLIENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <netdb.h>
#include "queue.h"

#include "isns_protocol.h"

#ifndef	TRUE
#define	TRUE		1
#endif

#ifndef	FALSE
#define	FALSE		0
#endif

/* isns update bitmap */
#define	ISNS_MOD_ALIAS	0x1
#define	ISNS_MOD_TPGT	0x2

/* iscsi isns protocol */

/*
 * Attribute size
 */
#define	ISNS_ISCSI_TYPE_SZ	(4)
#define	ISNS_SCN_BITMAP_SZ	(4)
#define	ISNS_PORT_SZ		(4)
#define	ISNS_ESI_TICK_SZ	(4)
#define	ISNS_PG_TAG_SZ		(4)
#define	ISNS_ENTITY_TYP_SZ	(4)
#define	ISNS_NODE_TYP_SZ	(4)

/*
 * iSNS attribute length:  See RFC 4171 Section 6.1
 *	iSCSI Name = 4-224
 *	iSCSI Alias = 4-256
 */
#define	ISCSI_MAX_NAME	224
#define	ISCSI_MAX_ALIAS	256

/*
 * Default pdu payload size, this is derived from a typical DevAttrReg
 * request, this should be sufficient for all requests.
 */
#define	MAX_PDU_SZ		(16384)
#define	MAX_PDU_PAYLOAD_SZ	(MAX_PDU_SZ - ISNSP_HEADER_SIZE)
#define	TAG_LEN_SZ		(8)

/* various isns data size */
#define	ISNS_STATUS_SZ		(4)
#define	ISNS_ATTR_SZ(attr_len)	(attr_len + TAG_LEN_SZ)

/*
 * PDU length is 4 bytes aligned.  See RFC 4171 Section 5.1.3
 */
#define	PAD4(a)	((a%4) ? ((4-a%4)+a) : a)

/*
 * Macro to check 1st and last pdu
 */
#define	IS_1ST_PDU(x)	((x & ISNS_FLAG_FIRST_PDU) ? 1 : 0)
#define	IS_LAST_PDU(x)	((x & ISNS_FLAG_LAST_PDU) ? 1 : 0)

/* RFC 4171 section 6 - null is included in strlen */
#define	STRLEN(x)	(strlen(x) + 1)

typedef struct esi_scn_arg {
	char		entity[MAXHOSTNAMELEN + 1]; /* iscsi target entity */
	char		server[MAXHOSTNAMELEN + 1]; /* isns server */
	int		isns_port;		/* isns server port */
} esi_scn_arg_t;

/*
 * ISNS message header
 * See RFC 4171 Section 5.0 & 5.1
 */
typedef	struct	isns_hdr {
	uint16_t	version;
	uint16_t	func_id;
	uint16_t	pdu_len;
	uint16_t	flags;
	uint16_t	xid;
	uint16_t	seqid;
} isns_hdr_t;

/*
 * ISNS attribute, the attribute is in Tag-Length_Value format
 * attr_len: NULLs are included in the length
 * attr_value: is variable size and it is 4 bytes aligned
 */
#if 0
typedef	struct	isns_attr {
	uint32_t	tag;
	uint32_t	len;
	uint8_t		val[1];
} isns_attr_t;
#endif

typedef struct isns_rsp {
	uint16_t	version;
	uint16_t	func_id;
	uint16_t	pdu_len;
	uint16_t	flags;
	uint16_t	xid;
	uint16_t	seqid;
	uint32_t	status;
	uint8_t		data[1];
} isns_rsp_t;

/* Function prototype */
int		isns_init(target_queue_t *q);
int		isns_update();
void		isns_fini();
Boolean_t	isns_qry_initiator(char *, char *);
int		isns_reg(char *);
int		isns_reg_all();
int		isns_dereg(char *);
int		isns_dereg_all();
int		isns_scn_reg_all();
int		isns_scn_dereg_all();
int		isns_dev_update(char *, uint32_t);
Boolean_t	isns_enabled();
void		isns_tpgt_update();
int		isns_open(char *);
void		isns_close(int);
int		isns_append_attr(isns_pdu_t *, uint32_t, uint32_t, void *,
			uint32_t);
int		isns_create_pdu(uint16_t, uint32_t, isns_pdu_t **);
void		isns_free_pdu(void *);
int		isns_send(int, isns_pdu_t *);
int		isns_recv(int, isns_rsp_t **);
void		ntoh_isns_hdr(isns_hdr_t *);
void		ntoh_tlv(isns_tlv_t *);
void		print_ntoh_tlv(isns_tlv_t *);
void		print_attr(isns_tlv_t *attr, void *pval, uint32_t ival);
void		print_isns_hdr(isns_hdr_t *);
int		setsocknonblocking(int so);
int		setsockblocking(int so);
Boolean_t	is_socket_ready(int so,
		    fd_set *rfdset, fd_set *wfdset, fd_set *errfdset);

#ifdef __cplusplus
}
#endif

#endif	/* _ISNS_CLIENT_H */
