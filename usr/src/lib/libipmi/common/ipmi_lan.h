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

#ifndef IPMI_LAN_H
#define	IPMI_LAN_H

#ifdef	__cplusplus
extern "C" {
#endif

#pragma pack(1)

#define	IPMI_CMD_GET_SESSION_CHALLENGE	0x39
#define	IPMI_CMD_ACTIVATE_SESSION	0x3a
#define	IPMI_CMD_SET_SESSION_PRIVLVL	0x3b
#define	IPMI_CMD_CLOSE_SESSION		0x3c

#define	IPMI_AUTHCODE_BUF_SIZE		20
/*
 * See section 22.13
 */
#define	IPMI_SESSION_AUTHTYPE_NONE	0x01
#define	IPMI_SESSION_AUTHTYPE_MD2	0x02
#define	IPMI_SESSION_AUTHTYPE_MD5	0x04
#define	IPMI_SESSION_AUTHTYPE_PASSWORD	0x10
#define	IPMI_SESSION_AUTHTYPE_OEM	0x20

#define	IPMI_SESSION_PRIV_UNSPECIFIED   0x0
#define	IPMI_SESSION_PRIV_CALLBACK	0x1
#define	IPMI_SESSION_PRIV_USER		0x2
#define	IPMI_SESSION_PRIV_OPERATOR	0x3
#define	IPMI_SESSION_PRIV_ADMIN		0x4
#define	IPMI_SESSION_PRIV_OEM		0x5

#define	IPMI_BMC_SLAVE_ADDR	0x20
#define	IPMI_BUF_SIZE		1024
#define	IPMI_REMOTE_SWID	0x81

/*
 * The primary RMCP port
 */
#define	RMCP_UDP_PORT		623

/*
 * The ASF IANA Enterprise Number
 */
#define	ASF_RMCP_IANA		4542

/*
 * ASF Message Types for presence ping and pong
 */
#define	ASF_TYPE_PING		0x80
#define	ASF_TYPE_PONG		0x40

/*
 * ASF message header
 *
 * See section 13.2.3
 */
typedef struct asf_hdr {
	uint32_t	ah_iana;
	uint8_t		ah_msg_type;
	uint8_t		ah_msg_tag;
	uint8_t		__reserved1;
	uint8_t		ah_dlen;
} asf_hdr_t;

/*
 * RMCP message header
 *
 * See section 13.1.3
 */
#define	RMCP_VERSION_1		0x06
#define	RMCP_CLASS_ASF		0x06
#define	RMCP_CLASS_IPMI		0x07
#define	RMCP_CLASS_OEM		0x08

typedef struct rmcp_hdr {
	uint8_t rh_version;
	uint8_t __reserved1;
	uint8_t rh_seq;
	DECL_BITFIELD3(
	    rh_msg_class:5,
	    __reserved2:2,
	    rh_msg_type:1);
} rmcp_hdr_t;

/*
 * IPMI Session Header
 *
 * The IPMI session header contains some optional payload fields that are only
 * present in RMCP+ sessions or if the payload type is "OEM explicit".  This
 * structure is only intended to represent the session header for IPMI v1.5
 * messages.
 *
 * See section 13.6
 */
typedef struct v15_session_hdr {
	uint8_t		sh_authtype;
	uint32_t	sh_seq;
	uint32_t	sh_id;
}  v15_session_hdr_t;

/*
 * IPMI Lan Message Header
 *
 * See section 13.8
 */
typedef struct ipmi_msg_hdr {
	uint8_t imh_addr1;
	DECL_BITFIELD2(
	    imh_lun:2,
	    imh_netfn:6);
	uint8_t	imh_csum;
	uint8_t imh_addr2;
	uint8_t imh_seq;
	uint8_t imh_cmd;
} ipmi_msg_hdr_t;

#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif /* IPMI_LAN_H */
