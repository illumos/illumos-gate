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

#ifndef _VNETMSG_H
#define	_VNETMSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	LM_SIGNATURE	0x564E45544C4D5347	/* "VNETLMSG" */

/* lm_type (below) */
#define	LM_DATA	0x1
#define	LM_ACK	0x2

/*
 * msg protocol used for ldc_mem IO. currently, 2 cookies are supported.
 * (In Unreliable mode LDC-maxpayload is 56 bytes).
 */

typedef struct vnet_ldc_msg {
	uint64_t		lm_signature;	/* signature: "VNETLMSG" */
	uint8_t			lm_type;	/* data or ack */
	uint8_t			lm_ncookies;	/* # of cookies in the msg */
	uint16_t		lm_id;		/* opaque id (sender) */
	uint16_t		lm_dlen;	/* actual data length */
	uint16_t		lm_resv;	/* reserved */
	ldc_mem_cookie_t	lm_cookie[2];	/* array of cookies */
} vnet_ldc_msg_t;

/*
 * XXX Co-ordinate these def's with Harsha, expect that these will
 * come from vnet header file.
 */
#define	MAX_COOKIES	((ETHERMTU >> MMU_PAGESHIFT) + 2)

#define	VNET_PUB_DESC_FREE	0x0
#define	VNET_PUB_DESC_READY	0x1
#define	VNET_PUB_DESC_DONE	0x2
#define	VNET_PUB_DESC_ACK	0x4

#define	VNET_PRIV_DESC_FREE	0x0
#define	VNET_PRIV_DESC_BUSY	0x1

typedef struct vnet_public_desc {
	uint64_t		flags;
	uint64_t		ncookies;
	ldc_mem_cookie_t	memcookie[MAX_COOKIES];
} vnet_public_desc_t;

#ifdef __cplusplus
}
#endif

#endif	/* _VNETMSG_H */
