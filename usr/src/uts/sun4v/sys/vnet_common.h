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

#ifndef _VNET_COMMON_H
#define	_VNET_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/vio_common.h>
#include <sys/vio_mailbox.h>
#include <sys/ethernet.h>

/*
 * This header file contains definitions common to LDoms Virtual Network
 * server (vsw) and client (vnet).
 */

/* max # of cookies per frame size */
#define	MAX_COOKIES	 ((ETHERMAX >> MMU_PAGESHIFT) + 2ULL)

/* initial send sequence number */
#define	VNET_ISS		0x1

#define	VNET_2K			(1 << 11)
#define	VNET_4K			(1 << 12)
#define	VNET_8K			(1 << 13)
#define	VNET_12K		((VNET_8K) + (VNET_4K))
#define	VNET_IPALIGN		6	/* padding for IP header alignment */
#define	VNET_LDCALIGN		8	/* padding for ldc_mem_copy() align */
#define	VNET_ROUNDUP_2K(n)	(((n) + (VNET_2K - 1)) & ~(VNET_2K - 1))
#define	VNET_ROUNDUP_4K(n)	(((n) + (VNET_4K - 1)) & ~(VNET_4K - 1))
#define	VNET_ROUNDUP_8K(n)	(((n) + (VNET_8K - 1)) & ~(VNET_8K - 1))

/*
 * Maximum MTU value currently supported. MAX_COOKIES for data has been defined
 * already based on ETHERMAX. Hence we limit the MTU to be within 2 8K pages
 * and take some additional steps (see related code in .c files) to ensure that
 * ldc cookies for each data buffer is within the MAX_COOKIES. This allows us
 * to support Jumbo MTUs without changing the size of the descriptor.
 */
#define	VNET_MAX_MTU		16000

#define	VNET_NUM_HANDSHAKES	6	/* # of handshake attempts */

/* vnet descriptor */
typedef struct vnet_public_desc {
	vio_dring_entry_hdr_t	hdr;		/* descriptor header */
	uint32_t		nbytes;		/* data length */
	uint32_t		ncookies;	/* number of data cookies */
	ldc_mem_cookie_t	memcookie[MAX_COOKIES]; /* data cookies */
} vnet_public_desc_t;

/*
 * Vnet in-band descriptor. Used by those vnet clients
 * such as OBP who do not use descriptor rings.
 */
typedef struct vnet_ibnd_desc {
	vio_inband_desc_msg_hdr_t	hdr;

	/* payload */
	uint32_t			nbytes;
	uint32_t			ncookies;
	ldc_mem_cookie_t		memcookie[MAX_COOKIES];
} vnet_ibnd_desc_t;

/* exported functions */
uint64_t vnet_macaddr_strtoul(const uint8_t *macaddr);
void vnet_macaddr_ultostr(uint64_t value, uint8_t *macaddr);
mblk_t *vnet_vlan_insert_tag(mblk_t *mp, uint16_t vid);
mblk_t *vnet_vlan_remove_tag(mblk_t *mp);
int vnet_dring_entry_copy(vnet_public_desc_t *dst, vnet_public_desc_t *src,
    uint8_t mtype, ldc_dring_handle_t handle, uint64_t start, uint64_t stop);
int vnet_dring_entry_set_dstate(vnet_public_desc_t *descp, uint8_t mtype,
    ldc_dring_handle_t handle, uint64_t start, uint64_t stop, uint8_t dstate);

#ifdef __cplusplus
}
#endif

#endif	/* _VNET_COMMON_H */
