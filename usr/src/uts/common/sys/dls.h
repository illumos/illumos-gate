/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#ifndef	_SYS_DLS_H
#define	_SYS_DLS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/mac.h>

/*
 * Data-Link Services Module
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Module name.
 */
#define	DLS_MODULE_NAME	"dls"

/*
 * Data-Link Services Information (text emitted by modinfo(1m))
 */
#define	DLS_INFO	"Data-Link Services v%I%"

/*
 * Check the legality of a DLSAP value. The following values are allowed,
 * as specified by PSARC 2003/150:
 *
 * 0							802 semantics
 * ETHERTYPE_802_MIN (1536)..ETHERTYPE_MAX (65535)	ethertype semantics
 * 1..ETHERMTU (1500)					802 semantics, for
 *							DL_ETHER only.
 */
#define	SAP_LEGAL(type, sap) \
	(((sap) >= ETHERTYPE_802_MIN && (sap) < ETHERTYPE_MAX) || \
	((sap) == 0) || \
	((sap) <= ETHERMTU && (type) == DL_ETHER))

/*
 * Macros for converting ppas to instance #s and to Vlan IDs.
 */
#define	DLS_PPA2INST(ppa)	((int)((ppa) % 1000))
#define	DLS_PPA2VID(ppa)	((uint16_t)((ppa) / 1000))

#ifdef	_KERNEL

extern int	dls_create(const char *, const char *, uint_t);
extern int	dls_destroy(const char *);

typedef	struct dls_t	*dls_channel_t;

extern int	dls_open(const char *, dls_channel_t *);
extern void	dls_close(dls_channel_t);

extern mac_handle_t	dls_mac(dls_channel_t);
extern uint16_t		dls_vid(dls_channel_t);

#define	DLS_SAP_LLC	0
#define	DLS_SAP_PROMISC	(1 << 16)

extern int	dls_bind(dls_channel_t, uint16_t);
extern void	dls_unbind(dls_channel_t);

#define	DLS_PROMISC_SAP		0x00000001
#define	DLS_PROMISC_MULTI	0x00000002
#define	DLS_PROMISC_PHYS	0x00000004

extern int	dls_promisc(dls_channel_t, uint32_t);

extern int	dls_multicst_add(dls_channel_t, const uint8_t *);
extern int	dls_multicst_remove(dls_channel_t, const uint8_t *);

extern mblk_t	*dls_header(dls_channel_t, const uint8_t *, uint16_t, uint_t);

typedef struct dls_header_info {
	size_t		dhi_length;
	const uint8_t	*dhi_daddr;
	const uint8_t	*dhi_saddr;
	uint16_t	dhi_ethertype;
	uint16_t	dhi_vid;
	boolean_t	dhi_isgroup;
} dls_header_info_t;

extern void	dls_header_info(dls_channel_t, mblk_t *, dls_header_info_t *);

typedef	void	(*dls_rx_t)(void *, mac_resource_handle_t, mblk_t *, size_t);

extern void	dls_rx_set(dls_channel_t, dls_rx_t, void *);

extern mblk_t		*dls_tx(dls_channel_t, mblk_t *);

extern boolean_t	dls_active_set(dls_channel_t);
extern void		dls_active_clear(dls_channel_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLS_H */
