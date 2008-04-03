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

#ifndef _HXGE_CLASSIFY_H
#define	_HXGE_CLASSIFY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <hxge_pfc.h>
#include <hxge_pfc_hw.h>
#include <hpi_pfc.h>


/*
 * The following are the user configurable ether types. Refer to
 * /usr/include/sys/ethernet.h
 *
 * ETHERTYPE_PUP	(0x0200)
 * ETHERTYPE_802_MIN	(0x0600)
 * ETHERTYPE_IP		(0x0800)
 * ETHERTYPE_ARP	(0x0806)
 * ETHERTYPE_REVARP	(0x8035)
 * ETHERTYPE_AT		(0x809b)
 * ETHERTYPE_AARP	(0x80f3)
 * ETHERTYPE_IPV6	(0x86dd)
 * ETHERTYPE_SLOW	(0x8809)
 * ETHERTYPE_PPPOED	(0x8863)
 * ETHERTYPE_PPPOES	(0x8864)
 * ETHERTYPE_MAX	(0xffff)
 */

/*
 * Used for ip class tcam key config
 */
#define	HXGE_CLASS_TCAM_LOOKUP		0x10000
#define	HXGE_CLASS_DISCARD		0x20000
#define	HXGE_CLASS_VALID		0x40000
#define	HXGE_CLASS_ETHER_TYPE_MASK	0x0FFFF

typedef struct _tcam_flow_spec {
	hxge_tcam_entry_t tce;
	uint64_t flags;
	uint64_t user_info;
} tcam_flow_spec_t, *p_tcam_flow_spec_t;

typedef struct {
	uint16_t	ether_type;
	int		count;	/* How many TCAM entries using this class. */
} hxge_class_usage_t;

#define	HXGE_PFC_HW_RESET	0x1
#define	HXGE_PFC_HW_INIT	0x2
#define	HXGE_PFC_SW_INIT	0x4

typedef struct _hxge_classify {
	uint32_t 		tcam_size;
	uint32_t		n_used;
	uint32_t 		state;
	p_hxge_pfc_stats_t	pfc_stats;

	tcam_flow_spec_t	*tcam_entries;
	uint8_t			tcam_location;
	hxge_class_usage_t	class_usage[TCAM_CLASS_MAX];
} hxge_classify_t, *p_hxge_classify_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _HXGE_CLASSIFY_H */
