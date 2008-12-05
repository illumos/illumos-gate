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

#ifndef	_SYS_VNIC_IMPL_H
#define	_SYS_VNIC_IMPL_H

#include <sys/mac_provider.h>
#include <sys/mac_client.h>
#include <sys/mac_client_priv.h>
#include <sys/vnic.h>
#include <sys/mac_flow.h>
#include <sys/ksynch.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct vnic_s {
	datalink_id_t		vn_id;
	uint32_t
				vn_started : 1,
				vn_pad_to_bit_31 : 31;

	mac_handle_t		vn_mh;
	mac_handle_t		vn_lower_mh;
	mac_client_handle_t	vn_mch;
	mac_unicast_handle_t	vn_muh;
	uint32_t		vn_margin;
	int			vn_slot_id;
	vnic_mac_addr_type_t	vn_addr_type;
	uint8_t			vn_addr[MAXMACADDRLEN];
	size_t			vn_addr_len;
	uint16_t		vn_vid;
	boolean_t		vn_force;
	datalink_id_t		vn_link_id;
	mac_notify_handle_t	vn_mnh;

	uint32_t		vn_hcksum_txflags;
} vnic_t;

#define	vn_madd_naddr		vn_mma_capab.maddr_naddr
#define	vn_maddr_naddrfree	vn_mma_capab.maddr_naddrfree
#define	vn_maddr_flag		vn_mma_capab.maddr_flag
#define	vn_maddr_handle		vn_mma_capab.maddr_handle
#define	vn_maddr_reserve	vn_mma_capab.maddr_reserve
#define	vn_maddr_add		vn_mma_capab.maddr_add
#define	vn_maddr_remove		vn_mma_capab.maddr_remove
#define	vn_maddr_modify		vn_mma_capab.maddr_modify
#define	vn_maddr_get		vn_mma_capab.maddr_get

extern int vnic_dev_create(datalink_id_t, datalink_id_t, vnic_mac_addr_type_t *,
    int *, uchar_t *, int *, uint_t, uint16_t, mac_resource_props_t *,
    uint32_t, vnic_ioc_diag_t *);
extern int vnic_dev_modify(datalink_id_t, uint_t, vnic_mac_addr_type_t,
    uint_t, uchar_t *, uint_t, mac_resource_props_t *);
extern int vnic_dev_delete(datalink_id_t, uint32_t);

extern void vnic_dev_init(void);
extern void vnic_dev_fini(void);
extern uint_t vnic_dev_count(void);
extern dev_info_t *vnic_get_dip(void);

extern int vnic_info(vnic_info_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VNIC_IMPL_H */
