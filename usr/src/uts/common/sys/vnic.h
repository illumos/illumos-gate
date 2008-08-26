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

#ifndef	_SYS_VNIC_H
#define	_SYS_VNIC_H

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/param.h>
#include <sys/mac.h>
#include <sys/dld_ioc.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Note that the datastructures defined here define an ioctl interface
 * that is shared betwen user and kernel space.  The vnic driver thus
 * assumes that the structures have identical layout and size when
 * compiled in either IPL32 or LP64.
 */

/*
 * For now, we support only MAC addresses specified by value.
 */

typedef enum {
	VNIC_MAC_ADDR_TYPE_FIXED
} vnic_mac_addr_type_t;

#define	VNIC_IOC_CREATE		VNICIOC(1)

typedef struct vnic_ioc_create {
	datalink_id_t	vc_vnic_id;
	datalink_id_t	vc_link_id;
	uint_t		vc_mac_len;
	vnic_mac_addr_type_t vc_mac_addr_type;
	uchar_t		vc_mac_addr[MAXMACADDRLEN];
} vnic_ioc_create_t;

#define	VNIC_IOC_DELETE		VNICIOC(2)

typedef struct vnic_ioc_delete {
	datalink_id_t	vd_vnic_id;
} vnic_ioc_delete_t;

#define	VNIC_IOC_INFO		VNICIOC(3)

typedef struct vnic_ioc_info_vnic {
	datalink_id_t	vn_vnic_id;
	datalink_id_t	vn_link_id;
	uint32_t	vn_mac_len;
	uchar_t		vn_mac_addr[MAXMACADDRLEN];
	vnic_mac_addr_type_t vn_mac_addr_type;
} vnic_ioc_info_vnic_t;

typedef struct vnic_ioc_info {
	uint_t		vi_nvnics;
	uint_t		vi_size;
	datalink_id_t	vi_vnic_id;	/* DATALINK_ALL_LINKID returns all */
	datalink_id_t	vi_linkid;
} vnic_ioc_info_t;

#define	VNIC_IOC_MODIFY		VNICIOC(4)

#define	VNIC_IOC_MODIFY_ADDR		0x01

typedef struct vnic_ioc_modify {
	datalink_id_t	vm_vnic_id;
	uint_t		vm_modify_mask;
	uchar_t		vm_mac_addr[MAXMACADDRLEN];
	vnic_mac_addr_type_t vm_mac_addr_type;
	uint_t		vm_mac_len;
} vnic_ioc_modify_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VNIC_H */
