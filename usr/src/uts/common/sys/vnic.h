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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/param.h>
#include <sys/mac.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* control interface name */
#define	VNIC_CTL_NODE_NAME	"ctl"
#define	VNIC_CTL_NODE_MINOR	1		/* control interface minor */

#define	VNIC_IOC(x)	(('v' << 24) | ('n' << 16) | ('i' << 8) | (x))

/*
 * For now, we support only MAC addresses specified by value.
 */

typedef enum {
	VNIC_MAC_ADDR_TYPE_FIXED
} vnic_mac_addr_type_t;

#define	VNIC_IOC_CREATE		VNIC_IOC(1)

typedef struct vnic_ioc_create {
	datalink_id_t	vc_vnic_id;
	datalink_id_t	vc_link_id;
	uint_t		vc_mac_len;
	vnic_mac_addr_type_t vc_mac_addr_type;
	uchar_t		vc_mac_addr[MAXMACADDRLEN];
} vnic_ioc_create_t;

#ifdef _SYSCALL32

typedef struct vnic_ioc_create32 {
	datalink_id_t	vc_vnic_id;
	datalink_id_t	vc_link_id;
	uint32_t	vc_mac_len;
	vnic_mac_addr_type_t vc_mac_addr_type;
	uchar_t		vc_mac_addr[MAXMACADDRLEN];
} vnic_ioc_create32_t;

#endif /* _SYSCALL32 */

#define	VNIC_IOC_DELETE		VNIC_IOC(2)

typedef struct vnic_ioc_delete {
	datalink_id_t	vd_vnic_id;
} vnic_ioc_delete_t;

#ifdef _SYSCALL32

typedef struct vnic_ioc_delete32 {
	datalink_id_t	vd_vnic_id;
} vnic_ioc_delete32_t;

#endif /* _SYSCALL32 */

#define	VNIC_IOC_INFO		VNIC_IOC(3)

typedef struct vnic_ioc_info_vnic {
	datalink_id_t	vn_vnic_id;
	datalink_id_t	vn_link_id;
	uint32_t	vn_mac_len;
	uchar_t		vn_mac_addr[MAXMACADDRLEN];
	vnic_mac_addr_type_t vn_mac_addr_type;
} vnic_ioc_info_vnic_t;

typedef struct vnic_ioc_info {
	uint_t		vi_nvnics;
	datalink_id_t	vi_vnic_id;	/* DATALINK_ALL_LINKID returns all */
	datalink_id_t	vi_linkid;
} vnic_ioc_info_t;

#ifdef _SYSCALL32

typedef struct vnic_ioc_info32 {
	uint32_t	vi_nvnics;
	datalink_id_t	vi_vnic_id;	/* DATALINK_ALL_LINKID returns all */
	datalink_id_t	vi_linkid;
} vnic_ioc_info32_t;

#endif /* _SYSCALL32 */

#define	VNIC_IOC_MODIFY		VNIC_IOC(4)

#define	VNIC_IOC_MODIFY_ADDR		0x01

typedef struct vnic_ioc_modify {
	datalink_id_t	vm_vnic_id;
	uint_t		vm_modify_mask;
	uchar_t		vm_mac_addr[MAXMACADDRLEN];
	vnic_mac_addr_type_t vm_mac_addr_type;
	uint_t		vm_mac_len;
} vnic_ioc_modify_t;

#ifdef _SYSCALL32

typedef struct vnic_ioc_modify32 {
	datalink_id_t	vm_vnic_id;
	uint32_t	vm_modify_mask;
	uchar_t		vm_mac_addr[MAXMACADDRLEN];
	vnic_mac_addr_type_t vm_mac_addr_type;
	uint32_t	vm_mac_len;
} vnic_ioc_modify32_t;

#endif /* _SYSCALL32 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VNIC_H */
