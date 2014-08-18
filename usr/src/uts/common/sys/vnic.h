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

#ifndef	_SYS_VNIC_H
#define	_SYS_VNIC_H

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/param.h>
#include <sys/mac.h>
#include <sys/mac_flow.h>
#include <sys/dld_ioc.h>
#include <inet/ip.h>
#include <inet/ip6.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Extended diagnostic codes that can be returned by the various
 */
typedef enum {
	VNIC_IOC_DIAG_NONE,
	VNIC_IOC_DIAG_MACADDR_NIC,
	VNIC_IOC_DIAG_MACADDR_INUSE,
	VNIC_IOC_DIAG_MACADDR_INVALID,
	VNIC_IOC_DIAG_MACADDRLEN_INVALID,
	VNIC_IOC_DIAG_MACFACTORYSLOTINVALID,
	VNIC_IOC_DIAG_MACFACTORYSLOTUSED,
	VNIC_IOC_DIAG_MACFACTORYSLOTALLUSED,
	VNIC_IOC_DIAG_MACFACTORYNOTSUP,
	VNIC_IOC_DIAG_MACPREFIX_INVALID,
	VNIC_IOC_DIAG_MACPREFIXLEN_INVALID,
	VNIC_IOC_DIAG_MACMARGIN_INVALID,
	VNIC_IOC_DIAG_NO_HWRINGS,
	VNIC_IOC_DIAG_MACMTU_INVALID
} vnic_ioc_diag_t;

/*
 * Allowed VNIC MAC address types.
 *
 * - VNIC_MAC_ADDR_TYPE_FIXED, VNIC_MAC_ADDR_TYPE_RANDOM:
 *   The MAC address is specified by value by the caller, which
 *   itself can obtain it from the user directly,
 *   or pick it in a random fashion. Which method is used by the
 *   caller is irrelevant to the VNIC driver. However two different
 *   types are provided so that the information can be made available
 *   back to user-space when listing the kernel defined VNICs.
 *
 *   When a VNIC is created, the address in passed through the
 *   vc_mac_addr and vc_mac_len fields of the vnic_ioc_create_t
 *   structure.
 *
 * - VNIC_MAC_ADDR_TYPE_FACTORY: the MAC address is obtained from
 *   one of the MAC factory MAC addresses of the underyling NIC.
 *
 * - VNIC_MAC_ADDR_TYPE_AUTO: the VNIC driver attempts to
 *   obtain the address from one of the factory MAC addresses of
 *   the underlying NIC. If none is available, the specified
 *   MAC address value is used.
 *
 * - VNIC_MAC_ADDR_TYPE_PRIMARY: this is a VNIC based VLAN. The
 *   address for this is the address of the primary MAC client.
 *
 */

typedef enum {
	VNIC_MAC_ADDR_TYPE_UNKNOWN = -1,
	VNIC_MAC_ADDR_TYPE_FIXED,
	VNIC_MAC_ADDR_TYPE_RANDOM,
	VNIC_MAC_ADDR_TYPE_FACTORY,
	VNIC_MAC_ADDR_TYPE_AUTO,
	VNIC_MAC_ADDR_TYPE_PRIMARY,
	VNIC_MAC_ADDR_TYPE_VRID
} vnic_mac_addr_type_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

#define	VNIC_IOC_CREATE		VNICIOC(1)

#define	VNIC_IOC_CREATE_NODUPCHECK		0x00000001
#define	VNIC_IOC_CREATE_ANCHOR			0x00000002

/*
 * Force creation of VLAN based VNIC without checking if the
 * undelying MAC supports the margin size.
 */
#define	VNIC_IOC_CREATE_FORCE			0x00000004

typedef struct vnic_ioc_create {
	datalink_id_t	vc_vnic_id;
	datalink_id_t	vc_link_id;
	vnic_mac_addr_type_t vc_mac_addr_type;
	uint_t		vc_mac_len;
	uchar_t		vc_mac_addr[MAXMACADDRLEN];
	uint_t		vc_mac_prefix_len;
	int		vc_mac_slot;
	uint16_t	vc_vid;
	vrid_t		vc_vrid;
	int		vc_af;
	uint_t		vc_status;
	uint_t		vc_flags;
	vnic_ioc_diag_t	vc_diag;
	mac_resource_props_t vc_resource_props;
} vnic_ioc_create_t;

#define	VNIC_IOC_DELETE		VNICIOC(2)

typedef struct vnic_ioc_delete {
	datalink_id_t	vd_vnic_id;
} vnic_ioc_delete_t;

#define	VNIC_IOC_INFO		VNICIOC(3)

typedef struct vnic_info {
	datalink_id_t	vn_vnic_id;
	datalink_id_t	vn_link_id;
	vnic_mac_addr_type_t vn_mac_addr_type;
	uint_t		vn_mac_len;
	uchar_t		vn_mac_addr[MAXMACADDRLEN];
	uint_t		vn_mac_slot;
	uint32_t	vn_mac_prefix_len;
	uint16_t	vn_vid;
	vrid_t		vn_vrid;
	int		vn_af;
	boolean_t	vn_force;
	mac_resource_props_t vn_resource_props;
} vnic_info_t;

typedef struct vnic_ioc_info {
	vnic_info_t	vi_info;
} vnic_ioc_info_t;

#define	VNIC_IOC_MODIFY		VNICIOC(4)

#define	VNIC_IOC_MODIFY_ADDR		0x01
#define	VNIC_IOC_MODIFY_RESOURCE_CTL	0x02

typedef struct vnic_ioc_modify {
	datalink_id_t	vm_vnic_id;
	uint_t		vm_modify_mask;
	uint_t		vm_mac_len;
	int		vm_mac_slot;
	uchar_t		vm_mac_addr[MAXMACADDRLEN];
	vnic_mac_addr_type_t vm_mac_addr_type;
	mac_resource_props_t vm_resource_props;
	vnic_ioc_diag_t	vm_diag;
} vnic_ioc_modify_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VNIC_H */
