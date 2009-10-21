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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_BOOTPROPS_H
#define	_BOOTPROPS_H

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/t_kuser.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Boot properties related to netboot:
 */
#define	BP_HOST_IP			"host-ip"
#define	BP_SUBNET_MASK			"subnet-mask"
#define	BP_ROUTER_IP			"router-ip"
#define	BP_BOOT_MAC			"boot-mac"
#define	BP_SERVER_IP			"server-ip"
#define	BP_SERVER_NAME			"server-name"
#define	BP_SERVER_PATH			"server-path"
#define	BP_SERVER_ROOTOPTS		"server-rootopts"
#define	BP_BOOTP_RESPONSE		"bootp-response"

/*
 * Boot properties related to iscsiboot:
 */
#define	BP_NETWORK_INTERFACE		"network-interface"
#define	BP_ISCSI_TARGET_NAME		"iscsi-target-name"
#define	BP_ISCSI_TARGET_IP		"iscsi-target-ip"
#define	BP_ISCSI_INITIATOR_ID		"iscsi-initiator-id"
#define	BP_ISCSI_PORT			"iscsi-port"
#define	BP_ISCSI_TPGT			"iscsi-tpgt"
#define	BP_ISCSI_LUN			"iscsi-lun"
#define	BP_ISCSI_PAR			"iscsi-partition"
#define	BP_ISCSI_NETWORK_BOOTPATH	"iscsi-network-bootpath"
#define	BP_ISCSI_DISK			"/iscsi-hba/disk"
#define	BP_BOOTPATH			"bootpath"
#define	BP_CHAP_USER			"chap-user"
#define	BP_CHAP_PASSWORD		"chap-password"
#define	BP_LOCAL_MAC_ADDRESS		"local-mac-address"

/*
 * kifconf prototypes
 */
int
kdlifconfig(TIUSER *tiptr, int af, void *myIPaddr, void *mymask,
    struct in_addr *mybraddr, struct in_addr *gateway, char *ifname);
int
ksetifflags(TIUSER *tiptr, uint_t value, char *ifname);
int
kifioctl(TIUSER *tiptr, int cmd, struct netbuf *nbuf, char *ifname);

/*
 * Boot properties related to iscsi boot:
 */
#define	IB_BOOT_MACLEN		6
#define	IB_IP_BUFLEN		16

/*
 * iSCSI boot initiator's properties
 */
typedef struct _ib_ini_prop {
	uchar_t		*ini_name;
	size_t		ini_name_len;
	uchar_t		*ini_chap_name;
	size_t		ini_chap_name_len;
	uchar_t		*ini_chap_sec;
	size_t		ini_chap_sec_len;
} ib_ini_prop_t;

/*
 * iSCSI boot nic's properties
 */
typedef struct _ib_nic_prop {
	uchar_t		nic_mac[6];
	uchar_t		nic_vlan[2];
	union {
		struct in_addr	u_in4;
		struct in6_addr	u_in6;
	} nic_ip_u;
	union {
		struct in_addr	u_in4;
		struct in6_addr	u_in6;
	} nic_gw_u;
	union {
		struct in_addr	u_in4;
		struct in6_addr	u_in6;
	} nic_dhcp_u;
	int		sin_family;
	uchar_t		sub_mask_prefix;

} ib_nic_prop_t;

/*
 * iSCSI boot target's properties
 */
typedef struct _ib_tgt_prop {
	union {
		struct in_addr	u_in4;
		struct in6_addr	u_in6;
	}tgt_ip_u;
	int		sin_family;
	uint32_t	tgt_port;
	uchar_t		tgt_boot_lun[8];
	uchar_t		*tgt_name;
	size_t		tgt_name_len;
	uchar_t		*tgt_chap_name;
	size_t		tgt_chap_name_len;
	uchar_t		*tgt_chap_sec;
	size_t		tgt_chap_sec_len;
	int		lun_online;
	uchar_t		*tgt_boot_par;
	size_t		tgt_boot_par_len;
	uint16_t	tgt_tpgt;
} ib_tgt_prop_t;

/*
 * iSCSI boot properties
 */
typedef struct _ib_boot_prop {
	ib_ini_prop_t	boot_init;
	ib_nic_prop_t	boot_nic;
	ib_tgt_prop_t	boot_tgt;
} ib_boot_prop_t;

void
ld_ib_prop();

void
iscsi_boot_prop_free();

void
get_iscsi_bootpath_vhci(char *bootpath);

void
get_iscsi_bootpath_phy(char *bootpath);

#ifdef	__cplusplus
}
#endif

#endif	/* _BOOTPROPS_H */
