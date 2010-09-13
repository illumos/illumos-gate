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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_IB_EOIB_EIB_H
#define	_SYS_IB_EOIB_EIB_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 *
 * EoIB Encapsulation Header Layout
 *
 *  31 30 29 28 27 26 25 24     22 21 20 ... 16 15                      0
 * +-----+-----+-----+-----+--+---+--+---------+-------------------------+
 * | sig | ver | TCP | IP  |  |fcs|ms| segment |       segment id        |
 * |     |     | chk | chk |  |   |  | offset  |                         |
 * +-----+-----+-----+-----+--+---+--+---------+-------------------------+
 *
 */
#define	EIB_ENCAP_HDR_SZ		4

#define	EIB_ENCAP_SIGN_MASK		0x3
#define	EIB_ENCAP_SIGN_SHIFT		30
#define	EIB_ENCAP_VER_MASK		0x3
#define	EIB_ENCAP_VER_SHIFT		28
#define	EIB_ENCAP_TCPCHK_MASK		0x3
#define	EIB_ENCAP_TCPCHK_SHIFT		26
#define	EIB_ENCAP_IPCHK_MASK		0x3
#define	EIB_ENCAP_IPCHK_SHIFT		24
#define	EIB_ENCAP_FCS_B_SHIFT		22
#define	EIB_ENCAP_MS_B_SHIFT		21
#define	EIB_ENCAP_SEGOFF_MASK		0x1F
#define	EIB_ENCAP_SEGOFF_SHIFT		16
#define	EIB_ENCAP_SEGID_MASK		0xFFFF

/*
 * Bit fields values definitions
 */
#define	EIB_EH_SIGNATURE		3
#define	EIB_EH_VERSION			0
#define	EIB_EH_CSUM_UNKNOWN		0
#define	EIB_EH_TCPCSUM_OK		1
#define	EIB_EH_UDPCSUM_OK		2
#define	EIB_EH_CSUM_BAD			3
#define	EIB_EH_IPCSUM_OK		1

/*
 * Some shortcuts
 */
#define	EIB_TX_ENCAP_HDR		0xC0000000
#define	EIB_RX_ENCAP_TCPIP_OK		0xC5000000
#define	EIB_RX_ENCAP_UDPIP_OK		0xC9000000

/*
 * Driver name
 */
#define	EIB_DRV_NAME			"eoib"

/*
 * Currently, the gateway responds to login requests on the qpn that carried
 * the solication request, rather than on the qpn that carried the login
 * request.  This means that EoIB nexus receives the acknowledgements from
 * gateways to login requests made by the individual EoIB instances, and must
 * pass this login ack information back to the appropriate EoIB instance.
 *
 * Now, the only field in the login ack packet that could identify the
 * individual EoIB instance is the vNIC id field, but this is a 16-bit field,
 * with the MSB reserved to indicate whether the mac/vlan is host-managed
 * or gateway-managed.  This leaves us with just 15-bits to encode the EoIB
 * device instance and its Solaris vnic instance.  For now, we divide this
 * field as a 6-bit vnic instance number (max Solaris vnics is 64) and a
 * 9-bit device instance number (max EoIB pseudo-NICs in a system is 512).
 *
 * The long-term solution is to get the gateway to respond directly to the
 * login requestor, so the requestor can use all 15-bits to identify its
 * Solaris vnic instance (max 32K) and leave the device instance limit to
 * the system limit.
 */
#define	EIB_DVI_SHIFT			6
#define	EIB_DVI_MASK			0x1FF
#define	EIB_VNI_MASK			0x03F

#define	EIB_VNIC_INSTANCE(id)		((id) & EIB_VNI_MASK)
#define	EIB_DEVI_INSTANCE(id)		(((id) >> EIB_DVI_SHIFT) & EIB_DVI_MASK)
#define	EIB_VNIC_ID(dvi, vni)		\
	((((dvi) & EIB_DVI_MASK) << EIB_DVI_SHIFT) | ((vni) & EIB_VNI_MASK))

/*
 * Making VHUB_ID from vlan and portid
 */
#define	EIB_VHUB_ID(portid, vlan)	\
	((((uint_t)(portid) & 0xfff) << 12) | ((uint_t)(vlan) & 0xfff))

/*
 * NDI Events that individual EoIB instance will be interested in
 */
#define	EIB_NDI_EVENT_GW_AVAILABLE	"SUNW,eoib:gateway-available"
#define	EIB_NDI_EVENT_LOGIN_ACK		"SUNW,eoib:vnic-login-ack"
#define	EIB_NDI_EVENT_GW_INFO_UPDATE	"SUNW,eoib:gateway-info-update"

/*
 * Properties for each eoib node created
 */
#define	EIB_PROP_HCA_GUID		"hca-guid"
#define	EIB_PROP_HCA_PORTNUM		"hca-port#"
#define	EIB_PROP_GW_SYS_GUID		"gw-system-guid"
#define	EIB_PROP_GW_GUID		"gw-guid"
#define	EIB_PROP_GW_SN_PREFIX		"gw-sn-prefix"
#define	EIB_PROP_GW_ADV_PERIOD		"gw-adv-period"
#define	EIB_PROP_GW_KA_PERIOD		"gw-ka-period"
#define	EIB_PROP_VNIC_KA_PERIOD		"vnic-ka-period"
#define	EIB_PROP_GW_CTRL_QPN		"gw-ctrl-qpn"
#define	EIB_PROP_GW_LID			"gw-lid"
#define	EIB_PROP_GW_PORTID		"gw-portid"
#define	EIB_PROP_GW_NUM_NET_VNICS	"gw-num-net-vnics"
#define	EIB_PROP_GW_AVAILABLE		"gw-available?"
#define	EIB_PROP_GW_HOST_VNICS		"gw-host-vnics?"
#define	EIB_PROP_GW_SL			"gw-sl"
#define	EIB_PROP_GW_N_RSS_QPN		"gw-n-rss-qpn"
#define	EIB_PROP_GW_SYS_NAME		"gw-system-name"
#define	EIB_PROP_GW_PORT_NAME		"gw-port-name"
#define	EIB_PROP_GW_VENDOR_ID		"gw-vendor-id"

/*
 * Gateway information passed by eibnx to eoib.  The lengths of character
 * strings should be longer than what is defined for these objects in fip.h,
 * to accomodate the terminating null.
 */
#define	EIB_GW_SYSNAME_LEN		40
#define	EIB_GW_PORTNAME_LEN		12
#define	EIB_GW_VENDOR_LEN		12

typedef struct eib_gw_info_s {
	ib_guid_t	gi_system_guid;
	ib_guid_t	gi_guid;
	ib_sn_prefix_t	gi_sn_prefix;
	uint32_t	gi_adv_period;
	uint32_t	gi_ka_period;
	uint32_t	gi_vnic_ka_period;
	ib_qpn_t	gi_ctrl_qpn;
	ib_lid_t	gi_lid;
	uint16_t	gi_portid;
	uint16_t	gi_num_net_vnics;
	uint8_t		gi_flag_available;
	uint8_t		gi_is_host_adm_vnics;
	uint8_t		gi_sl;
	uint8_t		gi_n_rss_qpn;
	uint8_t		gi_system_name[EIB_GW_SYSNAME_LEN];
	uint8_t		gi_port_name[EIB_GW_PORTNAME_LEN];
	uint8_t		gi_vendor_id[EIB_GW_VENDOR_LEN];
} eib_gw_info_t;

/*
 * Softint priority levels to use for data and control/admin cq handling
 * in EoIB leaf and nexus drivers
 */
#define	EIB_SOFTPRI_DATA		(DDI_INTR_SOFTPRI_MIN)
#define	EIB_SOFTPRI_CTL			(DDI_INTR_SOFTPRI_MIN + 1)
#define	EIB_SOFTPRI_ADM			(DDI_INTR_SOFTPRI_MIN + 1)

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_EOIB_EIB_H */
