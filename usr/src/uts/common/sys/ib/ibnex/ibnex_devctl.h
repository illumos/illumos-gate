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

#ifndef _SYS_IB_IBNEX_IBNEX_DEVCTL_H
#define	_SYS_IB_IBNEX_IBNEX_DEVCTL_H

#include <sys/ib/ib_types.h>
#include <sys/ib/ibtl/ibtl_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file contains info for devctls issued by IB cfgadm plugin.
 * The only devctl of interest is DEVCTL_AP_CONTROL which uses
 * these defines and data structures.
 */

#define	IBNEX_HCAGUID_STRSZ	17

/*
 * types of attachment point Identifiers (APID)s supported
 */
#define	IBNEX_BASE_APID		0x01	/* Base static attachment point */
#define	IBNEX_HCA_APID		0x02	/* HCA static attachment point */
#define	IBNEX_DYN_APID		0x04	/* Dynamic IOC/DLPI attachment point */
#define	IBNEX_UNKNOWN_APID	0x08	/* Unknown attachment point */


/* defines for dynamic APID handling */
#define	DYN_SEP		"::"
#define	GET_DYN(a)	(((a) != NULL) ? strstr((a), DYN_SEP) : (void *)0)

#define	IBNEX_FABRIC		"fabric"
#define	IBNEX_VPPA_STR		"vppa"
#define	IBNEX_PORT_STR		"port"
#define	IBNEX_HCASVC_STR	"hca-svc"

/* Enums while reading ib.conf file */
typedef enum ib_service_type_e {
	IB_NAME,		/* name = */
	IB_CLASS,		/* class = */
	IB_PORT_SERVICE,	/* port-svc-list = */
	IB_VPPA_SERVICE,	/* vppa-svc-list = */
	IB_HCASVC_SERVICE,	/* hca-svc-list = */
	IB_NONE
} ib_service_type_t;

/*
 * defines for nvlist types: (for PORT devices and IOCs)
 * The first 6 are common to both IOC and PORT devices.
 * The last 9 are used only for IOC devices.
 */
#define	IBNEX_NODE_INFO_NVL		"node_info"
#define	IBNEX_NODE_APID_NVL		"node_apid"
#define	IBNEX_NODE_TYPE_NVL		"node_type"
#define	IBNEX_NODE_RSTATE_NVL		"node_rstate"
#define	IBNEX_NODE_OSTATE_NVL		"node_ostate"
#define	IBNEX_NODE_COND_NVL		"node_condition"

/*
 * This flag is passed from cfgadm to ib(7d) to convey that it
 * need not attempt to probe the fabric.
 *
 * The value of these flags should be same as flags in enum
 * ibdm_ibnex_get_ioclist_mtd_t.
 */
#define	IBNEX_DONOT_PROBE_FLAG	1
#define	IBNEX_NORMAL_PROBE	0	/* flag used by ib(7d) only */

/*
 * The following are sub-commands to DEVCTL_AP_CONTROL.
 * NOTE: IBNEX_NUM_DEVICE_NODES and IBNEX_NUM_HCA_NODES need to be
 * separate. The former is used to figure out the dynamic ap_ids for
 * the IB fabric. The latter is used for a HCA count on a given host only.
 */
#define	IBNEX_NUM_DEVICE_NODES	0x00010	/* how many device nodes exist? */
#define	IBNEX_NUM_HCA_NODES	0x00020	/* how many HCAs exist in the host? */
#define	IBNEX_SNAPSHOT_SIZE	0x00040	/* What is the "snapshot" size? */
#define	IBNEX_GET_SNAPSHOT	0x00080	/* Get the actual dynamic "snapshot" */
#define	IBNEX_DEVICE_PATH_SZ	0x00100	/* Given APID's device path size */
#define	IBNEX_GET_DEVICE_PATH	0x00200	/* Get device path for a Dynamic APID */
#define	IBNEX_HCA_LIST_SZ	0x00400	/* -x list_clients size for HCA APID */
#define	IBNEX_HCA_LIST_INFO	0x00800	/* -x list_clients info for HCA APID */
#define	IBNEX_UNCFG_CLNTS_SZ	0x01000	/* -x unconfig_clients option size */
#define	IBNEX_UNCFG_CLNTS_INFO	0x02000	/* -x unconfig_clients option data */
#define	IBNEX_UPDATE_PKEY_TBLS	0x04000	/* -x update_pkey_tbls */
#define	IBNEX_CONF_ENTRY_ADD	0x08000	/* -x conf_file add_service */
#define	IBNEX_CONF_ENTRY_DEL	0x10000	/* -x conf_file delete_service */
#define	IBNEX_HCA_VERBOSE_SZ	0x20000	/* -alv hca_apid devctl size */
#define	IBNEX_HCA_VERBOSE_INFO	0x40000	/* -alv hca_apid devctl data */
#define	IBNEX_UPDATE_IOC_CONF	0x80000	/* -x update_ioc_conf */

/*
 * Data structure passed back and forth user/kernel w/ DEVCTL_AP_CONTROL
 * devctl. Note that these are separate structures as some fields are pointers.
 */
typedef struct ibnex_ioctl_data {
	uint_t		cmd;		/* one of the above commands */
	caddr_t		buf;		/* data buffer */
	uint_t		bufsiz;		/* data buffer size */
	caddr_t		ap_id;		/* Search based on this AP_ID name */
	uint_t		ap_id_len;	/* AP_ID name len */
	uint_t		misc_arg;	/* reserved */
} ibnex_ioctl_data_t;


/* For 32-bit app/64-bit kernel */
typedef struct ibnex_ioctl_data_32 {
	uint32_t	cmd;		/* one of the above commands */
	caddr32_t	buf;		/* data buffer */
	uint32_t	bufsiz;		/* data buffer size */
	caddr32_t	ap_id;		/* Search based on this AP_ID name */
	uint32_t	ap_id_len;	/* AP_ID name len */
	uint32_t	misc_arg;	/* reserved */
} ibnex_ioctl_data_32_t;

/*
 * General ibnex IOCTLs
 *
 * IBNEX_CTL_GET_API_VER
 * ======================
 *
 * Gets the version number of the API that IB nexus currently supports.
 *
 * arg - pointer to a structure of type ibnex_ctl_api_ver_t
 *
 * Caller does not set any field of this structure. When this IOCTL is issued,
 * ib nexus will set api_ver_num field to the currently supported API
 * version number.
 *
 * The caller could issue this IOCTL prior to issuing any other general
 * ibnex IOCTLs to detect incompatible changes to the API. The caller may
 * call other IOCTLs only if the api_ver_num matches the API version number
 * used by the caller.
 *
 *
 * IBNEX_CTL_GET_HCA_LIST
 * ======================
 *
 * Gets GUIDs of all HCAs in the system
 *
 * arg - pointer to a structure of type ibnex_ctl_get_hca_list_t
 *
 * Caller allocates memory for HCA GUIDs. Sets hca_guids field to point to the
 * allocated memory. Sets hca_guids_alloc_sz to the number of GUIDs for which
 * memory has been allocated.
 *
 * Upon successful return from the IOCTL, nhcas will contain the number of
 * HCAs in the system. HCA GUIDs will be copied into hca_guids array.
 * The number of GUIDs copied are nhcas or hca_guids_alloc_sz which ever is
 * smaller.
 *
 *
 * IBNEX_CTL_QUERY_HCA
 * ===================
 *
 * Query HCA attributes
 *
 * arg - pointer to a structure of type ibnex_ctl_query_hca_t
 *
 * Caller sets hca_guid field of this structure.
 *
 * Caller allocates memory for hca device path. Sets hca_device_path to point
 * to the allocated memory and hca_device_path_alloc_sz to the number of bytes
 * allocated.
 *
 * Upon successful return from the IOCTL, hca_info will contain HCA attributes
 * for the specified GUID. hca_info.hca_device_path_len will contain the actual
 * string length of the hca device path plus one (for the terminating null
 * character). hca_info.hca_device_path will point to null terminated hca device
 * path string if the caller allocated memory for the hca device path is large
 * enough to hold the hca device path and the terminating null character.
 * Otherwise hca_info.hca_device_path will be set to NULL.
 *
 *
 * IBNEX_CTL_QUERY_HCA_PORT
 * ========================
 *
 * Query HCA port attributes
 *
 * arg - pointer to a structure of type ibnex_ctl_query_hca_port_t
 *
 * Caller sets hca_guid and port_num fields.
 *
 * Caller allocates memory for sgid entries. Sets sgid_tbl to point to
 * the allocated memory and sgid_tbl_alloc_sz to the number of sgid entries
 * for which memory has been allocated.
 *
 * Caller allocates memory for pkey entries. Sets pkey_tbl to point to
 * the allocated memory and pkey_tbl_alloc_sz to the number of pkey entries
 * for which memory has been allocated.
 *
 * Upon successful return from the IOCTL, port_info will contain HCA port
 * attributes for the specified HCA port. port_info.p_sgid_tbl_sz will contain
 * the actual number of sgids associated with this port. port_info.p_pkey_tbl_sz
 * will contain the actual number of pkeys associated with this port.
 *
 * port_info.p_sgid_tbl will point to an array containing sgids. The number of
 * sgids in the array is sgid_tbl_alloc_sz or port_info.p_sgid_tbl_sz
 * whichever is smaller.
 *
 * port_info.p_pkey_tbl will point to an array containing pkeys. The number of
 * pkeys in the array is pkey_tbl_alloc_sz or port_info.p_pkey_tbl_sz
 * whichever is smaller.
 *
 * Error numbers for the above ioctls upon failure:
 *   EINVAL	Invalid parameter passed
 *   EFAULT	A fault occurred copying data to or from the user space
 *		to the kernel space.
 *   ENXIO	Specified HCA GUID does not exist
 *   ENOENT	Specified HCA port does not exist
 *
 */


/*
 * ibnex specific ioctls
 *
 * NOTE: The ioctl codes should not collide with generic devctl ioctls
 * such as DEVCTL_AP_CONFIGURE.
 */
#define	IBNEX_IOC		(1 << 16)
#define	IBNEX_CTL_GET_API_VER	(IBNEX_IOC + 1)	/* Get API version # */
#define	IBNEX_CTL_GET_HCA_LIST	(IBNEX_IOC + 2)	/* Get HCA GUID list */
#define	IBNEX_CTL_QUERY_HCA	(IBNEX_IOC + 3)	/* Query HCA attributes */
#define	IBNEX_CTL_QUERY_HCA_PORT (IBNEX_IOC + 4) /* Query HCA port attributes */

/*
 * The device to open for issuing ibnex IOCTLs
 */
#define	IBNEX_DEVCTL_DEV		"/devices/ib:devctl"

/*
 * ibnex IOCTL API version number - to be incremented when making an
 * incompatible change to the API.
 */
#define	IBNEX_CTL_API_VERSION		1

#define	MAX_HCA_DRVNAME_LEN		16

/*
 * Data structure for IBNEX_CTL_GET_API_VER
 */
typedef struct ibnex_ctl_api_ver_s {
	uint_t		api_ver_num;		/* out: supported API version */
} ibnex_ctl_api_ver_t;

/*
 * Data structure for IBNEX_CTL_GET_HCA_LIST
 */
typedef struct ibnex_ctl_get_hca_list_s {
	ib_guid_t	*hca_guids;		/* in/out: HCA GUID array */
	uint_t		hca_guids_alloc_sz;	/* in: # of HCA GUIDs for */
						/* which storage is allocated */
	uint_t		nhcas;			/* out: actual number of HCAs */
} ibnex_ctl_get_hca_list_t;

typedef struct ibnex_ctl_get_hca_list_32_s {
	caddr32_t	hca_guids;		/* in/out: HCA GUID array */
	uint_t		hca_guids_alloc_sz;	/* in: # of HCA GUIDs for */
						/* which storage is allocated */
	uint_t		nhcas;			/* out: actual number of HCAs */
} ibnex_ctl_get_hca_list_32_t;

/*
 * HCA information structure
 */
typedef struct ibnex_ctl_hca_info_s {
	ib_guid_t	hca_node_guid;		/* Node GUID */
	ib_guid_t	hca_si_guid;		/* Optional System Image GUID */
	uint_t		hca_nports;		/* Number of physical ports */

	/* HCA driver name and instance number */
	char		hca_driver_name[MAX_HCA_DRVNAME_LEN];
	int		hca_driver_instance;

	/*
	 * hca device path and the length.
	 * hca_device_path_len contains the string length of the actual hca
	 * device path plus one (for the terminating null character).
	 */
	char		*hca_device_path;
	uint_t		hca_device_path_len;

	ibt_hca_flags_t		hca_flags;	/* HCA capabilities etc */
	ibt_hca_flags2_t	hca_flags2;	/* HCA capabilities etc */

	uint32_t	hca_vendor_id;		/* Vendor ID */
	uint16_t	hca_device_id;		/* Device ID */
	uint32_t	hca_version_id;		/* Version ID */

	uint_t		hca_max_chans;		/* Max channels supported */
	uint_t		hca_max_chan_sz;	/* Max outstanding WRs on any */
						/* channel */

	uint_t		hca_max_sgl;		/* Max SGL entries per WR */

	uint_t		hca_max_cq;		/* Max num of CQs supported  */
	uint_t		hca_max_cq_sz;		/* Max capacity of each CQ */

	ibt_page_sizes_t	hca_page_sz;	/* Bit mask of page sizes */

	uint_t		hca_max_memr;		/* Max num of HCA mem regions */
	ib_memlen_t	hca_max_memr_len;	/* Largest block, in bytes of */
						/* mem that can be registered */
	uint_t		hca_max_mem_win;	/* Max Memory windows in HCA */

	uint_t		hca_max_rsc; 		/* Max Responder Resources of */
						/* this HCA for RDMAR/Atomics */
						/* with this HCA as target. */
	uint8_t		hca_max_rdma_in_chan;	/* Max RDMAR/Atomics in per */
						/* chan this HCA as target. */
	uint8_t		hca_max_rdma_out_chan;	/* Max RDMA Reads/Atomics out */
						/* per channel by this HCA */
	uint_t		hca_max_ipv6_chan;	/* Max IPV6 channels in HCA */
	uint_t		hca_max_ether_chan;	/* Max Ether channels in HCA */

	uint_t		hca_max_mcg_chans;	/* Max number of channels */
						/* that can join multicast */
						/* groups */
	uint_t		hca_max_mcg;		/* Max multicast groups */
	uint_t		hca_max_chan_per_mcg;	/* Max number of channels per */
						/* Multicast group in HCA */
	uint16_t	hca_max_partitions;	/* Max partitions in HCA */

	ib_time_t	hca_local_ack_delay;

	uint_t		hca_max_port_sgid_tbl_sz;
	uint16_t	hca_max_port_pkey_tbl_sz;
	uint_t		hca_max_pd;		/* Max# of Protection Domains */

	uint_t		hca_max_ud_dest;
	uint_t		hca_max_srqs;		/* Max SRQs supported */
	uint_t		hca_max_srqs_sz;	/* Max outstanding WRs on any */
						/* SRQ */
	uint_t		hca_max_srq_sgl;	/* Max SGL entries per SRQ WR */
	uint_t		hca_max_cq_handlers;
	ibt_lkey_t	hca_reserved_lkey;	/* Reserved L_Key value */
	uint_t		hca_max_fmrs;		/* Max FMR Supported */

	uint_t		hca_max_lso_size;
	uint_t		hca_max_lso_hdr_size;
	uint_t		hca_max_inline_size;

	uint_t		hca_max_cq_mod_count;	/* CQ notify moderation */
	uint_t		hca_max_cq_mod_usec;

	uint32_t	hca_fw_major_version;	/* firmware version */
	uint16_t	hca_fw_minor_version;
	uint16_t	hca_fw_micro_version;

	/* detailed WQE size info */
	uint_t		hca_ud_send_inline_sz;	/* inline size in bytes */
	uint_t		hca_conn_send_inline_sz;
	uint_t		hca_conn_rdmaw_inline_overhead;
	uint_t		hca_recv_sgl_sz;	/* detailed SGL sizes */
	uint_t		hca_ud_send_sgl_sz;
	uint_t		hca_conn_send_sgl_sz;
	uint_t		hca_conn_rdma_sgl_overhead;
	int32_t		hca_pad;
} ibnex_ctl_hca_info_t;

typedef struct ibnex_ctl_hca_info_32_s {
	ib_guid_t	hca_node_guid;		/* Node GUID */
	ib_guid_t	hca_si_guid;		/* Optional System Image GUID */
	uint_t		hca_nports;		/* Number of physical ports */

	/* HCA driver name and instance number */
	char		hca_driver_name[MAX_HCA_DRVNAME_LEN];
	int		hca_driver_instance;

	/*
	 * hca device path and the length.
	 * hca_device_path_len contains the string length of the actual hca
	 * device path plus one (for the terminating null character).
	 */
	caddr32_t	hca_device_path;
	uint_t		hca_device_path_len;

	ibt_hca_flags_t		hca_flags;	/* HCA capabilities etc */
	ibt_hca_flags2_t	hca_flags2;	/* HCA capabilities etc */

	uint32_t	hca_vendor_id;		/* Vendor ID */
	uint16_t	hca_device_id;		/* Device ID */
	uint32_t	hca_version_id;		/* Version ID */

	uint_t		hca_max_chans;		/* Max channels supported */
	uint_t		hca_max_chan_sz;	/* Max outstanding WRs on any */
						/* channel */

	uint_t		hca_max_sgl;		/* Max SGL entries per WR */

	uint_t		hca_max_cq;		/* Max num of CQs supported  */
	uint_t		hca_max_cq_sz;		/* Max capacity of each CQ */

	ibt_page_sizes_t	hca_page_sz;	/* Bit mask of page sizes */

	uint_t		hca_max_memr;		/* Max num of HCA mem regions */
	ib_memlen_t	hca_max_memr_len;	/* Largest block, in bytes of */
						/* mem that can be registered */
	uint_t		hca_max_mem_win;	/* Max Memory windows in HCA */

	uint_t		hca_max_rsc; 		/* Max Responder Resources of */
						/* this HCA for RDMAR/Atomics */
						/* with this HCA as target. */
	uint8_t		hca_max_rdma_in_chan;	/* Max RDMAR/Atomics in per */
						/* chan this HCA as target. */
	uint8_t		hca_max_rdma_out_chan;	/* Max RDMA Reads/Atomics out */
						/* per channel by this HCA */
	uint_t		hca_max_ipv6_chan;	/* Max IPV6 channels in HCA */
	uint_t		hca_max_ether_chan;	/* Max Ether channels in HCA */

	uint_t		hca_max_mcg_chans;	/* Max number of channels */
						/* that can join multicast */
						/* groups */
	uint_t		hca_max_mcg;		/* Max multicast groups */
	uint_t		hca_max_chan_per_mcg;	/* Max number of channels per */
						/* Multicast group in HCA */
	uint16_t	hca_max_partitions;	/* Max partitions in HCA */

	ib_time_t	hca_local_ack_delay;

	uint_t		hca_max_port_sgid_tbl_sz;
	uint16_t	hca_max_port_pkey_tbl_sz;
	uint_t		hca_max_pd;		/* Max# of Protection Domains */

	uint_t		hca_max_ud_dest;
	uint_t		hca_max_srqs;		/* Max SRQs supported */
	uint_t		hca_max_srqs_sz;	/* Max outstanding WRs on any */
						/* SRQ */
	uint_t		hca_max_srq_sgl;	/* Max SGL entries per SRQ WR */
	uint_t		hca_max_cq_handlers;
	ibt_lkey_t	hca_reserved_lkey;	/* Reserved L_Key value */
	uint_t		hca_max_fmrs;		/* Max FMR Supported */

	uint_t		hca_max_lso_size;
	uint_t		hca_max_lso_hdr_size;
	uint_t		hca_max_inline_size;

	uint_t		hca_max_cq_mod_count;	/* CQ notify moderation */
	uint_t		hca_max_cq_mod_usec;

	uint32_t	hca_fw_major_version;	/* firmware version */
	uint16_t	hca_fw_minor_version;
	uint16_t	hca_fw_micro_version;

	/* detailed WQE size info */
	uint_t		hca_ud_send_inline_sz;	/* inline size in bytes */
	uint_t		hca_conn_send_inline_sz;
	uint_t		hca_conn_rdmaw_inline_overhead;
	uint_t		hca_recv_sgl_sz;	/* detailed SGL sizes */
	uint_t		hca_ud_send_sgl_sz;
	uint_t		hca_conn_send_sgl_sz;
	uint_t		hca_conn_rdma_sgl_overhead;
	int32_t		hca_pad;
} ibnex_ctl_hca_info_32_t;

/*
 * Data structure for IBNEX_CTL_QUERY_HCA
 */
typedef struct ibnex_ctl_query_hca_s {
	ib_guid_t	hca_guid;	/* in: HCA GUID */

	/*
	 * in: user allocated memory pointer for hca device path and number of
	 * bytes allocated for the hca device path.
	 */
	char		*hca_device_path;
	uint_t		hca_device_path_alloc_sz;

	ibnex_ctl_hca_info_t	hca_info;	/* out: HCA information */
} ibnex_ctl_query_hca_t;

typedef struct ibnex_ctl_query_hca_32_s {
	ib_guid_t	hca_guid;	/* in: HCA GUID */

	/*
	 * in: user allocated memory pointer for hca device path and number of
	 * bytes allocated for the hca device path.
	 */
	caddr32_t	hca_device_path;
	uint_t		hca_device_path_alloc_sz;

	ibnex_ctl_hca_info_32_t	hca_info;	/* out: HCA information */
} ibnex_ctl_query_hca_32_t;

/*
 * HCA port information structure
 */
typedef struct ibnex_ctl_hca_port_info_s {
	ib_lid_t		p_lid;		/* Base LID of port */
	ib_qkey_cntr_t		p_qkey_violations; /* Bad Q_Key cnt */
	ib_pkey_cntr_t		p_pkey_violations; /* Optional bad P_Key cnt */
	uint8_t			p_sm_sl;	/* SM Service level */
	ib_port_phys_state_t	p_phys_state;
	ib_lid_t		p_sm_lid;	/* SM LID */
	ibt_port_state_t	p_linkstate;	/* Port state */
	uint8_t			p_port_num;	/* Port number */

	ib_link_width_t		p_width_supported;
	ib_link_width_t		p_width_enabled;
	ib_link_width_t		p_width_active;

	ib_mtu_t		p_mtu;		/* Max transfer unit - pkt */
	uint8_t			p_lmc;		/* LID mask control */

	ib_link_speed_t		p_speed_supported;
	ib_link_speed_t		p_speed_enabled;
	ib_link_speed_t		p_speed_active;

	ib_gid_t		*p_sgid_tbl;	/* SGID Table */
	uint_t			p_sgid_tbl_sz;	/* # of entries in SGID table */

	ib_pkey_t		*p_pkey_tbl;	/* P_Key table */
	uint16_t		p_pkey_tbl_sz;	/* # of entries in P_Key tbl */
	uint16_t		p_def_pkey_ix;	/* default pkey index for TI */

	uint8_t			p_max_vl;	/* Max num of virtual lanes */
	uint8_t			p_init_type_reply; /* Optional InitTypeReply */
	ib_time_t		p_subnet_timeout; /* Max Subnet Timeout */
	ibt_port_caps_t		p_capabilities;	/* Port Capabilities */
	uint32_t		p_msg_sz;	/* Max message size */
} ibnex_ctl_hca_port_info_t;

typedef struct ibnex_ctl_hca_port_info_32_s {
	ib_lid_t		p_lid;		/* Base LID of port */
	ib_qkey_cntr_t		p_qkey_violations; /* Bad Q_Key cnt */
	ib_pkey_cntr_t		p_pkey_violations; /* Optional bad P_Key cnt */
	uint8_t			p_sm_sl;	/* SM Service level */
	ib_port_phys_state_t	p_phys_state;
	ib_lid_t		p_sm_lid;	/* SM LID */
	ibt_port_state_t	p_linkstate;	/* Port state */
	uint8_t			p_port_num;	/* Port number */

	ib_link_width_t		p_width_supported;
	ib_link_width_t		p_width_enabled;
	ib_link_width_t		p_width_active;

	ib_mtu_t		p_mtu;		/* Max transfer unit - pkt */
	uint8_t			p_lmc;		/* LID mask control */

	ib_link_speed_t		p_speed_supported;
	ib_link_speed_t		p_speed_enabled;
	ib_link_speed_t		p_speed_active;

	caddr32_t		p_sgid_tbl;	/* SGID Table */
	uint_t			p_sgid_tbl_sz;	/* # of entries in SGID table */

	caddr32_t		p_pkey_tbl;	/* P_Key table */
	uint16_t		p_pkey_tbl_sz;	/* # of entries in P_Key tbl */
	uint16_t		p_def_pkey_ix;	/* default pkey index for TI */

	uint8_t			p_max_vl;	/* Max num of virtual lanes */
	uint8_t			p_init_type_reply; /* Optional InitTypeReply */
	ib_time_t		p_subnet_timeout; /* Max Subnet Timeout */
	ibt_port_caps_t		p_capabilities;	/* Port Capabilities */
	uint32_t		p_msg_sz;	/* Max message size */
} ibnex_ctl_hca_port_info_32_t;

/*
 * Data structure for IBNEX_CTL_QUERY_HCA_PORT
 */
typedef struct ibnex_ctl_query_hca_port_s {
	ib_guid_t	hca_guid;		/* in: HCA GUID */
	uint_t		port_num;		/* in: port number */

	ib_gid_t	*sgid_tbl;		/* in: SGID Table */
	uint_t		sgid_tbl_alloc_sz; /* in: # of entries in SGID table */

	ib_pkey_t	*pkey_tbl;		/* in: P_Key table */
	uint_t		pkey_tbl_alloc_sz; /* in: # of entries in P_Key table */

	uint32_t	pad;
	ibnex_ctl_hca_port_info_t port_info;	/* out: port information */
} ibnex_ctl_query_hca_port_t;

typedef struct ibnex_ctl_query_hca_port_32_s {
	ib_guid_t	hca_guid;		/* in: HCA GUID */
	uint_t		port_num;		/* in: port number */

	caddr32_t	sgid_tbl;		/* in: SGID Table */
	uint_t		sgid_tbl_alloc_sz; /* in: # of entries in SGID table */

	caddr32_t	pkey_tbl;		/* in: P_Key table */
	uint_t		pkey_tbl_alloc_sz; /* in: # of entries in P_Key table */

	uint32_t	pad;
	ibnex_ctl_hca_port_info_32_t port_info;	/* out: port information */
} ibnex_ctl_query_hca_port_32_t;

#ifdef _KERNEL
_NOTE(SCHEME_PROTECTS_DATA("", ibnex_ctl_hca_info_s))
_NOTE(SCHEME_PROTECTS_DATA("", ibnex_ctl_hca_port_info_s))
_NOTE(SCHEME_PROTECTS_DATA("", ibnex_ctl_hca_port_info_32_s))
_NOTE(SCHEME_PROTECTS_DATA("", ibnex_ctl_query_hca_port_s))
_NOTE(SCHEME_PROTECTS_DATA("", ibnex_ctl_query_hca_port_32_s))
#endif


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_IBNEX_IBNEX_DEVCTL_H */
