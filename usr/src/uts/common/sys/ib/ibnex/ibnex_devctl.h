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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_IBNEX_IBNEX_DEVCTL_H
#define	_SYS_IB_IBNEX_IBNEX_DEVCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_IBNEX_IBNEX_DEVCTL_H */
