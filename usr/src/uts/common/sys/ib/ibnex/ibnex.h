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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_IB_IBNEX_IBNEX_H
#define	_SYS_IB_IBNEX_IBNEX_H

/*
 * ibnex.h
 * This file contains defines and structures used within the IB Nexus
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/sunndi.h>

/* Defines for return codes within the IB nexus driver */
typedef enum {
	IBNEX_SUCCESS =	0,
	IBNEX_FAILURE = -1,
	IBNEX_OFFLINE_FAILED = -2,
	IBNEX_BUSY = -3,
	IBNEX_INVALID_NODE = -4
} ibnex_rval_t;

#define	IBNEX_IOC_GUID_LEN	33
#define	IBNEX_PHCI_GUID_LEN	66

/* IOC device node specific data */
typedef struct ibnex_ioc_node_s {
	ib_guid_t		iou_guid;	/* GUID of the IOU */
	ib_guid_t		ioc_guid;	/* GUID of the IOC */
	char			ioc_id_string[IB_DM_IOC_ID_STRING_LEN];
	uint32_t		ioc_ngids;
	/* This field will be non NULL only for diconnected IOCs */
	ib_dm_ioc_ctrl_profile_t	*ioc_profile;
	char				ioc_guid_str[IBNEX_IOC_GUID_LEN];
	char				ioc_phci_guid[IBNEX_PHCI_GUID_LEN];
} ibnex_ioc_node_t;

/* DLPI device node specific data */
typedef struct ibnex_port_node_s {
	uint8_t			port_num;
	int			port_commsvc_idx;
	ib_guid_t		port_guid;
	ib_guid_t		port_hcaguid;
	ib_pkey_t		port_pkey;
	dev_info_t		*port_pdip;
} ibnex_port_node_t;

/* Pseudo device node specific data */
typedef struct ibnex_pseudo_node_s {
	char			*pseudo_node_addr;	/* node addr of drvr */
	char			*pseudo_unit_addr;	/* unit addr of drvr */
	int			pseudo_unit_addr_len;	/* unit addr len */
	char			*pseudo_devi_name;	/* name of driver */
	int			pseudo_merge_node;	/* merge node */
} ibnex_pseudo_node_t;

/*
 * Defines for Child device node types. Note that these values are also
 * in use by usr/src/lib/cfgadm_plugins/ib/common/cfga_ib.h.
 * Any changes to these need to be reflected in that file as well.
 */
typedef enum {
	IBNEX_PORT_COMMSVC_NODE		= 0,
	IBNEX_VPPA_COMMSVC_NODE		= 1,
	IBNEX_HCASVC_COMMSVC_NODE	= 2,
	IBNEX_IOC_NODE			= 4,
	IBNEX_PSEUDO_NODE		= 8
} ibnex_node_type_t;

#define	IBNEX_HCA_CHILD_NODE (IBNEX_PORT_COMMSVC_NODE |	\
	    IBNEX_VPPA_COMMSVC_NODE | IBNEX_HCASVC_COMMSVC_NODE)


/*
 * Defines for Child device node state:
 *
 * By default the node is set to CONFIGURED state.
 *	CONFIGURED:---(bus_config/cfgadm configure)---->CONFIGURED
 *	CONFIGURED:----(cfgadm unconfigure:success)--->UNCONFIGURED
 *	CONFIGURED:----(cfgadm unconfigure:fail)--->still CONFIGURED
 *	UNCONFIGURED:----(cfgadm configure:success)--->CONFIGURED
 *
 * We maintain two additional states:
 *	CONFIGURING:---(bus_config/cfgadm configure in progress
 *	UNCONFIGURING:--(cfgadm unconfigure in progress)
 * This is maintained to avoid race conditions between multiple cfgadm
 * operations.
 */
typedef enum ibnex_node_state_e {
	IBNEX_CFGADM_CONFIGURED,	/* node is "configured" */
	IBNEX_CFGADM_UNCONFIGURED,	/* node is "unconfigured" */
	IBNEX_CFGADM_CONFIGURING,	/* node getting configured */
	IBNEX_CFGADM_UNCONFIGURING	/* node getting unconfigured */
} ibnex_node_state_t;

/*
 * Defines for reprobe_state:
 * 	IBNEX_NODE_REPROBE_NOTIFY_ON_UPDATE
 *		Reprobe and notify if there is a property update
 *	IBNEX_NODE_REPROBE_NOTIFY_ALWAYS
 *		Reprobe and notify always.
 *	IBNEX_NODE_REPROBE_IOC_WAIT
 *		Reprobe for IOC apid waiting
 *
 * Device reprobes triggered by ibt_reprobe_dev will result in an DDI
 * event, even though no prepoerties have changed.
 */

/*
 * Defines for node_ap_state:
 * IBNEX_NODE_AP_CONFIGURED
 * 	this node was not unconfigured by cfgadm.
 * IBNEX_NODE_AP_UNCONFIGURED
 * 	this node has been unconfigured by cfgadm.
 * IBNEX_NODE_AP_CONFIGURING
 * 	this node is being configured by cfgadm
 */
#define	IBNEX_NODE_AP_CONFIGURED	0x0
#define	IBNEX_NODE_AP_UNCONFIGURED	0x1
#define	IBNEX_NODE_AP_CONFIGURING	0x2

#define	IBNEX_NODE_REPROBE_NOTIFY_ON_UPDATE	0x01
#define	IBNEX_NODE_REPROBE_NOTIFY_ALWAYS	0x02
#define	IBNEX_NODE_REPROBE_IOC_WAIT			0x04

/* Node specific information, stored as dev_info_t private data */
typedef struct ibnex_node_data_s {
	dev_info_t		*node_dip;
	union {
		ibnex_ioc_node_t	ioc_node;
		ibnex_port_node_t	port_node;
		ibnex_pseudo_node_t	pseudo_node;
	} node_data;
	struct ibnex_node_data_s *node_next;
	struct ibnex_node_data_s *node_prev;
	ibnex_node_type_t	node_type;
	ibnex_node_state_t	node_state;
	int			node_reprobe_state;	/* Node reprobe flag */
	unsigned int		node_ap_state;
} ibnex_node_data_t;

/*
 * The fields of IOC and Port node are initialized when the
 * device node is created. These are read only for the rest
 * of the IBnexus driver.
 */
_NOTE(SCHEME_PROTECTS_DATA("stable data", ibnex_ioc_node_s))
_NOTE(SCHEME_PROTECTS_DATA("stable data", ibnex_port_node_s))
_NOTE(SCHEME_PROTECTS_DATA("stable data", ibnex_pseudo_node_s))
_NOTE(SCHEME_PROTECTS_DATA("stable data", ibnex_node_data_s))

#define	IBNEX_VALID_NODE_TYPE(n)	\
	(((n)->node_type == IBNEX_PORT_COMMSVC_NODE) || \
	((n)->node_type == IBNEX_VPPA_COMMSVC_NODE) || \
	((n)->node_type == IBNEX_HCASVC_COMMSVC_NODE) || \
	((n)->node_type == IBNEX_IOC_NODE) || \
	((n)->node_type == IBNEX_PSEUDO_NODE))

#define	IBNEX_COMMSVC_NODE_TYPE(n)	\
	(((n)->node_type == IBNEX_PORT_COMMSVC_NODE) || \
	((n)->node_type == IBNEX_VPPA_COMMSVC_NODE) || \
	((n)->node_type == IBNEX_HCASVC_COMMSVC_NODE))

/*
 * Definition for the IB nexus global per-instance structure.
 * IB nexus supports only one instance.
 */
typedef struct ibnex_s {
	dev_info_t		*ibnex_dip;
	kmutex_t		ibnex_mutex;
	int			ibnex_num_comm_svcs;
	char			**ibnex_comm_svc_names;
	int			ibnex_nvppa_comm_svcs;
	char			**ibnex_vppa_comm_svc_names;
	int			ibnex_nhcasvc_comm_svcs;
	char			**ibnex_hcasvc_comm_svc_names;
	ibnex_node_data_t	*ibnex_port_node_head;
	ibnex_node_data_t	*ibnex_ioc_node_head;
	ibnex_node_data_t	*ibnex_pseudo_node_head;

	/*
	 * NDI Event handle for -all- ibnexus events
	 * Event Cookie for IB_PROP_UPDATE_EVENT event
	 */
	ndi_event_hdl_t		ibnex_ndi_event_hdl;
	ddi_eventcookie_t	ibnex_prop_update_evt_cookie;

	/* Flags & condition variables for reprobe handling */
	int					ibnex_reprobe_state;
	kcondvar_t			ibnex_reprobe_cv;

	/* Count of disconnected IOCs still configured */
	int					ibnex_num_disconnect_iocs;

	/* Pseudo nodes inited from ibnex_get_snapshot? */
	int			ibnex_pseudo_inited;
	/*
	 * IOC list used by all HCAs.
	 */
	kcondvar_t		ibnex_ioc_list_cv;
	uint32_t		ibnex_ioc_list_state;
	ibdm_ioc_info_t		*ibnex_ioc_list;

	ddi_taskq_t		*ibnex_taskq_id;
} ibnex_t;

/*
 * States for ibnex_ioc_list_state
 */
#define	IBNEX_IOC_LIST_READY	0x0
#define	IBNEX_IOC_LIST_RENEW	0x1
#define	IBNEX_IOC_LIST_ACCESS	0x2

/*
 * States for ibnex_reprobe_state
 *	0 to REPROBE_ALL_PROGRESS
 *		Reprobe all when no reprobes pending
 *	REPROBE_ALL_PROGRESS to REPROBE_ALL_WAIT
 *		Reprobe all request when another in progress
 *	0 to REPROBE_IOC_WAIT
 *		Waiting for One or more reprobe_ioc to complete
 *
 * Reprobe logic will ensure :
 *	1. A single reprobe all at any time.
 *	2. No individual IOC reprobe overlaps with reprobe all.
 *	3. Reprobe for multiple IOCs can be in parallel
 *	4. Single reprobe for each IOC.
 */
#define	IBNEX_REPROBE_ALL_PROGRESS	0x01
#define	IBNEX_REPROBE_ALL_WAIT		0x02
#define	IBNEX_REPROBE_IOC_WAIT		0x04

/* Defines for creating and binding device nodes.  */
#define	IBNEX_MAX_COMPAT_NAMES		6
#define	IBNEX_MAX_IBPORT_COMPAT_NAMES	3
#define	IBNEX_MAX_COMPAT_LEN		48
#define	IBNEX_MAX_COMPAT_PROP_SZ	\
	IBNEX_MAX_COMPAT_NAMES * IBNEX_MAX_COMPAT_LEN
#define	IBNEX_MAX_IBPORT_COMPAT_PROP_SZ	\
	IBNEX_MAX_IBPORT_COMPAT_NAMES * IBNEX_MAX_COMPAT_LEN
#define	IBNEX_DEVFS_ENUMERATE		0x1	/* enumerate via devfs(7fs) */
#define	IBNEX_CFGADM_ENUMERATE		0x2	/* enumerate via cfgadm */

#define	IBNEX_MAX_NODEADDR_SZ		35

/* Define for forming the unit address from GUID and class string */
#define	IBNEX_FORM_GUID(buf, size, guid) \
		(void) snprintf((buf), (size), "%llX", (longlong_t)guid);

#define	IBNEX_INVALID_PKEY(pkey)	\
		(((pkey) == IB_PKEY_INVALID_FULL) || \
		((pkey) == IB_PKEY_INVALID_LIMITED))

/*
 * Defines for the tags of IB DDI events
 */
typedef enum {
		IB_EVENT_TAG_PROP_UPDATE = 0
} ib_ddi_event_tag_t;

/* Definations for IB HW in device tree status */
#define	IBNEX_DEVTREE_NOT_CHECKED	-1
#define	IBNEX_HW_NOT_IN_DEVTREE		0
#define	IBNEX_HW_IN_DEVTREE		1

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_IBNEX_IBNEX_H */
