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

#ifndef _CFGA_IB_H
#define	_CFGA_IB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <strings.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <libintl.h>
#include <sys/types32.h>
#include <sys/varargs.h>
#include <sys/ib/ibnex/ibnex_devctl.h>
#include <libdevinfo.h>
#include <libdevice.h>
#include <librcm.h>
#include <synch.h>
#include <thread.h>
#include <assert.h>

#define	CFGA_PLUGIN_LIB
#include <config_admin.h>


/*
 * Debug stuff.
 */
#ifdef	DEBUG
#define	DPRINTF	printf
#else
#define	DPRINTF 0 &&
#endif /* DEBUG */


/* for walking links */
typedef struct walk_link {
	char *path;
	char len;
	char **linkpp;
} walk_link_t;


/*
 * Stuff carried over for the routines borrowed from cfgadm/SCSI.
 */
#define	MATCH_MINOR_NAME	1
#define	S_FREE(x)	(((x) != NULL) ? (free(x), (x) = NULL) : (void *)0)

/* Return/error codes */
typedef enum {
	ICFGA_ERR = -2,
	ICFGA_LIB_ERR,
	ICFGA_OK,
	ICFGA_BUSY,
	ICFGA_NO_REC
} icfga_ret_t;


/* Error Messages */
typedef struct {
	int		intl;		/* Flag: if 1, internationalize */
	cfga_err_t	cfga_err;	/* Error code for libcfgadm */
	const char	*msgstr;
} msgcvt_t;

/* "intl" defines */
#define	NO_CVT			0
#define	CVT			1

#define	MSG_TBL_SZ(table)	(sizeof ((table)) / sizeof (msgcvt_t))


/* Error message ids (and indices into ib_error_msgs) "cfga_err values " */
typedef enum {
	CFGA_IB_OK = 0,			/* Plugin Related Errors */
	CFGA_IB_UNKNOWN,
	CFGA_IB_INTERNAL_ERR,
	CFGA_IB_INVAL_ARG_ERR,
	CFGA_IB_OPTIONS_ERR,
	CFGA_IB_AP_ERR,
	CFGA_IB_DEVCTL_ERR,
	CFGA_IB_NOT_CONNECTED,
	CFGA_IB_NOT_CONFIGURED,
	CFGA_IB_ALREADY_CONNECTED,
	CFGA_IB_ALREADY_CONFIGURED,
	CFGA_IB_CONFIG_OP_ERR,
	CFGA_IB_UNCONFIG_OP_ERR,
	CFGA_IB_OPEN_ERR,
	CFGA_IB_IOCTL_ERR,
	CFGA_IB_BUSY_ERR,
	CFGA_IB_ALLOC_FAIL,
	CFGA_IB_OPNOTSUPP,
	CFGA_IB_INVAL_APID_ERR,
	CFGA_IB_DEVLINK_ERR,
	CFGA_IB_PRIV_ERR,
	CFGA_IB_NVLIST_ERR,
	CFGA_IB_HCA_LIST_ERR,
	CFGA_IB_HCA_UNCONFIG_ERR,
	CFGA_IB_UPD_PKEY_TBLS_ERR,
	CFGA_IB_CONFIG_FILE_ERR,
	CFGA_IB_LOCK_FILE_ERR,
	CFGA_IB_UNLOCK_FILE_ERR,
	CFGA_IB_COMM_INVAL_ERR,
	CFGA_IB_SVC_INVAL_ERR,
	CFGA_IB_SVC_LEN_ERR,
	CFGA_IB_SVC_EXISTS_ERR,
	CFGA_IB_SVC_NO_EXIST_ERR,
	CFGA_IB_UCFG_CLNTS_ERR,
	CFGA_IB_INVALID_OP_ERR,

	CFGA_IB_RCM_HANDLE_ERR,		/* Plugin's RCM Related Errors */
	CFGA_IB_RCM_ONLINE_ERR,
	CFGA_IB_RCM_OFFLINE_ERR
} cfga_ib_ret_t;


/*
 * Given an error msg index, look up the associated string, and
 * convert it to the current locale if required.
 */
#define	ERR_STR(msg_idx) \
	    (ib_get_msg((msg_idx), ib_error_msgs, MSG_TBL_SZ(ib_error_msgs)))

/* Defines for "usage" */
#define	CFGA_IB_HELP_HEADER	1	/* Header only */
#define	CFGA_IB_HELP_CONFIG	2	/* -c usage help */
#define	CFGA_IB_HELP_LIST	3	/* -x list_clients usage help */
#define	CFGA_IB_HELP_UPD_PKEY	4	/* -x update_pkey_tbls usage help */
#define	CFGA_IB_HELP_CONF_FILE1	5	/* -x [add_service|delete_service] */
#define	CFGA_IB_HELP_CONF_FILE2	6	/* -x list_services help */
#define	CFGA_IB_HELP_UPD_IOC_CONF	\
				7	/* -x update_ioc_config help */
#define	CFGA_IB_HELP_UNCFG_CLNTS \
				8	/* -x unconfig_clients usage help */
#define	CFGA_IB_HELP_UNKNOWN	9	/* unknown help */

#define	IB_RETRY_DEVPATH	12	/* devicepath show up: retry count */
#define	IB_MAX_DEVPATH_DELAY	6	/* sleep for 6 seconds */
#define	IB_NUM_NVPAIRS		6	/* for "info", "ap_id" etc. */

/* Misc text strings */
#define	CFGA_DEV_DIR			"/dev/cfg"
#define	IB_STATIC_APID			"/dev/cfg/ib"
#define	MINOR_SEP			":"
#define	IB_APID				"apid"
#define	IB_CFGADM_DEFAULT_AP_TYPE	"unknown"
#define	IB_PORT_TYPE			"IB-PORT"
#define	IB_FABRIC_INFO			"InfiniBand Fabric"
#define	IB_HCA_TYPE			"IB-HCA"
#define	IB_IOC_TYPE			"IB-IOC"
#define	IB_VPPA_TYPE			"IB-VPPA"
#define	IB_HCASVC_TYPE			"IB-HCA_SVC"
#define	IB_PSEUDO_TYPE			"IB-PSEUDO"
#define	IB_FABRIC_TYPE			"IB-Fabric"
#define	IB_FABRIC_APID_STR		"ib:fabric"

/* -x commands */
#define	IB_LIST_HCA_CLIENTS		"list_clients"		/* list HCA's */
								/* clients */
#define	IB_UNCONFIG_HCA_CLIENTS		"unconfig_clients"	/* unconfig */
								/* HCA's */
								/* clients */
#define	IB_UPDATE_PKEY_TBLS		"update_pkey_tbls"	/* re-read */
								/* P_Keys */
#define	IB_ADD_SERVICE			"add_service"		/* add svc */
#define	IB_DELETE_SERVICE		"delete_service"	/* delete svc */
#define	IB_LIST_SERVICES		"list_services"		/* list svcs */
#define	IB_UPDATE_IOC_CONF		"update_ioc_config"	/* update IOC */
								/* config */

/* for confirm operation */
#define	IB_CONFIRM1 \
	"This operation will suspend activity on the IB device\nContinue"
#define	IB_CONFIRM3 \
	"This operation will unconfigure IB clients of this HCA\nContinue"
#define	IB_CONFIRM4 \
	"This operation will update P_Key tables for all ports of all HCAs"
#define	IB_CONFIRM5 \
	"This operation can update properties of IOC devices."

/*
 * Export "node_type"s from ibnex_node_type_t (see ibnex.h) to
 * cfgadm in user land. NOTE: If ibnex_node_type_t changes in
 * ibnex.h; do not forget to update these values here as well.
 */
#define	IBNEX_PORT_NODE_TYPE		0
#define	IBNEX_VPPA_NODE_TYPE		1
#define	IBNEX_HCASVC_NODE_TYPE		2
#define	IBNEX_IOC_NODE_TYPE		3
#define	IBNEX_PSEUDO_NODE_TYPE		4

/* for ib.conf file support */
#define	IBCONF_ADD_ENTRY		1
#define	IBCONF_DELETE_ENTRY		2

#ifdef __cplusplus
}
#endif

#endif /* _CFGA_IB_H */
