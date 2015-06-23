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
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SYS_IB_MGT_IBDM_IBDM_IBNEX_H
#define	_SYS_IB_MGT_IBDM_IBDM_IBNEX_H

/*
 * This file contains the definitions of private interfaces
 * and data structures used between IB nexus and IBDM.
 */

#include <sys/ib/ibtl/ibti_common.h>
#include <sys/ib/mgt/ibmf/ibmf.h>
#include <sys/ib/mgt/ib_dm_attr.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DM return status codes from private interfaces */
typedef enum ibdm_status_e {
	IBDM_SUCCESS = 0,
	IBDM_FAILURE = 1
} ibdm_status_t;

/*
 * IBDM events that are passed to IB nexus driver
 * NOTE: These are different from ibt_async_code_t
 */
typedef enum ibdm_events_e {
	IBDM_EVENT_HCA_ADDED,
	IBDM_EVENT_HCA_REMOVED,
	IBDM_EVENT_IOC_PROP_UPDATE,
	IBDM_EVENT_PORT_UP,
	IBDM_EVENT_PORT_PKEY_CHANGE
} ibdm_events_t;

/*
 * Flags for ibdm_ibnex_get_ioc_list.
 * The flags determine the functioning of ibdm_ibnex_get_ioc_list.
 *
 * 	IBDM_IBNEX_NORMAL_PROBE
 *		Sweep fabric and discover new GIDs only
 *		This value should be same as IBNEX_PROBE_ALLOWED_FLAG
 *	IBDM_IBNEX_DONOT_PROBE
 *		Do not probe, just get the current ioc_list.
 *		This value should be same as IBNEX_DONOT_PROBE_FLAG
 *	IBDM_IBNEX_REPROBE_ALL
 *		Sweep fabric, discover new GIDs. For GIDs
 *		discovered before, reprobe the IOCs on it.
 */
typedef enum ibdm_ibnex_get_ioclist_mtd_e {
	IBDM_IBNEX_NORMAL_PROBE,
	IBDM_IBNEX_DONOT_PROBE,
	IBDM_IBNEX_REPROBE_ALL
} ibdm_ibnex_get_ioclist_mtd_t;


/*
 * Private data structure called from IBDM timeout handler
 */
typedef struct ibdm_timeout_cb_args_s {
	struct ibdm_dp_gidinfo_s	*cb_gid_info;
	int				cb_req_type;
	int				cb_ioc_num;		/* IOC# */
	int				cb_retry_count;
	int				cb_srvents_start;
	int				cb_srvents_end;
} ibdm_timeout_cb_args_t;

/*
 * Service entry structure
 */
typedef struct ibdm_srvents_info_s {
	int				se_state;
	ib_dm_srv_t			se_attr;
	timeout_id_t			se_timeout_id;	/* IBDM specific */
	ibdm_timeout_cb_args_t		se_cb_args;
} ibdm_srvents_info_t;

/* values for "se_state" */
#define	IBDM_SE_VALID			0x1
#define	IBDM_SE_INVALID			0x0


/* I/O Controller information */
typedef struct ibdm_ioc_info_s {
	ib_dm_ioc_ctrl_profile_t	ioc_profile;
	int				ioc_state;
	ibdm_srvents_info_t		*ioc_serv;
	struct ibdm_gid_s		*ioc_gid_list;
	uint_t				ioc_nportgids;
	ib_guid_t			ioc_iou_guid;
	timeout_id_t			ioc_timeout_id;
	timeout_id_t			ioc_dc_timeout_id;
	boolean_t			ioc_dc_valid;
	boolean_t			ioc_iou_dc_valid;
	ibdm_timeout_cb_args_t		ioc_cb_args;
	ibdm_timeout_cb_args_t		ioc_dc_cb_args;
	ib_guid_t			ioc_nodeguid;
	uint16_t			ioc_diagcode;
	uint16_t			ioc_iou_diagcode;
	uint16_t			ioc_diagdeviceid;
	struct ibdm_iou_info_s		*ioc_iou_info;
	struct ibdm_ioc_info_s 		*ioc_next;

	/* Previous fields for reprobe */
	ibdm_srvents_info_t		*ioc_prev_serv;
	struct ibdm_gid_s		*ioc_prev_gid_list;
	uint8_t				ioc_prev_serv_cnt;
	uint_t				ioc_prev_nportgids;

	/* Flag indicating which IOC info has changed */
	ibt_prop_update_payload_t	ioc_info_updated;

	/*
	 * List of HCAs through which IOC is accessible
	 * This field will be initialized in ibdm_ibnex_probe_ioc
	 * and ibdm_get_ioc_list for all IOCs in the fabric.
	 *
	 * HCAs could have been added or deleted from the list,
	 * on calls to ibdm_ibnex_get_ioc_list & ibdm_ibnex_probe_ioc.
	 *
	 * Updates to HCAs in the list will be reported by
	 * IBDM_EVENT_HCA_DOWN and IBDM_EVENT_IOC_HCA_UNREACHABLE events
	 * in the IBDM<->IBDM callback.
	 *
	 * IOC not visible to the host system(because all HCAs cannot
	 * reach the IOC) will be reported in the same manner as TCA
	 * ports getting to 0 (using IOC_PROP_UPDATE event).
	 */
	struct ibdm_hca_list_s			*ioc_hca_list;

} ibdm_ioc_info_t;
_NOTE(SCHEME_PROTECTS_DATA("Serialized access by cv",
	ibdm_ioc_info_s::ioc_next))
_NOTE(SCHEME_PROTECTS_DATA("Unique per copy of ibdm_ioc_info_t",
	ibdm_ioc_info_s::ioc_info_updated))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibdm_ioc_info_s::ioc_dc_valid))

/* values for "ioc_state */
#define	IBDM_IOC_STATE_PROBE_SUCCESS	0x0
#define	IBDM_IOC_STATE_PROBE_INVALID	0x1
#define	IBDM_IOC_STATE_PROBE_FAILED	0x2
#define	IBDM_IOC_STATE_REPROBE_PROGRESS	0x4

/* I/O Unit Information */
typedef struct ibdm_iou_info_s {
	ib_dm_io_unitinfo_t	iou_info;
	ibdm_ioc_info_t		*iou_ioc_info;
	ib_guid_t		iou_guid;
	boolean_t		iou_dc_valid;
	uint16_t		iou_diagcode;
	int			iou_niocs_probe_in_progress;
} ibdm_iou_info_t;


/* P_Key table related info */
typedef struct ibdm_pkey_tbl_s {
	ib_pkey_t		pt_pkey;		/* P_Key value */
	ibmf_qp_handle_t	pt_qp_hdl;		/* QP handle */
} ibdm_pkey_tbl_t;
_NOTE(SCHEME_PROTECTS_DATA("Serialized access by cv", ibdm_pkey_tbl_s))


/*
 * Port Attributes structure
 */
typedef struct ibdm_port_attr_s {
	ibdm_pkey_tbl_t		*pa_pkey_tbl;
	ib_guid_t		pa_hca_guid;
	ib_guid_t		pa_port_guid;
	uint16_t		pa_npkeys;
	ibmf_handle_t		pa_ibmf_hdl;
	ib_sn_prefix_t		pa_sn_prefix;
	uint16_t		pa_port_num;
	uint32_t		pa_vendorid;
	uint32_t		pa_productid;
	uint32_t		pa_dev_version;
	ibt_port_state_t	pa_state;
	ibmf_saa_handle_t	pa_sa_hdl;
	ibmf_impl_caps_t	pa_ibmf_caps;
	ibt_hca_hdl_t		pa_hca_hdl;
} ibdm_port_attr_t;
_NOTE(SCHEME_PROTECTS_DATA("Serialized access by cv", ibdm_port_attr_s))

/*
 * HCA list structure.
 */
typedef struct ibdm_hca_list_s {
	ibdm_port_attr_t	*hl_port_attr;		/* port attributes */
	struct ibdm_hca_list_s	*hl_next;		/* ptr to next list */
	ib_guid_t		hl_hca_guid;		/* HCA GUID */
	uint32_t		hl_nports;		/* #ports of this HCA */
	uint32_t		hl_nports_active;	/* #ports active */
	hrtime_t		hl_attach_time;		/* attach time */
	ibt_hca_hdl_t		hl_hca_hdl;		/* HCA handle */
	ibdm_port_attr_t	*hl_hca_port_attr;	/* Dummy Port Attr */
							/* for HCA node */
} ibdm_hca_list_t;
_NOTE(SCHEME_PROTECTS_DATA("Serialized access by cv", ibdm_hca_list_s))

/*
 * The DM callback definitions
 *
 * ibdm_callback_t
 *	Pointer to DM callback function
 *	IBDM notifies IB nexus of ibdm_event_t using this callback.
 * Arguments
 *	arg	: The value of "arg" depends on the "event"
 *		IBDM_EVENT_CREATE_HCA_NODE	(pointer to HCA GUID)
 *		IBDM_EVENT_REMOVE_HCA_NODE	(pointer to HCA GUID)
 *		IBDM_EVENT_IOC_PROP_UPDATE	(ibdm_ioc_info_t *)
 *
 *	event 	: ibdm_event_t values
 *
 * Returns		: None
 *
 */
typedef void (*ibdm_callback_t)(void *arg, ibdm_events_t event);


/*
 * DM interface functions
 */

/*
 * ibdm_ibnex_register_callback
 *	Register the IB nexus IBDM callback routine
 *
 * Arguments		: IB nexus IBDM callback routine
 * Return Values	: None
 */
void		ibdm_ibnex_register_callback(ibdm_callback_t cb);

/*
 * ibdm_ibnex_unregister_callback
 *	Unregister IB nexus DM callback with IBDM
 *
 * Arguments		: None
 * Return Values	: None
 */
void		ibdm_ibnex_unregister_callback();


/*
 * PORT devices handling interfaces.
 *
 * ibdm_ibnex_probe_hcaport
 *	Probes the HCA port. If found, returns the port attributes.
 *	Caller is responsible for  freeing the memory for the port
 *	attribute structure by calling ibdm_ibnex_free_port_attr()
 *
 * Arguments		: GUID of the HCA and port number
 * Return Values	: ibdm_port_attr_t on SUCCESS, NULL on FAILURE.
 */
ibdm_port_attr_t *ibdm_ibnex_probe_hcaport(ib_guid_t, uint8_t);

/*
 * ibdm_ibnex_get_port_attrs
 *	Scans the HCA ports for a matching port_guid. If found,
 *	returns the port attributes.
 *	Caller is responsible for freeing the memory for the port
 *	attribute structure by calling ibdm_ibnex_free_port_attr()
 *
 * Arguments		: GUID of the port
 * Return Values	: ibdm_port_attr_t on SUCCESS, NULL on FAILURE.
 */
ibdm_port_attr_t *ibdm_ibnex_get_port_attrs(ib_guid_t);

/*
 * ibdm_ibnex_free_port_attr()
 *	Deallocates the memory from ibnex_get_dip_from_port_guid() and
 *	ibdm_ibnex_get_port_attrs() functions.
 */
void		ibdm_ibnex_free_port_attr(ibdm_port_attr_t *);


/*
 * IOC devices handling interfaces.
 *
 * ibdm_ibnex_probe_ioc
 *	Probes the  IOC device on the fabric. If found, allocates and
 *	returns pointer to the ibdm_ioc_info_t. Caller is responsible
 *	to free the memory for the ioc attribute structure by calling
 *	ibdm_ibnex_free_ioc_list.
 *
 * Arguments		:
 *	GUID of the IOU and GUID of the IOC
 *	reprobe_flag - Set if IOC information has to be reprobed.
 * Return Values	: ibdm_ioc_info_t on SUCCESS, NULL on FAILURE.
 */
ibdm_ioc_info_t	*ibdm_ibnex_probe_ioc(ib_guid_t iou_guid, ib_guid_t ioc_guid,
    int reprobe_flag);

/*
 * ibdm_ibnex_get_ioc_count
 *	Returns number of IOCs currently discovered in the fabric.
 * Arguments	  : NONE
 * Return Values  : number of IOCs seen
 */
int	ibdm_ibnex_get_ioc_count(void);

/*
 * ibdm_ibnex_get_ioc_list
 *	Returns linked list of ibdm_ioc_info_t structures for all the
 *	IOCs  present on the fabric. Caller is responsible for freeing
 *	the  memory allocated for the ioc  attribute  structure(s) by
 *	calling ibdm_ibnex_free_ioc_list().
 *
 * Arguments	  : list_flag :
 *		Get list according to ibdm_ibnex_get_ioclist_mtd_t defination.
 * Return Values  : IOC list based containing "ibdm_ioc_info_t"s if
 *			  successful, otherwise NULL.
 */
ibdm_ioc_info_t	*ibdm_ibnex_get_ioc_list(ibdm_ibnex_get_ioclist_mtd_t);

/*
 * ibdm_ibnex_get_ioc_info
 *	Returns pointer  ibdm_ioc_info_t structures for the request
 *	"ioc_guid".  Caller is  responsible to  free the  memory by
 *	calling ibdm_ibnex_free_ioc_list() when the return value is
 *	not NULL.
 *
 * Arguments		: GUID of the IOC
 * Return Values	: Address of kmem_alloc'ed memory if the IOC exists,
 *			  otherwise NULL.
 */
ibdm_ioc_info_t *ibdm_ibnex_get_ioc_info(ib_guid_t ioc_guid);

/*
 * ibdm_ibnex_free_ioc_list()
 *	Deallocates the memory from ibdm_ibnex_probe_ioc(),
 *	ibdm_ibnex_get_ioc_list() and ibdm_ibnex_get_ioc_info()
 */
void		ibdm_ibnex_free_ioc_list(ibdm_ioc_info_t *);

/*
 * HCA handling interfaces.
 *
 * ibdm_ibnex_get_hca_list
 *	Returns linked list of ibdm_hca_list_t structures for all
 *	the HCAs present on the fabric. Caller is responsible for
 *	freeing the memory for the hca attribute structure(s) by
 *	calling ibdm_ibnex_free_hca_list().
 *
 * Arguments		: "hca" contains pointer to pointer of ibdm_hca_list_t
 *			: "cnt" contains pointer to number of hca's
 * Return Values	: None
 */
void		ibdm_ibnex_get_hca_list(ibdm_hca_list_t **hca, int *cnt);

/*
 * ibdm_ibnex_get_hca_info_by_guid
 *	Returns a linked list of ibdm_hca_list_t structure that matches the
 *	given argument. The caller is responsible for freeing the memory for
 *	the hca attribute structure by calling ibdm_ibnex_free_hca_list().
 *
 * Arguments		: HCA GUID
 * Return Values	: Linked list of ibdm_hca_list_t(s)
 */
ibdm_hca_list_t *ibdm_ibnex_get_hca_info_by_guid(ib_guid_t);

/*
 * ibdm_ibnex_free_hca_list()
 *	Deallocates the memory from ibdm_ibnex_get_hca_list() and
 *	ibdm_ibnex_get_hca_info_by_guid() functions.
 */
void		ibdm_ibnex_free_hca_list(ibdm_hca_list_t *);

/*
 * ibdm_ibnex_update_pkey_tbls
 *	Updates the DM P_Key database.
 *
 * Arguments		: NONE
 * Return Values	: NONE
 */
void	ibdm_ibnex_update_pkey_tbls(void);

/*
 * ibdm_ibnex_port_settle_wait
 *	Wait until the ports come up
 *
 * Arguments
 *      HCA GUID and the maximum wait time since the hca instance attach
 */
void	ibdm_ibnex_port_settle_wait(ib_guid_t, int);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_MGT_IBDM_IBDM_IBNEX_H */
