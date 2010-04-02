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

#ifndef _SYS_IB_IBTL_IMPL_IBTL_CM_H
#define	_SYS_IB_IBTL_IMPL_IBTL_CM_H

/*
 * ibtl_cm.h
 *
 * All data structures and function prototypes that are specific to the
 * IBTL <-> IBCM private interface.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ibt_ud_dest_t is defined in ibtl_ci_types.h, it holds all the
 * information needed to reach a UD destination.
 *
 *	typedef struct ibt_ud_dest_s {
 *		ibc_ah_hdl_t		ud_ah;		* Address handle *
 *		ib_qpn_t		ud_dst_qpn;	* Destination QPN *
 *		ib_qkey_t		ud_qkey;	* Q_Key *
 *
 *		* The following fields are CM-only, i.e., opaque to the CI *
 *		struct ibtl_hca_s	*ud_hca;	* IBTL HCA handle *
 *	} ibt_ud_dest_t;
 */
#define	ud_dest_hca	ud_dest_opaque1

/* CM private data */
void ibtl_cm_set_chan_private(ibt_channel_hdl_t chan, void *cm_private);
void *ibtl_cm_get_chan_private(ibt_channel_hdl_t chan);
void ibtl_cm_release_chan_private(ibt_channel_hdl_t chan);
void ibtl_cm_wait_chan_private(ibt_channel_hdl_t chan);

/*
 * ibtl_cm_get_hca_port() helper function will retrieve these for the
 * specified SGID value.
 */
typedef struct ibtl_cm_hca_port_s {
	ib_guid_t	hp_hca_guid;	/* HCA GUID. */
	ib_guid_t	hp_port_guid;   /* Port GUID. */
	ib_lid_t	hp_base_lid;	/* Base LID of Port. */
	uint8_t		hp_port;	/* HCA Port Number. */
	uint8_t		hp_sgid_ix;	/* SGID Index in SGID Table. */
	uint8_t		hp_lmc:3;	/* Local mask control */
	ib_mtu_t	hp_mtu;		/* Max transfer unit - pkt */
} ibtl_cm_hca_port_t;

/*
 * ibtl_cm_get_hca_port()
 *
 * 	A helper function to get HCA node GUID, Base LID, SGID Index,
 *	port number, LMC and MTU for the specified SGID.
 *
 *	sgid		Input Source GID.
 *
 *	hca_guid	Optional HCA Guid.
 *
 *	hca_port	Pointer to ibtl_cm_hca_port_t structure,
 */
ibt_status_t ibtl_cm_get_hca_port(ib_gid_t sgid, ib_guid_t hca_guid,
    ibtl_cm_hca_port_t *hca_port);


ibt_status_t ibtl_cm_get_local_comp_gids(ib_guid_t hca_guid, ib_gid_t sgid,
    ib_gid_t **gids_p, uint_t *num_gids_p);

int ibtl_cm_is_multi_sm(ib_guid_t hca_guid);

/*
 * ibtl_cm_get_1st_full_pkey_ix()
 *
 *	A helper function to get P_Key Index of the first full member P_Key
 *	available on the specified HCA and Port combination.
 *
 *	hca_guid	HCA GUID.
 *
 *	port		HCA port number.
 */
uint16_t ibtl_cm_get_1st_full_pkey_ix(ib_guid_t hca_guid, uint8_t port);


/*
 * Functions to support CM and clients to reliably free RC QPs.
 *
 * ibtl_cm_chan_is_open()
 *
 *	Inform IBTL that the connection has been established on this
 *	channel so that a later call to ibtl_cm_chan_is_closed()
 *	will be required to free the QPN used by this channel.
 *
 * ibtl_cm_chan_is_opening()
 *
 *	Inform IBTL that the connection established on this channel is
 *	in progress.
 *
 * ibtl_cm_chan_open_is_aborted()
 *
 *	Inform IBTL that the connection established on this channel has
 *	aborted. So undo what was done in ibtl_cm_chan_is_opening().
 *
 * ibtl_cm_chan_is_closing()
 *
 *	Inform IBTL that the TIMEWAIT delay for the connection has been
 *	started for this channel so that the QP can be freed.
 *
 * ibtl_cm_is_chan_closing()
 *
 *	Returns 1 if the connection on this channel has been moved to TIME WAIT
 *
 * ibtl_cm_is_chan_closed()
 *
 *	Returns 1 if the connection on this channel has completed TIME WAIT
 *
 * ibtl_cm_chan_is_closed()
 *
 *	Inform IBTL that the TIMEWAIT delay for the connection has been
 *	reached for this channel so that the QPN can be reused.
 *
 *	rc_chan		Channel Handle
 *
 * ibtl_cm_chan_is_reused()
 *
 *	Inform IBTL that the channel is going to be re-used for another
 *	connection.
 *
 *	rc_chan		Channel Handle
 */
void ibtl_cm_chan_is_open(ibt_channel_hdl_t rc_chan);
void ibtl_cm_chan_is_opening(ibt_channel_hdl_t rc_chan);
void ibtl_cm_chan_open_is_aborted(ibt_channel_hdl_t rc_chan);
void ibtl_cm_chan_is_closing(ibt_channel_hdl_t rc_chan);
void ibtl_cm_chan_is_closed(ibt_channel_hdl_t rc_chan);
void ibtl_cm_chan_is_reused(ibt_channel_hdl_t rc_chan);
int  ibtl_cm_is_chan_closing(ibt_channel_hdl_t rc_chan);
int  ibtl_cm_is_chan_closed(ibt_channel_hdl_t rc_chan);

/*
 * ibtl_cm_get_chan_type()
 *
 *	A helper function to get channel transport type.
 */
ibt_tran_srv_t ibtl_cm_get_chan_type(ibt_channel_hdl_t chan);

/*
 * ibtl_cm_change_service_cnt()
 *
 *	Inform IBTL that service registration count has changed
 *	so that it can correctly manage whether or not it should
 *	allow ibt_detach() to succeed.
 */
void ibtl_cm_change_service_cnt(ibt_clnt_hdl_t ibt_hdl, int delta_num_sids);

/*
 * ibtl_cm_query_hca_ports_byguid()
 *
 *	Use the cached copy of the portinfo.
 */
ibt_status_t ibtl_cm_query_hca_ports_byguid(ib_guid_t hca_guid, uint8_t port,
    ibt_hca_portinfo_t **port_info_p, uint_t *ports_p, uint_t *size_p);


/*
 * ibtl_cm_get_active_plist
 *
 *	Returns a list of active source points which satisfy the desired
 *	attribute. The memory allocated for the array "port_list_p" should
 *	be freed by the caller using ibtl_cm_free_active_plist().
 *
 * ibtl_cm_free_active_plist
 *
 *	Frees the memory allocated in ibtl_cm_get_active_plist().
 */

#define	IBTL_CM_SIMPLE_SETUP	0
#define	IBTL_CM_MULTI_SM	(1 << 0)
#define	IBTL_CM_MULTI_HCA	(1 << 1)

typedef struct ibtl_cm_port_list_s {
	ib_guid_t	p_hca_guid;
	ib_gid_t	p_sgid;
	ib_lid_t	p_base_lid;
	ib_mtu_t	p_mtu;
	uint8_t		p_sgid_ix;
	uint8_t		p_port_num;
	uint8_t		p_count;
	uint8_t		p_multi;
	void		*p_saa_hdl;
	ibt_ip_addr_t	p_src_ip;
} ibtl_cm_port_list_t;

ibt_status_t ibtl_cm_get_active_plist(ibt_path_attr_t *attr,
    ibt_path_flags_t flags, ibtl_cm_port_list_t **port_list_p);
void ibtl_cm_free_active_plist(ibtl_cm_port_list_t *port_list);

/*
 * Functions to support ibt_register_subnet_notices and the
 * related callbacks.
 *
 * ibtl_cm_set_sm_notice_handler
 *	Pass the handler into IBTL where it will actually be used.
 *
 * ibtl_cm_sm_notice_handler
 *	Post an event to interested IBT clients.
 *
 * ibtl_cm_sm_notice_init_failure
 *	Inform the client that callbacks are not working.
 */
void ibtl_cm_sm_notice_handler(ib_gid_t sgid, ibt_subnet_event_code_t code,
    ibt_subnet_event_t *event);

void ibtl_cm_set_sm_notice_handler(ibt_clnt_hdl_t ibt_hdl,
    ibt_sm_notice_handler_t sm_notice_handler, void *private);

/* pass all failing sgids at once */
typedef struct ibtl_cm_sm_init_fail_s {
	int		smf_num_sgids;
	ibt_clnt_hdl_t	smf_ibt_hdl;
	ib_gid_t	smf_sgid[1];
} ibtl_cm_sm_init_fail_t;

void ibtl_cm_sm_notice_init_failure(ibtl_cm_sm_init_fail_t *ifail);

char *ibtl_cm_get_clnt_name(ibt_clnt_hdl_t ibt_hdl);

/*
 * ibtl_cm_set_node_info_cb: This is a private interface between IBTL and IBCM
 * to let IBTL get the Node Record of a remote port. This interface is used by
 * IBCM to register a callback which can be used by IBTL to get the Node record.
 */
void ibtl_cm_set_node_info_cb(ibt_status_t (*)(ib_guid_t, uint8_t, ib_lid_t,
    ibt_node_info_t *));

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_IBTL_IMPL_IBTL_CM_H */
