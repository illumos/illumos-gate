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

#include <sys/ib/mgt/ibcm/ibcm_impl.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/mgt/ibcm/ibcm_arp.h>

/*
 * ibcm_ti.c
 *	These routines implement the Communication Manager's interfaces to IBTL.
 */

/* CM rc recycle task args structure definition */
typedef struct ibcm_taskq_recycle_arg_s {
	ibt_channel_hdl_t	rc_chan;
	ibt_cep_flags_t		control;
	uint8_t			hca_port_num;
	ibt_recycle_handler_t	func;
	void			*arg;
} ibcm_taskq_recycle_arg_t;

_NOTE(READ_ONLY_DATA(ibcm_taskq_recycle_arg_s))

static ibt_status_t	ibcm_init_reply_addr(ibcm_hca_info_t *hcap,
    ibcm_mad_addr_t *reply_addr, ibt_chan_open_args_t *chan_args,
    ibt_chan_open_flags_t flags, ib_time_t *cm_pkt_lt, ib_lid_t prim_slid);
static void		ibcm_process_abort_via_taskq(void *args);
static ibt_status_t	ibcm_process_rc_recycle_ret(void *recycle_arg);
static ibt_status_t	ibcm_process_join_mcg(void *taskq_arg);
static void		ibcm_process_async_join_mcg(void *tq_arg);

ibt_status_t ibcm_get_node_rec(ibmf_saa_handle_t, sa_node_record_t *,
    uint64_t c_mask, void *, size_t *);

static ibt_status_t ibcm_close_rc_channel(ibt_channel_hdl_t channel,
    ibcm_state_data_t *statep, ibt_execution_mode_t mode);

/* Address Record management definitions */
#define	IBCM_DAPL_ATS_NAME	"DAPL Address Translation Service"
#define	IBCM_DAPL_ATS_SID	0x10000CE100415453ULL
#define	IBCM_DAPL_ATS_NBYTES	16
ibcm_svc_info_t *ibcm_ar_svcinfop;
ibcm_ar_t	*ibcm_ar_list;

/*
 * Tunable parameter to turnoff the overriding of pi_path_mtu value.
 *	1 	By default override the path record's pi_path_mtu value to
 *		IB_MTU_1K for all RC channels. This is done only for the
 *		channels established on Tavor HCA and the path's pi_path_mtu
 *		is greater than IB_MTU_1K.
 *	0	Do not override, use pi_path_mtu by default.
 */
int	ibcm_override_path_mtu = 1;

#ifdef DEBUG
static void	ibcm_print_reply_addr(ibt_channel_hdl_t channel,
		    ibcm_mad_addr_t *cm_reply_addr);
#endif

_NOTE(DATA_READABLE_WITHOUT_LOCK(ibcm_port_info_s::{port_ibmf_hdl}))

/* access is controlled between ibcm_sm.c and ibcm_ti.c by CVs */
_NOTE(SCHEME_PROTECTS_DATA("Serialized access by CV", {ibt_rc_returns_t
    ibt_ud_returns_t ibt_ap_returns_t ibt_ar_t}))

/*
 * Typically, clients initialize these args in one api call, and use in
 * another api
 */
_NOTE(SCHEME_PROTECTS_DATA("Expected usage of ibtl api by client",
    {ibt_path_info_s ibt_cep_path_s ibt_adds_vect_s ibt_mcg_info_s ib_gid_s
    ibt_ud_dest_attr_s ibt_ud_dest_s ibt_srv_data_s ibt_redirect_info_s}))

/*
 * ibt_open_rc_channel()
 *	ibt_open_rc_channel opens a communication channel on the specified
 *	channel to the specified service. For connection service type qp's
 *	the CM initiates the CEP to establish the connection and transitions
 *	the QP/EEC to the "Ready to send" State modifying the QP/EEC's
 *	attributes as necessary.
 *	The implementation of this function assumes that alt path is different
 *	from primary path. It is assumed that the Path functions ensure that.
 *
 * RETURN VALUES:
 *	IBT_SUCCESS	on success (or respective failure on error)
 */
ibt_status_t
ibt_open_rc_channel(ibt_channel_hdl_t channel, ibt_chan_open_flags_t flags,
    ibt_execution_mode_t mode, ibt_chan_open_args_t *chan_args,
    ibt_rc_returns_t *ret_args)
{
	/* all fields that are related to REQ MAD formation */

	ib_pkey_t		prim_pkey;
	ib_lid_t		primary_slid, alternate_slid;
	ib_qpn_t		local_qpn = 0;
	ib_guid_t		hca_guid;
	ib_qkey_t		local_qkey = 0;
	ib_eecn_t		local_eecn = 0;
	ib_eecn_t		remote_eecn = 0;
	boolean_t		primary_grh;
	boolean_t		alternate_grh = B_FALSE;
	ib_lid_t		base_lid;
	ib_com_id_t		local_comid;
	ibmf_msg_t		*ibmf_msg, *ibmf_msg_dreq;
	ibcm_req_msg_t		*req_msgp;

	uint8_t			rdma_in, rdma_out;
	uint8_t			cm_retries;
	uint64_t		local_cm_proc_time;	/* In usec */
	uint8_t			local_cm_resp_time;	/* IB time */
	uint64_t		remote_cm_resp_time;	/* In usec */
	uint32_t		starting_psn = 0;

	/* CM path related fields */
	ibmf_handle_t		ibmf_hdl;
	ibcm_qp_list_t		*cm_qp_entry;
	ibcm_mad_addr_t		cm_reply_addr;

	uint8_t			cm_pkt_lt;

	/* Local args for ibtl/internal CM functions called within */
	ibt_status_t		status;
	ibcm_status_t		lkup_status;
	ibt_qp_query_attr_t	qp_query_attr;

	/* Other misc local args */
	ibt_priv_data_len_t	len;
	ibcm_hca_info_t		*hcap;
	ibcm_state_data_t	*statep;
	uint8_t			port_no;

	IBTF_DPRINTF_L3(cmlog, "ibt_open_rc_channel(chan %p, %X, %x, %p, %p)",
	    channel, flags, mode, chan_args, ret_args);

	if (IBCM_INVALID_CHANNEL(channel)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: invalid channel");
		return (IBT_CHAN_HDL_INVALID);
	}

	/* cm handler should always be specified */
	if (chan_args->oc_cm_handler == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "CM handler is not be specified", channel);
		return (IBT_INVALID_PARAM);
	}

	if (mode == IBT_NONBLOCKING) {
		if (ret_args != NULL) {
			IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p"
			    " ret_args should be NULL when called in "
			    "non-blocking mode", channel);
			return (IBT_INVALID_PARAM);
		}
	} else if (mode == IBT_BLOCKING) {
		if (ret_args == NULL) {
			IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p"
			    " ret_args should be Non-NULL when called in "
			    "blocking mode", channel);
			return (IBT_INVALID_PARAM);
		}
		if (ret_args->rc_priv_data_len > IBT_REP_PRIV_DATA_SZ) {
			IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p"
			    " private data length is too large", channel);
			return (IBT_INVALID_PARAM);
		}
		if ((ret_args->rc_priv_data_len > 0) &&
		    (ret_args->rc_priv_data == NULL)) {
			IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p"
			    " rc_priv_data_len > 0, but rc_priv_data NULL",
			    channel);
			return (IBT_INVALID_PARAM);
		}
	} else { /* any other mode is not valid for ibt_open_rc_channel */
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "invalid mode %x specified", channel, mode);
		return (IBT_INVALID_PARAM);
	}

	/*
	 * XXX: no support yet for ibt_chan_open_flags_t - IBT_OCHAN_DUP
	 */
	if (flags & IBT_OCHAN_DUP) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "Unsupported Flags specified: 0x%X", channel, flags);
		return (IBT_INVALID_PARAM);
	}

	if ((flags & IBT_OCHAN_REDIRECTED) &&
	    (flags & IBT_OCHAN_PORT_REDIRECTED)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "Illegal to specify IBT_OCHAN_REDIRECTED and "
		    "IBT_OCHAN_PORT_REDIRECTED flags together", channel);
		return (IBT_INVALID_PARAM);
	}

	if (((flags & IBT_OCHAN_REDIRECTED) &&
	    (chan_args->oc_cm_redirect_info == NULL)) ||
	    ((flags & IBT_OCHAN_PORT_REDIRECTED) &&
	    (chan_args->oc_cm_cep_path == NULL))) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "Redirect flag specified, but respective arg is NULL",
		    channel);
		return (IBT_INVALID_PARAM);
	}

	if ((flags & IBT_OCHAN_REDIRECTED) &&
	    (chan_args->oc_cm_redirect_info->rdi_dlid == 0) &&
	    (chan_args->oc_cm_redirect_info->rdi_gid.gid_guid == 0)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "Either rdi_dlid or rdi_gid must be specified for"
		    " IBT_OCHAN_REDIRECTED", channel);
		return (IBT_INVALID_PARAM);
	}

	/* primary dlid and hca_port_num should never be zero */
	port_no = IBCM_PRIM_CEP_PATH(chan_args).cep_hca_port_num;

	if ((IBCM_PRIM_ADDS_VECT(chan_args).av_dlid == 0) && (port_no == 0)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "Primary Path's information is not valid", channel);
		return (IBT_INVALID_PARAM);
	}

	/* validate SID */
	if (chan_args->oc_path->pi_sid == 0) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "ERROR: Service ID in path information is 0", channel);
		return (IBT_INVALID_PARAM);
	}
	IBTF_DPRINTF_L3(cmlog, "ibt_open_rc_channel: chan 0x%p  SID %llX",
	    channel, chan_args->oc_path->pi_sid);

	/* validate rnr_retry_cnt (enum has more than 3 bits) */
	if ((uint_t)chan_args->oc_path_rnr_retry_cnt > IBT_RNR_INFINITE_RETRY) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "ERROR: oc_path_rnr_retry_cnt(%d) is out of range",
		    channel, chan_args->oc_path_rnr_retry_cnt);
		return (IBT_INVALID_PARAM);
	}

	/*
	 * Ensure that client is not re-using a QP that is still associated
	 * with a statep
	 */
	IBCM_GET_CHAN_PRIVATE(channel, statep);
	if (statep != NULL) {
		IBCM_RELEASE_CHAN_PRIVATE(channel);
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "Channel being re-used on active side", channel);
		return (IBT_CHAN_IN_USE);
	}

	/* Get GUID from Channel */
	hca_guid = ibt_channel_to_hca_guid(channel);

	/* validate QP's hca guid with that from primary path  */
	if (hca_guid != chan_args->oc_path->pi_hca_guid) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "GUID from Channel and primary path don't match", channel);
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "Channel GUID %llX primary path GUID %llX", channel,
		    hca_guid, chan_args->oc_path->pi_hca_guid);
		return (IBT_CHAN_HDL_INVALID);
	}

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
	    "Local HCA GUID %llX", channel, hca_guid);

	status = ibt_query_qp(channel, &qp_query_attr);
	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "ibt_query_qp failed %d", channel, status);
		return (status);
	}

	/* If client specified "no port change on QP" */
	if ((qp_query_attr.qp_info.qp_transport.rc.rc_path.cep_hca_port_num !=
	    port_no) && (flags & IBT_OCHAN_PORT_FIXED)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "chan port %d and path port %d does not match", channel,
		    qp_query_attr.qp_info.qp_transport.rc.rc_path. \
		    cep_hca_port_num, port_no);
		return (IBT_INVALID_PARAM);
	}

	if (qp_query_attr.qp_info.qp_trans != IBT_RC_SRV) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "Invalid Channel type: Applicable only to RC Channel",
		    channel);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}

	/* Check if QP is in INIT state or not */
	if (qp_query_attr.qp_info.qp_state != IBT_STATE_INIT) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "QP is not in INIT state %x", channel,
		    qp_query_attr.qp_info.qp_state);
		return (IBT_CHAN_STATE_INVALID);
	}

	local_qpn = qp_query_attr.qp_qpn;

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p Active QPN 0x%x",
	    channel, local_qpn);

#ifdef	NO_EEC_SUPPORT_YET

	if (flags & IBT_OCHAN_RDC_EXISTS) {
		ibt_eec_query_attr_t	eec_query_attr;

		local_qkey = qp_query_attr.qp_info.qp_transport.rd_qkey;

		IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: RD");

		status = ibt_query_eec(channel, &eec_query_attr);
		if (status != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p"
			    " ibt_query_eec failed %d", channel, status);
			return (status);
		}
		local_eecn = eec_query_attr.eec_eecn;
	}

#endif
	if (chan_args->oc_path->pi_prim_pkt_lt > ibcm_max_ib_pkt_lt) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "Huge PktLifeTime %d, Max is %d", channel,
		    chan_args->oc_path->pi_prim_pkt_lt, ibcm_max_ib_pkt_lt);
		return (IBT_PATH_PKT_LT_TOO_HIGH);
	}

	/* If no HCA found return failure */
	if ((hcap = ibcm_find_hca_entry(hca_guid)) == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "hcap is NULL. Probably hca is not in active state",
		    channel);
		return (IBT_CHAN_HDL_INVALID);
	}

	rdma_out = chan_args->oc_rdma_ra_out;
	rdma_in = chan_args->oc_rdma_ra_in;

	if ((rdma_in > hcap->hca_max_rdma_in_qp) ||
	    (rdma_out > hcap->hca_max_rdma_out_qp)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "rdma in %d/out %d values exceed hca limits(%d/%d)",
		    channel, rdma_in, rdma_out, hcap->hca_max_rdma_in_qp,
		    hcap->hca_max_rdma_out_qp);
		ibcm_dec_hca_acc_cnt(hcap);
		return (IBT_INVALID_PARAM);
	}

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
	    "rdma_in %d rdma_out %d", channel, rdma_in, rdma_out);

	status = ibt_get_port_state_byguid(hcap->hca_guid, port_no,
	    NULL, &base_lid);
	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "primary port_num %d not active", channel, port_no);
		ibcm_dec_hca_acc_cnt(hcap);
		return (status);
	}

	/* Validate P_KEY Index */
	status = ibt_index2pkey_byguid(hcap->hca_guid, port_no,
	    IBCM_PRIM_CEP_PATH(chan_args).cep_pkey_ix, &prim_pkey);
	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "Invalid Primary PKeyIx %x", channel,
		    IBCM_PRIM_CEP_PATH(chan_args).cep_pkey_ix);
		ibcm_dec_hca_acc_cnt(hcap);
		return (status);
	}

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
	    "primary_port_num %d primary_pkey 0x%x", channel, port_no,
	    prim_pkey);

	if ((hcap->hca_port_info[port_no - 1].port_ibmf_hdl == NULL) &&
	    ((status = ibcm_hca_reinit_port(hcap, port_no - 1))
	    != IBT_SUCCESS)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "ibmf reg or callback setup failed during re-initialize",
		    channel);
		ibcm_dec_hca_acc_cnt(hcap);
		return (status);
	}

	ibmf_hdl = hcap->hca_port_info[port_no - 1].port_ibmf_hdl;
	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
	    "primary ibmf_hdl = 0x%p", channel, ibmf_hdl);

	primary_slid = base_lid + IBCM_PRIM_ADDS_VECT(chan_args).av_src_path;

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: channel 0x%p "
	    "primary SLID = %x", channel, primary_slid);

	/* check first if alternate path exists or not as it is OPTIONAL */
	if (IBCM_ALT_CEP_PATH(chan_args).cep_hca_port_num != 0) {
		uint8_t	alt_port_no;

		alt_port_no = IBCM_ALT_CEP_PATH(chan_args).cep_hca_port_num;

		if (chan_args->oc_path->pi_alt_pkt_lt > ibcm_max_ib_pkt_lt) {
			IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
			    "Huge Alt Pkt lt %d", channel,
			    chan_args->oc_path->pi_alt_pkt_lt);
			ibcm_dec_hca_acc_cnt(hcap);
			return (IBT_PATH_PKT_LT_TOO_HIGH);
		}

		if (port_no != alt_port_no) {

			status = ibt_get_port_state_byguid(hcap->hca_guid,
			    alt_port_no, NULL, &base_lid);
			if (status != IBT_SUCCESS) {

				IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: "
				    "chan 0x%p alt_port_num %d inactive %d",
				    channel, alt_port_no, status);
				ibcm_dec_hca_acc_cnt(hcap);
				return (status);
			}

		}
		alternate_slid =
		    base_lid + IBCM_ALT_ADDS_VECT(chan_args).av_src_path;

		IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "alternate SLID = %x", channel, alternate_slid);
	}

	/*
	 * only pkey needs to be zero'ed, because all other fields are set in
	 * in ibcm_init_reply_addr. But, let's bzero the complete struct for
	 * any future modifications.
	 */
	bzero(&cm_reply_addr, sizeof (cm_reply_addr));

	/* Initialize the MAD destination address in stored_reply_addr */
	if ((status = ibcm_init_reply_addr(hcap, &cm_reply_addr, chan_args,
	    flags, &cm_pkt_lt, primary_slid)) != IBT_SUCCESS) {

		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "ibcm_init_reply_addr failed status %d ", channel, status);
		ibcm_dec_hca_acc_cnt(hcap);
		return (status);
	}


	/* Initialize the pkey for CM MAD communication */
	if (cm_reply_addr.rcvd_addr.ia_p_key == 0)
		cm_reply_addr.rcvd_addr.ia_p_key = prim_pkey;

#ifdef DEBUG
	ibcm_print_reply_addr(channel, &cm_reply_addr);
#endif

	/* Retrieve an ibmf qp for sending CM MADs */
	if ((cm_qp_entry = ibcm_find_qp(hcap, port_no,
	    cm_reply_addr.rcvd_addr.ia_p_key)) == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "unable to allocate ibmf qp for CM MADs", channel);
		ibcm_dec_hca_acc_cnt(hcap);
		return (IBT_INSUFF_RESOURCE);
	}


	if (ibcm_alloc_comid(hcap, &local_comid) != IBCM_SUCCESS) {
		ibcm_release_qp(cm_qp_entry);
		ibcm_dec_hca_acc_cnt(hcap);
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan 0x%p"
		    " Unable to allocate comid", channel);
		return (IBT_INSUFF_KERNEL_RESOURCE);
	}

	/* allocate an IBMF mad buffer (REQ) */
	if ((status = ibcm_alloc_out_msg(ibmf_hdl, &ibmf_msg,
	    MAD_METHOD_SEND)) != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: "
		    "chan 0x%p ibcm_alloc_out_msg failed", channel);
		ibcm_release_qp(cm_qp_entry);
		ibcm_free_comid(hcap, local_comid);
		ibcm_dec_hca_acc_cnt(hcap);
		return (status);
	}

	/* allocate an IBMF mad buffer (DREQ) */
	if ((status = ibcm_alloc_out_msg(ibmf_hdl, &ibmf_msg_dreq,
	    MAD_METHOD_SEND)) != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: "
		    "chan 0x%p ibcm_alloc_out_msg failed", channel);
		(void) ibcm_free_out_msg(ibmf_hdl, &ibmf_msg);
		ibcm_release_qp(cm_qp_entry);
		ibcm_free_comid(hcap, local_comid);
		ibcm_dec_hca_acc_cnt(hcap);
		return (status);
	}

	/* Init to Init, if QP's port does not match with path information */
	if (qp_query_attr.qp_info.qp_transport.rc.rc_path.cep_hca_port_num !=
	    IBCM_PRIM_CEP_PATH(chan_args).cep_hca_port_num) {

		ibt_qp_info_t		qp_info;
		ibt_cep_modify_flags_t	cep_flags;

		IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: "
		    "chan 0x%p chan port %d", channel,
		    qp_query_attr.qp_info.qp_transport.rc.rc_path.\
		    cep_hca_port_num);

		IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: "
		    "chan 0x%p path port %d", channel, port_no);

		bzero(&qp_info, sizeof (qp_info));
		/* For now, set it to RC type */

		qp_info.qp_trans = IBT_RC_SRV;
		qp_info.qp_state = IBT_STATE_INIT;
		qp_info.qp_transport.rc.rc_path.cep_hca_port_num = port_no;

		cep_flags = IBT_CEP_SET_STATE | IBT_CEP_SET_PORT;

		status = ibt_modify_qp(channel, cep_flags, &qp_info, NULL);

		if (status != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: "
			    "chan 0x%p ibt_modify_qp() = %d", channel, status);
			ibcm_release_qp(cm_qp_entry);
			ibcm_free_comid(hcap, local_comid);
			ibcm_dec_hca_acc_cnt(hcap);
			(void) ibcm_free_out_msg(ibmf_hdl, &ibmf_msg);
			(void) ibcm_free_out_msg(ibmf_hdl, &ibmf_msg_dreq);
			return (status);
		} else
			IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: "
			    "chan 0x%p ibt_modify_qp() = %d", channel, status);
	}

	/* allocate ibcm_state_data_t before grabbing the WRITER lock */
	statep = kmem_zalloc(sizeof (ibcm_state_data_t), KM_SLEEP);
	rw_enter(&hcap->hca_state_rwlock, RW_WRITER);
	lkup_status = ibcm_lookup_msg(IBCM_OUTGOING_REQ, local_comid, 0, 0,
	    hcap, &statep);
	rw_exit(&hcap->hca_state_rwlock);

	/* CM should be seeing this for the first time */
	ASSERT(lkup_status == IBCM_LOOKUP_NEW);

	/* Increment the hca's resource count */
	ibcm_inc_hca_res_cnt(hcap);

	/* Once a resource created on hca, no need to hold the acc cnt */
	ibcm_dec_hca_acc_cnt(hcap);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*statep))

	statep->timerid = 0;
	statep->local_hca_guid = hca_guid;
	statep->local_qpn = local_qpn;
	statep->stored_reply_addr.cm_qp_entry = cm_qp_entry;
	statep->prim_port = IBCM_PRIM_CEP_PATH(chan_args).cep_hca_port_num;
	statep->alt_port = IBCM_ALT_CEP_PATH(chan_args).cep_hca_port_num;


	/* Save "statep" as channel's CM private data.  */
	statep->channel = channel;
	IBCM_SET_CHAN_PRIVATE(statep->channel, statep);

	statep->stored_msg = ibmf_msg;
	statep->dreq_msg = ibmf_msg_dreq;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*req_msgp))

	/* Start filling in the REQ MAD */
	req_msgp = (ibcm_req_msg_t *)IBCM_OUT_MSGP(statep->stored_msg);
	req_msgp->req_local_comm_id = h2b32(local_comid);
	req_msgp->req_svc_id = h2b64(chan_args->oc_path->pi_sid);
	req_msgp->req_local_ca_guid = h2b64(hca_guid);
	req_msgp->req_local_qkey = h2b32(local_qkey);	/* for EEC/RD */

	/* Bytes 32-35 are req_local_qpn and req_off_resp_resources */
	req_msgp->req_local_qpn_plus = h2b32(local_qpn << 8 | rdma_in);

	/* Bytes 36-39 are req_local_eec_no and req_off_initiator_depth */
	req_msgp->req_local_eec_no_plus = h2b32(local_eecn << 8 | rdma_out);

	if (flags & IBT_OCHAN_REMOTE_CM_TM)
		remote_cm_resp_time = chan_args->oc_remote_cm_time;
	else
		remote_cm_resp_time = ibcm_remote_response_time;

	/*
	 * Bytes 40-43 - remote_eecn, remote_cm_resp_time, tran_type,
	 * IBT_CM_FLOW_CONTROL is always set by default.
	 */
	req_msgp->req_remote_eecn_plus = h2b32(
	    remote_eecn << 8 | (ibt_usec2ib(remote_cm_resp_time) & 0x1f) << 3 |
	    IBT_RC_SRV << 1 | IBT_CM_FLOW_CONTROL);

	if (flags & IBT_OCHAN_LOCAL_CM_TM)
		local_cm_proc_time = chan_args->oc_local_cm_time;
	else
		local_cm_proc_time = ibcm_local_processing_time;

	local_cm_resp_time = ibt_usec2ib(local_cm_proc_time +
	    2 * ibt_ib2usec(chan_args->oc_path->pi_prim_pkt_lt) +
	    ibcm_sw_delay);

	/* save retry count */
	statep->cep_retry_cnt = chan_args->oc_path_retry_cnt;

	if (flags & IBT_OCHAN_STARTING_PSN)
		starting_psn = chan_args->oc_starting_psn;

	if (local_cm_resp_time > 0x1f)
		local_cm_resp_time = 0x1f;

	/* Bytes 44-47 are req_starting_psn, local_cm_resp_time and retry_cnt */
	req_msgp->req_starting_psn_plus = h2b32(starting_psn << 8 |
	    local_cm_resp_time << 3 | statep->cep_retry_cnt);

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
	    "Prim Pkt lt (IB time) 0x%x", channel,
	    chan_args->oc_path->pi_prim_pkt_lt);

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
	    "local_cm_proc_time(usec) %d ", channel, local_cm_proc_time);

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
	    "local_cm_resp_time(ib_time) %d", channel, local_cm_resp_time);

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
	    "remote_cm_resp_time (usec) %d", channel, remote_cm_resp_time);

	statep->starting_psn = starting_psn;

	/* Pkey - bytes 48-49 */
	req_msgp->req_part_key = h2b16(prim_pkey);

	if (flags & IBT_OCHAN_CM_RETRY)
		cm_retries = chan_args->oc_cm_retry_cnt;
	else
		cm_retries = ibcm_max_retries;

	statep->max_cm_retries = statep->remaining_retry_cnt = cm_retries;
	req_msgp->req_max_cm_retries_plus = statep->max_cm_retries << 4;

	/*
	 * Check whether SRQ is associated with this Channel, if yes, then
	 * set the SRQ Exists bit in the REQ.
	 */
	if (qp_query_attr.qp_srq != NULL) {
		req_msgp->req_max_cm_retries_plus |= (1 << 3);
	}

	/*
	 * By default on Tavor, we override the PathMTU to 1K.
	 * To turn this off, set ibcm_override_path_mtu = 0.
	 */
	if (ibcm_override_path_mtu && IBCM_IS_HCA_TAVOR(hcap) &&
	    (chan_args->oc_path->pi_path_mtu > IB_MTU_1K)) {
		req_msgp->req_mtu_plus = IB_MTU_1K << 4 |
		    chan_args->oc_path_rnr_retry_cnt;
		IBTF_DPRINTF_L3(cmlog, "ibt_open_rc_channel: chan 0x%p PathMTU"
		    " overridden to IB_MTU_1K(%d) from %d", channel, IB_MTU_1K,
		    chan_args->oc_path->pi_path_mtu);
	} else
		req_msgp->req_mtu_plus = chan_args->oc_path->pi_path_mtu << 4 |
		    chan_args->oc_path_rnr_retry_cnt;

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p CM retry cnt %d"
	    " staring PSN %x", channel, cm_retries, starting_psn);


#ifdef	NO_EEC_SUPPORT_YET
	if (flags & IBT_OCHAN_RDC_EXISTS)
		req_msgp->req_mtu_plus |= 8;
#endif

	/* Initialize the "primary" port stuff next - bytes 52-95 */
	req_msgp->req_primary_l_port_lid = h2b16(primary_slid);
	req_msgp->req_primary_r_port_lid =
	    h2b16(IBCM_PRIM_ADDS_VECT(chan_args).av_dlid);
	req_msgp->req_primary_l_port_gid.gid_prefix =
	    h2b64(IBCM_PRIM_ADDS_VECT(chan_args).av_sgid.gid_prefix);
	req_msgp->req_primary_l_port_gid.gid_guid =
	    h2b64(IBCM_PRIM_ADDS_VECT(chan_args).av_sgid.gid_guid);
	req_msgp->req_primary_r_port_gid.gid_prefix =
	    h2b64(IBCM_PRIM_ADDS_VECT(chan_args).av_dgid.gid_prefix);
	req_msgp->req_primary_r_port_gid.gid_guid =
	    h2b64(IBCM_PRIM_ADDS_VECT(chan_args).av_dgid.gid_guid);
	primary_grh = IBCM_PRIM_ADDS_VECT(chan_args).av_send_grh;

	statep->remote_hca_guid = /* not correct, but helpful for debugging */
	    IBCM_PRIM_ADDS_VECT(chan_args).av_dgid.gid_guid;

	/* Bytes 88-91 - primary_flowlbl, and primary_srate */
	req_msgp->req_primary_flow_label_plus =
	    h2b32(((primary_grh == B_TRUE) ?
	    (IBCM_PRIM_ADDS_VECT(chan_args).av_flow << 12) : 0) |
	    IBCM_PRIM_ADDS_VECT(chan_args).av_srate);
	req_msgp->req_primary_traffic_class = (primary_grh == B_TRUE) ?
	    IBCM_PRIM_ADDS_VECT(chan_args).av_tclass : 0;
	req_msgp->req_primary_hop_limit = (primary_grh == B_TRUE) ?
	    IBCM_PRIM_ADDS_VECT(chan_args).av_hop : 1;
	req_msgp->req_primary_sl_plus =
	    IBCM_PRIM_ADDS_VECT(chan_args).av_srvl << 4 |
	    ((primary_grh == B_TRUE) ? 0 : 8);

	req_msgp->req_primary_localtime_plus =
	    ibt_usec2ib((2 * ibt_ib2usec(chan_args->oc_path->pi_prim_pkt_lt)) +
	    ibt_ib2usec(hcap->hca_ack_delay)) << 3;

	IBTF_DPRINTF_L2(cmlog, "ibt_open_rc_channel: chan %p statep %p",
	    channel, statep);
	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
	    "active hca_ack_delay (usec) %d", channel,
	    req_msgp->req_primary_localtime_plus);

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
	    "Sent primary cep timeout (IB Time) %d", channel,
	    hcap->hca_ack_delay);

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p prim_dlid %x ",
	    channel, IBCM_PRIM_ADDS_VECT(chan_args).av_dlid);

	IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
	    "prim GID %llX:%llX", channel,
	    IBCM_PRIM_ADDS_VECT(chan_args).av_dgid.gid_prefix,
	    IBCM_PRIM_ADDS_VECT(chan_args).av_dgid.gid_guid);

	/* Initialize the "alternate" port stuff - optional */
	if (chan_args->oc_path->pi_alt_cep_path.cep_hca_port_num != 0) {
		ib_gid_t	tmp_gid;

		req_msgp->req_alt_l_port_lid = h2b16(alternate_slid);
		req_msgp->req_alt_r_port_lid =
		    h2b16(IBCM_ALT_ADDS_VECT(chan_args).av_dlid);
		/*
		 * doing all this as req_alt_r/l_port_gid is at offset
		 * 100, 116 which is not divisible by 8
		 */

		tmp_gid.gid_prefix =
		    h2b64(IBCM_ALT_ADDS_VECT(chan_args).av_dgid.gid_prefix);
		tmp_gid.gid_guid =
		    h2b64(IBCM_ALT_ADDS_VECT(chan_args).av_dgid.gid_guid);
		bcopy(&tmp_gid, &req_msgp->req_alt_r_port_gid[0],
		    sizeof (ib_gid_t));
		tmp_gid.gid_prefix =
		    h2b64(IBCM_ALT_ADDS_VECT(chan_args).av_sgid.gid_prefix);
		tmp_gid.gid_guid =
		    h2b64(IBCM_ALT_ADDS_VECT(chan_args).av_sgid.gid_guid);

		bcopy(&tmp_gid, &req_msgp->req_alt_l_port_gid[0],
		    sizeof (ib_gid_t));
		alternate_grh = IBCM_ALT_ADDS_VECT(chan_args).av_send_grh;

		/* Bytes 132-135 - alternate_flow_label, and alternate srate */
		req_msgp->req_alt_flow_label_plus = h2b32(
		    (((alternate_grh == B_TRUE) ?
		    (IBCM_ALT_ADDS_VECT(chan_args).av_flow << 12) : 0) |
		    IBCM_ALT_ADDS_VECT(chan_args).av_srate));
		req_msgp->req_alt_traffic_class = (alternate_grh == B_TRUE) ?
		    IBCM_ALT_ADDS_VECT(chan_args).av_tclass : 0;
		req_msgp->req_alt_hop_limit = (alternate_grh == B_TRUE) ?
		    IBCM_ALT_ADDS_VECT(chan_args).av_hop : 1;
		req_msgp->req_alt_sl_plus =
		    IBCM_ALT_ADDS_VECT(chan_args).av_srvl << 4 |
		    ((alternate_grh == B_TRUE) ? 0 : 8);
		req_msgp->req_alt_localtime_plus = ibt_usec2ib((2 *
		    ibt_ib2usec(chan_args->oc_path->pi_alt_pkt_lt)) +
		    ibt_ib2usec(hcap->hca_ack_delay)) << 3;

		IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "alt_dlid %x ", channel,
		    IBCM_ALT_ADDS_VECT(chan_args).av_dlid);

		IBTF_DPRINTF_L5(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "alt GID %llX:%llX", channel,
		    IBCM_ALT_ADDS_VECT(chan_args).av_dgid.gid_prefix,
		    IBCM_ALT_ADDS_VECT(chan_args).av_dgid.gid_guid);
	}

	len = min(chan_args->oc_priv_data_len, IBT_REQ_PRIV_DATA_SZ);
	if ((len > 0) && chan_args->oc_priv_data)
		bcopy(chan_args->oc_priv_data, req_msgp->req_private_data, len);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*req_msgp))

	/* return_data is filled up in the state machine code */
	if (ret_args != NULL) {
		statep->open_return_data = ret_args;
	}

	/* initialize some statep fields here */
	statep->mode = IBCM_ACTIVE_MODE;
	statep->hcap = hcap;

	statep->cm_handler = chan_args->oc_cm_handler;
	statep->state_cm_private = chan_args->oc_cm_clnt_private;

	statep->pkt_life_time =
	    ibt_ib2usec(chan_args->oc_path->pi_prim_pkt_lt);

	statep->timer_value = ibt_ib2usec(ibt_usec2ib(
	    2 * ibt_ib2usec(cm_pkt_lt) + remote_cm_resp_time));

	/* Initialize statep->stored_reply_addr */
	statep->stored_reply_addr.ibmf_hdl = ibmf_hdl;

	/* Initialize stored reply addr fields */
	statep->stored_reply_addr.grh_hdr = cm_reply_addr.grh_hdr;
	statep->stored_reply_addr.rcvd_addr = cm_reply_addr.rcvd_addr;
	statep->stored_reply_addr.grh_exists = cm_reply_addr.grh_exists;
	statep->stored_reply_addr.port_num = cm_reply_addr.port_num;

	/*
	 * The IPD on local/active side is calculated by path functions,
	 * hence available in the args of ibt_open_rc_channel
	 */
	statep->local_srate = IBCM_PRIM_ADDS_VECT(chan_args).av_srate;
	statep->local_alt_srate = IBCM_ALT_ADDS_VECT(chan_args).av_srate;

	/* Store the source path bits for primary and alt paths */
	statep->prim_src_path_bits = IBCM_PRIM_ADDS_VECT(chan_args).av_src_path;
	statep->alt_src_path_bits = IBCM_ALT_ADDS_VECT(chan_args).av_src_path;

	statep->open_flow = 1;
	statep->open_done = B_FALSE;
	statep->state = statep->timer_stored_state = IBCM_STATE_REQ_SENT;
	IBCM_REF_CNT_INCR(statep);	/* Decremented before return */
	IBCM_REF_CNT_INCR(statep);	/* Decremented after REQ is posted */
	statep->send_mad_flags |= IBCM_REQ_POST_BUSY;

	/*
	 * Skip moving channel to error state during close, for OFUV clients.
	 * OFUV clients transition the channel to error state by itself.
	 */
	if (flags & IBT_OCHAN_OFUV)
		statep->is_this_ofuv_chan = B_TRUE;

	IBCM_OUT_HDRP(statep->stored_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_REQ + IBCM_ATTR_BASE_ID);

	IBCM_OUT_HDRP(statep->stored_msg)->TransactionID =
	    h2b64(ibcm_generate_tranid(IBCM_INCOMING_REQ, statep->local_comid,
	    0));

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*statep))

	ibtl_cm_chan_is_opening(channel);

	ibcm_open_enqueue(statep);

	mutex_enter(&statep->state_mutex);

	if (mode == IBT_BLOCKING) {

		/* wait for REQ/REP/RTU */
		while (statep->open_done != B_TRUE) {
			cv_wait(&statep->block_client_cv, &statep->state_mutex);
		}

		/*
		 * In the case that open_channel() fails because of a
		 * REJ or timeout, change retval to IBT_CM_FAILURE
		 */
		if (statep->open_return_data->rc_status != IBT_CM_SUCCESS) {
			status = IBT_CM_FAILURE;
			ibtl_cm_chan_open_is_aborted(channel);
		}

		IBTF_DPRINTF_L3(cmlog, "ibt_open_rc_channel: chan 0x%p "
		    "ret status %d cm status %d", channel, status,
		    statep->open_return_data->rc_status);
	}

	/* decrement the ref-count before leaving here */
	IBCM_REF_CNT_DECR(statep);

	mutex_exit(&statep->state_mutex);

	IBTF_DPRINTF_L4(cmlog, "ibt_open_rc_channel: chan 0x%p done", channel);
	return (status);
}

/*
 * ibcm_init_reply_addr:
 *
 * The brief description of functionality below.
 *
 * For IBT_OCHAN_PORT_REDIRECTED (ie., port redirected case):
 *	Build CM path from chan_args->oc_cm_cep_path
 *	Set CM pkt lt (ie.,life time) to chan_args->oc_cm_pkt_lt
 *
 * For IBT_OCHAN_REDIRECTED (ie., port and CM redirected case):
 *	If Redirect LID is specified,
 *		If Redirect GID is not specified or specified to be on the same
 *		    subnet, then
 *			Build CM path from chan_args->oc_cm_redirect_info
 *			Set CM pkt lt to subnet timeout
 *		Else (ie., GID specified, but on a different subnet)
 *			Do a path lookup to build CM Path and set CM pkt lt
 *
 */
static ibt_status_t
ibcm_init_reply_addr(ibcm_hca_info_t *hcap, ibcm_mad_addr_t *reply_addr,
    ibt_chan_open_args_t *chan_args, ibt_chan_open_flags_t flags,
    ib_time_t *cm_pkt_lt, ib_lid_t prim_slid)
{
	ibt_adds_vect_t	*cm_adds;
	ibt_path_info_t	path;
	boolean_t	cm_grh;
	ibt_status_t	status;

	IBTF_DPRINTF_L5(cmlog, "ibcm_init_reply_addr:");

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*reply_addr))

	/*
	 * sending side CM lid/gid/port num are not based on any redirect
	 * params. These values are set to primary RC path lid/gid/port num.
	 * In the future, these values can be set based on framework policy
	 * decisions ensuring reachability.
	 */
	reply_addr->grh_hdr.ig_sender_gid =
	    IBCM_PRIM_ADDS_VECT(chan_args).av_sgid;
	reply_addr->rcvd_addr.ia_local_lid = prim_slid;
	reply_addr->port_num = IBCM_PRIM_CEP_PATH(chan_args).cep_hca_port_num;

	if (flags & IBT_OCHAN_PORT_REDIRECTED) {
		IBTF_DPRINTF_L4(cmlog, "ibcm_init_rely_addr: "
		    "IBT_OCHAN_PORT_REDIRECTED specified");

		status = ibt_index2pkey_byguid(hcap->hca_guid,
		    chan_args->oc_cm_cep_path->cep_hca_port_num,
		    chan_args->oc_cm_cep_path->cep_pkey_ix,
		    &reply_addr->rcvd_addr.ia_p_key);

		if (status != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_init_rely_addr: Invalid "
			    "CM PKeyIx %x port_num %x",
			    chan_args->oc_cm_cep_path->cep_pkey_ix,
			    chan_args->oc_cm_cep_path->cep_hca_port_num);
			return (status);
		}

		cm_adds = &(chan_args->oc_cm_cep_path->cep_adds_vect);
		IBTF_DPRINTF_L4(cmlog, "ibcm_init_rely_addr: dlid = %x",
		    cm_adds->av_dlid);

		reply_addr->rcvd_addr.ia_q_key = IB_GSI_QKEY;
		reply_addr->rcvd_addr.ia_remote_qno = 1;
		*cm_pkt_lt = chan_args->oc_cm_pkt_lt;

	} else if (flags & IBT_OCHAN_REDIRECTED) {
		ibt_redirect_info_t	*redirect_info;
		ibt_hca_portinfo_t	*port_infop;
		uint_t			psize, nports;

		IBTF_DPRINTF_L4(cmlog, "ibcm_init_rely_addr: "
		    "IBT_OCHAN_REDIRECTED specified");

		redirect_info = chan_args->oc_cm_redirect_info;

		if ((redirect_info->rdi_gid.gid_prefix == 0) ||
		    (redirect_info->rdi_gid.gid_guid == 0)) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_init_reply_addr: "
			    "ERROR: Re-direct GID value NOT Provided.");
			return (IBT_INVALID_PARAM);
		}

		/* As per spec definition 1.1, it's always IB_GSI_QKEY */
		reply_addr->rcvd_addr.ia_q_key = redirect_info->rdi_qkey;
		reply_addr->rcvd_addr.ia_remote_qno = redirect_info->rdi_qpn;
		reply_addr->rcvd_addr.ia_p_key = redirect_info->rdi_pkey;

		/*
		 * if LID is non-zero in classportinfo then use classportinfo
		 * fields to form CM MAD destination address.
		 */
		if (redirect_info->rdi_dlid != 0) {
			status = ibtl_cm_query_hca_ports_byguid(hcap->hca_guid,
			    reply_addr->port_num, &port_infop, &nports, &psize);
			if ((status != IBT_SUCCESS) || (nports == 0)) {
				IBTF_DPRINTF_L2(cmlog, "ibcm_init_reply_addr: "
				    "Query Ports Failed: %d", status);
				return (status);
			} else if (port_infop->p_subnet_timeout >
			    ibcm_max_ib_pkt_lt) {
				IBTF_DPRINTF_L2(cmlog, "ibcm_init_reply_addr: "
				    "large subnet timeout %x port_no %x",
				    port_infop->p_subnet_timeout,
				    reply_addr->port_num);
				ibt_free_portinfo(port_infop, psize);
				return (IBT_PATH_PKT_LT_TOO_HIGH);
			} else {
				IBTF_DPRINTF_L3(cmlog, "ibcm_init_reply_addr: "
				    "subnet timeout %x port_no %x",
				    port_infop->p_subnet_timeout,
				    reply_addr->port_num);

				*cm_pkt_lt =
				    ibt_ib2usec(min(ibcm_max_ib_mad_pkt_lt,
				    port_infop->p_subnet_timeout));

				ibt_free_portinfo(port_infop, psize);
			}

			reply_addr->rcvd_addr.ia_remote_lid =
			    redirect_info->rdi_dlid;
			reply_addr->rcvd_addr.ia_service_level =
			    redirect_info->rdi_sl;
			reply_addr->grh_exists = B_TRUE;
			reply_addr->grh_hdr.ig_recver_gid =
			    redirect_info->rdi_gid;
			reply_addr->grh_hdr.ig_tclass =
			    redirect_info->rdi_tclass;
			reply_addr->grh_hdr.ig_flow_label =
			    redirect_info->rdi_flow;

			/* Classportinfo doesn't have hoplimit field */
			reply_addr->grh_hdr.ig_hop_limit = 1;
			return (IBT_SUCCESS);

		} else {
			ibt_path_attr_t	path_attr;
			ib_gid_t	path_dgid[1];

			/*
			 * If GID is specified, and LID is zero in classportinfo
			 * do a path lookup using specified GID, Pkey,
			 * in classportinfo
			 */

			bzero(&path_attr, sizeof (path_attr));

			path_attr.pa_dgids = &path_dgid[0];
			path_attr.pa_dgids[0] = redirect_info->rdi_gid;

			/*
			 * use reply_addr below, as sender_gid in reply_addr
			 * may have been set above based on some policy decision
			 * for originating end point for CM MADs above
			 */
			path_attr.pa_sgid = reply_addr->grh_hdr.ig_sender_gid;
			path_attr.pa_num_dgids = 1;
			path_attr.pa_pkey = redirect_info->rdi_pkey;

			if ((status = ibt_get_paths(ibcm_ibt_handle,
			    IBT_PATH_PKEY, &path_attr, 1, &path, NULL)) !=
			    IBT_SUCCESS)
				return (status);

			/* Initialize cm_adds */
			cm_adds = &path.pi_prim_cep_path.cep_adds_vect;
			*cm_pkt_lt = path.pi_prim_pkt_lt;
		}

	} else	{ /* cm_pkey initialized in ibt_open_rc_channel */
		reply_addr->rcvd_addr.ia_q_key = IB_GSI_QKEY;
		reply_addr->rcvd_addr.ia_remote_qno = 1;
		*cm_pkt_lt = chan_args->oc_path->pi_prim_pkt_lt;
		cm_adds = &(IBCM_PRIM_ADDS_VECT(chan_args));
	}


	cm_grh = cm_adds->av_send_grh;
	reply_addr->grh_exists = cm_grh;

	reply_addr->rcvd_addr.ia_remote_lid =
	    cm_adds->av_dlid;
	reply_addr->grh_hdr.ig_recver_gid =
	    cm_adds->av_dgid;
	reply_addr->grh_hdr.ig_flow_label =
	    cm_adds->av_flow & IB_GRH_FLOW_LABEL_MASK;
	reply_addr->grh_hdr.ig_tclass =
	    (cm_grh == B_TRUE) ? cm_adds->av_tclass : 0;
	reply_addr->grh_hdr.ig_hop_limit =
	    (cm_grh == B_TRUE) ? cm_adds->av_hop : 1;
	reply_addr->rcvd_addr.ia_service_level =
	    cm_adds->av_srvl;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*reply_addr))

	return (IBT_SUCCESS);
}


/*
 * ibt_prime_close_rc_channel()
 *	It allocates resources required for close channel operation, so
 *	ibt_close_rc_channel can be called from interrupt routine.
 *
 * INPUTS:
 *	channel			The address of an ibt_channel_t struct that
 *				specifies the channel to open.
 *
 * RETURN VALUES:
 *	IBT_SUCCESS	on success(or respective failure on error)
 *
 * Clients are typically expected to call this function in established state
 */
ibt_status_t
ibt_prime_close_rc_channel(ibt_channel_hdl_t channel)
{
	ibcm_state_data_t	*statep;
	ibt_status_t		status = IBT_SUCCESS;

	IBTF_DPRINTF_L3(cmlog, "ibt_prime_close_rc_channel(%p)", channel);

	/* validate channel, first */
	if (IBCM_INVALID_CHANNEL(channel)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_prime_close_rc_channel: chan 0x%p "
		    "invalid channel", channel);
		return (IBT_CHAN_HDL_INVALID);
	}

	if (ibtl_cm_get_chan_type(channel) != IBT_RC_SRV) {
		IBTF_DPRINTF_L2(cmlog, "ibt_prime_close_rc_channel: chan 0x%p "
		    "Invalid Channel type: Applicable only to RC Channel",
		    channel);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}

	/* get the statep */
	IBCM_GET_CHAN_PRIVATE(channel, statep);

	/*
	 * This can happen, if the statep is already gone by a DREQ from
	 * the remote side
	 */

	if (statep == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_prime_close_rc_channel: chan 0x%p "
		    "statep NULL", channel);
		return (IBT_SUCCESS);
	}

	mutex_enter(&statep->state_mutex);
	IBCM_RELEASE_CHAN_PRIVATE(channel);
	if (statep->state != IBCM_STATE_ESTABLISHED) {
		mutex_exit(&statep->state_mutex);
		return (IBT_CHAN_STATE_INVALID);
	}
	IBCM_REF_CNT_INCR(statep);
	IBTF_DPRINTF_L4(cmlog, "ibt_prime_close_rc_channel: chan 0x%p statep %p"
	    " state %x", channel, statep, statep->state);
	mutex_exit(&statep->state_mutex);

	/* clients could pre-allocate dreq mad, even before connection est */
	if (statep->dreq_msg == NULL)
		status = ibcm_alloc_out_msg(statep->stored_reply_addr.ibmf_hdl,
		    &statep->dreq_msg, MAD_METHOD_SEND);

	mutex_enter(&statep->state_mutex);
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);

	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_prime_close_rc_channel: chan 0x%p "
		    "ibcm_alloc_out_msg failed ", channel);
		return (status);
	}

	/* If this message isn't seen then ibt_prime_close_rc_channel failed */
	IBTF_DPRINTF_L5(cmlog, "ibt_prime_close_rc_channel: chan 0x%p done",
	    channel);

	return (IBT_SUCCESS);
}

/*
 * ibt_close_rc_channel()
 *	It closes an established channel.
 *
 * RETURN VALUES:
 *	IBT_SUCCESS	on success(or respective failure on error)
 */
ibt_status_t
ibt_close_rc_channel(ibt_channel_hdl_t channel, ibt_execution_mode_t mode,
    void *priv_data, ibt_priv_data_len_t priv_data_len, uint8_t *ret_status,
    void *ret_priv_data, ibt_priv_data_len_t *ret_priv_data_len_p)
{
	ibcm_state_data_t	*statep;

	IBTF_DPRINTF_L3(cmlog, "ibt_close_rc_channel(%p, %x, %p, %d, %p)",
	    channel, mode, priv_data, priv_data_len,
	    (ret_priv_data_len_p == NULL) ? 0 : *ret_priv_data_len_p);

	/* validate channel, first */
	if (IBCM_INVALID_CHANNEL(channel)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_close_rc_channel: chan 0x%p "
		    "invalid channel", channel);
		return (IBT_CHAN_HDL_INVALID);
	}

	if (ibtl_cm_get_chan_type(channel) != IBT_RC_SRV) {
		IBTF_DPRINTF_L2(cmlog, "ibt_close_rc_channel: chan 0x%p "
		    "Invalid Channel type: Applicable only to RC Channel",
		    channel);
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}

	if (mode == IBT_BLOCKING) {
		/* valid only for BLOCKING MODE */
		if ((ret_priv_data_len_p != NULL) &&
		    (*ret_priv_data_len_p > IBT_DREP_PRIV_DATA_SZ)) {
			IBTF_DPRINTF_L2(cmlog, "ibt_close_rc_channel: chan 0x%p"
			    " private data len %d is too large", channel,
			    *ret_priv_data_len_p);
			return (IBT_INVALID_PARAM);
		}
	} else if ((mode != IBT_NONBLOCKING) && (mode != IBT_NOCALLBACKS)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_close_rc_channel: chan 0x%p "
		    "invalid mode %x specified", channel, mode);
		return (IBT_INVALID_PARAM);
	}

	if (ibtl_cm_is_chan_closing(channel) ||
	    ibtl_cm_is_chan_closed(channel)) {
		if (ret_status)
			*ret_status = IBT_CM_CLOSED_ALREADY;

		/* No private data to return to the client */
		if (ret_priv_data_len_p != NULL)
			*ret_priv_data_len_p = 0;

		if ((mode == IBT_BLOCKING) ||
		    (mode == IBT_NOCALLBACKS)) {
			IBCM_GET_CHAN_PRIVATE(channel, statep);
			if (statep == NULL)
				return (IBT_SUCCESS);
			mutex_enter(&statep->state_mutex);
			IBCM_RELEASE_CHAN_PRIVATE(channel);
			IBCM_REF_CNT_INCR(statep);
			while (statep->close_done != B_TRUE)
				cv_wait(&statep->block_client_cv,
				    &statep->state_mutex);
			IBCM_REF_CNT_DECR(statep);
			mutex_exit(&statep->state_mutex);
		}

		IBTF_DPRINTF_L3(cmlog, "ibt_close_rc_channel: chan 0x%p "
		    "already marked for closing", channel);

		return (IBT_SUCCESS);
	}

	/* get the statep */
	IBCM_GET_CHAN_PRIVATE(channel, statep);
	if (statep == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_close_rc_channel: chan 0x%p "
		    "statep NULL", channel);
		return (IBT_CHAN_STATE_INVALID);
	}

	mutex_enter(&statep->state_mutex);

	if (statep->dreq_msg == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_close_rc_channel: chan 0x%p "
		    "Fatal Error: dreq_msg is NULL", channel);
		IBCM_RELEASE_CHAN_PRIVATE(channel);
		mutex_exit(&statep->state_mutex);
		return (IBT_CHAN_STATE_INVALID);
	}

	if ((ret_priv_data == NULL) || (ret_priv_data_len_p == NULL)) {
		statep->close_ret_priv_data = NULL;
		statep->close_ret_priv_data_len = NULL;
	} else {
		statep->close_ret_priv_data = ret_priv_data;
		statep->close_ret_priv_data_len = ret_priv_data_len_p;
	}

	priv_data_len = min(priv_data_len, IBT_DREQ_PRIV_DATA_SZ);
	if ((priv_data != NULL) && (priv_data_len > 0)) {
		bcopy(priv_data, ((ibcm_dreq_msg_t *)
		    IBCM_OUT_MSGP(statep->dreq_msg))->dreq_private_data,
		    priv_data_len);
	}
	statep->close_ret_status = ret_status;

	IBCM_RELEASE_CHAN_PRIVATE(channel);
	IBCM_REF_CNT_INCR(statep);

	if (mode != IBT_NONBLOCKING) {
		return (ibcm_close_rc_channel(channel, statep, mode));
	}

	/* IBT_NONBLOCKING */
	ibcm_close_enqueue(statep);
	mutex_exit(&statep->state_mutex);

	return (IBT_SUCCESS);
}

void
ibcm_close_start(ibcm_state_data_t *statep)
{
	mutex_enter(&statep->state_mutex);
	(void) ibcm_close_rc_channel(statep->channel, statep, IBT_NONBLOCKING);
}

static
ibt_status_t
ibcm_close_rc_channel(ibt_channel_hdl_t channel, ibcm_state_data_t *statep,
    ibt_execution_mode_t mode)
{
	ibcm_hca_info_t		*hcap;

	_NOTE(LOCK_RELEASED_AS_SIDE_EFFECT(&statep->state_mutex));
	ASSERT(MUTEX_HELD(&statep->state_mutex));

	IBTF_DPRINTF_L3(cmlog, "ibcm_close_rc_channel: chan 0x%p statep %p",
	    channel, statep);

	hcap = statep->hcap;

	/* HCA must have been in active state. If not, it's a client bug */
	if (!IBCM_ACCESS_HCA_OK(hcap)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_close_rc_channel: chan 0x%p "
		    "hcap 0x%p not active", channel, hcap);
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		return (IBT_CHAN_HDL_INVALID);
	}

	if (statep->state == IBCM_STATE_TRANSIENT_ESTABLISHED) {
		while (statep->cep_in_rts == IBCM_BLOCK)
			cv_wait(&statep->block_mad_cv, &statep->state_mutex);
	}

	/* Do TRANSIENT_DREQ check after TRANSIENT_ESTABLISHED check */
	while (statep->state == IBCM_STATE_TRANSIENT_DREQ_SENT)
		cv_wait(&statep->block_mad_cv, &statep->state_mutex);

	IBTF_DPRINTF_L4(cmlog, "ibcm_close_rc_channel: chan 0x%p "
	    "connection state is %x", channel, statep->state);

	/* If state is in pre-established states, abort the connection est */
	if (statep->state != IBCM_STATE_ESTABLISHED) {
		statep->cm_retries++;	/* ensure connection trace is dumped */

		/* No DREP private data possible */
		if (statep->close_ret_priv_data_len != NULL)
			*statep->close_ret_priv_data_len = 0;

		/*
		 * If waiting for a response mad, then cancel the timer,
		 * and delete the connection
		 */
		if (statep->state == IBCM_STATE_REQ_SENT ||
		    statep->state == IBCM_STATE_REP_SENT ||
		    statep->state == IBCM_STATE_REP_WAIT ||
		    statep->state == IBCM_STATE_MRA_REP_RCVD) {
			timeout_id_t		timer_val = statep->timerid;
			ibcm_conn_state_t	old_state;

			IBTF_DPRINTF_L4(cmlog, "ibcm_close_rc_channel: "
			    "chan 0x%p connection aborted in state %x", channel,
			    statep->state);

			old_state = statep->state;
			statep->state = IBCM_STATE_DELETE;

			if (mode == IBT_NONBLOCKING) {
				if (taskq_dispatch(ibcm_taskq,
				    ibcm_process_abort_via_taskq, statep,
				    TQ_NOSLEEP) == TASKQID_INVALID) {

					IBCM_REF_CNT_DECR(statep);
					statep->state = old_state;
					mutex_exit(&statep->state_mutex);
					return (IBT_INSUFF_KERNEL_RESOURCE);
				}	/* if taskq_dispatch succeeds */
				/* Cancel the timer */
				statep->timerid = 0;
				mutex_exit(&statep->state_mutex);
			} else {
				/* Cancel the timer */
				statep->timerid = 0;
				mutex_exit(&statep->state_mutex);
				(void) taskq_dispatch(ibcm_taskq,
				    ibcm_process_abort_via_taskq, statep,
				    TQ_SLEEP);
			}

			/* cancel the currently running timer */
			if (timer_val != 0)
				(void) untimeout(timer_val);

			/* wait until cm handler returns for BLOCKING cases */
			mutex_enter(&statep->state_mutex);
			if ((mode == IBT_BLOCKING) ||
			    (mode == IBT_NOCALLBACKS)) {
				while (statep->close_done != B_TRUE)
					cv_wait(&statep->block_client_cv,
					    &statep->state_mutex);
			}

			if (statep->close_ret_status)
				*statep->close_ret_status = IBT_CM_CLOSED_ABORT;
			mutex_exit(&statep->state_mutex);

			/*
			 * It would ideal to post a REJ MAD, but that would
			 * be non-conformance to spec. Hence, delete the state
			 * data. Assuming that happens quickly, any retransmits
			 * from the remote are replied by CM with reject
			 * reason " no valid com id". That would stop remote
			 * sending any more MADs.
			 */
			ibcm_delete_state_data(statep);
			return (IBT_SUCCESS);

		/* if CM busy in cm handler, wait until cm handler returns */
		} else if (statep->state == IBCM_STATE_REQ_RCVD ||
		    statep->state == IBCM_STATE_REP_RCVD ||
		    statep->state == IBCM_STATE_MRA_SENT ||
		    statep->state == IBCM_STATE_MRA_REP_SENT) {

			/* take control of statep */
			statep->abort_flag |= IBCM_ABORT_CLIENT;

			IBTF_DPRINTF_L4(cmlog, "ibcm_close_rc_channel: "
			    "chan 0x%p connection aborted in state = %x",
			    channel, statep->state);

			/*
			 * wait until state machine modifies qp state to error,
			 * including disassociating statep and QP
			 */
			if ((mode == IBT_BLOCKING) || (mode == IBT_NOCALLBACKS))
				while (statep->close_done != B_TRUE)
					cv_wait(&statep->block_client_cv,
					    &statep->state_mutex);

			/* a sanity setting */
			if (mode == IBT_NOCALLBACKS)
				statep->cm_handler = NULL;
			IBCM_REF_CNT_DECR(statep);

			/*
			 * In rare situations, connection attempt could be
			 * terminated for some other reason, before abort is
			 * processed, but CM still returns ret_status as abort
			 */
			if (statep->close_ret_status)
				*statep->close_ret_status = IBT_CM_CLOSED_ABORT;
			mutex_exit(&statep->state_mutex);

			/*
			 * REJ MAD is posted by the CM state machine for this
			 * case, hence state structure is deleted in the
			 * state machine processing.
			 */
			return (IBT_SUCCESS);

		} else if ((statep->state == IBCM_STATE_TIMEWAIT) ||
		    (statep->state == IBCM_STATE_DELETE)) {

			/* State already in timewait, so no return priv data */
			IBCM_REF_CNT_DECR(statep);

			/* The teardown has already been done */
			if (statep->close_ret_status)
				*statep->close_ret_status =
				    IBT_CM_CLOSED_ALREADY;
			mutex_exit(&statep->state_mutex);

			return (IBT_SUCCESS);

		} else if ((statep->state == IBCM_STATE_DREQ_RCVD) ||
		    (statep->state == IBCM_STATE_DREQ_SENT) ||
		    (statep->state == IBCM_STATE_DREP_RCVD) ||
		    ((statep->state == IBCM_STATE_TIMED_OUT) &&
		    (statep->timedout_state == IBCM_STATE_DREQ_SENT))) {

			/*
			 * Either the remote or local client has already
			 * initiated the teardown.  IBCM_STATE_DREP_RCVD is
			 * possible, if CM initiated teardown without client's
			 * knowledge, for stale handling, etc.,
			 */
			if (mode == IBT_NOCALLBACKS) {
				if (statep->close_nocb_state == IBCM_UNBLOCK) {
					statep->close_nocb_state = IBCM_FAIL;
					/* enable free qp after return */
					ibtl_cm_chan_is_closing(
					    statep->channel);
				} else while (statep->close_nocb_state ==
				    IBCM_BLOCK)
					cv_wait(&statep->block_client_cv,
					    &statep->state_mutex);
				statep->cm_handler = NULL; /* sanity setting */
				if (statep->close_ret_status)
					*statep->close_ret_status =
					    IBT_CM_CLOSED_ALREADY;
			} else if (mode == IBT_BLOCKING) {
				/* wait until state is moved to timewait */
				while (statep->close_done != B_TRUE)
					cv_wait(&statep->block_client_cv,
					    &statep->state_mutex);
			}

			IBCM_REF_CNT_DECR(statep);
			mutex_exit(&statep->state_mutex);

			/* ret_status is set in state machine code */
			return (IBT_SUCCESS);

		} else if (statep->state == IBCM_STATE_TIMED_OUT) {

			if ((mode == IBT_BLOCKING) ||
			    (mode == IBT_NOCALLBACKS)) {

				/*
				 * wait until cm handler invocation and
				 * disassociation between statep and channel
				 * is complete
				 */
				while (statep->close_done != B_TRUE)
					cv_wait(&statep->block_client_cv,
					    &statep->state_mutex);
			}

			if (statep->close_ret_status)
				*statep->close_ret_status = IBT_CM_CLOSED_ABORT;
			IBCM_REF_CNT_DECR(statep);
			mutex_exit(&statep->state_mutex);

			return (IBT_SUCCESS);
		} else {
			IBCM_REF_CNT_DECR(statep);
			mutex_exit(&statep->state_mutex);

			return (IBT_CM_FAILURE);
		}
	}

	ASSERT(statep->close_nocb_state != IBCM_BLOCK);

	if (mode == IBT_NOCALLBACKS) {
		statep->close_nocb_state = IBCM_FAIL;
		statep->cm_handler = NULL;
		ibtl_cm_chan_is_closing(statep->channel);
		IBTF_DPRINTF_L4(cmlog, "ibcm_close_rc_channel: "
		    "NOCALLBACKS on in statep = %p", statep);
	}

	if (statep->state != IBCM_STATE_ESTABLISHED) {
		goto lost_race;
	}

	/*
	 * Cancel/wait for any pending ibt_set_alt_path, and
	 * release state mutex
	 */
	ibcm_sync_lapr_idle(statep);

	ibcm_close_enter();

	mutex_enter(&statep->state_mutex);
	if (statep->state != IBCM_STATE_ESTABLISHED) {
		ibcm_close_exit();
		goto lost_race;
	}

	statep->state = IBCM_STATE_TRANSIENT_DREQ_SENT;
	statep->timerid = 0;
	statep->close_done = B_FALSE;
	statep->close_flow = 1;
	mutex_exit(&statep->state_mutex);

	ibcm_post_dreq_mad(statep);

	mutex_enter(&statep->state_mutex);

lost_race:
	if (mode == IBT_BLOCKING) {

		/* wait for DREP */
		while (statep->close_done != B_TRUE)
			cv_wait(&statep->block_client_cv,
			    &statep->state_mutex);

		IBTF_DPRINTF_L4(cmlog, "ibcm_close_rc_channel: chan 0x%p "
		    "done blocking", channel);
	}

	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);

	/* If this message isn't seen then ibt_close_rc_channel failed */
	IBTF_DPRINTF_L5(cmlog, "ibcm_close_rc_channel: chan 0x%p done",
	    channel);

	return (IBT_SUCCESS);
}

ibt_status_t
ibt_recycle_rc(ibt_channel_hdl_t rc_chan, ibt_cep_flags_t control,
    uint8_t hca_port_num, ibt_recycle_handler_t func, void *arg)
{
	ibcm_state_data_t		*statep;
	ibcm_taskq_recycle_arg_t	*ibcm_tq_recycle_arg;
	ibt_qp_query_attr_t		qp_attr;
	ibt_status_t			retval;

	IBTF_DPRINTF_L3(cmlog, "ibt_recycle_rc (%p, 0x%X, %d, %p, %p)", rc_chan,
	    control, hca_port_num, func, arg);

	if (IBCM_INVALID_CHANNEL(rc_chan)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_recycle_rc: invalid channel");
		return (IBT_CHAN_HDL_INVALID);
	}

	/* check qp state */
	retval = ibt_query_qp(rc_chan, &qp_attr);

	if (retval != IBT_SUCCESS)
		return (retval);

	if (qp_attr.qp_info.qp_trans != IBT_RC_SRV)
		return (IBT_CHAN_SRV_TYPE_INVALID);

	if (qp_attr.qp_info.qp_state != IBT_STATE_ERROR)
		return (IBT_CHAN_STATE_INVALID);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ibcm_tq_recycle_arg))

	ibcm_tq_recycle_arg = kmem_alloc(sizeof (ibcm_taskq_recycle_arg_t),
	    KM_SLEEP);

	ibcm_tq_recycle_arg->rc_chan		= rc_chan;
	ibcm_tq_recycle_arg->control		= control;
	ibcm_tq_recycle_arg->hca_port_num	= hca_port_num;
	ibcm_tq_recycle_arg->func		= func;
	ibcm_tq_recycle_arg->arg		= arg;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*ibcm_tq_recycle_arg))

	IBCM_GET_CHAN_PRIVATE(rc_chan, statep);

	/*
	 * If non-blocking ie., func specified and channel has not yet completed
	 * the timewait, then schedule the work for later
	 */
	if ((func != NULL) && (statep != NULL)) {
		IBCM_RELEASE_CHAN_PRIVATE(rc_chan);
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(statep->recycle_arg))
		statep->recycle_arg = ibcm_tq_recycle_arg;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(statep->recycle_arg))
		return (IBT_SUCCESS);
	}

	/*
	 * if blocking ie., func specified, and channel has not yet completed
	 * the timewait, then block until the channel completes the timewait
	 */
	if (statep != NULL)
		IBCM_RELEASE_CHAN_PRIVATE(rc_chan);
	IBCM_WAIT_CHAN_PRIVATE(rc_chan);

	if (func) {	/* NON BLOCKING case. Taskq for QP state change */
		(void) taskq_dispatch(ibcm_taskq, ibcm_process_rc_recycle,
		    ibcm_tq_recycle_arg, TQ_SLEEP);
		return (IBT_SUCCESS);
	} else	/* BLOCKING case */
		return (ibcm_process_rc_recycle_ret(ibcm_tq_recycle_arg));
}

void
ibcm_process_rc_recycle(void *recycle_arg)
{
	(void) ibcm_process_rc_recycle_ret(recycle_arg);
}

static ibt_status_t
ibcm_process_rc_recycle_ret(void *recycle_arg)
{
	ibt_qp_info_t			qp_info;
	ibt_status_t			ibt_status = IBT_SUCCESS;
	ibt_cep_modify_flags_t		cep_flags;
	ibt_qp_query_attr_t		qp_attr;
	ibcm_taskq_recycle_arg_t	*ibcm_tq_recycle_arg =
	    (ibcm_taskq_recycle_arg_t *)recycle_arg;

	/* QP must have been in error state */
	ibt_status = ibt_query_qp(ibcm_tq_recycle_arg->rc_chan, &qp_attr);
	if (ibt_status != IBT_SUCCESS)
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_rc_recycle_ret: "
		    "chanp %p ibt_query_qp() = %d",
		    ibcm_tq_recycle_arg->rc_chan, ibt_status);
	else {
		/* perform the QP state change from ERROR to RESET */
		bzero(&qp_info, sizeof (qp_info));

		qp_info.qp_trans = IBT_RC_SRV;
		qp_info.qp_state = IBT_STATE_RESET;

		/* Call modify_qp to move to RESET state */
		ibt_status = ibt_modify_qp(ibcm_tq_recycle_arg->rc_chan,
		    IBT_CEP_SET_STATE, &qp_info, NULL);

		if (ibt_status != IBT_SUCCESS)
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_rc_recycle_ret: "
			    "chanp %p ibt_modify_qp() = %d for ERROR to RESET",
			    ibcm_tq_recycle_arg->rc_chan, ibt_status);
	}

	if (ibt_status == IBT_SUCCESS) {

		qp_info.qp_state = IBT_STATE_INIT;

		/* set flags for all mandatory args from RESET to INIT */
		cep_flags = IBT_CEP_SET_STATE | IBT_CEP_SET_PORT;
		cep_flags |= IBT_CEP_SET_RDMA_R | IBT_CEP_SET_RDMA_W;
		cep_flags |= IBT_CEP_SET_ATOMIC;

		qp_info.qp_transport.rc.rc_path.cep_hca_port_num =
		    ibcm_tq_recycle_arg->hca_port_num;
		qp_info.qp_flags |=
		    ibcm_tq_recycle_arg->control & IBT_CEP_RDMA_RD;
		qp_info.qp_flags |=
		    ibcm_tq_recycle_arg->control & IBT_CEP_RDMA_WR;
		qp_info.qp_flags |=
		    ibcm_tq_recycle_arg->control & IBT_CEP_ATOMIC;

		/* Always use the existing pkey */
		qp_info.qp_transport.rc.rc_path.cep_pkey_ix =
		    qp_attr. qp_info.qp_transport.rc.rc_path.cep_pkey_ix;

		/* Call modify_qp to move to INIT state */
		ibt_status = ibt_modify_qp(ibcm_tq_recycle_arg->rc_chan,
		    cep_flags, &qp_info, NULL);

		if (ibt_status != IBT_SUCCESS)
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_rc_recycle_ret: "
			    "chanp %p ibt_modify_qp() = %d for RESET to INIT",
			    ibcm_tq_recycle_arg->rc_chan, ibt_status);
	}

	/* Change the QP CM state to indicate QP being re-used */
	if (ibt_status == IBT_SUCCESS)
		ibtl_cm_chan_is_reused(ibcm_tq_recycle_arg->rc_chan);

	/* Call func, if defined */
	if (ibcm_tq_recycle_arg->func)
		(*(ibcm_tq_recycle_arg->func))(ibt_status,
		    ibcm_tq_recycle_arg->arg);

	kmem_free(ibcm_tq_recycle_arg, sizeof (ibcm_taskq_recycle_arg_t));

	return (ibt_status);
}

static void
ibcm_process_abort_via_taskq(void *args)
{
	ibcm_state_data_t	*statep = (ibcm_state_data_t *)args;

	ibcm_process_abort(statep);
	mutex_enter(&statep->state_mutex);
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

/*
 * Local UD CM Handler's private data, used during ibt_request_ud_dest() in
 * Non-Blocking mode operations.
 */
typedef struct ibcm_local_handler_s {
	ibt_cm_ud_handler_t	actual_cm_handler;
	void			*actual_cm_private;
	ibt_ud_dest_t		*dest_hdl;
} ibcm_local_handler_t;

_NOTE(READ_ONLY_DATA(ibcm_local_handler_s))

/*
 * Local UD CM Handler, used when ibt_alloc_ud_dest() is issued in
 * NON-Blocking mode.
 *
 * Out here, we update the UD Destination handle with
 * the obtained DQPN and QKey (from SIDR REP) and invokes actual client
 * handler that was specified by the client.
 */
static ibt_cm_status_t
ibcm_local_cm_handler(void *priv, ibt_cm_ud_event_t *event,
    ibt_cm_ud_return_args_t *ret_args, void *priv_data, ibt_priv_data_len_t len)
{
	ibcm_local_handler_t	*handler_priv = (ibcm_local_handler_t *)priv;

	IBTF_DPRINTF_L4(cmlog, "ibcm_local_cm_handler: event %d",
	    event->cm_type);

	ASSERT(handler_priv != NULL);

	switch (event->cm_type) {
	case IBT_CM_UD_EVENT_SIDR_REP:
		/* Update QPN & QKey from event into destination handle. */
		if (handler_priv->dest_hdl != NULL) {
			handler_priv->dest_hdl->ud_dst_qpn =
			    event->cm_event.sidr_rep.srep_remote_qpn;
			handler_priv->dest_hdl->ud_qkey =
			    event->cm_event.sidr_rep.srep_remote_qkey;
		}

		/* Invoke the client handler - inform only, so ignore retval */
		(void) handler_priv->actual_cm_handler(
		    handler_priv->actual_cm_private, event, ret_args, priv_data,
		    len);

		/* Free memory allocated for local handler's private data. */
		if (handler_priv != NULL)
			kmem_free(handler_priv, sizeof (*handler_priv));

		break;
	default:
		IBTF_DPRINTF_L2(cmlog, "ibcm_local_cm_handler: ERROR");
		break;
	}

	return (IBT_CM_ACCEPT);
}


/* Validate the input UD destination attributes.  */
static ibt_status_t
ibcm_validate_dqpn_data(ibt_ud_dest_attr_t *attr, ibt_execution_mode_t mode,
    ibt_ud_returns_t *ret_args)
{
	/* cm handler must always be specified */
	if (mode == IBT_NONBLOCKING && attr->ud_cm_handler == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_validate_dqpn_data: "
		    "CM handler is not specified ");
		return (IBT_INVALID_PARAM);
	}

	if (mode == IBT_NONBLOCKING) {
		if (ret_args != NULL) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_validate_dqpn_data: "
			    "ret_args should be NULL when called in "
			    "non-blocking mode");
			return (IBT_INVALID_PARAM);
		}
	} else if (mode == IBT_BLOCKING) {
		if (ret_args == NULL) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_validate_dqpn_data: "
			    "ret_args should be Non-NULL when called in "
			    "blocking mode");
			return (IBT_INVALID_PARAM);
		}
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibcm_validate_dqpn_data: "
		    "invalid mode %x specified ", mode);
		return (IBT_INVALID_PARAM);
	}

	if (attr->ud_sid == 0) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_validate_dqpn_data: "
		    "ServiceID must be specified. ");
		return (IBT_INVALID_PARAM);
	}

	if (attr->ud_addr == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_validate_dqpn_data: "
		    "Address Info NULL");
		return (IBT_INVALID_PARAM);
	}

	/* Validate SGID */
	if ((attr->ud_addr->av_sgid.gid_prefix == 0) ||
	    (attr->ud_addr->av_sgid.gid_guid == 0)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_validate_dqpn_data: Invalid SGID");
		return (IBT_INVALID_PARAM);
	}
	IBTF_DPRINTF_L3(cmlog, "ibcm_validate_dqpn_data: SGID<%llX:%llX>",
	    attr->ud_addr->av_sgid.gid_prefix,
	    attr->ud_addr->av_sgid.gid_guid);

	/* Validate DGID */
	if ((attr->ud_addr->av_dgid.gid_prefix == 0) ||
	    (attr->ud_addr->av_dgid.gid_guid == 0)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_validate_dqpn_data: Invalid DGID");
		return (IBT_INVALID_PARAM);
	}
	IBTF_DPRINTF_L3(cmlog, "ibcm_validate_dqpn_data: DGID<%llX:%llX>",
	    attr->ud_addr->av_dgid.gid_prefix,
	    attr->ud_addr->av_dgid.gid_guid);

	return (IBT_SUCCESS);
}


/* Perform SIDR to retrieve DQPN and QKey.  */
static ibt_status_t
ibcm_ud_get_dqpn(ibt_ud_dest_attr_t *attr, ibt_execution_mode_t mode,
    ibt_ud_returns_t *ret_args)
{
	ibt_status_t		retval;
	ib_pkey_t		ud_pkey;
	ibmf_handle_t		ibmf_hdl;
	ibmf_msg_t		*ibmf_msg;
	ibcm_hca_info_t		*hcap;
	ibcm_sidr_req_msg_t	*sidr_req_msgp;
	ibcm_ud_state_data_t	*ud_statep;
	ibtl_cm_hca_port_t	port;
	ibcm_sidr_srch_t	sidr_entry;
	ibcm_qp_list_t		*cm_qp_entry;

	/* Retrieve HCA GUID value from the available SGID info. */
	retval = ibtl_cm_get_hca_port(attr->ud_addr->av_sgid, 0, &port);
	if ((retval != IBT_SUCCESS) || (port.hp_port == 0)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_ud_get_dqpn: "
		    "ibtl_cm_get_hca_port failed: %d", retval);
		return (retval);
	}

	IBTF_DPRINTF_L4(cmlog, "ibcm_ud_get_dqpn: "
	    "HCA GUID:%llX, port_num:%d", port.hp_hca_guid, port.hp_port);

	/* Lookup the HCA info for this GUID */
	if ((hcap = ibcm_find_hca_entry(port.hp_hca_guid)) == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_ud_get_dqpn: hcap is NULL");
		return (IBT_HCA_INVALID);
	}

	/* Return failure if the HCA device or Port is not operational */

	if ((retval = ibt_get_port_state_byguid(port.hp_hca_guid, port.hp_port,
	    NULL, NULL)) != IBT_SUCCESS) {
		/* Device Port is not in good state, don't use it. */
		IBTF_DPRINTF_L2(cmlog, "ibcm_ud_get_dqpn: Invalid "
		    "port specified or port not active");
		ibcm_dec_hca_acc_cnt(hcap);
		return (retval);
	}

	retval = ibt_index2pkey_byguid(port.hp_hca_guid, port.hp_port,
	    attr->ud_pkey_ix, &ud_pkey);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_ud_get_dqpn: "
		    "Failed to convert index2pkey: %d", retval);
		ibcm_dec_hca_acc_cnt(hcap);
		return (retval);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(sidr_entry))

	/* Allocate a new request id */
	if (ibcm_alloc_reqid(hcap, &sidr_entry.srch_req_id) == IBCM_FAILURE) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_ud_get_dqpn: "
		    "no req id available");
		ibcm_dec_hca_acc_cnt(hcap);
		return (IBT_INSUFF_KERNEL_RESOURCE);
	}

	if ((hcap->hca_port_info[port.hp_port - 1].port_ibmf_hdl == NULL) &&
	    ((retval = ibcm_hca_reinit_port(hcap, port.hp_port - 1))
	    != IBT_SUCCESS)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_ud_get_dqpn: "
		    "ibmf reg or callback setup failed during re-initialize");
		return (retval);
	}

	ibmf_hdl = hcap->hca_port_info[port.hp_port - 1].port_ibmf_hdl;

	/* find the ibmf QP to post the SIDR REQ */
	if ((cm_qp_entry = ibcm_find_qp(hcap, port.hp_port, ud_pkey)) ==
	    NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_ud_get_dqpn: IBMF QP allocation"
		    " failed");
		ibcm_dec_hca_acc_cnt(hcap);
		return (IBT_INSUFF_RESOURCE);
	}

	if ((retval = ibcm_alloc_out_msg(ibmf_hdl, &ibmf_msg, MAD_METHOD_SEND))
	    != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_ud_get_dqpn: IBMF MSG allocation"
		    " failed");
		ibcm_release_qp(cm_qp_entry);
		ibcm_dec_hca_acc_cnt(hcap);
		return (retval);
	}

	sidr_entry.srch_lid = port.hp_base_lid;
	sidr_entry.srch_gid = attr->ud_addr->av_sgid;
	sidr_entry.srch_grh_exists = attr->ud_addr->av_send_grh;
	sidr_entry.srch_mode = IBCM_ACTIVE_MODE;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(sidr_entry))

	/* do various allocations needed here */
	rw_enter(&hcap->hca_sidr_list_lock, RW_WRITER);

	(void) ibcm_find_sidr_entry(&sidr_entry, hcap, &ud_statep,
	    IBCM_FLAG_ADD);
	rw_exit(&hcap->hca_sidr_list_lock);

	/* Increment hca's resource count */
	ibcm_inc_hca_res_cnt(hcap);

	/* After a resource created on hca, no need to hold the acc cnt */
	ibcm_dec_hca_acc_cnt(hcap);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ud_statep))

	/* Initialize some ud_statep fields */
	ud_statep->ud_stored_msg = ibmf_msg;
	ud_statep->ud_svc_id = attr->ud_sid;
	ud_statep->ud_pkt_life_time =
	    ibt_ib2usec(attr->ud_pkt_lt);
	ud_statep->ud_stored_reply_addr.cm_qp_entry = cm_qp_entry;

	/* set remaining retry cnt */
	ud_statep->ud_remaining_retry_cnt = ud_statep->ud_max_cm_retries;

	/*
	 * Get UD handler and corresponding args which is pass it back
	 * as first argument for the handler.
	 */
	ud_statep->ud_state_cm_private = attr->ud_cm_private;

	if (mode == IBT_BLOCKING)
		ud_statep->ud_return_data = ret_args;
	else
		ud_statep->ud_cm_handler = attr->ud_cm_handler;

	/* Initialize the fields of ud_statep->ud_stored_reply_addr */
	ud_statep->ud_stored_reply_addr.grh_exists = attr->ud_addr->av_send_grh;
	ud_statep->ud_stored_reply_addr.ibmf_hdl = ibmf_hdl;
	ud_statep->ud_stored_reply_addr.grh_hdr.ig_hop_limit =
	    attr->ud_addr->av_hop;
	ud_statep->ud_stored_reply_addr.grh_hdr.ig_sender_gid =
	    attr->ud_addr->av_sgid;
	ud_statep->ud_stored_reply_addr.grh_hdr.ig_recver_gid =
	    attr->ud_addr->av_dgid;
	ud_statep->ud_stored_reply_addr.grh_hdr.ig_tclass =
	    attr->ud_addr->av_tclass;
	ud_statep->ud_stored_reply_addr.grh_hdr.ig_flow_label =
	    attr->ud_addr->av_flow & IB_GRH_FLOW_LABEL_MASK;

	/* needs to be derived based on the base LID and path bits */
	ud_statep->ud_stored_reply_addr.rcvd_addr.ia_local_lid =
	    port.hp_base_lid;
	ud_statep->ud_stored_reply_addr.rcvd_addr.ia_remote_lid =
	    attr->ud_addr->av_dlid;
	ud_statep->ud_stored_reply_addr.rcvd_addr.ia_p_key = ud_pkey;
	ud_statep->ud_stored_reply_addr.rcvd_addr.ia_q_key = IB_GSI_QKEY;
	ud_statep->ud_stored_reply_addr.rcvd_addr.ia_service_level =
	    attr->ud_addr->av_srvl;

	/*
	 * This may be enchanced later, to use a remote qno based on past
	 * redirect rej mad responses. This would be the place to specify
	 * appropriate remote qno
	 */
	ud_statep->ud_stored_reply_addr.rcvd_addr.ia_remote_qno = 1;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sidr_req_msgp))

	/* Initialize the SIDR REQ message fields */
	sidr_req_msgp =
	    (ibcm_sidr_req_msg_t *)IBCM_OUT_MSGP(ud_statep->ud_stored_msg);

	sidr_req_msgp->sidr_req_request_id = h2b32(ud_statep->ud_req_id);
	sidr_req_msgp->sidr_req_service_id = h2b64(attr->ud_sid);
	sidr_req_msgp->sidr_req_pkey = h2b16(ud_pkey);
	IBCM_OUT_HDRP(ud_statep->ud_stored_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_SIDR_REQ + IBCM_ATTR_BASE_ID);

	if ((attr->ud_priv_data != NULL) && (attr->ud_priv_data_len > 0)) {
		bcopy(attr->ud_priv_data, sidr_req_msgp->sidr_req_private_data,
		    min(attr->ud_priv_data_len, IBT_SIDR_REQ_PRIV_DATA_SZ));
	}

	/* Send out the SIDR REQ message */
	ud_statep->ud_state = IBCM_STATE_SIDR_REQ_SENT;
	ud_statep->ud_timer_stored_state = IBCM_STATE_SIDR_REQ_SENT;
	IBCM_UD_REF_CNT_INCR(ud_statep); /* for non-blocking SIDR REQ post */
	ud_statep->ud_timer_value = ibt_ib2usec(ibcm_max_sidr_rep_proctime) +
	    (ud_statep->ud_pkt_life_time * 2);

	IBCM_OUT_HDRP(ud_statep->ud_stored_msg)->TransactionID =
	    h2b64(ibcm_generate_tranid(IBCM_INCOMING_SIDR_REQ,
	    ud_statep->ud_req_id, 0));

	IBTF_DPRINTF_L4(cmlog, "ibcm_ud_get_dqpn: timer_value in HZ = %x",
	    ud_statep->ud_timer_value);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*ud_statep))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*sidr_req_msgp))

	ibcm_post_ud_mad(ud_statep, ud_statep->ud_stored_msg,
	    ibcm_post_sidr_req_complete, ud_statep);

	mutex_enter(&ud_statep->ud_state_mutex);

	/* Wait for SIDR_REP */
	if (mode == IBT_BLOCKING) {
		IBTF_DPRINTF_L4(cmlog, "ibcm_ud_get_dqpn: blocking");

		while (ud_statep->ud_blocking_done != B_TRUE) {
			cv_wait(&ud_statep->ud_block_client_cv,
			    &ud_statep->ud_state_mutex);
		}

		IBTF_DPRINTF_L4(cmlog, "ibcm_ud_get_dqpn: finished blocking");

		if (ret_args->ud_status == IBT_CM_SREP_QPN_VALID) {
			IBTF_DPRINTF_L4(cmlog, "ibcm_ud_get_dqpn: DQPN = %x, "
			    "status = %x, QKey = %x", ret_args->ud_dqpn,
			    ret_args->ud_status, ret_args->ud_qkey);

		} else {
			IBTF_DPRINTF_L4(cmlog, "ibcm_ud_get_dqpn: Status<%x>",
			    ret_args->ud_status);
			retval = IBT_CM_FAILURE;
		}
	}

	IBCM_UD_REF_CNT_DECR(ud_statep);
	mutex_exit(&ud_statep->ud_state_mutex);

	IBTF_DPRINTF_L4(cmlog, "ibcm_ud_get_dqpn: done");

	return (retval);
}


/*
 * Function:
 *	ibt_request_ud_dest
 * Input:
 *	ud_dest		A previously allocated UD destination handle.
 *	mode		This function can execute in blocking or non blocking
 *			modes.
 *	attr		UD destination attributes to be modified.
 * Output:
 *	ud_ret_args	If the function is called in blocking mode, ud_ret_args
 *			should be a pointer to an ibt_ud_returns_t struct.
 * Returns:
 *	IBT_SUCCESS
 * Description:
 *	Modify a previously allocated UD destination handle based on the
 *	results of doing the SIDR protocol.
 */
ibt_status_t
ibt_request_ud_dest(ibt_ud_dest_hdl_t ud_dest, ibt_execution_mode_t mode,
    ibt_ud_dest_attr_t *attr, ibt_ud_returns_t *ud_ret_args)
{
	ibt_status_t		retval;
	ibt_ud_dest_t		*ud_destp;
	ibcm_local_handler_t	*local_handler_priv = NULL;

	IBTF_DPRINTF_L3(cmlog, "ibt_request_ud_dest(%p, %x, %p, %p)",
	    ud_dest, mode, attr, ud_ret_args);

	retval = ibcm_validate_dqpn_data(attr, mode, ud_ret_args);
	if (retval != IBT_SUCCESS) {
		return (retval);
	}

	ud_destp = ud_dest;

	/* Allocate an Address handle. */
	retval = ibt_modify_ah(ud_destp->ud_dest_hca, ud_destp->ud_ah,
	    attr->ud_addr);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_request_ud_dest: "
		    "Address Handle Modification failed: %d", retval);
		return (retval);
	}

	if (mode == IBT_NONBLOCKING) {
		/*
		 * In NON-BLOCKING mode, and we need to update the destination
		 * handle with the DQPN and QKey that are obtained from
		 * SIDR REP, hook-up our own handler, so that we can catch
		 * the event, and we ourselves call the actual client's
		 * ud_cm_handler, in our handler.
		 */

		/* Allocate memory for local handler's private data. */
		local_handler_priv =
		    kmem_alloc(sizeof (*local_handler_priv), KM_SLEEP);

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*local_handler_priv))

		local_handler_priv->actual_cm_handler = attr->ud_cm_handler;
		local_handler_priv->actual_cm_private = attr->ud_cm_private;
		local_handler_priv->dest_hdl = ud_destp;

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*local_handler_priv))

		attr->ud_cm_handler = ibcm_local_cm_handler;
		attr->ud_cm_private = local_handler_priv;
	}

	/* In order to get DQPN and Destination QKey, perform SIDR */
	retval = ibcm_ud_get_dqpn(attr, mode, ud_ret_args);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_request_ud_dest: "
		    "Failed to get DQPN: %d", retval);

		/* Free memory allocated for local handler's private data. */
		if (local_handler_priv != NULL)
			kmem_free(local_handler_priv,
			    sizeof (*local_handler_priv));
		return (retval);
	}

	/*
	 * Fill in the dqpn and dqkey as obtained from ud_ret_args,
	 * values will be valid only on BLOCKING mode.
	 */
	if (mode == IBT_BLOCKING) {
		ud_destp->ud_dst_qpn = ud_ret_args->ud_dqpn;
		ud_destp->ud_qkey = ud_ret_args->ud_qkey;
	}

	return (retval);
}

/*
 * Function:
 *	ibt_ud_get_dqpn
 * Input:
 *	attr		A pointer to an ibt_ud_dest_attr_t struct that are
 *			required for SIDR REQ message. Not specified attributes
 *			should be set to "NULL" or "0".
 *			ud_sid, ud_addr and ud_pkt_lt must be specified.
 *	mode		This function can execute in blocking or non blocking
 *			modes.
 * Output:
 *	returns		If the function is called in blocking mode, returns
 *			should be a pointer to an ibt_ud_returns_t struct.
 * Return:
 *	IBT_SUCCESS	on success or respective failure on error.
 * Description:
 *	Finds the destination QPN at the specified destination that the
 *	specified service can be reached on. The IBTF CM initiates the
 *	service ID resolution protocol (SIDR) to determine a destination QPN.
 *
 * NOTE: SIDR_REQ is initiated from active side.
 */
ibt_status_t
ibt_ud_get_dqpn(ibt_ud_dest_attr_t *attr, ibt_execution_mode_t mode,
    ibt_ud_returns_t *returns)
{
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(cmlog, "ibt_ud_get_dqpn(%p, %x, %p)",
	    attr, mode, returns);

	retval = ibcm_validate_dqpn_data(attr, mode, returns);
	if (retval != IBT_SUCCESS) {
		return (retval);
	}

	return (ibcm_ud_get_dqpn(attr, mode, returns));
}


/*
 * ibt_cm_delay:
 *	A client CM handler function can call this function
 *	to extend its response time to a CM event.
 * INPUTS:
 *	flags		Indicates what CM message processing is being delayed
 *			by the CM handler, valid values are:
 *				IBT_CM_DELAY_REQ
 *				IBT_CM_DELAY_REP
 *				IBT_CM_DELAY_LAP
 *	cm_session_id	The session ID that was passed to client srv_handler
 *			by the CM
 *	service_time	The extended service time
 *	priv_data	Vendor specific data to be sent in the CM generated
 *			MRA message. Should be NULL if not specified.
 *	len		The number of bytes of data specified by priv_data.
 *
 * RETURN VALUES:
 *	IBT_SUCCESS	on success (or respective failure on error)
 */
ibt_status_t
ibt_cm_delay(ibt_cmdelay_flags_t flags, void *cm_session_id,
    clock_t service_time, void *priv_data, ibt_priv_data_len_t len)
{
	uint8_t			msg_typ = 0;
	ibcm_mra_msg_t		*mra_msgp;
	ibcm_state_data_t	*statep;
	ibt_status_t		status;

	IBTF_DPRINTF_L3(cmlog, "ibt_cm_delay(0x%x, %p, 0x%x)",
	    flags, cm_session_id, service_time);

	/*
	 * Make sure channel is associated with a statep
	 */
	statep = (ibcm_state_data_t *)cm_session_id;

	if (statep == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_cm_delay: statep NULL");
		return (IBT_INVALID_PARAM);
	}

	IBTF_DPRINTF_L4(cmlog, "ibt_cm_delay: statep %p", statep);

	/* Allocate an ibmf msg for mra, if not allocated yet */
	if (statep->mra_msg == NULL) {
		if ((status = ibcm_alloc_out_msg(
		    statep->stored_reply_addr.ibmf_hdl, &statep->mra_msg,
		    MAD_METHOD_SEND)) != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibt_cm_delay: chan 0x%p"
			    "IBMF MSG allocation failed", statep->channel);
			return (status);
		}
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mra_msgp))

	mra_msgp = (ibcm_mra_msg_t *)IBCM_OUT_MSGP(statep->mra_msg);
	mra_msgp->mra_local_comm_id = h2b32(statep->local_comid);
	mra_msgp->mra_remote_comm_id = h2b32(statep->remote_comid);

	/* fill in rest of MRA's fields - Message MRAed and Service Timeout */
	if (flags == IBT_CM_DELAY_REQ) {
		msg_typ = IBT_CM_MRA_TYPE_REQ;
	} else if (flags == IBT_CM_DELAY_REP) {
		msg_typ = IBT_CM_MRA_TYPE_REP;
	} else if (flags == IBT_CM_DELAY_LAP) {
		msg_typ = IBT_CM_MRA_TYPE_LAP;
	}

	mra_msgp->mra_message_type_plus = msg_typ << 6;
	mra_msgp->mra_service_timeout_plus = ibt_usec2ib(service_time) << 3;

	len = min(len, IBT_MRA_PRIV_DATA_SZ);
	if (priv_data && (len > 0))
		bcopy(priv_data, mra_msgp->mra_private_data, len);

	IBCM_OUT_HDRP(statep->mra_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_MRA + IBCM_ATTR_BASE_ID);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*mra_msgp))

	mutex_enter(&statep->state_mutex);

	if ((statep->mode == IBCM_ACTIVE_MODE) &&
	    (statep->state == IBCM_STATE_REP_RCVD)) {
		statep->state = IBCM_STATE_MRA_REP_SENT;
	} else if (statep->mode == IBCM_PASSIVE_MODE) {
		if (statep->state == IBCM_STATE_REQ_RCVD) {
			statep->state = IBCM_STATE_MRA_SENT;
		} else if (statep->ap_state == IBCM_AP_STATE_LAP_RCVD) {
			statep->ap_state = IBCM_AP_STATE_MRA_LAP_RCVD;
		} else {
			IBTF_DPRINTF_L2(cmlog, "ibt_cm_delay: invalid state "
			    "/ap_state/mode %x, %x, %x", statep->state,
			    statep->ap_state, statep->mode);
			mutex_exit(&statep->state_mutex);
			return (IBT_CHAN_STATE_INVALID);
		}
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibt_cm_delay: invalid state "
		    "/ap_state/mode %x, %x, %x", statep->state,
		    statep->ap_state, statep->mode);
		mutex_exit(&statep->state_mutex);

		return (IBT_CHAN_STATE_INVALID);
	}
	/* service time is usecs, stale_clock is nsecs */
	statep->stale_clock = gethrtime() +
	    (hrtime_t)ibt_ib2usec(ibt_usec2ib(service_time)) * (1000 *
	    statep->max_cm_retries);

	statep->send_mad_flags |= IBCM_MRA_POST_BUSY;
	IBCM_REF_CNT_INCR(statep);	/* for ibcm_post_mra_complete */
	mutex_exit(&statep->state_mutex);

	IBCM_OUT_HDRP(statep->mra_msg)->TransactionID =
	    IBCM_OUT_HDRP(statep->stored_msg)->TransactionID;

	/* post the MRA mad in blocking mode, as no timers involved */
	ibcm_post_rc_mad(statep, statep->mra_msg, ibcm_post_mra_complete,
	    statep);
	ibcm_insert_trace(statep, IBCM_TRACE_OUTGOING_MRA);
	/* If this message isn't seen then ibt_cm_delay failed */
	IBTF_DPRINTF_L3(cmlog, "ibt_cm_delay: done !!");

	return (IBT_SUCCESS);
}


/*
 * ibt_register_service()
 *	Register a service with the IBCM
 *
 * INPUTS:
 *	ibt_hdl		The IBT client handle returned to the client
 *			on an ibt_attach() call.
 *
 *	srv		The address of a ibt_srv_desc_t that describes
 *			the service, containing the following:
 *
 *		sd_ud_handler	The Service CM UD event Handler.
 *		sd_handler	The Service CM RC/UC/RD event Handler.
 *		sd_flags	Service flags (peer-to-peer, or not).
 *
 *	sid		This tells CM if the service is local (sid is 0) or
 *			wellknown (sid is the starting service id of the range).
 *
 *	num_sids	The number of contiguous service-ids to reserve.
 *
 *	srv_hdl		The address of a service identification handle, used
 *			to deregister a service, and to bind GIDs to.
 *
 *	ret_sid		The address to store the Service ID return value.
 *			If num_sids > 1, ret_sid is the first Service ID
 *			in the range.
 *
 * ibt_register_service() returns:
 *	IBT_SUCCESS		- added a service successfully.
 *	IBT_INVALID_PARAM	- invalid input parameter.
 *	IBT_CM_FAILURE		- failed to add the service.
 *	IBT_CM_SERVICE_EXISTS	- service already exists.
 *	IBT_INSUFF_KERNEL_RESOURCE - ran out of local service ids (should
 *				     never happen).
 */
ibt_status_t
ibt_register_service(ibt_clnt_hdl_t ibt_hdl, ibt_srv_desc_t *srv,
    ib_svc_id_t sid, int num_sids, ibt_srv_hdl_t *srv_hdl, ib_svc_id_t *ret_sid)
{
	ibcm_svc_info_t		*svcinfop;

	IBTF_DPRINTF_L2(cmlog, "ibt_register_service(%p (%s), %p, 0x%llX, %d)",
	    ibt_hdl, ibtl_cm_get_clnt_name(ibt_hdl), srv, (longlong_t)sid,
	    num_sids);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*svcinfop))

	*srv_hdl = NULL;

	if (num_sids <= 0) {
		IBTF_DPRINTF_L2(cmlog, "ibt_register_service: "
		    "Invalid number of service-ids specified (%d)", num_sids);
		return (IBT_INVALID_PARAM);
	}

	if (sid == 0) {
		if (ret_sid == NULL)
			return (IBT_INVALID_PARAM);
		sid = ibcm_alloc_local_sids(num_sids);
		if (sid == 0)
			return (IBT_INSUFF_KERNEL_RESOURCE);

	/* Make sure that the ServiceId specified is not of LOCAL AGN type. */
	} else if ((sid & IB_SID_AGN_MASK) == IB_SID_AGN_LOCAL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_register_service: "
		    "Invalid non-LOCAL SID specified: 0x%llX",
		    (longlong_t)sid);
		return (IBT_INVALID_PARAM);
	}

	svcinfop = ibcm_create_svc_entry(sid, num_sids);

	if (svcinfop == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_register_service: "
		    "Service-ID 0x%llx already registered", (longlong_t)sid);
		return (IBT_CM_SERVICE_EXISTS);
	}

	/*
	 * 'sid' and 'num_sids' are filled in ibcm_create_svc_entry()
	 */
	svcinfop->svc_flags = srv->sd_flags;
	svcinfop->svc_rc_handler = srv->sd_handler;
	svcinfop->svc_ud_handler = srv->sd_ud_handler;

	if (ret_sid != NULL)
		*ret_sid = sid;

	*srv_hdl = svcinfop;

	ibtl_cm_change_service_cnt(ibt_hdl, num_sids);

	/* If this message isn't seen, then ibt_register_service failed. */
	IBTF_DPRINTF_L2(cmlog, "ibt_register_service: done (%p, %llX)",
	    svcinfop, sid);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*svcinfop))

	return (IBT_SUCCESS);
}


static ibt_status_t
ibcm_write_service_record(ibmf_saa_handle_t saa_handle,
    sa_service_record_t *srv_recp, ibmf_saa_access_type_t saa_type)
{
	int	rval;
	int	retry;

	ibcm_sa_access_enter();
	for (retry = 0; retry < ibcm_max_sa_retries; retry++) {
		rval = ibmf_saa_update_service_record(
		    saa_handle, srv_recp, saa_type, 0);
		if (rval != IBMF_TRANS_TIMEOUT) {
			break;
		}
		IBTF_DPRINTF_L2(cmlog, "ibcm_write_service_record: "
		    "ibmf_saa_update_service_record timed out"
		    " SID = %llX, rval = %d, saa_type = %d",
		    (longlong_t)srv_recp->ServiceID, rval, saa_type);
		delay(ibcm_sa_timeout_delay);
	}
	ibcm_sa_access_exit();

	if (rval != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_write_service_record: "
		    "ibmf_saa_update_service_record() : Failed - %d", rval);
		return (ibcm_ibmf_analyze_error(rval));
	} else
		return (IBT_SUCCESS);
}


static void
ibcm_rem_stale_srec(ibmf_saa_handle_t saa_handle, sa_service_record_t *srec)
{
	ibt_status_t		retval;
	uint_t			num_found;
	size_t			length;
	sa_service_record_t	*srv_resp;
	void			*results_p;
	uint_t			i;
	uint64_t		component_mask;
	ibmf_saa_access_args_t	access_args;

	component_mask =
	    SA_SR_COMPMASK_PKEY | SA_SR_COMPMASK_NAME | SA_SR_COMPMASK_GID;

	/* Call in SA Access retrieve routine to get Service Records. */
	access_args.sq_attr_id = SA_SERVICERECORD_ATTRID;
	access_args.sq_access_type = IBMF_SAA_RETRIEVE;
	access_args.sq_component_mask = component_mask;
	access_args.sq_template = srec;
	access_args.sq_template_length = sizeof (sa_service_record_t);
	access_args.sq_callback = NULL;
	access_args.sq_callback_arg = NULL;

	retval = ibcm_contact_sa_access(saa_handle, &access_args, &length,
	    &results_p);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_rem_stale_srec: "
		    "SA Access Failure");
		return;
	}

	num_found = length / sizeof (sa_service_record_t);

	if (num_found)
		IBTF_DPRINTF_L3(cmlog, "ibcm_rem_stale_srec: "
		    "Found %d matching Service Records.", num_found);

	/* Validate the returned number of records. */
	if ((results_p != NULL) && (num_found > 0)) {

		/* Remove all the records. */
		for (i = 0; i < num_found; i++) {

			srv_resp = (sa_service_record_t *)
			    ((uchar_t *)results_p +
			    i * sizeof (sa_service_record_t));

			/*
			 * Found some matching records, but check out whether
			 * this Record is really stale or just happens to match
			 * the current session records. If yes, don't remove it.
			 */
			mutex_enter(&ibcm_svc_info_lock);
			if (ibcm_find_svc_entry(srv_resp->ServiceID) != NULL) {
				/* This record is NOT STALE. */
				mutex_exit(&ibcm_svc_info_lock);
				IBTF_DPRINTF_L3(cmlog, "ibcm_rem_stale_srec: "
				    "This is not Stale, it's an active record");
				continue;
			}
			mutex_exit(&ibcm_svc_info_lock);

			IBTF_DPRINTF_L2(cmlog, "ibcm_rem_stale_srec: "
			    "Removing Stale Rec: %s, %llX",
			    srv_resp->ServiceName, srv_resp->ServiceID);

			IBCM_DUMP_SERVICE_REC(srv_resp);

			/*
			 * Remove the Service Record Entry from SA.
			 *
			 * Get ServiceID info from Response Buf, other
			 * attributes are already filled-in.
			 */

			 _NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(srec->ServiceID))

			srec->ServiceID = srv_resp->ServiceID;

			 _NOTE(NOW_VISIBLE_TO_OTHER_THREADS(srec->ServiceID))

			(void) ibcm_write_service_record(saa_handle, srec,
			    IBMF_SAA_DELETE);
		}

		/* Deallocate the memory for results_p. */
		kmem_free(results_p, length);
	}
}



/*
 * ibt_bind_service()
 *	Register a service with the IBCM
 *
 * INPUTS:
 *	srv_hdl		The service id handle returned to the client
 *			on an ibt_service_register() call.
 *
 *	gid		The GID to which to bind the service.
 *
 *	srv_bind	The address of a ibt_srv_bind_t that describes
 *			the service record.  This should be NULL if there
 *			is to be no service record.  This contains:
 *
 *		sb_lease	Lease period
 *		sb_pkey		Partition
 *		sb_name		pointer to ASCII string Service Name,
 *				NULL terminated.
 *		sb_key[]	Key to secure the service record.
 *		sb_data		Service Data structure (64-byte)
 *
 *	cm_private	First argument of Service handler.
 *
 *	sb_hdl_p	The address of a service bind handle, used
 *			to undo the service binding.
 *
 * ibt_bind_service() returns:
 *	IBT_SUCCESS		- added a service successfully.
 *	IBT_INVALID_PARAM	- invalid input parameter.
 *	IBT_CM_FAILURE		- failed to add the service.
 *	IBT_CM_SERVICE_EXISTS	- service already exists.
 */
ibt_status_t
ibt_bind_service(ibt_srv_hdl_t srv_hdl, ib_gid_t gid, ibt_srv_bind_t *srv_bind,
    void *cm_private, ibt_sbind_hdl_t *sb_hdl_p)
{
	ibt_status_t		status;
	ibtl_cm_hca_port_t	port;
	ibcm_svc_bind_t		*sbindp, *sbp;
	ibcm_hca_info_t		*hcap;
	ib_svc_id_t		sid, start_sid, end_sid;
	ibmf_saa_handle_t	saa_handle;
	sa_service_record_t	srv_rec;
	uint16_t		pkey_ix;

	if (sb_hdl_p != NULL)
		*sb_hdl_p = NULL;	/* return value for error cases */

	IBTF_DPRINTF_L2(cmlog, "ibt_bind_service: srv_hdl %p, gid (%llX:%llX)",
	    srv_hdl, (longlong_t)gid.gid_prefix, (longlong_t)gid.gid_guid);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sbindp))

	/* Call ibtl_cm_get_hca_port to get the port number and the HCA GUID. */
	if ((status = ibtl_cm_get_hca_port(gid, 0, &port)) != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_bind_service: "
		    "ibtl_cm_get_hca_port failed: %d", status);
		return (status);
	}
	IBTF_DPRINTF_L4(cmlog, "ibt_bind_service: Port:%d HCA GUID:%llX",
	    port.hp_port, port.hp_hca_guid);

	hcap = ibcm_find_hca_entry(port.hp_hca_guid);
	if (hcap == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_bind_service: NO HCA found");
		return (IBT_HCA_BUSY_DETACHING);
	}
	IBTF_DPRINTF_L4(cmlog, "ibt_bind_service: hcap = %p", hcap);

	if (srv_bind != NULL) {
		saa_handle = ibcm_get_saa_handle(hcap, port.hp_port);
		if (saa_handle == NULL) {
			IBTF_DPRINTF_L2(cmlog, "ibt_bind_service: "
			    "saa_handle is NULL");
			ibcm_dec_hca_acc_cnt(hcap);
			return (IBT_HCA_PORT_NOT_ACTIVE);
		}
		if (srv_bind->sb_pkey == 0) {
			IBTF_DPRINTF_L2(cmlog, "ibt_bind_service: "
			    "P_Key must not be 0");
			ibcm_dec_hca_acc_cnt(hcap);
			return (IBT_INVALID_PARAM);
		}
		if (strlen(srv_bind->sb_name) >= IB_SVC_NAME_LEN) {
			IBTF_DPRINTF_L2(cmlog, "ibt_bind_service: "
			    "Service Name is too long");
			ibcm_dec_hca_acc_cnt(hcap);
			return (IBT_INVALID_PARAM);
		} else
			IBTF_DPRINTF_L3(cmlog, "ibt_bind_service: "
			    "Service Name='%s'", srv_bind->sb_name);
		status = ibt_pkey2index_byguid(port.hp_hca_guid,
		    port.hp_port, srv_bind->sb_pkey, &pkey_ix);
		if (status != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibt_bind_service: "
			    "P_Key 0x%x not found in P_Key_Table",
			    srv_bind->sb_pkey);
			ibcm_dec_hca_acc_cnt(hcap);
			return (status);
		}
	}

	/* assume success - allocate before locking */
	sbindp = kmem_zalloc(sizeof (*sbindp), KM_SLEEP);
	sbindp->sbind_cm_private = cm_private;
	sbindp->sbind_gid = gid;
	sbindp->sbind_hcaguid = port.hp_hca_guid;
	sbindp->sbind_port = port.hp_port;

	mutex_enter(&ibcm_svc_info_lock);

	sbp = srv_hdl->svc_bind_list;
	while (sbp != NULL) {
		if (sbp->sbind_gid.gid_guid == gid.gid_guid &&
		    sbp->sbind_gid.gid_prefix == gid.gid_prefix) {
			if (srv_bind == NULL ||
			    srv_bind->sb_pkey == sbp->sbind_pkey) {
				IBTF_DPRINTF_L2(cmlog, "ibt_bind_service: "
				    "failed: GID %llX:%llX and PKEY %x is "
				    "already bound", gid.gid_prefix,
				    gid.gid_guid, sbp->sbind_pkey);
				mutex_exit(&ibcm_svc_info_lock);
				ibcm_dec_hca_acc_cnt(hcap);
				kmem_free(sbindp, sizeof (*sbindp));
				return (IBT_CM_SERVICE_EXISTS);
			}
		}
		sbp = sbp->sbind_link;
	}
	/* no entry found */

	sbindp->sbind_link = srv_hdl->svc_bind_list;
	srv_hdl->svc_bind_list = sbindp;

	mutex_exit(&ibcm_svc_info_lock);

	if (srv_bind != NULL) {
		bzero(&srv_rec, sizeof (srv_rec));

		srv_rec.ServiceLease =
		    sbindp->sbind_lease = srv_bind->sb_lease;
		srv_rec.ServiceP_Key =
		    sbindp->sbind_pkey = srv_bind->sb_pkey;
		srv_rec.ServiceKey_hi =
		    sbindp->sbind_key[0] = srv_bind->sb_key[0];
		srv_rec.ServiceKey_lo =
		    sbindp->sbind_key[1] = srv_bind->sb_key[1];
		(void) strcpy(sbindp->sbind_name, srv_bind->sb_name);
		(void) strcpy((char *)srv_rec.ServiceName, srv_bind->sb_name);
		srv_rec.ServiceGID = gid;

		/*
		 * Find out whether we have any stale Local Service records
		 * matching the current attributes.  If yes, we shall try to
		 * remove them from SA using the current request's ServiceKey.
		 *
		 * We will perform this operation only for Local Services, as
		 * it is handled by SA automatically for WellKnown Services.
		 *
		 * Ofcourse, clients can specify NOT to do this clean-up by
		 * setting IBT_SBIND_NO_CLEANUP flag (srv_bind->sb_flag).
		 */
		if ((srv_hdl->svc_id & IB_SID_AGN_LOCAL) &&
		    (!(srv_bind->sb_flag & IBT_SBIND_NO_CLEANUP))) {
			ibcm_rem_stale_srec(saa_handle, &srv_rec);
		}

		/* Handle endianess for service data. */
		ibcm_swizzle_from_srv(&srv_bind->sb_data, sbindp->sbind_data);

		bcopy(sbindp->sbind_data, srv_rec.ServiceData, IB_SVC_DATA_LEN);

		/* insert srv record into the SA */
		start_sid = srv_hdl->svc_id;
		end_sid = start_sid + srv_hdl->svc_num_sids - 1;
		for (sid = start_sid; sid <= end_sid; sid++) {

			srv_rec.ServiceID = sid;

			IBCM_DUMP_SERVICE_REC(&srv_rec);

			IBTF_DPRINTF_L4(cmlog, "ibt_bind_service: "
			    "ibmf_saa_write_service_record, SvcId = %llX",
			    (longlong_t)sid);

			status = ibcm_write_service_record(saa_handle, &srv_rec,
			    IBMF_SAA_UPDATE);
			if (status != IBT_SUCCESS) {
				IBTF_DPRINTF_L2(cmlog, "ibt_bind_service:"
				    " ibcm_write_service_record fails %d, "
				    "sid %llX", status, (longlong_t)sid);

				if (sid != start_sid) {
					/*
					 * Bind failed while bind SID other than
					 * first in the sid_range.  So we need
					 * to unbind those, which are passed.
					 *
					 * Need to increment svc count to
					 * compensate for ibt_unbind_service().
					 */
					ibcm_inc_hca_svc_cnt(hcap);
					ibcm_dec_hca_acc_cnt(hcap);

					(void) ibt_unbind_service(srv_hdl,
					    sbindp);
				} else {
					ibcm_svc_bind_t		**sbpp;

					/*
					 * Bind failed for the first SID or the
					 * only SID in question, then no need
					 * to unbind, just free memory and
					 * return error.
					 */
					mutex_enter(&ibcm_svc_info_lock);

					sbpp = &srv_hdl->svc_bind_list;
					sbp = *sbpp;
					while (sbp != NULL) {
						if (sbp == sbindp) {
							*sbpp = sbp->sbind_link;
							break;
						}
						sbpp = &sbp->sbind_link;
						sbp = *sbpp;
					}
					mutex_exit(&ibcm_svc_info_lock);
					ibcm_dec_hca_acc_cnt(hcap);

					kmem_free(sbindp, sizeof (*sbindp));
				}
				return (status);
			}
		}
	}
	ibcm_inc_hca_svc_cnt(hcap);
	ibcm_dec_hca_acc_cnt(hcap);

	/* If this message isn't seen then ibt_bind_service failed */
	IBTF_DPRINTF_L2(cmlog, "ibt_bind_service: DONE (%p, %llX:%llX)",
	    srv_hdl, gid.gid_prefix, gid.gid_guid);

	if (sb_hdl_p != NULL)
		*sb_hdl_p = sbindp;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*sbindp))

	return (IBT_SUCCESS);
}

ibt_status_t
ibt_unbind_service(ibt_srv_hdl_t srv_hdl, ibt_sbind_hdl_t sbindp)
{
	ib_svc_id_t	sid, end_sid;
	ibt_status_t	rval;
	ibcm_hca_info_t	*hcap;
	ibcm_svc_bind_t	*sbp, **sbpp;

	IBTF_DPRINTF_L2(cmlog, "ibt_unbind_service(%p, %p)",
	    srv_hdl, sbindp);

	hcap = ibcm_find_hca_entry(sbindp->sbind_hcaguid);

	/* If there is a service on hca, respective hcap cannot go away */
	ASSERT(hcap != NULL);

	mutex_enter(&ibcm_svc_info_lock);

	sbpp = &srv_hdl->svc_bind_list;
	sbp = *sbpp;
	while (sbp != NULL) {
		if (sbp == sbindp) {
			*sbpp = sbp->sbind_link;
			break;
		}
		sbpp = &sbp->sbind_link;
		sbp = *sbpp;
	}
	sid = srv_hdl->svc_id;
	end_sid = srv_hdl->svc_id + srv_hdl->svc_num_sids - 1;
	if (sbp != NULL)
		while (sbp->sbind_rewrite_state == IBCM_REWRITE_BUSY)
			cv_wait(&ibcm_svc_info_cv, &ibcm_svc_info_lock);
	mutex_exit(&ibcm_svc_info_lock);

	if (sbp == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_unbind_service: "
		    "service binding not found: srv_hdl %p, srv_bind %p",
		    srv_hdl, sbindp);
		ibcm_dec_hca_acc_cnt(hcap);
		return (IBT_INVALID_PARAM);
	}

	if (sbindp->sbind_pkey != 0) {	/* Are there service records? */
		ibtl_cm_hca_port_t	port;
		sa_service_record_t	srv_rec;
		ibmf_saa_handle_t	saa_handle;
		ibt_status_t		status;

		/* get the default SGID of the port */
		if ((status = ibtl_cm_get_hca_port(sbindp->sbind_gid, 0, &port))
		    != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibt_unbind_service: "
			    "ibtl_cm_get_hca_port failed: %d", status);
			/* we're done, but there may be stale service records */
			goto done;
		}

		saa_handle = ibcm_get_saa_handle(hcap, port.hp_port);
		if (saa_handle == NULL) {
			IBTF_DPRINTF_L2(cmlog, "ibt_unbind_service: "
			    "saa_handle is NULL");
			/* we're done, but there may be stale service records */
			goto done;
		}

		/* Fill in fields of srv_rec */
		bzero(&srv_rec, sizeof (srv_rec));

		srv_rec.ServiceP_Key = sbindp->sbind_pkey;
		srv_rec.ServiceKey_hi = sbindp->sbind_key[0];
		srv_rec.ServiceKey_lo = sbindp->sbind_key[1];
		srv_rec.ServiceGID = sbindp->sbind_gid;
		(void) strcpy((char *)srv_rec.ServiceName, sbindp->sbind_name);

		while (sid <= end_sid) {

			srv_rec.ServiceID = sid;
			IBCM_DUMP_SERVICE_REC(&srv_rec);

			rval = ibcm_write_service_record(saa_handle, &srv_rec,
			    IBMF_SAA_DELETE);

			IBTF_DPRINTF_L4(cmlog, "ibt_unbind_service: "
			    "ibcm_write_service_record rval = %d, SID %llx",
			    rval, sid);
			if (rval != IBT_SUCCESS) {
				/* this is not considered a reason to fail */
				IBTF_DPRINTF_L2(cmlog, "ibt_unbind_service: "
				    "ibcm_write_service_record fails %d, "
				    "sid %llx", rval, sid);
			}
			sid++;
		}
	}
done:
	ibcm_dec_hca_svc_cnt(hcap);
	ibcm_dec_hca_acc_cnt(hcap);
	kmem_free(sbindp, sizeof (*sbindp));

	/* If this message isn't seen then ibt_unbind_service failed */
	IBTF_DPRINTF_L2(cmlog, "ibt_unbind_service: done !!");

	return (IBT_SUCCESS);
}

/*
 * Simply pull off each binding from the list and unbind it.
 * If any of the unbind calls fail, we fail.
 */
ibt_status_t
ibt_unbind_all_services(ibt_srv_hdl_t srv_hdl)
{
	ibt_status_t	status;
	ibcm_svc_bind_t	*sbp;

	mutex_enter(&ibcm_svc_info_lock);
	sbp = NULL;

	/* this compare keeps the loop from being infinite */
	while (sbp != srv_hdl->svc_bind_list) {
		sbp = srv_hdl->svc_bind_list;
		mutex_exit(&ibcm_svc_info_lock);
		status = ibt_unbind_service(srv_hdl, sbp);
		if (status != IBT_SUCCESS)
			return (status);
		mutex_enter(&ibcm_svc_info_lock);
		if (srv_hdl->svc_bind_list == NULL)
			break;
	}
	mutex_exit(&ibcm_svc_info_lock);
	return (IBT_SUCCESS);
}

/*
 * ibt_deregister_service()
 *	Deregister a service with the IBCM
 *
 * INPUTS:
 *	ibt_hdl		The IBT client handle returned to the client
 *			on an ibt_attach() call.
 *
 *	srv_hdl		The address of a service identification handle, used
 *			to de-register a service.
 * RETURN VALUES:
 *	IBT_SUCCESS	on success (or respective failure on error)
 */
ibt_status_t
ibt_deregister_service(ibt_clnt_hdl_t ibt_hdl, ibt_srv_hdl_t srv_hdl)
{
	ibcm_svc_info_t		*svcp;
	ibcm_svc_lookup_t	svc;

	IBTF_DPRINTF_L2(cmlog, "ibt_deregister_service(%p (%s), %p)",
	    ibt_hdl, ibtl_cm_get_clnt_name(ibt_hdl), srv_hdl);

	mutex_enter(&ibcm_svc_info_lock);

	if (srv_hdl->svc_bind_list != NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_deregister_service:"
		    " srv_hdl %p still has bindings", srv_hdl);
		mutex_exit(&ibcm_svc_info_lock);
		return (IBT_CM_SERVICE_BUSY);
	}
	svc.sid = srv_hdl->svc_id;
	svc.num_sids = 1;
	IBTF_DPRINTF_L3(cmlog, "ibt_deregister_service: SID 0x%llX, numsids %d",
	    srv_hdl->svc_id, srv_hdl->svc_num_sids);

#ifdef __lock_lint
	ibcm_svc_compare(NULL, NULL);
#endif
	svcp = avl_find(&ibcm_svc_avl_tree, &svc, NULL);
	if (svcp != srv_hdl) {
		mutex_exit(&ibcm_svc_info_lock);
		IBTF_DPRINTF_L2(cmlog, "ibt_deregister_service(): "
		    "srv_hdl %p not found", srv_hdl);
		return (IBT_INVALID_PARAM);
	}
	avl_remove(&ibcm_svc_avl_tree, svcp);

	/* wait for active REQ/SREQ handling to be done */
	svcp->svc_to_delete = 1;
	while (svcp->svc_ref_cnt != 0)
		cv_wait(&ibcm_svc_info_cv, &ibcm_svc_info_lock);

	mutex_exit(&ibcm_svc_info_lock);

	if ((srv_hdl->svc_id & IB_SID_AGN_MASK) == IB_SID_AGN_LOCAL)
		ibcm_free_local_sids(srv_hdl->svc_id, srv_hdl->svc_num_sids);

	ibtl_cm_change_service_cnt(ibt_hdl, -srv_hdl->svc_num_sids);
	kmem_free(srv_hdl, sizeof (*srv_hdl));

	/* If this message isn't seen then ibt_deregister_service failed */
	IBTF_DPRINTF_L2(cmlog, "ibt_deregister_service: done !!");

	return (IBT_SUCCESS);
}

ibcm_status_t
ibcm_ar_init(void)
{
	ib_svc_id_t	sid = IBCM_DAPL_ATS_SID;
	ibcm_svc_info_t *tmp_svcp;

	IBTF_DPRINTF_L3(cmlog, "ibcm_ar_init()");

	/* remove this special SID from the pool of available SIDs */
	if ((tmp_svcp = ibcm_create_svc_entry(sid, 1)) == NULL) {
		IBTF_DPRINTF_L3(cmlog, "ibcm_ar_init: "
		    "DAPL ATS SID 0x%llx already registered", (longlong_t)sid);
		return (IBCM_FAILURE);
	}
	mutex_enter(&ibcm_svc_info_lock);
	ibcm_ar_svcinfop = tmp_svcp;
	ibcm_ar_list = NULL;	/* no address records registered yet */
	mutex_exit(&ibcm_svc_info_lock);
	return (IBCM_SUCCESS);
}

ibcm_status_t
ibcm_ar_fini(void)
{
	ibcm_ar_t	*ar_list;
	ibcm_svc_info_t	*tmp_svcp;

	mutex_enter(&ibcm_svc_info_lock);
	ar_list = ibcm_ar_list;

	if (ar_list == NULL &&
	    avl_numnodes(&ibcm_svc_avl_tree) == 1 &&
	    avl_first(&ibcm_svc_avl_tree) == ibcm_ar_svcinfop) {
		avl_remove(&ibcm_svc_avl_tree, ibcm_ar_svcinfop);
		tmp_svcp = ibcm_ar_svcinfop;
		mutex_exit(&ibcm_svc_info_lock);
		kmem_free(tmp_svcp, sizeof (*ibcm_ar_svcinfop));
		return (IBCM_SUCCESS);
	}
	mutex_exit(&ibcm_svc_info_lock);
	return (IBCM_FAILURE);
}


/*
 * Return to the caller:
 *	IBT_SUCCESS		Found a perfect match.
 *				*arpp is set to the record.
 *	IBT_INCONSISTENT_AR	Found a record that's inconsistent.
 *	IBT_AR_NOT_REGISTERED	Found no record with same GID/pkey and
 *				found no record with same data.
 */
static ibt_status_t
ibcm_search_ar(ibt_ar_t *arp, ibcm_ar_t **arpp)
{
	ibcm_ar_t	*tmp;
	int		i;

	ASSERT(MUTEX_HELD(&ibcm_svc_info_lock));
	tmp = ibcm_ar_list;
	while (tmp != NULL) {
		if (tmp->ar.ar_gid.gid_prefix == arp->ar_gid.gid_prefix &&
		    tmp->ar.ar_gid.gid_guid == arp->ar_gid.gid_guid &&
		    tmp->ar.ar_pkey == arp->ar_pkey) {
			for (i = 0; i < IBCM_DAPL_ATS_NBYTES; i++)
				if (tmp->ar.ar_data[i] != arp->ar_data[i])
					return (IBT_INCONSISTENT_AR);
			*arpp = tmp;
			return (IBT_SUCCESS);
		} else {
			/* if all the data bytes match, we have inconsistency */
			for (i = 0; i < IBCM_DAPL_ATS_NBYTES; i++)
				if (tmp->ar.ar_data[i] != arp->ar_data[i])
					break;
			if (i == IBCM_DAPL_ATS_NBYTES)
				return (IBT_INCONSISTENT_AR);
			/* try next address record */
		}
		tmp = tmp->ar_link;
	}
	return (IBT_AR_NOT_REGISTERED);
}

ibt_status_t
ibt_register_ar(ibt_clnt_hdl_t ibt_hdl, ibt_ar_t *arp)
{
	ibcm_ar_t		*found;
	ibcm_ar_t		*tmp;
	ibt_status_t		status;
	ibt_status_t		s1, s2;
	char			*s;
	ibcm_ar_ref_t		*hdlp;
	ibcm_ar_t		*new;
	ibcm_ar_t		**linkp;
	ibtl_cm_hca_port_t	cm_port;
	uint16_t		pkey_ix;
	ibcm_hca_info_t		*hcap;
	ibmf_saa_handle_t	saa_handle;
	sa_service_record_t	*srv_recp;
	uint64_t		gid_ored;

	IBTF_DPRINTF_L3(cmlog, "ibt_register_ar: PKey 0x%X GID %llX:%llX",
	    arp->ar_pkey, (longlong_t)arp->ar_gid.gid_prefix,
	    (longlong_t)arp->ar_gid.gid_guid);

	/*
	 * If P_Key is 0, but GID is not, this query is invalid.
	 * If GID is 0, but P_Key is not, this query is invalid.
	 */
	gid_ored = arp->ar_gid.gid_guid | arp->ar_gid.gid_prefix;
	if ((arp->ar_pkey == 0 && gid_ored != 0ULL) ||
	    (arp->ar_pkey != 0 && gid_ored == 0ULL)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_register_ar: "
		    "GID/P_Key is not valid");
		return (IBT_INVALID_PARAM);
	}

	/* assume success, so these might be needed */
	hdlp = kmem_alloc(sizeof (*hdlp), KM_SLEEP);
	new = kmem_zalloc(sizeof (*new), KM_SLEEP);

	mutex_enter(&ibcm_svc_info_lock);
	/* search for existing GID/pkey (there can be at most 1) */
	status = ibcm_search_ar(arp, &found);
	if (status == IBT_INCONSISTENT_AR) {
		mutex_exit(&ibcm_svc_info_lock);
		kmem_free(new, sizeof (*new));
		kmem_free(hdlp, sizeof (*hdlp));
		IBTF_DPRINTF_L2(cmlog, "ibt_register_ar: "
		    "address record is inconsistent with a known one");
		return (IBT_INCONSISTENT_AR);
	} else if (status == IBT_SUCCESS) {
		if (found->ar_flags == IBCM_AR_INITING) {
			found->ar_waiters++;
			cv_wait(&found->ar_cv, &ibcm_svc_info_lock);
			found->ar_waiters--;
		}
		if (found->ar_flags == IBCM_AR_FAILED) {
			if (found->ar_waiters == 0) {
				cv_destroy(&found->ar_cv);
				kmem_free(found, sizeof (*found));
			}
			mutex_exit(&ibcm_svc_info_lock);
			kmem_free(new, sizeof (*new));
			kmem_free(hdlp, sizeof (*hdlp));
			return (ibt_get_module_failure(IBT_FAILURE_IBCM, 0));
		}
		hdlp->ar_ibt_hdl = ibt_hdl;
		hdlp->ar_ref_link = found->ar_ibt_hdl_list;
		found->ar_ibt_hdl_list = hdlp;
		mutex_exit(&ibcm_svc_info_lock);
		kmem_free(new, sizeof (*new));
		ibtl_cm_change_service_cnt(ibt_hdl, 1);
		return (IBT_SUCCESS);
	} else {
		ASSERT(status == IBT_AR_NOT_REGISTERED);
	}
	hdlp->ar_ref_link = NULL;
	hdlp->ar_ibt_hdl = ibt_hdl;
	new->ar_ibt_hdl_list = hdlp;
	new->ar = *arp;
	new->ar_flags = IBCM_AR_INITING;
	new->ar_waiters = 0;
	cv_init(&new->ar_cv, NULL, CV_DEFAULT, NULL);
	new->ar_link = ibcm_ar_list;
	ibcm_ar_list = new;

	/* verify GID/pkey is valid for a local port, etc. */
	hcap = NULL;
	if ((s1 = ibtl_cm_get_hca_port(arp->ar_gid, 0, &cm_port))
	    != IBT_SUCCESS ||
	    (s2 = ibt_pkey2index_byguid(cm_port.hp_hca_guid, cm_port.hp_port,
	    arp->ar_pkey, &pkey_ix)) != IBT_SUCCESS ||
	    (hcap = ibcm_find_hca_entry(cm_port.hp_hca_guid)) == NULL) {
		cv_destroy(&new->ar_cv);
		ibcm_ar_list = new->ar_link;
		mutex_exit(&ibcm_svc_info_lock);
		kmem_free(new, sizeof (*new));
		kmem_free(hdlp, sizeof (*hdlp));
		status = IBT_INVALID_PARAM;
		if (s1 == IBT_HCA_PORT_NOT_ACTIVE) {
			s = "PORT DOWN";
			status = IBT_HCA_PORT_NOT_ACTIVE;
		} else if (s1 != IBT_SUCCESS)
			s = "GID not found";
		else if (s2 != IBT_SUCCESS)
			s = "PKEY not found";
		else
			s = "CM could not find its HCA entry";
		IBTF_DPRINTF_L2(cmlog, "ibt_register_ar: %s, status = %d",
		    s, status);
		return (status);
	}
	mutex_exit(&ibcm_svc_info_lock);
	saa_handle = ibcm_get_saa_handle(hcap, cm_port.hp_port);

	/* create service record */
	srv_recp = kmem_zalloc(sizeof (*srv_recp), KM_SLEEP);
	srv_recp->ServiceLease = 0xFFFFFFFF;	/* infinite */
	srv_recp->ServiceP_Key = arp->ar_pkey;
	srv_recp->ServiceKey_hi = 0xDA410000ULL;	/* DAPL */
	srv_recp->ServiceKey_lo = 0xA7500000ULL;	/* ATS */
	(void) strcpy((char *)srv_recp->ServiceName, IBCM_DAPL_ATS_NAME);
	srv_recp->ServiceGID = arp->ar_gid;
	bcopy(arp->ar_data, srv_recp->ServiceData, IBCM_DAPL_ATS_NBYTES);
	srv_recp->ServiceID = IBCM_DAPL_ATS_SID;

	/* insert service record into the SA */

	IBCM_DUMP_SERVICE_REC(srv_recp);

	if (saa_handle != NULL)
		status = ibcm_write_service_record(saa_handle, srv_recp,
		    IBMF_SAA_UPDATE);
	else
		status = IBT_HCA_PORT_NOT_ACTIVE;

	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_register_ar: sa access fails %d, "
		    "sid %llX", status, (longlong_t)srv_recp->ServiceID);
		IBTF_DPRINTF_L2(cmlog, "ibt_register_ar: FAILED for gid "
		    "%llX:%llX pkey 0x%X", (longlong_t)arp->ar_gid.gid_prefix,
		    (longlong_t)arp->ar_gid.gid_guid, arp->ar_pkey);

		kmem_free(srv_recp, sizeof (*srv_recp));
		kmem_free(hdlp, sizeof (*hdlp));

		mutex_enter(&ibcm_svc_info_lock);
		linkp = &ibcm_ar_list;
		tmp = *linkp;
		while (tmp != NULL) {
			if (tmp == new) {
				*linkp = new->ar_link;
				break;
			}
			linkp = &tmp->ar_link;
			tmp = *linkp;
		}
		if (new->ar_waiters > 0) {
			new->ar_flags = IBCM_AR_FAILED;
			cv_broadcast(&new->ar_cv);
			mutex_exit(&ibcm_svc_info_lock);
		} else {
			cv_destroy(&new->ar_cv);
			mutex_exit(&ibcm_svc_info_lock);
			kmem_free(new, sizeof (*new));
		}
		ibcm_dec_hca_acc_cnt(hcap);
		IBTF_DPRINTF_L2(cmlog, "ibt_register_ar: "
		    "IBMF_SAA failed to write address record");
	} else {					/* SUCCESS */
		uint8_t		*b;

		IBTF_DPRINTF_L3(cmlog, "ibt_register_ar: SUCCESS for gid "
		    "%llx:%llx pkey %x", (longlong_t)arp->ar_gid.gid_prefix,
		    (longlong_t)arp->ar_gid.gid_guid, arp->ar_pkey);
		b = arp->ar_data;

		IBTF_DPRINTF_L3(cmlog, "ibt_register_ar:"
		    " data %d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d",
		    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9],
		    b[10], b[11], b[12], b[13], b[14], b[15]);
		mutex_enter(&ibcm_svc_info_lock);
		new->ar_srv_recp = srv_recp;
		new->ar_saa_handle = saa_handle;
		new->ar_port = cm_port.hp_port;
		new->ar_hcap = hcap;
		new->ar_flags = IBCM_AR_SUCCESS;
		if (new->ar_waiters > 0)
			cv_broadcast(&new->ar_cv);
		mutex_exit(&ibcm_svc_info_lock);
		ibtl_cm_change_service_cnt(ibt_hdl, 1);
		/* do not call ibcm_dec_hca_acc_cnt(hcap) until deregister */
	}
	return (status);
}

ibt_status_t
ibt_deregister_ar(ibt_clnt_hdl_t ibt_hdl, ibt_ar_t *arp)
{
	ibcm_ar_t		*found;
	ibcm_ar_t		*tmp;
	ibcm_ar_t		**linkp;
	ibcm_ar_ref_t		*hdlp;
	ibcm_ar_ref_t		**hdlpp;
	ibt_status_t		status;
	ibmf_saa_handle_t	saa_handle;
	sa_service_record_t	*srv_recp;
	uint64_t		gid_ored;

	IBTF_DPRINTF_L3(cmlog, "ibt_deregister_ar: pkey %x", arp->ar_pkey);
	IBTF_DPRINTF_L3(cmlog, "ibt_deregister_ar: gid %llx:%llx",
	    (longlong_t)arp->ar_gid.gid_prefix,
	    (longlong_t)arp->ar_gid.gid_guid);

	/*
	 * If P_Key is 0, but GID is not, this query is invalid.
	 * If GID is 0, but P_Key is not, this query is invalid.
	 */
	gid_ored = arp->ar_gid.gid_guid | arp->ar_gid.gid_prefix;
	if ((arp->ar_pkey == 0 && gid_ored != 0ULL) ||
	    (arp->ar_pkey != 0 && gid_ored == 0ULL)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_deregister_ar: "
		    "GID/P_Key is not valid");
		return (IBT_INVALID_PARAM);
	}

	mutex_enter(&ibcm_svc_info_lock);
	/* search for existing GID/pkey (there can be at most 1) */
	status = ibcm_search_ar(arp, &found);
	if (status == IBT_INCONSISTENT_AR || status == IBT_AR_NOT_REGISTERED) {
		mutex_exit(&ibcm_svc_info_lock);
		IBTF_DPRINTF_L2(cmlog, "ibt_deregister_ar: "
		    "address record not found");
		return (IBT_AR_NOT_REGISTERED);
	}
	ASSERT(status == IBT_SUCCESS);

	hdlpp = &found->ar_ibt_hdl_list;
	hdlp = *hdlpp;
	while (hdlp != NULL) {
		if (hdlp->ar_ibt_hdl == ibt_hdl)
			break;
		hdlpp = &hdlp->ar_ref_link;
		hdlp = *hdlpp;
	}
	if (hdlp == NULL) {	/* could not find ibt_hdl on list */
		mutex_exit(&ibcm_svc_info_lock);
		IBTF_DPRINTF_L2(cmlog, "ibt_deregister_ar: "
		    "address record found, but not for this client");
		return (IBT_AR_NOT_REGISTERED);
	}
	*hdlpp = hdlp->ar_ref_link;	/* remove ref for this client */
	if (found->ar_ibt_hdl_list == NULL && found->ar_waiters == 0) {
		/* last entry was removed */
		found->ar_flags = IBCM_AR_INITING; /* hold off register_ar */
		saa_handle = found->ar_saa_handle;
		srv_recp = found->ar_srv_recp;

		/* wait if this service record is being rewritten */
		while (found->ar_rewrite_state == IBCM_REWRITE_BUSY)
			cv_wait(&ibcm_svc_info_cv, &ibcm_svc_info_lock);
		mutex_exit(&ibcm_svc_info_lock);

		/* remove service record */
		status = ibcm_write_service_record(saa_handle, srv_recp,
		    IBMF_SAA_DELETE);
		if (status != IBT_SUCCESS)
			IBTF_DPRINTF_L2(cmlog, "ibt_deregister_ar: "
			    "IBMF_SAA failed to delete address record");
		mutex_enter(&ibcm_svc_info_lock);
		if (found->ar_waiters == 0) {	/* still no waiters */
			linkp = &ibcm_ar_list;
			tmp = *linkp;
			while (tmp != found) {
				linkp = &tmp->ar_link;
				tmp = *linkp;
			}
			*linkp = tmp->ar_link;
			ibcm_dec_hca_acc_cnt(found->ar_hcap);
			kmem_free(srv_recp, sizeof (*srv_recp));
			cv_destroy(&found->ar_cv);
			kmem_free(found, sizeof (*found));
		} else {
			/* add service record back in for the waiters */
			mutex_exit(&ibcm_svc_info_lock);
			status = ibcm_write_service_record(saa_handle, srv_recp,
			    IBMF_SAA_UPDATE);
			mutex_enter(&ibcm_svc_info_lock);
			if (status == IBT_SUCCESS)
				found->ar_flags = IBCM_AR_SUCCESS;
			else {
				found->ar_flags = IBCM_AR_FAILED;
				IBTF_DPRINTF_L2(cmlog, "ibt_deregister_ar: "
				    "IBMF_SAA failed to write address record");
			}
			cv_broadcast(&found->ar_cv);
		}
	}
	mutex_exit(&ibcm_svc_info_lock);
	kmem_free(hdlp, sizeof (*hdlp));
	ibtl_cm_change_service_cnt(ibt_hdl, -1);
	return (status);
}

ibt_status_t
ibt_query_ar(ib_gid_t *sgid, ibt_ar_t *queryp, ibt_ar_t *resultp)
{
	sa_service_record_t	svcrec_req;
	sa_service_record_t	*svcrec_resp;
	void			*results_p;
	uint64_t		component_mask = 0;
	uint64_t		gid_ored;
	size_t			length;
	int			num_rec;
	int			i;
	ibmf_saa_access_args_t	access_args;
	ibt_status_t		retval;
	ibtl_cm_hca_port_t	cm_port;
	ibcm_hca_info_t		*hcap;
	ibmf_saa_handle_t	saa_handle;

	IBTF_DPRINTF_L3(cmlog, "ibt_query_ar(%p, %p)", queryp, resultp);
	IBTF_DPRINTF_L3(cmlog, "ibt_query_ar: sgid %llx:%llx",
	    (longlong_t)sgid->gid_prefix, (longlong_t)sgid->gid_guid);
	IBTF_DPRINTF_L3(cmlog, "ibt_query_ar: query_pkey %x", queryp->ar_pkey);
	IBTF_DPRINTF_L3(cmlog, "ibt_query_ar: query_gid %llx:%llx",
	    (longlong_t)queryp->ar_gid.gid_prefix,
	    (longlong_t)queryp->ar_gid.gid_guid);

	/*
	 * If P_Key is 0, but GID is not, this query is invalid.
	 * If GID is 0, but P_Key is not, this query is invalid.
	 */
	gid_ored = queryp->ar_gid.gid_guid | queryp->ar_gid.gid_prefix;
	if ((queryp->ar_pkey == 0 && gid_ored != 0ULL) ||
	    (queryp->ar_pkey != 0 && gid_ored == 0ULL)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_query_ar: GID/P_Key is not valid");
		return (IBT_INVALID_PARAM);
	}

	hcap = NULL;
	if (ibtl_cm_get_hca_port(*sgid, 0, &cm_port) != IBT_SUCCESS ||
	    (hcap = ibcm_find_hca_entry(cm_port.hp_hca_guid)) == NULL ||
	    (saa_handle = ibcm_get_saa_handle(hcap, cm_port.hp_port)) == NULL) {
		if (hcap != NULL)
			ibcm_dec_hca_acc_cnt(hcap);
		IBTF_DPRINTF_L2(cmlog, "ibt_query_ar: sgid is not valid");
		return (IBT_INVALID_PARAM);
	}

	bzero(&svcrec_req, sizeof (svcrec_req));

	/* Is GID/P_Key Specified. */
	if (queryp->ar_pkey != 0) {	/* GID is non-zero from check above */
		svcrec_req.ServiceP_Key = queryp->ar_pkey;
		component_mask |= SA_SR_COMPMASK_PKEY;
		IBTF_DPRINTF_L3(cmlog, "ibt_query_ar: P_Key %X",
		    queryp->ar_pkey);
		svcrec_req.ServiceGID = queryp->ar_gid;
		component_mask |= SA_SR_COMPMASK_GID;
		IBTF_DPRINTF_L3(cmlog, "ibt_query_ar: GID %llX:%llX",
		    (longlong_t)queryp->ar_gid.gid_prefix,
		    (longlong_t)queryp->ar_gid.gid_guid);
	}

	/* Is ServiceData Specified. */
	for (i = 0; i < IBCM_DAPL_ATS_NBYTES; i++) {
		if (queryp->ar_data[i] != 0) {
			bcopy(queryp->ar_data, svcrec_req.ServiceData,
			    IBCM_DAPL_ATS_NBYTES);
			component_mask |= 0xFFFF << 7;	/* all 16 Data8 */
							/* components */
			break;
		}
	}

	/* Service Name */
	(void) strcpy((char *)svcrec_req.ServiceName, IBCM_DAPL_ATS_NAME);
	component_mask |= SA_SR_COMPMASK_NAME;

	svcrec_req.ServiceID = IBCM_DAPL_ATS_SID;
	component_mask |= SA_SR_COMPMASK_ID;

	IBTF_DPRINTF_L3(cmlog, "ibt_query_ar: "
	    "Perform SA Access: Mask: 0x%X", component_mask);

	/*
	 * Call in SA Access retrieve routine to get Service Records.
	 *
	 * SA Access framework allocated memory for the "results_p".
	 * Make sure to deallocate once we are done with the results_p.
	 * The size of the buffer allocated will be as returned in
	 * "length" field.
	 */
	access_args.sq_attr_id = SA_SERVICERECORD_ATTRID;
	access_args.sq_access_type = IBMF_SAA_RETRIEVE;
	access_args.sq_component_mask = component_mask;
	access_args.sq_template = &svcrec_req;
	access_args.sq_template_length = sizeof (sa_service_record_t);
	access_args.sq_callback = NULL;
	access_args.sq_callback_arg = NULL;

	retval = ibcm_contact_sa_access(saa_handle, &access_args, &length,
	    &results_p);

	ibcm_dec_hca_acc_cnt(hcap);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_query_ar: SA Access Failed");
		return (retval);
	}

	num_rec = length / sizeof (sa_service_record_t);

	IBTF_DPRINTF_L3(cmlog, "ibt_query_ar: "
	    "Found %d Service Records.", num_rec);

	/* Validate the returned number of records. */
	if ((results_p != NULL) && (num_rec > 0)) {
		uint8_t		*b;

		/* Just return info from the first service record. */
		svcrec_resp = (sa_service_record_t *)results_p;

		/* The Service GID and Service ID */
		resultp->ar_gid = svcrec_resp->ServiceGID;
		resultp->ar_pkey = svcrec_resp->ServiceP_Key;
		bcopy(svcrec_resp->ServiceData,
		    resultp->ar_data, IBCM_DAPL_ATS_NBYTES);

		IBTF_DPRINTF_L3(cmlog, "ibt_query_ar: "
		    "Found: pkey %x dgid %llX:%llX", resultp->ar_pkey,
		    (longlong_t)resultp->ar_gid.gid_prefix,
		    (longlong_t)resultp->ar_gid.gid_guid);
		b = resultp->ar_data;
		IBTF_DPRINTF_L3(cmlog, "ibt_query_ar:"
		    " data %d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d",
		    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9],
		    b[10], b[11], b[12], b[13], b[14], b[15]);

		/* Deallocate the memory for results_p. */
		kmem_free(results_p, length);
		if (num_rec > 1)
			retval = IBT_MULTIPLE_AR;
		else
			retval = IBT_SUCCESS;
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibt_query_ar: "
		    "ibmf_sa_access found 0 matching records");
		retval = IBT_AR_NOT_REGISTERED;
	}
	return (retval);
}

/* mark all ATS service records associated with the port */
static void
ibcm_mark_ar(ib_guid_t hca_guid, uint8_t port)
{
	ibcm_ar_t	*tmp;

	ASSERT(MUTEX_HELD(&ibcm_svc_info_lock));
	for (tmp = ibcm_ar_list; tmp != NULL; tmp = tmp->ar_link) {
		if (tmp->ar_hcap == NULL)
			continue;
		if (tmp->ar_hcap->hca_guid == hca_guid &&
		    tmp->ar_port == port) {
			/* even if it's busy, we mark it for rewrite */
			tmp->ar_rewrite_state = IBCM_REWRITE_NEEDED;
		}
	}
}

/* rewrite all ATS service records */
static int
ibcm_rewrite_ar(void)
{
	ibcm_ar_t		*tmp;
	ibmf_saa_handle_t	saa_handle;
	sa_service_record_t	*srv_recp;
	ibt_status_t		rval;
	int			did_something = 0;

	ASSERT(MUTEX_HELD(&ibcm_svc_info_lock));
check_for_work:
	for (tmp = ibcm_ar_list; tmp != NULL; tmp = tmp->ar_link) {
		if (tmp->ar_rewrite_state == IBCM_REWRITE_NEEDED) {
			tmp->ar_rewrite_state = IBCM_REWRITE_BUSY;
			saa_handle = tmp->ar_saa_handle;
			srv_recp = tmp->ar_srv_recp;
			mutex_exit(&ibcm_svc_info_lock);
			IBTF_DPRINTF_L3(cmlog, "ibcm_rewrite_ar: "
			    "rewriting ar @ %p", tmp);
			did_something = 1;
			rval = ibcm_write_service_record(saa_handle, srv_recp,
			    IBMF_SAA_UPDATE);
			if (rval != IBT_SUCCESS)
				IBTF_DPRINTF_L2(cmlog, "ibcm_rewrite_ar: "
				    "ibcm_write_service_record failed: "
				    "status = %d", rval);
			mutex_enter(&ibcm_svc_info_lock);
			/* if it got marked again, then we want to rewrite */
			if (tmp->ar_rewrite_state == IBCM_REWRITE_BUSY)
				tmp->ar_rewrite_state = IBCM_REWRITE_IDLE;
			/* in case there was a waiter... */
			cv_broadcast(&ibcm_svc_info_cv);
			goto check_for_work;
		}
	}
	return (did_something);
}

static void
ibcm_rewrite_svc_record(ibcm_svc_info_t *srv_hdl, ibcm_svc_bind_t *sbindp)
{
	ibcm_hca_info_t		*hcap;
	ib_svc_id_t		sid, start_sid, end_sid;
	ibmf_saa_handle_t	saa_handle;
	sa_service_record_t	srv_rec;
	ibt_status_t		rval;

	hcap = ibcm_find_hca_entry(sbindp->sbind_hcaguid);
	if (hcap == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_rewrite_svc_record: "
		    "NO HCA found for HCA GUID %llX", sbindp->sbind_hcaguid);
		return;
	}

	saa_handle = ibcm_get_saa_handle(hcap, sbindp->sbind_port);
	if (saa_handle == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_rewrite_svc_record: "
		    "saa_handle is NULL");
		ibcm_dec_hca_acc_cnt(hcap);
		return;
	}

	IBTF_DPRINTF_L3(cmlog, "ibcm_rewrite_svc_record: "
	    "rewriting svc '%s', port_guid = %llX", sbindp->sbind_name,
	    sbindp->sbind_gid.gid_guid);

	bzero(&srv_rec, sizeof (srv_rec));

	srv_rec.ServiceLease = sbindp->sbind_lease;
	srv_rec.ServiceP_Key = sbindp->sbind_pkey;
	srv_rec.ServiceKey_hi = sbindp->sbind_key[0];
	srv_rec.ServiceKey_lo = sbindp->sbind_key[1];
	(void) strcpy((char *)srv_rec.ServiceName, sbindp->sbind_name);
	srv_rec.ServiceGID = sbindp->sbind_gid;

	bcopy(sbindp->sbind_data, srv_rec.ServiceData, IB_SVC_DATA_LEN);

	/* insert srv record into the SA */
	start_sid = srv_hdl->svc_id;
	end_sid = start_sid + srv_hdl->svc_num_sids - 1;
	for (sid = start_sid; sid <= end_sid; sid++) {
		srv_rec.ServiceID = sid;

		rval = ibcm_write_service_record(saa_handle, &srv_rec,
		    IBMF_SAA_UPDATE);

		IBTF_DPRINTF_L4(cmlog, "ibcm_rewrite_svc_record: "
		    "ibcm_write_service_record, SvcId = %llX, "
		    "rval = %d", (longlong_t)sid, rval);
		if (rval != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_rewrite_svc_record:"
			    " ibcm_write_service_record fails %d sid %llX",
			    rval, (longlong_t)sid);
		}
	}
	ibcm_dec_hca_acc_cnt(hcap);
}

/*
 * Task to mark all service records as needing to be rewritten to the SM/SA.
 * This task does not return until all of them have been rewritten.
 */
void
ibcm_service_record_rewrite_task(void *arg)
{
	ibcm_port_up_t	*pup = (ibcm_port_up_t *)arg;
	ib_guid_t	hca_guid = pup->pup_hca_guid;
	uint8_t		port = pup->pup_port;
	ibcm_svc_info_t	*svcp;
	ibcm_svc_bind_t	*sbp;
	avl_tree_t	*avl_tree = &ibcm_svc_avl_tree;
	static int	task_is_running = 0;

	IBTF_DPRINTF_L3(cmlog, "ibcm_service_record_rewrite_task STARTED "
	    "for hca_guid %llX, port %d", hca_guid, port);

	mutex_enter(&ibcm_svc_info_lock);
	ibcm_mark_ar(hca_guid, port);
	for (svcp = avl_first(avl_tree); svcp != NULL;
	    svcp = avl_walk(avl_tree, svcp, AVL_AFTER)) {
		sbp = svcp->svc_bind_list;
		while (sbp != NULL) {
			if (sbp->sbind_pkey != 0 &&
			    sbp->sbind_port == port &&
			    sbp->sbind_hcaguid == hca_guid) {
				/* even if it's busy, we mark it for rewrite */
				sbp->sbind_rewrite_state = IBCM_REWRITE_NEEDED;
			}
			sbp = sbp->sbind_link;
		}
	}
	if (task_is_running) {
		/* let the other task thread finish the work */
		mutex_exit(&ibcm_svc_info_lock);
		return;
	}
	task_is_running = 1;

	(void) ibcm_rewrite_ar();

check_for_work:
	for (svcp = avl_first(avl_tree); svcp != NULL;
	    svcp = avl_walk(avl_tree, svcp, AVL_AFTER)) {
		sbp = svcp->svc_bind_list;
		while (sbp != NULL) {
			if (sbp->sbind_rewrite_state == IBCM_REWRITE_NEEDED) {
				sbp->sbind_rewrite_state = IBCM_REWRITE_BUSY;
				mutex_exit(&ibcm_svc_info_lock);
				ibcm_rewrite_svc_record(svcp, sbp);
				mutex_enter(&ibcm_svc_info_lock);
				/* if it got marked again, we want to rewrite */
				if (sbp->sbind_rewrite_state ==
				    IBCM_REWRITE_BUSY)
					sbp->sbind_rewrite_state =
					    IBCM_REWRITE_IDLE;
				/* in case there was a waiter... */
				cv_broadcast(&ibcm_svc_info_cv);
				goto check_for_work;
			}
			sbp = sbp->sbind_link;
		}
	}
	/*
	 * If there were no service records to write, and we failed to
	 * have to rewrite any more ATS service records, then we're done.
	 */
	if (ibcm_rewrite_ar() != 0)
		goto check_for_work;
	task_is_running = 0;
	mutex_exit(&ibcm_svc_info_lock);

	IBTF_DPRINTF_L3(cmlog, "ibcm_service_record_rewrite_task DONE");
	kmem_free(pup, sizeof (ibcm_port_up_t));
}

ibt_status_t
ibt_ofuvcm_get_req_data(void *session_id, ibt_ofuvcm_req_data_t *req_data)
{
	ibcm_state_data_t 	*statep = (ibcm_state_data_t *)session_id;
	ibcm_req_msg_t 		*req_msgp;

	IBTF_DPRINTF_L3(cmlog, "ibt_get_ofuvcm_req_data: session_id %p",
	    session_id);
	mutex_enter(&statep->state_mutex);
	if ((statep->state != IBCM_STATE_REQ_RCVD) &&
	    (statep->state != IBCM_STATE_MRA_SENT)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_get_ofuvcm_req_data: Invalid "
		    "State %x", statep->state);
		mutex_exit(&statep->state_mutex);
		return (IBT_CHAN_STATE_INVALID);
	}
	if (statep->mode == IBCM_ACTIVE_MODE) {
		IBTF_DPRINTF_L2(cmlog, "ibt_get_ofuvcm_req_data: Active mode "
		    "not supported");
		mutex_exit(&statep->state_mutex);
		return (IBT_INVALID_PARAM);
	}
	ASSERT(statep->req_msgp);

	/*
	 * Fill in the additional req message values reqired for
	 * RTR transition.
	 * Should the PSN be same as the active side??
	 */
	req_msgp = (ibcm_req_msg_t *)statep->req_msgp;
	req_data->req_rnr_nak_time = ibcm_default_rnr_nak_time;
	req_data->req_path_mtu = req_msgp->req_mtu_plus >> 4;
	req_data->req_rq_psn = b2h32(req_msgp->req_starting_psn_plus) >> 8;
	mutex_exit(&statep->state_mutex);
	return (IBT_SUCCESS);
}

ibt_status_t
ibt_ofuvcm_proceed(ibt_cm_event_type_t event, void *session_id,
    ibt_cm_status_t status, ibt_cm_proceed_reply_t *cm_event_data,
    void *priv_data, ibt_priv_data_len_t priv_data_len)
{
	ibcm_state_data_t *statep = (ibcm_state_data_t *)session_id;
	ibt_status_t		ret;

	IBTF_DPRINTF_L3(cmlog, "ibt_ofuvcm_proceed chan 0x%p event %x "
	    "status %x session_id %p", statep->channel, event, status,
	    session_id);

	IBTF_DPRINTF_L5(cmlog, "ibt_ofuvcm_proceed chan 0x%p "
	    "cm_event_data %p, priv_data %p priv_data_len %x",
	    statep->channel, cm_event_data, priv_data, priv_data_len);

	/* validate session_id and status */
	if ((statep == NULL) || (status == IBT_CM_DEFER)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_ofuvcm_proceed : Invalid Args");
		return (IBT_INVALID_PARAM);
	}

	if (event != IBT_CM_EVENT_REQ_RCV) {
		IBTF_DPRINTF_L2(cmlog, "ibt_ofuvcm_proceed : only for REQ_RCV");
		return (IBT_INVALID_PARAM);
	}
	mutex_enter(&statep->state_mutex);
	statep->is_this_ofuv_chan = B_TRUE;
	mutex_exit(&statep->state_mutex);

	ret = ibt_cm_proceed(event, session_id, status, cm_event_data,
	    priv_data, priv_data_len);
	return (ret);
}

/*
 * Function:
 * 	ibt_cm_proceed
 *
 * Verifies the arguments and dispatches the cm state machine processing
 * via taskq
 */

ibt_status_t
ibt_cm_proceed(ibt_cm_event_type_t event, void *session_id,
    ibt_cm_status_t status, ibt_cm_proceed_reply_t *cm_event_data,
    void *priv_data, ibt_priv_data_len_t priv_data_len)
{
	ibcm_state_data_t *statep = (ibcm_state_data_t *)session_id;
	ibcm_proceed_targs_t	*proceed_targs;
	ibcm_proceed_error_t	proceed_error;

	IBTF_DPRINTF_L3(cmlog, "ibt_cm_proceed chan 0x%p event %x status %x "
	    "session_id %p", statep->channel, event, status, session_id);

	IBTF_DPRINTF_L5(cmlog, "ibt_cm_proceed chan 0x%p cm_event_data %p, "
	    "priv_data %p priv_data_len %x", statep->channel, cm_event_data,
	    priv_data, priv_data_len);

	/* validate session_id and status */
	if ((statep == NULL) || (status == IBT_CM_DEFER)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_cm_proceed : Invalid Args");
		return (IBT_INVALID_PARAM);
	}

	/* If priv data len specified, then priv_data cannot be NULL */
	if ((priv_data_len > 0) && (priv_data == NULL))
		return (IBT_INVALID_PARAM);

	proceed_error = IBCM_PROCEED_INVALID_NONE;

	mutex_enter(&statep->state_mutex);
	if (event == IBT_CM_EVENT_REQ_RCV) {

		if ((statep->state != IBCM_STATE_REQ_RCVD) &&
		    (statep->state != IBCM_STATE_MRA_SENT))
			proceed_error = IBCM_PROCEED_INVALID_EVENT_STATE;
		else if (priv_data_len > IBT_REP_PRIV_DATA_SZ)
			proceed_error = IBCM_PROCEED_INVALID_PRIV_SZ;

	} else if (event == IBT_CM_EVENT_REP_RCV) {
		if ((statep->state != IBCM_STATE_REP_RCVD) &&
		    (statep->state != IBCM_STATE_MRA_REP_SENT))
			proceed_error = IBCM_PROCEED_INVALID_EVENT_STATE;
		else if (priv_data_len > IBT_RTU_PRIV_DATA_SZ)
			proceed_error = IBCM_PROCEED_INVALID_PRIV_SZ;
	} else if (event == IBT_CM_EVENT_LAP_RCV) {
		if ((statep->ap_state != IBCM_AP_STATE_LAP_RCVD) &&
		    (statep->ap_state != IBCM_AP_STATE_MRA_LAP_SENT))
			proceed_error = IBCM_PROCEED_INVALID_EVENT_STATE;
		else if (priv_data_len > IBT_APR_PRIV_DATA_SZ)
			proceed_error = IBCM_PROCEED_INVALID_PRIV_SZ;
	} else if (event == IBT_CM_EVENT_CONN_CLOSED) {
		if (statep->state != IBCM_STATE_DREQ_RCVD)
			proceed_error = IBCM_PROCEED_INVALID_EVENT_STATE;
		else if (priv_data_len > IBT_DREP_PRIV_DATA_SZ)
			proceed_error = IBCM_PROCEED_INVALID_PRIV_SZ;
	} else {
			proceed_error = IBCM_PROCEED_INVALID_EVENT;
	}

	/* if there is an error, print an error message and return */
	if (proceed_error != IBCM_PROCEED_INVALID_NONE) {
		mutex_exit(&statep->state_mutex);
		if (proceed_error == IBCM_PROCEED_INVALID_EVENT_STATE) {
			IBTF_DPRINTF_L2(cmlog, "ibt_cm_proceed : chan 0x%p"
			    "Invalid Event/State combination specified",
			    statep->channel);
			return (IBT_INVALID_PARAM);
		} else if (proceed_error == IBCM_PROCEED_INVALID_PRIV_SZ) {
			IBTF_DPRINTF_L2(cmlog, "ibt_cm_proceed : chan 0x%p"
			    "Invalid Event/priv len combination specified",
			    statep->channel);
			return (IBT_INVALID_PARAM);
		} else if (proceed_error == IBCM_PROCEED_INVALID_EVENT) {
			IBTF_DPRINTF_L2(cmlog, "ibt_cm_proceed : chan 0x%p"
			    "Invalid Event specified", statep->channel);
			return (IBT_INVALID_PARAM);
		} else {
			ASSERT(proceed_error == IBCM_PROCEED_INVALID_LAP);
			IBTF_DPRINTF_L2(cmlog, "ibt_cm_proceed : chan 0x%p"
			    "IBT_CM_EVENT_LAP_RCV not supported",
			    statep->channel);
			/* UNTIL HCA DRIVER ENABLES AP SUPPORT, FAIL THE CALL */
			return (IBT_APM_NOT_SUPPORTED);
		}
	}


	/* wait until client's CM handler returns DEFER status back to CM */

	while (statep->clnt_proceed == IBCM_BLOCK) {
		IBTF_DPRINTF_L5(cmlog, "ibt_cm_proceed : chan 0x%p blocked for "
		    "return of client's cm handler", statep->channel);
		cv_wait(&statep->block_client_cv, &statep->state_mutex);
	}

	if (statep->clnt_proceed == IBCM_FAIL) {
		mutex_exit(&statep->state_mutex);
		IBTF_DPRINTF_L2(cmlog, "ibt_cm_proceed : chan 0x%p Failed as "
		    "client returned non-DEFER status from cm handler",
		    statep->channel);
		return (IBT_CHAN_STATE_INVALID);
	}

	ASSERT(statep->clnt_proceed == IBCM_UNBLOCK);
	statep->clnt_proceed = IBCM_FAIL;
	mutex_exit(&statep->state_mutex);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*proceed_targs))

	/* the state machine processing is done in a separate thread */

	/* proceed_targs is freed in ibcm_proceed_via_taskq */
	proceed_targs = kmem_alloc(sizeof (ibcm_proceed_targs_t),
	    KM_SLEEP);

	proceed_targs->event  = event;
	proceed_targs->status = status;
	proceed_targs->priv_data_len = priv_data_len;

	bcopy(priv_data, proceed_targs->priv_data, priv_data_len);

	proceed_targs->tst.rc.statep = statep;
	bcopy(cm_event_data, &proceed_targs->tst.rc.rc_cm_event_data,
	    sizeof (ibt_cm_proceed_reply_t));

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*proceed_targs))

	(void) taskq_dispatch(ibcm_taskq, ibcm_proceed_via_taskq,
	    proceed_targs, TQ_SLEEP);

	return (IBT_SUCCESS);
}

/*
 * Function:
 * 	ibcm_proceed_via_taskq
 *
 * Called from taskq, dispatched by ibt_cm_proceed
 * Completes the cm state processing for ibt_cm_proceed
 */
void
ibcm_proceed_via_taskq(void *targs)
{
	ibcm_proceed_targs_t	*proceed_targs = (ibcm_proceed_targs_t *)targs;
	ibcm_state_data_t *statep = proceed_targs->tst.rc.statep;
	ibt_cm_reason_t reject_reason;
	uint8_t arej_len;
	ibcm_status_t response;
	ibcm_clnt_reply_info_t clnt_info;

	clnt_info.reply_event = &proceed_targs->tst.rc.rc_cm_event_data;
	clnt_info.priv_data = proceed_targs->priv_data;
	clnt_info.priv_data_len = proceed_targs->priv_data_len;

	IBTF_DPRINTF_L4(cmlog, "ibcm_proceed_via_taskq chan 0x%p targs %x",
	    statep->channel, targs);

	if (proceed_targs->event == IBT_CM_EVENT_REQ_RCV) {
		response =
		    ibcm_process_cep_req_cm_hdlr(statep, proceed_targs->status,
		    &clnt_info, &reject_reason, &arej_len,
		    (ibcm_req_msg_t *)statep->defer_cm_msg);

		ibcm_handle_cep_req_response(statep, response, reject_reason,
		    arej_len);

	} else if (proceed_targs->event == IBT_CM_EVENT_REP_RCV) {
		response =
		    ibcm_process_cep_rep_cm_hdlr(statep, proceed_targs->status,
		    &clnt_info, &reject_reason, &arej_len,
		    (ibcm_rep_msg_t *)statep->defer_cm_msg);

		ibcm_handle_cep_rep_response(statep, response, reject_reason,
		    arej_len, (ibcm_rep_msg_t *)statep->defer_cm_msg);

	} else if (proceed_targs->event == IBT_CM_EVENT_LAP_RCV) {
		ibcm_process_cep_lap_cm_hdlr(statep, proceed_targs->status,
		    &clnt_info, (ibcm_lap_msg_t *)statep->defer_cm_msg,
		    (ibcm_apr_msg_t *)IBCM_OUT_MSGP(statep->lapr_msg));

		ibcm_post_apr_mad(statep);

	} else {
		ASSERT(proceed_targs->event == IBT_CM_EVENT_CONN_CLOSED);
		ibcm_handle_cep_dreq_response(statep, proceed_targs->priv_data,
		    proceed_targs->priv_data_len);
	}

	kmem_free(targs, sizeof (ibcm_proceed_targs_t));
}

/*
 * Function:
 * 	ibt_cm_ud_proceed
 *
 * Verifies the arguments and dispatches the cm state machine processing
 * via taskq
 */
ibt_status_t
ibt_cm_ud_proceed(void *session_id, ibt_channel_hdl_t ud_channel,
    ibt_cm_status_t status, ibt_redirect_info_t *redirect_infop,
    void *priv_data, ibt_priv_data_len_t priv_data_len)
{
	ibcm_ud_state_data_t *ud_statep = (ibcm_ud_state_data_t *)session_id;
	ibcm_proceed_targs_t	*proceed_targs;
	ibt_qp_query_attr_t	qp_attr;
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(cmlog, "ibt_cm_ud_proceed session_id %p "
	    "ud_channel %p ", session_id, ud_channel);

	IBTF_DPRINTF_L4(cmlog, "ibt_cm_ud_proceed status %x priv_data %p "
	    "priv_data_len %x",  status, priv_data, priv_data_len);

	/* validate session_id and status */
	if ((ud_statep == NULL) || (status == IBT_CM_DEFER)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_cm_ud_proceed : Invalid Args");
		return (IBT_INVALID_PARAM);
	}

	/* If priv data len specified, then priv_data cannot be NULL */
	if ((priv_data_len > 0) && (priv_data == NULL))
		return (IBT_INVALID_PARAM);

	if (priv_data_len > IBT_SIDR_REP_PRIV_DATA_SZ)
		return (IBT_INVALID_PARAM);

	/* retrieve qpn and qkey from ud channel */

	/* validate event and statep's state */

	if (status == IBT_CM_ACCEPT) {
		retval = ibt_query_qp(ud_channel, &qp_attr);
		if ((retval != IBT_SUCCESS) ||
		    (qp_attr.qp_info.qp_trans != IBT_UD_SRV)) {
			IBTF_DPRINTF_L2(cmlog, "ibt_cm_ud_proceed: "
			    "Failed to retrieve QPN from the channel: %d",
			    retval);
			return (IBT_INVALID_PARAM);
		}
	}


	mutex_enter(&ud_statep->ud_state_mutex);

	if (ud_statep->ud_state != IBCM_STATE_SIDR_REQ_RCVD) {
		mutex_exit(&ud_statep->ud_state_mutex);
		IBTF_DPRINTF_L2(cmlog, "ibt_cm_ud_proceed : Invalid State "
		    "specified");
		return (IBT_INVALID_PARAM);
	}

	/* wait until client's CM handler returns DEFER status back to CM */

	while (ud_statep->ud_clnt_proceed == IBCM_BLOCK) {
		IBTF_DPRINTF_L5(cmlog, "ibt_cm_ud_proceed : Blocked for return"
		    " of client's ud cm handler");
		cv_wait(&ud_statep->ud_block_client_cv,
		    &ud_statep->ud_state_mutex);
	}

	if (ud_statep->ud_clnt_proceed == IBCM_FAIL) {
		mutex_exit(&ud_statep->ud_state_mutex);
		IBTF_DPRINTF_L2(cmlog, "ibt_cm_ud_proceed : Failed as client "
		    "returned non-DEFER status from cm handler");
		return (IBT_INVALID_PARAM);
	}

	ASSERT(ud_statep->ud_clnt_proceed == IBCM_UNBLOCK);
	ud_statep->ud_clnt_proceed = IBCM_FAIL;
	mutex_exit(&ud_statep->ud_state_mutex);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*proceed_targs))

	/* the state machine processing is done in a separate thread */

	/* proceed_targs is freed in ibcm_proceed_via_taskq */
	proceed_targs = kmem_zalloc(sizeof (ibcm_proceed_targs_t),
	    KM_SLEEP);

	proceed_targs->status = status;
	proceed_targs->priv_data_len = priv_data_len;

	bcopy(priv_data, proceed_targs->priv_data, priv_data_len);

	if (status == IBT_CM_ACCEPT) {
		proceed_targs->tst.ud.ud_qkey =
		    qp_attr.qp_info.qp_transport.ud.ud_qkey;
		proceed_targs->tst.ud.ud_qpn = qp_attr.qp_qpn;
	}

	proceed_targs->tst.ud.ud_statep = ud_statep;

	/* copy redirect info based on status */
	if (status == IBT_CM_REDIRECT)
		bcopy(redirect_infop, &proceed_targs->tst.ud.ud_redirect_info,
		    sizeof (ibt_redirect_info_t));

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*proceed_targs))

	(void) taskq_dispatch(ibcm_taskq, ibcm_ud_proceed_via_taskq,
	    proceed_targs, TQ_SLEEP);

	return (IBT_SUCCESS);
}

/*
 * Function:
 * 	ibcm_ud_proceed_via_taskq
 *
 * Called from taskq, dispatched by ibt_cm_ud_proceed
 * Completes the cm state processing for ibt_cm_ud_proceed
 */
void
ibcm_ud_proceed_via_taskq(void *targs)
{
	ibcm_proceed_targs_t	*proceed_targs = (ibcm_proceed_targs_t *)targs;
	ibcm_ud_state_data_t	*ud_statep = proceed_targs->tst.ud.ud_statep;
	ibcm_ud_clnt_reply_info_t ud_clnt_info;
	ibt_sidr_status_t	sidr_status;

	IBTF_DPRINTF_L4(cmlog, "ibcm_ud_proceed_via_taskq(%p)", targs);

	ud_clnt_info.ud_qpn  = proceed_targs->tst.ud.ud_qpn;
	ud_clnt_info.ud_qkey  = proceed_targs->tst.ud.ud_qkey;
	ud_clnt_info.priv_data = proceed_targs->priv_data;
	ud_clnt_info.priv_data_len = proceed_targs->priv_data_len;
	ud_clnt_info.redirect_infop = &proceed_targs->tst.ud.ud_redirect_info;

	/* validate event and statep's state */
	ibcm_process_sidr_req_cm_hdlr(ud_statep, proceed_targs->status,
	    &ud_clnt_info, &sidr_status,
	    (ibcm_sidr_rep_msg_t *)IBCM_OUT_MSGP(ud_statep->ud_stored_msg));

	ibcm_post_sidr_rep_mad(ud_statep, sidr_status);

	/* decr the statep ref cnt incremented in ibcm_process_sidr_req_msg */
	mutex_enter(&ud_statep->ud_state_mutex);
	IBCM_UD_REF_CNT_DECR(ud_statep);
	mutex_exit(&ud_statep->ud_state_mutex);

	kmem_free(targs, sizeof (ibcm_proceed_targs_t));
}

/*
 * Function:
 *	ibt_set_alt_path
 * Input:
 *	channel		Channel handle returned from ibt_alloc_rc_channel(9F).
 *
 *	mode		Execute in blocking or non blocking mode.
 *
 *	alt_path	A pointer to an ibt_alt_path_info_t as returned from an
 *			ibt_get_alt_path(9F) call that specifies the new
 *			alternate path.
 *
 *	priv_data       A pointer to a buffer specified by caller for the
 *			private data in the outgoing CM Load Alternate Path
 *			(LAP) message sent to the remote host. This can be NULL
 *			if no private data is available to communicate to the
 *			remote node.
 *
 *	priv_data_len   Length of valid data in priv_data, this should be less
 *			than or equal to IBT_LAP_PRIV_DATA_SZ.
 *
 * Output:
 *	ret_args	If called in blocking mode, points to a return argument
 *			structure of type ibt_ap_returns_t.
 *
 * Returns:
 *	IBT_SUCCESS on Success else appropriate error.
 * Description:
 *	Load the specified alternate path. Causes the CM to send an LAP message
 *	to the remote node.
 *	Can only be called on a previously opened RC channel.
 */
ibt_status_t
ibt_set_alt_path(ibt_channel_hdl_t channel, ibt_execution_mode_t mode,
    ibt_alt_path_info_t *alt_path, void *priv_data,
    ibt_priv_data_len_t priv_data_len, ibt_ap_returns_t *ret_args)
{
	ibmf_handle_t		ibmf_hdl;
	ibt_status_t		status = IBT_SUCCESS;
	ibcm_lap_msg_t		*lap_msgp;
	ibcm_hca_info_t		*hcap;
	ibcm_state_data_t	*statep;
	uint8_t			port_no;
	ib_lid_t		alternate_slid;
	ibt_priv_data_len_t	len;
	ib_lid_t		base_lid;
	boolean_t		alt_grh;

	IBTF_DPRINTF_L3(cmlog, "ibt_set_alt_path(%p, %x, %p, %p, %x, %p)",
	    channel, mode, alt_path, priv_data, priv_data_len, ret_args);

	/* validate channel */
	if (IBCM_INVALID_CHANNEL(channel)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_set_alt_path: invalid channel");
		return (IBT_CHAN_HDL_INVALID);
	}

	if (ibtl_cm_get_chan_type(channel) != IBT_RC_SRV) {
		IBTF_DPRINTF_L2(cmlog, "ibt_set_alt_path: "
		    "Invalid Channel type: Applicable only to RC Channel");
		return (IBT_CHAN_SRV_TYPE_INVALID);
	}

	if (mode == IBT_NONBLOCKING) {
		if (ret_args != NULL) {
			IBTF_DPRINTF_L2(cmlog, "ibt_set_alt_path: "
			    "ret_args should be NULL when called in "
			    "non-blocking mode");
			return (IBT_INVALID_PARAM);
		}
	} else if (mode == IBT_BLOCKING) {
		if (ret_args == NULL) {
			IBTF_DPRINTF_L2(cmlog, "ibt_set_alt_path: "
			    "ret_args should be Non-NULL when called in "
			    "blocking mode");
			return (IBT_INVALID_PARAM);
		}
		if (ret_args->ap_priv_data_len > IBT_APR_PRIV_DATA_SZ) {
			IBTF_DPRINTF_L2(cmlog, "ibt_set_alt_path: "
			    "expected private data length is too large");
			return (IBT_INVALID_PARAM);
		}
		if ((ret_args->ap_priv_data_len > 0) &&
		    (ret_args->ap_priv_data == NULL)) {
			IBTF_DPRINTF_L2(cmlog, "ibt_set_alt_path: "
			    "apr_priv_data_len > 0, but apr_priv_data NULL");
			return (IBT_INVALID_PARAM);
		}
	} else { /* any other mode is not valid for ibt_set_alt_path */
		IBTF_DPRINTF_L2(cmlog, "ibt_set_alt_path: "
		    "invalid mode %x specified", mode);
		return (IBT_INVALID_PARAM);
	}

	if ((port_no = alt_path->ap_alt_cep_path.cep_hca_port_num) == 0)
		return (IBT_INVALID_PARAM);

	/* get the statep */
	IBCM_GET_CHAN_PRIVATE(channel, statep);
	if (statep == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_set_alt_path: statep NULL");
		return (IBT_CM_FAILURE);
	}

	mutex_enter(&statep->state_mutex);
	IBCM_RELEASE_CHAN_PRIVATE(channel);
	IBCM_REF_CNT_INCR(statep);
	mutex_exit(&statep->state_mutex);

	IBTF_DPRINTF_L4(cmlog, "ibt_set_alt_path: statep %p", statep);

	hcap = statep->hcap;

	/* HCA must have been in active state. If not, it's a client bug */
	if (!IBCM_ACCESS_HCA_OK(hcap))
		IBTF_DPRINTF_L2(cmlog, "ibt_set_alt_path: hca in error state");

	ASSERT(statep->cm_handler != NULL);

	/* Check Alternate port */
	status = ibt_get_port_state_byguid(hcap->hca_guid, port_no, NULL,
	    &base_lid);
	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_set_alt_path: "
		    "ibt_get_port_state_byguid status %d ", status);
		mutex_enter(&statep->state_mutex);
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		return (status);
	}

	if ((hcap->hca_port_info[port_no - 1].port_ibmf_hdl == NULL) &&
	    ((status = ibcm_hca_reinit_port(hcap, port_no - 1))
	    != IBT_SUCCESS)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_set_alt_path: "
		    "ibmf reg or callback setup failed during re-initialize");
		mutex_enter(&statep->state_mutex);
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		return (status);
	}

	ibmf_hdl = statep->stored_reply_addr.ibmf_hdl;

	alternate_slid = base_lid +
	    alt_path->ap_alt_cep_path.cep_adds_vect.av_src_path;

	IBTF_DPRINTF_L4(cmlog, "ibt_set_alt_path: alternate SLID = %x",
	    h2b16(alternate_slid));

	ibcm_lapr_enter();	/* limit how many run simultaneously */

	/* Allocate MAD for LAP */
	if (statep->lapr_msg == NULL)
		if ((status = ibcm_alloc_out_msg(ibmf_hdl, &statep->lapr_msg,
		    MAD_METHOD_SEND)) != IBT_SUCCESS) {
			ibcm_lapr_exit();
			IBTF_DPRINTF_L2(cmlog, "ibt_set_alt_path: "
			    "chan 0x%p ibcm_alloc_out_msg failed", channel);
			mutex_enter(&statep->state_mutex);
			IBCM_REF_CNT_DECR(statep);
			mutex_exit(&statep->state_mutex);
			return (status);
		}

	mutex_enter(&statep->state_mutex);

	IBTF_DPRINTF_L4(cmlog, "ibt_set_alt_path: connection state is"
	    " %x", statep->state);

	/* Check state */
	if ((statep->state != IBCM_STATE_ESTABLISHED) ||
	    (statep->ap_state != IBCM_AP_STATE_IDLE)) {
		IBCM_REF_CNT_DECR(statep);
		mutex_exit(&statep->state_mutex);
		(void) ibcm_free_out_msg(ibmf_hdl, &statep->lapr_msg);
		ibcm_lapr_exit();
		return (IBT_CHAN_STATE_INVALID);
	} else {
		/* Set to LAP Sent state */
		statep->ap_state = IBCM_AP_STATE_LAP_SENT;
		statep->ap_done = B_FALSE;
		statep->remaining_retry_cnt = statep->max_cm_retries;
		statep->timer_stored_state = statep->state;
		statep->timer_stored_ap_state = statep->ap_state;
		IBCM_REF_CNT_INCR(statep); /* for ibcm_post_lap_complete */
	}

	mutex_exit(&statep->state_mutex);

	/* No more failure returns below */

	/* Allocate MAD for LAP */
	IBTF_DPRINTF_L5(cmlog, "ibt_set_alt_path:"
	    " statep's mad addr = 0x%p", IBCM_OUT_HDRP(statep->lapr_msg));

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*lap_msgp))

	lap_msgp = (ibcm_lap_msg_t *)IBCM_OUT_MSGP(statep->lapr_msg);

	lap_msgp->lap_alt_l_port_lid = h2b16(alternate_slid);
	lap_msgp->lap_alt_r_port_lid =
	    h2b16(alt_path->ap_alt_cep_path.cep_adds_vect.av_dlid);

	/* Fill in remote port gid */
	lap_msgp->lap_alt_r_port_gid.gid_prefix =
	    h2b64(alt_path->ap_alt_cep_path.cep_adds_vect.av_dgid.gid_prefix);
	lap_msgp->lap_alt_r_port_gid.gid_guid =
	    h2b64(alt_path->ap_alt_cep_path.cep_adds_vect.av_dgid.gid_guid);

	/* Fill in local port gid */
	lap_msgp->lap_alt_l_port_gid.gid_prefix =
	    h2b64(alt_path->ap_alt_cep_path.cep_adds_vect.av_sgid.gid_prefix);
	lap_msgp->lap_alt_l_port_gid.gid_guid =
	    h2b64(alt_path->ap_alt_cep_path.cep_adds_vect.av_sgid.gid_guid);

	alt_grh = alt_path->ap_alt_cep_path.cep_adds_vect.av_send_grh;

	/* alternate_flow_label, and alternate srate, alternate traffic class */
	lap_msgp->lap_alt_srate_plus =
	    alt_path->ap_alt_cep_path.cep_adds_vect.av_srate & 0x3f;
	lap_msgp->lap_alt_flow_label_plus = h2b32(((alt_grh == B_TRUE) ?
	    (alt_path->ap_alt_cep_path.cep_adds_vect.av_flow << 12) : 0) |
	    alt_path->ap_alt_cep_path.cep_adds_vect.av_tclass);

	/* Alternate hop limit, service level */
	lap_msgp->lap_alt_hop_limit = (alt_grh == B_TRUE) ?
	    alt_path->ap_alt_cep_path.cep_adds_vect.av_hop : 1;
	lap_msgp->lap_alt_sl_plus =
	    alt_path->ap_alt_cep_path.cep_adds_vect.av_srvl << 4 |
	    ((alt_grh == B_FALSE) ? 0x8 : 0);

	lap_msgp->lap_alt_local_acktime_plus = ibt_usec2ib(
	    (2 * statep->rc_alt_pkt_lt) +
	    ibt_ib2usec(hcap->hca_ack_delay)) << 3;

	lap_msgp->lap_local_comm_id = h2b32(statep->local_comid);
	lap_msgp->lap_remote_comm_id = h2b32(statep->remote_comid);

	lap_msgp->lap_remote_qpn_eecn_plus =
	    h2b32((statep->remote_qpn << 8) |
	    ibt_usec2ib(ibcm_remote_response_time) << 3);

	len = min(priv_data_len, IBT_LAP_PRIV_DATA_SZ);
	if ((len > 0) && priv_data) {
		bcopy(priv_data, lap_msgp->lap_private_data, len);
	}

	/* only rc_alt_pkt_lt and ap_return_data fields are initialized */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*statep))

	statep->rc_alt_pkt_lt = ibt_ib2usec(alt_path->ap_alt_pkt_lt);

	/* return_data is filled up in the state machine code */
	statep->ap_return_data = ret_args;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*statep))

	IBCM_OUT_HDRP(statep->lapr_msg)->AttributeID =
	    h2b16(IBCM_INCOMING_LAP + IBCM_ATTR_BASE_ID);

	IBCM_OUT_HDRP(statep->lapr_msg)->TransactionID =
	    h2b64(ibcm_generate_tranid(IBCM_INCOMING_LAP, statep->local_comid,
	    0));
	IBTF_DPRINTF_L3(cmlog, "ibt_set_alt_path: statep %p, tid %llx",
	    statep, IBCM_OUT_HDRP(statep->lapr_msg)->TransactionID);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*lap_msgp))

	/* Send LAP */
	ibcm_post_rc_mad(statep, statep->lapr_msg, ibcm_post_lap_complete,
	    statep);

	mutex_enter(&statep->state_mutex);

	if (mode == IBT_BLOCKING) {
		IBTF_DPRINTF_L4(cmlog, "ibt_set_alt_path: blocking");

		/* wait for APR */
		while (statep->ap_done != B_TRUE) {
			cv_wait(&statep->block_client_cv,
			    &statep->state_mutex);
		}

		IBTF_DPRINTF_L4(cmlog, "ibt_set_alt_path: done blocking");

		/*
		 * In the case that ibt_set_alt_path fails,
		 * change retval to IBT_CM_FAILURE
		 */
		if (statep->ap_return_data->ap_status != IBT_CM_AP_LOADED)
			status = IBT_CM_FAILURE;

	}

	/* decrement the ref-count before leaving here */
	IBCM_REF_CNT_DECR(statep);

	mutex_exit(&statep->state_mutex);

	ibcm_lapr_exit();

	/* If this message isn't seen then ibt_set_alt_path failed */
	IBTF_DPRINTF_L4(cmlog, "ibt_set_alt_path: done");

	return (status);
}


#ifdef DEBUG

/*
 * ibcm_query_classport_info:
 *	Query classportinfo
 *
 * INPUTS:
 *	channel		- Channel that is associated with a statep
 *
 * RETURN VALUE: NONE
 * This function is currently used to generate a valid get method classport
 * info, and test CM functionality. There is no ibtl client interface to
 * generate a classportinfo. It is possible that CM may use classportinfo
 * from other nodes in the future, and most of the code below could be re-used.
 */
void
ibcm_query_classport_info(ibt_channel_hdl_t channel)
{
	ibcm_state_data_t	*statep;
	ibmf_msg_t		*msgp;

	IBTF_DPRINTF_L3(cmlog, "ibcm_query_classport_info(%p)", channel);

	/* validate channel, first */
	if (IBCM_INVALID_CHANNEL(channel)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_query_classport_info: "
		    "invalid channel (%p)", channel);
		return;
	}

	/* get the statep */
	IBCM_GET_CHAN_PRIVATE(channel, statep);

	/*
	 * This can happen, if the statep is already gone by a DREQ from
	 * the remote side
	 */
	if (statep == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_query_classport_info: "
		    "statep NULL");
		return;
	}

	mutex_enter(&statep->state_mutex);
	IBCM_RELEASE_CHAN_PRIVATE(channel);
	IBCM_REF_CNT_INCR(statep);
	mutex_exit(&statep->state_mutex);

	/* Debug/test code, so don't care about return status */
	(void) ibcm_alloc_out_msg(statep->stored_reply_addr.ibmf_hdl, &msgp,
	    MAD_METHOD_GET);

	IBCM_OUT_HDRP(msgp)->TransactionID = h2b64(ibcm_generate_tranid(
	    MAD_ATTR_ID_CLASSPORTINFO, statep->local_comid, 0));
	IBCM_OUT_HDRP(msgp)->AttributeID = h2b16(MAD_ATTR_ID_CLASSPORTINFO);

	(void) ibcm_post_mad(msgp, &statep->stored_reply_addr, NULL, NULL);

	IBTF_DPRINTF_L3(cmlog, "ibcm_query_classport_info(%p) "
	    "Get method MAD posted ", channel);

	(void) ibcm_free_out_msg(statep->stored_reply_addr.ibmf_hdl, &msgp);

	mutex_enter(&statep->state_mutex);
	IBCM_REF_CNT_DECR(statep);
	mutex_exit(&statep->state_mutex);
}

static void
ibcm_print_reply_addr(ibt_channel_hdl_t channel, ibcm_mad_addr_t *cm_reply_addr)
{
	IBTF_DPRINTF_L4(cmlog, "ibcm_print_reply_addr: chan 0x%p, SLID %x, "
	    "DLID %x", channel, cm_reply_addr->rcvd_addr.ia_local_lid,
	    cm_reply_addr->rcvd_addr.ia_remote_lid);

	IBTF_DPRINTF_L4(cmlog, "ibcm_print_reply_addr: QKEY %x, PKEY %x, "
	    "RQPN %x SL %x", cm_reply_addr->rcvd_addr.ia_q_key,
	    cm_reply_addr->rcvd_addr.ia_p_key,
	    cm_reply_addr->rcvd_addr.ia_remote_qno,
	    cm_reply_addr->rcvd_addr.ia_service_level);

	IBTF_DPRINTF_L4(cmlog, "ibcm_print_reply_addr: CM SGID %llX:%llX ",
	    cm_reply_addr->grh_hdr.ig_sender_gid.gid_prefix,
	    cm_reply_addr->grh_hdr.ig_sender_gid.gid_guid);

	IBTF_DPRINTF_L4(cmlog, "ibcm_print_reply_addr: CM DGID %llX:%llX",
	    cm_reply_addr->grh_hdr.ig_recver_gid.gid_prefix,
	    cm_reply_addr->grh_hdr.ig_recver_gid.gid_guid);

	IBTF_DPRINTF_L4(cmlog, "ibcm_print_reply_addr: CM FL %x TC %x HL %x",
	    cm_reply_addr->grh_hdr.ig_flow_label,
	    cm_reply_addr->grh_hdr.ig_tclass,
	    cm_reply_addr->grh_hdr.ig_hop_limit);
}

#endif

/* For MCG List search */
typedef struct ibcm_mcg_list_s {
	struct ibcm_mcg_list_s	*ml_next;
	ib_gid_t		ml_sgid;
	ib_gid_t		ml_mgid;
	ib_pkey_t		ml_pkey;
	ib_qkey_t		ml_qkey;
	uint_t			ml_refcnt;
	uint8_t			ml_jstate;
} ibcm_mcg_list_t;

ibcm_mcg_list_t	*ibcm_mcglist = NULL;

_NOTE(MUTEX_PROTECTS_DATA(ibcm_mcglist_lock, ibcm_mcg_list_s))
_NOTE(MUTEX_PROTECTS_DATA(ibcm_mcglist_lock, ibcm_mcglist))

typedef struct ibcm_join_mcg_tqarg_s {
	ib_gid_t		rgid;
	ibt_mcg_attr_t		mcg_attr;
	ibt_mcg_info_t		*mcg_infop;
	ibt_mcg_handler_t	func;
	void			*arg;
} ibcm_join_mcg_tqarg_t;

_NOTE(READ_ONLY_DATA(ibcm_join_mcg_tqarg_s))

void
ibcm_add_incr_mcg_entry(sa_mcmember_record_t *mcg_req,
    sa_mcmember_record_t *mcg_resp)
{
	ibcm_mcg_list_t	*new = NULL;
	ibcm_mcg_list_t	*head = NULL;

	IBTF_DPRINTF_L3(cmlog, "ibcm_add_incr_mcg_entry: MGID %llX:%llX"
	    "\n SGID %llX:%llX, JState %X)", mcg_req->MGID.gid_prefix,
	    mcg_req->MGID.gid_guid, mcg_req->PortGID.gid_prefix,
	    mcg_req->PortGID.gid_guid, mcg_req->JoinState);

	mutex_enter(&ibcm_mcglist_lock);
	head = ibcm_mcglist;

	while (head != NULL) {
		if ((head->ml_mgid.gid_guid == mcg_resp->MGID.gid_guid) &&
		    (head->ml_mgid.gid_prefix == mcg_resp->MGID.gid_prefix) &&
		    (head->ml_sgid.gid_guid == mcg_resp->PortGID.gid_guid)) {
			/* Increment the count */
			head->ml_refcnt++;
			/* OR the join_state value, we need this during leave */
			head->ml_jstate |= mcg_req->JoinState;

			IBTF_DPRINTF_L3(cmlog, "ibcm_add_incr_mcg_entry: Entry "
			    "FOUND: refcnt %d JState %X", head->ml_refcnt,
			    head->ml_jstate);

			mutex_exit(&ibcm_mcglist_lock);
			return;
		}
		head = head->ml_next;
	}
	mutex_exit(&ibcm_mcglist_lock);

	IBTF_DPRINTF_L3(cmlog, "ibcm_add_incr_mcg_entry: Create NEW Entry ");

	/* If we are here, either list is empty or match couldn't be found */
	new = kmem_zalloc(sizeof (ibcm_mcg_list_t), KM_SLEEP);

	mutex_enter(&ibcm_mcglist_lock);
	/* Initialize the fields */
	new->ml_sgid = mcg_resp->PortGID;
	new->ml_mgid = mcg_resp->MGID;
	new->ml_qkey = mcg_req->Q_Key;
	new->ml_pkey = mcg_req->P_Key;
	new->ml_refcnt = 1; /* As this is the first entry */
	new->ml_jstate = mcg_req->JoinState;
	new->ml_next = NULL;

	new->ml_next = ibcm_mcglist;
	ibcm_mcglist = new;
	mutex_exit(&ibcm_mcglist_lock);
}

/*
 * ibcm_del_decr_mcg_entry
 *
 * Return value:
 * IBCM_SUCCESS		Entry found and ref_cnt is now zero. So go-ahead and
 * 			leave the MCG group. The return arg *jstate will have
 * 			a valid join_state value that needed to be used by
 * 			xxx_leave_mcg().
 * IBCM_LOOKUP_EXISTS	Entry found and ref_cnt is decremented but is NOT zero.
 * 			So do not leave the MCG group yet.
 * IBCM_LOOKUP_FAIL	Entry is NOT found.
 */
ibcm_status_t
ibcm_del_decr_mcg_entry(sa_mcmember_record_t *mcg_req, uint8_t *jstate)
{
	ibcm_mcg_list_t	*head, *prev;

	IBTF_DPRINTF_L3(cmlog, "ibcm_del_decr_mcg_entry: MGID %llX:%llX"
	    "\n SGID %llX:%llX, JState %X)", mcg_req->MGID.gid_prefix,
	    mcg_req->MGID.gid_guid, mcg_req->PortGID.gid_prefix,
	    mcg_req->PortGID.gid_guid, mcg_req->JoinState);

	*jstate = 0;

	mutex_enter(&ibcm_mcglist_lock);
	head = ibcm_mcglist;
	prev = NULL;

	while (head != NULL) {
		if ((head->ml_mgid.gid_guid == mcg_req->MGID.gid_guid) &&
		    (head->ml_mgid.gid_prefix == mcg_req->MGID.gid_prefix) &&
		    (head->ml_sgid.gid_guid == mcg_req->PortGID.gid_guid)) {
			if (!(head->ml_jstate & mcg_req->JoinState)) {
				IBTF_DPRINTF_L2(cmlog, "ibcm_del_decr_mcg_entry"
				    ": JoinState mismatch %X %X)",
				    head->ml_jstate, mcg_req->JoinState);
			}
			/* Decrement the count */
			head->ml_refcnt--;

			if (head->ml_refcnt == 0) {
				*jstate = head->ml_jstate;

				IBTF_DPRINTF_L3(cmlog, "ibcm_del_decr_mcg_entry"
				    ": refcnt is ZERO, so delete the entry ");
				if ((head == ibcm_mcglist) || (prev == NULL)) {
					ibcm_mcglist = head->ml_next;
				} else if (prev != NULL) {
					prev->ml_next = head->ml_next;
				}
				mutex_exit(&ibcm_mcglist_lock);

				kmem_free(head, sizeof (ibcm_mcg_list_t));
				return (IBCM_SUCCESS);
			}
			mutex_exit(&ibcm_mcglist_lock);
			return (IBCM_LOOKUP_EXISTS);
		}
		prev = head;
		head = head->ml_next;
	}
	mutex_exit(&ibcm_mcglist_lock);

	/*
	 * If we are here, something went wrong, we don't have the entry
	 * for that MCG being joined.
	 */
	IBTF_DPRINTF_L2(cmlog, "ibcm_del_decr_mcg_entry: Match NOT "
	    "Found ");

	return (IBCM_LOOKUP_FAIL);
}


/*
 * Function:
 *	ibt_join_mcg
 * Input:
 *	rgid		The request GID that defines the HCA port from which a
 *			contact to SA Access is performed to add the specified
 *			endport GID ((mcg_attr->mc_pgid) to a multicast group.
 *			If mcg_attr->mc_pgid is null, then this (rgid) will be
 *			treated as endport GID that is to be added to the
 *			multicast group.
 *
 *	mcg_attr	A pointer to an ibt_mcg_attr_t structure that defines
 *			the attributes of the desired multicast group to be
 *			created or joined.
 *
 *	func		NULL or a pointer to a function to call when
 *			ibt_join_mcg() completes. If 'func' is not NULL then
 *			ibt_join_mcg() will return as soon as possible after
 *			initiating the multicast group join/create process.
 *			'func' is then called when the process completes.
 *
 *	arg		Argument to the 'func'.
 *
 * Output:
 *	mcg_info_p	A pointer to the ibt_mcg_info_t structure, allocated
 *			by the caller, where the attributes of the created or
 *			joined multicast group are copied.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_INVALID_PARAM
 *	IBT_MCG_RECORDS_NOT_FOUND
 *	IBT_INSUFF_RESOURCE
 * Description:
 *	Join a multicast group.  The first full member "join" causes the MCG
 *	to be created.
 */
ibt_status_t
ibt_join_mcg(ib_gid_t rgid, ibt_mcg_attr_t *mcg_attr,
    ibt_mcg_info_t *mcg_info_p, ibt_mcg_handler_t func, void  *arg)
{
	ibcm_join_mcg_tqarg_t	*mcg_tq;
	int			flag = ((func == NULL) ? KM_SLEEP : KM_NOSLEEP);

	IBTF_DPRINTF_L3(cmlog, "ibt_join_mcg(%llX:%llX, %p)", rgid.gid_prefix,
	    rgid.gid_guid, mcg_attr);

	if ((rgid.gid_prefix == 0) || (rgid.gid_guid == 0)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_join_mcg: Request GID is required");
		return (IBT_INVALID_PARAM);
	}

	if ((mcg_attr->mc_pkey == IB_PKEY_INVALID_LIMITED) ||
	    (mcg_attr->mc_pkey == IB_PKEY_INVALID_FULL)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_join_mcg: Invalid P_Key specified");
		return (IBT_INVALID_PARAM);
	}

	if (mcg_attr->mc_join_state == 0) {
		IBTF_DPRINTF_L2(cmlog, "ibt_join_mcg: JoinState not specified");
		return (IBT_INVALID_PARAM);
	}

	if (mcg_info_p == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_join_mcg: mcg_info_p is NULL");
		return (IBT_INVALID_PARAM);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mcg_tq))

	mcg_tq = kmem_alloc(sizeof (ibcm_join_mcg_tqarg_t), flag);
	if (mcg_tq == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_join_mcg: "
		    "Unable to allocate memory for local usage.");
		return (IBT_INSUFF_KERNEL_RESOURCE);
	}

	mcg_tq->rgid = rgid;
	bcopy(mcg_attr, &mcg_tq->mcg_attr, sizeof (ibt_mcg_attr_t));
	mcg_tq->mcg_infop = mcg_info_p;
	mcg_tq->func = func;
	mcg_tq->arg = arg;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*mcg_tq))

	if (func != NULL) {	/* Non-Blocking */
		IBTF_DPRINTF_L3(cmlog, "ibt_join_mcg: Non-Blocking Call");
		if (taskq_dispatch(ibcm_taskq, ibcm_process_async_join_mcg,
		    mcg_tq, TQ_NOSLEEP) == TASKQID_INVALID) {
			IBTF_DPRINTF_L2(cmlog, "ibt_join_mcg: Failed to "
			    "Dispatch the TaskQ");
			kmem_free(mcg_tq, sizeof (ibcm_join_mcg_tqarg_t));
			return (IBT_INSUFF_KERNEL_RESOURCE);
		} else
			return (IBT_SUCCESS);
	} else {		/* Blocking */
		return (ibcm_process_join_mcg(mcg_tq));
	}
}

static void
ibcm_process_async_join_mcg(void *tq_arg)
{
	(void) ibcm_process_join_mcg(tq_arg);
}

static ibt_status_t
ibcm_process_join_mcg(void *taskq_arg)
{
	sa_mcmember_record_t	mcg_req;
	sa_mcmember_record_t	*mcg_resp;
	ibmf_saa_access_args_t	access_args;
	ibmf_saa_handle_t	saa_handle;
	uint64_t		component_mask = 0;
	ibt_status_t		retval;
	ibtl_cm_hca_port_t	hca_port;
	uint_t			num_records;
	size_t			length;
	ibcm_hca_info_t		*hcap;
	ibcm_join_mcg_tqarg_t	*mcg_arg = (ibcm_join_mcg_tqarg_t *)taskq_arg;
	ibt_mcg_info_t		*mcg_info_p = mcg_arg->mcg_infop;

	IBTF_DPRINTF_L3(cmlog, "ibcm_process_join_mcg(%p)", mcg_arg);

	retval = ibtl_cm_get_hca_port(mcg_arg->rgid, 0, &hca_port);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_join_mcg: Failed to get "
		    "port info from specified RGID: status = %d", retval);
		goto ibcm_join_mcg_exit1;
	}

	bzero(&mcg_req, sizeof (sa_mcmember_record_t));

	if ((mcg_arg->mcg_attr.mc_pgid.gid_prefix == 0) ||
	    (mcg_arg->mcg_attr.mc_pgid.gid_guid == 0)) {
		IBTF_DPRINTF_L3(cmlog, "ibcm_process_join_mcg: "
		    "Request GID is Port GID");
		mcg_req.PortGID = mcg_arg->rgid;
	} else {
		mcg_req.PortGID = mcg_arg->mcg_attr.mc_pgid;
	}
	component_mask |= SA_MC_COMPMASK_PORTGID;

	mcg_req.Q_Key = mcg_arg->mcg_attr.mc_qkey;
	mcg_req.P_Key = mcg_arg->mcg_attr.mc_pkey;
	mcg_req.JoinState = mcg_arg->mcg_attr.mc_join_state;
	mcg_req.TClass = mcg_arg->mcg_attr.mc_tclass;
	mcg_req.FlowLabel = mcg_arg->mcg_attr.mc_flow;
	mcg_req.SL = mcg_arg->mcg_attr.mc_sl;

	component_mask |= SA_MC_COMPMASK_QKEY | SA_MC_COMPMASK_PKEY |
	    SA_MC_COMPMASK_JOINSTATE | SA_MC_COMPMASK_TCLASS |
	    SA_MC_COMPMASK_FLOWLABEL | SA_MC_COMPMASK_SL;

	/* If client has specified MGID, use it else SA will assign one. */
	if ((mcg_arg->mcg_attr.mc_mgid.gid_prefix >> 56ULL & 0xFF) == 0xFF) {
		mcg_req.MGID = mcg_arg->mcg_attr.mc_mgid;
		component_mask |= SA_MC_COMPMASK_MGID;
	}

	IBTF_DPRINTF_L3(cmlog, "ibcm_process_join_mcg: ");
	IBTF_DPRINTF_L3(cmlog, "PGID=%016llX:%016llX, ",
	    mcg_req.PortGID.gid_prefix, mcg_req.PortGID.gid_guid);
	IBTF_DPRINTF_L3(cmlog, "MGID=%016llX:%016llX",
	    mcg_req.MGID.gid_prefix, mcg_req.MGID.gid_guid);
	IBTF_DPRINTF_L3(cmlog, "JoinState = %X",
	    mcg_arg->mcg_attr.mc_join_state);
	IBTF_DPRINTF_L5(cmlog, "QKey %lX, PKey %lX",
	    mcg_arg->mcg_attr.mc_qkey, mcg_arg->mcg_attr.mc_pkey);
	IBTF_DPRINTF_L5(cmlog, "Scope %X, MLID %X",
	    mcg_arg->mcg_attr.mc_scope, mcg_arg->mcg_attr.mc_mlid);

	/* Is MTU specified. */
	if (mcg_arg->mcg_attr.mc_mtu_req.r_mtu) {
		mcg_req.MTU = mcg_arg->mcg_attr.mc_mtu_req.r_mtu;
		mcg_req.MTUSelector = mcg_arg->mcg_attr.mc_mtu_req.r_selector;

		component_mask |= SA_MC_COMPMASK_MTUSELECTOR |
		    SA_MC_COMPMASK_MTU;
	}

	/* Is RATE specified. */
	if (mcg_arg->mcg_attr.mc_rate_req.r_srate) {
		mcg_req.Rate = mcg_arg->mcg_attr.mc_rate_req.r_srate;
		mcg_req.RateSelector =
		    mcg_arg->mcg_attr.mc_rate_req.r_selector;

		component_mask |= SA_MC_COMPMASK_RATESELECTOR |
		    SA_MC_COMPMASK_RATE;
	}

	/* Is Packet Life Time specified. */
	if (mcg_arg->mcg_attr.mc_pkt_lt_req.p_pkt_lt) {
		mcg_req.Rate = mcg_arg->mcg_attr.mc_pkt_lt_req.p_pkt_lt;
		mcg_req.RateSelector =
		    mcg_arg->mcg_attr.mc_pkt_lt_req.p_selector;

		component_mask |= SA_MC_COMPMASK_PKTLTSELECTOR |
		    SA_MC_COMPMASK_PKTLT;
	}

	if (mcg_arg->mcg_attr.mc_hop) {
		mcg_req.HopLimit = mcg_arg->mcg_attr.mc_hop;
		component_mask |= SA_MC_COMPMASK_HOPLIMIT;
	}

	if (mcg_arg->mcg_attr.mc_scope) {
		mcg_req.Scope = mcg_arg->mcg_attr.mc_scope;
		component_mask |= SA_MC_COMPMASK_SCOPE;
	}

	if (mcg_arg->mcg_attr.mc_mlid) {
		mcg_req.MLID = mcg_arg->mcg_attr.mc_mlid;
		component_mask |= SA_MC_COMPMASK_MLID;
	}

	/* Get SA Access Handle. */
	hcap = ibcm_find_hca_entry(hca_port.hp_hca_guid);
	if (hcap == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_join_mcg: NO HCA found");

		retval = IBT_HCA_BUSY_DETACHING;
		goto ibcm_join_mcg_exit1;
	}

	saa_handle = ibcm_get_saa_handle(hcap, hca_port.hp_port);
	if (saa_handle == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_join_mcg: SA Handle NULL");

		retval = IBT_HCA_PORT_NOT_ACTIVE;
		goto ibcm_join_mcg_exit;
	}

	if ((mcg_arg->mcg_attr.mc_pgid.gid_prefix != 0) &&
	    (mcg_arg->mcg_attr.mc_pgid.gid_guid != 0)) {
		retval = ibtl_cm_get_hca_port(mcg_arg->mcg_attr.mc_pgid, 0,
		    &hca_port);
		if (retval != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_process_join_mcg: Failed "
			    "to get PortInfo of specified PGID: status = %d",
			    retval);
			goto ibcm_join_mcg_exit1;
		}
	}

	/* Contact SA Access */
	access_args.sq_attr_id = SA_MCMEMBERRECORD_ATTRID;
	access_args.sq_access_type = IBMF_SAA_UPDATE;
	access_args.sq_component_mask = component_mask;
	access_args.sq_template = &mcg_req;
	access_args.sq_template_length = sizeof (sa_mcmember_record_t);
	access_args.sq_callback = NULL;
	access_args.sq_callback_arg = NULL;

	retval = ibcm_contact_sa_access(saa_handle, &access_args, &length,
	    (void **)&mcg_resp);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_process_join_mcg: "
		    "SA Access Failed");
		goto ibcm_join_mcg_exit;
	}

	num_records = length/sizeof (sa_mcmember_record_t);

	IBTF_DPRINTF_L4(cmlog, "ibcm_process_join_mcg: "
	    "Found %d MCMember Records", num_records);

	/* Validate the returned number of records. */
	if ((mcg_resp != NULL) && (num_records > 0)) {
		/* Update the return values. */
		mcg_info_p->mc_adds_vect.av_dgid = mcg_resp->MGID;
		mcg_info_p->mc_adds_vect.av_sgid = mcg_resp->PortGID;
		mcg_info_p->mc_adds_vect.av_srate = mcg_resp->Rate;
		mcg_info_p->mc_adds_vect.av_srvl = mcg_resp->SL;
		mcg_info_p->mc_adds_vect.av_flow = mcg_resp->FlowLabel;
		mcg_info_p->mc_adds_vect.av_tclass = mcg_resp->TClass;
		mcg_info_p->mc_adds_vect.av_hop = mcg_resp->HopLimit;
		mcg_info_p->mc_adds_vect.av_send_grh = B_TRUE;
		mcg_info_p->mc_adds_vect.av_dlid = mcg_resp->MLID;
		mcg_info_p->mc_mtu = mcg_resp->MTU;
		mcg_info_p->mc_qkey = mcg_resp->Q_Key;

		retval = ibt_pkey2index_byguid(hca_port.hp_hca_guid,
		    hca_port.hp_port, mcg_resp->P_Key, &mcg_info_p->mc_pkey_ix);
		if (retval != IBT_SUCCESS) {
			IBTF_DPRINTF_L3(cmlog, "ibcm_process_join_mcg: "
			    "Pkey2Index Conversion failed<%d>", retval);
			mcg_info_p->mc_pkey_ix = 0;
		}

		mcg_info_p->mc_scope = mcg_resp->Scope;
		mcg_info_p->mc_pkt_lt = mcg_resp->PacketLifeTime;

		mcg_info_p->mc_adds_vect.av_port_num = hca_port.hp_port;
		mcg_info_p->mc_adds_vect.av_sgid_ix = hca_port.hp_sgid_ix;
		mcg_info_p->mc_adds_vect.av_src_path = 0;

		/* Add or Incr the matching MCG entry. */
		ibcm_add_incr_mcg_entry(&mcg_req, mcg_resp);
		/* Deallocate the memory allocated by SA for mcg_resp. */
		kmem_free(mcg_resp, length);

		retval = IBT_SUCCESS;
	} else {
		retval = IBT_MCG_RECORDS_NOT_FOUND;
		IBTF_DPRINTF_L3(cmlog, "ibcm_process_join_mcg: "
		    "MCG RECORDS NOT FOUND");
	}

ibcm_join_mcg_exit:
	ibcm_dec_hca_acc_cnt(hcap);

ibcm_join_mcg_exit1:
	if (mcg_arg->func)
		(*(mcg_arg->func))(mcg_arg->arg, retval, mcg_info_p);

	kmem_free(mcg_arg, sizeof (ibcm_join_mcg_tqarg_t));

	return (retval);
}


/*
 * Function:
 *	ibt_leave_mcg
 * Input:
 *	rgid		The request GID that defines the HCA port upon which
 *			to send the request to the Subnet Administrator, to
 *			remove the specified port (port_gid) from the multicast
 *			group.  If 'port_gid' is the Reserved GID (i.e.
 *			port_gid.gid_prefix = 0 and port_gid.gid_guid = 0),
 *			then the end-port associated with 'rgid' is removed
 *			from the multicast group.
 *
 *	mc_gid		A multicast group GID as returned from ibt_join_mcg()
 *			call.  This is optional, if not specified (i.e.
 *			mc_gid.gid_prefix has 0xFF in its upper 8 bits to
 *			identify this as being a multicast GID), then the
 *			port is removed from all the multicast groups of
 *			which it is a member.
 *
 *	port_gid	This is optional, if not the Reserved GID (gid_prefix
 *			and gid_guid not equal to 0), then this specifies the
 *			endport GID of the multicast group member being deleted
 *			from the group. If it is the Reserved GID (gid_prefix
 *			and gid_guid equal to 0) then the member endport GID is
 *			determined from 'rgid'.
 *
 *	mc_join_state	The Join State attribute used when the group was joined
 *			using ibt_join_mcg(). This Join State component must
 *			contains at least one bit set to 1 in the same position
 *			as that used during ibt_join_mcg(). i.e. the logical
 *			AND of the two JoinState components is not all zeros.
 *			This Join State component must not have some bits set
 *			which are not set using ibt_join_mcg().
 * Output:
 *	None.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_INVALID_PARAM
 *	IBT_MC_GROUP_INVALID
 *	IBT_INSUFF_RESOURCE
 * Description:
 *	The port associated with the port GID shall be removed from the
 *	multicast group specified by MGID (mc_gid) or from all the multicast
 *	groups of which it is a member if the MGID (mc_gid) is not specified.
 *
 *	The last full member to leave causes the destruction of the Multicast
 *	Group.
 */
ibt_status_t
ibt_leave_mcg(ib_gid_t rgid, ib_gid_t mc_gid, ib_gid_t port_gid,
    uint8_t mc_join_state)
{
	sa_mcmember_record_t	mcg_req;
	ibmf_saa_access_args_t	access_args;
	ibmf_saa_handle_t	saa_handle;
	uint64_t		component_mask = 0;
	int			sa_retval;
	ibt_status_t		retval;
	ibcm_status_t		ret;
	ibtl_cm_hca_port_t	hca_port;
	size_t			length;
	void			*results_p;
	ibcm_hca_info_t		*hcap;
	uint8_t			jstate = 0;

	IBTF_DPRINTF_L3(cmlog, "ibt_leave_mcg(%llX:%llX, %llX:%llX)",
	    rgid.gid_prefix, rgid.gid_guid, mc_gid.gid_prefix, mc_gid.gid_guid);

	IBTF_DPRINTF_L3(cmlog, "ibt_leave_mcg(%llX:%llX, 0x%X)",
	    port_gid.gid_prefix, port_gid.gid_guid, mc_join_state);

	if ((rgid.gid_prefix == 0) || (rgid.gid_guid == 0)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_leave_mcg: RequestGID is required");
		return (IBT_INVALID_PARAM);
	}

	bzero(&mcg_req, sizeof (sa_mcmember_record_t));

	IBTF_DPRINTF_L3(cmlog, "ibt_leave_mcg: MGID: %llX%llX",
	    mc_gid.gid_prefix, mc_gid.gid_guid);

	/* Validate MGID */
	if ((mc_gid.gid_prefix >> 56ULL & 0xFF) == 0xFF) {
		mcg_req.MGID = mc_gid;
		component_mask |= SA_MC_COMPMASK_MGID;
	} else if ((mc_gid.gid_prefix != 0) || (mc_gid.gid_guid != 0)) {
		IBTF_DPRINTF_L3(cmlog, "ibt_leave_mcg: Invalid MGID specified");
		return (IBT_MC_MGID_INVALID);
	}

	if ((port_gid.gid_prefix == 0) || (port_gid.gid_guid == 0)) {
		mcg_req.PortGID = rgid;
	} else {
		IBTF_DPRINTF_L3(cmlog, "ibt_leave_mcg: Performing PROXY Leave");
		mcg_req.PortGID = port_gid;
	}
	component_mask |= SA_MC_COMPMASK_PORTGID;

	IBTF_DPRINTF_L3(cmlog, "ibt_leave_mcg: Port GID <%llX:%llX>",
	    mcg_req.PortGID.gid_prefix, mcg_req.PortGID.gid_guid);

	/* Join State */
	mcg_req.JoinState = mc_join_state;
	component_mask |= SA_MC_COMPMASK_JOINSTATE;

	ret = ibcm_del_decr_mcg_entry(&mcg_req, &jstate);
	if (ret == IBCM_LOOKUP_EXISTS) {
		IBTF_DPRINTF_L3(cmlog, "ibt_leave_mcg: Multiple JoinMCG record "
		    " still exists, we shall leave for last leave_mcg call");
		return (IBT_SUCCESS);
	} else if (ret == IBCM_LOOKUP_FAIL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_leave_mcg: No Record found, "
		    "continue with leave_mcg call");
	} else if ((ret == IBCM_SUCCESS) && (jstate != 0)) {
		/*
		 * Update with cached "jstate", as this will be OR'ed of
		 * all ibt_join_mcg() calls for this record.
		 */
		mcg_req.JoinState = jstate;
	}

	retval = ibtl_cm_get_hca_port(rgid, 0, &hca_port);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_leave_mcg: Failed to get port info "
		    "from specified RGID : status = %d", retval);
		return (retval);
	}

	/* Get SA Access Handle. */
	hcap = ibcm_find_hca_entry(hca_port.hp_hca_guid);
	if (hcap == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_leave_mcg: "
		    "NO HCA found");
		return (IBT_HCA_BUSY_DETACHING);
	}

	saa_handle = ibcm_get_saa_handle(hcap, hca_port.hp_port);
	if (saa_handle == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_leave_mcg: saa_handle is NULL");
		ibcm_dec_hca_acc_cnt(hcap);
		return (IBT_HCA_PORT_NOT_ACTIVE);
	}

	/* Contact SA Access */
	access_args.sq_attr_id = SA_MCMEMBERRECORD_ATTRID;
	access_args.sq_access_type = IBMF_SAA_DELETE;
	access_args.sq_component_mask = component_mask;
	access_args.sq_template = &mcg_req;
	access_args.sq_template_length = sizeof (sa_mcmember_record_t);
	access_args.sq_callback = NULL;
	access_args.sq_callback_arg = NULL;

	ibcm_sa_access_enter();

	sa_retval = ibmf_sa_access(saa_handle, &access_args, 0, &length,
	    &results_p);
	if (sa_retval != IBMF_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_leave_mcg: SA access Failed: %d",
		    sa_retval);
		(void) ibcm_ibmf_analyze_error(sa_retval);
		retval = IBT_MC_GROUP_INVALID;
	}

	ibcm_sa_access_exit();

	ibcm_dec_hca_acc_cnt(hcap);

	return (retval);
}


/*
 * Function:
 *	ibt_query_mcg
 * Input:
 *	rgid		The request GID that defines the HCA port upon which
 *			to send the request to the Subnet Administrator, to
 *			retrieve Multicast Records matching attributes as
 *			specified through 'mcg_attr' argument.
 *
 *	mcg_attr	NULL or a pointer to an ibt_mcg_attr_t structure that
 *			specifies MCG attributes that are to be matched.
 *			Attributes that are not required can be wild carded
 *			by specifying as '0'.
 *
 *	mcgs_max_num	The maximum number of matching multicast groups to
 *			return.  If zero, then all available matching multicast
 *			groups are returned.
 * Output:
 *	mcgs_info_p	The address of an ibt_mcg_info_t pointer, where
 *			multicast group information is returned. The actual
 *			number of entries filled in the array is returned in
 *			entries_p.
 *
 *	entries_p	The number of ibt_mcg_attr_t entries returned.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_INVALID_PARAM
 *	IBT_MCG_RECORDS_NOT_FOUND
 * Description:
 *	Request information on multicast groups that match the parameters
 *	specified in mcg_attr. Information on each multicast group is returned
 *	to the caller in the form of an array of ibt_mcg_info_t.
 *	ibt_query_mcg() allocates the memory for this array and returns a
 *	pointer to the array (mcgs_p) and the number of entries in the array
 *	(entries_p). This memory should be freed by the client using
 *	ibt_free_mcg_info().
 */
ibt_status_t
ibt_query_mcg(ib_gid_t rgid, ibt_mcg_attr_t *mcg_attr, uint_t mcgs_max_num,
    ibt_mcg_info_t **mcgs_info_p, uint_t *entries_p)
{
	sa_mcmember_record_t	mcg_req;
	sa_mcmember_record_t	*mcg_resp;
	ibt_mcg_info_t		*mcg_infop;
	ibmf_saa_access_args_t	access_args;
	ibmf_saa_handle_t	saa_handle;
	uint64_t		component_mask = 0;
	ibt_status_t		retval;
	ibtl_cm_hca_port_t	hport;
	uint_t			num_records;
	size_t			length;
	void			*results_p;
	ib_gid_t		port_gid;
	ibcm_hca_info_t		*hcap;

	IBTF_DPRINTF_L3(cmlog, "ibt_query_mcg(%p, %d)", mcg_attr, mcgs_max_num);

	if ((entries_p == NULL) || (mcgs_info_p == NULL)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_query_mcg: "
		    "entries_p or mcgs_info_p is NULL");
		return (IBT_INVALID_PARAM);
	}

	if ((rgid.gid_prefix == 0) || (rgid.gid_guid == 0)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_query_mcg: RequestGID is required");
		return (IBT_INVALID_PARAM);
	}
	IBTF_DPRINTF_L4(cmlog, "ibt_query_mcg: Request GID <%llX:%llX>",
	    rgid.gid_prefix, rgid.gid_guid);

	bzero(&mcg_req, sizeof (sa_mcmember_record_t));
	port_gid.gid_prefix = port_gid.gid_guid = 0;

	if (mcg_attr != NULL) {
		port_gid = mcg_attr->mc_pgid;

		if ((port_gid.gid_prefix != 0) && (port_gid.gid_guid != 0)) {
			mcg_req.PortGID = mcg_attr->mc_pgid;
			component_mask |= SA_MC_COMPMASK_PORTGID;

			IBTF_DPRINTF_L4(cmlog, "ibt_query_mcg: PGID %llX:%llX",
			    port_gid.gid_prefix, port_gid.gid_guid);
		}

		/* Is Q_Key specified. */
		if (mcg_attr->mc_qkey != 0) {
			mcg_req.Q_Key = mcg_attr->mc_qkey;
			component_mask |= SA_MC_COMPMASK_QKEY;
		}

		/* Is P_Key specified. */
		if (mcg_attr->mc_pkey != 0) {
			mcg_req.P_Key = mcg_attr->mc_pkey;
			component_mask |= SA_MC_COMPMASK_PKEY;
		}

		/* Is MGID specified. */
		if ((mcg_attr->mc_mgid.gid_prefix >> 56ULL & 0xFF) == 0xFF) {
			mcg_req.MGID = mcg_attr->mc_mgid;
			component_mask |= SA_MC_COMPMASK_MGID;
		}

		/* Is MTU specified. */
		if (mcg_attr->mc_mtu_req.r_mtu) {
			mcg_req.MTU = mcg_attr->mc_mtu_req.r_mtu;
			mcg_req.MTUSelector = mcg_attr->mc_mtu_req.r_selector;

			component_mask |= SA_MC_COMPMASK_MTUSELECTOR |
			    SA_MC_COMPMASK_MTU;
		}

		if (mcg_attr->mc_tclass) {
			mcg_req.TClass = mcg_attr->mc_tclass;
			component_mask |= SA_MC_COMPMASK_TCLASS;
		}

		/* Is RATE specified. */
		if (mcg_attr->mc_rate_req.r_srate) {
			mcg_req.Rate = mcg_attr->mc_rate_req.r_srate;
			mcg_req.RateSelector = mcg_attr->mc_rate_req.r_selector;

			component_mask |= SA_MC_COMPMASK_RATESELECTOR |
			    SA_MC_COMPMASK_RATE;
		}

		/* Is Packet Life Time specified. */
		if (mcg_attr->mc_pkt_lt_req.p_pkt_lt) {
			mcg_req.Rate = mcg_attr->mc_pkt_lt_req.p_pkt_lt;
			mcg_req.RateSelector =
			    mcg_attr->mc_pkt_lt_req.p_selector;

			component_mask |= SA_MC_COMPMASK_PKTLTSELECTOR |
			    SA_MC_COMPMASK_PKTLT;
		}

		if (mcg_attr->mc_hop) {
			mcg_req.HopLimit = mcg_attr->mc_hop;
			component_mask |= SA_MC_COMPMASK_HOPLIMIT;
		}

		if (mcg_attr->mc_flow) {
			mcg_req.FlowLabel = mcg_attr->mc_flow;
			component_mask |= SA_MC_COMPMASK_FLOWLABEL;
		}

		if (mcg_attr->mc_sl) {
			mcg_req.SL = mcg_attr->mc_sl;
			component_mask |= SA_MC_COMPMASK_SL;
		}

		if (mcg_attr->mc_scope) {
			mcg_req.Scope = mcg_attr->mc_scope;
			component_mask |= SA_MC_COMPMASK_SCOPE;
		}

		if (mcg_attr->mc_join_state) {
			mcg_req.JoinState = mcg_attr->mc_join_state;
			component_mask |= SA_MC_COMPMASK_JOINSTATE;
		}

		if (mcg_attr->mc_mlid) {
			mcg_req.MLID = mcg_attr->mc_mlid;
			component_mask |= SA_MC_COMPMASK_MLID;
		}
	}

	retval = ibtl_cm_get_hca_port(rgid, 0, &hport);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_query_mcg: Failed to get port info "
		    "from specified RGID : status = %d", retval);
		return (retval);
	}

	/* Get SA Access Handle. */
	hcap = ibcm_find_hca_entry(hport.hp_hca_guid);
	if (hcap == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_query_mcg: NO HCA found");
		return (IBT_HCA_BUSY_DETACHING);
	}

	saa_handle = ibcm_get_saa_handle(hcap, hport.hp_port);
	if (saa_handle == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_query_mcg: saa_handle is NULL");
		ibcm_dec_hca_acc_cnt(hcap);
		return (IBT_HCA_PORT_NOT_ACTIVE);
	}

	/* Contact SA Access */
	access_args.sq_attr_id = SA_MCMEMBERRECORD_ATTRID;
	access_args.sq_access_type = IBMF_SAA_RETRIEVE;
	access_args.sq_component_mask = component_mask;
	access_args.sq_template = &mcg_req;
	access_args.sq_template_length = sizeof (sa_mcmember_record_t);
	access_args.sq_callback = NULL;
	access_args.sq_callback_arg = NULL;

	retval = ibcm_contact_sa_access(saa_handle, &access_args, &length,
	    &results_p);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_query_mcg: SA access Failed");
		ibcm_dec_hca_acc_cnt(hcap);
		return (retval);
	}

	num_records = length/sizeof (sa_mcmember_record_t);

	IBTF_DPRINTF_L4(cmlog, "ibt_query_mcg: Found %d MCMember Records",
	    num_records);

	/* Validate the returned number of records. */
	if ((results_p != NULL) && (num_records > 0)) {
		uint_t	i;

		/*
		 * If mcgs_max_num is zero, then return all records else
		 * return only requested number of records
		 */
		if ((mcgs_max_num != 0) && (num_records > mcgs_max_num)) {
			/* we are interested in only mcgs_max_num records */
			num_records = mcgs_max_num;
		}

		/*
		 * The SGID returned in "mcg_info_p" buffer should be PortGID,
		 * (mcg_attr->mc_pgid), if 'mcg_attr->mc_pgid' was specified,
		 * else RequestGID (rgid) should be returned.
		 */
		if ((port_gid.gid_prefix != 0) && (port_gid.gid_guid != 0)) {

			/* Get sgid_ix and port number of 'port_gid' */
			retval = ibtl_cm_get_hca_port(port_gid, 0, &hport);
			if (retval != IBT_SUCCESS) {
				IBTF_DPRINTF_L2(cmlog, "ibt_query_mcg: "
				    "Failed to Get Portinfo for PortGID :"
				    "status = %d", retval);
				return (retval);
			}
		} else {
			/*
			 * The sgid_ix and port number related to RequestGID
			 * are already obtained at the beginning.
			 */
			port_gid = rgid;
		}

		/*
		 * Allocate memory for return buffer, to be freed in
		 * ibt_free_mcg_info().
		 */
		mcg_infop = kmem_alloc((num_records * sizeof (ibt_mcg_info_t)),
		    KM_SLEEP);

		*mcgs_info_p = mcg_infop;
		*entries_p = num_records;

		/* Update the return values. */
		for (i = 0; i < num_records; i++) {

			mcg_resp = (sa_mcmember_record_t *)((uchar_t *)
			    results_p + i * sizeof (sa_mcmember_record_t));

			mcg_infop[i].mc_adds_vect.av_dgid = mcg_resp->MGID;
			mcg_infop[i].mc_adds_vect.av_sgid = port_gid;
			mcg_infop[i].mc_adds_vect.av_srate = mcg_resp->Rate;
			mcg_infop[i].mc_adds_vect.av_srvl = mcg_resp->SL;
			mcg_infop[i].mc_adds_vect.av_flow = mcg_resp->FlowLabel;
			mcg_infop[i].mc_adds_vect.av_tclass = mcg_resp->TClass;
			mcg_infop[i].mc_adds_vect.av_hop = mcg_resp->HopLimit;
			mcg_infop[i].mc_adds_vect.av_port_num = hport.hp_port;
			mcg_infop[i].mc_adds_vect.av_send_grh = B_TRUE;
			mcg_infop[i].mc_adds_vect.av_dlid = mcg_resp->MLID;
			mcg_infop[i].mc_adds_vect.av_sgid_ix = hport.hp_sgid_ix;
			mcg_infop[i].mc_adds_vect.av_src_path = 0;
			mcg_infop[i].mc_mtu = mcg_resp->MTU;
			mcg_infop[i].mc_qkey = mcg_resp->Q_Key;
			mcg_infop[i].mc_scope = mcg_resp->Scope;
			mcg_infop[i].mc_pkt_lt = mcg_resp->PacketLifeTime;

			if (ibt_pkey2index_byguid(hport.hp_hca_guid,
			    hport.hp_port, mcg_resp->P_Key,
			    &mcg_infop[i].mc_pkey_ix) != IBT_SUCCESS) {
				IBTF_DPRINTF_L3(cmlog, "ibt_query_mcg: "
				    "Pkey2Index Conversion failed");
				mcg_infop[i].mc_pkey_ix = 0;
			}
		}

		/*
		 * Deallocate the memory allocated by SA for results_p.
		 */
		kmem_free(results_p, length);
		retval = IBT_SUCCESS;

		IBTF_DPRINTF_L3(cmlog, "ibt_query_mcg: returning %d MCGRecords",
		    num_records);

	} else {
		retval = IBT_MCG_RECORDS_NOT_FOUND;
		*entries_p = 0;

		IBTF_DPRINTF_L3(cmlog, "ibt_query_mcg: MCG RECORDS NOT FOUND");
	}

	ibcm_dec_hca_acc_cnt(hcap);

	return (retval);
}


/*
 * ibt_free_mcg_info()
 *	Free the memory allocated by successful ibt_query_mcg()
 *
 *	mcgs_info	Pointer returned by ibt_query_mcg().
 *
 *	entries		The number of ibt_mcg_info_t entries to free.
 */
void
ibt_free_mcg_info(ibt_mcg_info_t *mcgs_info, uint_t entries)
{
	IBTF_DPRINTF_L3(cmlog, "ibt_free_mcg_info: "
	    "Free <%d> entries from 0x%p", entries, mcgs_info);

	if ((mcgs_info != NULL) && (entries > 0))
		kmem_free(mcgs_info, entries * sizeof (ibt_mcg_info_t));
	else
		IBTF_DPRINTF_L2(cmlog, "ibt_free_mcg_info: "
		    "ERROR: NULL buf pointer or length specified.");
}


/*
 * Function:
 *	ibt_gid_to_node_info()
 * Input:
 *	gid		Identifies the IB Node and port for which to obtain
 *			Node information.
 * Output:
 *	node_info_p	A pointer to an ibt_node_info_t structure (allocated
 *			by the caller) in which to return the node information.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_INVALID_PARAM
 *	IBT_NODE_RECORDS_NOT_FOUND
 *	IBT_NO_HCAS_AVAILABLE
 * Description:
 *	Retrieve Node Information for the specified GID.
 */
ibt_status_t
ibt_gid_to_node_info(ib_gid_t gid, ibt_node_info_t *node_info_p)
{
	sa_node_record_t	nr_req, *nr_resp;
	ibmf_saa_handle_t	saa_handle;
	ibt_status_t		retval;
	ibcm_hca_info_t		*hcap;
	ibtl_cm_hca_port_t	hport;
	int			i, j;
	uint_t			num_rec;
	ib_guid_t		*guid_array = NULL;
	sa_path_record_t	*path;
	size_t			len;
	uint8_t			npaths;
	uint32_t		num_hcas = 0;
	ib_lid_t		node_lid;
	boolean_t		local_node = B_FALSE;
	void			*res_p;
	uint8_t			num_ports = 0;


	IBTF_DPRINTF_L4(cmlog, "ibt_gid_to_node_info(%llX:%llX, %p)",
	    gid.gid_prefix, gid.gid_guid, node_info_p);

	if ((gid.gid_prefix == 0) || (gid.gid_guid == 0)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_gid_to_node_info: GID is required");
		return (IBT_INVALID_PARAM);
	}

	if (node_info_p == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibt_gid_to_node_info: "
		    "Return Buf (node_info_p) is NULL.");
		return (IBT_INVALID_PARAM);
	}

	/*
	 * If 'gid' is on local node, then get node lid (i.e. base lid of the
	 * associated port) info via ibtl_cm_get_hca_port() call.
	 */
	bzero(&hport, sizeof (ibtl_cm_hca_port_t));
	if (ibtl_cm_get_hca_port(gid, 0, &hport) == IBT_SUCCESS) {

		hcap = ibcm_find_hca_entry(hport.hp_hca_guid);
		if (hcap == NULL) {
			IBTF_DPRINTF_L3(cmlog, "ibt_gid_to_node_info: "
			    "HCA(%llX) info not found", hport.hp_hca_guid);
			return (IBT_NO_HCAS_AVAILABLE);
		}
		num_ports = 1;
		num_hcas = 1;
		node_lid = hport.hp_base_lid;
		local_node = B_TRUE;
		IBTF_DPRINTF_L4(cmlog, "ibt_gid_to_node_info: Local Node: "
		    "LID = 0x%X", node_lid);
	} else {
		/* Get the number of HCAs and their GUIDs */
		num_hcas = ibt_get_hca_list(&guid_array);
		IBTF_DPRINTF_L4(cmlog, "ibt_gid_to_node_info: ibt_get_hca_list "
		    "returned %d hcas", num_hcas);

		if (num_hcas == 0) {
			IBTF_DPRINTF_L2(cmlog, "ibt_gid_to_node_info: "
			    "NO HCA's Found on this system");
			return (IBT_NO_HCAS_AVAILABLE);
		}
	}

	for (i = 0; i < num_hcas; i++) {
		if (local_node == B_FALSE) {
			hcap = ibcm_find_hca_entry(guid_array[i]);
			if (hcap == NULL) {
				IBTF_DPRINTF_L3(cmlog, "ibt_gid_to_node_info: "
				    "HCA(%llX) info not found", guid_array[i]);
				retval = IBT_NO_HCAS_AVAILABLE;
				continue;
			}
			num_ports = hcap->hca_num_ports;
		}

		for (j = 0; j < num_ports; j++) {
			uint8_t		port = 0;

			if (local_node == B_TRUE)
				port = hport.hp_port;
			else
				port = j + 1;

			/* Get SA Access Handle. */
			saa_handle = ibcm_get_saa_handle(hcap, port);
			if (saa_handle == NULL) {
				IBTF_DPRINTF_L3(cmlog, "ibt_gid_to_node_info: "
				    "Port %d of HCA (%llX) is NOT ACTIVE",
				    port, hport.hp_hca_guid);
				retval = IBT_NODE_RECORDS_NOT_FOUND;
				continue;
			}

			if (local_node == B_FALSE) {
				ib_gid_t	sgid;
				int		sa_ret;

				/*
				 * Check whether 'gid' and this port has same
				 * subnet prefix. If not, then there is no use
				 * in searching from this port.
				 */
				sgid = hcap->hca_port_info[j].port_sgid0;
				if (gid.gid_prefix != sgid.gid_prefix) {
					IBTF_DPRINTF_L3(cmlog,
					    "ibt_gid_to_node_info:Sn_Prefix of "
					    "GID(%llX) and Port's(%llX) differ",
					    gid.gid_prefix, sgid.gid_prefix);
					retval = IBT_NODE_RECORDS_NOT_FOUND;
					continue;
				}

				/*
				 * First Get Path Records for the specified DGID
				 * from this port (SGID). From Path Records,
				 * note down DLID, then use this DLID as Input
				 * attribute to get NodeRecords from SA Access.
				 */
				npaths = 1;
				path = NULL;

				sa_ret = ibmf_saa_gid_to_pathrecords(saa_handle,
				    sgid, gid, 0, 0, B_TRUE, &npaths, 0, &len,
				    &path);
				if (sa_ret != IBMF_SUCCESS) {
					IBTF_DPRINTF_L2(cmlog,
					    "ibt_gid_to_node_info: "
					    "ibmf_saa_gid_to_pathrecords() "
					    "returned error: %d ", sa_ret);
					retval =
					    ibcm_ibmf_analyze_error(sa_ret);
					continue;
				} else if ((npaths == 0) || (path == NULL)) {
					IBTF_DPRINTF_L3(cmlog,
					    "ibt_gid_to_node_info: failed (%d) "
					    "to get path records for the DGID "
					    "0x%llX from SGID 0x%llX", sa_ret,
					    gid.gid_guid, sgid.gid_guid);
					retval = IBT_NODE_RECORDS_NOT_FOUND;
					continue;
				}
				node_lid = path->DLID;	/* LID */

				IBTF_DPRINTF_L3(cmlog, "ibt_gid_to_node_info: "
				    "Remote Node: LID = 0x%X", node_lid);

				/* Free SA_Access memory for path record. */
				kmem_free(path, len);
			}

			/* Retrieve Node Records from SA Access. */
			bzero(&nr_req, sizeof (sa_node_record_t));

			nr_req.LID = node_lid;	/* LID */

			retval = ibcm_get_node_rec(saa_handle, &nr_req,
			    SA_NODEINFO_COMPMASK_NODELID, &res_p, &len);
			if (retval == IBT_NODE_RECORDS_NOT_FOUND) {
				IBTF_DPRINTF_L2(cmlog, "ibt_gid_to_node_info: "
				    "failed (%d) to get Node records", retval);
				continue;
			} else if (retval != IBT_SUCCESS) {
				IBTF_DPRINTF_L2(cmlog, "ibt_gid_to_node_info: "
				    "failed (%d) to get Node records", retval);
				ibcm_dec_hca_acc_cnt(hcap);
				goto gid_to_ni_exit;
			}

			num_rec = len/sizeof (sa_node_record_t);
			nr_resp = (sa_node_record_t *)(uchar_t *)res_p;

			/* Validate the returned number of records. */
			if ((nr_resp != NULL) && (num_rec > 0)) {

				IBCM_DUMP_NODE_REC(nr_resp);

				_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(
				    *node_info_p))

				node_info_p->n_sys_img_guid =
				    nr_resp->NodeInfo.SystemImageGUID;
				node_info_p->n_node_guid =
				    nr_resp->NodeInfo.NodeGUID;
				node_info_p->n_port_guid =
				    nr_resp->NodeInfo.PortGUID;
				node_info_p->n_dev_id =
				    nr_resp->NodeInfo.DeviceID;
				node_info_p->n_revision =
				    nr_resp->NodeInfo.Revision;
				node_info_p->n_vendor_id =
				    nr_resp->NodeInfo.VendorID;
				node_info_p->n_num_ports =
				    nr_resp->NodeInfo.NumPorts;
				node_info_p->n_port_num =
				    nr_resp->NodeInfo.LocalPortNum;
				node_info_p->n_node_type =
				    nr_resp->NodeInfo.NodeType;
				(void) strncpy(node_info_p->n_description,
				    (char *)&nr_resp->NodeDescription, 64);

				_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(
				    *node_info_p))

				/*
				 * Deallocate the memory allocated by SA for
				 * 'nr_resp'.
				 */
				ibcm_dec_hca_acc_cnt(hcap);
				kmem_free(nr_resp, len);
				retval = IBT_SUCCESS;

				goto gid_to_ni_exit;
			} else {
				retval = IBT_NODE_RECORDS_NOT_FOUND;
				IBTF_DPRINTF_L3(cmlog, "ibt_gid_to_node_info: "
				    "Node Records NOT found - PortGUID %016llX",
				    gid.gid_guid);
			}
		}
		ibcm_dec_hca_acc_cnt(hcap);

		if (local_node == B_TRUE)
			break;
	}

gid_to_ni_exit:
	if (guid_array)
		ibt_free_hca_list(guid_array, num_hcas);

	IBTF_DPRINTF_L3(cmlog, "ibt_gid_to_node_info: done. Status %d", retval);

	return (retval);
}


ibt_status_t
ibcm_get_node_rec(ibmf_saa_handle_t saa_handle, sa_node_record_t *nr_req,
    uint64_t component_mask, void *result_p, size_t *len)
{
	ibmf_saa_access_args_t  args;
	size_t			length;
	ibt_status_t		retval;

	args.sq_attr_id = SA_NODERECORD_ATTRID;
	args.sq_template = nr_req;
	args.sq_access_type = IBMF_SAA_RETRIEVE;
	args.sq_template_length = sizeof (sa_node_record_t);
	args.sq_component_mask = component_mask;
	args.sq_callback = NULL;
	args.sq_callback_arg = NULL;

	retval = ibcm_contact_sa_access(saa_handle, &args, &length, result_p);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_get_node_rec: SA Call Failed");
		return (retval);
	}

	*len = length;

	/* Validate the returned number of records. */
	if ((result_p != NULL) && (length > 0)) {
		IBTF_DPRINTF_L3(cmlog, "ibcm_get_node_rec: Node Records FOUND");

		/* Got it, done!. */
		return (IBT_SUCCESS);
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibcm_get_node_rec: Node Rec NOT found");
		return (IBT_NODE_RECORDS_NOT_FOUND);
	}
}


/*
 * Function:
 *	ibt_lid_to_node_info()
 * Input:
 *	lid		Identifies the IB Node and port for which to obtain
 *			Node information.
 * Output:
 *	node_info_p	A pointer to an ibt_node_info_t structure (allocated
 *			by the caller) in which to return the node information.
 * Returns:
 *	IBT_SUCCESS
 *	IBT_INVALID_PARAM
 *	IBT_NODE_RECORDS_NOT_FOUND
 *	IBT_NO_HCAS_AVAILABLE
 * Description:
 *	Retrieve Node Information for the specified LID.
 */
ibt_status_t
ibt_lid_to_node_info(ib_lid_t lid, ibt_node_info_t *node_info_p)
{
	ibt_status_t	retval;
	ibcm_hca_info_t	*hcap;
	uint8_t		i, j;
	ib_guid_t	*guid_array = NULL;
	uint_t		num_hcas = 0;


	IBTF_DPRINTF_L4(cmlog, "ibt_lid_to_node_info(0x%lX, %p)",
	    lid, node_info_p);

	if ((lid == 0) || (node_info_p == NULL)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_lid_to_node_info: "
		    "Lid is zero, or node_info_p is NULL.");
		return (IBT_INVALID_PARAM);
	}

	/* Get the number of HCAs and their GUIDs */
	num_hcas = ibt_get_hca_list(&guid_array);
	IBTF_DPRINTF_L4(cmlog, "ibt_lid_to_node_info: ibt_get_hca_list "
	    "returned %d hcas", num_hcas);

	if (num_hcas == 0) {
		IBTF_DPRINTF_L2(cmlog, "ibt_lid_to_node_info: "
		    "NO HCA's Found on this system");
		return (IBT_NO_HCAS_AVAILABLE);
	}

	for (i = 0; i < num_hcas; i++) {
		hcap = ibcm_find_hca_entry(guid_array[i]);
		if (hcap == NULL) {
			IBTF_DPRINTF_L3(cmlog, "ibt_lid_to_node_info: "
			    "HCA(%llX) info not found", guid_array[i]);
			retval = IBT_NO_HCAS_AVAILABLE;
			continue;
		}

		for (j = 0; j < hcap->hca_num_ports; j++) {
			uint8_t			port;
			ibmf_saa_handle_t	saa_handle;
			uint_t			num_rec;
			size_t			len;
			void			*res_p;
			sa_node_record_t	nr_req, *nr_resp;

			port = j + 1;

			/* Get SA Access Handle. */
			saa_handle = ibcm_get_saa_handle(hcap, port);
			if (saa_handle == NULL) {
				IBTF_DPRINTF_L3(cmlog, "ibt_lid_to_node_info: "
				    "Port %d of HCA (%llX) is NOT ACTIVE",
				    port, guid_array[i]);
				retval = IBT_NODE_RECORDS_NOT_FOUND;
				continue;
			}

			/* Retrieve Node Records from SA Access. */
			bzero(&nr_req, sizeof (sa_node_record_t));

			nr_req.LID = lid;	/* LID */

			retval = ibcm_get_node_rec(saa_handle, &nr_req,
			    SA_NODEINFO_COMPMASK_NODELID, &res_p, &len);
			if (retval == IBT_NODE_RECORDS_NOT_FOUND) {
				IBTF_DPRINTF_L2(cmlog, "ibt_lid_to_node_info: "
				    "failed (%d) to get Node records", retval);
				continue;
			} else if (retval != IBT_SUCCESS) {
				IBTF_DPRINTF_L2(cmlog, "ibt_lid_to_node_info: "
				    "failed (%d) to get Node records", retval);
				ibcm_dec_hca_acc_cnt(hcap);
				goto lid_to_ni_exit;
			}

			num_rec = len/sizeof (sa_node_record_t);
			nr_resp = (sa_node_record_t *)(uchar_t *)res_p;

			/* Validate the returned number of records. */
			if ((nr_resp != NULL) && (num_rec > 0)) {

				IBCM_DUMP_NODE_REC(nr_resp);

				_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(
				    *node_info_p))

				node_info_p->n_sys_img_guid =
				    nr_resp->NodeInfo.SystemImageGUID;
				node_info_p->n_node_guid =
				    nr_resp->NodeInfo.NodeGUID;
				node_info_p->n_port_guid =
				    nr_resp->NodeInfo.PortGUID;
				node_info_p->n_dev_id =
				    nr_resp->NodeInfo.DeviceID;
				node_info_p->n_revision =
				    nr_resp->NodeInfo.Revision;
				node_info_p->n_vendor_id =
				    nr_resp->NodeInfo.VendorID;
				node_info_p->n_num_ports =
				    nr_resp->NodeInfo.NumPorts;
				node_info_p->n_port_num =
				    nr_resp->NodeInfo.LocalPortNum;
				node_info_p->n_node_type =
				    nr_resp->NodeInfo.NodeType;
				(void) strncpy(node_info_p->n_description,
				    (char *)&nr_resp->NodeDescription, 64);

				_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(
				    *node_info_p))

				/*
				 * Deallocate the memory allocated by SA for
				 * 'nr_resp'.
				 */
				ibcm_dec_hca_acc_cnt(hcap);
				kmem_free(nr_resp, len);
				retval = IBT_SUCCESS;

				goto lid_to_ni_exit;
			} else {
				retval = IBT_NODE_RECORDS_NOT_FOUND;
				IBTF_DPRINTF_L3(cmlog, "ibt_lid_to_node_info: "
				    "Node Records NOT found - LID 0x%lX",
				    lid);
			}
		}
		ibcm_dec_hca_acc_cnt(hcap);
	}

lid_to_ni_exit:
	if (guid_array)
		ibt_free_hca_list(guid_array, num_hcas);

	IBTF_DPRINTF_L3(cmlog, "ibt_lid_to_node_info: done. Status %d", retval);

	return (retval);
}

/*
 * Function:
 *	ibt_get_companion_port_gids()
 * Description:
 *	Get list of GID's available on a companion port(s) of the specified
 *	GID or list of GIDs available on a specified Node GUID/SystemImage GUID.
 */
ibt_status_t
ibt_get_companion_port_gids(ib_gid_t gid, ib_guid_t hca_guid,
    ib_guid_t sysimg_guid, ib_gid_t **gids_p, uint_t *num_gids_p)
{
	sa_node_record_t	nr_req, *nr_resp;
	void			*res_p;
	ibmf_saa_handle_t	saa_handle;
	int			sa_ret;
	ibt_status_t		retval = IBT_SUCCESS;
	ibcm_hca_info_t		*hcap;
	ibtl_cm_hca_port_t	hport;
	int			i, j;
	uint_t			num_rec;
	ib_guid_t		*guid_array = NULL;
	sa_path_record_t	*path;
	size_t			len;
	uint8_t			npaths;
	uint32_t		num_hcas = 0;
	boolean_t		local_node = B_FALSE;
	boolean_t		local_hca = B_FALSE;
	ib_guid_t		h_guid = hca_guid;
	ib_gid_t		*gidp = NULL, *t_gidp = NULL;
	int			multi_hca_loop = 0;

	IBTF_DPRINTF_L4(cmlog, "ibt_get_companion_port_gids(%llX:%llX, %llX, "
	    "%llX)", gid.gid_prefix, gid.gid_guid, hca_guid, sysimg_guid);

	if (((gid.gid_prefix == 0) || (gid.gid_guid == 0)) && (hca_guid == 0) &&
	    (sysimg_guid == 0)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_get_companion_port_gids: "
		    "Null Input attribute specified.");
		return (IBT_INVALID_PARAM);
	}

	if ((num_gids_p == NULL) || (gids_p == NULL)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_get_companion_port_gids: "
		    "num_gids_p or gids_p is NULL");
		return (IBT_INVALID_PARAM);
	}

	*num_gids_p = 0;

	/* Get the number of HCAs and their GUIDs */
	if ((num_hcas = ibt_get_hca_list(&guid_array)) == 0) {
		IBTF_DPRINTF_L2(cmlog, "ibt_get_companion_port_gids: "
		    "NO HCA's Found on this system");
		return (IBT_NO_HCAS_AVAILABLE);
	}

	IBTF_DPRINTF_L4(cmlog, "ibt_get_companion_port_gids: "
	    "ibt_get_hca_list() returned %d hcas", num_hcas);

	/*
	 * If 'gid' is on local node, then get node lid (i.e. base lid of the
	 * associated port) info via ibtl_cm_get_hca_port() call.
	 */
	bzero(&hport, sizeof (ibtl_cm_hca_port_t));
	if ((gid.gid_prefix != 0) && (gid.gid_guid != 0) &&
	    (ibtl_cm_get_hca_port(gid, 0, &hport) == IBT_SUCCESS)) {

		if ((hca_guid != 0) && (hca_guid != hport.hp_hca_guid)) {
			IBTF_DPRINTF_L2(cmlog, "ibt_get_companion_port_gids: "
			    "Invalid GID<->HCAGUID combination specified.");
			retval = IBT_INVALID_PARAM;
			goto get_comp_pgid_exit;
		}
		h_guid = hport.hp_hca_guid;
		local_node = B_TRUE;

		IBTF_DPRINTF_L4(cmlog, "ibt_get_companion_port_gids: "
		    "Local Node: HCA (0x%llX)", h_guid);
	} else if (h_guid) {	/* Is specified HCA GUID - local? */
		for (i = 0; i < num_hcas; i++) {
			if (h_guid == guid_array[i]) {
				local_hca = B_TRUE;
				break;
			}
		}
	} else if (sysimg_guid) { /* Is specified SystemImage GUID - local? */
		for (i = 0; i < num_hcas; i++) {
			ibt_status_t	ret;
			ibt_hca_attr_t	hca_attr;

			ret = ibt_query_hca_byguid(guid_array[i], &hca_attr);
			if (ret != IBT_SUCCESS) {
				IBTF_DPRINTF_L2(cmlog,
				    "ibt_get_companion_port_gids: HCA(%llX) "
				    "info not found", guid_array[i]);
				retval = IBT_NO_HCAS_AVAILABLE;
				continue;
			}
			if (hca_attr.hca_si_guid == sysimg_guid) {
				if ((hca_guid != 0) &&
				    (hca_guid != hca_attr.hca_node_guid)) {
					IBTF_DPRINTF_L2(cmlog,
					    "ibt_get_companion_port_gids: "
					    "Invalid SysImg<->HCA GUID "
					    "combination specified.");
					retval = IBT_INVALID_PARAM;
					goto get_comp_pgid_exit;
				}
				local_hca = B_TRUE;
				h_guid = hca_attr.hca_node_guid;
				break;
			}
		}
	}

	if ((local_node == B_TRUE) || (local_hca == B_TRUE)) {
		retval = ibtl_cm_get_local_comp_gids(h_guid, gid, gids_p,
		    num_gids_p);
		goto get_comp_pgid_exit;
	}

get_comp_for_multihca:
	/* We will be here, if request is for remote node */
	for (i = 0; i < num_hcas; i++) {
		int		multism;
		uint_t		count = 0;
		int		multi_sm_loop = 0;
		uint_t		k = 0, l;

		hcap = ibcm_find_hca_entry(guid_array[i]);
		if (hcap == NULL) {
			IBTF_DPRINTF_L3(cmlog, "ibt_get_companion_port_gids: "
			    "HCA(%llX) info not found", guid_array[i]);
			retval = IBT_NO_HCAS_AVAILABLE;
			continue;
		}

		/* 1 - MultiSM, 0 - Single SM */
		multism = ibtl_cm_is_multi_sm(guid_array[i]);

		for (j = 0; j < hcap->hca_num_ports; j++) {
			ib_gid_t	sgid;
			uint64_t	c_mask = 0;
			ib_guid_t	pg;
			uint_t		port = j;

get_comp_for_multism:
			IBTF_DPRINTF_L3(cmlog, "ibt_get_companion_port_gids: "
			    "Port %d, HCA %llX, MultiSM= %d, Loop=%d",
			    port + 1, h_guid, multism, multi_sm_loop);

			/* Get SA Access Handle. */
			saa_handle = ibcm_get_saa_handle(hcap, port + 1);
			if (saa_handle == NULL) {
				IBTF_DPRINTF_L2(cmlog,
				    "ibt_get_companion_port_gids: "
				    "Port (%d)  - NOT ACTIVE", port + 1);
				retval = IBT_GIDS_NOT_FOUND;
				continue;
			}

			/*
			 * Check whether 'gid' and this port has same subnet
			 * prefix. If not, then there is no use in searching
			 * from this port.
			 */
			sgid = hcap->hca_port_info[port].port_sgid0;
			if ((h_guid == 0) && (gid.gid_prefix != 0) &&
			    (multi_sm_loop == 0) &&
			    (gid.gid_prefix != sgid.gid_prefix)) {
				IBTF_DPRINTF_L2(cmlog,
				    "ibt_get_companion_port_gids: SnPrefix of "
				    "GID(%llX) and Port SN_Pfx(%llX) differ",
				    gid.gid_prefix, sgid.gid_prefix);
				retval = IBT_GIDS_NOT_FOUND;
				continue;
			}

			/*
			 * If HCA GUID or System Image GUID is specified, then
			 * we can achieve our goal sooner!.
			 */
			if ((h_guid == 0) && (sysimg_guid == 0)) {
				/* So only GID info is provided. */

				/*
				 * First Get Path Records for the specified DGID
				 * from this port (SGID). From Path Records,
				 * note down DLID, then use this DLID as Input
				 * attribute to get NodeRecords.
				 */
				npaths = 1;
				path = NULL;

				sa_ret = ibmf_saa_gid_to_pathrecords(saa_handle,
				    sgid, gid, 0, 0, B_TRUE, &npaths, 0, &len,
				    &path);
				if (sa_ret != IBMF_SUCCESS) {
					IBTF_DPRINTF_L2(cmlog,
					    "ibt_get_companion_port_gids: "
					    "ibmf_saa_gid_to_pathrecords() "
					    "returned error: %d ", sa_ret);
					retval =
					    ibcm_ibmf_analyze_error(sa_ret);
					ibcm_dec_hca_acc_cnt(hcap);
					goto get_comp_pgid_exit;
				} else if ((npaths == 0) || (path == NULL)) {
					IBTF_DPRINTF_L2(cmlog,
					    "ibt_get_companion_port_gids: "
					    "failed (%d) to get path records "
					    "for the DGID (0x%llX) from SGID "
					    "(0x%llX)", sa_ret, gid.gid_guid,
					    sgid.gid_guid);
					retval = IBT_GIDS_NOT_FOUND;
					continue;
				}

				bzero(&nr_req, sizeof (sa_node_record_t));
				nr_req.LID = path->DLID;	/* LID */

				IBTF_DPRINTF_L3(cmlog,
				    "ibt_get_companion_port_gids: "
				    "Remote Node: LID = 0x%X", nr_req.LID);

				/* Free SA_Access memory for path record. */
				kmem_free(path, len);

				IBTF_DPRINTF_L3(cmlog,
				    "ibt_get_companion_port_gids: SAA Call: "
				    "based on LID ");

				retval = ibcm_get_node_rec(saa_handle, &nr_req,
				    SA_NODEINFO_COMPMASK_NODELID, &res_p, &len);
				if (retval == IBT_NODE_RECORDS_NOT_FOUND) {
					IBTF_DPRINTF_L2(cmlog,
					    "ibt_get_companion_port_gids: "
					    "failed (%d) to get Node records",
					    retval);
					continue;
				} else if (retval != IBT_SUCCESS) {
					IBTF_DPRINTF_L2(cmlog,
					    "ibt_get_companion_port_gids: "
					    "failed (%d) to get Node records",
					    retval);
					ibcm_dec_hca_acc_cnt(hcap);
					goto get_comp_pgid_exit;
				}

				nr_resp = (sa_node_record_t *)(uchar_t *)res_p;
				/* Note down HCA GUID info. */
				h_guid = nr_resp->NodeInfo.NodeGUID;

				IBTF_DPRINTF_L3(cmlog,
				    "ibt_get_companion_port_gids: "
				    "Remote HCA GUID: 0x%llX", h_guid);

				IBCM_DUMP_NODE_REC(nr_resp);

				kmem_free(res_p, len);
			}

			bzero(&nr_req, sizeof (sa_node_record_t));
			if (h_guid != 0) {
				nr_req.NodeInfo.NodeGUID = h_guid;
				c_mask = SA_NODEINFO_COMPMASK_NODEGUID;
			}

			if (sysimg_guid != 0) {
				nr_req.NodeInfo.SystemImageGUID = sysimg_guid;
				c_mask |= SA_NODEINFO_COMPMASK_SYSIMAGEGUID;
			}

			IBTF_DPRINTF_L3(cmlog, "ibt_get_companion_port_gids: "
			    "SAA Call: CMASK= 0x%llX", c_mask);

			retval = ibcm_get_node_rec(saa_handle, &nr_req, c_mask,
			    &res_p, &len);
			if (retval == IBT_NODE_RECORDS_NOT_FOUND) {
				IBTF_DPRINTF_L3(cmlog,
				    "ibt_get_companion_port_gids: "
				    "failed (%d) to get Node records", retval);
				continue;
			} else if (retval != IBT_SUCCESS) {
				IBTF_DPRINTF_L2(cmlog,
				    "ibt_get_companion_port_gids: Error: (%d) "
				    "while getting Node records", retval);
				ibcm_dec_hca_acc_cnt(hcap);
				goto get_comp_pgid_exit;
			}

			num_rec = len/sizeof (sa_node_record_t);

			/* We will be here, only if we found some NodeRec */
			if (gid.gid_prefix && gid.gid_guid) {
				nr_resp = (sa_node_record_t *)res_p;
				for (l = 0; l < num_rec; l++, nr_resp++) {
					pg = nr_resp->NodeInfo.PortGUID;
					if (gid.gid_guid != pg)
						count++;
				}
			} else {
				count = num_rec;
			}

			if (count != 0) {
				if (multi_sm_loop == 1) {
					count += k;
					t_gidp = kmem_zalloc(count *
					    sizeof (ib_gid_t), KM_SLEEP);

					if ((k != 0) && (gidp != NULL)) {
						bcopy(gidp, t_gidp,
						    k * sizeof (ib_gid_t));
						kmem_free(gidp,
						    k * sizeof (ib_gid_t));
					}
					gidp = t_gidp;
				} else {
					gidp = kmem_zalloc(count *
					    sizeof (ib_gid_t), KM_SLEEP);
				}
				*num_gids_p = count;
				*gids_p = gidp;

				nr_resp = (sa_node_record_t *)res_p;
				for (l = 0; l < num_rec; l++, nr_resp++) {
					IBCM_DUMP_NODE_REC(nr_resp);

					pg = nr_resp->NodeInfo.PortGUID;
					IBTF_DPRINTF_L4(cmlog,
					    "ibt_get_companion_port_gids: "
					    "PortGID %llX", pg);

					if (pg != gid.gid_guid) {
						gidp[k].gid_prefix =
						    sgid.gid_prefix;
						gidp[k].gid_guid = pg;

						IBTF_DPRINTF_L3(cmlog,
						    "ibt_get_companion_pgids: "
						    "GID[%d] = %llX:%llX", k,
						    gidp[k].gid_prefix,
						    gidp[k].gid_guid);

						k++;
						if (k == count)
							break;
					}
				}
				retval = IBT_SUCCESS;	/* done!. */
				kmem_free(res_p, len);
				ibcm_dec_hca_acc_cnt(hcap);
				goto get_comp_pgid_exit;
			} else {
				IBTF_DPRINTF_L2(cmlog,
				    "ibt_get_companion_port_gids: "
				    "Companion PortGIDs not available");
				retval = IBT_GIDS_NOT_FOUND;
			}
			/* Deallocate the memory for 'res_p'. */
			kmem_free(res_p, len);

			/*
			 * If we are on MultiSM setup, then we need to lookout
			 * from that subnet port too.
			 */
			if (multism) {
				/* break if already searched both the subnet */
				if (multi_sm_loop == 1)
					break;

				port = (j == 0) ? 1 : 0;
				multi_sm_loop = 1;
				goto get_comp_for_multism;
			} else {
				break;
			}
		}
		ibcm_dec_hca_acc_cnt(hcap);

		/*
		 * We may be on dual HCA with dual SM configured system.  And
		 * the input attr GID was visible from second HCA. So in order
		 * to get the companion portgid we need to re-look from the
		 * first HCA ports.
		 */
		if ((num_hcas > 1) && (i > 0) && (h_guid != 0) &&
		    (multi_hca_loop != 1)) {
			multi_hca_loop = 1;
			goto get_comp_for_multihca;
		}
	}
	if (*num_gids_p == 0)
		retval = IBT_GIDS_NOT_FOUND;

get_comp_pgid_exit:
	if (guid_array)
		ibt_free_hca_list(guid_array, num_hcas);

	if ((retval != IBT_SUCCESS) && (*num_gids_p != 0)) {
		retval = IBT_SUCCESS;
	}

	IBTF_DPRINTF_L3(cmlog, "ibt_get_companion_port_gids: done. Status %d, "
	    "Found %d GIDs", retval, *num_gids_p);

	return (retval);
}

/* RDMA IP CM Support routines */
ibt_status_t
ibt_get_src_ip(ibt_srcip_attr_t *sattr, ibt_srcip_info_t **src_info_p,
    uint_t *entries_p)
{
	ibt_srcip_info_t	*s_ip;
	ibcm_arp_ip_t		*ipp;
	ibcm_arp_ibd_insts_t	ibds;
	uint8_t			i, j;
	uint_t			count;
	ibt_status_t		retval = IBT_SUCCESS;

	IBTF_DPRINTF_L4(cmlog, "ibt_get_src_ip(%p, %p, %p)",
	    sattr, src_info_p, entries_p);

	if (sattr == NULL || entries_p == NULL) {
		IBTF_DPRINTF_L3(cmlog, "ibt_get_src_ip: Invalid I/P Args.");
		return (IBT_INVALID_PARAM);
	}

	if (sattr->sip_gid.gid_prefix == 0 || sattr->sip_gid.gid_guid == 0) {
		IBTF_DPRINTF_L3(cmlog, "ibt_get_src_ip: Invalid GID.");
		return (IBT_INVALID_PARAM);
	}

	/* TBD: Zoneid */
	retval = ibcm_arp_get_ibds(&ibds, sattr->sip_family);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(cmlog, "ibt_get_src_ip: ibcm_arp_get_ibds "
		    "failed to get IBD Instances: ret 0x%x", retval);
		goto get_src_ip_end;
	}

	count = 0;
	for (i = 0, ipp = ibds.ibcm_arp_ip; i < ibds.ibcm_arp_ibd_cnt;
	    i++, ipp++) {
		if (ipp->ip_inet_family == AF_UNSPEC)
			continue;
		if (ipp->ip_port_gid.gid_prefix == sattr->sip_gid.gid_prefix &&
		    ipp->ip_port_gid.gid_guid == sattr->sip_gid.gid_guid) {
			if ((sattr->sip_pkey) &&
			    (ipp->ip_pkey != sattr->sip_pkey))
				continue;

			if ((sattr->sip_zoneid != ALL_ZONES) &&
			    (sattr->sip_zoneid != ipp->ip_zoneid))
				continue;

			count++;
			break;
		}
	}

	if (count) {
		/*
		 * Allocate memory for return buffer, to be freed by
		 * ibt_free_srcip_info().
		 */
		s_ip = kmem_alloc((count * sizeof (ibt_srcip_info_t)),
		    KM_SLEEP);

		*src_info_p = s_ip;
		*entries_p = count;

		j = 0;
		for (i = 0, ipp = ibds.ibcm_arp_ip; i < ibds.ibcm_arp_ibd_cnt;
		    i++, ipp++) {
			if (ipp->ip_inet_family == AF_UNSPEC)
				continue;
			if ((ipp->ip_port_gid.gid_prefix ==
			    sattr->sip_gid.gid_prefix) &&
			    (ipp->ip_port_gid.gid_guid ==
			    sattr->sip_gid.gid_guid)) {
				if ((sattr->sip_pkey) &&
				    (ipp->ip_pkey != sattr->sip_pkey))
					continue;

				if ((sattr->sip_zoneid != ALL_ZONES) &&
				    (sattr->sip_zoneid != ipp->ip_zoneid))
					continue;

				_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*s_ip))
				s_ip[j].ip_addr.family = ipp->ip_inet_family;
				_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*s_ip))
				if (s_ip[j].ip_addr.family == AF_INET) {
					bcopy(&ipp->ip_cm_sin.sin_addr,
					    &s_ip[j].ip_addr.un.ip4addr,
					    sizeof (in_addr_t));
				} else if (s_ip[j].ip_addr.family == AF_INET6) {
					bcopy(&ipp->ip_cm_sin6.sin6_addr,
					    &s_ip[j].ip_addr.un.ip6addr,
					    sizeof (in6_addr_t));
					/* TBD: scope_id */
				}
				IBCM_PRINT_IP("ibt_get_src_ip",
				    &s_ip[j].ip_addr);
				j++;
			}
		}
	} else {
		retval = IBT_SRC_IP_NOT_FOUND;
	}

get_src_ip_end:
	ibcm_arp_free_ibds(&ibds);
	return (retval);
}

/*
 * ibt_free_srcip_info()
 *	Free the memory allocated by successful ibt_get_src_ip()
 *
 *	src_info	Pointer returned by ibt_get_src_ip().
 *
 *	entries		The number of ibt_ip_addr_t entries to free.
 */
void
ibt_free_srcip_info(ibt_srcip_info_t *src_info, uint_t entries)
{
	IBTF_DPRINTF_L3(cmlog, "ibt_free_srcip_info: "
	    "Free <%d> entries from 0x%p", entries, src_info);

	if ((src_info != NULL) && (entries > 0))
		kmem_free(src_info, entries * sizeof (ibt_srcip_info_t));
	else
		IBTF_DPRINTF_L2(cmlog, "ibt_free_srcip_info: "
		    "ERROR: NULL buf pointer or ZERO length specified.");
}


ib_svc_id_t
ibt_get_ip_sid(uint8_t protocol_num, in_port_t dst_port)
{
	ib_svc_id_t	sid;

	IBTF_DPRINTF_L4(cmlog, "ibt_get_ip_sid(%X, %lX)", protocol_num,
	    dst_port);

	/*
	 * If protocol_num is non-zero, then formulate the SID and return it.
	 * If protocol_num is zero, then we need to assign a locally generated
	 * IP SID with IB_SID_IPADDR_PREFIX.
	 */
	if (protocol_num) {
		sid = IB_SID_IPADDR_PREFIX | protocol_num << 16 | dst_port;
	} else {
		sid = ibcm_alloc_ip_sid();
	}

	IBTF_DPRINTF_L3(cmlog, "ibt_get_ip_sid: SID: 0x%016llX", sid);
	return (sid);
}

ibt_status_t
ibt_release_ip_sid(ib_svc_id_t ip_sid)
{
	IBTF_DPRINTF_L4(cmlog, "ibt_release_ip_sid(%llX)", ip_sid);

	if (((ip_sid & IB_SID_IPADDR_PREFIX_MASK) != 0) ||
	    (!(ip_sid & IB_SID_IPADDR_PREFIX))) {
		IBTF_DPRINTF_L2(cmlog, "ibt_release_ip_sid(0x%016llX): ERROR: "
		    "Called for Non-RDMA IP SID", ip_sid);
		return (IBT_INVALID_PARAM);
	}

	/*
	 * If protocol_num in ip_sid are all ZEROs, then this SID is allocated
	 * by IBTF. If not, then the specified ip_sid is invalid.
	 */
	if (ip_sid & IB_SID_IPADDR_IPNUM_MASK) {
		IBTF_DPRINTF_L2(cmlog, "ibt_release_ip_sid(0x%016llX): ERROR: "
		    "Called for Non-IBTF assigned RDMA IP SID", ip_sid);
		return (IBT_INVALID_PARAM);
	}

	ibcm_free_ip_sid(ip_sid);

	return (IBT_SUCCESS);
}


uint8_t
ibt_get_ip_protocol_num(ib_svc_id_t sid)
{
	return ((sid & IB_SID_IPADDR_IPNUM_MASK) >> 16);
}

in_port_t
ibt_get_ip_dst_port(ib_svc_id_t sid)
{
	return (sid & IB_SID_IPADDR_PORTNUM_MASK);
}

_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibt_ip_cm_info_t))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibcm_ip_pvtdata_t))

ibt_status_t
ibt_format_ip_private_data(ibt_ip_cm_info_t *ip_cm_info,
    ibt_priv_data_len_t priv_data_len, void *priv_data_p)
{
	ibcm_ip_pvtdata_t	ip_data;

	IBTF_DPRINTF_L4(cmlog, "ibt_format_ip_private_data(%p, %d, %p)",
	    ip_cm_info, priv_data_len, priv_data_p);

	if ((ip_cm_info == NULL) || (priv_data_p == NULL) ||
	    (priv_data_len < IBT_IP_HDR_PRIV_DATA_SZ)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_format_ip_private_data: ERROR "
		    "Invalid Inputs.");
		return (IBT_INVALID_PARAM);
	}

	bzero(&ip_data, sizeof (ibcm_ip_pvtdata_t));
	ip_data.ip_srcport = ip_cm_info->src_port; /* Source Port */

	IBCM_PRINT_IP("format_ip_pvt: src", &ip_cm_info->src_addr);
	IBCM_PRINT_IP("format_ip_pvt: dst", &ip_cm_info->dst_addr);
	/* IPV = 0x4, if IP-Addr are IPv4 format, else 0x6 for IPv6 */
	if (ip_cm_info->src_addr.family == AF_INET) {
		ip_data.ip_ipv = IBT_CM_IP_IPV_V4;
		ip_data.ip_srcv4 = ip_cm_info->src_addr.un.ip4addr;
		ip_data.ip_dstv4 = ip_cm_info->dst_addr.un.ip4addr;
	} else if (ip_cm_info->src_addr.family == AF_INET6) {
		ip_data.ip_ipv = IBT_CM_IP_IPV_V6;
		bcopy(&ip_cm_info->src_addr.un.ip6addr,
		    &ip_data.ip_srcv6, sizeof (in6_addr_t));
		bcopy(&ip_cm_info->dst_addr.un.ip6addr,
		    &ip_data.ip_dstv6, sizeof (in6_addr_t));
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibt_format_ip_private_data: ERROR "
		    "IP Addr needs to be either AF_INET or AF_INET6 family.");
		return (IBT_INVALID_PARAM);
	}

	ip_data.ip_MajV = IBT_CM_IP_MAJ_VER;
	ip_data.ip_MinV = IBT_CM_IP_MIN_VER;

	bcopy(&ip_data, priv_data_p, IBT_IP_HDR_PRIV_DATA_SZ);

	return (IBT_SUCCESS);
}


ibt_status_t
ibt_get_ip_data(ibt_priv_data_len_t priv_data_len, void *priv_data,
    ibt_ip_cm_info_t *ip_cm_infop)
{
	ibcm_ip_pvtdata_t	ip_data;

	IBTF_DPRINTF_L4(cmlog, "ibt_get_ip_data(%d, %p, %p)",
	    priv_data_len, priv_data, ip_cm_infop);

	if ((ip_cm_infop == NULL) || (priv_data == NULL) ||
	    (priv_data_len < IBT_IP_HDR_PRIV_DATA_SZ)) {
		IBTF_DPRINTF_L2(cmlog, "ibt_get_ip_data: ERROR Invalid Inputs");
		return (IBT_INVALID_PARAM);
	}

	bcopy(priv_data, &ip_data, IBT_IP_HDR_PRIV_DATA_SZ);
	ip_cm_infop->src_port = ip_data.ip_srcport; /* Source Port */

	/* IPV = 0x4, if IP Address are IPv4 format, else 0x6 for IPv6 */
	if (ip_data.ip_ipv == IBT_CM_IP_IPV_V4) {
		/* Copy IPv4 Addr */
		ip_cm_infop->src_addr.family = ip_cm_infop->dst_addr.family =
		    AF_INET;
		ip_cm_infop->src_addr.un.ip4addr = ip_data.ip_srcv4;
		ip_cm_infop->dst_addr.un.ip4addr = ip_data.ip_dstv4;
	} else if (ip_data.ip_ipv == IBT_CM_IP_IPV_V6) {
		/* Copy IPv6 Addr */
		ip_cm_infop->src_addr.family = ip_cm_infop->dst_addr.family =
		    AF_INET6;
		bcopy(&ip_data.ip_srcv6, &ip_cm_infop->src_addr.un.ip6addr,
		    sizeof (in6_addr_t));
		bcopy(&ip_data.ip_dstv6, &ip_cm_infop->dst_addr.un.ip6addr,
		    sizeof (in6_addr_t));
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibt_get_ip_data: ERROR: IP Addr needs"
		    " to be either AF_INET or AF_INET6 family.");
		return (IBT_INVALID_PARAM);
	}
	IBCM_PRINT_IP("ibt_get_ip_data: src", &ip_cm_infop->src_addr);
	IBCM_PRINT_IP("ibt_get_ip_data: dst", &ip_cm_infop->dst_addr);

	return (IBT_SUCCESS);
}


/* Routines for warlock */

/* ARGSUSED */
static void
ibcm_dummy_mcg_handler(void *arg, ibt_status_t retval, ibt_mcg_info_t *minfo)
{
	ibcm_join_mcg_tqarg_t	dummy_mcg;

	dummy_mcg.func = ibcm_dummy_mcg_handler;

	IBTF_DPRINTF_L5(cmlog, "ibcm_dummy_mcg_handler: "
	    "dummy_mcg.func %p", dummy_mcg.func);
}


/* ARGSUSED */
static void
ibcm_dummy_recycle_rc_handler(ibt_status_t retval, void *arg)
{
	ibcm_taskq_recycle_arg_t	dummy_rc_recycle;

	dummy_rc_recycle.func = ibcm_dummy_recycle_rc_handler;

	IBTF_DPRINTF_L5(cmlog, "ibcm_dummy_recycle_rc_handler: "
	    "dummy_rc_recycle.func %p", dummy_rc_recycle.func);
}


/* ARGSUSED */
static ibt_cm_status_t
ibcm_dummy_ud_handler(void *priv, ibt_cm_ud_event_t *event,
    ibt_cm_ud_return_args_t *ret_args,
    void *priv_data, ibt_priv_data_len_t len)
{
	/*
	 * Let warlock see that ibcm_local_handler_s::actual_cm_handler
	 * points to this routine.
	 */
	ibcm_local_handler_t	p;
	ibcm_ud_state_data_t	dummy_ud;

	p.actual_cm_handler = ibcm_dummy_ud_handler;
	dummy_ud.ud_cm_handler = ibcm_dummy_ud_handler;

	IBTF_DPRINTF_L5(cmlog, "ibcm_dummy_ud_handler: p.actual_cm_handler %p"
	    "dummy_ud.ud_cm_handler %p", p.actual_cm_handler,
	    dummy_ud.ud_cm_handler);
	/*
	 * Call all routines that the client's callback routine could call.
	 */

	return (IBT_CM_ACCEPT);
}

/* ARGSUSED */
static ibt_cm_status_t
ibcm_dummy_rc_handler(void *priv, ibt_cm_event_t *event,
    ibt_cm_return_args_t *ret_args, void *priv_data, ibt_priv_data_len_t len)
{
	ibcm_state_data_t	dummy_rc;

	dummy_rc.cm_handler = ibcm_dummy_rc_handler;

	IBTF_DPRINTF_L5(cmlog, "ibcm_dummy_rc_handler: "
	    "dummy_ud.ud_cm_handler %p", dummy_rc.cm_handler);
	/*
	 * Call all routines that the client's callback routine could call.
	 */

	return (IBT_CM_ACCEPT);
}
