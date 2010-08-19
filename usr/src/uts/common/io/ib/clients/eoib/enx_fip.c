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

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/byteorder.h>

#include <sys/ib/clients/eoib/enx_impl.h>

const char fip_vendor_mellanox[] = {
	0x4d, 0x65, 0x6c, 0x6c, 0x61, 0x6e, 0x6f, 0x78
};

/*
 * HW/FW workaround
 *
 * Verification of descriptor list length in the received packets is
 * disabled, since experimentation shows that BX does not set the desc
 * list length correctly.
 */
int enx_wa_no_desc_list_len = 1;

/*
 * Static function declarations
 */
static int eibnx_fip_make_solicit_pkt(eibnx_thr_info_t *, eibnx_wqe_t *);
static int eibnx_fip_send_solicit_pkt(eibnx_thr_info_t *, eibnx_wqe_t *,
    eibnx_gw_addr_t *);
static int eibnx_fip_parse_advt_pkt(uint8_t *, eibnx_gw_msg_t *);
static void eibnx_rb_fip_make_solicit_pkt(eibnx_wqe_t *);

/*
 * Prepare and send a solicit multicast packet to the All-EoIB-GWs-GID
 */
int
eibnx_fip_solicit_mcast(eibnx_thr_info_t *info)
{
	eibnx_wqe_t *swqe;
	int ret;

	if ((swqe = eibnx_acquire_swqe(info, KM_SLEEP)) == NULL)
		return (ENX_E_FAILURE);

	ret = eibnx_fip_make_solicit_pkt(info, swqe);
	if (ret != ENX_E_SUCCESS) {
		eibnx_release_swqe(swqe);
		return (ENX_E_FAILURE);
	}

	ret = eibnx_fip_send_solicit_pkt(info, swqe, NULL);
	if (ret != ENX_E_SUCCESS) {
		eibnx_rb_fip_make_solicit_pkt(swqe);
		eibnx_release_swqe(swqe);
		return (ENX_E_FAILURE);
	}

	return (ENX_E_SUCCESS);
}

/*
 * Go through the list of already discovered gateways and send
 * a unicast solicitation to each gateway.  This is required by
 * the EoIB specification ostensibly to receive updated
 * advertisements.
 */
int
eibnx_fip_solicit_ucast(eibnx_thr_info_t *info, clock_t *solicit_period_ticks)
{
	eibnx_gw_info_t *gw;
	eibnx_wqe_t *swqe;
	clock_t min_solicit_period_msec;
	int ret;

	/*
	 * We want to read the gwlist and send a unicast to each
	 * destination.  Now, the only places where the gw list pointers
	 * are updated are when we're adding a new gw item to the list
	 * and when the list is being torn down and freed.
	 *
	 * Since new GWs are always inserted at the head of the list,
	 * we're guaranteed that any tail subchain of the list will
	 * not change by the addition of a new gw item coming into
	 * the list.
	 *
	 * Also, since the gw list is torn down only by the port-monitor
	 * thread (i.e. ourselves), we are also protected against the
	 * list itself going away while we're here.
	 *
	 * Given these two constraints, we can safely read the list
	 * of gateways without the gw list lock in this routine.
	 */
	min_solicit_period_msec = drv_hztousec(*solicit_period_ticks) / 1000;
	for (gw = info->ti_gw; gw; gw = gw->gw_next) {

		if (eibnx_is_gw_dead(gw))
			continue;

		swqe = gw->gw_swqe;
		ASSERT(swqe != NULL);

		mutex_enter(&swqe->qe_lock);
		if (swqe->qe_type != ENX_QETYP_SWQE) {
			ENX_DPRINTF_DEBUG("eibnx_fip_solicit_ucast: "
			    "gw wqe type (0x%lx) indicates this is not an "
			    "swqe!, cannot send solicitation to gw",
			    swqe->qe_type);
			mutex_exit(&swqe->qe_lock);
			continue;
		} else if ((swqe->qe_flags & ENX_QEFL_INUSE) !=
		    ENX_QEFL_INUSE) {
			ENX_DPRINTF_DEBUG("eibnx_fip_solicit_ucast: "
			    "gw swqe flags (0x%lx) indicate swqe is free!, "
			    "cannot send solicitation to gw", swqe->qe_flags);
			mutex_exit(&swqe->qe_lock);
			continue;
		} else if ((swqe->qe_flags & ENX_QEFL_POSTED) ==
		    ENX_QEFL_POSTED) {
			ENX_DPRINTF_DEBUG("eibnx_fip_solicit_ucast: gw swqe "
			    "flags (0x%lx) indicate swqe is still with HCA!, "
			    "cannot send solicitation to gw", swqe->qe_flags);
			mutex_exit(&swqe->qe_lock);
			continue;
		}
		mutex_exit(&swqe->qe_lock);

		/*
		 * EoIB spec requires that each host send solicitation
		 * to discovered gateways atleast every 4 * GW_ADV_PERIOD.
		 * We make sure we send a solicitation to all gateways
		 * every 4 * GW_ADV_PERIOD of the smallest value of
		 * GW_ADV_PERIOD that we have in our gw list.
		 */
		if ((gw->gw_adv_period * 4) < min_solicit_period_msec)
			min_solicit_period_msec = gw->gw_adv_period * 4;

		ret = eibnx_fip_make_solicit_pkt(info, swqe);
		if (ret != ENX_E_SUCCESS)
			continue;

		ret = eibnx_fip_send_solicit_pkt(info, swqe, &gw->gw_addr);
		if (ret != ENX_E_SUCCESS)
			eibnx_rb_fip_make_solicit_pkt(swqe);
	}

	*solicit_period_ticks = drv_usectohz(min_solicit_period_msec * 1000);

	return (ENX_E_SUCCESS);
}

/*
 * Given a send wqe and an eibnx_thr_info_t pointer, fill in the
 * send buffer with a solicit packet in the network byte order.
 */
static int
eibnx_fip_make_solicit_pkt(eibnx_thr_info_t *info, eibnx_wqe_t *swqe)
{
	fip_solicit_t *solicit;
	fip_proto_t *proto;
	fip_basic_hdr_t *hdr;
	fip_desc_iba_t *iba;
	ib_gid_t port_gid;
	ib_guid_t port_guid;

	uint8_t *pkt = (uint8_t *)(uintptr_t)(swqe->qe_sgl.ds_va);
	uint_t pktsz = swqe->qe_sgl.ds_len;
	uint_t solicit_sz = sizeof (fip_solicit_t);

	if (pktsz < solicit_sz) {
		ENX_DPRINTF_ERR("swqe bufsize too small for pkt, "
		    "pktsz=%x < expsz=%x", pktsz, solicit_sz);
		return (ENX_E_FAILURE);
	}

	/*
	 * Lint complains that there may be an alignment issue here,
	 * but we know that the "pkt" is atleast double-word aligned,
	 * so it's ok.
	 */
	solicit = (fip_solicit_t *)pkt;

	/*
	 * Fill in the FIP protocol version
	 */
	proto = &solicit->sl_proto_version;
	proto->pr_version = FIP_PROTO_VERSION;

	/*
	 * Fill in the basic header
	 */
	hdr = &solicit->sl_fip_hdr;
	hdr->hd_opcode = htons(FIP_OPCODE_EOIB);
	hdr->hd_subcode = FIP_SUBCODE_H_SOLICIT;
	hdr->hd_desc_list_len = htons((solicit_sz >> 2) - 2);
	hdr->hd_flags = 0;
	hdr->hd_type = FIP_DESC_TYPE_VENDOR_ID;
	hdr->hd_len = FIP_DESC_LEN_VENDOR_ID;
	bcopy(fip_vendor_mellanox, hdr->hd_vendor_id, FIP_VENDOR_LEN);

	/*
	 * Fill in the Infiniband Address descriptor
	 */
	iba = &solicit->sl_iba;
	iba->ia_type = FIP_DESC_TYPE_IBA;
	iba->ia_len = FIP_DESC_LEN_IBA;
	bcopy(fip_vendor_mellanox, iba->ia_vendor_id, FIP_VENDOR_LEN);
	iba->ia_qpn = htonl(info->ti_qpn);
	iba->ia_sl_portid = 0;
	iba->ia_lid = htons(info->ti_pi->p_base_lid);
	port_gid = info->ti_pi->p_sgid_tbl[0];
	port_guid = htonll(port_gid.gid_guid);
	bcopy(&port_guid, iba->ia_guid, FIP_GUID_LEN);

	/*
	 * Adjust the ds_len in the sgl to indicate the size of the
	 * solicit pkt before returning
	 */
	swqe->qe_sgl.ds_len = solicit_sz;

	return (ENX_E_SUCCESS);
}

static int
eibnx_setup_ud_dest(eibnx_thr_info_t *info, eibnx_wqe_t *swqe,
    eibnx_gw_addr_t *gw_addr)
{
	eibnx_t *ss = enx_global_ss;
	ibt_path_attr_t attr;
	ibt_path_info_t path;
	ibt_status_t ret;

	/*
	 * If this a multicast send, we'll have the gateway address NULL,
	 * and we'll need to modify the UD destination to send to the
	 * solicit mcg.
	 */
	if (gw_addr == NULL) {
		ret = ibt_modify_ud_dest(swqe->qe_wr.send.wr.ud.udwr_dest,
		    info->ti_solicit_mcg->mc_qkey, IB_MC_QPN,
		    &info->ti_solicit_mcg->mc_adds_vect);
		if (ret != IBT_SUCCESS) {
			ENX_DPRINTF_ERR("ibt_modify_ud_dest() failed with "
			    "ret=%d, qkey=%x, qpn=%x", ret,
			    info->ti_solicit_mcg->mc_qkey, IB_MC_QPN);
			return (ENX_E_FAILURE);
		}

		return (ENX_E_SUCCESS);
	}

	/*
	 * If this is a unicast send, but we already have the gw address
	 * vector, the ud destination handle has already been set up for
	 * this gateway, so we can return.
	 */
	if (gw_addr->ga_vect)
		return (ENX_E_SUCCESS);

	/*
	 * Get the reversible path information for this gateway
	 */
	bzero(&attr, sizeof (ibt_path_info_t));
	attr.pa_dgids = &gw_addr->ga_gid;
	attr.pa_num_dgids = 1;
	attr.pa_sgid = info->ti_pi->p_sgid_tbl[0];
	attr.pa_pkey = gw_addr->ga_pkey;

	bzero(&path, sizeof (ibt_path_info_t));
	ret = ibt_get_paths(ss->nx_ibt_hdl, IBT_PATH_PKEY,
	    &attr, 1, &path, NULL);
	if ((ret != IBT_SUCCESS) || (path.pi_hca_guid == 0)) {
		ENX_DPRINTF_ERR("ibt_get_paths() failed with "
		    "ret=%d, gid_prefix=%llx, gid_guid=%llx", ret,
		    gw_addr->ga_gid.gid_prefix, gw_addr->ga_gid.gid_guid);
		return (ENX_E_FAILURE);
	}

	/*
	 * And save the address vector
	 */
	gw_addr->ga_vect = kmem_zalloc(sizeof (ibt_adds_vect_t), KM_SLEEP);
	bcopy(&path.pi_prim_cep_path.cep_adds_vect, gw_addr->ga_vect,
	    sizeof (ibt_adds_vect_t));

	/*
	 * Modify the UD destination handle on this swqe entry to address
	 * this gateway
	 */
	ret = ibt_modify_ud_dest(swqe->qe_wr.send.wr.ud.udwr_dest,
	    gw_addr->ga_qkey, gw_addr->ga_qpn, gw_addr->ga_vect);
	if (ret != IBT_SUCCESS) {
		ENX_DPRINTF_ERR("ibt_modify_ud_dest() failed with "
		    "ret=%d, qkey=%x, qpn=%x", ret, gw_addr->ga_qkey,
		    gw_addr->ga_qpn);
		kmem_free(gw_addr->ga_vect, sizeof (ibt_adds_vect_t));
		gw_addr->ga_vect = NULL;
		return (ENX_E_FAILURE);
	}

	return (ENX_E_SUCCESS);
}

/*
 * Send a solicit packet to the appropriate destination: if the
 * destination gw addr is specified, send a unicast message to it;
 * if not, send a multicast using the solicit mcg address.
 */
static int
eibnx_fip_send_solicit_pkt(eibnx_thr_info_t *info, eibnx_wqe_t *swqe,
    eibnx_gw_addr_t *gw_addr)
{
	ibt_status_t ret;

	if (eibnx_setup_ud_dest(info, swqe, gw_addr) != ENX_E_SUCCESS)
		return (ENX_E_FAILURE);

	mutex_enter(&swqe->qe_lock);

	/*
	 * Note that if the post send fails, we don't really need to undo
	 * anything we did in setting up the ud destination; we can always
	 * use it for the next time.
	 */
	ret = ibt_post_send(info->ti_chan, &(swqe->qe_wr.send), 1, NULL);
	if (ret != IBT_SUCCESS) {
		mutex_exit(&swqe->qe_lock);
		ENX_DPRINTF_ERR("ibt_post_send() failed for solicit, "
		    "ret=%d", ret);
		return (ENX_E_FAILURE);
	}

	/*
	 * Set the 'posted' flag for the send wqe. If this is an unicast
	 * send, the wqe is attached to a specific gw entry and we should
	 * not release the wqe back to the pool on the send completion.
	 */
	swqe->qe_flags |= ENX_QEFL_POSTED;
	if (gw_addr == NULL) {
		swqe->qe_flags |= ENX_QEFL_RELONCOMP;
		info->ti_mcast_done = 1;
	}

	mutex_exit(&swqe->qe_lock);

	return (ENX_E_SUCCESS);
}

/*
 * Parse a received packet from the gateway into the
 * eibnx_gw_msg_t argument.  Note that at this point, this
 * driver only expects to receive advertisements from the
 * GW, nothing else.
 */
int
eibnx_fip_parse_pkt(uint8_t *pkt, eibnx_gw_msg_t *msg)
{
	fip_basic_hdr_t *hdr;
	uint16_t opcode;
	uint8_t subcode;
	int ret = ENX_E_FAILURE;

	/*
	 * Lint complains about potential alignment problem here,
	 * but the fip_* structures are all packed and each of them
	 * is aligned on a word boundary, so we're ok.
	 */
	hdr = (fip_basic_hdr_t *)(pkt + sizeof (fip_proto_t));

	/*
	 * Verify that the opcode is EoIB
	 */
	if ((opcode = ntohs(hdr->hd_opcode)) != FIP_OPCODE_EOIB) {
		ENX_DPRINTF_WARN("unsupported opcode (%x) found in "
		    "gw advertisement, ignoring", opcode);
		return (ENX_E_FAILURE);
	}

	/*
	 * We only handle GW advertisements in the eibnx driver code.  However,
	 * the BridgeX gateway software currently sends login acknowledgements
	 * to the one who did the solicitation instead of the one who actually
	 * made the login request, so we need to do something about this as
	 * well.
	 */
	subcode = hdr->hd_subcode;
	switch (subcode) {
	case FIP_SUBCODE_G_ADVERTISE:
		ret = eibnx_fip_parse_advt_pkt(pkt, msg);
		break;

	case FIP_SUBCODE_G_VNIC_LOGIN_ACK:
		msg->gm_type = FIP_VNIC_LOGIN_ACK;
		ret = ENX_E_SUCCESS;
		break;

	default:
		ENX_DPRINTF_WARN("unsupported subcode (%x) found in "
		    "gw advertisement, ignoring", subcode);
		ret = ENX_E_FAILURE;
		break;
	}

	return (ret);
}

/*
 * Parse and validate a packet known to be an advertisement from
 * the GW.
 */
static int
eibnx_fip_parse_advt_pkt(uint8_t *pkt, eibnx_gw_msg_t *msg)
{
	fip_advertise_t *advertise;
	fip_basic_hdr_t *hdr;
	fip_desc_iba_t *desc_iba;
	fip_desc_gwinfo_t *desc_gwinfo;
	fip_desc_gwid_t *desc_gwid;
	fip_desc_keepalive_t *desc_ka;
	eibnx_gw_info_t *gwi;
	ib_guid_t guid;
	uint16_t rss_qpn_num_net_vnics;
	uint16_t sl_portid;
	uint16_t flags;

	/*
	 * Lint complains about potential alignment problem here,
	 * but we know that "pkt" is always atleast double-word
	 * aligned when it's passed to us, so we're ok.
	 */
	advertise = (fip_advertise_t *)pkt;

	/*
	 * Verify if the descriptor list length in the received
	 * packet is valid.  Currently disabled.
	 *
	 * Experimentation shows that BX doesn't set the desc list
	 * length correctly, so we also simply ignore it and move
	 * on.  If and when BX fixes this problem, we'll need to
	 * enable the warning+failure below.
	 */
	hdr = &(advertise->ad_fip_header);
	if (!enx_wa_no_desc_list_len) {
		uint_t pkt_data_sz;

		pkt_data_sz = (ntohs(hdr->hd_desc_list_len) + 2) << 2;
		if (pkt_data_sz < sizeof (fip_advertise_t)) {
			ENX_DPRINTF_WARN("advertisement from gw too small; "
			    "expected %x, got %x", sizeof (fip_advertise_t),
			    pkt_data_sz);
			return (ENX_E_FAILURE);
		}
	}

	/*
	 * Validate all the header and descriptor types and lengths
	 */

	if (hdr->hd_type != FIP_DESC_TYPE_VENDOR_ID ||
	    hdr->hd_len != FIP_DESC_LEN_VENDOR_ID) {
		ENX_DPRINTF_WARN("invalid type/len in fip basic header; "
		    "expected (%x,%x), got (%x,%x)", FIP_DESC_TYPE_VENDOR_ID,
		    FIP_DESC_LEN_VENDOR_ID, hdr->hd_type, hdr->hd_len);
		return (ENX_E_FAILURE);
	}

	desc_iba = &(advertise->ad_iba);
	if (desc_iba->ia_type != FIP_DESC_TYPE_IBA ||
	    desc_iba->ia_len != FIP_DESC_LEN_IBA) {
		ENX_DPRINTF_WARN("invalid type/len in fip iba desc; "
		    "expected (%x,%x), got (%x,%x)", FIP_DESC_TYPE_IBA,
		    FIP_DESC_LEN_IBA, desc_iba->ia_type, desc_iba->ia_len);
		return (ENX_E_FAILURE);
	}

	desc_gwinfo = &(advertise->ad_gwinfo);
	if (desc_gwinfo->gi_type != FIP_DESC_TYPE_EOIB_GW_INFO ||
	    desc_gwinfo->gi_len != FIP_DESC_LEN_EOIB_GW_INFO) {
		ENX_DPRINTF_WARN("invalid type/len in fip gwinfo desc; "
		    "expected (%x,%x), got (%x,%x)",
		    FIP_DESC_TYPE_EOIB_GW_INFO, FIP_DESC_LEN_EOIB_GW_INFO,
		    desc_gwinfo->gi_type, desc_gwinfo->gi_len);
		return (ENX_E_FAILURE);
	}

	desc_gwid = &(advertise->ad_gwid);
	if (desc_gwid->id_type != FIP_DESC_TYPE_GW_ID ||
	    desc_gwid->id_len != FIP_DESC_LEN_GW_ID) {
		ENX_DPRINTF_WARN("invalid type/len in fip gwid desc; "
		    "expected (%x,%x), got (%x,%x)",
		    FIP_DESC_TYPE_GW_ID, FIP_DESC_LEN_GW_ID,
		    desc_gwid->id_type, desc_gwid->id_len);
		return (ENX_E_FAILURE);
	}

	desc_ka = &(advertise->ad_keep_alive);
	if (desc_ka->ka_type != FIP_DESC_TYPE_KEEP_ALIVE ||
	    desc_ka->ka_len != FIP_DESC_LEN_KEEP_ALIVE) {
		ENX_DPRINTF_WARN("invalid type/len in fip ka desc; "
		    "expected (%x,%x), got (%x,%x)",
		    FIP_DESC_TYPE_KEEP_ALIVE, FIP_DESC_LEN_KEEP_ALIVE,
		    desc_ka->ka_type, desc_ka->ka_len);
		return (ENX_E_FAILURE);
	}

	/*
	 * Record if the gw is available for login ('A' bit in the header)
	 */
	flags = ntohs(hdr->hd_flags);
	gwi = &(msg->u.gm_info);
	gwi->gw_flag_available = (flags & FIP_BHFLAG_GWAVAIL) ? 1 : 0;

	/*
	 * Record if this was in response to a solicit request (unicast
	 * advertisement) or not ('S' bit in the header)
	 */
	gwi->gw_flag_ucast_advt = (flags & FIP_BHFLAG_SLCTMSG) ? 1 : 0;
	msg->gm_type = (gwi->gw_flag_ucast_advt) ?
	    FIP_GW_ADVERTISE_UCAST : FIP_GW_ADVERTISE_MCAST;

	/*
	 * Record all info from the Infiniband Address descriptor
	 */
	gwi->gw_ctrl_qpn = (ntohl(desc_iba->ia_qpn) & FIP_IBA_QPN_MASK);

	sl_portid = ntohs(desc_iba->ia_sl_portid);
	gwi->gw_portid = (sl_portid & FIP_IBA_PORTID_MASK);
	gwi->gw_sl = ((sl_portid & FIP_IBA_SL_MASK) >> FIP_IBA_SL_SHIFT);

	gwi->gw_lid = ntohs(desc_iba->ia_lid);

	bcopy(desc_iba->ia_guid, &guid, sizeof (ib_guid_t));
	gwi->gw_guid = ntohll(guid);

	/*
	 * Record all info from the EoIB GW Information descriptor
	 */
	if (desc_gwinfo->gi_flags & FIP_GWI_HOST_ADMIND_VNICS_MASK)
		gwi->gw_is_host_adm_vnics = 1;
	else
		gwi->gw_is_host_adm_vnics = 0;

	rss_qpn_num_net_vnics = ntohs(desc_gwinfo->gi_rss_qpn_num_net_vnics);
	gwi->gw_num_net_vnics = (rss_qpn_num_net_vnics &
	    FIP_GWI_NUM_NET_VNICS_MASK);
	gwi->gw_n_rss_qpn = ((rss_qpn_num_net_vnics &
	    FIP_GWI_RSS_QPN_MASK) >> FIP_GWI_RSS_QPN_SHIFT);
	bcopy(desc_gwinfo->gi_vendor_id, gwi->gw_vendor_id, FIP_VENDOR_LEN);
	(gwi->gw_vendor_id)[FIP_VENDOR_LEN] = '\0';

	/*
	 * Record all info from the Gateway Identifier descriptor
	 */
	bcopy(desc_gwid->id_guid, &guid, sizeof (ib_guid_t));
	gwi->gw_system_guid = ntohll(guid);
	bcopy(desc_gwid->id_sysname, gwi->gw_system_name, FIP_SYSNAME_LEN);
	(gwi->gw_system_name)[FIP_SYSNAME_LEN] = '\0';
	bcopy(desc_gwid->id_portname, gwi->gw_port_name, FIP_PORTNAME_LEN);
	(gwi->gw_port_name)[FIP_PORTNAME_LEN] = '\0';

	/*
	 * Record all info from the Keep Alive descriptor
	 */
	gwi->gw_adv_period = ntohl(desc_ka->ka_gw_adv_period);
	gwi->gw_ka_period = ntohl(desc_ka->ka_gw_ka_period);
	gwi->gw_vnic_ka_period = ntohl(desc_ka->ka_vnic_ka_period);

	gwi->gw_next = NULL;

	return (ENX_E_SUCCESS);
}

/*
 * Rollback whatever we did for making a solicit packet
 */
static void
eibnx_rb_fip_make_solicit_pkt(eibnx_wqe_t *swqe)
{
	uint8_t *pkt = (uint8_t *)(uintptr_t)(swqe->qe_sgl.ds_va);

	bzero(pkt, sizeof (fip_solicit_t));
	swqe->qe_sgl.ds_len = swqe->qe_bufsz;
}
