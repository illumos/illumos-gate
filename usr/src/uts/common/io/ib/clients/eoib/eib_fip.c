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

#include <sys/ib/clients/eoib/eib_impl.h>

/*
 * Declarations private to this file
 */
static int eib_fip_make_login(eib_t *, eib_vnic_t *, eib_wqe_t *, int *);
static int eib_fip_make_update(eib_t *, eib_vnic_t *, eib_wqe_t *, int, int *);
static int eib_fip_make_table(eib_t *, eib_vnic_t *, eib_wqe_t *, int *);
static int eib_fip_make_ka(eib_t *, eib_vnic_t *, eib_wqe_t *, int *);
static int eib_fip_make_logout(eib_t *, eib_vnic_t *, eib_wqe_t *, int *);

static int eib_fip_send_login(eib_t *, eib_vnic_t *, eib_wqe_t *, int *);
static int eib_fip_send_update(eib_t *, eib_vnic_t *, eib_wqe_t *,
    uint_t, int *);
static int eib_fip_send_table(eib_t *, eib_vnic_t *, eib_wqe_t *, int *);
static int eib_fip_send_ka(eib_t *, eib_vnic_t *, eib_wqe_t *, int *);
static int eib_fip_send_logout(eib_t *, eib_vnic_t *, eib_wqe_t *, int *);

static int eib_fip_parse_vhub_table(uint8_t *, eib_vnic_t *);
static int eib_fip_parse_vhub_update(uint8_t *, eib_vnic_t *);
static void eib_fip_update_eport_state(eib_t *, eib_vhub_table_t *,
    eib_vhub_update_t *, boolean_t, uint8_t);
static void eib_fip_queue_tbl_entry(eib_vhub_table_t *, eib_vhub_map_t *,
    uint32_t, uint8_t);
static void eib_fip_queue_upd_entry(eib_vhub_update_t *, eib_vhub_map_t *,
    uint32_t, uint8_t);
static void eib_fip_queue_gw_entry(eib_vnic_t *, eib_vhub_table_t *, uint32_t,
    uint8_t);
static int eib_fip_apply_updates(eib_t *, eib_vhub_table_t *,
    eib_vhub_update_t *);
static void eib_fip_dequeue_tbl_entry(eib_vhub_table_t *, uint8_t *, uint32_t,
    uint8_t);
static eib_vhub_map_t *eib_fip_get_vhub_map(void);

/*
 * Definitions private to this file
 */
const char eib_vendor_mellanox[] = {
	0x4d, 0x65, 0x6c, 0x6c, 0x61, 0x6e, 0x6f, 0x78
};

/*
 * The three requests to the gateway - request a vHUB table, request a
 * vHUB update (aka keepalive) and vNIC logout - all need the same
 * vnic identity descriptor to be sent with different flag settings.
 *
 *      vHUB table: R=1, U=0, TUSN=last, subcode=KEEPALIVE
 *      keepalive/vHUB update: R=0, U=1, TUSN=last, subcode=KEEPALIVE
 *      vNIC logout: R=0, U=0, TUSN=0, subcode=LOGOUT
 */
#define	EIB_UPD_REQ_TABLE	1
#define	EIB_UPD_REQ_KA		2
#define	EIB_UPD_REQ_LOGOUT	3

int
eib_fip_login(eib_t *ss, eib_vnic_t *vnic, int *err)
{
	eib_wqe_t *swqe;
	int ret;
	int ntries = 0;

	do {
		if ((swqe = eib_rsrc_grab_swqe(ss, EIB_WPRI_LO)) == NULL) {
			EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_login: "
			    "no swqe available, not sending "
			    "vnic login request");
			*err = ENOMEM;
			return (EIB_E_FAILURE);
		}

		ret = eib_fip_make_login(ss, vnic, swqe, err);
		if (ret != EIB_E_SUCCESS) {
			eib_rsrc_return_swqe(ss, swqe, NULL);
			return (EIB_E_FAILURE);
		}

		ret = eib_fip_send_login(ss, vnic, swqe, err);
		if (ret != EIB_E_SUCCESS) {
			eib_rsrc_return_swqe(ss, swqe, NULL);
			return (EIB_E_FAILURE);
		}

		ret = eib_vnic_wait_for_login_ack(ss, vnic, err);
		if (ret == EIB_E_SUCCESS)
			break;

	} while ((*err == ETIME) && (ntries++ < EIB_MAX_LOGIN_ATTEMPTS));

	return (ret);
}

int
eib_fip_vhub_table(eib_t *ss, eib_vnic_t *vnic, int *err)
{
	eib_wqe_t *swqe;
	int ret;
	int ntries = 0;

	do {
		if ((swqe = eib_rsrc_grab_swqe(ss, EIB_WPRI_LO)) == NULL) {
			EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_vhub_table: "
			    "no swqe available, not sending "
			    "vhub table request");
			*err = ENOMEM;
			return (EIB_E_FAILURE);
		}

		ret = eib_fip_make_table(ss, vnic, swqe, err);
		if (ret != EIB_E_SUCCESS) {
			eib_rsrc_return_swqe(ss, swqe, NULL);
			return (EIB_E_FAILURE);
		}

		ret = eib_fip_send_table(ss, vnic, swqe, err);
		if (ret != EIB_E_SUCCESS) {
			eib_rsrc_return_swqe(ss, swqe, NULL);
			return (EIB_E_FAILURE);
		}

		ret = eib_vnic_wait_for_table(ss, vnic, err);
		if (ret == EIB_E_SUCCESS) {
			return (EIB_E_SUCCESS);
		}

		/*
		 * If we'd failed in constructing a proper vhub table above,
		 * the vnic login state would be set to EIB_LOGIN_TBL_FAILED.
		 * We need to clean up any pending entries from the vhub
		 * table and vhub update structures and reset the vnic state
		 * to EIB_LOGIN_ACK_RCVD before we can try again.
		 */
		eib_vnic_fini_tables(ss, vnic, B_FALSE);
		mutex_enter(&vnic->vn_lock);
		vnic->vn_state = EIB_LOGIN_ACK_RCVD;
		mutex_exit(&vnic->vn_lock);

	} while ((*err == ETIME) && (ntries++ < EIB_MAX_VHUB_TBL_ATTEMPTS));

	return (EIB_E_FAILURE);
}

int
eib_fip_heartbeat(eib_t *ss, eib_vnic_t *vnic, int *err)
{
	eib_wqe_t *swqe;
	int ntries = 0;
	int ret;

	/*
	 * Even if we're running low on the wqe resource, we want to be
	 * able to grab a wqe to send the keepalive, to avoid getting
	 * logged out by the gateway, so we use EIB_WPRI_HI.
	 */
	if ((swqe = eib_rsrc_grab_swqe(ss, EIB_WPRI_HI)) == NULL) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_heartbeat: "
		    "no swqe available, not sending heartbeat");
		return (EIB_E_FAILURE);
	}

	while (ntries++ < EIB_MAX_KA_ATTEMPTS) {
		ret = eib_fip_make_ka(ss, vnic, swqe, err);
		if (ret != EIB_E_SUCCESS)
			continue;

		ret = eib_fip_send_ka(ss, vnic, swqe, err);
		if (ret == EIB_E_SUCCESS)
			break;
	}

	if (ret != EIB_E_SUCCESS)
		eib_rsrc_return_swqe(ss, swqe, NULL);

	return (ret);
}

int
eib_fip_logout(eib_t *ss, eib_vnic_t *vnic, int *err)
{
	eib_wqe_t *swqe;
	int ret;

	/*
	 * This routine is only called after the vnic has successfully
	 * logged in to the gateway. If that's really the case, there
	 * is nothing in terms of resources we need to release: the swqe
	 * that was acquired during login has already been posted, the
	 * work has been completed and the swqe has also been reaped back
	 * into the free pool. The only thing we need to rollback is the
	 * fact that we're logged in to the gateway at all -- and the way
	 * to do this is to send a logout request.
	 */
	if ((swqe = eib_rsrc_grab_swqe(ss, EIB_WPRI_LO)) == NULL) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_logout: "
		    "no swqe available, not sending logout");
		return (EIB_E_FAILURE);
	}

	ret = eib_fip_make_logout(ss, vnic, swqe, err);
	if (ret != EIB_E_SUCCESS) {
		eib_rsrc_return_swqe(ss, swqe, NULL);
		return (EIB_E_FAILURE);
	}

	ret = eib_fip_send_logout(ss, vnic, swqe, err);
	if (ret != EIB_E_SUCCESS) {
		eib_rsrc_return_swqe(ss, swqe, NULL);
		return (EIB_E_FAILURE);
	}

	return (EIB_E_SUCCESS);
}

int
eib_fip_parse_login_ack(eib_t *ss, uint8_t *pkt, eib_login_data_t *ld)
{
	fip_login_ack_t *ack;
	fip_basic_hdr_t *hdr;
	fip_desc_iba_t *iba;
	fip_desc_vnic_login_t *login;
	fip_desc_partition_t *partition;
	ib_guid_t guid;
	uint32_t syn_ctl_qpn;
	uint16_t sl_portid;
	uint16_t flags_vlan;
	uint16_t opcode;
	uint8_t subcode;

	/*
	 * Note that 'pkt' is always atleast double-word aligned
	 * when it is passed to us, so we can cast it without any
	 * problems.
	 */
	ack = (fip_login_ack_t *)(void *)pkt;
	hdr = &(ack->ak_fip_header);

	/*
	 * Verify that the opcode is EoIB
	 */
	if ((opcode = ntohs(hdr->hd_opcode)) != FIP_OPCODE_EOIB) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_login_ack: "
		    "unsupported opcode 0x%x in login ack, ignoring",
		    opcode);
		return (EIB_E_FAILURE);
	}

	/*
	 * The admin qp in the EoIB driver should receive only the login
	 * acknowledgements
	 */
	subcode = hdr->hd_subcode;
	if (subcode != FIP_SUBCODE_G_VNIC_LOGIN_ACK) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_login_ack: "
		    "unexpected subcode 0x%x received by adm qp, ignoring",
		    subcode);
		return (EIB_E_FAILURE);
	}

	/*
	 * Verify if the descriptor list length in the received packet is
	 * valid if the workaround to disable it explicitly is absent.
	 */
	if (!eib_wa_no_desc_list_len) {
		uint_t pkt_data_sz;

		pkt_data_sz = (ntohs(hdr->hd_desc_list_len) + 2) << 2;
		if (pkt_data_sz < sizeof (fip_login_ack_t)) {
			EIB_DPRINTF_WARN(ss->ei_instance,
			    "eib_fip_parse_login_ack: "
			    "login ack desc list len (0x%lx) too small "
			    "(min 0x%lx)",
			    pkt_data_sz, sizeof (fip_login_ack_t));
			return (EIB_E_FAILURE);
		}
	}

	/*
	 * Validate all the header and descriptor types and lengths
	 */
	if (hdr->hd_type != FIP_DESC_TYPE_VENDOR_ID ||
	    hdr->hd_len != FIP_DESC_LEN_VENDOR_ID) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_login_ack: "
		    "invalid type/len in basic hdr: expected (0x%x,0x%x), "
		    "got (0x%x,0x%x)", FIP_DESC_TYPE_VENDOR_ID,
		    FIP_DESC_LEN_VENDOR_ID, hdr->hd_type, hdr->hd_len);
		return (EIB_E_FAILURE);
	}
	iba = &(ack->ak_iba);
	if (iba->ia_type != FIP_DESC_TYPE_IBA ||
	    iba->ia_len != FIP_DESC_LEN_IBA) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_login_ack: "
		    "invalid type/len in iba desc: expected (0x%x,0x%x), "
		    "got (0x%x,0x%x)", FIP_DESC_TYPE_IBA, FIP_DESC_LEN_IBA,
		    iba->ia_type, iba->ia_len);
		return (EIB_E_FAILURE);
	}
	login = &(ack->ak_vnic_login);
	if (login->vl_type != FIP_DESC_TYPE_VNIC_LOGIN ||
	    login->vl_len != FIP_DESC_LEN_VNIC_LOGIN) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_login_ack: "
		    "invalid type/len in login desc: expected (0x%x,0x%x), "
		    "got (0x%x,0x%x)", FIP_DESC_TYPE_VNIC_LOGIN,
		    FIP_DESC_LEN_VNIC_LOGIN, login->vl_type, login->vl_len);
		return (EIB_E_FAILURE);
	}
	partition = &(ack->ak_vhub_partition);
	if (partition->pn_type != FIP_DESC_TYPE_PARTITION ||
	    partition->pn_len != FIP_DESC_LEN_PARTITION) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_login_ack: "
		    "invalid type/len in partition desc: expected (0x%x,0x%x), "
		    "got (0x%x,0x%x)", FIP_DESC_TYPE_PARTITION,
		    FIP_DESC_LEN_PARTITION, partition->pn_type,
		    partition->pn_len);
		return (EIB_E_FAILURE);
	}

	/*
	 * Note that we'll return the vnic id as-is.  The msb is not actually
	 * part of the vnic id in our internal records, so we'll mask it out
	 * later before we do our searches.
	 */
	ld->ld_vnic_id = ntohs(login->vl_vnic_id);

	syn_ctl_qpn = ntohl(login->vl_syndrome_ctl_qpn);

	/*
	 * If the syndrome indicates a nack, we're done.  No need to collect
	 * any more information
	 */
	ld->ld_syndrome = (uint8_t)((syn_ctl_qpn & FIP_VL_SYN_MASK) >>
	    FIP_VL_SYN_SHIFT);
	if (ld->ld_syndrome) {
		return (EIB_E_SUCCESS);
	}

	/*
	 * Let's get the rest of the information out of the login ack
	 */
	sl_portid = ntohs(iba->ia_sl_portid);
	ld->ld_gw_port_id = sl_portid & FIP_IBA_PORTID_MASK;
	ld->ld_gw_sl = (sl_portid & FIP_IBA_SL_MASK) >> FIP_IBA_SL_SHIFT;

	ld->ld_gw_data_qpn = ntohl(iba->ia_qpn) & FIP_IBA_QPN_MASK;
	ld->ld_gw_lid = ntohs(iba->ia_lid);

	bcopy(iba->ia_guid, &guid, sizeof (ib_guid_t));
	ld->ld_gw_guid = ntohll(guid);
	ld->ld_vhub_mtu = ntohs(login->vl_mtu);
	bcopy(login->vl_mac, ld->ld_assigned_mac, ETHERADDRL);
	bcopy(login->vl_gw_mgid_prefix, ld->ld_gw_mgid_prefix,
	    FIP_MGID_PREFIX_LEN);
	ld->ld_n_rss_mcgid = login->vl_flags_rss & FIP_VL_N_RSS_MCGID_MASK;
	ld->ld_n_mac_mcgid = login->vl_n_mac_mcgid & FIP_VL_N_MAC_MCGID_MASK;
	ld->ld_gw_ctl_qpn = (syn_ctl_qpn & FIP_VL_CTL_QPN_MASK);

	flags_vlan = ntohs(login->vl_flags_vlan);
	ld->ld_assigned_vlan = flags_vlan & FIP_VL_VLAN_MASK;
	ld->ld_vlan_in_packets = (flags_vlan & FIP_VL_FLAGS_VP) ? 1 : 0;
	bcopy(login->vl_vnic_name, ld->ld_vnic_name, FIP_VNIC_NAME_LEN);

	ld->ld_vhub_pkey = ntohs(partition->pn_pkey);

	return (EIB_E_SUCCESS);
}

int
eib_fip_parse_ctl_pkt(uint8_t *pkt, eib_vnic_t *vnic)
{
	eib_t *ss = vnic->vn_ss;
	fip_vhub_pkt_t *vhb;
	fip_basic_hdr_t *hdr;
	uint16_t opcode;
	uint8_t subcode;
	uint_t vnic_state;
	int ret = EIB_E_FAILURE;

	/*
	 * Note that 'pkt' is always atleast double-word aligned when it is
	 * passed to us, so we can cast it without any problems.
	 */
	vhb = (fip_vhub_pkt_t *)(void *)pkt;
	hdr = &(vhb->hb_fip_header);

	/*
	 * Verify that the opcode is EoIB
	 */
	if ((opcode = ntohs(hdr->hd_opcode)) != FIP_OPCODE_EOIB) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_ctl_pkt: "
		    "unsupported opcode 0x%x in ctl pkt, ignoring",
		    opcode);
		return (EIB_E_FAILURE);
	}

	mutex_enter(&vnic->vn_lock);
	vnic_state = vnic->vn_state;
	mutex_exit(&vnic->vn_lock);

	/*
	 * The ctl qp in the EoIB driver should receive only vHUB messages
	 */
	subcode = hdr->hd_subcode;
	if (subcode == FIP_SUBCODE_G_VHUB_UPDATE) {
		if (vnic_state != EIB_LOGIN_TBL_WAIT &&
		    vnic_state != EIB_LOGIN_TBL_INPROG &&
		    vnic_state != EIB_LOGIN_TBL_DONE &&
		    vnic_state != EIB_LOGIN_DONE) {

			EIB_DPRINTF_WARN(ss->ei_instance,
			    "eib_fip_parse_ctl_pkt: unexpected vnic state "
			    "(0x%lx) for subcode (VHUB_UPDATE 0x%x)",
			    vnic_state, subcode);
			return (EIB_E_FAILURE);
		}

		ret = eib_fip_parse_vhub_update(pkt, vnic);

	} else if (subcode == FIP_SUBCODE_G_VHUB_TABLE) {
		if ((vnic_state != EIB_LOGIN_TBL_WAIT) &&
		    (vnic_state != EIB_LOGIN_TBL_INPROG)) {

			EIB_DPRINTF_WARN(ss->ei_instance,
			    "eib_fip_parse_ctl_pkt: unexpected vnic state "
			    "(0x%lx) for subcode (VHUB_TABLE 0x%x)",
			    vnic_state, subcode);
			return (EIB_E_FAILURE);
		}

		ret = eib_fip_parse_vhub_table(pkt, vnic);

	} else {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_ctl_pkt: "
		    "unexpected subcode 0x%x for ctl pkt", subcode);
	}

	if (ret == EIB_E_SUCCESS) {
		/*
		 * Update last gateway heartbeat received time and
		 * gateway eport state.  The eport state should only
		 * be updated if the vnic's vhub table has been fully
		 * constructed.
		 */
		mutex_enter(&ss->ei_vnic_lock);
		ss->ei_gw_last_heartbeat = ddi_get_lbolt64();
		if (vnic_state == EIB_LOGIN_TBL_DONE ||
		    vnic_state == EIB_LOGIN_DONE) {
			ss->ei_gw_eport_state =
			    vnic->vn_vhub_table->tb_eport_state;
		}
		mutex_exit(&ss->ei_vnic_lock);
	}

	return (ret);
}

static int
eib_fip_make_login(eib_t *ss, eib_vnic_t *vnic, eib_wqe_t *swqe, int *err)
{
	fip_login_t *login;
	fip_proto_t *proto;
	fip_basic_hdr_t *hdr;
	fip_desc_iba_t *iba;
	fip_desc_vnic_login_t *vlg;
	ib_gid_t port_gid;
	ib_guid_t port_guid;
	uint16_t sl_portid;
	uint16_t flags_vlan;

	uint16_t gw_portid = ss->ei_gw_props->pp_gw_portid;
	uint16_t sl = ss->ei_gw_props->pp_gw_sl;
	uint8_t *pkt = (uint8_t *)(uintptr_t)(swqe->qe_sgl.ds_va);
	uint_t pktsz = swqe->qe_sgl.ds_len;
	uint_t login_sz = sizeof (fip_login_t);

	if (pktsz < login_sz) {
		*err = EINVAL;

		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_make_login: "
		    "send buffer size (0x%lx) too small to send"
		    "login request (min 0x%lx)",
		    pktsz, login_sz);
		return (EIB_E_FAILURE);
	}

	/*
	 * Lint complains that there may be an alignment issue here,
	 * but we know that the "pkt" is atleast double-word aligned,
	 * so it's ok.
	 */
	login = (fip_login_t *)(void *)pkt;
	bzero(pkt, login_sz);

	/*
	 * Fill in the FIP protocol version
	 */
	proto = &login->lg_proto_version;
	proto->pr_version = FIP_PROTO_VERSION;

	/*
	 * Fill in the basic header
	 */
	hdr = &login->lg_fip_header;
	hdr->hd_opcode = htons(FIP_OPCODE_EOIB);
	hdr->hd_subcode = FIP_SUBCODE_H_VNIC_LOGIN;
	hdr->hd_desc_list_len = htons((login_sz >> 2) - 2);
	hdr->hd_flags = 0;
	hdr->hd_type = FIP_DESC_TYPE_VENDOR_ID;
	hdr->hd_len = FIP_DESC_LEN_VENDOR_ID;
	bcopy(eib_vendor_mellanox, hdr->hd_vendor_id, FIP_VENDOR_LEN);

	/*
	 * Fill in the Infiniband Address descriptor
	 */
	iba = &login->lg_iba;
	iba->ia_type = FIP_DESC_TYPE_IBA;
	iba->ia_len = FIP_DESC_LEN_IBA;
	bcopy(eib_vendor_mellanox, iba->ia_vendor_id, FIP_VENDOR_LEN);
	iba->ia_qpn = htonl(vnic->vn_data_chan->ch_qpn);

	sl_portid = (gw_portid & FIP_IBA_PORTID_MASK) |
	    ((sl << FIP_IBA_SL_SHIFT) & FIP_IBA_SL_MASK);
	iba->ia_sl_portid = htons(sl_portid);

	iba->ia_lid = htons(ss->ei_props->ep_blid);

	port_gid = ss->ei_props->ep_sgid;
	port_guid = htonll(port_gid.gid_guid);
	bcopy(&port_guid, iba->ia_guid, FIP_GUID_LEN);

	/*
	 * Now, fill in the vNIC Login descriptor
	 */

	vlg = &login->lg_vnic_login;
	vlg->vl_type = FIP_DESC_TYPE_VNIC_LOGIN;
	vlg->vl_len = FIP_DESC_LEN_VNIC_LOGIN;
	bcopy(eib_vendor_mellanox, vlg->vl_vendor_id, FIP_VENDOR_LEN);

	/*
	 * Only for the physlink instance 0, we ask the gateway to assign
	 * the mac address and a VLAN (tagless, actually).  For this vnic
	 * only, we do not set the H bit. All other vnics are created by
	 * Solaris admin and will have the H bit set. Note also that we
	 * need to clear the vnic id's most significant bit for those that
	 * are administered by the gateway, so vnic0's vnic_id's msb should
	 * be 0 as well.
	 */
	if (vnic->vn_instance == 0) {
		vlg->vl_vnic_id = htons(vnic->vn_id);
		flags_vlan = vnic->vn_vlan & FIP_VL_VLAN_MASK;
	} else {
		vlg->vl_vnic_id = htons(vnic->vn_id | FIP_VL_VNIC_ID_MSBIT);
		flags_vlan = (vnic->vn_vlan & FIP_VL_VLAN_MASK) |
		    FIP_VL_FLAGS_H | FIP_VL_FLAGS_M;

		if (vnic->vn_vlan & FIP_VL_VLAN_MASK)
			flags_vlan |= (FIP_VL_FLAGS_V | FIP_VL_FLAGS_VP);
	}

	vlg->vl_flags_vlan = htons(flags_vlan);
	bcopy(vnic->vn_macaddr, vlg->vl_mac, ETHERADDRL);

	/*
	 * We aren't ready to enable rss, so we set the RSS bit and
	 * the n_rss_mcgid field to 0.  Set the mac mcgid to 0 as well.
	 */
	vlg->vl_flags_rss = 0;
	vlg->vl_n_mac_mcgid = 0;

	/*
	 * Set the syndrome to 0 and pass the control qpn
	 */
	vlg->vl_syndrome_ctl_qpn =
	    htonl(vnic->vn_ctl_chan->ch_qpn & FIP_VL_CTL_QPN_MASK);

	/*
	 * Try to set as unique a name as possible for this vnic
	 */
	(void) snprintf((char *)(vlg->vl_vnic_name), FIP_VNIC_NAME_LEN,
	    "eoib_%02x_%02x", ss->ei_instance, vnic->vn_instance);

	/*
	 * Adjust the ds_len in the sgl to indicate the size of this
	 * request before returning
	 */
	swqe->qe_sgl.ds_len = login_sz;

	return (EIB_E_SUCCESS);
}

static int
eib_fip_make_update(eib_t *ss, eib_vnic_t *vnic, eib_wqe_t *swqe, int req,
    int *err)
{
	fip_keep_alive_t *ka;
	fip_proto_t *proto;
	fip_basic_hdr_t *hdr;
	fip_desc_vnic_identity_t *vid;
	ib_gid_t port_gid;
	ib_guid_t port_guid;
	uint32_t flags_vhub_id;

	uint8_t *pkt = (uint8_t *)(uintptr_t)(swqe->qe_sgl.ds_va);
	uint_t pktsz = swqe->qe_sgl.ds_len;
	uint_t ka_sz = sizeof (fip_keep_alive_t);

	if (pktsz < ka_sz) {
		*err = EINVAL;

		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_make_update: "
		    "send buffer size (0x%lx) too small to send"
		    "keepalive/update request (min 0x%lx)",
		    pktsz, ka_sz);
		return (EIB_E_FAILURE);
	}

	/*
	 * Lint complains that there may be an alignment issue here,
	 * but we know that the "pkt" is atleast double-word aligned,
	 * so it's ok.
	 */
	ka = (fip_keep_alive_t *)(void *)pkt;
	bzero(pkt, ka_sz);

	/*
	 * Fill in the FIP protocol version
	 */
	proto = &ka->ka_proto_version;
	proto->pr_version = FIP_PROTO_VERSION;

	/*
	 * Fill in the basic header
	 */
	hdr = &ka->ka_fip_header;
	hdr->hd_opcode = htons(FIP_OPCODE_EOIB);
	hdr->hd_subcode = (req == EIB_UPD_REQ_LOGOUT) ?
	    FIP_SUBCODE_H_VNIC_LOGOUT : FIP_SUBCODE_H_KEEP_ALIVE;
	hdr->hd_desc_list_len = htons((ka_sz >> 2) - 2);
	hdr->hd_flags = 0;
	hdr->hd_type = FIP_DESC_TYPE_VENDOR_ID;
	hdr->hd_len = FIP_DESC_LEN_VENDOR_ID;
	bcopy(eib_vendor_mellanox, hdr->hd_vendor_id, FIP_VENDOR_LEN);

	/*
	 * Fill in the vNIC Identity descriptor
	 */
	vid = &ka->ka_vnic_identity;

	vid->vi_type = FIP_DESC_TYPE_VNIC_IDENTITY;
	vid->vi_len = FIP_DESC_LEN_VNIC_IDENTITY;
	bcopy(eib_vendor_mellanox, vid->vi_vendor_id, FIP_VENDOR_LEN);

	flags_vhub_id = vnic->vn_login_data.ld_vhub_id;
	if (vnic->vn_login_data.ld_vlan_in_packets) {
		flags_vhub_id |= FIP_VI_FLAG_VP;
	}
	if (req == EIB_UPD_REQ_TABLE) {
		flags_vhub_id |= FIP_VI_FLAG_R;
	} else if (req == EIB_UPD_REQ_KA) {
		flags_vhub_id |= FIP_VI_FLAG_U;
	}
	vid->vi_flags_vhub_id = htonl(flags_vhub_id);

	vid->vi_tusn = (req != EIB_UPD_REQ_LOGOUT) ?
	    htonl(vnic->vn_vhub_table->tb_tusn) : 0;

	vid->vi_vnic_id = htons(vnic->vn_login_data.ld_vnic_id);
	bcopy(vnic->vn_login_data.ld_assigned_mac, vid->vi_mac, ETHERADDRL);

	port_gid = ss->ei_props->ep_sgid;
	port_guid = htonll(port_gid.gid_guid);
	bcopy(&port_guid, vid->vi_port_guid, FIP_GUID_LEN);
	bcopy(vnic->vn_login_data.ld_vnic_name, vid->vi_vnic_name,
	    FIP_VNIC_NAME_LEN);

	/*
	 * Adjust the ds_len in the sgl to indicate the size of this
	 * request before returning
	 */
	swqe->qe_sgl.ds_len = ka_sz;

	return (EIB_E_SUCCESS);
}

static int
eib_fip_make_table(eib_t *ss, eib_vnic_t *vnic, eib_wqe_t *swqe, int *err)
{
	return (eib_fip_make_update(ss, vnic, swqe, EIB_UPD_REQ_TABLE, err));
}

static int
eib_fip_make_ka(eib_t *ss, eib_vnic_t *vnic, eib_wqe_t *swqe, int *err)
{
	return (eib_fip_make_update(ss, vnic, swqe, EIB_UPD_REQ_KA, err));
}

static int
eib_fip_make_logout(eib_t *ss, eib_vnic_t *vnic, eib_wqe_t *swqe, int *err)
{
	return (eib_fip_make_update(ss, vnic, swqe, EIB_UPD_REQ_LOGOUT, err));
}

static int
eib_fip_send_login(eib_t *ss, eib_vnic_t *vnic, eib_wqe_t *swqe, int *err)
{
	eib_avect_t *av;
	eib_chan_t *chan = ss->ei_admin_chan;
	ibt_status_t ret;

	/*
	 * Get an address vector for this destination
	 */
	if ((av = eib_ibt_hold_avect(ss, ss->ei_gw_props->pp_gw_lid,
	    ss->ei_gw_props->pp_gw_sl)) == NULL) {
		*err = ENOMEM;
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_send_login: "
		    "eib_ibt_hold_avect(gw_lid=0x%x, sl=0x%x) failed",
		    ss->ei_gw_props->pp_gw_lid, ss->ei_gw_props->pp_gw_sl);
		return (EIB_E_FAILURE);
	}

	/*
	 * Modify the UD destination handle to the gateway
	 */
	ret = ibt_modify_ud_dest(swqe->qe_dest, EIB_FIP_QKEY,
	    ss->ei_gw_props->pp_gw_ctrl_qpn, &av->av_vect);

	eib_ibt_release_avect(ss, av);
	if (ret != IBT_SUCCESS) {
		*err = EINVAL;

		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_send_login: "
		    "ibt_modify_ud_dest(gw_ctl_qpn=0x%lx, qkey=0x%lx) failed, "
		    "ret=%d", ss->ei_gw_props->pp_gw_ctrl_qpn,
		    EIB_FIP_QKEY, ret);
		return (EIB_E_FAILURE);
	}

	/*
	 * Send the login packet to the destination gateway. Posting
	 * the login and setting the login state to wait-for-ack should
	 * ideally be atomic to avoid race.
	 */
	mutex_enter(&vnic->vn_lock);
	ret = ibt_post_send(chan->ch_chan, &(swqe->qe_wr.send), 1, NULL);
	if (ret != IBT_SUCCESS) {
		mutex_exit(&vnic->vn_lock);
		*err = EINVAL;
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_send_login: "
		    "ibt_post_send() failed for vnic id 0x%x, ret=%d",
		    vnic->vn_id, ret);
		return (EIB_E_FAILURE);
	}
	vnic->vn_state = EIB_LOGIN_ACK_WAIT;

	mutex_enter(&chan->ch_tx_lock);
	chan->ch_tx_posted++;
	mutex_exit(&chan->ch_tx_lock);

	mutex_exit(&vnic->vn_lock);

	return (EIB_E_SUCCESS);
}

static int
eib_fip_send_update(eib_t *ss, eib_vnic_t *vnic, eib_wqe_t *swqe,
    uint_t nxt_state, int *err)
{
	eib_login_data_t *ld = &vnic->vn_login_data;
	eib_chan_t *chan = vnic->vn_ctl_chan;
	eib_avect_t *av;
	ibt_status_t ret;

	/*
	 * Get an address vector for this destination
	 */
	if ((av = eib_ibt_hold_avect(ss, ld->ld_gw_lid,
	    ld->ld_gw_sl)) == NULL) {
		*err = ENOMEM;
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_send_update: "
		    "eib_ibt_hold_avect(gw_lid=0x%x, sl=0x%x) failed",
		    ld->ld_gw_lid, ld->ld_gw_sl);
		return (EIB_E_FAILURE);
	}

	/*
	 * Modify the UD destination handle to the destination appropriately
	 */
	ret = ibt_modify_ud_dest(swqe->qe_dest, EIB_FIP_QKEY,
	    ld->ld_gw_ctl_qpn, &av->av_vect);

	eib_ibt_release_avect(ss, av);
	if (ret != IBT_SUCCESS) {
		*err = EINVAL;
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_send_update: "
		    "ibt_modify_ud_dest(gw_ctl_qpn=0x%lx, qkey=0x%lx) failed, "
		    "ret=%d", ld->ld_gw_ctl_qpn, EIB_FIP_QKEY, ret);
		return (EIB_E_FAILURE);
	}

	/*
	 * Send the update packet to the destination. Posting the update request
	 * and setting the login state to wait-for-vhub_table needs to be atomic
	 * to avoid race.
	 */
	mutex_enter(&vnic->vn_lock);
	ret = ibt_post_send(chan->ch_chan, &(swqe->qe_wr.send), 1, NULL);
	if (ret != IBT_SUCCESS) {
		mutex_exit(&vnic->vn_lock);
		*err = EINVAL;
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_send_update: "
		    "ibt_post_send() failed for vnic id 0x%x, ret=%d",
		    vnic->vn_id, ret);
		return (EIB_E_FAILURE);
	}
	vnic->vn_state = nxt_state;

	mutex_enter(&chan->ch_tx_lock);
	chan->ch_tx_posted++;
	mutex_exit(&chan->ch_tx_lock);

	mutex_exit(&vnic->vn_lock);

	return (EIB_E_SUCCESS);
}

static int
eib_fip_send_table(eib_t *ss, eib_vnic_t *vnic, eib_wqe_t *swqe, int *err)
{
	return (eib_fip_send_update(ss, vnic, swqe, EIB_LOGIN_TBL_WAIT, err));
}

static int
eib_fip_send_ka(eib_t *ss, eib_vnic_t *vnic, eib_wqe_t *swqe, int *err)
{
	return (eib_fip_send_update(ss, vnic, swqe, EIB_LOGIN_DONE, err));
}

static int
eib_fip_send_logout(eib_t *ss, eib_vnic_t *vnic, eib_wqe_t *swqe, int *err)
{
	return (eib_fip_send_update(ss, vnic, swqe, EIB_LOGOUT_DONE, err));
}

static int
eib_fip_parse_vhub_table(uint8_t *pkt, eib_vnic_t *vnic)
{
	fip_vhub_table_t *tbl;
	fip_desc_vhub_table_t *desc_tbl;
	fip_vhub_table_entry_t *entry;
	fip_basic_hdr_t *hdr;
	eib_t *ss = vnic->vn_ss;
	eib_login_data_t *ld = &vnic->vn_login_data;
	eib_vhub_table_t *etbl = vnic->vn_vhub_table;
	eib_vhub_update_t *eupd = vnic->vn_vhub_update;
	eib_vhub_map_t *newmap;

	uint32_t *ipkt;
	uint32_t init_checksum = 0;
	uint32_t tusn;
	uint32_t vhub_id;
	uint_t entries_in_pkt;
	uint_t ndx;
	uint_t i;

	/*
	 * If we're here receiving vhub table messages, we certainly should
	 * have the vhub table structure allocated and present at this point.
	 */
	if (etbl == NULL) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_vhub_table: "
		    "vhub table missing for vnic id 0x%x", vnic->vn_id);
		return (EIB_E_FAILURE);
	}

	/*
	 * Note that 'pkt' is always atleast double-word aligned when it is
	 * passed to us, so we can cast it without any problems.
	 */
	ipkt = (uint32_t *)(void *)pkt;
	tbl = (fip_vhub_table_t *)(void *)pkt;
	hdr = &(tbl->vt_fip_header);

	/*
	 * Validate all the header and descriptor types and lengths
	 */
	if (hdr->hd_type != FIP_DESC_TYPE_VENDOR_ID ||
	    hdr->hd_len != FIP_DESC_LEN_VENDOR_ID) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_vhub_table: "
		    "invalid type/len in fip basic header, "
		    "exp (0x%x,0x%x), got (0x%x,0x%x)",
		    FIP_DESC_TYPE_VENDOR_ID, FIP_DESC_LEN_VENDOR_ID,
		    hdr->hd_type, hdr->hd_len);
		return (EIB_E_FAILURE);
	}
	desc_tbl = &(tbl->vt_vhub_table);
	if (desc_tbl->tb_type != FIP_DESC_TYPE_VHUB_TABLE) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_vhub_table: "
		    "invalid type in vhub desc, exp 0x%x, got 0x%x",
		    FIP_DESC_TYPE_VHUB_TABLE, desc_tbl->tb_type);
		return (EIB_E_FAILURE);
	}

	/*
	 * Verify that the vhub id is ok for this vnic
	 */
	vhub_id = ntohl(desc_tbl->tb_flags_vhub_id) & FIP_TB_VHUB_ID_MASK;
	if (vhub_id != ld->ld_vhub_id) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_vhub_table: "
		    "invalid vhub id in vhub table pkt: exp 0x%x, got 0x%x",
		    ld->ld_vhub_id, vhub_id);
		return (EIB_E_FAILURE);
	}

	/*
	 * Count the number of vhub table entries in this packet
	 */
	entries_in_pkt = (desc_tbl->tb_len - FIP_DESC_VHUB_TABLE_WORDS) /
	    FIP_VHUB_TABLE_ENTRY_WORDS;

	/*
	 * While we're here, also compute the 32-bit 2's complement carry-
	 * discarded checksum of the vHUB table descriptor in this packet
	 * till the first vhub table entry.
	 */
	for (i = 0; i < FIP_DESC_VHUB_TABLE_WORDS; i++)
		init_checksum += ipkt[i];

	/*
	 * Initialize the vhub's Table Update Sequence Number (tusn),
	 * checksum and record the total number of entries in in the table
	 * if this is the first pkt of the table.
	 */
	tusn = ntohl(desc_tbl->tb_tusn);
	if (desc_tbl->tb_hdr & FIP_TB_HDR_FIRST) {
		etbl->tb_entries_in_table = ntohs(desc_tbl->tb_table_size);
		etbl->tb_tusn = tusn;
		etbl->tb_checksum = 0;

		mutex_enter(&vnic->vn_lock);
		vnic->vn_state = EIB_LOGIN_TBL_INPROG;
		mutex_exit(&vnic->vn_lock);
	}

	/*
	 * First, middle or last, the current table TUSN we have must match this
	 * packet's TUSN.
	 */
	if (etbl->tb_tusn != tusn) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_vhub_table: "
		    "unexpected TUSN (0x%lx) during vhub table construction, "
		    "expected 0x%lx", etbl->tb_tusn, tusn);
		goto vhub_table_fail;
	}

	/*
	 * See if we've overrun/underrun our original entries count
	 */
	if ((etbl->tb_entries_seen + entries_in_pkt) >
	    etbl->tb_entries_in_table) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_vhub_table: "
		    "vhub table overrun, total_exp=%d, so_far=%d, this_pkt=%d",
		    etbl->tb_entries_in_table, etbl->tb_entries_seen,
		    entries_in_pkt);
		goto vhub_table_fail;
	} else if (((etbl->tb_entries_seen + entries_in_pkt) <
	    etbl->tb_entries_in_table) &&
	    (desc_tbl->tb_hdr & FIP_TB_HDR_LAST)) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_vhub_table: "
		    "vhub table underrun, total_exp=%d, so_far=%d, last_pkt=%d",
		    etbl->tb_entries_in_table, etbl->tb_entries_seen,
		    entries_in_pkt);
		goto vhub_table_fail;
	}

	/*
	 * Process and add the entries we have in this packet
	 */
	etbl->tb_checksum += init_checksum;
	entry = (fip_vhub_table_entry_t *)(void *)
	    ((uint8_t *)desc_tbl + FIP_DESC_VHUB_TABLE_SZ);

	for (ndx = 0; ndx < entries_in_pkt; ndx++, entry++) {
		/*
		 * Allocate a eib_vhub_map_t, copy the current entry details
		 * and chain it to the appropriate queue.
		 */
		if ((newmap = eib_fip_get_vhub_map()) == NULL) {
			EIB_DPRINTF_WARN(ss->ei_instance,
			    "eib_fip_parse_vhub_table: no memory for vhub "
			    "table entry, ignoring this vhub table packet");
			goto vhub_table_fail;
		}

		ASSERT((entry->te_v_rss_type & FIP_TE_VALID) == FIP_TE_VALID);
		newmap->mp_v_rss_type = entry->te_v_rss_type;
		bcopy(entry->te_mac, newmap->mp_mac, ETHERADDRL);
		newmap->mp_qpn = (ntohl(entry->te_qpn) & FIP_TE_QPN_MASK);
		newmap->mp_sl = (entry->te_sl & FIP_TE_SL_MASK);
		newmap->mp_lid = ntohs(entry->te_lid);
		newmap->mp_tusn = tusn;
		newmap->mp_next = NULL;

		/*
		 * The vhub table messages do not provide status on eport
		 * state, so we'll simply assume that the eport is up.
		 */
		eib_fip_queue_tbl_entry(etbl, newmap, tusn, FIP_EPORT_UP);

		/*
		 * Update table checksum with this entry's computed checksum
		 */
		ipkt = (uint32_t *)entry;
		for (i = 0; i < FIP_VHUB_TABLE_ENTRY_WORDS; i++)
			etbl->tb_checksum += ipkt[i];
	}
	etbl->tb_entries_seen += entries_in_pkt;

	/*
	 * If this is the last packet of this vhub table, complete vhub
	 * table by verifying checksum and applying all the vhub updates
	 * that may have come in while we were constructing this table.
	 */
	if (desc_tbl->tb_hdr & FIP_TB_HDR_LAST) {

		ipkt = (uint32_t *)entry;
		if (!eib_wa_no_good_vhub_cksum) {
			if (*ipkt != etbl->tb_checksum) {
				EIB_DPRINTF_VERBOSE(ss->ei_instance,
				    "eib_fip_parse_vhub_table: "
				    "vhub table checksum invalid, "
				    "computed=0x%lx, found=0x%lx",
				    etbl->tb_checksum, *ipkt);
			}
		}

		/*
		 * Per the EoIB specification, the gateway is supposed to
		 * include its address information for data messages in the
		 * vhub table.  But we've observed that it doesn't do this
		 * (with the current version). If this is the case, we'll
		 * hand-create and add a vhub map for the gateway from the
		 * information we got in login ack.
		 */
		if (etbl->tb_gateway == NULL)
			eib_fip_queue_gw_entry(vnic, etbl, tusn, FIP_EPORT_UP);

		/*
		 * Apply pending vhub updates and reset table counters needed
		 * during table construction.
		 */
		if (eib_fip_apply_updates(ss, etbl, eupd) != EIB_E_SUCCESS)
			goto vhub_table_fail;

		etbl->tb_entries_seen = 0;
		etbl->tb_entries_in_table = 0;

		eib_vnic_vhub_table_done(vnic, EIB_LOGIN_TBL_DONE);
	}

	return (EIB_E_SUCCESS);

vhub_table_fail:
	eib_vnic_vhub_table_done(vnic, EIB_LOGIN_TBL_FAILED);
	return (EIB_E_FAILURE);
}

static int
eib_fip_parse_vhub_update(uint8_t *pkt, eib_vnic_t *vnic)
{
	fip_vhub_update_t *upd;
	fip_desc_vhub_update_t *desc_upd;
	fip_vhub_table_entry_t *entry;
	fip_basic_hdr_t *hdr;
	eib_t *ss = vnic->vn_ss;
	eib_login_data_t *ld = &vnic->vn_login_data;
	eib_vhub_table_t *etbl = vnic->vn_vhub_table;
	eib_vhub_update_t *eupd = vnic->vn_vhub_update;
	eib_vhub_map_t *newmap;
	boolean_t vhub_tbl_done;
	uint32_t eport_vp_vhub_id;
	uint32_t vhub_id;
	uint32_t tusn;
	uint32_t prev_tusn;
	uint8_t eport_state;

	/*
	 * We should have the vhub table allocated as long as we're receiving
	 * vhub control messages.
	 */
	if (etbl == NULL) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_vhub_update: "
		    "vhub table missing for vnic id 0x%x", vnic->vn_id);
		return (EIB_E_FAILURE);
	}

	mutex_enter(&vnic->vn_lock);
	vhub_tbl_done = ((vnic->vn_state == EIB_LOGIN_TBL_DONE) ||
	    (vnic->vn_state == EIB_LOGIN_DONE)) ? B_TRUE : B_FALSE;
	mutex_exit(&vnic->vn_lock);

	/*
	 * Note that 'pkt' is always atleast double-word aligned when it is
	 * passed to us, so we can cast it without any problems.
	 */
	upd = (fip_vhub_update_t *)(void *)pkt;
	hdr = &(upd->vu_fip_header);

	/*
	 * Validate all the header and descriptor types and lengths
	 */
	if (hdr->hd_type != FIP_DESC_TYPE_VENDOR_ID ||
	    hdr->hd_len != FIP_DESC_LEN_VENDOR_ID) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_vhub_update: "
		    "invalid type/len in fip basic header, "
		    "exp (0x%x,0x%x), got (0x%x,0x%x)",
		    FIP_DESC_TYPE_VENDOR_ID, FIP_DESC_LEN_VENDOR_ID,
		    hdr->hd_type, hdr->hd_len);
		return (EIB_E_FAILURE);
	}
	desc_upd = &(upd->vu_vhub_update);
	if (desc_upd->up_type != FIP_DESC_TYPE_VHUB_UPDATE ||
	    desc_upd->up_len != FIP_DESC_LEN_VHUB_UPDATE) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_vhub_update: "
		    "invalid type/len in vhub update desc: "
		    "exp (0x%x,0x%x), got (0x%x,0x%x)",
		    FIP_DESC_TYPE_VHUB_UPDATE, FIP_DESC_LEN_VHUB_UPDATE,
		    desc_upd->up_type, desc_upd->up_len);
		return (EIB_E_FAILURE);
	}

	/*
	 * Verify that the vhub id is ok for this vnic and save the eport state
	 */
	eport_vp_vhub_id = ntohl(desc_upd->up_eport_vp_vhub_id);

	vhub_id = eport_vp_vhub_id & FIP_UP_VHUB_ID_MASK;
	if (vhub_id != ld->ld_vhub_id) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_vhub_update: "
		    "invalid vhub id in vhub update pkt: exp 0x%x, got 0x%x",
		    ld->ld_vhub_id, vhub_id);
		return (EIB_E_FAILURE);
	}
	eport_state = (uint8_t)((eport_vp_vhub_id >> FIP_UP_EPORT_STATE_SHIFT) &
	    FIP_UP_EPORT_STATE_MASK);

	/*
	 * If this is the first update we receive, any tusn is ok.  Otherwise,
	 * make sure the tusn we see in the packet is appropriate.
	 */
	tusn = ntohl(desc_upd->up_tusn);
	prev_tusn = vhub_tbl_done ? etbl->tb_tusn : eupd->up_tusn;

	if (prev_tusn != 0) {
		if (tusn == prev_tusn) {
			eib_fip_update_eport_state(ss, etbl, eupd,
			    vhub_tbl_done, eport_state);
			return (EIB_E_SUCCESS);
		}
		if (tusn != (prev_tusn + 1)) {
			EIB_DPRINTF_WARN(ss->ei_instance,
			    "eib_fip_parse_vhub_update: "
			    "out of order TUSN received (exp 0x%lx, "
			    "got 0x%lx), dropping pkt", prev_tusn + 1, tusn);
			return (EIB_E_FAILURE);
		}
	}

	/*
	 * EoIB expects only type 0 (vnic address) entries to maintain the
	 * context table
	 */
	entry = &(desc_upd->up_tbl_entry);
	ASSERT((entry->te_v_rss_type & FIP_TE_TYPE_MASK) == FIP_TE_TYPE_VNIC);

	/*
	 * If the vHUB table has already been fully constructed and if we've
	 * now received a notice to remove a vnic entry from it, do it.
	 */
	if ((vhub_tbl_done) &&
	    ((entry->te_v_rss_type & FIP_TE_VALID) == 0)) {
		eib_fip_dequeue_tbl_entry(etbl, entry->te_mac,
		    tusn, eport_state);

		if (bcmp(entry->te_mac, ld->ld_assigned_mac, ETHERADDRL) == 0) {
			uint8_t *mymac;

			mymac = entry->te_mac;
			EIB_DPRINTF_WARN(ss->ei_instance,
			    "eib_fip_parse_vhub_update: "
			    "vhub update pkt received to kill self "
			    "(%x:%x:%x:%x:%x:%x)", mymac[0], mymac[1], mymac[2],
			    mymac[3], mymac[4], mymac[5]);

			return (EIB_E_FAILURE);
		}
		return (EIB_E_SUCCESS);
	}

	/*
	 * Otherwise, allocate a new eib_vhub_map_t and fill it in with
	 * the details of the new entry
	 */
	if ((newmap = eib_fip_get_vhub_map()) == NULL) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_parse_vhub_update: "
		    "no memory for vhub update entry, will be ignoring"
		    "this vhub update packet");
		return (EIB_E_FAILURE);
	}

	newmap->mp_v_rss_type = entry->te_v_rss_type;
	bcopy(entry->te_mac, newmap->mp_mac, ETHERADDRL);
	newmap->mp_qpn = (ntohl(entry->te_qpn) & FIP_TE_QPN_MASK);
	newmap->mp_sl = (entry->te_sl & FIP_TE_SL_MASK);
	newmap->mp_lid = ntohs(entry->te_lid);
	newmap->mp_tusn = tusn;
	newmap->mp_next = NULL;

	/*
	 * Update the full vhub table or chain it to the list of pending
	 * updates depending on if the vhub table construction is over
	 * or not.
	 */
	if (vhub_tbl_done) {
		eib_fip_queue_tbl_entry(etbl, newmap, tusn, eport_state);
	} else {
		eib_fip_queue_upd_entry(eupd, newmap, tusn, eport_state);
	}

	return (EIB_E_SUCCESS);
}

static void
eib_fip_update_eport_state(eib_t *ss, eib_vhub_table_t *tbl,
    eib_vhub_update_t *upd, boolean_t tbl_done, uint8_t eport_state)
{
	if (tbl_done) {
		mutex_enter(&tbl->tb_lock);
		if (tbl->tb_eport_state != eport_state) {
			EIB_DPRINTF_DEBUG(ss->ei_instance,
			    "eib_fip_update_eport_state: "
			    "eport state changing from %d to %d",
			    tbl->tb_eport_state, eport_state);
			tbl->tb_eport_state = eport_state;
		}
		mutex_exit(&tbl->tb_lock);
	} else {
		mutex_enter(&upd->up_lock);
		if (upd->up_eport_state != eport_state) {
			EIB_DPRINTF_DEBUG(ss->ei_instance,
			    "eib_fip_update_eport_state: "
			    "eport state changing from %d to %d",
			    upd->up_eport_state, eport_state);
			upd->up_eport_state = eport_state;
		}
		mutex_exit(&upd->up_lock);
	}
}

static void
eib_fip_queue_tbl_entry(eib_vhub_table_t *tbl, eib_vhub_map_t *map,
    uint32_t tusn, uint8_t eport_state)
{
	uint8_t bkt;

	mutex_enter(&tbl->tb_lock);

	switch (map->mp_v_rss_type & FIP_TE_TYPE_MASK) {
	case FIP_TE_TYPE_GATEWAY:
		if (tbl->tb_gateway) {
			kmem_free(tbl->tb_gateway,
			    sizeof (eib_vhub_map_t));
		}
		tbl->tb_gateway = map;
		break;

	case FIP_TE_TYPE_UNICAST_MISS:
		if (tbl->tb_unicast_miss) {
			kmem_free(tbl->tb_unicast_miss,
			    sizeof (eib_vhub_map_t));
		}
		tbl->tb_unicast_miss = map;
		break;

	case FIP_TE_TYPE_VHUB_MULTICAST:
		if (tbl->tb_vhub_multicast) {
			kmem_free(tbl->tb_vhub_multicast,
			    sizeof (eib_vhub_map_t));
		}
		tbl->tb_vhub_multicast = map;
		break;

	case FIP_TE_TYPE_MULTICAST_ENTRY:
		/*
		 * If multicast entry types are not to be specially
		 * processed, treat them like regular vnic addresses.
		 */
		if (!eib_wa_no_mcast_entries) {
			bkt = (map->mp_mac[ETHERADDRL-1]) % EIB_TB_NBUCKETS;
			map->mp_next = tbl->tb_mcast_entry[bkt];
			tbl->tb_mcast_entry[bkt] = map;
			break;
		}
		/*FALLTHROUGH*/

	case FIP_TE_TYPE_VNIC:
		bkt = (map->mp_mac[ETHERADDRL-1]) % EIB_TB_NBUCKETS;
		map->mp_next = tbl->tb_vnic_entry[bkt];
		tbl->tb_vnic_entry[bkt] = map;
		break;
	}

	tbl->tb_tusn = tusn;
	tbl->tb_eport_state = eport_state;

	mutex_exit(&tbl->tb_lock);
}

static void
eib_fip_queue_upd_entry(eib_vhub_update_t *upd, eib_vhub_map_t *map,
    uint32_t tusn, uint8_t eport_state)
{
	eib_vhub_map_t *tail;

	/*
	 * The eib_vhub_update_t list is only touched/traversed when the
	 * control cq handler is parsing either update or table message,
	 * or by the table cleanup routine when we aren't attached to any
	 * control mcgs.  Bottom line is that this list traversal is always
	 * single-threaded and we could probably do away with the lock.
	 */
	mutex_enter(&upd->up_lock);
	for (tail = upd->up_vnic_entry;  tail != NULL; tail = tail->mp_next) {
		if (tail->mp_next == NULL)
			break;
	}
	if (tail) {
		tail->mp_next = map;
	} else {
		upd->up_vnic_entry = map;
	}

	upd->up_tusn = tusn;
	upd->up_eport_state = eport_state;

	mutex_exit(&upd->up_lock);
}

static void
eib_fip_queue_gw_entry(eib_vnic_t *vnic, eib_vhub_table_t *tbl, uint32_t tusn,
    uint8_t eport_state)
{
	eib_t *ss = vnic->vn_ss;
	eib_vhub_map_t *newmap;
	eib_login_data_t *ld = &vnic->vn_login_data;

	if ((newmap = eib_fip_get_vhub_map()) == NULL) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_queue_gw_entry: "
		    "no memory to queue gw entry, transactions could fail");
		return;
	}

	newmap->mp_v_rss_type = FIP_TE_VALID | FIP_TE_TYPE_GATEWAY;
	bcopy(eib_zero_mac, newmap->mp_mac, ETHERADDRL);
	newmap->mp_qpn = ld->ld_gw_data_qpn;
	newmap->mp_sl = ld->ld_gw_sl;
	newmap->mp_lid = ld->ld_gw_lid;
	newmap->mp_tusn = tusn;
	newmap->mp_next = NULL;

	eib_fip_queue_tbl_entry(tbl, newmap, tusn, eport_state);
}

static int
eib_fip_apply_updates(eib_t *ss, eib_vhub_table_t *tbl, eib_vhub_update_t *upd)
{
	eib_vhub_map_t *list;
	eib_vhub_map_t *map;
	eib_vhub_map_t *nxt;
	uint32_t tbl_tusn = tbl->tb_tusn;

	/*
	 * Take the update list out
	 */
	mutex_enter(&upd->up_lock);
	list = upd->up_vnic_entry;
	upd->up_vnic_entry = NULL;
	mutex_exit(&upd->up_lock);

	/*
	 * Skip any updates with older/same tusn as our vhub table
	 */
	nxt = NULL;
	for (map = list; (map) && (map->mp_tusn <= tbl_tusn); map = nxt) {
		nxt = map->mp_next;
		kmem_free(map, sizeof (eib_vhub_map_t));
	}

	if (map == NULL)
		return (EIB_E_SUCCESS);

	/*
	 * If we missed any updates between table tusn and the first
	 * update tusn we got, we need to fail.
	 */
	if (map->mp_tusn > (tbl_tusn + 1)) {
		EIB_DPRINTF_WARN(ss->ei_instance, "eib_fip_apply_updates: "
		    "vhub update missed tusn(s), expected=0x%lx, got=0x%lx",
		    (tbl_tusn + 1), map->mp_tusn);
		for (; map != NULL; map = nxt) {
			nxt = map->mp_next;
			kmem_free(map, sizeof (eib_vhub_map_t));
		}
		return (EIB_E_FAILURE);
	}

	/*
	 * If everything is fine, apply all the updates we received
	 */
	for (; map != NULL; map = nxt) {
		nxt = map->mp_next;
		map->mp_next = NULL;

		if (map->mp_v_rss_type & FIP_TE_VALID) {
			eib_fip_queue_tbl_entry(tbl, map, upd->up_tusn,
			    upd->up_eport_state);
		} else {
			eib_fip_dequeue_tbl_entry(tbl, map->mp_mac,
			    upd->up_tusn, upd->up_eport_state);
			kmem_free(map, sizeof (eib_vhub_map_t));
		}
	}

	return (EIB_E_SUCCESS);
}

static void
eib_fip_dequeue_tbl_entry(eib_vhub_table_t *tbl, uint8_t *mac, uint32_t tusn,
    uint8_t eport_state)
{
	uint8_t bkt;
	eib_vhub_map_t *prev;
	eib_vhub_map_t *elem;

	bkt = (mac[ETHERADDRL-1]) % EIB_TB_NBUCKETS;

	mutex_enter(&tbl->tb_lock);

	/*
	 * Note that for EoIB, the vhub table is maintained using only
	 * vnic entry updates
	 */
	prev = NULL;
	for (elem = tbl->tb_vnic_entry[bkt]; elem; elem = elem->mp_next) {
		if (bcmp(elem->mp_mac, mac, ETHERADDRL) == 0)
			break;
		prev = elem;
	}

	if (prev && elem) {
		prev->mp_next = elem->mp_next;
		kmem_free(elem, sizeof (eib_vhub_map_t));
	}

	tbl->tb_tusn = tusn;
	tbl->tb_eport_state = eport_state;

	mutex_exit(&tbl->tb_lock);
}

static eib_vhub_map_t *
eib_fip_get_vhub_map(void)
{
	return (kmem_zalloc(sizeof (eib_vhub_map_t), KM_NOSLEEP));
}
