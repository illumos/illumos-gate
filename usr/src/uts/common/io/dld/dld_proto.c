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
 * Copyright 2012, Nexenta Systems, Inc. All rights reserved.
 */

/*
 * Data-Link Driver
 */
#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/vlan.h>
#include <sys/dld_impl.h>
#include <sys/mac_client.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_client_priv.h>

typedef void proto_reqfunc_t(dld_str_t *, mblk_t *);

static proto_reqfunc_t proto_info_req, proto_attach_req, proto_detach_req,
    proto_bind_req, proto_unbind_req, proto_promiscon_req, proto_promiscoff_req,
    proto_enabmulti_req, proto_disabmulti_req, proto_physaddr_req,
    proto_setphysaddr_req, proto_udqos_req, proto_req, proto_capability_req,
    proto_notify_req, proto_passive_req;

static void proto_capability_advertise(dld_str_t *, mblk_t *);
static int dld_capab_poll_disable(dld_str_t *, dld_capab_poll_t *);
static boolean_t check_mod_above(queue_t *, const char *);

#define	DL_ACK_PENDING(state) \
	((state) == DL_ATTACH_PENDING || \
	(state) == DL_DETACH_PENDING || \
	(state) == DL_BIND_PENDING || \
	(state) == DL_UNBIND_PENDING)

/*
 * Process a DLPI protocol message.
 * The primitives DL_BIND_REQ, DL_ENABMULTI_REQ, DL_PROMISCON_REQ,
 * DL_SET_PHYS_ADDR_REQ put the data link below our dld_str_t into an
 * 'active' state. The primitive DL_PASSIVE_REQ marks our dld_str_t
 * as 'passive' and forbids it from being subsequently made 'active'
 * by the above primitives.
 */
void
dld_proto(dld_str_t *dsp, mblk_t *mp)
{
	t_uscalar_t		prim;

	if (MBLKL(mp) < sizeof (t_uscalar_t)) {
		freemsg(mp);
		return;
	}
	prim = ((union DL_primitives *)mp->b_rptr)->dl_primitive;

	switch (prim) {
	case DL_INFO_REQ:
		proto_info_req(dsp, mp);
		break;
	case DL_BIND_REQ:
		proto_bind_req(dsp, mp);
		break;
	case DL_UNBIND_REQ:
		proto_unbind_req(dsp, mp);
		break;
	case DL_UNITDATA_REQ:
		proto_unitdata_req(dsp, mp);
		break;
	case DL_UDQOS_REQ:
		proto_udqos_req(dsp, mp);
		break;
	case DL_ATTACH_REQ:
		proto_attach_req(dsp, mp);
		break;
	case DL_DETACH_REQ:
		proto_detach_req(dsp, mp);
		break;
	case DL_ENABMULTI_REQ:
		proto_enabmulti_req(dsp, mp);
		break;
	case DL_DISABMULTI_REQ:
		proto_disabmulti_req(dsp, mp);
		break;
	case DL_PROMISCON_REQ:
		proto_promiscon_req(dsp, mp);
		break;
	case DL_PROMISCOFF_REQ:
		proto_promiscoff_req(dsp, mp);
		break;
	case DL_PHYS_ADDR_REQ:
		proto_physaddr_req(dsp, mp);
		break;
	case DL_SET_PHYS_ADDR_REQ:
		proto_setphysaddr_req(dsp, mp);
		break;
	case DL_NOTIFY_REQ:
		proto_notify_req(dsp, mp);
		break;
	case DL_CAPABILITY_REQ:
		proto_capability_req(dsp, mp);
		break;
	case DL_PASSIVE_REQ:
		proto_passive_req(dsp, mp);
		break;
	default:
		proto_req(dsp, mp);
		break;
	}
}

#define	NEG(x)	-(x)
typedef struct dl_info_ack_wrapper {
	dl_info_ack_t		dl_info;
	uint8_t			dl_addr[MAXMACADDRLEN + sizeof (uint16_t)];
	uint8_t			dl_brdcst_addr[MAXMACADDRLEN];
	dl_qos_cl_range1_t	dl_qos_range1;
	dl_qos_cl_sel1_t	dl_qos_sel1;
} dl_info_ack_wrapper_t;

/*
 * DL_INFO_REQ
 */
static void
proto_info_req(dld_str_t *dsp, mblk_t *mp)
{
	dl_info_ack_wrapper_t	*dlwp;
	dl_info_ack_t		*dlp;
	dl_qos_cl_sel1_t	*selp;
	dl_qos_cl_range1_t	*rangep;
	uint8_t			*addr;
	uint8_t			*brdcst_addr;
	uint_t			addr_length;
	uint_t			sap_length;
	mac_info_t		minfo;
	mac_info_t		*minfop;
	queue_t			*q = dsp->ds_wq;

	/*
	 * Swap the request message for one large enough to contain the
	 * wrapper structure defined above.
	 */
	if ((mp = mexchange(q, mp, sizeof (dl_info_ack_wrapper_t),
	    M_PCPROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_info_ack_wrapper_t));
	dlwp = (dl_info_ack_wrapper_t *)mp->b_rptr;

	dlp = &(dlwp->dl_info);
	ASSERT(dlp == (dl_info_ack_t *)mp->b_rptr);

	dlp->dl_primitive = DL_INFO_ACK;

	/*
	 * Set up the sub-structure pointers.
	 */
	addr = dlwp->dl_addr;
	brdcst_addr = dlwp->dl_brdcst_addr;
	rangep = &(dlwp->dl_qos_range1);
	selp = &(dlwp->dl_qos_sel1);

	/*
	 * This driver supports only version 2 connectionless DLPI provider
	 * nodes.
	 */
	dlp->dl_service_mode = DL_CLDLS;
	dlp->dl_version = DL_VERSION_2;

	/*
	 * Set the style of the provider
	 */
	dlp->dl_provider_style = dsp->ds_style;
	ASSERT(dlp->dl_provider_style == DL_STYLE1 ||
	    dlp->dl_provider_style == DL_STYLE2);

	/*
	 * Set the current DLPI state.
	 */
	dlp->dl_current_state = dsp->ds_dlstate;

	/*
	 * Gratuitously set the media type. This is to deal with modules
	 * that assume the media type is known prior to DL_ATTACH_REQ
	 * being completed.
	 */
	dlp->dl_mac_type = DL_ETHER;

	/*
	 * If the stream is not at least attached we try to retrieve the
	 * mac_info using mac_info_get()
	 */
	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    dsp->ds_dlstate == DL_ATTACH_PENDING ||
	    dsp->ds_dlstate == DL_DETACH_PENDING) {
		if (!mac_info_get(ddi_major_to_name(dsp->ds_major), &minfo)) {
			/*
			 * Cannot find mac_info. giving up.
			 */
			goto done;
		}
		minfop = &minfo;
	} else {
		minfop = (mac_info_t *)dsp->ds_mip;
		/* We can only get the sdu if we're attached. */
		mac_sdu_get(dsp->ds_mh, &dlp->dl_min_sdu, &dlp->dl_max_sdu);
	}

	/*
	 * Set the media type (properly this time).
	 */
	if (dsp->ds_native)
		dlp->dl_mac_type = minfop->mi_nativemedia;
	else
		dlp->dl_mac_type = minfop->mi_media;

	/*
	 * Set the DLSAP length. We only support 16 bit values and they
	 * appear after the MAC address portion of DLSAP addresses.
	 */
	sap_length = sizeof (uint16_t);
	dlp->dl_sap_length = NEG(sap_length);

	addr_length = minfop->mi_addr_length;

	/*
	 * Copy in the media broadcast address.
	 */
	if (minfop->mi_brdcst_addr != NULL) {
		dlp->dl_brdcst_addr_offset =
		    (uintptr_t)brdcst_addr - (uintptr_t)dlp;
		bcopy(minfop->mi_brdcst_addr, brdcst_addr, addr_length);
		dlp->dl_brdcst_addr_length = addr_length;
	}

	/* Only VLAN links and links that have a normal tag mode support QOS. */
	if ((dsp->ds_mch != NULL &&
	    mac_client_vid(dsp->ds_mch) != VLAN_ID_NONE) ||
	    (dsp->ds_dlp != NULL &&
	    dsp->ds_dlp->dl_tagmode == LINK_TAGMODE_NORMAL)) {
		dlp->dl_qos_range_offset = (uintptr_t)rangep - (uintptr_t)dlp;
		dlp->dl_qos_range_length = sizeof (dl_qos_cl_range1_t);

		rangep->dl_qos_type = DL_QOS_CL_RANGE1;
		rangep->dl_trans_delay.dl_target_value = DL_UNKNOWN;
		rangep->dl_trans_delay.dl_accept_value = DL_UNKNOWN;
		rangep->dl_protection.dl_min = DL_UNKNOWN;
		rangep->dl_protection.dl_max = DL_UNKNOWN;
		rangep->dl_residual_error = DL_UNKNOWN;

		/*
		 * Specify the supported range of priorities.
		 */
		rangep->dl_priority.dl_min = 0;
		rangep->dl_priority.dl_max = (1 << VLAN_PRI_SIZE) - 1;

		dlp->dl_qos_offset = (uintptr_t)selp - (uintptr_t)dlp;
		dlp->dl_qos_length = sizeof (dl_qos_cl_sel1_t);

		selp->dl_qos_type = DL_QOS_CL_SEL1;
		selp->dl_trans_delay = DL_UNKNOWN;
		selp->dl_protection = DL_UNKNOWN;
		selp->dl_residual_error = DL_UNKNOWN;

		/*
		 * Specify the current priority (which can be changed by
		 * the DL_UDQOS_REQ primitive).
		 */
		selp->dl_priority = dsp->ds_pri;
	}

	dlp->dl_addr_length = addr_length + sizeof (uint16_t);
	if (dsp->ds_dlstate == DL_IDLE) {
		/*
		 * The stream is bound. Therefore we can formulate a valid
		 * DLSAP address.
		 */
		dlp->dl_addr_offset = (uintptr_t)addr - (uintptr_t)dlp;
		if (addr_length > 0)
			mac_unicast_primary_get(dsp->ds_mh, addr);

		*(uint16_t *)(addr + addr_length) = dsp->ds_sap;
	}

done:
	IMPLY(dlp->dl_qos_offset != 0, dlp->dl_qos_length != 0);
	IMPLY(dlp->dl_qos_range_offset != 0,
	    dlp->dl_qos_range_length != 0);
	IMPLY(dlp->dl_addr_offset != 0, dlp->dl_addr_length != 0);
	IMPLY(dlp->dl_brdcst_addr_offset != 0,
	    dlp->dl_brdcst_addr_length != 0);

	qreply(q, mp);
}

/*
 * DL_ATTACH_REQ
 */
static void
proto_attach_req(dld_str_t *dsp, mblk_t *mp)
{
	dl_attach_req_t	*dlp = (dl_attach_req_t *)mp->b_rptr;
	int		err = 0;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;

	if (MBLKL(mp) < sizeof (dl_attach_req_t) ||
	    dlp->dl_ppa < 0 || dsp->ds_style == DL_STYLE1) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (dsp->ds_dlstate != DL_UNATTACHED) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	dsp->ds_dlstate = DL_ATTACH_PENDING;

	err = dld_str_attach(dsp, dlp->dl_ppa);
	if (err != 0) {
		switch (err) {
		case ENOENT:
			dl_err = DL_BADPPA;
			err = 0;
			break;
		default:
			dl_err = DL_SYSERR;
			break;
		}
		dsp->ds_dlstate = DL_UNATTACHED;
		goto failed;
	}
	ASSERT(dsp->ds_dlstate == DL_UNBOUND);
	dlokack(q, mp, DL_ATTACH_REQ);
	return;

failed:
	dlerrorack(q, mp, DL_ATTACH_REQ, dl_err, (t_uscalar_t)err);
}

/*
 * DL_DETACH_REQ
 */
static void
proto_detach_req(dld_str_t *dsp, mblk_t *mp)
{
	queue_t		*q = dsp->ds_wq;
	t_uscalar_t	dl_err;

	if (MBLKL(mp) < sizeof (dl_detach_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (dsp->ds_dlstate != DL_UNBOUND) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	if (dsp->ds_style == DL_STYLE1) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	ASSERT(dsp->ds_datathr_cnt == 0);
	dsp->ds_dlstate = DL_DETACH_PENDING;

	dld_str_detach(dsp);
	dlokack(dsp->ds_wq, mp, DL_DETACH_REQ);
	return;

failed:
	dlerrorack(q, mp, DL_DETACH_REQ, dl_err, 0);
}

/*
 * DL_BIND_REQ
 */
static void
proto_bind_req(dld_str_t *dsp, mblk_t *mp)
{
	dl_bind_req_t	*dlp = (dl_bind_req_t *)mp->b_rptr;
	int		err = 0;
	uint8_t		dlsap_addr[MAXMACADDRLEN + sizeof (uint16_t)];
	uint_t		dlsap_addr_length;
	t_uscalar_t	dl_err;
	t_scalar_t	sap;
	queue_t		*q = dsp->ds_wq;
	mac_perim_handle_t	mph;
	void		*mdip;
	int32_t		intr_cpu;

	if (MBLKL(mp) < sizeof (dl_bind_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (dlp->dl_xidtest_flg != 0) {
		dl_err = DL_NOAUTO;
		goto failed;
	}

	if (dlp->dl_service_mode != DL_CLDLS) {
		dl_err = DL_UNSUPPORTED;
		goto failed;
	}

	if (dsp->ds_dlstate != DL_UNBOUND) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	mac_perim_enter_by_mh(dsp->ds_mh, &mph);

	if ((err = dls_active_set(dsp)) != 0) {
		dl_err = DL_SYSERR;
		goto failed2;
	}

	dsp->ds_dlstate = DL_BIND_PENDING;
	/*
	 * Set the receive callback.
	 */
	dls_rx_set(dsp, (dsp->ds_mode == DLD_RAW) ?
	    dld_str_rx_raw : dld_str_rx_unitdata, dsp);

	/*
	 * Bind the channel such that it can receive packets.
	 */
	sap = dlp->dl_sap;
	dsp->ds_nonip = !check_mod_above(dsp->ds_rq, "ip") &&
	    !check_mod_above(dsp->ds_rq, "arp");

	err = dls_bind(dsp, sap);
	if (err != 0) {
		switch (err) {
		case EINVAL:
			dl_err = DL_BADADDR;
			err = 0;
			break;
		default:
			dl_err = DL_SYSERR;
			break;
		}

		dsp->ds_dlstate = DL_UNBOUND;
		dls_active_clear(dsp, B_FALSE);
		goto failed2;
	}

	intr_cpu = mac_client_intr_cpu(dsp->ds_mch);
	mdip = mac_get_devinfo(dsp->ds_mh);
	mac_perim_exit(mph);

	/*
	 * We do this after we get out of the perim to avoid deadlocks
	 * etc. since part of mac_client_retarget_intr is to walk the
	 * device tree in order to find and retarget the interrupts.
	 */
	if (intr_cpu != -1)
		mac_client_set_intr_cpu(mdip, dsp->ds_mch, intr_cpu);

	/*
	 * Copy in MAC address.
	 */
	dlsap_addr_length = dsp->ds_mip->mi_addr_length;
	mac_unicast_primary_get(dsp->ds_mh, dlsap_addr);

	/*
	 * Copy in the SAP.
	 */
	*(uint16_t *)(dlsap_addr + dlsap_addr_length) = sap;
	dlsap_addr_length += sizeof (uint16_t);

	dsp->ds_dlstate = DL_IDLE;
	dlbindack(q, mp, sap, dlsap_addr, dlsap_addr_length, 0, 0);
	return;

failed2:
	mac_perim_exit(mph);
failed:
	dlerrorack(q, mp, DL_BIND_REQ, dl_err, (t_uscalar_t)err);
}

/*
 * DL_UNBIND_REQ
 */
static void
proto_unbind_req(dld_str_t *dsp, mblk_t *mp)
{
	queue_t		*q = dsp->ds_wq;
	t_uscalar_t	dl_err;
	mac_perim_handle_t	mph;

	if (MBLKL(mp) < sizeof (dl_unbind_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (dsp->ds_dlstate != DL_IDLE) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	mutex_enter(&dsp->ds_lock);
	while (dsp->ds_datathr_cnt != 0)
		cv_wait(&dsp->ds_datathr_cv, &dsp->ds_lock);

	dsp->ds_dlstate = DL_UNBIND_PENDING;
	mutex_exit(&dsp->ds_lock);

	mac_perim_enter_by_mh(dsp->ds_mh, &mph);
	/*
	 * Unbind the channel to stop packets being received.
	 */
	dls_unbind(dsp);

	/*
	 * Disable polling mode, if it is enabled.
	 */
	(void) dld_capab_poll_disable(dsp, NULL);

	/*
	 * Clear LSO flags.
	 */
	dsp->ds_lso = B_FALSE;
	dsp->ds_lso_max = 0;

	/*
	 * Clear the receive callback.
	 */
	dls_rx_set(dsp, NULL, NULL);
	dsp->ds_direct = B_FALSE;

	/*
	 * Set the mode back to the default (unitdata).
	 */
	dsp->ds_mode = DLD_UNITDATA;
	dsp->ds_dlstate = DL_UNBOUND;

	dls_active_clear(dsp, B_FALSE);
	mac_perim_exit(mph);
	dlokack(dsp->ds_wq, mp, DL_UNBIND_REQ);
	return;
failed:
	dlerrorack(q, mp, DL_UNBIND_REQ, dl_err, 0);
}

/*
 * DL_PROMISCON_REQ
 */
static void
proto_promiscon_req(dld_str_t *dsp, mblk_t *mp)
{
	dl_promiscon_req_t *dlp = (dl_promiscon_req_t *)mp->b_rptr;
	int		err = 0;
	t_uscalar_t	dl_err;
	uint32_t	new_flags, promisc_saved;
	queue_t		*q = dsp->ds_wq;
	mac_perim_handle_t	mph;

	if (MBLKL(mp) < sizeof (dl_promiscon_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	mac_perim_enter_by_mh(dsp->ds_mh, &mph);

	new_flags = promisc_saved = dsp->ds_promisc;
	switch (dlp->dl_level) {
	case DL_PROMISC_SAP:
		new_flags |= DLS_PROMISC_SAP;
		break;

	case DL_PROMISC_MULTI:
		new_flags |= DLS_PROMISC_MULTI;
		break;

	case DL_PROMISC_PHYS:
		new_flags |= DLS_PROMISC_PHYS;
		break;

	default:
		dl_err = DL_NOTSUPPORTED;
		goto failed2;
	}

	if ((promisc_saved == 0) && (err = dls_active_set(dsp)) != 0) {
		ASSERT(dsp->ds_promisc == promisc_saved);
		dl_err = DL_SYSERR;
		goto failed2;
	}

	/*
	 * Adjust channel promiscuity.
	 */
	err = dls_promisc(dsp, new_flags);

	if (err != 0) {
		dl_err = DL_SYSERR;
		dsp->ds_promisc = promisc_saved;
		if (promisc_saved == 0)
			dls_active_clear(dsp, B_FALSE);
		goto failed2;
	}

	mac_perim_exit(mph);

	dlokack(q, mp, DL_PROMISCON_REQ);
	return;

failed2:
	mac_perim_exit(mph);
failed:
	dlerrorack(q, mp, DL_PROMISCON_REQ, dl_err, (t_uscalar_t)err);
}

/*
 * DL_PROMISCOFF_REQ
 */
static void
proto_promiscoff_req(dld_str_t *dsp, mblk_t *mp)
{
	dl_promiscoff_req_t *dlp = (dl_promiscoff_req_t *)mp->b_rptr;
	int		err = 0;
	t_uscalar_t	dl_err;
	uint32_t	new_flags;
	queue_t		*q = dsp->ds_wq;
	mac_perim_handle_t	mph;

	if (MBLKL(mp) < sizeof (dl_promiscoff_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	mac_perim_enter_by_mh(dsp->ds_mh, &mph);

	new_flags = dsp->ds_promisc;
	switch (dlp->dl_level) {
	case DL_PROMISC_SAP:
		if (!(dsp->ds_promisc & DLS_PROMISC_SAP)) {
			dl_err = DL_NOTENAB;
			goto failed;
		}
		new_flags &= ~DLS_PROMISC_SAP;
		break;

	case DL_PROMISC_MULTI:
		if (!(dsp->ds_promisc & DLS_PROMISC_MULTI)) {
			dl_err = DL_NOTENAB;
			goto failed;
		}
		new_flags &= ~DLS_PROMISC_MULTI;
		break;

	case DL_PROMISC_PHYS:
		if (!(dsp->ds_promisc & DLS_PROMISC_PHYS)) {
			dl_err = DL_NOTENAB;
			goto failed;
		}
		new_flags &= ~DLS_PROMISC_PHYS;
		break;

	default:
		dl_err = DL_NOTSUPPORTED;
		mac_perim_exit(mph);
		goto failed;
	}

	/*
	 * Adjust channel promiscuity.
	 */
	err = dls_promisc(dsp, new_flags);

	if (err != 0) {
		mac_perim_exit(mph);
		dl_err = DL_SYSERR;
		goto failed;
	}

	ASSERT(dsp->ds_promisc == new_flags);
	if (dsp->ds_promisc == 0)
		dls_active_clear(dsp, B_FALSE);

	mac_perim_exit(mph);

	dlokack(q, mp, DL_PROMISCOFF_REQ);
	return;
failed:
	dlerrorack(q, mp, DL_PROMISCOFF_REQ, dl_err, (t_uscalar_t)err);
}

/*
 * DL_ENABMULTI_REQ
 */
static void
proto_enabmulti_req(dld_str_t *dsp, mblk_t *mp)
{
	dl_enabmulti_req_t *dlp = (dl_enabmulti_req_t *)mp->b_rptr;
	int		err = 0;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;
	mac_perim_handle_t	mph;

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	if (MBLKL(mp) < sizeof (dl_enabmulti_req_t) ||
	    !MBLKIN(mp, dlp->dl_addr_offset, dlp->dl_addr_length) ||
	    dlp->dl_addr_length != dsp->ds_mip->mi_addr_length) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	mac_perim_enter_by_mh(dsp->ds_mh, &mph);

	if ((dsp->ds_dmap == NULL) && (err = dls_active_set(dsp)) != 0) {
		dl_err = DL_SYSERR;
		goto failed2;
	}

	err = dls_multicst_add(dsp, mp->b_rptr + dlp->dl_addr_offset);
	if (err != 0) {
		switch (err) {
		case EINVAL:
			dl_err = DL_BADADDR;
			err = 0;
			break;
		case ENOSPC:
			dl_err = DL_TOOMANY;
			err = 0;
			break;
		default:
			dl_err = DL_SYSERR;
			break;
		}
		if (dsp->ds_dmap == NULL)
			dls_active_clear(dsp, B_FALSE);
		goto failed2;
	}

	mac_perim_exit(mph);

	dlokack(q, mp, DL_ENABMULTI_REQ);
	return;

failed2:
	mac_perim_exit(mph);
failed:
	dlerrorack(q, mp, DL_ENABMULTI_REQ, dl_err, (t_uscalar_t)err);
}

/*
 * DL_DISABMULTI_REQ
 */
static void
proto_disabmulti_req(dld_str_t *dsp, mblk_t *mp)
{
	dl_disabmulti_req_t *dlp = (dl_disabmulti_req_t *)mp->b_rptr;
	int		err = 0;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;
	mac_perim_handle_t	mph;

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	if (MBLKL(mp) < sizeof (dl_disabmulti_req_t) ||
	    !MBLKIN(mp, dlp->dl_addr_offset, dlp->dl_addr_length) ||
	    dlp->dl_addr_length != dsp->ds_mip->mi_addr_length) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	mac_perim_enter_by_mh(dsp->ds_mh, &mph);
	err = dls_multicst_remove(dsp, mp->b_rptr + dlp->dl_addr_offset);
	if ((err == 0) && (dsp->ds_dmap == NULL))
		dls_active_clear(dsp, B_FALSE);
	mac_perim_exit(mph);

	if (err != 0) {
	switch (err) {
		case EINVAL:
			dl_err = DL_BADADDR;
			err = 0;
			break;

		case ENOENT:
			dl_err = DL_NOTENAB;
			err = 0;
			break;

		default:
			dl_err = DL_SYSERR;
			break;
		}
		goto failed;
	}
	dlokack(q, mp, DL_DISABMULTI_REQ);
	return;
failed:
	dlerrorack(q, mp, DL_DISABMULTI_REQ, dl_err, (t_uscalar_t)err);
}

/*
 * DL_PHYS_ADDR_REQ
 */
static void
proto_physaddr_req(dld_str_t *dsp, mblk_t *mp)
{
	dl_phys_addr_req_t *dlp = (dl_phys_addr_req_t *)mp->b_rptr;
	queue_t		*q = dsp->ds_wq;
	t_uscalar_t	dl_err = 0;
	char		*addr = NULL;
	uint_t		addr_length;

	if (MBLKL(mp) < sizeof (dl_phys_addr_req_t)) {
		dl_err = DL_BADPRIM;
		goto done;
	}

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dl_err = DL_OUTSTATE;
		goto done;
	}

	addr_length = dsp->ds_mip->mi_addr_length;
	if (addr_length > 0) {
		addr = kmem_alloc(addr_length, KM_SLEEP);
		switch (dlp->dl_addr_type) {
		case DL_CURR_PHYS_ADDR:
			mac_unicast_primary_get(dsp->ds_mh, (uint8_t *)addr);
			break;
		case DL_FACT_PHYS_ADDR:
			bcopy(dsp->ds_mip->mi_unicst_addr, addr, addr_length);
			break;
		case DL_CURR_DEST_ADDR:
			if (!mac_dst_get(dsp->ds_mh, (uint8_t *)addr))
				dl_err = DL_NOTSUPPORTED;
			break;
		default:
			dl_err = DL_UNSUPPORTED;
		}
	}
done:
	if (dl_err == 0)
		dlphysaddrack(q, mp, addr, (t_uscalar_t)addr_length);
	else
		dlerrorack(q, mp, DL_PHYS_ADDR_REQ, dl_err, 0);
	if (addr != NULL)
		kmem_free(addr, addr_length);
}

/*
 * DL_SET_PHYS_ADDR_REQ
 */
static void
proto_setphysaddr_req(dld_str_t *dsp, mblk_t *mp)
{
	dl_set_phys_addr_req_t *dlp = (dl_set_phys_addr_req_t *)mp->b_rptr;
	int		err = 0;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;
	mac_perim_handle_t	mph;

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	if (MBLKL(mp) < sizeof (dl_set_phys_addr_req_t) ||
	    !MBLKIN(mp, dlp->dl_addr_offset, dlp->dl_addr_length) ||
	    dlp->dl_addr_length != dsp->ds_mip->mi_addr_length) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	mac_perim_enter_by_mh(dsp->ds_mh, &mph);

	if ((err = dls_active_set(dsp)) != 0) {
		dl_err = DL_SYSERR;
		goto failed2;
	}

	/*
	 * If mac-nospoof is enabled and the link is owned by a
	 * non-global zone, changing the mac address is not allowed.
	 */
	if (dsp->ds_dlp->dl_zid != GLOBAL_ZONEID &&
	    mac_protect_enabled(dsp->ds_mch, MPT_MACNOSPOOF)) {
		dls_active_clear(dsp, B_FALSE);
		err = EACCES;
		goto failed2;
	}

	err = mac_unicast_primary_set(dsp->ds_mh,
	    mp->b_rptr + dlp->dl_addr_offset);
	if (err != 0) {
		switch (err) {
		case EINVAL:
			dl_err = DL_BADADDR;
			err = 0;
			break;

		default:
			dl_err = DL_SYSERR;
			break;
		}
		dls_active_clear(dsp, B_FALSE);
		goto failed2;

	}

	mac_perim_exit(mph);

	dlokack(q, mp, DL_SET_PHYS_ADDR_REQ);
	return;

failed2:
	mac_perim_exit(mph);
failed:
	dlerrorack(q, mp, DL_SET_PHYS_ADDR_REQ, dl_err, (t_uscalar_t)err);
}

/*
 * DL_UDQOS_REQ
 */
static void
proto_udqos_req(dld_str_t *dsp, mblk_t *mp)
{
	dl_udqos_req_t *dlp = (dl_udqos_req_t *)mp->b_rptr;
	dl_qos_cl_sel1_t *selp;
	int		off, len;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;

	off = dlp->dl_qos_offset;
	len = dlp->dl_qos_length;

	if (MBLKL(mp) < sizeof (dl_udqos_req_t) || !MBLKIN(mp, off, len)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	selp = (dl_qos_cl_sel1_t *)(mp->b_rptr + off);
	if (selp->dl_qos_type != DL_QOS_CL_SEL1) {
		dl_err = DL_BADQOSTYPE;
		goto failed;
	}

	if (selp->dl_priority > (1 << VLAN_PRI_SIZE) - 1 ||
	    selp->dl_priority < 0) {
		dl_err = DL_BADQOSPARAM;
		goto failed;
	}

	dsp->ds_pri = selp->dl_priority;
	dlokack(q, mp, DL_UDQOS_REQ);
	return;
failed:
	dlerrorack(q, mp, DL_UDQOS_REQ, dl_err, 0);
}

static boolean_t
check_mod_above(queue_t *q, const char *mod)
{
	queue_t		*next_q;
	boolean_t	ret = B_TRUE;

	claimstr(q);
	next_q = q->q_next;
	if (strcmp(next_q->q_qinfo->qi_minfo->mi_idname, mod) != 0)
		ret = B_FALSE;
	releasestr(q);
	return (ret);
}

/*
 * DL_CAPABILITY_REQ
 */
static void
proto_capability_req(dld_str_t *dsp, mblk_t *mp)
{
	dl_capability_req_t *dlp = (dl_capability_req_t *)mp->b_rptr;
	dl_capability_sub_t *sp;
	size_t		size, len;
	offset_t	off, end;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;

	if (MBLKL(mp) < sizeof (dl_capability_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	/*
	 * This request is overloaded. If there are no requested capabilities
	 * then we just want to acknowledge with all the capabilities we
	 * support. Otherwise we enable the set of capabilities requested.
	 */
	if (dlp->dl_sub_length == 0) {
		proto_capability_advertise(dsp, mp);
		return;
	}

	if (!MBLKIN(mp, dlp->dl_sub_offset, dlp->dl_sub_length)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	dlp->dl_primitive = DL_CAPABILITY_ACK;

	off = dlp->dl_sub_offset;
	len = dlp->dl_sub_length;

	/*
	 * Walk the list of capabilities to be enabled.
	 */
	for (end = off + len; off < end; ) {
		sp = (dl_capability_sub_t *)(mp->b_rptr + off);
		size = sizeof (dl_capability_sub_t) + sp->dl_length;

		if (off + size > end ||
		    !IS_P2ALIGNED(off, sizeof (uint32_t))) {
			dl_err = DL_BADPRIM;
			goto failed;
		}

		switch (sp->dl_cap) {
		/*
		 * TCP/IP checksum offload to hardware.
		 */
		case DL_CAPAB_HCKSUM: {
			dl_capab_hcksum_t *hcksump;
			dl_capab_hcksum_t hcksum;

			hcksump = (dl_capab_hcksum_t *)&sp[1];
			/*
			 * Copy for alignment.
			 */
			bcopy(hcksump, &hcksum, sizeof (dl_capab_hcksum_t));
			dlcapabsetqid(&(hcksum.hcksum_mid), dsp->ds_rq);
			bcopy(&hcksum, hcksump, sizeof (dl_capab_hcksum_t));
			break;
		}

		case DL_CAPAB_DLD: {
			dl_capab_dld_t	*dldp;
			dl_capab_dld_t	dld;

			dldp = (dl_capab_dld_t *)&sp[1];
			/*
			 * Copy for alignment.
			 */
			bcopy(dldp, &dld, sizeof (dl_capab_dld_t));
			dlcapabsetqid(&(dld.dld_mid), dsp->ds_rq);
			bcopy(&dld, dldp, sizeof (dl_capab_dld_t));
			break;
		}
		default:
			break;
		}
		off += size;
	}
	qreply(q, mp);
	return;
failed:
	dlerrorack(q, mp, DL_CAPABILITY_REQ, dl_err, 0);
}

/*
 * DL_NOTIFY_REQ
 */
static void
proto_notify_req(dld_str_t *dsp, mblk_t *mp)
{
	dl_notify_req_t	*dlp = (dl_notify_req_t *)mp->b_rptr;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;
	uint_t		note =
	    DL_NOTE_PROMISC_ON_PHYS |
	    DL_NOTE_PROMISC_OFF_PHYS |
	    DL_NOTE_PHYS_ADDR |
	    DL_NOTE_LINK_UP |
	    DL_NOTE_LINK_DOWN |
	    DL_NOTE_CAPAB_RENEG |
	    DL_NOTE_FASTPATH_FLUSH |
	    DL_NOTE_SPEED |
	    DL_NOTE_SDU_SIZE|
	    DL_NOTE_SDU_SIZE2|
	    DL_NOTE_ALLOWED_IPS;

	if (MBLKL(mp) < sizeof (dl_notify_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	note &= ~(mac_no_notification(dsp->ds_mh));

	/*
	 * Cache the notifications that are being enabled.
	 */
	dsp->ds_notifications = dlp->dl_notifications & note;
	/*
	 * The ACK carries all notifications regardless of which set is
	 * being enabled.
	 */
	dlnotifyack(q, mp, note);

	/*
	 * Generate DL_NOTIFY_IND messages for each enabled notification.
	 */
	if (dsp->ds_notifications != 0) {
		dld_str_notify_ind(dsp);
	}
	return;
failed:
	dlerrorack(q, mp, DL_NOTIFY_REQ, dl_err, 0);
}

/*
 * DL_UINTDATA_REQ
 */
void
proto_unitdata_req(dld_str_t *dsp, mblk_t *mp)
{
	queue_t			*q = dsp->ds_wq;
	dl_unitdata_req_t	*dlp = (dl_unitdata_req_t *)mp->b_rptr;
	off_t			off;
	size_t			len, size;
	const uint8_t		*addr;
	uint16_t		sap;
	uint_t			addr_length;
	mblk_t			*bp, *payload;
	uint32_t		start, stuff, end, value, flags;
	t_uscalar_t		dl_err;
	uint_t			max_sdu;

	if (MBLKL(mp) < sizeof (dl_unitdata_req_t) || mp->b_cont == NULL) {
		dlerrorack(q, mp, DL_UNITDATA_REQ, DL_BADPRIM, 0);
		return;
	}

	mutex_enter(&dsp->ds_lock);
	if (dsp->ds_dlstate != DL_IDLE) {
		mutex_exit(&dsp->ds_lock);
		dlerrorack(q, mp, DL_UNITDATA_REQ, DL_OUTSTATE, 0);
		return;
	}
	DLD_DATATHR_INC(dsp);
	mutex_exit(&dsp->ds_lock);

	addr_length = dsp->ds_mip->mi_addr_length;

	off = dlp->dl_dest_addr_offset;
	len = dlp->dl_dest_addr_length;

	if (!MBLKIN(mp, off, len) || !IS_P2ALIGNED(off, sizeof (uint16_t))) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (len != addr_length + sizeof (uint16_t)) {
		dl_err = DL_BADADDR;
		goto failed;
	}

	addr = mp->b_rptr + off;
	sap = *(uint16_t *)(mp->b_rptr + off + addr_length);

	/*
	 * Check the length of the packet and the block types.
	 */
	size = 0;
	payload = mp->b_cont;
	for (bp = payload; bp != NULL; bp = bp->b_cont) {
		if (DB_TYPE(bp) != M_DATA)
			goto baddata;

		size += MBLKL(bp);
	}

	mac_sdu_get(dsp->ds_mh, NULL, &max_sdu);
	if (size > max_sdu)
		goto baddata;

	/*
	 * Build a packet header.
	 */
	if ((bp = dls_header(dsp, addr, sap, dlp->dl_priority.dl_max,
	    &payload)) == NULL) {
		dl_err = DL_BADADDR;
		goto failed;
	}

	/*
	 * We no longer need the M_PROTO header, so free it.
	 */
	freeb(mp);

	/*
	 * Transfer the checksum offload information if it is present.
	 */
	hcksum_retrieve(payload, NULL, NULL, &start, &stuff, &end, &value,
	    &flags);
	(void) hcksum_assoc(bp, NULL, NULL, start, stuff, end, value, flags, 0);

	/*
	 * Link the payload onto the new header.
	 */
	ASSERT(bp->b_cont == NULL);
	bp->b_cont = payload;

	/*
	 * No lock can be held across modules and putnext()'s,
	 * which can happen here with the call from DLD_TX().
	 */
	if (DLD_TX(dsp, bp, 0, 0) != NULL) {
		/* flow-controlled */
		DLD_SETQFULL(dsp);
	}
	DLD_DATATHR_DCR(dsp);
	return;

failed:
	dlerrorack(q, mp, DL_UNITDATA_REQ, dl_err, 0);
	DLD_DATATHR_DCR(dsp);
	return;

baddata:
	dluderrorind(q, mp, (void *)addr, len, DL_BADDATA, 0);
	DLD_DATATHR_DCR(dsp);
}

/*
 * DL_PASSIVE_REQ
 */
static void
proto_passive_req(dld_str_t *dsp, mblk_t *mp)
{
	t_uscalar_t dl_err;

	/*
	 * If we've already become active by issuing an active primitive,
	 * then it's too late to try to become passive.
	 */
	if (dsp->ds_passivestate == DLD_ACTIVE) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	if (MBLKL(mp) < sizeof (dl_passive_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	dsp->ds_passivestate = DLD_PASSIVE;
	dlokack(dsp->ds_wq, mp, DL_PASSIVE_REQ);
	return;
failed:
	dlerrorack(dsp->ds_wq, mp, DL_PASSIVE_REQ, dl_err, 0);
}


/*
 * Catch-all handler.
 */
static void
proto_req(dld_str_t *dsp, mblk_t *mp)
{
	union DL_primitives	*dlp = (union DL_primitives *)mp->b_rptr;

	dlerrorack(dsp->ds_wq, mp, dlp->dl_primitive, DL_UNSUPPORTED, 0);
}

static int
dld_capab_perim(dld_str_t *dsp, void *data, uint_t flags)
{
	switch (flags) {
	case DLD_ENABLE:
		mac_perim_enter_by_mh(dsp->ds_mh, (mac_perim_handle_t *)data);
		return (0);

	case DLD_DISABLE:
		mac_perim_exit((mac_perim_handle_t)data);
		return (0);

	case DLD_QUERY:
		return (mac_perim_held(dsp->ds_mh));
	}
	return (0);
}

static int
dld_capab_direct(dld_str_t *dsp, void *data, uint_t flags)
{
	dld_capab_direct_t	*direct = data;

	ASSERT(MAC_PERIM_HELD(dsp->ds_mh));

	switch (flags) {
	case DLD_ENABLE:
		dls_rx_set(dsp, (dls_rx_t)direct->di_rx_cf,
		    direct->di_rx_ch);

		direct->di_tx_df = (uintptr_t)str_mdata_fastpath_put;
		direct->di_tx_dh = dsp;
		direct->di_tx_cb_df = (uintptr_t)mac_client_tx_notify;
		direct->di_tx_cb_dh = dsp->ds_mch;
		direct->di_tx_fctl_df = (uintptr_t)mac_tx_is_flow_blocked;
		direct->di_tx_fctl_dh = dsp->ds_mch;

		dsp->ds_direct = B_TRUE;

		return (0);

	case DLD_DISABLE:
		dls_rx_set(dsp, (dsp->ds_mode == DLD_FASTPATH) ?
		    dld_str_rx_fastpath : dld_str_rx_unitdata, (void *)dsp);
		dsp->ds_direct = B_FALSE;

		return (0);
	}
	return (ENOTSUP);
}

/*
 * dld_capab_poll_enable()
 *
 * This function is misnamed. All polling  and fanouts are run out of the
 * lower mac (in case of VNIC and the only mac in case of NICs). The
 * availability of Rx ring and promiscous mode is all taken care between
 * the soft ring set (mac_srs), the Rx ring, and S/W classifier. Any
 * fanout necessary is done by the soft rings that are part of the
 * mac_srs (by default mac_srs sends the packets up via a TCP and
 * non TCP soft ring).
 *
 * The mac_srs (or its associated soft rings) always store the ill_rx_ring
 * (the cookie returned when they registered with IP during plumb) as their
 * 2nd argument which is passed up as mac_resource_handle_t. The upcall
 * function and 1st argument is what the caller registered when they
 * called mac_rx_classify_flow_add() to register the flow. For VNIC,
 * the function is vnic_rx and argument is vnic_t. For regular NIC
 * case, it mac_rx_default and mac_handle_t. As explained above, the
 * mac_srs (or its soft ring) will add the ill_rx_ring (mac_resource_handle_t)
 * from its stored 2nd argument.
 */
static int
dld_capab_poll_enable(dld_str_t *dsp, dld_capab_poll_t *poll)
{
	if (dsp->ds_polling)
		return (EINVAL);

	if ((dld_opt & DLD_OPT_NO_POLL) != 0 || dsp->ds_mode == DLD_RAW)
		return (ENOTSUP);

	/*
	 * Enable client polling if and only if DLS bypass is possible.
	 * Special cases like VLANs need DLS processing in the Rx data path.
	 * In such a case we can neither allow the client (IP) to directly
	 * poll the softring (since DLS processing hasn't been done) nor can
	 * we allow DLS bypass.
	 */
	if (!mac_rx_bypass_set(dsp->ds_mch, dsp->ds_rx, dsp->ds_rx_arg))
		return (ENOTSUP);

	/*
	 * Register soft ring resources. This will come in handy later if
	 * the user decides to modify CPU bindings to use more CPUs for the
	 * device in which case we will switch to fanout using soft rings.
	 */
	mac_resource_set_common(dsp->ds_mch,
	    (mac_resource_add_t)poll->poll_ring_add_cf,
	    (mac_resource_remove_t)poll->poll_ring_remove_cf,
	    (mac_resource_quiesce_t)poll->poll_ring_quiesce_cf,
	    (mac_resource_restart_t)poll->poll_ring_restart_cf,
	    (mac_resource_bind_t)poll->poll_ring_bind_cf,
	    poll->poll_ring_ch);

	mac_client_poll_enable(dsp->ds_mch);

	dsp->ds_polling = B_TRUE;
	return (0);
}

/* ARGSUSED */
static int
dld_capab_poll_disable(dld_str_t *dsp, dld_capab_poll_t *poll)
{
	if (!dsp->ds_polling)
		return (EINVAL);

	mac_client_poll_disable(dsp->ds_mch);
	mac_resource_set(dsp->ds_mch, NULL, NULL);

	dsp->ds_polling = B_FALSE;
	return (0);
}

static int
dld_capab_poll(dld_str_t *dsp, void *data, uint_t flags)
{
	dld_capab_poll_t	*poll = data;

	ASSERT(MAC_PERIM_HELD(dsp->ds_mh));

	switch (flags) {
	case DLD_ENABLE:
		return (dld_capab_poll_enable(dsp, poll));
	case DLD_DISABLE:
		return (dld_capab_poll_disable(dsp, poll));
	}
	return (ENOTSUP);
}

static int
dld_capab_lso(dld_str_t *dsp, void *data, uint_t flags)
{
	dld_capab_lso_t		*lso = data;

	ASSERT(MAC_PERIM_HELD(dsp->ds_mh));

	switch (flags) {
	case DLD_ENABLE: {
		mac_capab_lso_t		mac_lso;

		/*
		 * Check if LSO is supported on this MAC & enable LSO
		 * accordingly.
		 */
		if (mac_capab_get(dsp->ds_mh, MAC_CAPAB_LSO, &mac_lso)) {
			lso->lso_max = mac_lso.lso_basic_tcp_ipv4.lso_max;
			lso->lso_flags = 0;
			/* translate the flag for mac clients */
			if ((mac_lso.lso_flags & LSO_TX_BASIC_TCP_IPV4) != 0)
				lso->lso_flags |= DLD_LSO_BASIC_TCP_IPV4;
			dsp->ds_lso = B_TRUE;
			dsp->ds_lso_max = lso->lso_max;
		} else {
			dsp->ds_lso = B_FALSE;
			dsp->ds_lso_max = 0;
			return (ENOTSUP);
		}
		return (0);
	}
	case DLD_DISABLE: {
		dsp->ds_lso = B_FALSE;
		dsp->ds_lso_max = 0;
		return (0);
	}
	}
	return (ENOTSUP);
}

static int
dld_capab(dld_str_t *dsp, uint_t type, void *data, uint_t flags)
{
	int	err;

	/*
	 * Don't enable direct callback capabilities unless the caller is
	 * the IP client. When a module is inserted in a stream (_I_INSERT)
	 * the stack initiates capability disable, but due to races, the
	 * module insertion may complete before the capability disable
	 * completes. So we limit the check to DLD_ENABLE case.
	 */
	if ((flags == DLD_ENABLE && type != DLD_CAPAB_PERIM) &&
	    (dsp->ds_sap != ETHERTYPE_IP ||
	    !check_mod_above(dsp->ds_rq, "ip"))) {
		return (ENOTSUP);
	}

	switch (type) {
	case DLD_CAPAB_DIRECT:
		err = dld_capab_direct(dsp, data, flags);
		break;

	case DLD_CAPAB_POLL:
		err =  dld_capab_poll(dsp, data, flags);
		break;

	case DLD_CAPAB_PERIM:
		err = dld_capab_perim(dsp, data, flags);
		break;

	case DLD_CAPAB_LSO:
		err = dld_capab_lso(dsp, data, flags);
		break;

	default:
		err = ENOTSUP;
		break;
	}

	return (err);
}

/*
 * DL_CAPABILITY_ACK/DL_ERROR_ACK
 */
static void
proto_capability_advertise(dld_str_t *dsp, mblk_t *mp)
{
	dl_capability_ack_t	*dlap;
	dl_capability_sub_t	*dlsp;
	size_t			subsize;
	dl_capab_dld_t		dld;
	dl_capab_hcksum_t	hcksum;
	dl_capab_zerocopy_t	zcopy;
	dl_capab_vrrp_t		vrrp;
	mac_capab_vrrp_t	vrrp_capab;
	uint8_t			*ptr;
	queue_t			*q = dsp->ds_wq;
	mblk_t			*mp1;
	boolean_t		hcksum_capable = B_FALSE;
	boolean_t		zcopy_capable = B_FALSE;
	boolean_t		dld_capable = B_FALSE;
	boolean_t		vrrp_capable = B_FALSE;

	/*
	 * Initially assume no capabilities.
	 */
	subsize = 0;

	/*
	 * Check if checksum offload is supported on this MAC.
	 */
	bzero(&hcksum, sizeof (dl_capab_hcksum_t));
	if (mac_capab_get(dsp->ds_mh, MAC_CAPAB_HCKSUM,
	    &hcksum.hcksum_txflags)) {
		if (hcksum.hcksum_txflags != 0) {
			hcksum_capable = B_TRUE;
			subsize += sizeof (dl_capability_sub_t) +
			    sizeof (dl_capab_hcksum_t);
		}
	}

	/*
	 * Check if zerocopy is supported on this interface.
	 * If advertising DL_CAPAB_ZEROCOPY has not been explicitly disabled
	 * then reserve space for that capability.
	 */
	if (!mac_capab_get(dsp->ds_mh, MAC_CAPAB_NO_ZCOPY, NULL) &&
	    !(dld_opt & DLD_OPT_NO_ZEROCOPY)) {
		zcopy_capable = B_TRUE;
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_zerocopy_t);
	}

	/*
	 * Direct capability negotiation interface between IP and DLD
	 */
	if (dsp->ds_sap == ETHERTYPE_IP && check_mod_above(dsp->ds_rq, "ip")) {
		dld_capable = B_TRUE;
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_dld_t);
	}

	/*
	 * Check if vrrp is supported on this interface. If so, reserve
	 * space for that capability.
	 */
	if (mac_capab_get(dsp->ds_mh, MAC_CAPAB_VRRP, &vrrp_capab)) {
		vrrp_capable = B_TRUE;
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_vrrp_t);
	}

	/*
	 * If there are no capabilities to advertise or if we
	 * can't allocate a response, send a DL_ERROR_ACK.
	 */
	if ((mp1 = reallocb(mp,
	    sizeof (dl_capability_ack_t) + subsize, 0)) == NULL) {
		dlerrorack(q, mp, DL_CAPABILITY_REQ, DL_NOTSUPPORTED, 0);
		return;
	}

	mp = mp1;
	DB_TYPE(mp) = M_PROTO;
	mp->b_wptr = mp->b_rptr + sizeof (dl_capability_ack_t) + subsize;
	bzero(mp->b_rptr, MBLKL(mp));
	dlap = (dl_capability_ack_t *)mp->b_rptr;
	dlap->dl_primitive = DL_CAPABILITY_ACK;
	dlap->dl_sub_offset = sizeof (dl_capability_ack_t);
	dlap->dl_sub_length = subsize;
	ptr = (uint8_t *)&dlap[1];

	/*
	 * TCP/IP checksum offload.
	 */
	if (hcksum_capable) {
		dlsp = (dl_capability_sub_t *)ptr;

		dlsp->dl_cap = DL_CAPAB_HCKSUM;
		dlsp->dl_length = sizeof (dl_capab_hcksum_t);
		ptr += sizeof (dl_capability_sub_t);

		hcksum.hcksum_version = HCKSUM_VERSION_1;
		dlcapabsetqid(&(hcksum.hcksum_mid), dsp->ds_rq);
		bcopy(&hcksum, ptr, sizeof (dl_capab_hcksum_t));
		ptr += sizeof (dl_capab_hcksum_t);
	}

	/*
	 * Zero copy
	 */
	if (zcopy_capable) {
		dlsp = (dl_capability_sub_t *)ptr;

		dlsp->dl_cap = DL_CAPAB_ZEROCOPY;
		dlsp->dl_length = sizeof (dl_capab_zerocopy_t);
		ptr += sizeof (dl_capability_sub_t);

		bzero(&zcopy, sizeof (dl_capab_zerocopy_t));
		zcopy.zerocopy_version = ZEROCOPY_VERSION_1;
		zcopy.zerocopy_flags = DL_CAPAB_VMSAFE_MEM;

		dlcapabsetqid(&(zcopy.zerocopy_mid), dsp->ds_rq);
		bcopy(&zcopy, ptr, sizeof (dl_capab_zerocopy_t));
		ptr += sizeof (dl_capab_zerocopy_t);
	}

	/*
	 * VRRP capability negotiation
	 */
	if (vrrp_capable) {
		dlsp = (dl_capability_sub_t *)ptr;
		dlsp->dl_cap = DL_CAPAB_VRRP;
		dlsp->dl_length = sizeof (dl_capab_vrrp_t);
		ptr += sizeof (dl_capability_sub_t);

		bzero(&vrrp, sizeof (dl_capab_vrrp_t));
		vrrp.vrrp_af = vrrp_capab.mcv_af;
		bcopy(&vrrp, ptr, sizeof (dl_capab_vrrp_t));
		ptr += sizeof (dl_capab_vrrp_t);
	}

	/*
	 * Direct capability negotiation interface between IP and DLD.
	 * Refer to dld.h for details.
	 */
	if (dld_capable) {
		dlsp = (dl_capability_sub_t *)ptr;
		dlsp->dl_cap = DL_CAPAB_DLD;
		dlsp->dl_length = sizeof (dl_capab_dld_t);
		ptr += sizeof (dl_capability_sub_t);

		bzero(&dld, sizeof (dl_capab_dld_t));
		dld.dld_version = DLD_CURRENT_VERSION;
		dld.dld_capab = (uintptr_t)dld_capab;
		dld.dld_capab_handle = (uintptr_t)dsp;

		dlcapabsetqid(&(dld.dld_mid), dsp->ds_rq);
		bcopy(&dld, ptr, sizeof (dl_capab_dld_t));
		ptr += sizeof (dl_capab_dld_t);
	}

	ASSERT(ptr == mp->b_rptr + sizeof (dl_capability_ack_t) + subsize);
	qreply(q, mp);
}

/*
 * Disable any enabled capabilities.
 */
void
dld_capabilities_disable(dld_str_t *dsp)
{
	if (dsp->ds_polling)
		(void) dld_capab_poll_disable(dsp, NULL);
}
