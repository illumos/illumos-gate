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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data-Link Driver
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/cpuvar.h>
#include <sys/dlpi.h>
#include <netinet/in.h>
#include <sys/sdt.h>
#include <sys/strsubr.h>
#include <sys/vlan.h>
#include <sys/mac.h>
#include <sys/dls.h>
#include <sys/dld.h>
#include <sys/dld_impl.h>
#include <sys/dls_soft_ring.h>

typedef boolean_t proto_reqfunc_t(dld_str_t *, union DL_primitives *, mblk_t *);

static proto_reqfunc_t proto_info_req, proto_attach_req, proto_detach_req,
    proto_bind_req, proto_unbind_req, proto_promiscon_req, proto_promiscoff_req,
    proto_enabmulti_req, proto_disabmulti_req, proto_physaddr_req,
    proto_setphysaddr_req, proto_udqos_req, proto_req, proto_capability_req,
    proto_notify_req, proto_passive_req;

static void proto_poll_disable(dld_str_t *);
static boolean_t proto_poll_enable(dld_str_t *, dl_capab_dls_t *);

static void proto_soft_ring_disable(dld_str_t *);
static boolean_t proto_soft_ring_enable(dld_str_t *, dl_capab_dls_t *);
static boolean_t proto_capability_advertise(dld_str_t *, mblk_t *);
static void proto_change_soft_ring_fanout(dld_str_t *, int);

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
dld_wput_proto_nondata(dld_str_t *dsp, mblk_t *mp)
{
	union DL_primitives	*udlp;
	t_uscalar_t		prim;

	ASSERT(MBLKL(mp) >= sizeof (t_uscalar_t));

	udlp = (union DL_primitives *)mp->b_rptr;
	prim = udlp->dl_primitive;

	switch (prim) {
	case DL_INFO_REQ:
		(void) proto_info_req(dsp, udlp, mp);
		break;
	case DL_BIND_REQ:
		(void) proto_bind_req(dsp, udlp, mp);
		break;
	case DL_UNBIND_REQ:
		(void) proto_unbind_req(dsp, udlp, mp);
		break;
	case DL_UDQOS_REQ:
		(void) proto_udqos_req(dsp, udlp, mp);
		break;
	case DL_ATTACH_REQ:
		(void) proto_attach_req(dsp, udlp, mp);
		break;
	case DL_DETACH_REQ:
		(void) proto_detach_req(dsp, udlp, mp);
		break;
	case DL_ENABMULTI_REQ:
		(void) proto_enabmulti_req(dsp, udlp, mp);
		break;
	case DL_DISABMULTI_REQ:
		(void) proto_disabmulti_req(dsp, udlp, mp);
		break;
	case DL_PROMISCON_REQ:
		(void) proto_promiscon_req(dsp, udlp, mp);
		break;
	case DL_PROMISCOFF_REQ:
		(void) proto_promiscoff_req(dsp, udlp, mp);
		break;
	case DL_PHYS_ADDR_REQ:
		(void) proto_physaddr_req(dsp, udlp, mp);
		break;
	case DL_SET_PHYS_ADDR_REQ:
		(void) proto_setphysaddr_req(dsp, udlp, mp);
		break;
	case DL_NOTIFY_REQ:
		(void) proto_notify_req(dsp, udlp, mp);
		break;
	case DL_CAPABILITY_REQ:
		(void) proto_capability_req(dsp, udlp, mp);
		break;
	case DL_PASSIVE_REQ:
		(void) proto_passive_req(dsp, udlp, mp);
		break;
	default:
		(void) proto_req(dsp, udlp, mp);
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
/*ARGSUSED*/
static boolean_t
proto_info_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
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
		return (B_FALSE);

	rw_enter(&dsp->ds_lock, RW_READER);

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

	/*
	 * Set the minimum and maximum payload sizes.
	 */
	dlp->dl_min_sdu = minfop->mi_sdu_min;
	dlp->dl_max_sdu = minfop->mi_sdu_max;

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

	dlp->dl_addr_length = addr_length + sizeof (uint16_t);
	if (dsp->ds_dlstate == DL_IDLE) {
		/*
		 * The stream is bound. Therefore we can formulate a valid
		 * DLSAP address.
		 */
		dlp->dl_addr_offset = (uintptr_t)addr - (uintptr_t)dlp;
		if (addr_length > 0)
			bcopy(dsp->ds_curr_addr, addr, addr_length);
		*(uint16_t *)(addr + addr_length) = dsp->ds_sap;
	}

done:
	ASSERT(IMPLY(dlp->dl_qos_offset != 0, dlp->dl_qos_length != 0));
	ASSERT(IMPLY(dlp->dl_qos_range_offset != 0,
	    dlp->dl_qos_range_length != 0));
	ASSERT(IMPLY(dlp->dl_addr_offset != 0, dlp->dl_addr_length != 0));
	ASSERT(IMPLY(dlp->dl_brdcst_addr_offset != 0,
	    dlp->dl_brdcst_addr_length != 0));

	rw_exit(&dsp->ds_lock);

	qreply(q, mp);
	return (B_TRUE);
}

/*
 * DL_ATTACH_REQ
 */
static boolean_t
proto_attach_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_attach_req_t	*dlp = (dl_attach_req_t *)udlp;
	int		err = 0;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;

	rw_enter(&dsp->ds_lock, RW_WRITER);

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
	rw_exit(&dsp->ds_lock);

	dlokack(q, mp, DL_ATTACH_REQ);
	return (B_TRUE);
failed:
	rw_exit(&dsp->ds_lock);
	dlerrorack(q, mp, DL_ATTACH_REQ, dl_err, (t_uscalar_t)err);
	return (B_FALSE);
}

/*ARGSUSED*/
static boolean_t
proto_detach_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	queue_t		*q = dsp->ds_wq;
	t_uscalar_t	dl_err;

	rw_enter(&dsp->ds_lock, RW_WRITER);

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

	dsp->ds_dlstate = DL_DETACH_PENDING;
	dld_str_detach(dsp);

	rw_exit(&dsp->ds_lock);
	dlokack(dsp->ds_wq, mp, DL_DETACH_REQ);
	return (B_TRUE);
failed:
	rw_exit(&dsp->ds_lock);
	dlerrorack(q, mp, DL_DETACH_REQ, dl_err, 0);
	return (B_FALSE);
}

/*
 * DL_BIND_REQ
 */
static boolean_t
proto_bind_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_bind_req_t	*dlp = (dl_bind_req_t *)udlp;
	int		err = 0;
	uint8_t		dlsap_addr[MAXMACADDRLEN + sizeof (uint16_t)];
	uint_t		dlsap_addr_length;
	t_uscalar_t	dl_err;
	t_scalar_t	sap;
	queue_t		*q = dsp->ds_wq;

	/*
	 * Because control message processing is serialized, we don't need
	 * to hold any locks to read any fields of dsp; we only need ds_lock
	 * to update the ds_dlstate, ds_sap and ds_passivestate fields.
	 */
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

	if (dsp->ds_passivestate == DLD_UNINITIALIZED &&
	    !dls_active_set(dsp->ds_dc)) {
		dl_err = DL_SYSERR;
		err = EBUSY;
		goto failed;
	}

	/*
	 * Set the receive callback.
	 */
	dls_rx_set(dsp->ds_dc, (dsp->ds_mode == DLD_RAW) ?
	    dld_str_rx_raw : dld_str_rx_unitdata, dsp);

	/*
	 * Bind the channel such that it can receive packets.
	 */
	sap = dlp->dl_sap;
	err = dls_bind(dsp->ds_dc, sap);
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

		if (dsp->ds_passivestate == DLD_UNINITIALIZED)
			dls_active_clear(dsp->ds_dc);

		goto failed;
	}

	/*
	 * Copy in MAC address.
	 */
	dlsap_addr_length = dsp->ds_mip->mi_addr_length;
	bcopy(dsp->ds_curr_addr, dlsap_addr, dlsap_addr_length);

	/*
	 * Copy in the SAP.
	 */
	*(uint16_t *)(dlsap_addr + dlsap_addr_length) = sap;
	dlsap_addr_length += sizeof (uint16_t);

	rw_enter(&dsp->ds_lock, RW_WRITER);

	dsp->ds_dlstate = DL_IDLE;
	if (dsp->ds_passivestate == DLD_UNINITIALIZED)
		dsp->ds_passivestate = DLD_ACTIVE;
	dsp->ds_sap = sap;

	if (dsp->ds_mode == DLD_FASTPATH)
		dsp->ds_tx = str_mdata_fastpath_put;
	else if (dsp->ds_mode == DLD_RAW)
		dsp->ds_tx = str_mdata_raw_put;
	dsp->ds_unitdata_tx = dld_wput_proto_data;

	rw_exit(&dsp->ds_lock);

	dlbindack(q, mp, sap, dlsap_addr, dlsap_addr_length, 0, 0);
	return (B_TRUE);
failed:
	dlerrorack(q, mp, DL_BIND_REQ, dl_err, (t_uscalar_t)err);
	return (B_FALSE);
}

/*
 * DL_UNBIND_REQ
 */
/*ARGSUSED*/
static boolean_t
proto_unbind_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	queue_t		*q = dsp->ds_wq;
	t_uscalar_t	dl_err;

	if (MBLKL(mp) < sizeof (dl_unbind_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (dsp->ds_dlstate != DL_IDLE) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	/*
	 * Flush any remaining packets scheduled for transmission.
	 */
	dld_tx_flush(dsp);

	/*
	 * Unbind the channel to stop packets being received.
	 */
	dls_unbind(dsp->ds_dc);

	/*
	 * Clear the receive callback.
	 */
	dls_rx_set(dsp->ds_dc, NULL, NULL);

	rw_enter(&dsp->ds_lock, RW_WRITER);

	/*
	 * Disable polling mode, if it is enabled.
	 */
	proto_poll_disable(dsp);

	/*
	 * If soft rings were enabled, the workers should be quiesced.
	 */
	dls_soft_ring_disable(dsp->ds_dc);

	/*
	 * Clear LSO flags.
	 */
	dsp->ds_lso = B_FALSE;
	dsp->ds_lso_max = 0;

	/*
	 * Set the mode back to the default (unitdata).
	 */
	dsp->ds_mode = DLD_UNITDATA;
	dsp->ds_dlstate = DL_UNBOUND;
	DLD_TX_QUIESCE(dsp);
	rw_exit(&dsp->ds_lock);

	dlokack(q, mp, DL_UNBIND_REQ);

	return (B_TRUE);
failed:
	dlerrorack(q, mp, DL_UNBIND_REQ, dl_err, 0);
	return (B_FALSE);
}

/*
 * DL_PROMISCON_REQ
 */
static boolean_t
proto_promiscon_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_promiscon_req_t *dlp = (dl_promiscon_req_t *)udlp;
	int		err = 0;
	t_uscalar_t	dl_err;
	uint32_t	promisc;
	queue_t		*q = dsp->ds_wq;

	/*
	 * Because control message processing is serialized, we don't need
	 * to hold any locks to read any fields of dsp; we only need ds_lock
	 * to update the ds_promisc and ds_passivestate fields.
	 */
	if (MBLKL(mp) < sizeof (dl_promiscon_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	switch (dlp->dl_level) {
	case DL_PROMISC_SAP:
		promisc = DLS_PROMISC_SAP;
		break;
	case DL_PROMISC_MULTI:
		promisc = DLS_PROMISC_MULTI;
		break;
	case DL_PROMISC_PHYS:
		promisc = DLS_PROMISC_PHYS;
		break;
	default:
		dl_err = DL_NOTSUPPORTED;
		goto failed;
	}

	if (dsp->ds_passivestate == DLD_UNINITIALIZED &&
	    !dls_active_set(dsp->ds_dc)) {
		dl_err = DL_SYSERR;
		err = EBUSY;
		goto failed;
	}

	/*
	 * Adjust channel promiscuity.
	 */
	promisc = (dsp->ds_promisc | promisc);
	err = dls_promisc(dsp->ds_dc, promisc);
	if (err != 0) {
		dl_err = DL_SYSERR;
		if (dsp->ds_passivestate == DLD_UNINITIALIZED)
			dls_active_clear(dsp->ds_dc);
		goto failed;
	}

	rw_enter(&dsp->ds_lock, RW_WRITER);
	if (dsp->ds_passivestate == DLD_UNINITIALIZED)
		dsp->ds_passivestate = DLD_ACTIVE;
	dsp->ds_promisc = promisc;
	rw_exit(&dsp->ds_lock);

	dlokack(q, mp, DL_PROMISCON_REQ);
	return (B_TRUE);
failed:
	dlerrorack(q, mp, DL_PROMISCON_REQ, dl_err, (t_uscalar_t)err);
	return (B_FALSE);
}

/*
 * DL_PROMISCOFF_REQ
 */
static boolean_t
proto_promiscoff_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_promiscoff_req_t *dlp = (dl_promiscoff_req_t *)udlp;
	int		err = 0;
	t_uscalar_t	dl_err;
	uint32_t	promisc;
	queue_t		*q = dsp->ds_wq;

	/*
	 * Because control messages processing is serialized, we don't need
	 * to hold any lock to read any field of dsp; we hold ds_lock to
	 * update the ds_promisc field.
	 */
	if (MBLKL(mp) < sizeof (dl_promiscoff_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	switch (dlp->dl_level) {
	case DL_PROMISC_SAP:
		promisc = DLS_PROMISC_SAP;
		break;
	case DL_PROMISC_MULTI:
		promisc = DLS_PROMISC_MULTI;
		break;
	case DL_PROMISC_PHYS:
		promisc = DLS_PROMISC_PHYS;
		break;
	default:
		dl_err = DL_NOTSUPPORTED;
		goto failed;
	}

	if (!(dsp->ds_promisc & promisc)) {
		dl_err = DL_NOTENAB;
		goto failed;
	}

	promisc = (dsp->ds_promisc & ~promisc);
	err = dls_promisc(dsp->ds_dc, promisc);
	if (err != 0) {
		dl_err = DL_SYSERR;
		goto failed;
	}

	rw_enter(&dsp->ds_lock, RW_WRITER);
	dsp->ds_promisc = promisc;
	rw_exit(&dsp->ds_lock);

	dlokack(q, mp, DL_PROMISCOFF_REQ);
	return (B_TRUE);
failed:
	dlerrorack(q, mp, DL_PROMISCOFF_REQ, dl_err, (t_uscalar_t)err);
	return (B_FALSE);
}

/*
 * DL_ENABMULTI_REQ
 */
static boolean_t
proto_enabmulti_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_enabmulti_req_t *dlp = (dl_enabmulti_req_t *)udlp;
	int		err = 0;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;

	/*
	 * Because control messages processing is serialized, we don't need
	 * to hold any lock to read any field of dsp; we hold ds_lock to
	 * update the ds_passivestate field.
	 */
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

	if (dsp->ds_passivestate == DLD_UNINITIALIZED &&
	    !dls_active_set(dsp->ds_dc)) {
		dl_err = DL_SYSERR;
		err = EBUSY;
		goto failed;
	}

	err = dls_multicst_add(dsp->ds_dc, mp->b_rptr + dlp->dl_addr_offset);
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

		if (dsp->ds_passivestate == DLD_UNINITIALIZED)
			dls_active_clear(dsp->ds_dc);

		goto failed;
	}

	rw_enter(&dsp->ds_lock, RW_WRITER);
	if (dsp->ds_passivestate == DLD_UNINITIALIZED)
		dsp->ds_passivestate = DLD_ACTIVE;
	rw_exit(&dsp->ds_lock);

	dlokack(q, mp, DL_ENABMULTI_REQ);
	return (B_TRUE);
failed:
	dlerrorack(q, mp, DL_ENABMULTI_REQ, dl_err, (t_uscalar_t)err);
	return (B_FALSE);
}

/*
 * DL_DISABMULTI_REQ
 */
static boolean_t
proto_disabmulti_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_disabmulti_req_t *dlp = (dl_disabmulti_req_t *)udlp;
	int		err = 0;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;

	/*
	 * Because control messages processing is serialized, we don't need
	 * to hold any lock to read any field of dsp.
	 */
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

	err = dls_multicst_remove(dsp->ds_dc, mp->b_rptr + dlp->dl_addr_offset);
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
	return (B_TRUE);
failed:
	dlerrorack(q, mp, DL_DISABMULTI_REQ, dl_err, (t_uscalar_t)err);
	return (B_FALSE);
}

/*
 * DL_PHYS_ADDR_REQ
 */
static boolean_t
proto_physaddr_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_phys_addr_req_t *dlp = (dl_phys_addr_req_t *)udlp;
	queue_t		*q = dsp->ds_wq;
	t_uscalar_t	dl_err;
	char		*addr;
	uint_t		addr_length;

	rw_enter(&dsp->ds_lock, RW_READER);

	if (MBLKL(mp) < sizeof (dl_phys_addr_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	if (dlp->dl_addr_type != DL_CURR_PHYS_ADDR &&
	    dlp->dl_addr_type != DL_FACT_PHYS_ADDR) {
		dl_err = DL_UNSUPPORTED;
		goto failed;
	}

	addr_length = dsp->ds_mip->mi_addr_length;
	addr = kmem_alloc(addr_length, KM_NOSLEEP);
	if (addr == NULL) {
		rw_exit(&dsp->ds_lock);
		merror(q, mp, ENOSR);
		return (B_FALSE);
	}

	/*
	 * Copy out the address before we drop the lock; we don't
	 * want to call dlphysaddrack() while holding ds_lock.
	 */
	bcopy((dlp->dl_addr_type == DL_CURR_PHYS_ADDR) ?
	    dsp->ds_curr_addr : dsp->ds_fact_addr, addr, addr_length);

	rw_exit(&dsp->ds_lock);
	dlphysaddrack(q, mp, addr, (t_uscalar_t)addr_length);
	kmem_free(addr, addr_length);
	return (B_TRUE);
failed:
	rw_exit(&dsp->ds_lock);
	dlerrorack(q, mp, DL_PHYS_ADDR_REQ, dl_err, 0);
	return (B_FALSE);
}

/*
 * DL_SET_PHYS_ADDR_REQ
 */
static boolean_t
proto_setphysaddr_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_set_phys_addr_req_t *dlp = (dl_set_phys_addr_req_t *)udlp;
	int		err = 0;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;

	/*
	 * Because control message processing is serialized, we don't need
	 * to hold any locks to read any fields of dsp; we only need ds_lock
	 * to update the ds_passivestate field.
	 */
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

	if (dsp->ds_passivestate == DLD_UNINITIALIZED &&
	    !dls_active_set(dsp->ds_dc)) {
		dl_err = DL_SYSERR;
		err = EBUSY;
		goto failed;
	}

	err = mac_unicst_set(dsp->ds_mh, mp->b_rptr + dlp->dl_addr_offset);
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

		if (dsp->ds_passivestate == DLD_UNINITIALIZED)
			dls_active_clear(dsp->ds_dc);

		goto failed;
	}

	rw_enter(&dsp->ds_lock, RW_WRITER);
	if (dsp->ds_passivestate == DLD_UNINITIALIZED)
		dsp->ds_passivestate = DLD_ACTIVE;
	rw_exit(&dsp->ds_lock);

	dlokack(q, mp, DL_SET_PHYS_ADDR_REQ);
	return (B_TRUE);
failed:
	dlerrorack(q, mp, DL_SET_PHYS_ADDR_REQ, dl_err, (t_uscalar_t)err);
	return (B_FALSE);
}

/*
 * DL_UDQOS_REQ
 */
static boolean_t
proto_udqos_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_udqos_req_t *dlp = (dl_udqos_req_t *)udlp;
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

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	rw_enter(&dsp->ds_lock, RW_WRITER);
	dsp->ds_pri = selp->dl_priority;
	rw_exit(&dsp->ds_lock);

	dlokack(q, mp, DL_UDQOS_REQ);
	return (B_TRUE);
failed:
	dlerrorack(q, mp, DL_UDQOS_REQ, dl_err, 0);
	return (B_FALSE);
}

static boolean_t
check_ip_above(queue_t *q)
{
	queue_t		*next_q;
	boolean_t	ret = B_TRUE;

	claimstr(q);
	next_q = q->q_next;
	if (strcmp(next_q->q_qinfo->qi_minfo->mi_idname, "ip") != 0)
		ret = B_FALSE;
	releasestr(q);
	return (ret);
}

/*
 * DL_CAPABILITY_REQ
 */
/*ARGSUSED*/
static boolean_t
proto_capability_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_capability_req_t *dlp = (dl_capability_req_t *)udlp;
	dl_capability_sub_t *sp;
	size_t		size, len;
	offset_t	off, end;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;

	rw_enter(&dsp->ds_lock, RW_WRITER);

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
		/* callee drops lock */
		return (proto_capability_advertise(dsp, mp));
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

		/*
		 * Large segment offload. (LSO)
		 */
		case DL_CAPAB_LSO: {
			dl_capab_lso_t *lsop;
			dl_capab_lso_t lso;

			lsop = (dl_capab_lso_t *)&sp[1];
			/*
			 * Copy for alignment.
			 */
			bcopy(lsop, &lso, sizeof (dl_capab_lso_t));
			dlcapabsetqid(&(lso.lso_mid), dsp->ds_rq);
			bcopy(&lso, lsop, sizeof (dl_capab_lso_t));
			break;
		}

		/*
		 * IP polling interface.
		 */
		case DL_CAPAB_POLL: {
			dl_capab_dls_t *pollp;
			dl_capab_dls_t	poll;

			pollp = (dl_capab_dls_t *)&sp[1];
			/*
			 * Copy for alignment.
			 */
			bcopy(pollp, &poll, sizeof (dl_capab_dls_t));

			switch (poll.dls_flags) {
			default:
				/*FALLTHRU*/
			case POLL_DISABLE:
				proto_poll_disable(dsp);
				break;

			case POLL_ENABLE:
				ASSERT(!(dld_opt & DLD_OPT_NO_POLL));

				/*
				 * Make sure polling is disabled.
				 */
				proto_poll_disable(dsp);

				/*
				 * Note that only IP should enable POLL.
				 */
				if (check_ip_above(dsp->ds_rq) &&
				    proto_poll_enable(dsp, &poll)) {
					bzero(&poll, sizeof (dl_capab_dls_t));
					poll.dls_flags = POLL_ENABLE;
				} else {
					bzero(&poll, sizeof (dl_capab_dls_t));
					poll.dls_flags = POLL_DISABLE;
				}
				break;
			}

			dlcapabsetqid(&(poll.dls_mid), dsp->ds_rq);
			bcopy(&poll, pollp, sizeof (dl_capab_dls_t));
			break;
		}
		case DL_CAPAB_SOFT_RING: {
			dl_capab_dls_t *soft_ringp;
			dl_capab_dls_t soft_ring;

			soft_ringp = (dl_capab_dls_t *)&sp[1];
			/*
			 * Copy for alignment.
			 */
			bcopy(soft_ringp, &soft_ring,
			    sizeof (dl_capab_dls_t));

			switch (soft_ring.dls_flags) {
			default:
				/*FALLTHRU*/
			case SOFT_RING_DISABLE:
				proto_soft_ring_disable(dsp);
				break;

			case SOFT_RING_ENABLE:
				ASSERT(!(dld_opt & DLD_OPT_NO_SOFTRING));
				/*
				 * Make sure soft_ring is disabled.
				 */
				proto_soft_ring_disable(dsp);

				/*
				 * Note that only IP can enable soft ring.
				 */
				if (check_ip_above(dsp->ds_rq) &&
				    proto_soft_ring_enable(dsp, &soft_ring)) {
					bzero(&soft_ring,
					    sizeof (dl_capab_dls_t));
					soft_ring.dls_flags = SOFT_RING_ENABLE;
				} else {
					bzero(&soft_ring,
					    sizeof (dl_capab_dls_t));
					soft_ring.dls_flags = SOFT_RING_DISABLE;
				}
				break;
			}

			dlcapabsetqid(&(soft_ring.dls_mid), dsp->ds_rq);
			bcopy(&soft_ring, soft_ringp,
			    sizeof (dl_capab_dls_t));
			break;
		}
		default:
			break;
		}

		off += size;
	}
	rw_exit(&dsp->ds_lock);
	qreply(q, mp);
	return (B_TRUE);
failed:
	rw_exit(&dsp->ds_lock);
	dlerrorack(q, mp, DL_CAPABILITY_REQ, dl_err, 0);
	return (B_FALSE);
}

/*
 * DL_NOTIFY_REQ
 */
static boolean_t
proto_notify_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_notify_req_t	*dlp = (dl_notify_req_t *)udlp;
	t_uscalar_t	dl_err;
	queue_t		*q = dsp->ds_wq;
	uint_t		note =
	    DL_NOTE_PROMISC_ON_PHYS |
	    DL_NOTE_PROMISC_OFF_PHYS |
	    DL_NOTE_PHYS_ADDR |
	    DL_NOTE_LINK_UP |
	    DL_NOTE_LINK_DOWN |
	    DL_NOTE_CAPAB_RENEG |
	    DL_NOTE_SPEED;

	rw_enter(&dsp->ds_lock, RW_WRITER);

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
	rw_exit(&dsp->ds_lock);
	/*
	 * The ACK carries all notifications regardless of which set is
	 * being enabled.
	 */
	dlnotifyack(q, mp, note);

	/*
	 * Solicit DL_NOTIFY_IND messages for each enabled notification.
	 */
	rw_enter(&dsp->ds_lock, RW_READER);
	if (dsp->ds_notifications != 0) {
		rw_exit(&dsp->ds_lock);
		dld_str_notify_ind(dsp);
	} else {
		rw_exit(&dsp->ds_lock);
	}
	return (B_TRUE);
failed:
	rw_exit(&dsp->ds_lock);
	dlerrorack(q, mp, DL_NOTIFY_REQ, dl_err, 0);
	return (B_FALSE);
}

/*
 * DL_UNITDATA_REQ
 */
void
dld_wput_proto_data(dld_str_t *dsp, mblk_t *mp)
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

	if (MBLKL(mp) < sizeof (dl_unitdata_req_t) || mp->b_cont == NULL) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

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

	if (size > dsp->ds_mip->mi_sdu_max)
		goto baddata;

	/*
	 * Build a packet header.
	 */
	if ((bp = dls_header(dsp->ds_dc, addr, sap, dlp->dl_priority.dl_max,
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
	dld_tx_single(dsp, bp);
	return;
failed:
	dlerrorack(q, mp, DL_UNITDATA_REQ, dl_err, 0);
	return;

baddata:
	dluderrorind(q, mp, (void *)addr, len, DL_BADDATA, 0);
}

/*
 * DL_PASSIVE_REQ
 */
/* ARGSUSED */
static boolean_t
proto_passive_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	t_uscalar_t dl_err;

	/*
	 * READER lock is enough because ds_passivestate can only be changed
	 * as the result of non-data message processing.
	 */
	rw_enter(&dsp->ds_lock, RW_READER);

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
	rw_exit(&dsp->ds_lock);
	dlokack(dsp->ds_wq, mp, DL_PASSIVE_REQ);
	return (B_TRUE);
failed:
	rw_exit(&dsp->ds_lock);
	dlerrorack(dsp->ds_wq, mp, DL_PASSIVE_REQ, dl_err, 0);
	return (B_FALSE);
}

/*
 * Catch-all handler.
 */
static boolean_t
proto_req(dld_str_t *dsp, union DL_primitives *dlp, mblk_t *mp)
{
	dlerrorack(dsp->ds_wq, mp, dlp->dl_primitive, DL_UNSUPPORTED, 0);
	return (B_FALSE);
}

static void
proto_poll_disable(dld_str_t *dsp)
{
	mac_handle_t	mh;

	ASSERT(RW_WRITE_HELD(&dsp->ds_lock));

	if (!dsp->ds_polling)
		return;

	/*
	 * It should be impossible to enable raw mode if polling is turned on.
	 */
	ASSERT(dsp->ds_mode != DLD_RAW);

	/*
	 * Reset the resource_add callback.
	 */
	mh = dls_mac(dsp->ds_dc);
	mac_resource_set(mh, NULL, NULL);
	mac_resources(mh);

	/*
	 * Set receive function back to default.
	 */
	dls_rx_set(dsp->ds_dc, (dsp->ds_mode == DLD_FASTPATH) ?
	    dld_str_rx_fastpath : dld_str_rx_unitdata, dsp);

	/*
	 * Note that polling is disabled.
	 */
	dsp->ds_polling = B_FALSE;
}

static boolean_t
proto_poll_enable(dld_str_t *dsp, dl_capab_dls_t *pollp)
{
	mac_handle_t	mh;

	ASSERT(RW_WRITE_HELD(&dsp->ds_lock));
	ASSERT(!dsp->ds_polling);

	/*
	 * We cannot enable polling if raw mode
	 * has been enabled.
	 */
	if (dsp->ds_mode == DLD_RAW)
		return (B_FALSE);

	mh = dls_mac(dsp->ds_dc);

	/*
	 * Register resources.
	 */
	mac_resource_set(mh, (mac_resource_add_t)pollp->dls_ring_add,
	    (void *)pollp->dls_rx_handle);

	mac_resources(mh);

	/*
	 * Set the upstream receive function.
	 */
	dls_rx_set(dsp->ds_dc, (dls_rx_t)pollp->dls_rx,
	    (void *)pollp->dls_rx_handle);

	/*
	 * Note that polling is enabled. This prevents further DLIOCHDRINFO
	 * ioctls from overwriting the receive function pointer.
	 */
	dsp->ds_polling = B_TRUE;
	return (B_TRUE);
}

static void
proto_soft_ring_disable(dld_str_t *dsp)
{
	ASSERT(RW_WRITE_HELD(&dsp->ds_lock));

	if (!dsp->ds_soft_ring)
		return;

	/*
	 * It should be impossible to enable raw mode if soft_ring is turned on.
	 */
	ASSERT(dsp->ds_mode != DLD_RAW);
	proto_change_soft_ring_fanout(dsp, SOFT_RING_NONE);
	/*
	 * Note that fanout is disabled.
	 */
	dsp->ds_soft_ring = B_FALSE;
}

static boolean_t
proto_soft_ring_enable(dld_str_t *dsp, dl_capab_dls_t *soft_ringp)
{
	ASSERT(RW_WRITE_HELD(&dsp->ds_lock));
	ASSERT(!dsp->ds_soft_ring);

	/*
	 * We cannot enable soft_ring if raw mode
	 * has been enabled.
	 */
	if (dsp->ds_mode == DLD_RAW)
		return (B_FALSE);

	if (dls_soft_ring_enable(dsp->ds_dc, soft_ringp) == B_FALSE)
		return (B_FALSE);

	dsp->ds_soft_ring = B_TRUE;
	return (B_TRUE);
}

static void
proto_change_soft_ring_fanout(dld_str_t *dsp, int type)
{
	dls_channel_t	dc = dsp->ds_dc;

	if (type == SOFT_RING_NONE) {
		dls_rx_set(dc, (dsp->ds_mode == DLD_FASTPATH) ?
		    dld_str_rx_fastpath : dld_str_rx_unitdata, dsp);
	} else if (type != SOFT_RING_NONE) {
		dls_rx_set(dc, (dls_rx_t)dls_soft_ring_fanout, dc);
	}
}

/*
 * DL_CAPABILITY_ACK/DL_ERROR_ACK
 */
static boolean_t
proto_capability_advertise(dld_str_t *dsp, mblk_t *mp)
{
	dl_capability_ack_t	*dlap;
	dl_capability_sub_t	*dlsp;
	size_t			subsize;
	dl_capab_dls_t		poll;
	dl_capab_dls_t		soft_ring;
	dl_capab_hcksum_t	hcksum;
	dl_capab_lso_t		lso;
	dl_capab_zerocopy_t	zcopy;
	uint8_t			*ptr;
	queue_t			*q = dsp->ds_wq;
	mblk_t			*mp1;
	boolean_t		is_vlan = (dsp->ds_vid != VLAN_ID_NONE);
	boolean_t		poll_capable = B_FALSE;
	boolean_t		soft_ring_capable = B_FALSE;
	boolean_t		hcksum_capable = B_FALSE;
	boolean_t		zcopy_capable = B_FALSE;
	boolean_t		lso_capable = B_FALSE;
	mac_capab_lso_t		mac_lso;

	ASSERT(RW_WRITE_HELD(&dsp->ds_lock));

	/*
	 * Initially assume no capabilities.
	 */
	subsize = 0;

	/*
	 * Check if soft ring can be enabled on this interface. Note that we
	 * do not enable softring on any legacy drivers, because doing that
	 * would hurt the performance if the legacy driver has its own taskq
	 * implementation. Further, most high-performance legacy drivers do
	 * have their own taskq implementation.
	 *
	 * If advertising DL_CAPAB_SOFT_RING has not been explicitly disabled,
	 * reserve space for that capability.
	 */
	if (!mac_is_legacy(dsp->ds_mh) && !(dld_opt & DLD_OPT_NO_SOFTRING)) {
		soft_ring_capable = B_TRUE;
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_dls_t);
	}

	/*
	 * Check if polling can be enabled on this interface.
	 * If advertising DL_CAPAB_POLL has not been explicitly disabled
	 * then reserve space for that capability.
	 */
	if (mac_capab_get(dsp->ds_mh, MAC_CAPAB_POLL, NULL) &&
	    !(dld_opt & DLD_OPT_NO_POLL) && !is_vlan) {
		poll_capable = B_TRUE;
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_dls_t);
	}

	/*
	 * Check if checksum offload is supported on this MAC.  Don't
	 * advertise DL_CAPAB_HCKSUM if the underlying MAC is VLAN incapable,
	 * since it might not be able to do the hardware checksum offload
	 * with the correct offset.
	 */
	bzero(&hcksum, sizeof (dl_capab_hcksum_t));
	if ((!is_vlan || (!mac_capab_get(dsp->ds_mh, MAC_CAPAB_NO_NATIVEVLAN,
	    NULL))) && mac_capab_get(dsp->ds_mh, MAC_CAPAB_HCKSUM,
	    &hcksum.hcksum_txflags)) {
		if (hcksum.hcksum_txflags != 0) {
			hcksum_capable = B_TRUE;
			subsize += sizeof (dl_capability_sub_t) +
			    sizeof (dl_capab_hcksum_t);
		}
	}

	/*
	 * Check if LSO is supported on this MAC, then reserve space for
	 * the DL_CAPAB_LSO capability.
	 */
	if (mac_capab_get(dsp->ds_mh, MAC_CAPAB_LSO, &mac_lso)) {
		lso_capable = B_TRUE;
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_lso_t);
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
	 * If there are no capabilities to advertise or if we
	 * can't allocate a response, send a DL_ERROR_ACK.
	 */
	if ((mp1 = reallocb(mp,
	    sizeof (dl_capability_ack_t) + subsize, 0)) == NULL) {
		rw_exit(&dsp->ds_lock);
		dlerrorack(q, mp, DL_CAPABILITY_REQ, DL_NOTSUPPORTED, 0);
		return (B_FALSE);
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
	 * IP polling interface.
	 */
	if (poll_capable) {
		/*
		 * Attempt to disable just in case this is a re-negotiation;
		 * READER lock is enough because ds_polling can only be
		 * changed as the result of non-data message processing.
		 */
		proto_poll_disable(dsp);

		dlsp = (dl_capability_sub_t *)ptr;

		dlsp->dl_cap = DL_CAPAB_POLL;
		dlsp->dl_length = sizeof (dl_capab_dls_t);
		ptr += sizeof (dl_capability_sub_t);

		bzero(&poll, sizeof (dl_capab_dls_t));
		poll.dls_version = POLL_VERSION_1;
		poll.dls_flags = POLL_CAPABLE;
		poll.dls_tx_handle = (uintptr_t)dsp;
		poll.dls_tx = (uintptr_t)str_mdata_fastpath_put;
		dlcapabsetqid(&(poll.dls_mid), dsp->ds_rq);
		bcopy(&poll, ptr, sizeof (dl_capab_dls_t));
		ptr += sizeof (dl_capab_dls_t);
	}


	if (soft_ring_capable) {
		dlsp = (dl_capability_sub_t *)ptr;

		dlsp->dl_cap = DL_CAPAB_SOFT_RING;
		dlsp->dl_length = sizeof (dl_capab_dls_t);
		ptr += sizeof (dl_capability_sub_t);

		bzero(&soft_ring, sizeof (dl_capab_dls_t));
		soft_ring.dls_version = SOFT_RING_VERSION_1;
		soft_ring.dls_flags = SOFT_RING_CAPABLE;
		soft_ring.dls_tx_handle = (uintptr_t)dsp;
		soft_ring.dls_tx = (uintptr_t)str_mdata_fastpath_put;
		soft_ring.dls_ring_change_status =
		    (uintptr_t)proto_change_soft_ring_fanout;
		soft_ring.dls_ring_bind = (uintptr_t)soft_ring_bind;
		soft_ring.dls_ring_unbind = (uintptr_t)soft_ring_unbind;

		dlcapabsetqid(&(soft_ring.dls_mid), dsp->ds_rq);
		bcopy(&soft_ring, ptr, sizeof (dl_capab_dls_t));
		ptr += sizeof (dl_capab_dls_t);
	}

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
	 * Large segment offload. (LSO)
	 */
	if (lso_capable) {
		dlsp = (dl_capability_sub_t *)ptr;

		dlsp->dl_cap = DL_CAPAB_LSO;
		dlsp->dl_length = sizeof (dl_capab_lso_t);
		ptr += sizeof (dl_capability_sub_t);

		lso.lso_version = LSO_VERSION_1;
		lso.lso_flags = mac_lso.lso_flags;
		lso.lso_max = mac_lso.lso_basic_tcp_ipv4.lso_max;

		/* Simply enable LSO with DLD */
		dsp->ds_lso = B_TRUE;
		dsp->ds_lso_max = lso.lso_max;

		dlcapabsetqid(&(lso.lso_mid), dsp->ds_rq);
		bcopy(&lso, ptr, sizeof (dl_capab_lso_t));
		ptr += sizeof (dl_capab_lso_t);
	} else {
		dsp->ds_lso = B_FALSE;
		dsp->ds_lso_max = 0;
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

	ASSERT(ptr == mp->b_rptr + sizeof (dl_capability_ack_t) + subsize);

	rw_exit(&dsp->ds_lock);
	qreply(q, mp);
	return (B_TRUE);
}

/*
 * Disable any enabled capabilities.
 */
void
dld_capabilities_disable(dld_str_t *dsp)
{
	if (dsp->ds_polling)
		proto_poll_disable(dsp);

	if (dsp->ds_soft_ring)
		proto_soft_ring_disable(dsp);
}
