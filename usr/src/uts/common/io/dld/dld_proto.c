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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/dlpi.h>
#include <netinet/in.h>
#include <sys/sdt.h>
#include <sys/strsubr.h>
#include <sys/vlan.h>
#include <sys/mac.h>
#include <sys/dls.h>
#include <sys/dld.h>
#include <sys/dld_impl.h>

typedef boolean_t proto_reqfunc_t(dld_str_t *, union DL_primitives *, mblk_t *);

static proto_reqfunc_t proto_info_req, proto_attach_req, proto_detach_req,
    proto_bind_req, proto_unbind_req, proto_promiscon_req, proto_promiscoff_req,
    proto_enabmulti_req, proto_disabmulti_req, proto_physaddr_req,
    proto_setphysaddr_req, proto_udqos_req, proto_req, proto_capability_req,
    proto_notify_req, proto_unitdata_req, proto_passive_req;

static void		proto_excl(queue_t *, mblk_t *);
static void		proto_info_ack(dld_str_t *, mblk_t *);
static void		proto_attach_ack(dld_str_t *, mblk_t *, int);
static void		proto_detach_ack(dld_str_t *, mblk_t *);
static void		proto_bind_ack(dld_str_t *, mblk_t *, int);
static void		proto_unbind_ack(dld_str_t *, mblk_t *);
static void		proto_promiscon_ack(dld_str_t *, mblk_t *, int);
static void		proto_promiscoff_ack(dld_str_t *, mblk_t *, int);
static void		proto_enabmulti_ack(dld_str_t *, mblk_t *, int);
static void		proto_disabmulti_ack(dld_str_t *, mblk_t *, int);
static void		proto_setphysaddr_ack(dld_str_t *, mblk_t *, int);
static void		proto_physaddr_ack(dld_str_t *, mblk_t *, t_uscalar_t);
static void		proto_udqos_ack(dld_str_t *, mblk_t *);
static void		proto_poll_disable(dld_str_t *);
static boolean_t	proto_poll_enable(dld_str_t *, dl_capab_poll_t *);
static void		proto_capability_ack(dld_str_t *, mblk_t *);
static void		proto_capability_enable(dld_str_t *, mblk_t *);
static void		proto_notify_ack(dld_str_t *, mblk_t *, uint_t,
    uint_t);

#define	DL_SOLARIS	0x100

/*
 * M_PROTO/M_PCPROTO request handlers
 */

typedef struct proto_req_info {
	t_uscalar_t	pri_prim;
	const char	*pri_txt;
	boolean_t	pri_needexcl;
	boolean_t	pri_active;
	proto_reqfunc_t	*pri_fn;
} proto_req_info_t;

static proto_req_info_t	proto_ri[] = {
	{ DL_INFO_REQ, "DL_INFO_REQ", B_FALSE, B_FALSE, proto_info_req },
	{ DL_BIND_REQ, "DL_BIND_REQ", B_TRUE, B_TRUE, proto_bind_req },
	{ DL_UNBIND_REQ, "DL_UNBIND_REQ", B_TRUE, B_FALSE, proto_unbind_req },
	{ DL_INFO_ACK, "DL_INFO_ACK", B_FALSE, B_FALSE, proto_req },
	{ DL_BIND_ACK, "DL_BIND_ACK", B_FALSE, B_FALSE, proto_req },
	{ DL_ERROR_ACK, "DL_ERROR_ACK", B_FALSE, B_FALSE, proto_req },
	{ DL_OK_ACK, "DL_OK_ACK", B_FALSE, B_FALSE, proto_req },
	{ DL_UNITDATA_REQ, "DL_UNITDATA_REQ", B_FALSE, B_FALSE,
    proto_unitdata_req },
	{ DL_UNITDATA_IND, "DL_UNITDATA_IND", B_FALSE, B_FALSE, proto_req },
	{ DL_UDERROR_IND, "DL_UDERROR_IND", B_FALSE, B_FALSE, proto_req },
	{ DL_UDQOS_REQ, "DL_UDQOS_REQ", B_TRUE, B_FALSE, proto_udqos_req },
	{ DL_ATTACH_REQ, "DL_ATTACH_REQ", B_TRUE, B_FALSE, proto_attach_req },
	{ DL_DETACH_REQ, "DL_DETACH_REQ", B_TRUE, B_FALSE, proto_detach_req },
	{ DL_CONNECT_REQ, "DL_CONNECT_REQ", B_FALSE, B_FALSE, proto_req },
	{ DL_CONNECT_IND, "DL_CONNECT_IND", B_FALSE, B_FALSE, proto_req },
	{ DL_CONNECT_RES, "DL_CONNECT_RES", B_FALSE, B_FALSE, proto_req },
	{ DL_CONNECT_CON, "DL_CONNECT_CON", B_FALSE, B_FALSE, proto_req },
	{ DL_TOKEN_REQ, "DL_TOKEN_REQ", B_FALSE, B_FALSE, proto_req },
	{ DL_TOKEN_ACK, "DL_TOKEN_ACK", B_FALSE, B_FALSE, proto_req },
	{ DL_DISCONNECT_REQ, "DL_DISCONNECT_REQ", B_FALSE, B_FALSE, proto_req },
	{ DL_DISCONNECT_IND, "DL_DISCONNECT_IND", B_FALSE, B_FALSE, proto_req },
	{ DL_SUBS_UNBIND_REQ, "DL_SUBS_UNBIND_REQ", B_FALSE, B_FALSE,
    proto_req },
	{ 0x16, "undefined", B_FALSE, B_FALSE, proto_req },
	{ DL_RESET_REQ, "DL_RESET_REQ", B_FALSE, B_FALSE, proto_req },
	{ DL_RESET_IND, "DL_RESET_IND", B_FALSE, B_FALSE, proto_req },
	{ DL_RESET_RES, "DL_RESET_RES", B_FALSE, B_FALSE, proto_req },
	{ DL_RESET_CON, "DL_RESET_CON", B_FALSE, B_FALSE, proto_req },
	{ DL_SUBS_BIND_REQ, "DL_SUBS_BIND_REQ", B_FALSE, B_FALSE, proto_req },
	{ DL_SUBS_BIND_ACK, "DL_SUBS_BIND_ACK", B_FALSE, B_FALSE, proto_req },
	{ DL_ENABMULTI_REQ, "DL_ENABMULTI_REQ", B_TRUE, B_TRUE,
    proto_enabmulti_req },
	{ DL_DISABMULTI_REQ, "DL_DISABMULTI_REQ", B_TRUE, B_FALSE,
    proto_disabmulti_req },
	{ DL_PROMISCON_REQ, "DL_PROMISCON_REQ", B_TRUE, B_TRUE,
    proto_promiscon_req },
	{ DL_PROMISCOFF_REQ, "DL_PROMISCOFF_REQ", B_TRUE, B_FALSE,
    proto_promiscoff_req },
	{ DL_DATA_ACK_REQ, "DL_DATA_ACK_REQ", B_FALSE, B_FALSE, proto_req },
	{ DL_DATA_ACK_IND, "DL_DATA_ACK_IND", B_FALSE, B_FALSE, proto_req },
	{ DL_DATA_ACK_STATUS_IND, "DL_DATA_ACK_STATUS_IND", B_FALSE, B_FALSE,
    proto_req },
	{ DL_REPLY_REQ, "DL_REPLY_REQ", B_FALSE, B_FALSE, proto_req },
	{ DL_REPLY_IND, "DL_REPLY_IND", B_FALSE, B_FALSE, proto_req },
	{ DL_REPLY_STATUS_IND, "DL_REPLY_STATUS_IND", B_FALSE, B_FALSE,
    proto_req },
	{ DL_REPLY_UPDATE_REQ, "DL_REPLY_UPDATE_REQ", B_FALSE, B_FALSE,
    proto_req },
	{ DL_REPLY_UPDATE_STATUS_IND, "DL_REPLY_UPDATE_STATUS_IND", B_FALSE,
    B_FALSE, proto_req },
	{ DL_XID_REQ, "DL_XID_REQ", B_FALSE, B_FALSE, proto_req },
	{ DL_XID_IND, "DL_XID_IND", B_FALSE, B_FALSE, proto_req },
	{ DL_XID_RES, "DL_XID_RES", B_FALSE, B_FALSE, proto_req },
	{ DL_XID_CON, "DL_XID_CON", B_FALSE, B_FALSE, proto_req },
	{ DL_TEST_REQ, "DL_TEST_REQ", B_FALSE, B_FALSE, proto_req },
	{ DL_TEST_IND, "DL_TEST_IND", B_FALSE, B_FALSE, proto_req },
	{ DL_TEST_RES, "DL_TEST_RES", B_FALSE, B_FALSE, proto_req },
	{ DL_TEST_CON, "DL_TEST_CON", B_FALSE, B_FALSE, proto_req },
	{ DL_PHYS_ADDR_REQ, "DL_PHYS_ADDR_REQ", B_FALSE, B_FALSE,
    proto_physaddr_req },
	{ DL_PHYS_ADDR_ACK, "DL_PHYS_ADDR_ACK", B_FALSE, B_FALSE, proto_req },
	{ DL_SET_PHYS_ADDR_REQ, "DL_SET_PHYS_ADDR_REQ", B_TRUE, B_TRUE,
    proto_setphysaddr_req },
	{ DL_GET_STATISTICS_REQ, "DL_GET_STATISTICS_REQ", B_FALSE, B_FALSE,
    proto_req },
	{ DL_GET_STATISTICS_ACK, "DL_GET_STATISTICS_ACK", B_FALSE, B_FALSE,
    proto_req }
};

#define	PROTO_RI_COUNT	(sizeof (proto_ri) / sizeof (proto_ri[0]))

static proto_req_info_t	proto_sri[] = {
	{ DL_NOTIFY_REQ, "DL_NOTIFY_REQ", B_FALSE, B_FALSE, proto_notify_req },
	{ DL_NOTIFY_ACK, "DL_NOTIFY_ACK", B_FALSE, B_FALSE, proto_req },
	{ DL_NOTIFY_IND, "DL_NOTIFY_IND", B_FALSE, B_FALSE, proto_req },
	{ DL_AGGR_REQ, "DL_AGGR_REQ", B_FALSE, B_TRUE, proto_req },
	{ DL_AGGR_IND, "DL_AGGR_IND", B_FALSE, B_FALSE, proto_req },
	{ DL_UNAGGR_REQ, "DL_UNAGGR_REQ", B_FALSE, B_TRUE, proto_req },
	{ 0x106, "undefined", B_FALSE, B_FALSE, proto_req },
	{ 0x107, "undefined", B_FALSE, B_FALSE, proto_req },
	{ 0x108, "undefined", B_FALSE, B_FALSE, proto_req },
	{ 0x109, "undefined", B_FALSE, B_FALSE, proto_req },
	{ 0x10a, "undefined", B_FALSE, B_FALSE, proto_req },
	{ 0x10b, "undefined", B_FALSE, B_FALSE, proto_req },
	{ 0x10c, "undefined", B_FALSE, B_FALSE, proto_req },
	{ 0x10d, "undefined", B_FALSE, B_FALSE, proto_req },
	{ 0x10e, "undefined", B_FALSE, B_FALSE, proto_req },
	{ 0x10f, "undefined", B_FALSE, B_FALSE, proto_req },
	{ DL_CAPABILITY_REQ, "DL_CAPABILITY_REQ", B_FALSE, B_FALSE,
    proto_capability_req },
	{ DL_CAPABILITY_ACK, "DL_CAPABILITY_ACK", B_FALSE, B_FALSE, proto_req },
	{ DL_CONTROL_REQ, "DL_CONTROL_REQ", B_FALSE, B_TRUE, proto_req },
	{ DL_CONTROL_ACK, "DL_CONTROL_ACK", B_FALSE, B_FALSE, proto_req },
	{ DL_PASSIVE_REQ, "DL_PASSIVE_REQ", B_TRUE, B_FALSE, proto_passive_req }
};

#define	PROTO_SRI_COUNT	(sizeof (proto_sri) / sizeof (proto_sri[0]))

#define	DL_ACK_PENDING(state) \
	((state) == DL_ATTACH_PENDING || \
	(state) == DL_DETACH_PENDING || \
	(state) == DL_BIND_PENDING || \
	(state) == DL_UNBIND_PENDING)

/*
 * Process a DLPI protocol message. (Only ever called from put(9e)).
 */
void
dld_proto(dld_str_t *dsp, mblk_t *mp)
{
	union DL_primitives	*udlp;
	t_uscalar_t		prim;
	proto_req_info_t	*prip;
	boolean_t		success;

	if (MBLKL(mp) < sizeof (t_uscalar_t)) {
		freemsg(mp);
		return;
	}

	udlp = (union DL_primitives *)mp->b_rptr;
	prim = udlp->dl_primitive;

	/*
	 * Select the correct jump table.
	 */
	if (prim & DL_SOLARIS) {
		/*
		 * Entries in the 'solaris extensions' jump table
		 * have an extra bit in the primitive value. Clear it
		 * to do the lookup.
		 */
		prim &= ~DL_SOLARIS;

		/*
		 * Check the primitive is in range.
		 */
		if (prim >= PROTO_SRI_COUNT)
			goto unsupported;

		/*
		 * Grab the jump table entry.
		 */
		prip = &proto_sri[prim];

		/*
		 * OR the cleared bit back in to make the primitive valid
		 * again.
		 */
		prim |= DL_SOLARIS;
	} else {
		/*
		 * Check the primitive is in range.
		 */
		if (prim >= PROTO_RI_COUNT)
			goto unsupported;

		/*
		 * Grab the jump table entry.
		 */
		prip = &proto_ri[prim];
	}

	ASSERT(prip->pri_prim == prim);

	/*
	 * If this primitive causes the data-link channel used by this
	 * object to become active, then we need to notify dls.  Note that
	 * if we're already passive by having succesfully processed a
	 * DL_PASSIVE_REQ, then active primitives do not cause us to become
	 * active.
	 */
	if (prip->pri_active && dsp->ds_passivestate == DLD_UNINITIALIZED) {
		if (!dls_active_set(dsp->ds_dc)) {
			dlerrorack(dsp->ds_wq, mp, prim, DL_SYSERR, EBUSY);
			return;
		}
	}

	/*
	 * Check whether we need, and whether we have, exclusive access to
	 * the stream.
	 */
	if (prip->pri_needexcl) {
		/*
		 * We only have shared access and we need exclusive access.
		 */
		ASSERT(!PERIM_EXCL(dsp->ds_wq));

		/*
		 * Process via qwriter(9f).
		 */
		qwriter(dsp->ds_wq, mp, proto_excl, PERIM_INNER);
		return;
	}

	success = prip->pri_fn(dsp, udlp, mp);
	if (prip->pri_active && dsp->ds_passivestate == DLD_UNINITIALIZED) {
		if (success)
			dsp->ds_passivestate = DLD_ACTIVE;
		else
			dls_active_clear(dsp->ds_dc);
	}

	return;

unsupported:
	(void) proto_req(dsp, udlp, mp);
}

/*
 * Called via qwriter(9f).
 */
static void
proto_excl(queue_t *q, mblk_t *mp)
{
	dld_str_t		*dsp = q->q_ptr;
	union DL_primitives	*udlp;
	t_uscalar_t		prim;
	proto_req_info_t	*prip;
	boolean_t		success;

	ASSERT(MBLKL(mp) >= sizeof (t_uscalar_t));

	udlp = (union DL_primitives *)mp->b_rptr;
	prim = udlp->dl_primitive;

	/*
	 * Select the correct jump table.
	 */
	if (prim & DL_SOLARIS) {
		/*
		 * Entries in the 'solaris extensions' jump table
		 * have an extra bit in the primitive value. Clear it
		 * to do the lookup.
		 */
		prim &= ~DL_SOLARIS;

		/*
		 * Grab the jump table entry.
		 */
		ASSERT(prim < PROTO_SRI_COUNT);
		prip = &proto_sri[prim];

		/*
		 * OR the cleared bit back in to make the primitive valid
		 * again.
		 */
		prim |= DL_SOLARIS;
	} else {
		/*
		 * Grab the jump table entry.
		 */
		ASSERT(prim < PROTO_RI_COUNT);
		prip = &proto_ri[prim];
	}

	ASSERT(prip->pri_prim == prim);

	success = prip->pri_fn(dsp, udlp, mp);
	if (prip->pri_active && dsp->ds_passivestate == DLD_UNINITIALIZED) {
		if (success)
			dsp->ds_passivestate = DLD_ACTIVE;
		else
			dls_active_clear(dsp->ds_dc);
	}
}

/*
 * DL_INFO_REQ
 */
/*ARGSUSED*/
static boolean_t
proto_info_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	proto_info_ack(dsp, mp);
	return (B_TRUE);
}

/*
 * DL_ATTACH_REQ
 */
static boolean_t
proto_attach_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_attach_req_t		*dlp = (dl_attach_req_t *)udlp;
	t_scalar_t		index;
	dld_node_t		*dnp;
	dld_ppa_t		*dpp;
	int			err;

	ASSERT(PERIM_EXCL(dsp->ds_wq));

	if (dsp->ds_dlstate != DL_UNATTACHED) {
		dlerrorack(dsp->ds_wq, mp, DL_ATTACH_REQ, DL_OUTSTATE, 0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_attach_req_t)) {
		dlerrorack(dsp->ds_wq, mp, DL_ATTACH_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	index = dlp->dl_ppa;

	dnp = dsp->ds_dnp;
	ASSERT(dnp->dn_style == DL_STYLE2);

	if ((dpp = dld_node_ppa_find(dnp, index)) == NULL) {
		dlerrorack(dsp->ds_wq, mp, DL_ATTACH_REQ, DL_BADPPA, 0);
		return (B_FALSE);
	}

	dsp->ds_dlstate = DL_ATTACH_PENDING;

	err = dld_str_attach(dsp, dpp);
	proto_attach_ack(dsp, mp, err);
	return (err == 0);
}

/*
 * DL_DETACH_REQ
 */
/*ARGSUSED*/
static boolean_t
proto_detach_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	ASSERT(PERIM_EXCL(dsp->ds_wq));

	if (dsp->ds_dlstate != DL_UNBOUND) {
		dlerrorack(dsp->ds_wq, mp, DL_DETACH_REQ, DL_OUTSTATE, 0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_detach_req_t)) {
		dlerrorack(dsp->ds_wq, mp, DL_DETACH_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	if ((dsp->ds_dnp)->dn_style == DL_STYLE1) {
		dlerrorack(dsp->ds_wq, mp, DL_DETACH_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	dsp->ds_dlstate = DL_DETACH_PENDING;

	dld_str_detach(dsp);
	proto_detach_ack(dsp, mp);
	return (B_TRUE);
}

/*
 * DL_BIND_REQ
 */
static boolean_t
proto_bind_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_bind_req_t		*dlp = (dl_bind_req_t *)udlp;
	int			err;

	ASSERT(PERIM_EXCL(dsp->ds_wq));

	if (dsp->ds_dlstate != DL_UNBOUND) {
		dlerrorack(dsp->ds_wq, mp, DL_BIND_REQ, DL_OUTSTATE, 0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_bind_req_t)) {
		dlerrorack(dsp->ds_wq, mp, DL_BIND_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	if (dlp->dl_xidtest_flg != 0) {
		dlerrorack(dsp->ds_wq, mp, DL_BIND_REQ, DL_NOAUTO, 0);
		return (B_FALSE);
	}

	if (dlp->dl_service_mode != DL_CLDLS) {
		dlerrorack(dsp->ds_wq, mp, DL_BIND_REQ, DL_UNSUPPORTED, 0);
		return (B_FALSE);
	}

	dsp->ds_dlstate = DL_BIND_PENDING;

	/*
	 * Set the receive callback.
	 */
	dls_rx_set(dsp->ds_dc, dld_str_rx_unitdata, (void *)dsp);

	/*
	 * Bind the channel such that it can receive packets.
	 */
	dsp->ds_sap = dlp->dl_sap;
	err = dls_bind(dsp->ds_dc, dlp->dl_sap);

	proto_bind_ack(dsp, mp, err);
	return (err == 0);
}

/*
 * DL_UNBIND_REQ
 */
/*ARGSUSED*/
static boolean_t
proto_unbind_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	ASSERT(PERIM_EXCL(dsp->ds_wq));

	if (dsp->ds_dlstate != DL_IDLE) {
		dlerrorack(dsp->ds_wq, mp, DL_UNBIND_REQ, DL_OUTSTATE, 0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_unbind_req_t)) {
		dlerrorack(dsp->ds_wq, mp, DL_BIND_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	dsp->ds_dlstate = DL_UNBIND_PENDING;

	/*
	 * Flush any remaining packets scheduled for transmission.
	 */
	flushq(dsp->ds_wq, FLUSHALL);

	/*
	 * Reset the M_DATA handler.
	 */
	dld_str_tx_drop(dsp);

	/*
	 * Unbind the channel to stop packets being received.
	 */
	dls_unbind(dsp->ds_dc);

	/*
	 * Disable polling mode, if it is enabled.
	 */
	proto_poll_disable(dsp);

	/*
	 * Clear the receive callback.
	 */
	dls_rx_set(dsp->ds_dc, NULL, NULL);

	/*
	 * Set the mode back to the default (unitdata).
	 */
	dsp->ds_mode = DLD_UNITDATA;

	proto_unbind_ack(dsp, mp);
	return (B_TRUE);
}

/*
 * DL_PROMISCON_REQ
 */
static boolean_t
proto_promiscon_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_promiscon_req_t	*dlp = (dl_promiscon_req_t *)udlp;
	int			err;

	ASSERT(PERIM_EXCL(dsp->ds_wq));

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dlerrorack(dsp->ds_wq, mp, DL_PROMISCON_REQ, DL_OUTSTATE, 0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_promiscon_req_t)) {
		dlerrorack(dsp->ds_wq, mp, DL_PROMISCON_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	switch (dlp->dl_level) {
	case DL_PROMISC_SAP:
		dsp->ds_promisc |= DLS_PROMISC_SAP;
		break;

	case DL_PROMISC_MULTI:
		dsp->ds_promisc |= DLS_PROMISC_MULTI;
		break;

	case DL_PROMISC_PHYS:
		dsp->ds_promisc |= DLS_PROMISC_PHYS;
		break;

	default:
		dlerrorack(dsp->ds_wq, mp, DL_PROMISCON_REQ, DL_NOTSUPPORTED,
		    0);
		return (B_FALSE);
	}

	/*
	 * Adjust channel promiscuity.
	 */
	err = dls_promisc(dsp->ds_dc, dsp->ds_promisc);
	proto_promiscon_ack(dsp, mp, err);
	return (err == 0);
}

/*
 * DL_PROMISCOFF_REQ
 */
static boolean_t
proto_promiscoff_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_promiscoff_req_t	*dlp = (dl_promiscoff_req_t *)udlp;
	int			err;

	ASSERT(PERIM_EXCL(dsp->ds_wq));

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dlerrorack(dsp->ds_wq, mp, DL_PROMISCOFF_REQ, DL_OUTSTATE, 0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_promiscoff_req_t)) {
		dlerrorack(dsp->ds_wq, mp, DL_PROMISCOFF_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	switch (dlp->dl_level) {
	case DL_PROMISC_SAP:
		if (!(dsp->ds_promisc & DLS_PROMISC_SAP))
			goto notenab;

		dsp->ds_promisc &= ~DLS_PROMISC_SAP;
		break;

	case DL_PROMISC_MULTI:
		if (!(dsp->ds_promisc & DLS_PROMISC_MULTI))
			goto notenab;

		dsp->ds_promisc &= ~DLS_PROMISC_MULTI;
		break;

	case DL_PROMISC_PHYS:
		if (!(dsp->ds_promisc & DLS_PROMISC_PHYS))
			goto notenab;

		dsp->ds_promisc &= ~DLS_PROMISC_PHYS;
		break;

	default:
		dlerrorack(dsp->ds_wq, mp, DL_PROMISCOFF_REQ, DL_NOTSUPPORTED,
		    0);
		return (B_FALSE);
	}

	/*
	 * Adjust channel promiscuity.
	 */
	err = dls_promisc(dsp->ds_dc, dsp->ds_promisc);

	proto_promiscoff_ack(dsp, mp, err);
	return (err == 0);

notenab:
	dlerrorack(dsp->ds_wq, mp, DL_PROMISCOFF_REQ, DL_NOTENAB, 0);
	return (B_FALSE);
}

/*
 * DL_ENABMULTI_REQ
 */
static boolean_t
proto_enabmulti_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_enabmulti_req_t	*dlp = (dl_enabmulti_req_t *)udlp;
	int			err;

	ASSERT(PERIM_EXCL(dsp->ds_wq));

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dlerrorack(dsp->ds_wq, mp, DL_ENABMULTI_REQ, DL_OUTSTATE, 0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_enabmulti_req_t) ||
	    !MBLKIN(mp, dlp->dl_addr_offset, dlp->dl_addr_length) ||
	    dlp->dl_addr_length != dsp->ds_mip->mi_addr_length) {
		dlerrorack(dsp->ds_wq, mp, DL_ENABMULTI_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	err = dls_multicst_add(dsp->ds_dc, mp->b_rptr + dlp->dl_addr_offset);
	proto_enabmulti_ack(dsp, mp, err);
	return (err == 0);
}

/*
 * DL_DISABMULTI_REQ
 */
static boolean_t
proto_disabmulti_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_disabmulti_req_t	*dlp = (dl_disabmulti_req_t *)udlp;
	int			err;

	ASSERT(PERIM_EXCL(dsp->ds_wq));

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dlerrorack(dsp->ds_wq, mp, DL_DISABMULTI_REQ, DL_OUTSTATE, 0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_disabmulti_req_t) ||
	    !MBLKIN(mp, dlp->dl_addr_offset, dlp->dl_addr_length) ||
	    dlp->dl_addr_length != dsp->ds_mip->mi_addr_length) {
		dlerrorack(dsp->ds_wq, mp, DL_DISABMULTI_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	err = dls_multicst_remove(dsp->ds_dc, mp->b_rptr + dlp->dl_addr_offset);
	proto_disabmulti_ack(dsp, mp, err);
	return (err == 0);
}

/*
 * DL_PHYS_ADDR_REQ
 */
static boolean_t
proto_physaddr_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_phys_addr_req_t	*dlp = (dl_phys_addr_req_t *)udlp;

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dlerrorack(dsp->ds_wq, mp, DL_PHYS_ADDR_REQ, DL_OUTSTATE, 0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_phys_addr_req_t)) {
		dlerrorack(dsp->ds_wq, mp, DL_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	if (dlp->dl_addr_type != DL_CURR_PHYS_ADDR &&
	    dlp->dl_addr_type != DL_FACT_PHYS_ADDR) {
		dlerrorack(dsp->ds_wq, mp, DL_PHYS_ADDR_REQ, DL_UNSUPPORTED, 0);
		return (B_FALSE);
	}

	proto_physaddr_ack(dsp, mp, dlp->dl_addr_type);
	return (B_TRUE);
}

/*
 * DL_SET_PHYS_ADDR_REQ
 */
static boolean_t
proto_setphysaddr_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_set_phys_addr_req_t	*dlp = (dl_set_phys_addr_req_t *)udlp;
	int			err;

	ASSERT(PERIM_EXCL(dsp->ds_wq));

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dlerrorack(dsp->ds_wq, mp, DL_SET_PHYS_ADDR_REQ, DL_OUTSTATE,
		    0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_set_phys_addr_req_t) ||
	    !MBLKIN(mp, dlp->dl_addr_offset, dlp->dl_addr_length) ||
	    dlp->dl_addr_length != dsp->ds_mip->mi_addr_length) {
		dlerrorack(dsp->ds_wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADPRIM,
		    0);
		return (B_FALSE);
	}

	err = mac_unicst_set(dsp->ds_mh, mp->b_rptr + dlp->dl_addr_offset);
	proto_setphysaddr_ack(dsp, mp, err);
	return (err == 0);
}

/*
 * DL_UDQOS_REQ
 */
static boolean_t
proto_udqos_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_udqos_req_t		*dlp = (dl_udqos_req_t *)udlp;
	dl_qos_cl_sel1_t	*selp;
	int			off, len;

	ASSERT(PERIM_EXCL(dsp->ds_wq));

	off = dlp->dl_qos_offset;
	len = dlp->dl_qos_length;

	if (MBLKL(mp) < sizeof (dl_udqos_req_t) || !MBLKIN(mp, off, len)) {
		dlerrorack(dsp->ds_wq, mp, DL_UDQOS_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	selp = (dl_qos_cl_sel1_t *)(mp->b_rptr + off);
	if (selp->dl_qos_type != DL_QOS_CL_SEL1) {
		dlerrorack(dsp->ds_wq, mp, DL_UDQOS_REQ, DL_BADQOSTYPE, 0);
		return (B_FALSE);
	}

	if (dsp->ds_vid == VLAN_ID_NONE ||
	    selp->dl_priority > (1 << VLAN_PRI_SIZE) - 1 ||
	    selp->dl_priority < 0) {
		dlerrorack(dsp->ds_wq, mp, DL_UDQOS_REQ, DL_BADQOSPARAM, 0);
		return (B_FALSE);
	}

	dsp->ds_pri = selp->dl_priority;
	proto_udqos_ack(dsp, mp);
	return (B_TRUE);
}

/*
 * DL_CAPABILITY_REQ
 */
/*ARGSUSED*/
static boolean_t
proto_capability_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_capability_req_t	*dlp = (dl_capability_req_t *)udlp;

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dlerrorack(dsp->ds_wq, mp, DL_CAPABILITY_REQ, DL_OUTSTATE,
		    0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_capability_req_t)) {
		dlerrorack(dsp->ds_wq, mp, DL_CAPABILITY_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	/*
	 * This request is overloaded. If there are no requested capabilities
	 * then we just want to acknowledge with all the capabilities we
	 * support. Otherwise we enable the set of capabilities requested.
	 */
	if (dlp->dl_sub_length == 0) {
		proto_capability_ack(dsp, mp);
		return (B_TRUE);
	}

	if (!MBLKIN(mp, dlp->dl_sub_offset, dlp->dl_sub_length)) {
		dlerrorack(dsp->ds_wq, mp, DL_CAPABILITY_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	proto_capability_enable(dsp, mp);
	return (B_TRUE);
}

/*
 * DL_NOTIFY_REQ
 */
static boolean_t
proto_notify_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	dl_notify_req_t		*dlp = (dl_notify_req_t *)udlp;
	uint_t			notifications =
	    DL_NOTE_PROMISC_ON_PHYS |
	    DL_NOTE_PROMISC_OFF_PHYS |
	    DL_NOTE_PHYS_ADDR |
	    DL_NOTE_LINK_UP |
	    DL_NOTE_LINK_DOWN |
	    DL_NOTE_CAPAB_RENEG;

	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    DL_ACK_PENDING(dsp->ds_dlstate)) {
		dlerrorack(dsp->ds_wq, mp, DL_NOTIFY_REQ, DL_OUTSTATE,
		    0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_notify_req_t)) {
		dlerrorack(dsp->ds_wq, mp, DL_NOTIFY_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	if (dsp->ds_mip->mi_stat[MAC_STAT_IFSPEED])
		notifications |= DL_NOTE_SPEED;

	proto_notify_ack(dsp, mp, dlp->dl_notifications & notifications,
	    notifications);
	return (B_TRUE);
}

/*
 * DL_UINTDATA_REQ
 */
static boolean_t
proto_unitdata_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	queue_t			*q = dsp->ds_wq;
	dl_unitdata_req_t	*dlp = (dl_unitdata_req_t *)udlp;
	off_t			off;
	size_t			len;
	size_t			size;
	const uint8_t		*addr;
	uint16_t		sap;
	uint_t			addr_length;
	mblk_t			*bp;
	mblk_t			*cont;
	uint32_t		start;
	uint32_t		stuff;
	uint32_t		end;
	uint32_t		value;
	uint32_t		flags;

	if (dsp->ds_dlstate != DL_IDLE) {
		dlerrorack(q, mp, DL_UNITDATA_REQ, DL_OUTSTATE, 0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_unitdata_req_t) || mp->b_cont == NULL) {
		dlerrorack(q, mp, DL_UNITDATA_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	off = dlp->dl_dest_addr_offset;
	len = dlp->dl_dest_addr_length;

	if (!MBLKIN(mp, off, len) || !IS_P2ALIGNED(off, sizeof (uint16_t))) {
		dlerrorack(q, mp, DL_UNITDATA_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	addr_length = dsp->ds_mip->mi_addr_length;
	if (len != addr_length + sizeof (uint16_t))
		goto badaddr;

	addr = mp->b_rptr + off;
	sap = *(uint16_t *)(mp->b_rptr + off + addr_length);

	/*
	 * Check the length of the packet and the block types.
	 */
	size = 0;
	cont = mp->b_cont;
	for (bp = cont; bp != NULL; bp = bp->b_cont) {
		if (DB_TYPE(bp) != M_DATA)
			goto baddata;

		size += MBLKL(bp);
	}

	if (size > dsp->ds_mip->mi_sdu_max)
		goto baddata;

	/*
	 * Build a packet header.
	 */
	if ((bp = dls_header(dsp->ds_dc, addr, sap, dsp->ds_pri)) == NULL)
		goto badaddr;

	/*
	 * We no longer need the M_PROTO header, so free it.
	 */
	freeb(mp);

	/*
	 * Transfer the checksum offload information if it is present.
	 */
	hcksum_retrieve(cont, NULL, NULL, &start, &stuff, &end, &value,
	    &flags);
	(void) hcksum_assoc(bp, NULL, NULL, start, stuff, end, value, flags,
	    0);

	/*
	 * Link the payload onto the new header.
	 */
	ASSERT(bp->b_cont == NULL);
	bp->b_cont = cont;

	/*
	 * If something is already queued then we must queue to avoid
	 * re-ordering.
	 */
	if (q->q_first != NULL) {
		(void) putq(q, bp);
		return (B_TRUE);
	}

	/*
	 * Attempt to transmit the packet.
	 */
	if ((mp = dls_tx(dsp->ds_dc, bp)) != NULL) {
		noenable(q);
		while ((bp = mp) != NULL) {
			mp = mp->b_next;
			bp->b_next = NULL;
			(void) putq(q, bp);
		}
	}
	return (B_TRUE);

badaddr:
	dlerrorack(q, mp, DL_UNITDATA_REQ, DL_BADADDR, 0);
	return (B_FALSE);

baddata:
	dluderrorind(q, mp, (void *)addr, len, DL_BADDATA, 0);
	return (B_FALSE);
}

/*
 * DL_PASSIVE_REQ
 */
/* ARGSUSED */
static boolean_t
proto_passive_req(dld_str_t *dsp, union DL_primitives *udlp, mblk_t *mp)
{
	ASSERT(PERIM_EXCL(dsp->ds_wq));

	/*
	 * If we've already become active by issuing an active primitive,
	 * then it's too late to try to become passive.
	 */
	if (dsp->ds_passivestate == DLD_ACTIVE) {
		dlerrorack(dsp->ds_wq, mp, DL_PASSIVE_REQ, DL_OUTSTATE, 0);
		return (B_FALSE);
	}

	if (MBLKL(mp) < sizeof (dl_passive_req_t)) {
		dlerrorack(dsp->ds_wq, mp, DL_PASSIVE_REQ, DL_BADPRIM, 0);
		return (B_FALSE);
	}

	dsp->ds_passivestate = DLD_PASSIVE;
	dlokack(dsp->ds_wq, mp, DL_PASSIVE_REQ);
	return (B_TRUE);
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

typedef struct dl_info_ack_wrapper {
	dl_info_ack_t		dl_info;
	uint8_t			dl_addr[MAXADDRLEN + sizeof (uint16_t)];
	uint8_t			dl_brdcst_addr[MAXADDRLEN];
	dl_qos_cl_range1_t	dl_qos_range1;
	dl_qos_cl_sel1_t	dl_qos_sel1;
} dl_info_ack_wrapper_t;

#define	NEG(x)	-(x)

/*
 * DL_INFO_ACK
 */
static void
proto_info_ack(dld_str_t *dsp, mblk_t *mp)
{
	dl_info_ack_wrapper_t	*dlwp;
	dl_info_ack_t		*dlp;
	dl_qos_cl_sel1_t	*selp;
	dl_qos_cl_range1_t	*rangep;
	uint8_t			*addr;
	uint8_t			*brdcst_addr;
	dld_node_t		*dnp;
	uint_t			addr_length;
	uint_t			sap_length;

	/*
	 * Swap the request message for one large enough to contain the
	 * wrapper structure defined above.
	 */
	if ((mp = mexchange(dsp->ds_wq, mp, sizeof (dl_info_ack_wrapper_t),
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
	 * Set the style of the provider from the dld_node_t structure
	 * representing the dev_t that was opened.
	 */
	dnp = dsp->ds_dnp;
	dlp->dl_provider_style = dnp->dn_style;
	ASSERT(dlp->dl_provider_style == DL_STYLE1 ||
	    dlp->dl_provider_style == DL_STYLE2);

	/*
	 * Set the current DLPI state.
	 */
	dlp->dl_current_state = dsp->ds_dlstate;

	/*
	 * Gratuitously set the media type. This is because the Cisco VPN 3000
	 * module assumes that the media type is known prior to DL_ATTACH_REQ
	 * being completed.
	 */
	dlp->dl_mac_type = DL_ETHER;

	/*
	 * If the stream is not at least attached then we're done.
	 */
	if (dsp->ds_dlstate == DL_UNATTACHED ||
	    dsp->ds_dlstate == DL_ATTACH_PENDING ||
	    dsp->ds_dlstate == DL_DETACH_PENDING)
		goto done;

	/*
	 * Set the media type (properly this time).
	 */
	dlp->dl_mac_type = dsp->ds_mip->mi_media;

	/*
	 * Set the DLSAP length. We only support 16 bit values and they
	 * appear after the MAC address portion of DLSAP addresses.
	 */
	sap_length = sizeof (uint16_t);
	dlp->dl_sap_length = NEG(sap_length);

	/*
	 * Set the minimum and maximum payload sizes.
	 */
	dlp->dl_min_sdu = dsp->ds_mip->mi_sdu_min;
	dlp->dl_max_sdu = dsp->ds_mip->mi_sdu_max;

	addr_length = dsp->ds_mip->mi_addr_length;
	ASSERT(addr_length != 0);

	/*
	 * Copy in the media broadcast address.
	 */
	dlp->dl_brdcst_addr_offset = (uintptr_t)brdcst_addr - (uintptr_t)dlp;
	bcopy(dsp->ds_mip->mi_brdcst_addr, brdcst_addr, addr_length);
	dlp->dl_brdcst_addr_length = addr_length;

	/*
	 * We only support QoS information for VLAN interfaces.
	 */
	if (dsp->ds_vid != VLAN_ID_NONE) {
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
	} else {
		/*
		 * Shorten the buffer to lose the unused QoS information
		 * structures. This is to work around a bug in the Cisco VPN
		 * 3000 module.
		 */
		mp->b_wptr = (uint8_t *)rangep;
	}

	dlp->dl_addr_length = addr_length + sizeof (uint16_t);
	if (dsp->ds_dlstate == DL_IDLE) {
		/*
		 * The stream is bound. Therefore we can formulate a valid
		 * DLSAP address.
		 */
		dlp->dl_addr_offset = (uintptr_t)addr - (uintptr_t)dlp;
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

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_OK_ACK/DL_ERROR_ACK
 */
static void
proto_attach_ack(dld_str_t *dsp, mblk_t *mp, int err)
{
	int		dl_err;

	if (err != 0)
		goto failed;

	dsp->ds_dlstate = DL_UNBOUND;
	dlokack(dsp->ds_wq, mp, DL_ATTACH_REQ);
	return;

failed:
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
	dlerrorack(dsp->ds_wq, mp, DL_ATTACH_REQ, dl_err, err);
}

/*
 * DL_OK_ACK
 */
static void
proto_detach_ack(dld_str_t *dsp, mblk_t *mp)
{
	dsp->ds_dlstate = DL_UNATTACHED;
	dlokack(dsp->ds_wq, mp, DL_DETACH_REQ);
}

/*
 * DL_BIND_ACK/DL_ERROR_ACK
 */
static void
proto_bind_ack(dld_str_t *dsp, mblk_t *mp, int err)
{
	uint8_t			addr[MAXADDRLEN];
	uint_t			addr_length;
	int			dl_err;

	if (err != 0)
		goto failed;

	/*
	 * Copy in MAC address.
	 */
	addr_length = dsp->ds_mip->mi_addr_length;
	bcopy(dsp->ds_curr_addr, addr, addr_length);

	/*
	 * Copy in the DLSAP.
	 */
	*(uint16_t *)(addr + addr_length) = dsp->ds_sap;
	addr_length += sizeof (uint16_t);

	dsp->ds_dlstate = DL_IDLE;
	dlbindack(dsp->ds_wq, mp, dsp->ds_sap, (void *)addr, addr_length, 0,
	    0);
	return;

failed:
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
	dlerrorack(dsp->ds_wq, mp, DL_BIND_REQ, dl_err, err);
}

/*
 * DL_OK_ACK
 */
static void
proto_unbind_ack(dld_str_t *dsp, mblk_t *mp)
{
	dsp->ds_dlstate = DL_UNBOUND;
	dlokack(dsp->ds_wq, mp, DL_UNBIND_REQ);
}

/*
 * DL_OK_ACK/DL_ERROR_ACK
 */
static void
proto_promiscon_ack(dld_str_t *dsp, mblk_t *mp, int err)
{
	if (err != 0)
		goto failed;

	dlokack(dsp->ds_wq, mp, DL_PROMISCON_REQ);
	return;

failed:
	dlerrorack(dsp->ds_wq, mp, DL_PROMISCON_REQ, DL_SYSERR, err);
}

/*
 * DL_OK_ACK/DL_ERROR_ACK
 */
static void
proto_promiscoff_ack(dld_str_t *dsp, mblk_t *mp, int err)
{
	if (err != 0)
		goto failed;

	dlokack(dsp->ds_wq, mp, DL_PROMISCOFF_REQ);
	return;

failed:
	dlerrorack(dsp->ds_wq, mp, DL_PROMISCOFF_REQ, DL_SYSERR, err);
}

/*
 * DL_OK_ACK/DL_ERROR_ACK
 */
static void
proto_enabmulti_ack(dld_str_t *dsp, mblk_t *mp, int err)
{
	int		dl_err;

	if (err != 0)
		goto failed;

	dlokack(dsp->ds_wq, mp, DL_ENABMULTI_REQ);
	return;

failed:
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

	dlerrorack(dsp->ds_wq, mp, DL_ENABMULTI_REQ, dl_err, err);
}

/*
 * DL_OK_ACK/DL_ERROR_ACK
 */
static void
proto_disabmulti_ack(dld_str_t *dsp, mblk_t *mp, int err)
{
	int		dl_err;

	if (err != 0)
		goto failed;

	dlokack(dsp->ds_wq, mp, DL_DISABMULTI_REQ);
	return;

failed:
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

	dlerrorack(dsp->ds_wq, mp, DL_DISABMULTI_REQ, dl_err, err);
}

/*
 * DL_PHYS_ADDR_ACK
 */
static void
proto_physaddr_ack(dld_str_t *dsp, mblk_t *mp, t_uscalar_t type)
{
	uint_t			addr_length;

	/*
	 * Copy in the address.
	 */
	addr_length = dsp->ds_mip->mi_addr_length;
	dlphysaddrack(dsp->ds_wq, mp, (type == DL_CURR_PHYS_ADDR) ?
	    dsp->ds_curr_addr : dsp->ds_fact_addr, addr_length);
}

/*
 * DL_OK_ACK/DL_ERROR_ACK
 */
static void
proto_setphysaddr_ack(dld_str_t *dsp, mblk_t *mp, int err)
{
	int		dl_err;

	if (err != 0)
		goto failed;

	dlokack(dsp->ds_wq, mp, DL_SET_PHYS_ADDR_REQ);
	return;

failed:
	switch (err) {
	case EINVAL:
		dl_err = DL_BADADDR;
		err = 0;
		break;

	default:
		dl_err = DL_SYSERR;
		break;
	}

	dlerrorack(dsp->ds_wq, mp, DL_SET_PHYS_ADDR_REQ, dl_err, err);
}

/*
 * DL_OK_ACK
 */
static void
proto_udqos_ack(dld_str_t *dsp, mblk_t *mp)
{
	dlokack(dsp->ds_wq, mp, DL_UDQOS_REQ);
}

static void
proto_poll_disable(dld_str_t *dsp)
{
	mac_handle_t	mh;

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

	/*
	 * Set receive function back to default.
	 */
	dls_rx_set(dsp->ds_dc, (dsp->ds_mode == DLD_FASTPATH) ?
	    dld_str_rx_fastpath : dld_str_rx_unitdata, (void *)dsp);

	/*
	 * Note that polling is disabled.
	 */
	dsp->ds_polling = B_FALSE;
}

static boolean_t
proto_poll_enable(dld_str_t *dsp, dl_capab_poll_t *pollp)
{
	mac_handle_t	mh;

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
	mac_resource_set(mh, (mac_resource_add_t)pollp->poll_ring_add,
	    (void *)pollp->poll_rx_handle);
	mac_resources(mh);

	/*
	 * Set the receive function.
	 */
	dls_rx_set(dsp->ds_dc, (dls_rx_t)pollp->poll_rx,
	    (void *)pollp->poll_rx_handle);

	/*
	 * Note that polling is enabled. This prevents further DLIOCHDRINFO
	 * ioctls from overwriting the receive function pointer.
	 */
	dsp->ds_polling = B_TRUE;
	return (B_TRUE);
}

/*
 * DL_CAPABILITY_ACK/DL_ERROR_ACK
 */
static void
proto_capability_ack(dld_str_t *dsp, mblk_t *mp)
{
	dl_capability_ack_t	*dlap;
	dl_capability_sub_t	*dlsp;
	size_t			subsize;
	dl_capab_poll_t		poll;
	dl_capab_hcksum_t	hcksum;
	dl_capab_zerocopy_t	zcopy;
	uint8_t			*ptr;
	uint32_t		cksum;
	boolean_t		poll_cap;

	/*
	 * Initially assume no capabilities.
	 */
	subsize = 0;

	/*
	 * Check if polling can be enabled on this interface.
	 * If advertising DL_CAPAB_POLL has not been explicitly disabled
	 * then reserve space for that capability.
	 */
	poll_cap = ((dsp->ds_mip->mi_poll & DL_CAPAB_POLL) &&
	    !(dld_opt & DLD_OPT_NO_POLL) && (dsp->ds_vid == VLAN_ID_NONE));
	if (poll_cap) {
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_poll_t);
	}

	/*
	 * If the MAC interface supports checksum offload then reserve
	 * space for the DL_CAPAB_HCKSUM capability.
	 */
	if ((cksum = dsp->ds_mip->mi_cksum) != 0) {
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_hcksum_t);
	}

	/*
	 * If DL_CAPAB_ZEROCOPY has not be explicitly disabled then
	 * reserve space for it.
	 */
	if (!(dld_opt & DLD_OPT_NO_ZEROCOPY)) {
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_zerocopy_t);
	}

	/*
	 * If there are no capabilities to advertise, send a DL_ERROR_ACK.
	 */
	if (subsize == 0) {
		dlerrorack(dsp->ds_wq, mp, DL_CAPABILITY_REQ, DL_NOTSUPPORTED,
		    0);
		return;
	}

	if ((mp = mexchange(dsp->ds_wq, mp,
	    sizeof (dl_capability_ack_t) + subsize, M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_capability_ack_t));
	dlap = (dl_capability_ack_t *)mp->b_rptr;
	dlap->dl_primitive = DL_CAPABILITY_ACK;
	dlap->dl_sub_offset = sizeof (dl_capability_ack_t);
	dlap->dl_sub_length = subsize;
	ptr = (uint8_t *)&dlap[1];

	/*
	 * IP polling interface.
	 */
	if (poll_cap) {
		/*
		 * Attempt to disable just in case this is a re-negotiation.
		 */
		proto_poll_disable(dsp);

		dlsp = (dl_capability_sub_t *)ptr;

		dlsp->dl_cap = DL_CAPAB_POLL;
		dlsp->dl_length = sizeof (dl_capab_poll_t);
		ptr += sizeof (dl_capability_sub_t);

		bzero(&poll, sizeof (dl_capab_poll_t));
		poll.poll_version = POLL_VERSION_1;
		poll.poll_flags = POLL_CAPABLE;
		poll.poll_tx_handle = (uintptr_t)dsp->ds_dc;
		poll.poll_tx = (uintptr_t)dls_tx;

		dlcapabsetqid(&(poll.poll_mid), dsp->ds_rq);
		bcopy(&poll, ptr, sizeof (dl_capab_poll_t));
		ptr += sizeof (dl_capab_poll_t);
	}

	/*
	 * TCP/IP checksum offload.
	 */
	if (cksum != 0) {
		dlsp = (dl_capability_sub_t *)ptr;

		dlsp->dl_cap = DL_CAPAB_HCKSUM;
		dlsp->dl_length = sizeof (dl_capab_hcksum_t);
		ptr += sizeof (dl_capability_sub_t);

		bzero(&hcksum, sizeof (dl_capab_hcksum_t));
		hcksum.hcksum_version = HCKSUM_VERSION_1;
		hcksum.hcksum_txflags = cksum;

		dlcapabsetqid(&(hcksum.hcksum_mid), dsp->ds_rq);
		bcopy(&hcksum, ptr, sizeof (dl_capab_hcksum_t));
		ptr += sizeof (dl_capab_hcksum_t);
	}

	/*
	 * Zero copy
	 */
	if (!(dld_opt & DLD_OPT_NO_ZEROCOPY)) {
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
	qreply(dsp->ds_wq, mp);
}

/*
 * DL_CAPABILITY_ACK/DL_ERROR_ACK
 */
static void
proto_capability_enable(dld_str_t *dsp, mblk_t *mp)
{
	dl_capability_req_t	*dlp = (dl_capability_req_t *)mp->b_rptr;
	dl_capability_sub_t	*sp;
	size_t			size;
	offset_t		off;
	size_t			len;
	offset_t		end;

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
			dlerrorack(dsp->ds_wq, mp, DL_CAPABILITY_REQ,
			    DL_BADPRIM, 0);
			return;
		}

		switch (sp->dl_cap) {

		/*
		 * TCP/IP checksum offload to hardware.
		 */
		case DL_CAPAB_HCKSUM: {
			dl_capab_hcksum_t 	*hcksump;
			dl_capab_hcksum_t	hcksum;

			ASSERT(dsp->ds_mip->mi_cksum != 0);

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
		 * IP polling interface.
		 */
		case DL_CAPAB_POLL: {
			dl_capab_poll_t 	*pollp;
			dl_capab_poll_t		poll;

			pollp = (dl_capab_poll_t *)&sp[1];

			/*
			 * Copy for alignment.
			 */
			bcopy(pollp, &poll, sizeof (dl_capab_poll_t));

			switch (poll.poll_flags) {
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
				 * Now attempt enable it.
				 */
				if (!proto_poll_enable(dsp, &poll))
					break;

				bzero(&poll, sizeof (dl_capab_poll_t));
				poll.poll_flags = POLL_ENABLE;
				break;
			}

			dlcapabsetqid(&(poll.poll_mid), dsp->ds_rq);
			bcopy(&poll, pollp, sizeof (dl_capab_poll_t));
			break;
		}
		default:
			break;
		}

		off += size;
	}

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_ACK
 */
static void
proto_notify_ack(dld_str_t *dsp, mblk_t *mp, uint_t enable_set, uint_t ack_set)
{
	/*
	 * Cache the notifications that are being enabled.
	 */
	dsp->ds_notifications = enable_set;

	/*
	 * The ACK carries all notifications regardless of which set is
	 * being enabled.
	 */
	dlnotifyack(dsp->ds_wq, mp, ack_set);

	/*
	 * Solicit DL_NOTIFY_IND messages for each enabled notification.
	 */
	if (dsp->ds_notifications != 0)
		dld_str_notify_ind(dsp);
}
