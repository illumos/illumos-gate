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
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/callb.h>
#include <sys/softmac_impl.h>

int
softmac_send_notify_req(softmac_lower_t *slp, uint32_t notifications)
{
	mblk_t		*reqmp;

	/*
	 * create notify req message and send it down
	 */
	reqmp = mexchange(NULL, NULL, DL_NOTIFY_REQ_SIZE, M_PROTO,
	    DL_NOTIFY_REQ);
	if (reqmp == NULL)
		return (ENOMEM);

	((dl_notify_req_t *)reqmp->b_rptr)->dl_notifications = notifications;

	return (softmac_proto_tx(slp, reqmp, NULL));
}

int
softmac_send_bind_req(softmac_lower_t *slp, uint_t sap)
{
	dl_bind_req_t	*bind;
	mblk_t		*reqmp;

	/*
	 * create bind req message and send it down
	 */
	reqmp = mexchange(NULL, NULL, DL_BIND_REQ_SIZE, M_PROTO, DL_BIND_REQ);
	if (reqmp == NULL)
		return (ENOMEM);

	bind = (dl_bind_req_t *)reqmp->b_rptr;
	bind->dl_sap = sap;
	bind->dl_conn_mgmt = 0;
	bind->dl_max_conind = 0;
	bind->dl_xidtest_flg = 0;
	bind->dl_service_mode = DL_CLDLS;

	return (softmac_proto_tx(slp, reqmp, NULL));
}

int
softmac_send_unbind_req(softmac_lower_t *slp)
{
	mblk_t			*reqmp;

	/*
	 * create unbind req message and send it down
	 */
	reqmp = mexchange(NULL, NULL, DL_UNBIND_REQ_SIZE, M_PROTO,
	    DL_UNBIND_REQ);
	if (reqmp == NULL)
		return (ENOMEM);

	return (softmac_proto_tx(slp, reqmp, NULL));
}

int
softmac_send_promisc_req(softmac_lower_t *slp, t_uscalar_t level, boolean_t on)
{
	mblk_t		*reqmp;
	size_t		size;
	t_uscalar_t	dl_prim;

	/*
	 * create promisc message and send it down
	 */
	if (on) {
		dl_prim = DL_PROMISCON_REQ;
		size = DL_PROMISCON_REQ_SIZE;
	} else {
		dl_prim = DL_PROMISCOFF_REQ;
		size = DL_PROMISCOFF_REQ_SIZE;
	}

	reqmp = mexchange(NULL, NULL, size, M_PROTO, dl_prim);
	if (reqmp == NULL)
		return (ENOMEM);

	if (on)
		((dl_promiscon_req_t *)reqmp->b_rptr)->dl_level = level;
	else
		((dl_promiscoff_req_t *)reqmp->b_rptr)->dl_level = level;

	return (softmac_proto_tx(slp, reqmp, NULL));
}

int
softmac_m_promisc(void *arg, boolean_t on)
{
	softmac_t		*softmac = arg;
	softmac_lower_t		*slp = softmac->smac_lower;

	ASSERT(MAC_PERIM_HELD(softmac->smac_mh));
	ASSERT(slp != NULL);
	return (softmac_send_promisc_req(slp, DL_PROMISC_PHYS, on));
}

int
softmac_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	softmac_t		*softmac = arg;
	softmac_lower_t		*slp;
	dl_enabmulti_req_t	*enabmulti;
	dl_disabmulti_req_t	*disabmulti;
	mblk_t			*reqmp;
	t_uscalar_t		dl_prim;
	uint32_t		size, addr_length;

	ASSERT(MAC_PERIM_HELD(softmac->smac_mh));
	/*
	 * create multicst message and send it down
	 */
	addr_length = softmac->smac_addrlen;
	if (add) {
		size = sizeof (dl_enabmulti_req_t) + addr_length;
		dl_prim = DL_ENABMULTI_REQ;
	} else {
		size = sizeof (dl_disabmulti_req_t) + addr_length;
		dl_prim = DL_DISABMULTI_REQ;
	}

	reqmp = mexchange(NULL, NULL, size, M_PROTO, dl_prim);
	if (reqmp == NULL)
		return (ENOMEM);

	if (add) {
		enabmulti = (dl_enabmulti_req_t *)reqmp->b_rptr;
		enabmulti->dl_addr_offset = sizeof (dl_enabmulti_req_t);
		enabmulti->dl_addr_length = addr_length;
		(void) memcpy(&enabmulti[1], mca, addr_length);
	} else {
		disabmulti = (dl_disabmulti_req_t *)reqmp->b_rptr;
		disabmulti->dl_addr_offset = sizeof (dl_disabmulti_req_t);
		disabmulti->dl_addr_length = addr_length;
		(void) memcpy(&disabmulti[1], mca, addr_length);
	}

	slp = softmac->smac_lower;
	ASSERT(slp != NULL);
	return (softmac_proto_tx(slp, reqmp, NULL));
}

int
softmac_m_unicst(void *arg, const uint8_t *macaddr)
{
	softmac_t		*softmac = arg;
	softmac_lower_t		*slp;
	dl_set_phys_addr_req_t	*phyaddr;
	mblk_t			*reqmp;
	size_t			size;

	ASSERT(MAC_PERIM_HELD(softmac->smac_mh));
	/*
	 * create set_phys_addr message and send it down
	 */
	size = DL_SET_PHYS_ADDR_REQ_SIZE + softmac->smac_addrlen;
	reqmp = mexchange(NULL, NULL, size, M_PROTO, DL_SET_PHYS_ADDR_REQ);
	if (reqmp == NULL)
		return (ENOMEM);

	phyaddr = (dl_set_phys_addr_req_t *)reqmp->b_rptr;
	phyaddr->dl_addr_offset = sizeof (dl_set_phys_addr_req_t);
	phyaddr->dl_addr_length = softmac->smac_addrlen;
	(void) memcpy(&phyaddr[1], macaddr, softmac->smac_addrlen);

	slp = softmac->smac_lower;
	ASSERT(slp != NULL);
	return (softmac_proto_tx(slp, reqmp, NULL));
}

void
softmac_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	softmac_lower_t *slp = ((softmac_t *)arg)->smac_lower;
	mblk_t *ackmp;

	ASSERT(slp != NULL);
	softmac_ioctl_tx(slp, mp, &ackmp);
	qreply(wq, ackmp);
}

static void
softmac_process_notify_ind(softmac_t *softmac, mblk_t *mp)
{
	dl_notify_ind_t	*dlnip = (dl_notify_ind_t *)mp->b_rptr;
	uint_t		addroff, addrlen;

	ASSERT(dlnip->dl_primitive == DL_NOTIFY_IND);

	switch (dlnip->dl_notification) {
	case DL_NOTE_PHYS_ADDR:
		if (dlnip->dl_data != DL_CURR_PHYS_ADDR)
			break;

		addroff = dlnip->dl_addr_offset;
		addrlen = dlnip->dl_addr_length - softmac->smac_saplen;
		if (addroff == 0 || addrlen != softmac->smac_addrlen ||
		    !MBLKIN(mp, addroff, addrlen)) {
			cmn_err(CE_NOTE, "softmac: got malformed "
			    "DL_NOTIFY_IND; length/offset %d/%d",
			    addrlen, addroff);
			break;
		}

		mac_unicst_update(softmac->smac_mh, mp->b_rptr + addroff);
		break;

	case DL_NOTE_LINK_UP:
		mac_link_update(softmac->smac_mh, LINK_STATE_UP);
		break;

	case DL_NOTE_LINK_DOWN:
		mac_link_update(softmac->smac_mh, LINK_STATE_DOWN);
		break;
	}

	freemsg(mp);
}

void
softmac_notify_thread(void *arg)
{
	softmac_t	*softmac = arg;
	callb_cpr_t	cprinfo;

	CALLB_CPR_INIT(&cprinfo, &softmac->smac_mutex, callb_generic_cpr,
	    "softmac_notify_thread");

	mutex_enter(&softmac->smac_mutex);

	/*
	 * Quit the thread if smac_mh is unregistered.
	 */
	while (softmac->smac_mh != NULL &&
	    !(softmac->smac_flags & SOFTMAC_NOTIFY_QUIT)) {
		mblk_t		*mp, *nextmp;

		if ((mp = softmac->smac_notify_head) == NULL) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&softmac->smac_cv, &softmac->smac_mutex);
			CALLB_CPR_SAFE_END(&cprinfo, &softmac->smac_mutex);
			continue;
		}

		softmac->smac_notify_head = softmac->smac_notify_tail = NULL;
		mutex_exit(&softmac->smac_mutex);

		while (mp != NULL) {
			nextmp = mp->b_next;
			mp->b_next = NULL;
			softmac_process_notify_ind(softmac, mp);
			mp = nextmp;
		}
		mutex_enter(&softmac->smac_mutex);
	}

	/*
	 * The softmac is being destroyed, simply free all of the DL_NOTIFY_IND
	 * messages left in the queue which did not have the chance to be
	 * processed.
	 */
	freemsgchain(softmac->smac_notify_head);
	softmac->smac_notify_head = softmac->smac_notify_tail = NULL;
	softmac->smac_flags |= SOFTMAC_NOTIFY_DONE;
	cv_broadcast(&softmac->smac_cv);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

static void
softmac_enqueue_notify_ind(queue_t *rq, mblk_t *mp)
{
	softmac_lower_t	*slp = rq->q_ptr;
	softmac_t	*softmac = slp->sl_softmac;

	mutex_enter(&softmac->smac_mutex);
	if (softmac->smac_notify_tail == NULL) {
		softmac->smac_notify_head = softmac->smac_notify_tail = mp;
	} else {
		softmac->smac_notify_tail->b_next = mp;
		softmac->smac_notify_tail = mp;
	}
	cv_broadcast(&softmac->smac_cv);
	mutex_exit(&softmac->smac_mutex);
}

static void
softmac_process_dlpi(softmac_lower_t *slp, mblk_t *mp, uint_t minlen,
    t_uscalar_t reqprim)
{
	const char *ackname;

	ackname = dl_primstr(((union DL_primitives *)mp->b_rptr)->dl_primitive);

	if (MBLKL(mp) < minlen) {
		cmn_err(CE_WARN, "softmac: got short %s", ackname);
		freemsg(mp);
		return;
	}

	mutex_enter(&slp->sl_mutex);
	if (slp->sl_pending_prim != reqprim) {
		cmn_err(CE_NOTE, "softmac: got unexpected %s", ackname);
		mutex_exit(&slp->sl_mutex);
		freemsg(mp);
		return;
	}

	slp->sl_pending_prim = DL_PRIM_INVAL;
	slp->sl_ack_mp = mp;
	cv_signal(&slp->sl_cv);
	mutex_exit(&slp->sl_mutex);
}

void
softmac_rput_process_proto(queue_t *rq, mblk_t *mp)
{
	softmac_lower_t		*slp = rq->q_ptr;
	union DL_primitives	*dlp = (union DL_primitives *)mp->b_rptr;
	ssize_t			len = MBLKL(mp);
	const char		*primstr;

	if (len < sizeof (t_uscalar_t)) {
		cmn_err(CE_WARN, "softmac: got runt DLPI message");
		goto exit;
	}

	primstr = dl_primstr(dlp->dl_primitive);

	switch (dlp->dl_primitive) {
	case DL_OK_ACK:
		if (len < DL_OK_ACK_SIZE)
			goto runt;

		softmac_process_dlpi(slp, mp, DL_OK_ACK_SIZE,
		    dlp->ok_ack.dl_correct_primitive);
		return;

	case DL_ERROR_ACK:
		if (len < DL_ERROR_ACK_SIZE)
			goto runt;

		softmac_process_dlpi(slp, mp, DL_ERROR_ACK_SIZE,
		    dlp->error_ack.dl_error_primitive);
		return;

	case DL_NOTIFY_IND:
		if (len < DL_NOTIFY_IND_SIZE)
			goto runt;

		/*
		 * Enqueue all the DL_NOTIFY_IND messages and process them
		 * in another separate thread to avoid deadlock. Here is an
		 * example of the deadlock scenario:
		 *
		 * Thread A: mac_promisc_set()->softmac_m_promisc()
		 *
		 *   The softmac driver waits for the ACK of the
		 *   DL_PROMISC_PHYS request with the MAC perimeter;
		 *
		 * Thread B:
		 *
		 *   The driver handles the DL_PROMISC_PHYS request. Before
		 *   it sends back the ACK, it could first send a
		 *   DL_NOTE_PROMISC_ON_PHYS notification.
		 *
		 * Since DL_NOTIFY_IND could eventually cause softmac to call
		 * mac_xxx_update(), which requires MAC perimeter, this would
		 * cause deadlock between the two threads. Enqueuing the
		 * DL_NOTIFY_IND message and defer its processing would
		 * avoid the potential deadlock.
		 */
		softmac_enqueue_notify_ind(rq, mp);
		return;

	case DL_NOTIFY_ACK:
		softmac_process_dlpi(slp, mp, DL_NOTIFY_ACK_SIZE,
		    DL_NOTIFY_REQ);
		return;

	case DL_CAPABILITY_ACK:
		softmac_process_dlpi(slp, mp, DL_CAPABILITY_ACK_SIZE,
		    DL_CAPABILITY_REQ);
		return;

	case DL_BIND_ACK:
		softmac_process_dlpi(slp, mp, DL_BIND_ACK_SIZE, DL_BIND_REQ);
		return;

	case DL_CONTROL_ACK:
		softmac_process_dlpi(slp, mp, DL_CONTROL_ACK_SIZE,
		    DL_CONTROL_REQ);
		return;

	case DL_UNITDATA_IND:
	case DL_PHYS_ADDR_ACK:
		/*
		 * a. Because the stream is in DLIOCRAW mode,
		 *    DL_UNITDATA_IND messages are not expected.
		 * b. The lower stream should not receive DL_PHYS_ADDR_REQ,
		 *    so DL_PHYS_ADDR_ACK messages are also unexpected.
		 */
	default:
		cmn_err(CE_WARN, "softmac: got unexpected %s", primstr);
		break;
	}
exit:
	freemsg(mp);
	return;
runt:
	cmn_err(CE_WARN, "softmac: got runt %s", primstr);
	freemsg(mp);
}

void
softmac_rput_process_notdata(queue_t *rq, softmac_upper_t *sup, mblk_t *mp)
{
	softmac_lower_t		*slp = rq->q_ptr;
	union DL_primitives	*dlp;
	ssize_t			len = MBLKL(mp);

	switch (DB_TYPE(mp)) {
	case M_PROTO:
	case M_PCPROTO:
		/*
		 * If this is a shared-lower-stream, pass it to softmac to
		 * process.
		 */
		if (sup == NULL) {
			softmac_rput_process_proto(rq, mp);
			break;
		}

		/*
		 * Dedicated-lower-stream.
		 */
		dlp = (union DL_primitives *)mp->b_rptr;
		ASSERT(len >= sizeof (dlp->dl_primitive));
		switch (dlp->dl_primitive) {
		case DL_OK_ACK:
			if (len < DL_OK_ACK_SIZE)
				goto runt;

			/*
			 * If this is a DL_OK_ACK for a DL_UNBIND_REQ, pass it
			 * to softmac to process, otherwise directly pass it to
			 * the upper stream.
			 */
			if (dlp->ok_ack.dl_correct_primitive == DL_UNBIND_REQ) {
				softmac_rput_process_proto(rq, mp);
				break;
			}

			putnext(sup->su_rq, mp);
			break;
		case DL_ERROR_ACK:
			if (len < DL_ERROR_ACK_SIZE)
				goto runt;

			/*
			 * If this is a DL_ERROR_ACK for a DL_UNBIND_REQ, pass
			 * it to softmac to process, otherwise directly pass it
			 * to the upper stream.
			 */
			if (dlp->error_ack.dl_error_primitive ==
			    DL_UNBIND_REQ) {
				softmac_rput_process_proto(rq, mp);
				break;
			}

			putnext(sup->su_rq, mp);
			break;
		case DL_BIND_ACK:
		case DL_CAPABILITY_ACK:
			softmac_rput_process_proto(rq, mp);
			break;
		default:
			putnext(sup->su_rq, mp);
			break;
		}
		break;
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHR)
			flushq(rq, FLUSHDATA);
		if (*mp->b_rptr & FLUSHW)
			flushq(OTHERQ(rq), FLUSHDATA);
		putnext(rq, mp);
		break;

	case M_IOCACK:
	case M_IOCNAK:
	case M_COPYIN:
	case M_COPYOUT:
		if (sup != NULL) {
			putnext(sup->su_rq, mp);
			break;
		}

		mutex_enter(&slp->sl_mutex);
		if (!slp->sl_pending_ioctl) {
			mutex_exit(&slp->sl_mutex);
			cmn_err(CE_NOTE, "softmac: got unexpected mblk "
			    "type 0x%x", DB_TYPE(mp));
			freemsg(mp);
			break;
		}

		slp->sl_pending_ioctl = B_FALSE;
		slp->sl_ack_mp = mp;
		cv_broadcast(&slp->sl_cv);
		mutex_exit(&slp->sl_mutex);
		break;

	default:
		cmn_err(CE_NOTE, "softmac: got unsupported mblk type 0x%x",
		    DB_TYPE(mp));
		freemsg(mp);
		break;
	}
	return;
runt:
	cmn_err(CE_WARN, "softmac: got runt %s", dl_primstr(dlp->dl_primitive));
	freemsg(mp);
}
