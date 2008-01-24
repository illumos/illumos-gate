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

#include <sys/strsubr.h>
#include <inet/led.h>
#include <sys/softmac_impl.h>

/*
 * Macro to check whether the write-queue of the lower stream is full.
 *
 * Because softmac is pushed right above the underlying device and
 * _I_INSERT/_I_REMOVE is not processed in the lower stream, it is
 * safe to directly access the q_next pointer.
 */
#define	CANPUTNEXT(q)	\
	(!((q)->q_next->q_nfsrv->q_flag & QFULL) || canput((q)->q_next))

mblk_t *
softmac_m_tx(void *arg, mblk_t *mp)
{
	queue_t *wq = ((softmac_t *)arg)->smac_lower->sl_wq;

	/*
	 * Optimize for the most common case.
	 */
	if (mp->b_cont == NULL) {
		if (!CANPUTNEXT(wq))
			return (mp);

		mp->b_flag |= MSGNOLOOP;
		putnext(wq, mp);
		return (NULL);
	}

	while (mp != NULL) {
		mblk_t *next = mp->b_next;

		if (!CANPUTNEXT(wq))
			break;
		mp->b_next = NULL;
		mp->b_flag |= MSGNOLOOP;
		putnext(wq, mp);
		mp = next;
	}
	return (mp);
}

/*ARGSUSED*/
static void
softmac_blank(void *arg, time_t ticks, uint_t count)
{
}

void
softmac_m_resources(void *arg)
{
	softmac_t	*softmac = arg;
	softmac_lower_t	*slp = softmac->smac_lower;
	mac_rx_fifo_t	mrf;

	ASSERT((softmac->smac_state == SOFTMAC_READY) && (slp != NULL));

	/*
	 * Register rx resources and save resource handle for future reference.
	 * Note that the mac_resources() function must be called when the lower
	 * stream is plumbed.
	 */

	mutex_enter(&slp->sl_mutex);

	mrf.mrf_type = MAC_RX_FIFO;
	mrf.mrf_blank = softmac_blank;
	mrf.mrf_arg = slp;
	mrf.mrf_normal_blank_time = SOFTMAC_BLANK_TICKS;
	mrf.mrf_normal_pkt_count = SOFTMAC_BLANK_PKT_COUNT;

	slp->sl_handle =
	    mac_resource_add(softmac->smac_mh, (mac_resource_t *)&mrf);

	mutex_exit(&slp->sl_mutex);
}

void
softmac_rput_process_data(softmac_lower_t *slp, mblk_t *mp)
{
	/*
	 * When packets arrive, the softmac might not be fully started.
	 */
	ASSERT((slp->sl_softmac != NULL));
	ASSERT((mp->b_next == NULL) && (mp->b_prev == NULL));

	if (DB_REF(mp) > 1) {
		mblk_t *tmp;

		if ((tmp = copymsg(mp)) == NULL) {
			cmn_err(CE_WARN, "softmac_rput_process_data: "
			    "copymsg failed");
			goto failed;
		}
		freemsg(mp);
		mp = tmp;
	}

	mac_rx(slp->sl_softmac->smac_mh, slp->sl_handle, mp);
	return;

failed:
	freemsg(mp);
}

#define	ACKTIMEOUT	(10 * hz)

/*
 * Serialize control message processing.
 */
static void
softmac_serialize_enter(softmac_lower_t *slp)
{
	mutex_enter(&slp->sl_ctl_mutex);
	while (slp->sl_ctl_inprogress)
		cv_wait(&slp->sl_ctl_cv, &slp->sl_ctl_mutex);

	ASSERT(!slp->sl_ctl_inprogress);
	ASSERT(!slp->sl_pending_ioctl);
	ASSERT(slp->sl_pending_prim == DL_PRIM_INVAL);

	slp->sl_ctl_inprogress = B_TRUE;
	mutex_exit(&slp->sl_ctl_mutex);
}

static void
softmac_serialize_exit(softmac_lower_t *slp)
{
	mutex_enter(&slp->sl_ctl_mutex);

	ASSERT(slp->sl_ctl_inprogress);
	ASSERT(!slp->sl_pending_ioctl);
	ASSERT(slp->sl_pending_prim == DL_PRIM_INVAL);

	slp->sl_ctl_inprogress = B_FALSE;
	cv_broadcast(&slp->sl_ctl_cv);
	mutex_exit(&slp->sl_ctl_mutex);
}

static int
dlpi_get_errno(t_uscalar_t error, t_uscalar_t unix_errno)
{
	return (error == DL_SYSERR ? unix_errno : EINVAL);
}

static int
softmac_output(softmac_lower_t *slp, mblk_t *mp, t_uscalar_t dl_prim,
    t_uscalar_t ack, mblk_t **mpp)
{
	union DL_primitives	*dlp;
	int			err = 0;

	softmac_serialize_enter(slp);

	/*
	 * Record the pending DLPI primitive.
	 */
	mutex_enter(&slp->sl_mutex);
	slp->sl_pending_prim = dl_prim;
	mutex_exit(&slp->sl_mutex);

	putnext(slp->sl_wq, mp);

	mutex_enter(&slp->sl_mutex);
	while (slp->sl_pending_prim != DL_PRIM_INVAL) {
		if (cv_timedwait(&slp->sl_cv, &slp->sl_mutex,
		    lbolt + ACKTIMEOUT) == -1)
			break;
	}

	mp = slp->sl_ack_mp;
	slp->sl_ack_mp = NULL;

	/*
	 * If we timed out, sl_ack_mp will still be NULL, but sl_pending_prim
	 * won't be set to DL_PRIM_INVAL.
	 */
	ASSERT(mp != NULL || slp->sl_pending_prim != DL_PRIM_INVAL);

	slp->sl_pending_prim = DL_PRIM_INVAL;
	mutex_exit(&slp->sl_mutex);

	if (mp != NULL) {
		dlp = (union DL_primitives *)mp->b_rptr;

		if (dlp->dl_primitive == DL_ERROR_ACK) {
			err = dlpi_get_errno(dlp->error_ack.dl_errno,
			    dlp->error_ack.dl_unix_errno);
		} else {
			ASSERT(dlp->dl_primitive == ack);
		}
	} else {
		err = ENOMSG;
	}

	if (mpp != NULL)
		*mpp = mp;
	else
		freemsg(mp);

	softmac_serialize_exit(slp);
	return (err);
}

void
softmac_ioctl_tx(softmac_lower_t *slp, mblk_t *mp, mblk_t **mpp)
{
	softmac_serialize_enter(slp);

	/*
	 * Record that ioctl processing is currently in progress.
	 */
	mutex_enter(&slp->sl_mutex);
	slp->sl_pending_ioctl = B_TRUE;
	mutex_exit(&slp->sl_mutex);

	putnext(slp->sl_wq, mp);

	mutex_enter(&slp->sl_mutex);
	while (slp->sl_pending_ioctl)
		cv_wait(&slp->sl_cv, &slp->sl_mutex);
	mp = slp->sl_ack_mp;
	slp->sl_ack_mp = NULL;
	mutex_exit(&slp->sl_mutex);

	ASSERT(mpp != NULL && mp != NULL);
	*mpp = mp;

	softmac_serialize_exit(slp);
}

static int
softmac_mexchange_error_ack(mblk_t **mpp, t_uscalar_t error_primitive,
	t_uscalar_t error, t_uscalar_t unix_errno)
{
	union DL_primitives *dlp;

	if ((*mpp = mexchange(NULL, *mpp, sizeof (dl_error_ack_t), M_PCPROTO,
	    DL_ERROR_ACK)) == NULL)
		return (ENOMEM);

	dlp = (union DL_primitives *)(*mpp)->b_rptr;
	dlp->error_ack.dl_error_primitive = error_primitive;
	dlp->error_ack.dl_errno = error;
	dlp->error_ack.dl_unix_errno = unix_errno;

	return (0);
}

int
softmac_proto_tx(softmac_lower_t *slp, mblk_t *mp, mblk_t **mpp)
{
	int err = 0;
	t_uscalar_t dl_prim;

	dl_prim = ((union DL_primitives *)mp->b_rptr)->dl_primitive;

	ASSERT(slp->sl_softmac != NULL);

	switch (dl_prim) {
	case DL_ENABMULTI_REQ:
	case DL_DISABMULTI_REQ:
	case DL_SET_PHYS_ADDR_REQ:
	case DL_UNBIND_REQ:
	case DL_UDQOS_REQ:
	case DL_PROMISCON_REQ:
	case DL_PROMISCOFF_REQ:
		err = softmac_output(slp, mp, dl_prim, DL_OK_ACK, mpp);
		break;
	case DL_BIND_REQ:
		err = softmac_output(slp, mp, dl_prim, DL_BIND_ACK, mpp);
		break;
	case DL_NOTIFY_REQ:
		err = softmac_output(slp, mp, dl_prim, DL_NOTIFY_ACK, mpp);
		break;
	case DL_CONTROL_REQ:
		err = softmac_output(slp, mp, dl_prim, DL_CONTROL_ACK, mpp);
		break;
	case DL_CAPABILITY_REQ:
		err = softmac_output(slp, mp, dl_prim, DL_CAPABILITY_ACK, mpp);
		break;
	default:
		if (mpp != NULL) {
			*mpp = mp;
			err = softmac_mexchange_error_ack(mpp, dl_prim,
			    DL_UNSUPPORTED, 0);
		}
		break;
	}
	return (err);
}
