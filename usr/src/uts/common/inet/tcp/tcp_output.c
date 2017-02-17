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
 * Copyright (c) 2014 by Delphix. All rights reserved.
 */

/* This file contains all TCP output processing functions. */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/suntpi.h>
#include <sys/xti_inet.h>
#include <sys/timod.h>
#include <sys/pattr.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>
#include <sys/sockio.h>
#include <sys/tsol/tnet.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/snmpcom.h>
#include <inet/proto_set.h>
#include <inet/ipsec_impl.h>
#include <inet/ip_ndp.h>

static mblk_t	*tcp_get_seg_mp(tcp_t *, uint32_t, int32_t *);
static void	tcp_wput_cmdblk(queue_t *, mblk_t *);
static void	tcp_wput_flush(tcp_t *, mblk_t *);
static void	tcp_wput_iocdata(tcp_t *tcp, mblk_t *mp);
static int	tcp_xmit_end(tcp_t *);
static int	tcp_send(tcp_t *, const int, const int, const int,
		    const int, int *, uint_t *, int *, mblk_t **, mblk_t *);
static void	tcp_xmit_early_reset(char *, mblk_t *, uint32_t, uint32_t,
		    int, ip_recv_attr_t *, ip_stack_t *, conn_t *);
static boolean_t	tcp_send_rst_chk(tcp_stack_t *);
static void	tcp_process_shrunk_swnd(tcp_t *, uint32_t);
static void	tcp_fill_header(tcp_t *, uchar_t *, clock_t, int);

/*
 * Functions called directly via squeue having a prototype of edesc_t.
 */
static void	tcp_wput_nondata(void *, mblk_t *, void *, ip_recv_attr_t *);
static void	tcp_wput_ioctl(void *, mblk_t *, void *, ip_recv_attr_t *);
static void	tcp_wput_proto(void *, mblk_t *, void *, ip_recv_attr_t *);

/*
 * This controls how tiny a write must be before we try to copy it
 * into the mblk on the tail of the transmit queue.  Not much
 * speedup is observed for values larger than sixteen.  Zero will
 * disable the optimisation.
 */
static int tcp_tx_pull_len = 16;

void
tcp_wput(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = Q_TO_CONN(q);
	tcp_t	*tcp;
	void (*output_proc)();
	t_scalar_t type;
	uchar_t *rptr;
	struct iocblk	*iocp;
	size_t size;

	ASSERT(connp->conn_ref >= 2);

	switch (DB_TYPE(mp)) {
	case M_DATA:
		tcp = connp->conn_tcp;
		ASSERT(tcp != NULL);

		size = msgdsize(mp);

		mutex_enter(&tcp->tcp_non_sq_lock);
		tcp->tcp_squeue_bytes += size;
		if (TCP_UNSENT_BYTES(tcp) > connp->conn_sndbuf) {
			tcp_setqfull(tcp);
		}
		mutex_exit(&tcp->tcp_non_sq_lock);

		CONN_INC_REF(connp);
		SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_output, connp,
		    NULL, tcp_squeue_flag, SQTAG_TCP_OUTPUT);
		return;

	case M_CMD:
		tcp_wput_cmdblk(q, mp);
		return;

	case M_PROTO:
	case M_PCPROTO:
		/*
		 * if it is a snmp message, don't get behind the squeue
		 */
		tcp = connp->conn_tcp;
		rptr = mp->b_rptr;
		if ((mp->b_wptr - rptr) >= sizeof (t_scalar_t)) {
			type = ((union T_primitives *)rptr)->type;
		} else {
			if (connp->conn_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "tcp_wput_proto, dropping one...");
			}
			freemsg(mp);
			return;
		}
		if (type == T_SVR4_OPTMGMT_REQ) {
			/*
			 * All Solaris components should pass a db_credp
			 * for this TPI message, hence we ASSERT.
			 * But in case there is some other M_PROTO that looks
			 * like a TPI message sent by some other kernel
			 * component, we check and return an error.
			 */
			cred_t	*cr = msg_getcred(mp, NULL);

			ASSERT(cr != NULL);
			if (cr == NULL) {
				tcp_err_ack(tcp, mp, TSYSERR, EINVAL);
				return;
			}
			if (snmpcom_req(q, mp, tcp_snmp_set, ip_snmp_get,
			    cr)) {
				/*
				 * This was a SNMP request
				 */
				return;
			} else {
				output_proc = tcp_wput_proto;
			}
		} else {
			output_proc = tcp_wput_proto;
		}
		break;
	case M_IOCTL:
		/*
		 * Most ioctls can be processed right away without going via
		 * squeues - process them right here. Those that do require
		 * squeue (currently _SIOCSOCKFALLBACK)
		 * are processed by tcp_wput_ioctl().
		 */
		iocp = (struct iocblk *)mp->b_rptr;
		tcp = connp->conn_tcp;

		switch (iocp->ioc_cmd) {
		case TCP_IOC_ABORT_CONN:
			tcp_ioctl_abort_conn(q, mp);
			return;
		case TI_GETPEERNAME:
		case TI_GETMYNAME:
			mi_copyin(q, mp, NULL,
			    SIZEOF_STRUCT(strbuf, iocp->ioc_flag));
			return;

		default:
			output_proc = tcp_wput_ioctl;
			break;
		}
		break;
	default:
		output_proc = tcp_wput_nondata;
		break;
	}

	CONN_INC_REF(connp);
	SQUEUE_ENTER_ONE(connp->conn_sqp, mp, output_proc, connp,
	    NULL, tcp_squeue_flag, SQTAG_TCP_WPUT_OTHER);
}

/*
 * The TCP normal data output path.
 * NOTE: the logic of the fast path is duplicated from this function.
 */
void
tcp_wput_data(tcp_t *tcp, mblk_t *mp, boolean_t urgent)
{
	int		len;
	mblk_t		*local_time;
	mblk_t		*mp1;
	uint32_t	snxt;
	int		tail_unsent;
	int		tcpstate;
	int		usable = 0;
	mblk_t		*xmit_tail;
	int32_t		mss;
	int32_t		num_sack_blk = 0;
	int32_t		total_hdr_len;
	int32_t		tcp_hdr_len;
	int		rc;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;
	clock_t		now = LBOLT_FASTPATH;

	tcpstate = tcp->tcp_state;
	if (mp == NULL) {
		/*
		 * tcp_wput_data() with NULL mp should only be called when
		 * there is unsent data.
		 */
		ASSERT(tcp->tcp_unsent > 0);
		/* Really tacky... but we need this for detached closes. */
		len = tcp->tcp_unsent;
		goto data_null;
	}

	ASSERT(mp->b_datap->db_type == M_DATA);
	/*
	 * Don't allow data after T_ORDREL_REQ or T_DISCON_REQ,
	 * or before a connection attempt has begun.
	 */
	if (tcpstate < TCPS_SYN_SENT || tcpstate > TCPS_CLOSE_WAIT ||
	    (tcp->tcp_valid_bits & TCP_FSS_VALID) != 0) {
		if ((tcp->tcp_valid_bits & TCP_FSS_VALID) != 0) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "tcp_wput_data: data after ordrel, %s",
			    tcp_display(tcp, NULL,
			    DISP_ADDR_AND_PORT));
#else
			if (connp->conn_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_TRACE|SL_ERROR,
				    "tcp_wput_data: data after ordrel, %s\n",
				    tcp_display(tcp, NULL,
				    DISP_ADDR_AND_PORT));
			}
#endif /* DEBUG */
		}
		if (tcp->tcp_snd_zcopy_aware &&
		    (mp->b_datap->db_struioflag & STRUIO_ZCNOTIFY))
			tcp_zcopy_notify(tcp);
		freemsg(mp);
		mutex_enter(&tcp->tcp_non_sq_lock);
		if (tcp->tcp_flow_stopped &&
		    TCP_UNSENT_BYTES(tcp) <= connp->conn_sndlowat) {
			tcp_clrqfull(tcp);
		}
		mutex_exit(&tcp->tcp_non_sq_lock);
		return;
	}

	/* Strip empties */
	for (;;) {
		ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <=
		    (uintptr_t)INT_MAX);
		len = (int)(mp->b_wptr - mp->b_rptr);
		if (len > 0)
			break;
		mp1 = mp;
		mp = mp->b_cont;
		freeb(mp1);
		if (mp == NULL) {
			return;
		}
	}

	/* If we are the first on the list ... */
	if (tcp->tcp_xmit_head == NULL) {
		tcp->tcp_xmit_head = mp;
		tcp->tcp_xmit_tail = mp;
		tcp->tcp_xmit_tail_unsent = len;
	} else {
		/* If tiny tx and room in txq tail, pullup to save mblks. */
		struct datab *dp;

		mp1 = tcp->tcp_xmit_last;
		if (len < tcp_tx_pull_len &&
		    (dp = mp1->b_datap)->db_ref == 1 &&
		    dp->db_lim - mp1->b_wptr >= len) {
			ASSERT(len > 0);
			ASSERT(!mp1->b_cont);
			if (len == 1) {
				*mp1->b_wptr++ = *mp->b_rptr;
			} else {
				bcopy(mp->b_rptr, mp1->b_wptr, len);
				mp1->b_wptr += len;
			}
			if (mp1 == tcp->tcp_xmit_tail)
				tcp->tcp_xmit_tail_unsent += len;
			mp1->b_cont = mp->b_cont;
			if (tcp->tcp_snd_zcopy_aware &&
			    (mp->b_datap->db_struioflag & STRUIO_ZCNOTIFY))
				mp1->b_datap->db_struioflag |= STRUIO_ZCNOTIFY;
			freeb(mp);
			mp = mp1;
		} else {
			tcp->tcp_xmit_last->b_cont = mp;
		}
		len += tcp->tcp_unsent;
	}

	/* Tack on however many more positive length mblks we have */
	if ((mp1 = mp->b_cont) != NULL) {
		do {
			int tlen;
			ASSERT((uintptr_t)(mp1->b_wptr - mp1->b_rptr) <=
			    (uintptr_t)INT_MAX);
			tlen = (int)(mp1->b_wptr - mp1->b_rptr);
			if (tlen <= 0) {
				mp->b_cont = mp1->b_cont;
				freeb(mp1);
			} else {
				len += tlen;
				mp = mp1;
			}
		} while ((mp1 = mp->b_cont) != NULL);
	}
	tcp->tcp_xmit_last = mp;
	tcp->tcp_unsent = len;

	if (urgent)
		usable = 1;

data_null:
	snxt = tcp->tcp_snxt;
	xmit_tail = tcp->tcp_xmit_tail;
	tail_unsent = tcp->tcp_xmit_tail_unsent;

	/*
	 * Note that tcp_mss has been adjusted to take into account the
	 * timestamp option if applicable.  Because SACK options do not
	 * appear in every TCP segments and they are of variable lengths,
	 * they cannot be included in tcp_mss.  Thus we need to calculate
	 * the actual segment length when we need to send a segment which
	 * includes SACK options.
	 */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
		int32_t	opt_len;

		num_sack_blk = MIN(tcp->tcp_max_sack_blk,
		    tcp->tcp_num_sack_blk);
		opt_len = num_sack_blk * sizeof (sack_blk_t) + TCPOPT_NOP_LEN *
		    2 + TCPOPT_HEADER_LEN;
		mss = tcp->tcp_mss - opt_len;
		total_hdr_len = connp->conn_ht_iphc_len + opt_len;
		tcp_hdr_len = connp->conn_ht_ulp_len + opt_len;
	} else {
		mss = tcp->tcp_mss;
		total_hdr_len = connp->conn_ht_iphc_len;
		tcp_hdr_len = connp->conn_ht_ulp_len;
	}

	if ((tcp->tcp_suna == snxt) && !tcp->tcp_localnet &&
	    (TICK_TO_MSEC(now - tcp->tcp_last_recv_time) >= tcp->tcp_rto)) {
		TCP_SET_INIT_CWND(tcp, mss, tcps->tcps_slow_start_after_idle);
	}
	if (tcpstate == TCPS_SYN_RCVD) {
		/*
		 * The three-way connection establishment handshake is not
		 * complete yet. We want to queue the data for transmission
		 * after entering ESTABLISHED state (RFC793). A jump to
		 * "done" label effectively leaves data on the queue.
		 */
		goto done;
	} else {
		int usable_r;

		/*
		 * In the special case when cwnd is zero, which can only
		 * happen if the connection is ECN capable, return now.
		 * New segments is sent using tcp_timer().  The timer
		 * is set in tcp_input_data().
		 */
		if (tcp->tcp_cwnd == 0) {
			/*
			 * Note that tcp_cwnd is 0 before 3-way handshake is
			 * finished.
			 */
			ASSERT(tcp->tcp_ecn_ok ||
			    tcp->tcp_state < TCPS_ESTABLISHED);
			return;
		}

		/* NOTE: trouble if xmitting while SYN not acked? */
		usable_r = snxt - tcp->tcp_suna;
		usable_r = tcp->tcp_swnd - usable_r;

		/*
		 * Check if the receiver has shrunk the window.  If
		 * tcp_wput_data() with NULL mp is called, tcp_fin_sent
		 * cannot be set as there is unsent data, so FIN cannot
		 * be sent out.  Otherwise, we need to take into account
		 * of FIN as it consumes an "invisible" sequence number.
		 */
		ASSERT(tcp->tcp_fin_sent == 0);
		if (usable_r < 0) {
			/*
			 * The receiver has shrunk the window and we have sent
			 * -usable_r date beyond the window, re-adjust.
			 *
			 * If TCP window scaling is enabled, there can be
			 * round down error as the advertised receive window
			 * is actually right shifted n bits.  This means that
			 * the lower n bits info is wiped out.  It will look
			 * like the window is shrunk.  Do a check here to
			 * see if the shrunk amount is actually within the
			 * error in window calculation.  If it is, just
			 * return.  Note that this check is inside the
			 * shrunk window check.  This makes sure that even
			 * though tcp_process_shrunk_swnd() is not called,
			 * we will stop further processing.
			 */
			if ((-usable_r >> tcp->tcp_snd_ws) > 0) {
				tcp_process_shrunk_swnd(tcp, -usable_r);
			}
			return;
		}

		/* usable = MIN(swnd, cwnd) - unacked_bytes */
		if (tcp->tcp_swnd > tcp->tcp_cwnd)
			usable_r -= tcp->tcp_swnd - tcp->tcp_cwnd;

		/* usable = MIN(usable, unsent) */
		if (usable_r > len)
			usable_r = len;

		/* usable = MAX(usable, {1 for urgent, 0 for data}) */
		if (usable_r > 0) {
			usable = usable_r;
		} else {
			/* Bypass all other unnecessary processing. */
			goto done;
		}
	}

	local_time = (mblk_t *)now;

	/*
	 * "Our" Nagle Algorithm.  This is not the same as in the old
	 * BSD.  This is more in line with the true intent of Nagle.
	 *
	 * The conditions are:
	 * 1. The amount of unsent data (or amount of data which can be
	 *    sent, whichever is smaller) is less than Nagle limit.
	 * 2. The last sent size is also less than Nagle limit.
	 * 3. There is unack'ed data.
	 * 4. Urgent pointer is not set.  Send urgent data ignoring the
	 *    Nagle algorithm.  This reduces the probability that urgent
	 *    bytes get "merged" together.
	 * 5. The app has not closed the connection.  This eliminates the
	 *    wait time of the receiving side waiting for the last piece of
	 *    (small) data.
	 *
	 * If all are satisified, exit without sending anything.  Note
	 * that Nagle limit can be smaller than 1 MSS.  Nagle limit is
	 * the smaller of 1 MSS and global tcp_naglim_def (default to be
	 * 4095).
	 */
	if (usable < (int)tcp->tcp_naglim &&
	    tcp->tcp_naglim > tcp->tcp_last_sent_len &&
	    snxt != tcp->tcp_suna &&
	    !(tcp->tcp_valid_bits & TCP_URG_VALID) &&
	    !(tcp->tcp_valid_bits & TCP_FSS_VALID)) {
		goto done;
	}

	/*
	 * If tcp_zero_win_probe is not set and the tcp->tcp_cork option
	 * is set, then we have to force TCP not to send partial segment
	 * (smaller than MSS bytes). We are calculating the usable now
	 * based on full mss and will save the rest of remaining data for
	 * later. When tcp_zero_win_probe is set, TCP needs to send out
	 * something to do zero window probe.
	 */
	if (tcp->tcp_cork && !tcp->tcp_zero_win_probe) {
		if (usable < mss)
			goto done;
		usable = (usable / mss) * mss;
	}

	/* Update the latest receive window size in TCP header. */
	tcp->tcp_tcpha->tha_win = htons(tcp->tcp_rwnd >> tcp->tcp_rcv_ws);

	/* Send the packet. */
	rc = tcp_send(tcp, mss, total_hdr_len, tcp_hdr_len,
	    num_sack_blk, &usable, &snxt, &tail_unsent, &xmit_tail,
	    local_time);

	/* Pretend that all we were trying to send really got sent */
	if (rc < 0 && tail_unsent < 0) {
		do {
			xmit_tail = xmit_tail->b_cont;
			xmit_tail->b_prev = local_time;
			ASSERT((uintptr_t)(xmit_tail->b_wptr -
			    xmit_tail->b_rptr) <= (uintptr_t)INT_MAX);
			tail_unsent += (int)(xmit_tail->b_wptr -
			    xmit_tail->b_rptr);
		} while (tail_unsent < 0);
	}
done:;
	tcp->tcp_xmit_tail = xmit_tail;
	tcp->tcp_xmit_tail_unsent = tail_unsent;
	len = tcp->tcp_snxt - snxt;
	if (len) {
		/*
		 * If new data was sent, need to update the notsack
		 * list, which is, afterall, data blocks that have
		 * not been sack'ed by the receiver.  New data is
		 * not sack'ed.
		 */
		if (tcp->tcp_snd_sack_ok && tcp->tcp_notsack_list != NULL) {
			/* len is a negative value. */
			tcp->tcp_pipe -= len;
			tcp_notsack_update(&(tcp->tcp_notsack_list),
			    tcp->tcp_snxt, snxt,
			    &(tcp->tcp_num_notsack_blk),
			    &(tcp->tcp_cnt_notsack_list));
		}
		tcp->tcp_snxt = snxt + tcp->tcp_fin_sent;
		tcp->tcp_rack = tcp->tcp_rnxt;
		tcp->tcp_rack_cnt = 0;
		if ((snxt + len) == tcp->tcp_suna) {
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
		}
	} else if (snxt == tcp->tcp_suna && tcp->tcp_swnd == 0) {
		/*
		 * Didn't send anything. Make sure the timer is running
		 * so that we will probe a zero window.
		 */
		TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
	}
	/* Note that len is the amount we just sent but with a negative sign */
	tcp->tcp_unsent += len;
	mutex_enter(&tcp->tcp_non_sq_lock);
	if (tcp->tcp_flow_stopped) {
		if (TCP_UNSENT_BYTES(tcp) <= connp->conn_sndlowat) {
			tcp_clrqfull(tcp);
		}
	} else if (TCP_UNSENT_BYTES(tcp) >= connp->conn_sndbuf) {
		if (!(tcp->tcp_detached))
			tcp_setqfull(tcp);
	}
	mutex_exit(&tcp->tcp_non_sq_lock);
}

/*
 * Initial STREAMS write side put() procedure for sockets. It tries to
 * handle the T_CAPABILITY_REQ which sockfs sends down while setting
 * up the socket without using the squeue. Non T_CAPABILITY_REQ messages
 * are handled by tcp_wput() as usual.
 *
 * All further messages will also be handled by tcp_wput() because we cannot
 * be sure that the above short cut is safe later.
 */
void
tcp_wput_sock(queue_t *wq, mblk_t *mp)
{
	conn_t			*connp = Q_TO_CONN(wq);
	tcp_t			*tcp = connp->conn_tcp;
	struct T_capability_req	*car = (struct T_capability_req *)mp->b_rptr;

	ASSERT(wq->q_qinfo == &tcp_sock_winit);
	wq->q_qinfo = &tcp_winit;

	ASSERT(IPCL_IS_TCP(connp));
	ASSERT(TCP_IS_SOCKET(tcp));

	if (DB_TYPE(mp) == M_PCPROTO &&
	    MBLKL(mp) == sizeof (struct T_capability_req) &&
	    car->PRIM_type == T_CAPABILITY_REQ) {
		tcp_capability_req(tcp, mp);
		return;
	}

	tcp_wput(wq, mp);
}

/* ARGSUSED */
void
tcp_wput_fallback(queue_t *wq, mblk_t *mp)
{
#ifdef DEBUG
	cmn_err(CE_CONT, "tcp_wput_fallback: Message during fallback \n");
#endif
	freemsg(mp);
}

/*
 * Call by tcp_wput() to handle misc non M_DATA messages.
 */
/* ARGSUSED */
static void
tcp_wput_nondata(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;

	ASSERT(DB_TYPE(mp) != M_IOCTL);
	/*
	 * TCP is D_MP and qprocsoff() is done towards the end of the tcp_close.
	 * Once the close starts, streamhead and sockfs will not let any data
	 * packets come down (close ensures that there are no threads using the
	 * queue and no new threads will come down) but since qprocsoff()
	 * hasn't happened yet, a M_FLUSH or some non data message might
	 * get reflected back (in response to our own FLUSHRW) and get
	 * processed after tcp_close() is done. The conn would still be valid
	 * because a ref would have added but we need to check the state
	 * before actually processing the packet.
	 */
	if (TCP_IS_DETACHED(tcp) || (tcp->tcp_state == TCPS_CLOSED)) {
		freemsg(mp);
		return;
	}

	switch (DB_TYPE(mp)) {
	case M_IOCDATA:
		tcp_wput_iocdata(tcp, mp);
		break;
	case M_FLUSH:
		tcp_wput_flush(tcp, mp);
		break;
	default:
		ip_wput_nondata(connp->conn_wq, mp);
		break;
	}
}

/* tcp_wput_flush is called by tcp_wput_nondata to handle M_FLUSH messages. */
static void
tcp_wput_flush(tcp_t *tcp, mblk_t *mp)
{
	uchar_t	fval = *mp->b_rptr;
	mblk_t	*tail;
	conn_t	*connp = tcp->tcp_connp;
	queue_t	*q = connp->conn_wq;

	/* TODO: How should flush interact with urgent data? */
	if ((fval & FLUSHW) && tcp->tcp_xmit_head != NULL &&
	    !(tcp->tcp_valid_bits & TCP_URG_VALID)) {
		/*
		 * Flush only data that has not yet been put on the wire.  If
		 * we flush data that we have already transmitted, life, as we
		 * know it, may come to an end.
		 */
		tail = tcp->tcp_xmit_tail;
		tail->b_wptr -= tcp->tcp_xmit_tail_unsent;
		tcp->tcp_xmit_tail_unsent = 0;
		tcp->tcp_unsent = 0;
		if (tail->b_wptr != tail->b_rptr)
			tail = tail->b_cont;
		if (tail) {
			mblk_t **excess = &tcp->tcp_xmit_head;
			for (;;) {
				mblk_t *mp1 = *excess;
				if (mp1 == tail)
					break;
				tcp->tcp_xmit_tail = mp1;
				tcp->tcp_xmit_last = mp1;
				excess = &mp1->b_cont;
			}
			*excess = NULL;
			tcp_close_mpp(&tail);
			if (tcp->tcp_snd_zcopy_aware)
				tcp_zcopy_notify(tcp);
		}
		/*
		 * We have no unsent data, so unsent must be less than
		 * conn_sndlowat, so re-enable flow.
		 */
		mutex_enter(&tcp->tcp_non_sq_lock);
		if (tcp->tcp_flow_stopped) {
			tcp_clrqfull(tcp);
		}
		mutex_exit(&tcp->tcp_non_sq_lock);
	}
	/*
	 * TODO: you can't just flush these, you have to increase rwnd for one
	 * thing.  For another, how should urgent data interact?
	 */
	if (fval & FLUSHR) {
		*mp->b_rptr = fval & ~FLUSHW;
		/* XXX */
		qreply(q, mp);
		return;
	}
	freemsg(mp);
}

/*
 * tcp_wput_iocdata is called by tcp_wput_nondata to handle all M_IOCDATA
 * messages.
 */
static void
tcp_wput_iocdata(tcp_t *tcp, mblk_t *mp)
{
	mblk_t		*mp1;
	struct iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	STRUCT_HANDLE(strbuf, sb);
	uint_t		addrlen;
	conn_t		*connp = tcp->tcp_connp;
	queue_t 	*q = connp->conn_wq;

	/* Make sure it is one of ours. */
	switch (iocp->ioc_cmd) {
	case TI_GETMYNAME:
	case TI_GETPEERNAME:
		break;
	default:
		/*
		 * If the conn is closing, then error the ioctl here. Otherwise
		 * use the CONN_IOCTLREF_* macros to hold off tcp_close until
		 * we're done here.
		 */
		mutex_enter(&connp->conn_lock);
		if (connp->conn_state_flags & CONN_CLOSING) {
			mutex_exit(&connp->conn_lock);
			iocp->ioc_error = EINVAL;
			mp->b_datap->db_type = M_IOCNAK;
			iocp->ioc_count = 0;
			qreply(q, mp);
			return;
		}

		CONN_INC_IOCTLREF_LOCKED(connp);
		ip_wput_nondata(q, mp);
		CONN_DEC_IOCTLREF(connp);
		return;
	}
	switch (mi_copy_state(q, mp, &mp1)) {
	case -1:
		return;
	case MI_COPY_CASE(MI_COPY_IN, 1):
		break;
	case MI_COPY_CASE(MI_COPY_OUT, 1):
		/* Copy out the strbuf. */
		mi_copyout(q, mp);
		return;
	case MI_COPY_CASE(MI_COPY_OUT, 2):
		/* All done. */
		mi_copy_done(q, mp, 0);
		return;
	default:
		mi_copy_done(q, mp, EPROTO);
		return;
	}
	/* Check alignment of the strbuf */
	if (!OK_32PTR(mp1->b_rptr)) {
		mi_copy_done(q, mp, EINVAL);
		return;
	}

	STRUCT_SET_HANDLE(sb, iocp->ioc_flag, (void *)mp1->b_rptr);

	if (connp->conn_family == AF_INET)
		addrlen = sizeof (sin_t);
	else
		addrlen = sizeof (sin6_t);

	if (STRUCT_FGET(sb, maxlen) < addrlen) {
		mi_copy_done(q, mp, EINVAL);
		return;
	}

	switch (iocp->ioc_cmd) {
	case TI_GETMYNAME:
		break;
	case TI_GETPEERNAME:
		if (tcp->tcp_state < TCPS_SYN_RCVD) {
			mi_copy_done(q, mp, ENOTCONN);
			return;
		}
		break;
	}
	mp1 = mi_copyout_alloc(q, mp, STRUCT_FGETP(sb, buf), addrlen, B_TRUE);
	if (!mp1)
		return;

	STRUCT_FSET(sb, len, addrlen);
	switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {
	case TI_GETMYNAME:
		(void) conn_getsockname(connp, (struct sockaddr *)mp1->b_wptr,
		    &addrlen);
		break;
	case TI_GETPEERNAME:
		(void) conn_getpeername(connp, (struct sockaddr *)mp1->b_wptr,
		    &addrlen);
		break;
	}
	mp1->b_wptr += addrlen;
	/* Copy out the address */
	mi_copyout(q, mp);
}

/*
 * tcp_wput_ioctl is called by tcp_wput_nondata() to handle all M_IOCTL
 * messages.
 */
/* ARGSUSED */
static void
tcp_wput_ioctl(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	conn_t 		*connp = (conn_t *)arg;
	tcp_t		*tcp = connp->conn_tcp;
	queue_t		*q = connp->conn_wq;
	struct iocblk	*iocp;

	ASSERT(DB_TYPE(mp) == M_IOCTL);
	/*
	 * Try and ASSERT the minimum possible references on the
	 * conn early enough. Since we are executing on write side,
	 * the connection is obviously not detached and that means
	 * there is a ref each for TCP and IP. Since we are behind
	 * the squeue, the minimum references needed are 3. If the
	 * conn is in classifier hash list, there should be an
	 * extra ref for that (we check both the possibilities).
	 */
	ASSERT((connp->conn_fanout != NULL && connp->conn_ref >= 4) ||
	    (connp->conn_fanout == NULL && connp->conn_ref >= 3));

	iocp = (struct iocblk *)mp->b_rptr;
	switch (iocp->ioc_cmd) {
	case _SIOCSOCKFALLBACK:
		/*
		 * Either sockmod is about to be popped and the socket
		 * would now be treated as a plain stream, or a module
		 * is about to be pushed so we could no longer use read-
		 * side synchronous streams for fused loopback tcp.
		 * Drain any queued data and disable direct sockfs
		 * interface from now on.
		 */
		if (!tcp->tcp_issocket) {
			DB_TYPE(mp) = M_IOCNAK;
			iocp->ioc_error = EINVAL;
		} else {
			tcp_use_pure_tpi(tcp);
			DB_TYPE(mp) = M_IOCACK;
			iocp->ioc_error = 0;
		}
		iocp->ioc_count = 0;
		iocp->ioc_rval = 0;
		qreply(q, mp);
		return;
	}

	/*
	 * If the conn is closing, then error the ioctl here. Otherwise bump the
	 * conn_ioctlref to hold off tcp_close until we're done here.
	 */
	mutex_enter(&(connp)->conn_lock);
	if ((connp)->conn_state_flags & CONN_CLOSING) {
		mutex_exit(&(connp)->conn_lock);
		iocp->ioc_error = EINVAL;
		mp->b_datap->db_type = M_IOCNAK;
		iocp->ioc_count = 0;
		qreply(q, mp);
		return;
	}

	CONN_INC_IOCTLREF_LOCKED(connp);
	ip_wput_nondata(q, mp);
	CONN_DEC_IOCTLREF(connp);
}

/*
 * This routine is called by tcp_wput() to handle all TPI requests.
 */
/* ARGSUSED */
static void
tcp_wput_proto(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	conn_t		*connp = (conn_t *)arg;
	tcp_t		*tcp = connp->conn_tcp;
	union T_primitives *tprim = (union T_primitives *)mp->b_rptr;
	uchar_t		*rptr;
	t_scalar_t	type;
	cred_t		*cr;

	/*
	 * Try and ASSERT the minimum possible references on the
	 * conn early enough. Since we are executing on write side,
	 * the connection is obviously not detached and that means
	 * there is a ref each for TCP and IP. Since we are behind
	 * the squeue, the minimum references needed are 3. If the
	 * conn is in classifier hash list, there should be an
	 * extra ref for that (we check both the possibilities).
	 */
	ASSERT((connp->conn_fanout != NULL && connp->conn_ref >= 4) ||
	    (connp->conn_fanout == NULL && connp->conn_ref >= 3));

	rptr = mp->b_rptr;
	ASSERT((uintptr_t)(mp->b_wptr - rptr) <= (uintptr_t)INT_MAX);
	if ((mp->b_wptr - rptr) >= sizeof (t_scalar_t)) {
		type = ((union T_primitives *)rptr)->type;
		if (type == T_EXDATA_REQ) {
			tcp_output_urgent(connp, mp, arg2, NULL);
		} else if (type != T_DATA_REQ) {
			goto non_urgent_data;
		} else {
			/* TODO: options, flags, ... from user */
			/* Set length to zero for reclamation below */
			tcp_wput_data(tcp, mp->b_cont, B_TRUE);
			freeb(mp);
		}
		return;
	} else {
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_wput_proto, dropping one...");
		}
		freemsg(mp);
		return;
	}

non_urgent_data:

	switch ((int)tprim->type) {
	case O_T_BIND_REQ:	/* bind request */
	case T_BIND_REQ:	/* new semantics bind request */
		tcp_tpi_bind(tcp, mp);
		break;
	case T_UNBIND_REQ:	/* unbind request */
		tcp_tpi_unbind(tcp, mp);
		break;
	case O_T_CONN_RES:	/* old connection response XXX */
	case T_CONN_RES:	/* connection response */
		tcp_tli_accept(tcp, mp);
		break;
	case T_CONN_REQ:	/* connection request */
		tcp_tpi_connect(tcp, mp);
		break;
	case T_DISCON_REQ:	/* disconnect request */
		tcp_disconnect(tcp, mp);
		break;
	case T_CAPABILITY_REQ:
		tcp_capability_req(tcp, mp);	/* capability request */
		break;
	case T_INFO_REQ:	/* information request */
		tcp_info_req(tcp, mp);
		break;
	case T_SVR4_OPTMGMT_REQ:	/* manage options req */
	case T_OPTMGMT_REQ:
		/*
		 * Note:  no support for snmpcom_req() through new
		 * T_OPTMGMT_REQ. See comments in ip.c
		 */

		/*
		 * All Solaris components should pass a db_credp
		 * for this TPI message, hence we ASSERT.
		 * But in case there is some other M_PROTO that looks
		 * like a TPI message sent by some other kernel
		 * component, we check and return an error.
		 */
		cr = msg_getcred(mp, NULL);
		ASSERT(cr != NULL);
		if (cr == NULL) {
			tcp_err_ack(tcp, mp, TSYSERR, EINVAL);
			return;
		}
		/*
		 * If EINPROGRESS is returned, the request has been queued
		 * for subsequent processing by ip_restart_optmgmt(), which
		 * will do the CONN_DEC_REF().
		 */
		if ((int)tprim->type == T_SVR4_OPTMGMT_REQ) {
			svr4_optcom_req(connp->conn_wq, mp, cr, &tcp_opt_obj);
		} else {
			tpi_optcom_req(connp->conn_wq, mp, cr, &tcp_opt_obj);
		}
		break;

	case T_UNITDATA_REQ:	/* unitdata request */
		tcp_err_ack(tcp, mp, TNOTSUPPORT, 0);
		break;
	case T_ORDREL_REQ:	/* orderly release req */
		freemsg(mp);

		if (tcp->tcp_fused)
			tcp_unfuse(tcp);

		if (tcp_xmit_end(tcp) != 0) {
			/*
			 * We were crossing FINs and got a reset from
			 * the other side. Just ignore it.
			 */
			if (connp->conn_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "tcp_wput_proto, T_ORDREL_REQ out of "
				    "state %s",
				    tcp_display(tcp, NULL,
				    DISP_ADDR_AND_PORT));
			}
		}
		break;
	case T_ADDR_REQ:
		tcp_addr_req(tcp, mp);
		break;
	default:
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_wput_proto, bogus TPI msg, type %d",
			    tprim->type);
		}
		/*
		 * We used to M_ERROR.  Sending TNOTSUPPORT gives the user
		 * to recover.
		 */
		tcp_err_ack(tcp, mp, TNOTSUPPORT, 0);
		break;
	}
}

/*
 * Handle special out-of-band ioctl requests (see PSARC/2008/265).
 */
static void
tcp_wput_cmdblk(queue_t *q, mblk_t *mp)
{
	void	*data;
	mblk_t	*datamp = mp->b_cont;
	conn_t	*connp = Q_TO_CONN(q);
	tcp_t	*tcp = connp->conn_tcp;
	cmdblk_t *cmdp = (cmdblk_t *)mp->b_rptr;

	if (datamp == NULL || MBLKL(datamp) < cmdp->cb_len) {
		cmdp->cb_error = EPROTO;
		qreply(q, mp);
		return;
	}

	data = datamp->b_rptr;

	switch (cmdp->cb_cmd) {
	case TI_GETPEERNAME:
		if (tcp->tcp_state < TCPS_SYN_RCVD)
			cmdp->cb_error = ENOTCONN;
		else
			cmdp->cb_error = conn_getpeername(connp, data,
			    &cmdp->cb_len);
		break;
	case TI_GETMYNAME:
		cmdp->cb_error = conn_getsockname(connp, data, &cmdp->cb_len);
		break;
	default:
		cmdp->cb_error = EINVAL;
		break;
	}

	qreply(q, mp);
}

/*
 * The TCP fast path write put procedure.
 * NOTE: the logic of the fast path is duplicated from tcp_wput_data()
 */
/* ARGSUSED */
void
tcp_output(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	int		len;
	int		hdrlen;
	int		plen;
	mblk_t		*mp1;
	uchar_t		*rptr;
	uint32_t	snxt;
	tcpha_t		*tcpha;
	struct datab	*db;
	uint32_t	suna;
	uint32_t	mss;
	ipaddr_t	*dst;
	ipaddr_t	*src;
	uint32_t	sum;
	int		usable;
	conn_t		*connp = (conn_t *)arg;
	tcp_t		*tcp = connp->conn_tcp;
	uint32_t	msize;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ip_xmit_attr_t	*ixa;
	clock_t		now;

	/*
	 * Try and ASSERT the minimum possible references on the
	 * conn early enough. Since we are executing on write side,
	 * the connection is obviously not detached and that means
	 * there is a ref each for TCP and IP. Since we are behind
	 * the squeue, the minimum references needed are 3. If the
	 * conn is in classifier hash list, there should be an
	 * extra ref for that (we check both the possibilities).
	 */
	ASSERT((connp->conn_fanout != NULL && connp->conn_ref >= 4) ||
	    (connp->conn_fanout == NULL && connp->conn_ref >= 3));

	ASSERT(DB_TYPE(mp) == M_DATA);
	msize = (mp->b_cont == NULL) ? MBLKL(mp) : msgdsize(mp);

	mutex_enter(&tcp->tcp_non_sq_lock);
	tcp->tcp_squeue_bytes -= msize;
	mutex_exit(&tcp->tcp_non_sq_lock);

	/* Bypass tcp protocol for fused tcp loopback */
	if (tcp->tcp_fused && tcp_fuse_output(tcp, mp, msize))
		return;

	mss = tcp->tcp_mss;
	/*
	 * If ZEROCOPY has turned off, try not to send any zero-copy message
	 * down. Do backoff, now.
	 */
	if (tcp->tcp_snd_zcopy_aware && !tcp->tcp_snd_zcopy_on)
		mp = tcp_zcopy_backoff(tcp, mp, B_FALSE);


	ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <= (uintptr_t)INT_MAX);
	len = (int)(mp->b_wptr - mp->b_rptr);

	/*
	 * Criteria for fast path:
	 *
	 *   1. no unsent data
	 *   2. single mblk in request
	 *   3. connection established
	 *   4. data in mblk
	 *   5. len <= mss
	 *   6. no tcp_valid bits
	 */
	if ((tcp->tcp_unsent != 0) ||
	    (tcp->tcp_cork) ||
	    (mp->b_cont != NULL) ||
	    (tcp->tcp_state != TCPS_ESTABLISHED) ||
	    (len == 0) ||
	    (len > mss) ||
	    (tcp->tcp_valid_bits != 0)) {
		tcp_wput_data(tcp, mp, B_FALSE);
		return;
	}

	ASSERT(tcp->tcp_xmit_tail_unsent == 0);
	ASSERT(tcp->tcp_fin_sent == 0);

	/* queue new packet onto retransmission queue */
	if (tcp->tcp_xmit_head == NULL) {
		tcp->tcp_xmit_head = mp;
	} else {
		tcp->tcp_xmit_last->b_cont = mp;
	}
	tcp->tcp_xmit_last = mp;
	tcp->tcp_xmit_tail = mp;

	/* find out how much we can send */
	/* BEGIN CSTYLED */
	/*
	 *    un-acked	   usable
	 *  |--------------|-----------------|
	 *  tcp_suna       tcp_snxt	  tcp_suna+tcp_swnd
	 */
	/* END CSTYLED */

	/* start sending from tcp_snxt */
	snxt = tcp->tcp_snxt;

	/*
	 * Check to see if this connection has been idled for some
	 * time and no ACK is expected.  If it is, we need to slow
	 * start again to get back the connection's "self-clock" as
	 * described in VJ's paper.
	 *
	 * Reinitialize tcp_cwnd after idle.
	 */
	now = LBOLT_FASTPATH;
	if ((tcp->tcp_suna == snxt) && !tcp->tcp_localnet &&
	    (TICK_TO_MSEC(now - tcp->tcp_last_recv_time) >= tcp->tcp_rto)) {
		TCP_SET_INIT_CWND(tcp, mss, tcps->tcps_slow_start_after_idle);
	}

	usable = tcp->tcp_swnd;		/* tcp window size */
	if (usable > tcp->tcp_cwnd)
		usable = tcp->tcp_cwnd;	/* congestion window smaller */
	usable -= snxt;		/* subtract stuff already sent */
	suna = tcp->tcp_suna;
	usable += suna;
	/* usable can be < 0 if the congestion window is smaller */
	if (len > usable) {
		/* Can't send complete M_DATA in one shot */
		goto slow;
	}

	mutex_enter(&tcp->tcp_non_sq_lock);
	if (tcp->tcp_flow_stopped &&
	    TCP_UNSENT_BYTES(tcp) <= connp->conn_sndlowat) {
		tcp_clrqfull(tcp);
	}
	mutex_exit(&tcp->tcp_non_sq_lock);

	/*
	 * determine if anything to send (Nagle).
	 *
	 *   1. len < tcp_mss (i.e. small)
	 *   2. unacknowledged data present
	 *   3. len < nagle limit
	 *   4. last packet sent < nagle limit (previous packet sent)
	 */
	if ((len < mss) && (snxt != suna) &&
	    (len < (int)tcp->tcp_naglim) &&
	    (tcp->tcp_last_sent_len < tcp->tcp_naglim)) {
		/*
		 * This was the first unsent packet and normally
		 * mss < xmit_hiwater so there is no need to worry
		 * about flow control. The next packet will go
		 * through the flow control check in tcp_wput_data().
		 */
		/* leftover work from above */
		tcp->tcp_unsent = len;
		tcp->tcp_xmit_tail_unsent = len;

		return;
	}

	/*
	 * len <= tcp->tcp_mss && len == unsent so no sender silly window.  Can
	 * send now.
	 */

	if (snxt == suna) {
		TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
	}

	/* we have always sent something */
	tcp->tcp_rack_cnt = 0;

	tcp->tcp_snxt = snxt + len;
	tcp->tcp_rack = tcp->tcp_rnxt;

	if ((mp1 = dupb(mp)) == 0)
		goto no_memory;
	mp->b_prev = (mblk_t *)(uintptr_t)now;
	mp->b_next = (mblk_t *)(uintptr_t)snxt;

	/* adjust tcp header information */
	tcpha = tcp->tcp_tcpha;
	tcpha->tha_flags = (TH_ACK|TH_PUSH);

	sum = len + connp->conn_ht_ulp_len + connp->conn_sum;
	sum = (sum >> 16) + (sum & 0xFFFF);
	tcpha->tha_sum = htons(sum);

	tcpha->tha_seq = htonl(snxt);

	TCPS_BUMP_MIB(tcps, tcpOutDataSegs);
	TCPS_UPDATE_MIB(tcps, tcpOutDataBytes, len);
	BUMP_LOCAL(tcp->tcp_obsegs);

	/* Update the latest receive window size in TCP header. */
	tcpha->tha_win = htons(tcp->tcp_rwnd >> tcp->tcp_rcv_ws);

	tcp->tcp_last_sent_len = (ushort_t)len;

	plen = len + connp->conn_ht_iphc_len;

	ixa = connp->conn_ixa;
	ixa->ixa_pktlen = plen;

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		tcp->tcp_ipha->ipha_length = htons(plen);
	} else {
		tcp->tcp_ip6h->ip6_plen = htons(plen - IPV6_HDR_LEN);
	}

	/* see if we need to allocate a mblk for the headers */
	hdrlen = connp->conn_ht_iphc_len;
	rptr = mp1->b_rptr - hdrlen;
	db = mp1->b_datap;
	if ((db->db_ref != 2) || rptr < db->db_base ||
	    (!OK_32PTR(rptr))) {
		/* NOTE: we assume allocb returns an OK_32PTR */
		mp = allocb(hdrlen + tcps->tcps_wroff_xtra, BPRI_MED);
		if (!mp) {
			freemsg(mp1);
			goto no_memory;
		}
		mp->b_cont = mp1;
		mp1 = mp;
		/* Leave room for Link Level header */
		rptr = &mp1->b_rptr[tcps->tcps_wroff_xtra];
		mp1->b_wptr = &rptr[hdrlen];
	}
	mp1->b_rptr = rptr;

	/* Fill in the timestamp option. */
	if (tcp->tcp_snd_ts_ok) {
		uint32_t llbolt = (uint32_t)LBOLT_FASTPATH;

		U32_TO_BE32(llbolt,
		    (char *)tcpha + TCP_MIN_HEADER_LENGTH+4);
		U32_TO_BE32(tcp->tcp_ts_recent,
		    (char *)tcpha + TCP_MIN_HEADER_LENGTH+8);
	} else {
		ASSERT(connp->conn_ht_ulp_len == TCP_MIN_HEADER_LENGTH);
	}

	/* copy header into outgoing packet */
	dst = (ipaddr_t *)rptr;
	src = (ipaddr_t *)connp->conn_ht_iphc;
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	dst[3] = src[3];
	dst[4] = src[4];
	dst[5] = src[5];
	dst[6] = src[6];
	dst[7] = src[7];
	dst[8] = src[8];
	dst[9] = src[9];
	if (hdrlen -= 40) {
		hdrlen >>= 2;
		dst += 10;
		src += 10;
		do {
			*dst++ = *src++;
		} while (--hdrlen);
	}

	/*
	 * Set the ECN info in the TCP header.  Note that this
	 * is not the template header.
	 */
	if (tcp->tcp_ecn_ok) {
		TCP_SET_ECT(tcp, rptr);

		tcpha = (tcpha_t *)(rptr + ixa->ixa_ip_hdr_length);
		if (tcp->tcp_ecn_echo_on)
			tcpha->tha_flags |= TH_ECE;
		if (tcp->tcp_cwr && !tcp->tcp_ecn_cwr_sent) {
			tcpha->tha_flags |= TH_CWR;
			tcp->tcp_ecn_cwr_sent = B_TRUE;
		}
	}

	if (tcp->tcp_ip_forward_progress) {
		tcp->tcp_ip_forward_progress = B_FALSE;
		connp->conn_ixa->ixa_flags |= IXAF_REACH_CONF;
	} else {
		connp->conn_ixa->ixa_flags &= ~IXAF_REACH_CONF;
	}
	tcp_send_data(tcp, mp1);
	return;

	/*
	 * If we ran out of memory, we pretend to have sent the packet
	 * and that it was lost on the wire.
	 */
no_memory:
	return;

slow:
	/* leftover work from above */
	tcp->tcp_unsent = len;
	tcp->tcp_xmit_tail_unsent = len;
	tcp_wput_data(tcp, NULL, B_FALSE);
}

/* ARGSUSED2 */
void
tcp_output_urgent(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	int len;
	uint32_t msize;
	conn_t *connp = (conn_t *)arg;
	tcp_t *tcp = connp->conn_tcp;

	msize = msgdsize(mp);

	len = msize - 1;
	if (len < 0) {
		freemsg(mp);
		return;
	}

	/*
	 * Try to force urgent data out on the wire. Even if we have unsent
	 * data this will at least send the urgent flag.
	 * XXX does not handle more flag correctly.
	 */
	len += tcp->tcp_unsent;
	len += tcp->tcp_snxt;
	tcp->tcp_urg = len;
	tcp->tcp_valid_bits |= TCP_URG_VALID;

	/* Bypass tcp protocol for fused tcp loopback */
	if (tcp->tcp_fused && tcp_fuse_output(tcp, mp, msize))
		return;

	/* Strip off the T_EXDATA_REQ if the data is from TPI */
	if (DB_TYPE(mp) != M_DATA) {
		mblk_t *mp1 = mp;
		ASSERT(!IPCL_IS_NONSTR(connp));
		mp = mp->b_cont;
		freeb(mp1);
	}
	tcp_wput_data(tcp, mp, B_TRUE);
}

/*
 * Called by streams close routine via squeues when our client blows off its
 * descriptor, we take this to mean: "close the stream state NOW, close the tcp
 * connection politely" When SO_LINGER is set (with a non-zero linger time and
 * it is not a nonblocking socket) then this routine sleeps until the FIN is
 * acked.
 *
 * NOTE: tcp_close potentially returns error when lingering.
 * However, the stream head currently does not pass these errors
 * to the application. 4.4BSD only returns EINTR and EWOULDBLOCK
 * errors to the application (from tsleep()) and not errors
 * like ECONNRESET caused by receiving a reset packet.
 */

/* ARGSUSED */
void
tcp_close_output(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	char	*msg;
	conn_t	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;
	clock_t	delta = 0;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * When a non-STREAMS socket is being closed, it does not always
	 * stick around waiting for tcp_close_output to run and can therefore
	 * have dropped a reference already. So adjust the asserts accordingly.
	 */
	ASSERT((connp->conn_fanout != NULL &&
	    connp->conn_ref >= (IPCL_IS_NONSTR(connp) ? 3 : 4)) ||
	    (connp->conn_fanout == NULL &&
	    connp->conn_ref >= (IPCL_IS_NONSTR(connp) ? 2 : 3)));

	mutex_enter(&tcp->tcp_eager_lock);
	if (tcp->tcp_conn_req_cnt_q0 != 0 || tcp->tcp_conn_req_cnt_q != 0) {
		/*
		 * Cleanup for listener. For non-STREAM sockets sockfs will
		 * close all the eagers on 'q', so in that case only deal
		 * with 'q0'.
		 */
		tcp_eager_cleanup(tcp, IPCL_IS_NONSTR(connp) ? 1 : 0);
		tcp->tcp_wait_for_eagers = 1;
	}
	mutex_exit(&tcp->tcp_eager_lock);

	tcp->tcp_lso = B_FALSE;

	msg = NULL;
	switch (tcp->tcp_state) {
	case TCPS_CLOSED:
	case TCPS_IDLE:
		break;
	case TCPS_BOUND:
		if (tcp->tcp_listener != NULL) {
			ASSERT(IPCL_IS_NONSTR(connp));
			/*
			 * Unlink from the listener and drop the reference
			 * put on it by the eager. tcp_closei_local will not
			 * do it because tcp_tconnind_started is TRUE.
			 */
			mutex_enter(&tcp->tcp_saved_listener->tcp_eager_lock);
			tcp_eager_unlink(tcp);
			mutex_exit(&tcp->tcp_saved_listener->tcp_eager_lock);
			CONN_DEC_REF(tcp->tcp_saved_listener->tcp_connp);
		}
		break;
	case TCPS_LISTEN:
		break;
	case TCPS_SYN_SENT:
		msg = "tcp_close, during connect";
		break;
	case TCPS_SYN_RCVD:
		/*
		 * Close during the connect 3-way handshake
		 * but here there may or may not be pending data
		 * already on queue. Process almost same as in
		 * the ESTABLISHED state.
		 */
		/* FALLTHRU */
	default:
		if (tcp->tcp_fused)
			tcp_unfuse(tcp);

		/*
		 * If SO_LINGER has set a zero linger time, abort the
		 * connection with a reset.
		 */
		if (connp->conn_linger && connp->conn_lingertime == 0) {
			msg = "tcp_close, zero lingertime";
			break;
		}

		/*
		 * Abort connection if there is unread data queued.
		 */
		if (tcp->tcp_rcv_list || tcp->tcp_reass_head) {
			msg = "tcp_close, unread data";
			break;
		}

		/*
		 * Abort connection if it is being closed without first
		 * being accepted. This can happen if a listening non-STREAM
		 * socket wants to get rid of the socket, for example, if the
		 * listener is closing.
		 */
		if (tcp->tcp_listener != NULL) {
			ASSERT(IPCL_IS_NONSTR(connp));
			msg = "tcp_close, close before accept";

			/*
			 * Unlink from the listener and drop the reference
			 * put on it by the eager. tcp_closei_local will not
			 * do it because tcp_tconnind_started is TRUE.
			 */
			mutex_enter(&tcp->tcp_saved_listener->tcp_eager_lock);
			tcp_eager_unlink(tcp);
			mutex_exit(&tcp->tcp_saved_listener->tcp_eager_lock);
			CONN_DEC_REF(tcp->tcp_saved_listener->tcp_connp);
			break;
		}

		/*
		 * Transmit the FIN before detaching the tcp_t.
		 * After tcp_detach returns this queue/perimeter
		 * no longer owns the tcp_t thus others can modify it.
		 */
		(void) tcp_xmit_end(tcp);

		/*
		 * If lingering on close then wait until the fin is acked,
		 * the SO_LINGER time passes, or a reset is sent/received.
		 */
		if (connp->conn_linger && connp->conn_lingertime > 0 &&
		    !(tcp->tcp_fin_acked) &&
		    tcp->tcp_state >= TCPS_ESTABLISHED) {
			if (tcp->tcp_closeflags & (FNDELAY|FNONBLOCK)) {
				tcp->tcp_client_errno = EWOULDBLOCK;
			} else if (tcp->tcp_client_errno == 0) {

				ASSERT(tcp->tcp_linger_tid == 0);

				/* conn_lingertime is in sec. */
				tcp->tcp_linger_tid = TCP_TIMER(tcp,
				    tcp_close_linger_timeout,
				    connp->conn_lingertime * MILLISEC);

				/* tcp_close_linger_timeout will finish close */
				if (tcp->tcp_linger_tid == 0)
					tcp->tcp_client_errno = ENOSR;
				else
					return;
			}

			/*
			 * Check if we need to detach or just close
			 * the instance.
			 */
			if (tcp->tcp_state <= TCPS_LISTEN)
				break;
		}

		/*
		 * Make sure that no other thread will access the conn_rq of
		 * this instance (through lookups etc.) as conn_rq will go
		 * away shortly.
		 */
		tcp_acceptor_hash_remove(tcp);

		mutex_enter(&tcp->tcp_non_sq_lock);
		if (tcp->tcp_flow_stopped) {
			tcp_clrqfull(tcp);
		}
		mutex_exit(&tcp->tcp_non_sq_lock);

		if (tcp->tcp_timer_tid != 0) {
			delta = TCP_TIMER_CANCEL(tcp, tcp->tcp_timer_tid);
			tcp->tcp_timer_tid = 0;
		}
		/*
		 * Need to cancel those timers which will not be used when
		 * TCP is detached.  This has to be done before the conn_wq
		 * is set to NULL.
		 */
		tcp_timers_stop(tcp);

		tcp->tcp_detached = B_TRUE;
		if (tcp->tcp_state == TCPS_TIME_WAIT) {
			tcp_time_wait_append(tcp);
			TCP_DBGSTAT(tcps, tcp_detach_time_wait);
			ASSERT(connp->conn_ref >=
			    (IPCL_IS_NONSTR(connp) ? 2 : 3));
			goto finish;
		}

		/*
		 * If delta is zero the timer event wasn't executed and was
		 * successfully canceled. In this case we need to restart it
		 * with the minimal delta possible.
		 */
		if (delta >= 0)
			tcp->tcp_timer_tid = TCP_TIMER(tcp, tcp_timer,
			    delta ? delta : 1);

		ASSERT(connp->conn_ref >= (IPCL_IS_NONSTR(connp) ? 2 : 3));
		goto finish;
	}

	/* Detach did not complete. Still need to remove q from stream. */
	if (msg) {
		if (tcp->tcp_state == TCPS_ESTABLISHED ||
		    tcp->tcp_state == TCPS_CLOSE_WAIT)
			TCPS_BUMP_MIB(tcps, tcpEstabResets);
		if (tcp->tcp_state == TCPS_SYN_SENT ||
		    tcp->tcp_state == TCPS_SYN_RCVD)
			TCPS_BUMP_MIB(tcps, tcpAttemptFails);
		tcp_xmit_ctl(msg, tcp,  tcp->tcp_snxt, 0, TH_RST);
	}

	tcp_closei_local(tcp);
	CONN_DEC_REF(connp);
	ASSERT(connp->conn_ref >= (IPCL_IS_NONSTR(connp) ? 1 : 2));

finish:
	/*
	 * Don't change the queues in the case of a listener that has
	 * eagers in its q or q0. It could surprise the eagers.
	 * Instead wait for the eagers outside the squeue.
	 *
	 * For non-STREAMS sockets tcp_wait_for_eagers implies that
	 * we should delay the su_closed upcall until all eagers have
	 * dropped their references.
	 */
	if (!tcp->tcp_wait_for_eagers) {
		tcp->tcp_detached = B_TRUE;
		connp->conn_rq = NULL;
		connp->conn_wq = NULL;

		/* non-STREAM socket, release the upper handle */
		if (IPCL_IS_NONSTR(connp)) {
			ASSERT(connp->conn_upper_handle != NULL);
			(*connp->conn_upcalls->su_closed)
			    (connp->conn_upper_handle);
			connp->conn_upper_handle = NULL;
			connp->conn_upcalls = NULL;
		}
	}

	/* Signal tcp_close() to finish closing. */
	mutex_enter(&tcp->tcp_closelock);
	tcp->tcp_closed = 1;
	cv_signal(&tcp->tcp_closecv);
	mutex_exit(&tcp->tcp_closelock);
}

/* ARGSUSED */
void
tcp_shutdown_output(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	conn_t 	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;

	freemsg(mp);

	if (tcp->tcp_fused)
		tcp_unfuse(tcp);

	if (tcp_xmit_end(tcp) != 0) {
		/*
		 * We were crossing FINs and got a reset from
		 * the other side. Just ignore it.
		 */
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1,
			    SL_ERROR|SL_TRACE,
			    "tcp_shutdown_output() out of state %s",
			    tcp_display(tcp, NULL, DISP_ADDR_AND_PORT));
		}
	}
}

#pragma inline(tcp_send_data)

void
tcp_send_data(tcp_t *tcp, mblk_t *mp)
{
	conn_t		*connp = tcp->tcp_connp;

	/*
	 * Check here to avoid sending zero-copy message down to IP when
	 * ZEROCOPY capability has turned off. We only need to deal with
	 * the race condition between sockfs and the notification here.
	 * Since we have tried to backoff the tcp_xmit_head when turning
	 * zero-copy off and new messages in tcp_output(), we simply drop
	 * the dup'ed packet here and let tcp retransmit, if tcp_xmit_zc_clean
	 * is not true.
	 */
	if (tcp->tcp_snd_zcopy_aware && !tcp->tcp_snd_zcopy_on &&
	    !tcp->tcp_xmit_zc_clean) {
		ip_drop_output("TCP ZC was disabled but not clean", mp, NULL);
		freemsg(mp);
		return;
	}

	DTRACE_TCP5(send, mblk_t *, NULL, ip_xmit_attr_t *, connp->conn_ixa,
	    __dtrace_tcp_void_ip_t *, mp->b_rptr, tcp_t *, tcp,
	    __dtrace_tcp_tcph_t *,
	    &mp->b_rptr[connp->conn_ixa->ixa_ip_hdr_length]);

	ASSERT(connp->conn_ixa->ixa_notify_cookie == connp->conn_tcp);
	(void) conn_ip_output(mp, connp->conn_ixa);
}

/* ARGSUSED2 */
void
tcp_send_synack(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	conn_t	*econnp = (conn_t *)arg;
	tcp_t	*tcp = econnp->conn_tcp;
	ip_xmit_attr_t *ixa = econnp->conn_ixa;

	/* Guard against a RST having blown it away while on the squeue */
	if (tcp->tcp_state == TCPS_CLOSED) {
		freemsg(mp);
		return;
	}

	/*
	 * In the off-chance that the eager received and responded to
	 * some other packet while the SYN|ACK was queued, we recalculate
	 * the ixa_pktlen. It would be better to fix the SYN/accept
	 * multithreading scheme to avoid this complexity.
	 */
	ixa->ixa_pktlen = msgdsize(mp);
	(void) conn_ip_output(mp, ixa);
}

/*
 * tcp_send() is called by tcp_wput_data() and returns one of the following:
 *
 * -1 = failed allocation.
 *  0 = We've either successfully sent data, or our usable send window is too
 *      small and we'd rather wait until later before sending again.
 */
static int
tcp_send(tcp_t *tcp, const int mss, const int total_hdr_len,
    const int tcp_hdr_len, const int num_sack_blk, int *usable,
    uint_t *snxt, int *tail_unsent, mblk_t **xmit_tail, mblk_t *local_time)
{
	int		num_lso_seg = 1;
	uint_t		lso_usable;
	boolean_t	do_lso_send = B_FALSE;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;
	ip_xmit_attr_t	*ixa = connp->conn_ixa;

	/*
	 * Check LSO possibility. The value of tcp->tcp_lso indicates whether
	 * the underlying connection is LSO capable. Will check whether having
	 * enough available data to initiate LSO transmission in the for(){}
	 * loops.
	 */
	if (tcp->tcp_lso && (tcp->tcp_valid_bits & ~TCP_FSS_VALID) == 0)
		do_lso_send = B_TRUE;

	for (;;) {
		struct datab	*db;
		tcpha_t		*tcpha;
		uint32_t	sum;
		mblk_t		*mp, *mp1;
		uchar_t		*rptr;
		int		len;

		/*
		 * Calculate the maximum payload length we can send at one
		 * time.
		 */
		if (do_lso_send) {
			/*
			 * Determine whether or not it's possible to do LSO,
			 * and if so, how much data we can send.
			 */
			if ((*usable - 1) / mss >= 1) {
				lso_usable = MIN(tcp->tcp_lso_max, *usable);
				num_lso_seg = lso_usable / mss;
				if (lso_usable % mss) {
					num_lso_seg++;
					tcp->tcp_last_sent_len = (ushort_t)
					    (lso_usable % mss);
				} else {
					tcp->tcp_last_sent_len = (ushort_t)mss;
				}
			} else {
				do_lso_send = B_FALSE;
				num_lso_seg = 1;
				lso_usable = mss;
			}
		}

		ASSERT(num_lso_seg <= IP_MAXPACKET / mss + 1);

		len = mss;
		if (len > *usable) {
			ASSERT(do_lso_send == B_FALSE);

			len = *usable;
			if (len <= 0) {
				/* Terminate the loop */
				break;	/* success; too small */
			}
			/*
			 * Sender silly-window avoidance.
			 * Ignore this if we are going to send a
			 * zero window probe out.
			 *
			 * TODO: force data into microscopic window?
			 *	==> (!pushed || (unsent > usable))
			 */
			if (len < (tcp->tcp_max_swnd >> 1) &&
			    (tcp->tcp_unsent - (*snxt - tcp->tcp_snxt)) > len &&
			    !((tcp->tcp_valid_bits & TCP_URG_VALID) &&
			    len == 1) && (! tcp->tcp_zero_win_probe)) {
				/*
				 * If the retransmit timer is not running
				 * we start it so that we will retransmit
				 * in the case when the receiver has
				 * decremented the window.
				 */
				if (*snxt == tcp->tcp_snxt &&
				    *snxt == tcp->tcp_suna) {
					/*
					 * We are not supposed to send
					 * anything.  So let's wait a little
					 * bit longer before breaking SWS
					 * avoidance.
					 *
					 * What should the value be?
					 * Suggestion: MAX(init rexmit time,
					 * tcp->tcp_rto)
					 */
					TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
				}
				break;	/* success; too small */
			}
		}

		tcpha = tcp->tcp_tcpha;

		/*
		 * The reason to adjust len here is that we need to set flags
		 * and calculate checksum.
		 */
		if (do_lso_send)
			len = lso_usable;

		*usable -= len; /* Approximate - can be adjusted later */
		if (*usable > 0)
			tcpha->tha_flags = TH_ACK;
		else
			tcpha->tha_flags = (TH_ACK | TH_PUSH);

		/*
		 * Prime pump for IP's checksumming on our behalf.
		 * Include the adjustment for a source route if any.
		 * In case of LSO, the partial pseudo-header checksum should
		 * exclusive TCP length, so zero tha_sum before IP calculate
		 * pseudo-header checksum for partial checksum offload.
		 */
		if (do_lso_send) {
			sum = 0;
		} else {
			sum = len + tcp_hdr_len + connp->conn_sum;
			sum = (sum >> 16) + (sum & 0xFFFF);
		}
		tcpha->tha_sum = htons(sum);
		tcpha->tha_seq = htonl(*snxt);

		/*
		 * Branch off to tcp_xmit_mp() if any of the VALID bits is
		 * set.  For the case when TCP_FSS_VALID is the only valid
		 * bit (normal active close), branch off only when we think
		 * that the FIN flag needs to be set.  Note for this case,
		 * that (snxt + len) may not reflect the actual seg_len,
		 * as len may be further reduced in tcp_xmit_mp().  If len
		 * gets modified, we will end up here again.
		 */
		if (tcp->tcp_valid_bits != 0 &&
		    (tcp->tcp_valid_bits != TCP_FSS_VALID ||
		    ((*snxt + len) == tcp->tcp_fss))) {
			uchar_t		*prev_rptr;
			uint32_t	prev_snxt = tcp->tcp_snxt;

			if (*tail_unsent == 0) {
				ASSERT((*xmit_tail)->b_cont != NULL);
				*xmit_tail = (*xmit_tail)->b_cont;
				prev_rptr = (*xmit_tail)->b_rptr;
				*tail_unsent = (int)((*xmit_tail)->b_wptr -
				    (*xmit_tail)->b_rptr);
			} else {
				prev_rptr = (*xmit_tail)->b_rptr;
				(*xmit_tail)->b_rptr = (*xmit_tail)->b_wptr -
				    *tail_unsent;
			}
			mp = tcp_xmit_mp(tcp, *xmit_tail, len, NULL, NULL,
			    *snxt, B_FALSE, (uint32_t *)&len, B_FALSE);
			/* Restore tcp_snxt so we get amount sent right. */
			tcp->tcp_snxt = prev_snxt;
			if (prev_rptr == (*xmit_tail)->b_rptr) {
				/*
				 * If the previous timestamp is still in use,
				 * don't stomp on it.
				 */
				if ((*xmit_tail)->b_next == NULL) {
					(*xmit_tail)->b_prev = local_time;
					(*xmit_tail)->b_next =
					    (mblk_t *)(uintptr_t)(*snxt);
				}
			} else
				(*xmit_tail)->b_rptr = prev_rptr;

			if (mp == NULL) {
				return (-1);
			}
			mp1 = mp->b_cont;

			if (len <= mss) /* LSO is unusable (!do_lso_send) */
				tcp->tcp_last_sent_len = (ushort_t)len;
			while (mp1->b_cont) {
				*xmit_tail = (*xmit_tail)->b_cont;
				(*xmit_tail)->b_prev = local_time;
				(*xmit_tail)->b_next =
				    (mblk_t *)(uintptr_t)(*snxt);
				mp1 = mp1->b_cont;
			}
			*snxt += len;
			*tail_unsent = (*xmit_tail)->b_wptr - mp1->b_wptr;
			BUMP_LOCAL(tcp->tcp_obsegs);
			TCPS_BUMP_MIB(tcps, tcpOutDataSegs);
			TCPS_UPDATE_MIB(tcps, tcpOutDataBytes, len);
			tcp_send_data(tcp, mp);
			continue;
		}

		*snxt += len;	/* Adjust later if we don't send all of len */
		TCPS_BUMP_MIB(tcps, tcpOutDataSegs);
		TCPS_UPDATE_MIB(tcps, tcpOutDataBytes, len);

		if (*tail_unsent) {
			/* Are the bytes above us in flight? */
			rptr = (*xmit_tail)->b_wptr - *tail_unsent;
			if (rptr != (*xmit_tail)->b_rptr) {
				*tail_unsent -= len;
				if (len <= mss) /* LSO is unusable */
					tcp->tcp_last_sent_len = (ushort_t)len;
				len += total_hdr_len;
				ixa->ixa_pktlen = len;

				if (ixa->ixa_flags & IXAF_IS_IPV4) {
					tcp->tcp_ipha->ipha_length = htons(len);
				} else {
					tcp->tcp_ip6h->ip6_plen =
					    htons(len - IPV6_HDR_LEN);
				}

				mp = dupb(*xmit_tail);
				if (mp == NULL) {
					return (-1);	/* out_of_mem */
				}
				mp->b_rptr = rptr;
				/*
				 * If the old timestamp is no longer in use,
				 * sample a new timestamp now.
				 */
				if ((*xmit_tail)->b_next == NULL) {
					(*xmit_tail)->b_prev = local_time;
					(*xmit_tail)->b_next =
					    (mblk_t *)(uintptr_t)(*snxt-len);
				}
				goto must_alloc;
			}
		} else {
			*xmit_tail = (*xmit_tail)->b_cont;
			ASSERT((uintptr_t)((*xmit_tail)->b_wptr -
			    (*xmit_tail)->b_rptr) <= (uintptr_t)INT_MAX);
			*tail_unsent = (int)((*xmit_tail)->b_wptr -
			    (*xmit_tail)->b_rptr);
		}

		(*xmit_tail)->b_prev = local_time;
		(*xmit_tail)->b_next = (mblk_t *)(uintptr_t)(*snxt - len);

		*tail_unsent -= len;
		if (len <= mss) /* LSO is unusable (!do_lso_send) */
			tcp->tcp_last_sent_len = (ushort_t)len;

		len += total_hdr_len;
		ixa->ixa_pktlen = len;

		if (ixa->ixa_flags & IXAF_IS_IPV4) {
			tcp->tcp_ipha->ipha_length = htons(len);
		} else {
			tcp->tcp_ip6h->ip6_plen = htons(len - IPV6_HDR_LEN);
		}

		mp = dupb(*xmit_tail);
		if (mp == NULL) {
			return (-1);	/* out_of_mem */
		}

		len = total_hdr_len;
		/*
		 * There are four reasons to allocate a new hdr mblk:
		 *  1) The bytes above us are in use by another packet
		 *  2) We don't have good alignment
		 *  3) The mblk is being shared
		 *  4) We don't have enough room for a header
		 */
		rptr = mp->b_rptr - len;
		if (!OK_32PTR(rptr) ||
		    ((db = mp->b_datap), db->db_ref != 2) ||
		    rptr < db->db_base) {
			/* NOTE: we assume allocb returns an OK_32PTR */

		must_alloc:;
			mp1 = allocb(connp->conn_ht_iphc_allocated +
			    tcps->tcps_wroff_xtra, BPRI_MED);
			if (mp1 == NULL) {
				freemsg(mp);
				return (-1);	/* out_of_mem */
			}
			mp1->b_cont = mp;
			mp = mp1;
			/* Leave room for Link Level header */
			len = total_hdr_len;
			rptr = &mp->b_rptr[tcps->tcps_wroff_xtra];
			mp->b_wptr = &rptr[len];
		}

		/*
		 * Fill in the header using the template header, and add
		 * options such as time-stamp, ECN and/or SACK, as needed.
		 */
		tcp_fill_header(tcp, rptr, (clock_t)local_time, num_sack_blk);

		mp->b_rptr = rptr;

		if (*tail_unsent) {
			int spill = *tail_unsent;

			mp1 = mp->b_cont;
			if (mp1 == NULL)
				mp1 = mp;

			/*
			 * If we're a little short, tack on more mblks until
			 * there is no more spillover.
			 */
			while (spill < 0) {
				mblk_t *nmp;
				int nmpsz;

				nmp = (*xmit_tail)->b_cont;
				nmpsz = MBLKL(nmp);

				/*
				 * Excess data in mblk; can we split it?
				 * If LSO is enabled for the connection,
				 * keep on splitting as this is a transient
				 * send path.
				 */
				if (!do_lso_send && (spill + nmpsz > 0)) {
					/*
					 * Don't split if stream head was
					 * told to break up larger writes
					 * into smaller ones.
					 */
					if (tcp->tcp_maxpsz_multiplier > 0)
						break;

					/*
					 * Next mblk is less than SMSS/2
					 * rounded up to nearest 64-byte;
					 * let it get sent as part of the
					 * next segment.
					 */
					if (tcp->tcp_localnet &&
					    !tcp->tcp_cork &&
					    (nmpsz < roundup((mss >> 1), 64)))
						break;
				}

				*xmit_tail = nmp;
				ASSERT((uintptr_t)nmpsz <= (uintptr_t)INT_MAX);
				/* Stash for rtt use later */
				(*xmit_tail)->b_prev = local_time;
				(*xmit_tail)->b_next =
				    (mblk_t *)(uintptr_t)(*snxt - len);
				mp1->b_cont = dupb(*xmit_tail);
				mp1 = mp1->b_cont;

				spill += nmpsz;
				if (mp1 == NULL) {
					*tail_unsent = spill;
					freemsg(mp);
					return (-1);	/* out_of_mem */
				}
			}

			/* Trim back any surplus on the last mblk */
			if (spill >= 0) {
				mp1->b_wptr -= spill;
				*tail_unsent = spill;
			} else {
				/*
				 * We did not send everything we could in
				 * order to remain within the b_cont limit.
				 */
				*usable -= spill;
				*snxt += spill;
				tcp->tcp_last_sent_len += spill;
				TCPS_UPDATE_MIB(tcps, tcpOutDataBytes, spill);
				/*
				 * Adjust the checksum
				 */
				tcpha = (tcpha_t *)(rptr +
				    ixa->ixa_ip_hdr_length);
				sum += spill;
				sum = (sum >> 16) + (sum & 0xFFFF);
				tcpha->tha_sum = htons(sum);
				if (connp->conn_ipversion == IPV4_VERSION) {
					sum = ntohs(
					    ((ipha_t *)rptr)->ipha_length) +
					    spill;
					((ipha_t *)rptr)->ipha_length =
					    htons(sum);
				} else {
					sum = ntohs(
					    ((ip6_t *)rptr)->ip6_plen) +
					    spill;
					((ip6_t *)rptr)->ip6_plen =
					    htons(sum);
				}
				ixa->ixa_pktlen += spill;
				*tail_unsent = 0;
			}
		}
		if (tcp->tcp_ip_forward_progress) {
			tcp->tcp_ip_forward_progress = B_FALSE;
			ixa->ixa_flags |= IXAF_REACH_CONF;
		} else {
			ixa->ixa_flags &= ~IXAF_REACH_CONF;
		}

		if (do_lso_send) {
			/* Append LSO information to the mp. */
			lso_info_set(mp, mss, HW_LSO);
			ixa->ixa_fragsize = IP_MAXPACKET;
			ixa->ixa_extra_ident = num_lso_seg - 1;

			DTRACE_PROBE2(tcp_send_lso, int, num_lso_seg,
			    boolean_t, B_TRUE);

			tcp_send_data(tcp, mp);

			/*
			 * Restore values of ixa_fragsize and ixa_extra_ident.
			 */
			ixa->ixa_fragsize = ixa->ixa_pmtu;
			ixa->ixa_extra_ident = 0;
			tcp->tcp_obsegs += num_lso_seg;
			TCP_STAT(tcps, tcp_lso_times);
			TCP_STAT_UPDATE(tcps, tcp_lso_pkt_out, num_lso_seg);
		} else {
			/*
			 * Make sure to clean up LSO information. Wherever a
			 * new mp uses the prepended header room after dupb(),
			 * lso_info_cleanup() should be called.
			 */
			lso_info_cleanup(mp);
			tcp_send_data(tcp, mp);
			BUMP_LOCAL(tcp->tcp_obsegs);
		}
	}

	return (0);
}

/*
 * Initiate closedown sequence on an active connection.  (May be called as
 * writer.)  Return value zero for OK return, non-zero for error return.
 */
static int
tcp_xmit_end(tcp_t *tcp)
{
	mblk_t		*mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	iulp_t		uinfo;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;
	conn_t		*connp = tcp->tcp_connp;

	if (tcp->tcp_state < TCPS_SYN_RCVD ||
	    tcp->tcp_state > TCPS_CLOSE_WAIT) {
		/*
		 * Invalid state, only states TCPS_SYN_RCVD,
		 * TCPS_ESTABLISHED and TCPS_CLOSE_WAIT are valid
		 */
		return (-1);
	}

	tcp->tcp_fss = tcp->tcp_snxt + tcp->tcp_unsent;
	tcp->tcp_valid_bits |= TCP_FSS_VALID;
	/*
	 * If there is nothing more unsent, send the FIN now.
	 * Otherwise, it will go out with the last segment.
	 */
	if (tcp->tcp_unsent == 0) {
		mp = tcp_xmit_mp(tcp, NULL, 0, NULL, NULL,
		    tcp->tcp_fss, B_FALSE, NULL, B_FALSE);

		if (mp) {
			tcp_send_data(tcp, mp);
		} else {
			/*
			 * Couldn't allocate msg.  Pretend we got it out.
			 * Wait for rexmit timeout.
			 */
			tcp->tcp_snxt = tcp->tcp_fss + 1;
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
		}

		/*
		 * If needed, update tcp_rexmit_snxt as tcp_snxt is
		 * changed.
		 */
		if (tcp->tcp_rexmit && tcp->tcp_rexmit_nxt == tcp->tcp_fss) {
			tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
		}
	} else {
		/*
		 * If tcp->tcp_cork is set, then the data will not get sent,
		 * so we have to check that and unset it first.
		 */
		if (tcp->tcp_cork)
			tcp->tcp_cork = B_FALSE;
		tcp_wput_data(tcp, NULL, B_FALSE);
	}

	/*
	 * If TCP does not get enough samples of RTT or tcp_rtt_updates
	 * is 0, don't update the cache.
	 */
	if (tcps->tcps_rtt_updates == 0 ||
	    tcp->tcp_rtt_update < tcps->tcps_rtt_updates)
		return (0);

	/*
	 * We do not have a good algorithm to update ssthresh at this time.
	 * So don't do any update.
	 */
	bzero(&uinfo, sizeof (uinfo));
	uinfo.iulp_rtt = tcp->tcp_rtt_sa;
	uinfo.iulp_rtt_sd = tcp->tcp_rtt_sd;

	/*
	 * Note that uinfo is kept for conn_faddr in the DCE. Could update even
	 * if source routed but we don't.
	 */
	if (connp->conn_ipversion == IPV4_VERSION) {
		if (connp->conn_faddr_v4 !=  tcp->tcp_ipha->ipha_dst) {
			return (0);
		}
		(void) dce_update_uinfo_v4(connp->conn_faddr_v4, &uinfo, ipst);
	} else {
		uint_t ifindex;

		if (!(IN6_ARE_ADDR_EQUAL(&connp->conn_faddr_v6,
		    &tcp->tcp_ip6h->ip6_dst))) {
			return (0);
		}
		ifindex = 0;
		if (IN6_IS_ADDR_LINKSCOPE(&connp->conn_faddr_v6)) {
			ip_xmit_attr_t *ixa = connp->conn_ixa;

			/*
			 * If we are going to create a DCE we'd better have
			 * an ifindex
			 */
			if (ixa->ixa_nce != NULL) {
				ifindex = ixa->ixa_nce->nce_common->ncec_ill->
				    ill_phyint->phyint_ifindex;
			} else {
				return (0);
			}
		}

		(void) dce_update_uinfo(&connp->conn_faddr_v6, ifindex, &uinfo,
		    ipst);
	}
	return (0);
}

/*
 * Send out a control packet on the tcp connection specified.  This routine
 * is typically called where we need a simple ACK or RST generated.
 */
void
tcp_xmit_ctl(char *str, tcp_t *tcp, uint32_t seq, uint32_t ack, int ctl)
{
	uchar_t		*rptr;
	tcpha_t		*tcpha;
	ipha_t		*ipha = NULL;
	ip6_t		*ip6h = NULL;
	uint32_t	sum;
	int		total_hdr_len;
	int		ip_hdr_len;
	mblk_t		*mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;
	ip_xmit_attr_t	*ixa = connp->conn_ixa;

	/*
	 * Save sum for use in source route later.
	 */
	sum = connp->conn_ht_ulp_len + connp->conn_sum;
	total_hdr_len = connp->conn_ht_iphc_len;
	ip_hdr_len = ixa->ixa_ip_hdr_length;

	/* If a text string is passed in with the request, pass it to strlog. */
	if (str != NULL && connp->conn_debug) {
		(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
		    "tcp_xmit_ctl: '%s', seq 0x%x, ack 0x%x, ctl 0x%x",
		    str, seq, ack, ctl);
	}
	mp = allocb(connp->conn_ht_iphc_allocated + tcps->tcps_wroff_xtra,
	    BPRI_MED);
	if (mp == NULL) {
		return;
	}
	rptr = &mp->b_rptr[tcps->tcps_wroff_xtra];
	mp->b_rptr = rptr;
	mp->b_wptr = &rptr[total_hdr_len];
	bcopy(connp->conn_ht_iphc, rptr, total_hdr_len);

	ixa->ixa_pktlen = total_hdr_len;

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipha = (ipha_t *)rptr;
		ipha->ipha_length = htons(total_hdr_len);
	} else {
		ip6h = (ip6_t *)rptr;
		ip6h->ip6_plen = htons(total_hdr_len - IPV6_HDR_LEN);
	}
	tcpha = (tcpha_t *)&rptr[ip_hdr_len];
	tcpha->tha_flags = (uint8_t)ctl;
	if (ctl & TH_RST) {
		TCPS_BUMP_MIB(tcps, tcpOutRsts);
		TCPS_BUMP_MIB(tcps, tcpOutControl);
		/*
		 * Don't send TSopt w/ TH_RST packets per RFC 1323.
		 */
		if (tcp->tcp_snd_ts_ok &&
		    tcp->tcp_state > TCPS_SYN_SENT) {
			mp->b_wptr = &rptr[total_hdr_len - TCPOPT_REAL_TS_LEN];
			*(mp->b_wptr) = TCPOPT_EOL;

			ixa->ixa_pktlen = total_hdr_len - TCPOPT_REAL_TS_LEN;

			if (connp->conn_ipversion == IPV4_VERSION) {
				ipha->ipha_length = htons(total_hdr_len -
				    TCPOPT_REAL_TS_LEN);
			} else {
				ip6h->ip6_plen = htons(total_hdr_len -
				    IPV6_HDR_LEN - TCPOPT_REAL_TS_LEN);
			}
			tcpha->tha_offset_and_reserved -= (3 << 4);
			sum -= TCPOPT_REAL_TS_LEN;
		}
	}
	if (ctl & TH_ACK) {
		if (tcp->tcp_snd_ts_ok) {
			uint32_t llbolt = (uint32_t)LBOLT_FASTPATH;

			U32_TO_BE32(llbolt,
			    (char *)tcpha + TCP_MIN_HEADER_LENGTH+4);
			U32_TO_BE32(tcp->tcp_ts_recent,
			    (char *)tcpha + TCP_MIN_HEADER_LENGTH+8);
		}

		/* Update the latest receive window size in TCP header. */
		tcpha->tha_win = htons(tcp->tcp_rwnd >> tcp->tcp_rcv_ws);
		/* Track what we sent to the peer */
		tcp->tcp_tcpha->tha_win = tcpha->tha_win;
		tcp->tcp_rack = ack;
		tcp->tcp_rack_cnt = 0;
		TCPS_BUMP_MIB(tcps, tcpOutAck);
	}
	BUMP_LOCAL(tcp->tcp_obsegs);
	tcpha->tha_seq = htonl(seq);
	tcpha->tha_ack = htonl(ack);
	/*
	 * Include the adjustment for a source route if any.
	 */
	sum = (sum >> 16) + (sum & 0xFFFF);
	tcpha->tha_sum = htons(sum);
	tcp_send_data(tcp, mp);
}

/*
 * Generate a reset based on an inbound packet, connp is set by caller
 * when RST is in response to an unexpected inbound packet for which
 * there is active tcp state in the system.
 *
 * IPSEC NOTE : Try to send the reply with the same protection as it came
 * in.  We have the ip_recv_attr_t which is reversed to form the ip_xmit_attr_t.
 * That way the packet will go out at the same level of protection as it
 * came in with.
 */
static void
tcp_xmit_early_reset(char *str, mblk_t *mp, uint32_t seq, uint32_t ack, int ctl,
    ip_recv_attr_t *ira, ip_stack_t *ipst, conn_t *connp)
{
	ipha_t		*ipha = NULL;
	ip6_t		*ip6h = NULL;
	ushort_t	len;
	tcpha_t		*tcpha;
	int		i;
	ipaddr_t	v4addr;
	in6_addr_t	v6addr;
	netstack_t	*ns = ipst->ips_netstack;
	tcp_stack_t	*tcps = ns->netstack_tcp;
	ip_xmit_attr_t	ixas, *ixa;
	uint_t		ip_hdr_len = ira->ira_ip_hdr_length;
	boolean_t	need_refrele = B_FALSE;		/* ixa_refrele(ixa) */
	ushort_t	port;

	if (!tcp_send_rst_chk(tcps)) {
		TCP_STAT(tcps, tcp_rst_unsent);
		freemsg(mp);
		return;
	}

	/*
	 * If connp != NULL we use conn_ixa to keep IP_NEXTHOP and other
	 * options from the listener. In that case the caller must ensure that
	 * we are running on the listener = connp squeue.
	 *
	 * We get a safe copy of conn_ixa so we don't need to restore anything
	 * we or ip_output_simple might change in the ixa.
	 */
	if (connp != NULL) {
		ASSERT(connp->conn_on_sqp);

		ixa = conn_get_ixa_exclusive(connp);
		if (ixa == NULL) {
			TCP_STAT(tcps, tcp_rst_unsent);
			freemsg(mp);
			return;
		}
		need_refrele = B_TRUE;
	} else {
		bzero(&ixas, sizeof (ixas));
		ixa = &ixas;
		/*
		 * IXAF_VERIFY_SOURCE is overkill since we know the
		 * packet was for us.
		 */
		ixa->ixa_flags |= IXAF_SET_ULP_CKSUM | IXAF_VERIFY_SOURCE;
		ixa->ixa_protocol = IPPROTO_TCP;
		ixa->ixa_zoneid = ira->ira_zoneid;
		ixa->ixa_ifindex = 0;
		ixa->ixa_ipst = ipst;
		ixa->ixa_cred = kcred;
		ixa->ixa_cpid = NOPID;
	}

	if (str && tcps->tcps_dbg) {
		(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
		    "tcp_xmit_early_reset: '%s', seq 0x%x, ack 0x%x, "
		    "flags 0x%x",
		    str, seq, ack, ctl);
	}
	if (mp->b_datap->db_ref != 1) {
		mblk_t *mp1 = copyb(mp);
		freemsg(mp);
		mp = mp1;
		if (mp == NULL)
			goto done;
	} else if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
		DB_CKSUMFLAGS(mp) = 0;
	}
	/*
	 * We skip reversing source route here.
	 * (for now we replace all IP options with EOL)
	 */
	if (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION) {
		ipha = (ipha_t *)mp->b_rptr;
		for (i = IP_SIMPLE_HDR_LENGTH; i < (int)ip_hdr_len; i++)
			mp->b_rptr[i] = IPOPT_EOL;
		/*
		 * Make sure that src address isn't flagrantly invalid.
		 * Not all broadcast address checking for the src address
		 * is possible, since we don't know the netmask of the src
		 * addr.  No check for destination address is done, since
		 * IP will not pass up a packet with a broadcast dest
		 * address to TCP.  Similar checks are done below for IPv6.
		 */
		if (ipha->ipha_src == 0 || ipha->ipha_src == INADDR_BROADCAST ||
		    CLASSD(ipha->ipha_src)) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, NULL);
			freemsg(mp);
			goto done;
		}
	} else {
		ip6h = (ip6_t *)mp->b_rptr;

		if (IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src) ||
		    IN6_IS_ADDR_MULTICAST(&ip6h->ip6_src)) {
			BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, NULL);
			freemsg(mp);
			goto done;
		}

		/* Remove any extension headers assuming partial overlay */
		if (ip_hdr_len > IPV6_HDR_LEN) {
			uint8_t *to;

			to = mp->b_rptr + ip_hdr_len - IPV6_HDR_LEN;
			ovbcopy(ip6h, to, IPV6_HDR_LEN);
			mp->b_rptr += ip_hdr_len - IPV6_HDR_LEN;
			ip_hdr_len = IPV6_HDR_LEN;
			ip6h = (ip6_t *)mp->b_rptr;
			ip6h->ip6_nxt = IPPROTO_TCP;
		}
	}
	tcpha = (tcpha_t *)&mp->b_rptr[ip_hdr_len];
	if (tcpha->tha_flags & TH_RST) {
		freemsg(mp);
		goto done;
	}
	tcpha->tha_offset_and_reserved = (5 << 4);
	len = ip_hdr_len + sizeof (tcpha_t);
	mp->b_wptr = &mp->b_rptr[len];
	if (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION) {
		ipha->ipha_length = htons(len);
		/* Swap addresses */
		v4addr = ipha->ipha_src;
		ipha->ipha_src = ipha->ipha_dst;
		ipha->ipha_dst = v4addr;
		ipha->ipha_ident = 0;
		ipha->ipha_ttl = (uchar_t)tcps->tcps_ipv4_ttl;
		ixa->ixa_flags |= IXAF_IS_IPV4;
		ixa->ixa_ip_hdr_length = ip_hdr_len;
	} else {
		ip6h->ip6_plen = htons(len - IPV6_HDR_LEN);
		/* Swap addresses */
		v6addr = ip6h->ip6_src;
		ip6h->ip6_src = ip6h->ip6_dst;
		ip6h->ip6_dst = v6addr;
		ip6h->ip6_hops = (uchar_t)tcps->tcps_ipv6_hoplimit;
		ixa->ixa_flags &= ~IXAF_IS_IPV4;

		if (IN6_IS_ADDR_LINKSCOPE(&ip6h->ip6_dst)) {
			ixa->ixa_flags |= IXAF_SCOPEID_SET;
			ixa->ixa_scopeid = ira->ira_ruifindex;
		}
		ixa->ixa_ip_hdr_length = IPV6_HDR_LEN;
	}
	ixa->ixa_pktlen = len;

	/* Swap the ports */
	port = tcpha->tha_fport;
	tcpha->tha_fport = tcpha->tha_lport;
	tcpha->tha_lport = port;

	tcpha->tha_ack = htonl(ack);
	tcpha->tha_seq = htonl(seq);
	tcpha->tha_win = 0;
	tcpha->tha_sum = htons(sizeof (tcpha_t));
	tcpha->tha_flags = (uint8_t)ctl;
	if (ctl & TH_RST) {
		if (ctl & TH_ACK) {
			/*
			 * Probe connection rejection here.
			 * tcp_xmit_listeners_reset() drops non-SYN segments
			 * that do not specify TH_ACK in their flags without
			 * calling this function.  As a consequence, if this
			 * function is called with a TH_RST|TH_ACK ctl argument,
			 * it is being called in response to a SYN segment
			 * and thus the tcp:::accept-refused probe point
			 * is valid here.
			 */
			DTRACE_TCP5(accept__refused, mblk_t *, NULL,
			    void, NULL, void_ip_t *, mp->b_rptr, tcp_t *, NULL,
			    tcph_t *, tcpha);
		}
		TCPS_BUMP_MIB(tcps, tcpOutRsts);
		TCPS_BUMP_MIB(tcps, tcpOutControl);
	}

	/* Discard any old label */
	if (ixa->ixa_free_flags & IXA_FREE_TSL) {
		ASSERT(ixa->ixa_tsl != NULL);
		label_rele(ixa->ixa_tsl);
		ixa->ixa_free_flags &= ~IXA_FREE_TSL;
	}
	ixa->ixa_tsl = ira->ira_tsl;	/* Behave as a multi-level responder */

	if (ira->ira_flags & IRAF_IPSEC_SECURE) {
		/*
		 * Apply IPsec based on how IPsec was applied to
		 * the packet that caused the RST.
		 */
		if (!ipsec_in_to_out(ira, ixa, mp, ipha, ip6h)) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			/* Note: mp already consumed and ip_drop_packet done */
			goto done;
		}
	} else {
		/*
		 * This is in clear. The RST message we are building
		 * here should go out in clear, independent of our policy.
		 */
		ixa->ixa_flags |= IXAF_NO_IPSEC;
	}

	DTRACE_TCP5(send, mblk_t *, NULL, ip_xmit_attr_t *, ixa,
	    __dtrace_tcp_void_ip_t *, mp->b_rptr, tcp_t *, NULL,
	    __dtrace_tcp_tcph_t *, tcpha);

	/*
	 * NOTE:  one might consider tracing a TCP packet here, but
	 * this function has no active TCP state and no tcp structure
	 * that has a trace buffer.  If we traced here, we would have
	 * to keep a local trace buffer in tcp_record_trace().
	 */

	(void) ip_output_simple(mp, ixa);
done:
	ixa_cleanup(ixa);
	if (need_refrele) {
		ASSERT(ixa != &ixas);
		ixa_refrele(ixa);
	}
}

/*
 * Generate a "no listener here" RST in response to an "unknown" segment.
 * connp is set by caller when RST is in response to an unexpected
 * inbound packet for which there is active tcp state in the system.
 * Note that we are reusing the incoming mp to construct the outgoing RST.
 */
void
tcp_xmit_listeners_reset(mblk_t *mp, ip_recv_attr_t *ira, ip_stack_t *ipst,
    conn_t *connp)
{
	uchar_t		*rptr;
	uint32_t	seg_len;
	tcpha_t		*tcpha;
	uint32_t	seg_seq;
	uint32_t	seg_ack;
	uint_t		flags;
	ipha_t 		*ipha;
	ip6_t 		*ip6h;
	boolean_t	policy_present;
	netstack_t	*ns = ipst->ips_netstack;
	tcp_stack_t	*tcps = ns->netstack_tcp;
	ipsec_stack_t	*ipss = tcps->tcps_netstack->netstack_ipsec;
	uint_t		ip_hdr_len = ira->ira_ip_hdr_length;

	TCP_STAT(tcps, tcp_no_listener);

	/*
	 * DTrace this "unknown" segment as a tcp:::receive, as we did
	 * just receive something that was TCP.
	 */
	DTRACE_TCP5(receive, mblk_t *, NULL, ip_xmit_attr_t *, NULL,
	    __dtrace_tcp_void_ip_t *, mp->b_rptr, tcp_t *, NULL,
	    __dtrace_tcp_tcph_t *, &mp->b_rptr[ip_hdr_len]);

	if (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION) {
		policy_present = ipss->ipsec_inbound_v4_policy_present;
		ipha = (ipha_t *)mp->b_rptr;
		ip6h = NULL;
	} else {
		policy_present = ipss->ipsec_inbound_v6_policy_present;
		ipha = NULL;
		ip6h = (ip6_t *)mp->b_rptr;
	}

	if (policy_present) {
		/*
		 * The conn_t parameter is NULL because we already know
		 * nobody's home.
		 */
		mp = ipsec_check_global_policy(mp, (conn_t *)NULL, ipha, ip6h,
		    ira, ns);
		if (mp == NULL)
			return;
	}
	if (is_system_labeled() && !tsol_can_reply_error(mp, ira)) {
		DTRACE_PROBE2(
		    tx__ip__log__error__nolistener__tcp,
		    char *, "Could not reply with RST to mp(1)",
		    mblk_t *, mp);
		ip2dbg(("tcp_xmit_listeners_reset: not permitted to reply\n"));
		freemsg(mp);
		return;
	}

	rptr = mp->b_rptr;

	tcpha = (tcpha_t *)&rptr[ip_hdr_len];
	seg_seq = ntohl(tcpha->tha_seq);
	seg_ack = ntohl(tcpha->tha_ack);
	flags = tcpha->tha_flags;

	seg_len = msgdsize(mp) - (TCP_HDR_LENGTH(tcpha) + ip_hdr_len);
	if (flags & TH_RST) {
		freemsg(mp);
	} else if (flags & TH_ACK) {
		tcp_xmit_early_reset("no tcp, reset", mp, seg_ack, 0, TH_RST,
		    ira, ipst, connp);
	} else {
		if (flags & TH_SYN) {
			seg_len++;
		} else {
			/*
			 * Here we violate the RFC.  Note that a normal
			 * TCP will never send a segment without the ACK
			 * flag, except for RST or SYN segment.  This
			 * segment is neither.  Just drop it on the
			 * floor.
			 */
			freemsg(mp);
			TCP_STAT(tcps, tcp_rst_unsent);
			return;
		}

		tcp_xmit_early_reset("no tcp, reset/ack", mp, 0,
		    seg_seq + seg_len, TH_RST | TH_ACK, ira, ipst, connp);
	}
}

/*
 * Helper function for tcp_xmit_mp() in handling connection set up flag
 * options setting.
 */
static void
tcp_xmit_mp_aux_iss(tcp_t *tcp, conn_t *connp, tcpha_t *tcpha, mblk_t *mp,
    uint_t *flags)
{
	uint32_t u1;
	uint8_t	*wptr = mp->b_wptr;
	tcp_stack_t *tcps = tcp->tcp_tcps;
	boolean_t add_sack = B_FALSE;

	/*
	 * If TCP_ISS_VALID and the seq number is tcp_iss,
	 * TCP can only be in SYN-SENT, SYN-RCVD or
	 * FIN-WAIT-1 state.  It can be FIN-WAIT-1 if
	 * our SYN is not ack'ed but the app closes this
	 * TCP connection.
	 */
	ASSERT(tcp->tcp_state == TCPS_SYN_SENT ||
	    tcp->tcp_state == TCPS_SYN_RCVD ||
	    tcp->tcp_state == TCPS_FIN_WAIT_1);

	/*
	 * Tack on the MSS option.  It is always needed
	 * for both active and passive open.
	 *
	 * MSS option value should be interface MTU - MIN
	 * TCP/IP header according to RFC 793 as it means
	 * the maximum segment size TCP can receive.  But
	 * to get around some broken middle boxes/end hosts
	 * out there, we allow the option value to be the
	 * same as the MSS option size on the peer side.
	 * In this way, the other side will not send
	 * anything larger than they can receive.
	 *
	 * Note that for SYN_SENT state, the ndd param
	 * tcp_use_smss_as_mss_opt has no effect as we
	 * don't know the peer's MSS option value. So
	 * the only case we need to take care of is in
	 * SYN_RCVD state, which is done later.
	 */
	wptr[0] = TCPOPT_MAXSEG;
	wptr[1] = TCPOPT_MAXSEG_LEN;
	wptr += 2;
	u1 = tcp->tcp_initial_pmtu - (connp->conn_ipversion == IPV4_VERSION ?
	    IP_SIMPLE_HDR_LENGTH : IPV6_HDR_LEN) - TCP_MIN_HEADER_LENGTH;
	U16_TO_BE16(u1, wptr);
	wptr += 2;

	/* Update the offset to cover the additional word */
	tcpha->tha_offset_and_reserved += (1 << 4);

	switch (tcp->tcp_state) {
	case TCPS_SYN_SENT:
		*flags = TH_SYN;

		if (tcp->tcp_snd_sack_ok)
			add_sack = B_TRUE;

		if (tcp->tcp_snd_ts_ok) {
			uint32_t llbolt = (uint32_t)LBOLT_FASTPATH;

			if (add_sack) {
				wptr[0] = TCPOPT_SACK_PERMITTED;
				wptr[1] = TCPOPT_SACK_OK_LEN;
				add_sack = B_FALSE;
			} else {
				wptr[0] = TCPOPT_NOP;
				wptr[1] = TCPOPT_NOP;
			}
			wptr[2] = TCPOPT_TSTAMP;
			wptr[3] = TCPOPT_TSTAMP_LEN;
			wptr += 4;
			U32_TO_BE32(llbolt, wptr);
			wptr += 4;
			ASSERT(tcp->tcp_ts_recent == 0);
			U32_TO_BE32(0L, wptr);
			wptr += 4;
			tcpha->tha_offset_and_reserved += (3 << 4);
		}

		/*
		 * Set up all the bits to tell other side
		 * we are ECN capable.
		 */
		if (tcp->tcp_ecn_ok)
			*flags |= (TH_ECE | TH_CWR);

		break;

	case TCPS_SYN_RCVD:
		*flags |= TH_SYN;

		/*
		 * Reset the MSS option value to be SMSS
		 * We should probably add back the bytes
		 * for timestamp option and IPsec.  We
		 * don't do that as this is a workaround
		 * for broken middle boxes/end hosts, it
		 * is better for us to be more cautious.
		 * They may not take these things into
		 * account in their SMSS calculation.  Thus
		 * the peer's calculated SMSS may be smaller
		 * than what it can be.  This should be OK.
		 */
		if (tcps->tcps_use_smss_as_mss_opt) {
			u1 = tcp->tcp_mss;
			/*
			 * Note that wptr points just past the MSS
			 * option value.
			 */
			U16_TO_BE16(u1, wptr - 2);
		}

		/*
		 * tcp_snd_ts_ok can only be set in TCPS_SYN_RCVD
		 * when the peer also uses timestamps option.  And
		 * the TCP header template must have already been
		 * updated to include the timestamps option.
		 */
		if (tcp->tcp_snd_sack_ok) {
			if (tcp->tcp_snd_ts_ok) {
				uint8_t *tmp_wptr;

				/*
				 * Use the NOP in the header just
				 * before timestamps opton.
				 */
				tmp_wptr = (uint8_t *)tcpha +
				    TCP_MIN_HEADER_LENGTH;
				ASSERT(tmp_wptr[0] == TCPOPT_NOP &&
				    tmp_wptr[1] == TCPOPT_NOP);
				tmp_wptr[0] = TCPOPT_SACK_PERMITTED;
				tmp_wptr[1] = TCPOPT_SACK_OK_LEN;
			} else {
				add_sack = B_TRUE;
			}
		}


		/*
		 * If the other side is ECN capable, reply
		 * that we are also ECN capable.
		 */
		if (tcp->tcp_ecn_ok)
			*flags |= TH_ECE;
		break;

	default:
		/*
		 * The above ASSERT() makes sure that this
		 * must be FIN-WAIT-1 state.  Our SYN has
		 * not been ack'ed so retransmit it.
		 */
		*flags |= TH_SYN;
		break;
	}

	if (add_sack) {
		wptr[0] = TCPOPT_NOP;
		wptr[1] = TCPOPT_NOP;
		wptr[2] = TCPOPT_SACK_PERMITTED;
		wptr[3] = TCPOPT_SACK_OK_LEN;
		wptr += TCPOPT_REAL_SACK_OK_LEN;
		tcpha->tha_offset_and_reserved += (1 << 4);
	}

	if (tcp->tcp_snd_ws_ok) {
		wptr[0] =  TCPOPT_NOP;
		wptr[1] =  TCPOPT_WSCALE;
		wptr[2] =  TCPOPT_WS_LEN;
		wptr[3] = (uchar_t)tcp->tcp_rcv_ws;
		wptr += TCPOPT_REAL_WS_LEN;
		tcpha->tha_offset_and_reserved += (1 << 4);
	}

	mp->b_wptr = wptr;
	u1 = (int)(mp->b_wptr - mp->b_rptr);
	/*
	 * Get IP set to checksum on our behalf
	 * Include the adjustment for a source route if any.
	 */
	u1 += connp->conn_sum;
	u1 = (u1 >> 16) + (u1 & 0xFFFF);
	tcpha->tha_sum = htons(u1);
	TCPS_BUMP_MIB(tcps, tcpOutControl);
}

/*
 * Helper function for tcp_xmit_mp() in handling connection tear down
 * flag setting and state changes.
 */
static void
tcp_xmit_mp_aux_fss(tcp_t *tcp, ip_xmit_attr_t *ixa, uint_t *flags)
{
	if (!tcp->tcp_fin_acked) {
		*flags |= TH_FIN;
		TCPS_BUMP_MIB(tcp->tcp_tcps, tcpOutControl);
	}
	if (!tcp->tcp_fin_sent) {
		tcp->tcp_fin_sent = B_TRUE;
		switch (tcp->tcp_state) {
		case TCPS_SYN_RCVD:
			tcp->tcp_state = TCPS_FIN_WAIT_1;
			DTRACE_TCP6(state__change, void, NULL,
			    ip_xmit_attr_t *, ixa, void, NULL,
			    tcp_t *, tcp, void, NULL,
			    int32_t, TCPS_SYN_RCVD);
			break;
		case TCPS_ESTABLISHED:
			tcp->tcp_state = TCPS_FIN_WAIT_1;
			DTRACE_TCP6(state__change, void, NULL,
			    ip_xmit_attr_t *, ixa, void, NULL,
			    tcp_t *, tcp, void, NULL,
			    int32_t, TCPS_ESTABLISHED);
			break;
		case TCPS_CLOSE_WAIT:
			tcp->tcp_state = TCPS_LAST_ACK;
			DTRACE_TCP6(state__change, void, NULL,
			    ip_xmit_attr_t *, ixa, void, NULL,
			    tcp_t *, tcp, void, NULL,
			    int32_t, TCPS_CLOSE_WAIT);
			break;
		}
		if (tcp->tcp_suna == tcp->tcp_snxt)
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
		tcp->tcp_snxt = tcp->tcp_fss + 1;
	}
}

/*
 * tcp_xmit_mp is called to return a pointer to an mblk chain complete with
 * ip and tcp header ready to pass down to IP.  If the mp passed in is
 * non-NULL, then up to max_to_send bytes of data will be dup'ed off that
 * mblk. (If sendall is not set the dup'ing will stop at an mblk boundary
 * otherwise it will dup partial mblks.)
 * Otherwise, an appropriate ACK packet will be generated.  This
 * routine is not usually called to send new data for the first time.  It
 * is mostly called out of the timer for retransmits, and to generate ACKs.
 *
 * If offset is not NULL, the returned mblk chain's first mblk's b_rptr will
 * be adjusted by *offset.  And after dupb(), the offset and the ending mblk
 * of the original mblk chain will be returned in *offset and *end_mp.
 */
mblk_t *
tcp_xmit_mp(tcp_t *tcp, mblk_t *mp, int32_t max_to_send, int32_t *offset,
    mblk_t **end_mp, uint32_t seq, boolean_t sendall, uint32_t *seg_len,
    boolean_t rexmit)
{
	int	data_length;
	int32_t	off = 0;
	uint_t	flags;
	mblk_t	*mp1;
	mblk_t	*mp2;
	uchar_t	*rptr;
	tcpha_t	*tcpha;
	int32_t	num_sack_blk = 0;
	int32_t	sack_opt_len = 0;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;
	ip_xmit_attr_t	*ixa = connp->conn_ixa;

	/* Allocate for our maximum TCP header + link-level */
	mp1 = allocb(connp->conn_ht_iphc_allocated + tcps->tcps_wroff_xtra,
	    BPRI_MED);
	if (mp1 == NULL)
		return (NULL);
	data_length = 0;

	/*
	 * Note that tcp_mss has been adjusted to take into account the
	 * timestamp option if applicable.  Because SACK options do not
	 * appear in every TCP segments and they are of variable lengths,
	 * they cannot be included in tcp_mss.  Thus we need to calculate
	 * the actual segment length when we need to send a segment which
	 * includes SACK options.
	 */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
		num_sack_blk = MIN(tcp->tcp_max_sack_blk,
		    tcp->tcp_num_sack_blk);
		sack_opt_len = num_sack_blk * sizeof (sack_blk_t) +
		    TCPOPT_NOP_LEN * 2 + TCPOPT_HEADER_LEN;
		if (max_to_send + sack_opt_len > tcp->tcp_mss)
			max_to_send -= sack_opt_len;
	}

	if (offset != NULL) {
		off = *offset;
		/* We use offset as an indicator that end_mp is not NULL. */
		*end_mp = NULL;
	}
	for (mp2 = mp1; mp && data_length != max_to_send; mp = mp->b_cont) {
		/* This could be faster with cooperation from downstream */
		if (mp2 != mp1 && !sendall &&
		    data_length + (int)(mp->b_wptr - mp->b_rptr) >
		    max_to_send)
			/*
			 * Don't send the next mblk since the whole mblk
			 * does not fit.
			 */
			break;
		mp2->b_cont = dupb(mp);
		mp2 = mp2->b_cont;
		if (!mp2) {
			freemsg(mp1);
			return (NULL);
		}
		mp2->b_rptr += off;
		ASSERT((uintptr_t)(mp2->b_wptr - mp2->b_rptr) <=
		    (uintptr_t)INT_MAX);

		data_length += (int)(mp2->b_wptr - mp2->b_rptr);
		if (data_length > max_to_send) {
			mp2->b_wptr -= data_length - max_to_send;
			data_length = max_to_send;
			off = mp2->b_wptr - mp->b_rptr;
			break;
		} else {
			off = 0;
		}
	}
	if (offset != NULL) {
		*offset = off;
		*end_mp = mp;
	}
	if (seg_len != NULL) {
		*seg_len = data_length;
	}

	/* Update the latest receive window size in TCP header. */
	tcp->tcp_tcpha->tha_win = htons(tcp->tcp_rwnd >> tcp->tcp_rcv_ws);

	rptr = mp1->b_rptr + tcps->tcps_wroff_xtra;
	mp1->b_rptr = rptr;
	mp1->b_wptr = rptr + connp->conn_ht_iphc_len + sack_opt_len;
	bcopy(connp->conn_ht_iphc, rptr, connp->conn_ht_iphc_len);
	tcpha = (tcpha_t *)&rptr[ixa->ixa_ip_hdr_length];
	tcpha->tha_seq = htonl(seq);

	/*
	 * Use tcp_unsent to determine if the PUSH bit should be used assumes
	 * that this function was called from tcp_wput_data. Thus, when called
	 * to retransmit data the setting of the PUSH bit may appear some
	 * what random in that it might get set when it should not. This
	 * should not pose any performance issues.
	 */
	if (data_length != 0 && (tcp->tcp_unsent == 0 ||
	    tcp->tcp_unsent == data_length)) {
		flags = TH_ACK | TH_PUSH;
	} else {
		flags = TH_ACK;
	}

	if (tcp->tcp_ecn_ok) {
		if (tcp->tcp_ecn_echo_on)
			flags |= TH_ECE;

		/*
		 * Only set ECT bit and ECN_CWR if a segment contains new data.
		 * There is no TCP flow control for non-data segments, and
		 * only data segment is transmitted reliably.
		 */
		if (data_length > 0 && !rexmit) {
			TCP_SET_ECT(tcp, rptr);
			if (tcp->tcp_cwr && !tcp->tcp_ecn_cwr_sent) {
				flags |= TH_CWR;
				tcp->tcp_ecn_cwr_sent = B_TRUE;
			}
		}
	}

	/* Check if there is any special processing needs to be done. */
	if (tcp->tcp_valid_bits) {
		uint32_t u1;

		/* We don't allow having SYN and FIN in the same segment... */
		if ((tcp->tcp_valid_bits & TCP_ISS_VALID) &&
		    seq == tcp->tcp_iss) {
			/* Need to do connection set up processing. */
			tcp_xmit_mp_aux_iss(tcp, connp, tcpha, mp1, &flags);
		} else if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
		    (seq + data_length) == tcp->tcp_fss) {
			/* Need to do connection tear down processing. */
			tcp_xmit_mp_aux_fss(tcp, ixa, &flags);
		}

		/*
		 * Need to do urgent pointer processing.
		 *
		 * Note the trick here.  u1 is unsigned.  When tcp_urg
		 * is smaller than seq, u1 will become a very huge value.
		 * So the comparison will fail.  Also note that tcp_urp
		 * should be positive, see RFC 793 page 17.
		 */
		u1 = tcp->tcp_urg - seq + TCP_OLD_URP_INTERPRETATION;
		if ((tcp->tcp_valid_bits & TCP_URG_VALID) && u1 != 0 &&
		    u1 < (uint32_t)(64 * 1024)) {
			flags |= TH_URG;
			TCPS_BUMP_MIB(tcps, tcpOutUrg);
			tcpha->tha_urp = htons(u1);
		}
	}
	tcpha->tha_flags = (uchar_t)flags;
	tcp->tcp_rack = tcp->tcp_rnxt;
	tcp->tcp_rack_cnt = 0;

	/* Fill in the current value of timestamps option. */
	if (tcp->tcp_snd_ts_ok) {
		if (tcp->tcp_state != TCPS_SYN_SENT) {
			uint32_t llbolt = (uint32_t)LBOLT_FASTPATH;

			U32_TO_BE32(llbolt,
			    (char *)tcpha + TCP_MIN_HEADER_LENGTH+4);
			U32_TO_BE32(tcp->tcp_ts_recent,
			    (char *)tcpha + TCP_MIN_HEADER_LENGTH+8);
		}
	}

	/* Fill in the SACK blocks. */
	if (num_sack_blk > 0) {
		uchar_t *wptr = (uchar_t *)tcpha + connp->conn_ht_ulp_len;
		sack_blk_t *tmp;
		int32_t	i;

		wptr[0] = TCPOPT_NOP;
		wptr[1] = TCPOPT_NOP;
		wptr[2] = TCPOPT_SACK;
		wptr[3] = TCPOPT_HEADER_LEN + num_sack_blk *
		    sizeof (sack_blk_t);
		wptr += TCPOPT_REAL_SACK_LEN;

		tmp = tcp->tcp_sack_list;
		for (i = 0; i < num_sack_blk; i++) {
			U32_TO_BE32(tmp[i].begin, wptr);
			wptr += sizeof (tcp_seq);
			U32_TO_BE32(tmp[i].end, wptr);
			wptr += sizeof (tcp_seq);
		}
		tcpha->tha_offset_and_reserved += ((num_sack_blk * 2 + 1) << 4);
	}
	ASSERT((uintptr_t)(mp1->b_wptr - rptr) <= (uintptr_t)INT_MAX);
	data_length += (int)(mp1->b_wptr - rptr);

	ixa->ixa_pktlen = data_length;

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		((ipha_t *)rptr)->ipha_length = htons(data_length);
	} else {
		ip6_t *ip6 = (ip6_t *)rptr;

		ip6->ip6_plen = htons(data_length - IPV6_HDR_LEN);
	}

	/*
	 * Prime pump for IP
	 * Include the adjustment for a source route if any.
	 */
	data_length -= ixa->ixa_ip_hdr_length;
	data_length += connp->conn_sum;
	data_length = (data_length >> 16) + (data_length & 0xFFFF);
	tcpha->tha_sum = htons(data_length);
	if (tcp->tcp_ip_forward_progress) {
		tcp->tcp_ip_forward_progress = B_FALSE;
		connp->conn_ixa->ixa_flags |= IXAF_REACH_CONF;
	} else {
		connp->conn_ixa->ixa_flags &= ~IXAF_REACH_CONF;
	}
	return (mp1);
}

/*
 * If this routine returns B_TRUE, TCP can generate a RST in response
 * to a segment.  If it returns B_FALSE, TCP should not respond.
 */
static boolean_t
tcp_send_rst_chk(tcp_stack_t *tcps)
{
	int64_t	now;

	/*
	 * TCP needs to protect itself from generating too many RSTs.
	 * This can be a DoS attack by sending us random segments
	 * soliciting RSTs.
	 *
	 * What we do here is to have a limit of tcp_rst_sent_rate RSTs
	 * in each 1 second interval.  In this way, TCP still generate
	 * RSTs in normal cases but when under attack, the impact is
	 * limited.
	 */
	if (tcps->tcps_rst_sent_rate_enabled != 0) {
		now = ddi_get_lbolt64();
		if (TICK_TO_MSEC(now - tcps->tcps_last_rst_intrvl) >
		    1*SECONDS) {
			tcps->tcps_last_rst_intrvl = now;
			tcps->tcps_rst_cnt = 1;
		} else if (++tcps->tcps_rst_cnt > tcps->tcps_rst_sent_rate) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

/*
 * This function handles all retransmissions if SACK is enabled for this
 * connection.  First it calculates how many segments can be retransmitted
 * based on tcp_pipe.  Then it goes thru the notsack list to find eligible
 * segments.  A segment is eligible if sack_cnt for that segment is greater
 * than or equal tcp_dupack_fast_retransmit.  After it has retransmitted
 * all eligible segments, it checks to see if TCP can send some new segments
 * (fast recovery).  If it can, set the appropriate flag for tcp_input_data().
 *
 * Parameters:
 *	tcp_t *tcp: the tcp structure of the connection.
 *	uint_t *flags: in return, appropriate value will be set for
 *	tcp_input_data().
 */
void
tcp_sack_rexmit(tcp_t *tcp, uint_t *flags)
{
	notsack_blk_t	*notsack_blk;
	int32_t		usable_swnd;
	int32_t		mss;
	uint32_t	seg_len;
	mblk_t		*xmit_mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	ASSERT(tcp->tcp_notsack_list != NULL);
	ASSERT(tcp->tcp_rexmit == B_FALSE);

	/* Defensive coding in case there is a bug... */
	if (tcp->tcp_notsack_list == NULL) {
		return;
	}
	notsack_blk = tcp->tcp_notsack_list;
	mss = tcp->tcp_mss;

	/*
	 * Limit the num of outstanding data in the network to be
	 * tcp_cwnd_ssthresh, which is half of the original congestion wnd.
	 */
	usable_swnd = tcp->tcp_cwnd_ssthresh - tcp->tcp_pipe;

	/* At least retransmit 1 MSS of data. */
	if (usable_swnd <= 0) {
		usable_swnd = mss;
	}

	/* Make sure no new RTT samples will be taken. */
	tcp->tcp_csuna = tcp->tcp_snxt;

	notsack_blk = tcp->tcp_notsack_list;
	while (usable_swnd > 0) {
		mblk_t		*snxt_mp, *tmp_mp;
		tcp_seq		begin = tcp->tcp_sack_snxt;
		tcp_seq		end;
		int32_t		off;

		for (; notsack_blk != NULL; notsack_blk = notsack_blk->next) {
			if (SEQ_GT(notsack_blk->end, begin) &&
			    (notsack_blk->sack_cnt >=
			    tcps->tcps_dupack_fast_retransmit)) {
				end = notsack_blk->end;
				if (SEQ_LT(begin, notsack_blk->begin)) {
					begin = notsack_blk->begin;
				}
				break;
			}
		}
		/*
		 * All holes are filled.  Manipulate tcp_cwnd to send more
		 * if we can.  Note that after the SACK recovery, tcp_cwnd is
		 * set to tcp_cwnd_ssthresh.
		 */
		if (notsack_blk == NULL) {
			usable_swnd = tcp->tcp_cwnd_ssthresh - tcp->tcp_pipe;
			if (usable_swnd <= 0 || tcp->tcp_unsent == 0) {
				tcp->tcp_cwnd = tcp->tcp_snxt - tcp->tcp_suna;
				ASSERT(tcp->tcp_cwnd > 0);
				return;
			} else {
				usable_swnd = usable_swnd / mss;
				tcp->tcp_cwnd = tcp->tcp_snxt - tcp->tcp_suna +
				    MAX(usable_swnd * mss, mss);
				*flags |= TH_XMIT_NEEDED;
				return;
			}
		}

		/*
		 * Note that we may send more than usable_swnd allows here
		 * because of round off, but no more than 1 MSS of data.
		 */
		seg_len = end - begin;
		if (seg_len > mss)
			seg_len = mss;
		snxt_mp = tcp_get_seg_mp(tcp, begin, &off);
		ASSERT(snxt_mp != NULL);
		/* This should not happen.  Defensive coding again... */
		if (snxt_mp == NULL) {
			return;
		}

		xmit_mp = tcp_xmit_mp(tcp, snxt_mp, seg_len, &off,
		    &tmp_mp, begin, B_TRUE, &seg_len, B_TRUE);
		if (xmit_mp == NULL)
			return;

		usable_swnd -= seg_len;
		tcp->tcp_pipe += seg_len;
		tcp->tcp_sack_snxt = begin + seg_len;

		tcp_send_data(tcp, xmit_mp);

		/*
		 * Update the send timestamp to avoid false retransmission.
		 */
		snxt_mp->b_prev = (mblk_t *)ddi_get_lbolt();

		TCPS_BUMP_MIB(tcps, tcpRetransSegs);
		TCPS_UPDATE_MIB(tcps, tcpRetransBytes, seg_len);
		TCPS_BUMP_MIB(tcps, tcpOutSackRetransSegs);
		/*
		 * Update tcp_rexmit_max to extend this SACK recovery phase.
		 * This happens when new data sent during fast recovery is
		 * also lost.  If TCP retransmits those new data, it needs
		 * to extend SACK recover phase to avoid starting another
		 * fast retransmit/recovery unnecessarily.
		 */
		if (SEQ_GT(tcp->tcp_sack_snxt, tcp->tcp_rexmit_max)) {
			tcp->tcp_rexmit_max = tcp->tcp_sack_snxt;
		}
	}
}

/*
 * tcp_ss_rexmit() is called to do slow start retransmission after a timeout
 * or ICMP errors.
 */
void
tcp_ss_rexmit(tcp_t *tcp)
{
	uint32_t	snxt;
	uint32_t	smax;
	int32_t		win;
	int32_t		mss;
	int32_t		off;
	mblk_t		*snxt_mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * Note that tcp_rexmit can be set even though TCP has retransmitted
	 * all unack'ed segments.
	 */
	if (SEQ_LT(tcp->tcp_rexmit_nxt, tcp->tcp_rexmit_max)) {
		smax = tcp->tcp_rexmit_max;
		snxt = tcp->tcp_rexmit_nxt;
		if (SEQ_LT(snxt, tcp->tcp_suna)) {
			snxt = tcp->tcp_suna;
		}
		win = MIN(tcp->tcp_cwnd, tcp->tcp_swnd);
		win -= snxt - tcp->tcp_suna;
		mss = tcp->tcp_mss;
		snxt_mp = tcp_get_seg_mp(tcp, snxt, &off);

		while (SEQ_LT(snxt, smax) && (win > 0) && (snxt_mp != NULL)) {
			mblk_t	*xmit_mp;
			mblk_t	*old_snxt_mp = snxt_mp;
			uint32_t cnt = mss;

			if (win < cnt) {
				cnt = win;
			}
			if (SEQ_GT(snxt + cnt, smax)) {
				cnt = smax - snxt;
			}
			xmit_mp = tcp_xmit_mp(tcp, snxt_mp, cnt, &off,
			    &snxt_mp, snxt, B_TRUE, &cnt, B_TRUE);
			if (xmit_mp == NULL)
				return;

			tcp_send_data(tcp, xmit_mp);

			snxt += cnt;
			win -= cnt;
			/*
			 * Update the send timestamp to avoid false
			 * retransmission.
			 */
			old_snxt_mp->b_prev = (mblk_t *)ddi_get_lbolt();
			TCPS_BUMP_MIB(tcps, tcpRetransSegs);
			TCPS_UPDATE_MIB(tcps, tcpRetransBytes, cnt);

			tcp->tcp_rexmit_nxt = snxt;
		}
		/*
		 * If we have transmitted all we have at the time
		 * we started the retranmission, we can leave
		 * the rest of the job to tcp_wput_data().  But we
		 * need to check the send window first.  If the
		 * win is not 0, go on with tcp_wput_data().
		 */
		if (SEQ_LT(snxt, smax) || win == 0) {
			return;
		}
	}
	/* Only call tcp_wput_data() if there is data to be sent. */
	if (tcp->tcp_unsent) {
		tcp_wput_data(tcp, NULL, B_FALSE);
	}
}

/*
 * Do slow start retransmission after ICMP errors of PMTU changes.
 */
void
tcp_rexmit_after_error(tcp_t *tcp)
{
	/*
	 * All sent data has been acknowledged or no data left to send, just
	 * to return.
	 */
	if (!SEQ_LT(tcp->tcp_suna, tcp->tcp_snxt) ||
	    (tcp->tcp_xmit_head == NULL))
		return;

	if ((tcp->tcp_valid_bits & TCP_FSS_VALID) && (tcp->tcp_unsent == 0))
		tcp->tcp_rexmit_max = tcp->tcp_fss;
	else
		tcp->tcp_rexmit_max = tcp->tcp_snxt;

	tcp->tcp_rexmit_nxt = tcp->tcp_suna;
	tcp->tcp_rexmit = B_TRUE;
	tcp->tcp_dupack_cnt = 0;
	tcp_ss_rexmit(tcp);
}

/*
 * tcp_get_seg_mp() is called to get the pointer to a segment in the
 * send queue which starts at the given sequence number. If the given
 * sequence number is equal to last valid sequence number (tcp_snxt), the
 * returned mblk is the last valid mblk, and off is set to the length of
 * that mblk.
 *
 * send queue which starts at the given seq. no.
 *
 * Parameters:
 *	tcp_t *tcp: the tcp instance pointer.
 *	uint32_t seq: the starting seq. no of the requested segment.
 *	int32_t *off: after the execution, *off will be the offset to
 *		the returned mblk which points to the requested seq no.
 *		It is the caller's responsibility to send in a non-null off.
 *
 * Return:
 *	A mblk_t pointer pointing to the requested segment in send queue.
 */
static mblk_t *
tcp_get_seg_mp(tcp_t *tcp, uint32_t seq, int32_t *off)
{
	int32_t	cnt;
	mblk_t	*mp;

	/* Defensive coding.  Make sure we don't send incorrect data. */
	if (SEQ_LT(seq, tcp->tcp_suna) || SEQ_GT(seq, tcp->tcp_snxt))
		return (NULL);

	cnt = seq - tcp->tcp_suna;
	mp = tcp->tcp_xmit_head;
	while (cnt > 0 && mp != NULL) {
		cnt -= mp->b_wptr - mp->b_rptr;
		if (cnt <= 0) {
			cnt += mp->b_wptr - mp->b_rptr;
			break;
		}
		mp = mp->b_cont;
	}
	ASSERT(mp != NULL);
	*off = cnt;
	return (mp);
}

/*
 * This routine adjusts next-to-send sequence number variables, in the
 * case where the reciever has shrunk it's window.
 */
void
tcp_update_xmit_tail(tcp_t *tcp, uint32_t snxt)
{
	mblk_t *xmit_tail;
	int32_t offset;

	tcp->tcp_snxt = snxt;

	/* Get the mblk, and the offset in it, as per the shrunk window */
	xmit_tail = tcp_get_seg_mp(tcp, snxt, &offset);
	ASSERT(xmit_tail != NULL);
	tcp->tcp_xmit_tail = xmit_tail;
	tcp->tcp_xmit_tail_unsent = xmit_tail->b_wptr -
	    xmit_tail->b_rptr - offset;
}

/*
 * This handles the case when the receiver has shrunk its win. Per RFC 1122
 * if the receiver shrinks the window, i.e. moves the right window to the
 * left, the we should not send new data, but should retransmit normally the
 * old unacked data between suna and suna + swnd. We might has sent data
 * that is now outside the new window, pretend that we didn't send  it.
 */
static void
tcp_process_shrunk_swnd(tcp_t *tcp, uint32_t shrunk_count)
{
	uint32_t	snxt = tcp->tcp_snxt;

	ASSERT(shrunk_count > 0);

	if (!tcp->tcp_is_wnd_shrnk) {
		tcp->tcp_snxt_shrunk = snxt;
		tcp->tcp_is_wnd_shrnk = B_TRUE;
	} else if (SEQ_GT(snxt, tcp->tcp_snxt_shrunk)) {
		tcp->tcp_snxt_shrunk = snxt;
	}

	/* Pretend we didn't send the data outside the window */
	snxt -= shrunk_count;

	/* Reset all the values per the now shrunk window */
	tcp_update_xmit_tail(tcp, snxt);
	tcp->tcp_unsent += shrunk_count;

	/*
	 * If the SACK option is set, delete the entire list of
	 * notsack'ed blocks.
	 */
	TCP_NOTSACK_REMOVE_ALL(tcp->tcp_notsack_list, tcp);

	if (tcp->tcp_suna == tcp->tcp_snxt && tcp->tcp_swnd == 0)
		/*
		 * Make sure the timer is running so that we will probe a zero
		 * window.
		 */
		TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
}

/*
 * tcp_fill_header is called by tcp_send() to fill the outgoing TCP header
 * with the template header, as well as other options such as time-stamp,
 * ECN and/or SACK.
 */
static void
tcp_fill_header(tcp_t *tcp, uchar_t *rptr, clock_t now, int num_sack_blk)
{
	tcpha_t *tcp_tmpl, *tcpha;
	uint32_t *dst, *src;
	int hdrlen;
	conn_t *connp = tcp->tcp_connp;

	ASSERT(OK_32PTR(rptr));

	/* Template header */
	tcp_tmpl = tcp->tcp_tcpha;

	/* Header of outgoing packet */
	tcpha = (tcpha_t *)(rptr + connp->conn_ixa->ixa_ip_hdr_length);

	/* dst and src are opaque 32-bit fields, used for copying */
	dst = (uint32_t *)rptr;
	src = (uint32_t *)connp->conn_ht_iphc;
	hdrlen = connp->conn_ht_iphc_len;

	/* Fill time-stamp option if needed */
	if (tcp->tcp_snd_ts_ok) {
		U32_TO_BE32((uint32_t)now,
		    (char *)tcp_tmpl + TCP_MIN_HEADER_LENGTH + 4);
		U32_TO_BE32(tcp->tcp_ts_recent,
		    (char *)tcp_tmpl + TCP_MIN_HEADER_LENGTH + 8);
	} else {
		ASSERT(connp->conn_ht_ulp_len == TCP_MIN_HEADER_LENGTH);
	}

	/*
	 * Copy the template header; is this really more efficient than
	 * calling bcopy()?  For simple IPv4/TCP, it may be the case,
	 * but perhaps not for other scenarios.
	 */
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	dst[3] = src[3];
	dst[4] = src[4];
	dst[5] = src[5];
	dst[6] = src[6];
	dst[7] = src[7];
	dst[8] = src[8];
	dst[9] = src[9];
	if (hdrlen -= 40) {
		hdrlen >>= 2;
		dst += 10;
		src += 10;
		do {
			*dst++ = *src++;
		} while (--hdrlen);
	}

	/*
	 * Set the ECN info in the TCP header if it is not a zero
	 * window probe.  Zero window probe is only sent in
	 * tcp_wput_data() and tcp_timer().
	 */
	if (tcp->tcp_ecn_ok && !tcp->tcp_zero_win_probe) {
		TCP_SET_ECT(tcp, rptr);

		if (tcp->tcp_ecn_echo_on)
			tcpha->tha_flags |= TH_ECE;
		if (tcp->tcp_cwr && !tcp->tcp_ecn_cwr_sent) {
			tcpha->tha_flags |= TH_CWR;
			tcp->tcp_ecn_cwr_sent = B_TRUE;
		}
	}

	/* Fill in SACK options */
	if (num_sack_blk > 0) {
		uchar_t *wptr = rptr + connp->conn_ht_iphc_len;
		sack_blk_t *tmp;
		int32_t	i;

		wptr[0] = TCPOPT_NOP;
		wptr[1] = TCPOPT_NOP;
		wptr[2] = TCPOPT_SACK;
		wptr[3] = TCPOPT_HEADER_LEN + num_sack_blk *
		    sizeof (sack_blk_t);
		wptr += TCPOPT_REAL_SACK_LEN;

		tmp = tcp->tcp_sack_list;
		for (i = 0; i < num_sack_blk; i++) {
			U32_TO_BE32(tmp[i].begin, wptr);
			wptr += sizeof (tcp_seq);
			U32_TO_BE32(tmp[i].end, wptr);
			wptr += sizeof (tcp_seq);
		}
		tcpha->tha_offset_and_reserved +=
		    ((num_sack_blk * 2 + 1) << 4);
	}
}
