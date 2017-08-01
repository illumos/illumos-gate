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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

/*
 * The TCP congestion control algorithm extracted from the pre-framework
 * implementation of TCP congestion control.
 */

#include <sys/errno.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/cc.h>
#include <inet/cc/cc_module.h>

static void	sunreno_ack_received(struct cc_var *ccv, uint16_t type);
static void	sunreno_after_idle(struct cc_var *ccv);
static void	sunreno_cong_signal(struct cc_var *ccv, uint32_t type);
static void	sunreno_post_recovery(struct cc_var *ccv);

#define	CC_SUNRENO_ALGO_NAME "sunreno"

static struct modlmisc cc_sunreno_modlmisc = {
	&mod_miscops,
	"SUNReno Congestion Control"
};

static struct modlinkage cc_sunreno_modlinkage = {
	MODREV_1,
	&cc_sunreno_modlmisc,
	NULL
};

struct cc_algo sunreno_cc_algo = {
	.name = CC_SUNRENO_ALGO_NAME,
	.ack_received = sunreno_ack_received,
	.after_idle = sunreno_after_idle,
	.cong_signal = sunreno_cong_signal,
	.post_recovery = sunreno_post_recovery,
};

int
_init(void)
{
	int err;

	if ((err = cc_register_algo(&sunreno_cc_algo)) == 0) {
		if ((err = mod_install(&cc_sunreno_modlinkage)) != 0)
			(void) cc_deregister_algo(&sunreno_cc_algo);
	}
	return (err);
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&cc_sunreno_modlinkage, modinfop));
}

static void
sunreno_ack_received(struct cc_var *ccv, uint16_t type)
{
	uint32_t add;
	uint32_t cwnd;
	int mss;

	if (type == CC_ACK && !IN_RECOVERY(ccv->flags)) {
		mss = CCV(ccv, tcp_mss);
		cwnd = CCV(ccv, tcp_cwnd);
		add = mss;

		if (cwnd >= CCV(ccv, tcp_cwnd_ssthresh)) {
			/*
			 * This is to prevent an increase of less than 1 MSS of
			 * tcp_cwnd.  With partial increase, tcp_wput_data()
			 * may send out tinygrams in order to preserve mblk
			 * boundaries.
			 *
			 * By initializing tcp_cwnd_cnt to new tcp_cwnd and
			 * decrementing it by 1 MSS for every ACKs, tcp_cwnd is
			 * increased by 1 MSS for every RTTs.
			 */
			if (CCV(ccv, tcp_cwnd_cnt) <= 0) {
				CCV(ccv, tcp_cwnd_cnt) = cwnd + add;
			} else {
				CCV(ccv, tcp_cwnd_cnt) -= add;
				add = 0;
			}
		}
		CCV(ccv, tcp_cwnd) = MIN(cwnd + add, CCV(ccv, tcp_cwnd_max));
	}
}

static void
sunreno_after_idle(struct cc_var *ccv)
{
	int32_t	num_sack_blk = 0;
	int mss;

	if (CCV(ccv, tcp_snd_sack_ok) && CCV(ccv, tcp_num_sack_blk) > 0) {
		int32_t	opt_len;

		num_sack_blk = MIN(CCV(ccv, tcp_max_sack_blk),
		    CCV(ccv, tcp_num_sack_blk));
		opt_len = num_sack_blk * sizeof (sack_blk_t) + TCPOPT_NOP_LEN *
		    2 + TCPOPT_HEADER_LEN;
		mss = CCV(ccv, tcp_mss) - opt_len;
	} else {
		mss = CCV(ccv, tcp_mss);
	}

	TCP_SET_INIT_CWND(CCV_PROTO(ccv), mss,
	    CCSV(ccv, tcps_slow_start_after_idle));
}

/*
 * Perform any necessary tasks before we enter congestion recovery.
 */
static void
sunreno_cong_signal(struct cc_var *ccv, uint32_t type)
{
	int npkt;
	int mss;

	/* Catch algos which mistakenly leak private signal types. */
	ASSERT((type & CC_SIGPRIVMASK) == 0);

	mss = CCV(ccv, tcp_mss);
	npkt = ((CCV(ccv, tcp_snxt) - CCV(ccv, tcp_suna)) >> 1) / mss;

	switch (type) {
	case CC_NDUPACK:
		if (!IN_FASTRECOVERY(ccv->flags)) {
			if (!IN_CONGRECOVERY(ccv->flags)) {
				CCV(ccv, tcp_cwnd_ssthresh) = MAX(npkt, 2) *
				    mss;
				CCV(ccv, tcp_cwnd) = (npkt +
				    CCV(ccv, tcp_dupack_cnt)) * mss;
			}
			ENTER_RECOVERY(ccv->flags);
		}
		break;
	case CC_ECN:
		if (!IN_CONGRECOVERY(ccv->flags) && !CCV(ccv, tcp_cwr)) {
			CCV(ccv, tcp_cwnd_ssthresh) = MAX(npkt, 2) * mss;
			CCV(ccv, tcp_cwnd) = npkt * mss;
			if (CCV(ccv, tcp_cwnd) == 0) {
				/*
				 * This makes sure that when the ACK comes
				 * back, we will increase tcp_cwnd by 1 MSS.
				 */
				CCV(ccv, tcp_cwnd_cnt) = 0;
			}
			ENTER_CONGRECOVERY(ccv->flags);
		}
		break;
	case CC_RTO:
		/*
		 * After retransmission, we need to do slow start.  Set the
		 * ssthresh to one half of current effective window and cwnd to
		 * one MSS.  Also reset tcp_cwnd_cnt.
		 *
		 * Note that if tcp_ssthresh is reduced because of ECN, do not
		 * reduce it again unless it is already one window of data away
		 * (tcp_cwr should then be cleared) or this is a timeout for a
		 * retransmitted segment.
		 */
		if (!CCV(ccv, tcp_cwr) || CCV(ccv, tcp_rexmit)) {
			if (CCV(ccv, tcp_timer_backoff) != 0)
				npkt = CCV(ccv, tcp_cwnd_ssthresh) / 2 / mss;
			CCV(ccv, tcp_cwnd_ssthresh) = MAX(npkt, 2) * mss;
		}
		CCV(ccv, tcp_cwnd) = mss;
		CCV(ccv, tcp_cwnd_cnt) = 0;
		break;
	}
}

/*
 * Perform any necessary tasks before we exit congestion recovery.
 */
static void
sunreno_post_recovery(struct cc_var *ccv)
{
	/*
	 * Restore the congestion window back to ssthresh as per RFC 5681
	 * section 3.2.
	 */
	if (IN_FASTRECOVERY(ccv->flags)) {
		if (CCV(ccv, tcp_cwnd) > CCV(ccv, tcp_cwnd_ssthresh)) {
			CCV(ccv, tcp_cwnd) = CCV(ccv, tcp_cwnd_ssthresh);
		}
	}
	CCV(ccv, tcp_cwnd_cnt) = 0;
}
