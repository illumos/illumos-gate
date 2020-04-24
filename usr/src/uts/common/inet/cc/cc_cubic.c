/*
 * Copyright (c) 2008-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2020 RackTop Systems, Inc.
 *
 * This software was developed by Lawrence Stewart while studying at the Centre
 * for Advanced Internet Architectures, Swinburne University of Technology, made
 * possible in part by a grant from the Cisco University Research Program Fund
 * at Community Foundation Silicon Valley.
 *
 * Portions of this software were developed at the Centre for Advanced
 * Internet Architectures, Swinburne University of Technology, Melbourne,
 * Australia by David Hayes under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * An implementation of the CUBIC congestion control algorithm for FreeBSD,
 * based on the Internet Draft "draft-rhee-tcpm-cubic-02" by Rhee, Xu and Ha.
 * Originally released as part of the NewTCP research project at Swinburne
 * University of Technology's Centre for Advanced Internet Architectures,
 * Melbourne, Australia, which was made possible in part by a grant from the
 * Cisco University Research Program Fund at Community Foundation Silicon
 * Valley. More details are available at:
 *   http://caia.swin.edu.au/urp/newtcp/
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/time.h>

#include <inet/tcp_impl.h>
#include <inet/cc.h>
#include <inet/cc/cc_cubic.h>
#include <inet/cc/cc_module.h>

static struct modlmisc cc_cubic_modlmisc = {
	&mod_miscops,
	"Cubic Congestion Control"
};

static struct modlinkage cc_cubic_modlinkage = {
	MODREV_1,
	&cc_cubic_modlmisc,
	NULL
};

/*
 * cubic uses the NewReno implementation of after_idle and uses NewReno's
 * ack_received callback during slow start.
 */
static struct cc_algo *newreno_cc_algo;

static void	cubic_ack_received(struct cc_var *ccv, uint16_t type);
static void	cubic_cb_destroy(struct cc_var *ccv);
static int	cubic_cb_init(struct cc_var *ccv);
static void	cubic_cong_signal(struct cc_var *ccv, uint32_t type);
static void	cubic_conn_init(struct cc_var *ccv);
static void	cubic_post_recovery(struct cc_var *ccv);
static void	cubic_record_rtt(struct cc_var *ccv);
static void	cubic_ssthresh_update(struct cc_var *ccv);
static void	cubic_after_idle(struct cc_var *ccv);

struct cubic {
	/* Cubic K in fixed point form with CUBIC_SHIFT worth of precision. */
	int64_t		K;
	/* Sum of RTT samples across an epoch in nanoseconds. */
	hrtime_t	sum_rtt_nsecs;
	/* cwnd at the most recent congestion event. */
	uint32_t	max_cwnd;
	/* cwnd at the previous congestion event. */
	uint32_t	prev_max_cwnd;
	/* Number of congestion events. */
	uint32_t	num_cong_events;
	/* Minimum observed rtt in nanoseconds. */
	hrtime_t	min_rtt_nsecs;
	/* Mean observed rtt between congestion epochs. */
	hrtime_t	mean_rtt_nsecs;
	/* ACKs since last congestion event. */
	int		epoch_ack_count;
	/* Time of last congestion event in nanoseconds. */
	hrtime_t	t_last_cong;
};

struct cc_algo cubic_cc_algo = {
	.name = "cubic",
	.ack_received = cubic_ack_received,
	.cb_destroy = cubic_cb_destroy,
	.cb_init = cubic_cb_init,
	.cong_signal = cubic_cong_signal,
	.conn_init = cubic_conn_init,
	.post_recovery = cubic_post_recovery,
	.after_idle = cubic_after_idle,
};

int
_init(void)
{
	int err;

	if ((newreno_cc_algo = cc_load_algo("newreno")) == NULL)
		return (EINVAL);

	if ((err = cc_register_algo(&cubic_cc_algo)) == 0) {
		if ((err = mod_install(&cc_cubic_modlinkage)) != 0)
			(void) cc_deregister_algo(&cubic_cc_algo);
	}

	return (err);
}

int
_fini(void)
{
	/* XXX Not unloadable for now */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&cc_cubic_modlinkage, modinfop));
}

static void
cubic_ack_received(struct cc_var *ccv, uint16_t type)
{
	struct cubic *cubic_data;
	uint32_t w_tf, w_cubic_next;
	hrtime_t nsecs_since_cong;

	cubic_data = ccv->cc_data;
	cubic_record_rtt(ccv);

	/*
	 * Regular ACK and we're not in cong/fast recovery and we're cwnd
	 * limited and we're either not doing ABC or are slow starting or are
	 * doing ABC and we've sent a cwnd's worth of bytes.
	 */
	if (type == CC_ACK && !IN_RECOVERY(ccv->flags) &&
	    (ccv->flags & CCF_CWND_LIMITED) && (!CC_ABC(ccv) ||
	    CCV(ccv, tcp_cwnd) <= CCV(ccv, tcp_cwnd_ssthresh) ||
	    (CC_ABC(ccv) && (ccv->flags & CCF_ABC_SENTAWND)))) {
		/* Use the logic in NewReno ack_received() for slow start. */
		if (CCV(ccv, tcp_cwnd) <= CCV(ccv, tcp_cwnd_ssthresh) ||
		    cubic_data->min_rtt_nsecs == TCPTV_SRTTBASE)
			newreno_cc_algo->ack_received(ccv, type);
		else {
			nsecs_since_cong = gethrtime() -
			    cubic_data->t_last_cong;

			/*
			 * The mean RTT is used to best reflect the equations in
			 * the I-D. Using min_rtt in the tf_cwnd calculation
			 * causes w_tf to grow much faster than it should if the
			 * RTT is dominated by network buffering rather than
			 * propagation delay.
			 */
			w_tf = tf_cwnd(nsecs_since_cong,
			    cubic_data->mean_rtt_nsecs, cubic_data->max_cwnd,
			    CCV(ccv, tcp_mss));

			w_cubic_next = cubic_cwnd(nsecs_since_cong +
			    cubic_data->mean_rtt_nsecs, cubic_data->max_cwnd,
			    CCV(ccv, tcp_mss), cubic_data->K);

			ccv->flags &= ~CCF_ABC_SENTAWND;

			if (w_cubic_next < w_tf) {
				/*
				 * TCP-friendly region, follow tf
				 * cwnd growth.
				 */
				if (CCV(ccv, tcp_cwnd) < w_tf)
					CCV(ccv, tcp_cwnd) = w_tf;
			} else if (CCV(ccv, tcp_cwnd) < w_cubic_next) {
				/*
				 * Concave or convex region, follow CUBIC
				 * cwnd growth.
				 */
				if (CC_ABC(ccv))
					CCV(ccv, tcp_cwnd) = MIN(w_cubic_next,
					    INT_MAX);
				else
					CCV(ccv, tcp_cwnd) += MAX(1,
					    ((MIN(w_cubic_next, INT_MAX) -
					    CCV(ccv, tcp_cwnd)) *
					    CCV(ccv, tcp_mss)) /
					    CCV(ccv, tcp_cwnd));
			}

			/*
			 * If we're not in slow start and we're probing for a
			 * new cwnd limit at the start of a connection
			 * (happens when hostcache has a relevant entry),
			 * keep updating our current estimate of the
			 * max_cwnd.
			 */
			if (cubic_data->num_cong_events == 0 &&
			    cubic_data->max_cwnd < CCV(ccv, tcp_cwnd)) {
				cubic_data->max_cwnd = CCV(ccv, tcp_cwnd);
				cubic_data->K = cubic_k(cubic_data->max_cwnd /
				    CCV(ccv, tcp_mss));
			}
		}
	}
}

/*
 * This is a Cubic specific implementation of after_idle.
 *   - Reset cwnd by calling New Reno implementation of after_idle.
 *   - Reset t_last_cong.
 */
static void
cubic_after_idle(struct cc_var *ccv)
{
	struct cubic *cubic_data;

	cubic_data = ccv->cc_data;

	cubic_data->max_cwnd = max(cubic_data->max_cwnd, CCV(ccv, tcp_cwnd));
	cubic_data->K = cubic_k(cubic_data->max_cwnd / CCV(ccv, tcp_mss));

	newreno_cc_algo->after_idle(ccv);
	cubic_data->t_last_cong = gethrtime();
}

static void
cubic_cb_destroy(struct cc_var *ccv)
{

	if (ccv->cc_data != NULL)
		kmem_free(ccv->cc_data, sizeof (struct cubic));
}

static int
cubic_cb_init(struct cc_var *ccv)
{
	struct cubic *cubic_data;

	cubic_data = kmem_zalloc(sizeof (struct cubic), KM_NOSLEEP);

	if (cubic_data == NULL)
		return (ENOMEM);

	/* Init some key variables with sensible defaults. */
	cubic_data->t_last_cong = gethrtime();
	cubic_data->min_rtt_nsecs = TCPTV_SRTTBASE;
	cubic_data->mean_rtt_nsecs = 1;

	ccv->cc_data = cubic_data;

	return (0);
}

/*
 * Perform any necessary tasks before we enter congestion recovery.
 */
static void
cubic_cong_signal(struct cc_var *ccv, uint32_t type)
{
	struct cubic *cubic_data;
	uint32_t cwin;
	uint32_t mss;

	cubic_data = ccv->cc_data;
	cwin = CCV(ccv, tcp_cwnd);
	mss = CCV(ccv, tcp_mss);

	switch (type) {
	case CC_NDUPACK:
		if (!IN_FASTRECOVERY(ccv->flags)) {
			if (!IN_CONGRECOVERY(ccv->flags)) {
				cubic_ssthresh_update(ccv);
				cubic_data->num_cong_events++;
				cubic_data->prev_max_cwnd =
				    cubic_data->max_cwnd;
				cubic_data->max_cwnd = cwin;
				CCV(ccv, tcp_cwnd) =
				    CCV(ccv, tcp_cwnd_ssthresh);
			}
			ENTER_RECOVERY(ccv->flags);
		}
		break;

	case CC_ECN:
		if (!IN_CONGRECOVERY(ccv->flags)) {
			cubic_ssthresh_update(ccv);
			cubic_data->num_cong_events++;
			cubic_data->prev_max_cwnd = cubic_data->max_cwnd;
			cubic_data->max_cwnd = cwin;
			cubic_data->t_last_cong = gethrtime();
			CCV(ccv, tcp_cwnd) = CCV(ccv, tcp_cwnd_ssthresh);
			ENTER_CONGRECOVERY(ccv->flags);
		}
		break;

	case CC_RTO:
		/*
		 * Grab the current time and record it so we know when the
		 * most recent congestion event was.
		 */
		cubic_data->num_cong_events++;
		cubic_data->t_last_cong = gethrtime();
		cubic_ssthresh_update(ccv);
		cubic_data->max_cwnd = cwin;
		CCV(ccv, tcp_cwnd) = mss;
		break;
	}
}

static void
cubic_conn_init(struct cc_var *ccv)
{
	struct cubic *cubic_data;

	cubic_data = ccv->cc_data;

	/*
	 * Ensure we have a sane initial value for max_cwnd recorded. Without
	 * this here bad things happen when entries from the TCP hostcache
	 * get used.
	 */
	cubic_data->max_cwnd = CCV(ccv, tcp_cwnd);
}

/*
 * Perform any necessary tasks before we exit congestion recovery.
 */
static void
cubic_post_recovery(struct cc_var *ccv)
{
	struct cubic *cubic_data;
	uint32_t mss, pipe;

	cubic_data = ccv->cc_data;

	/* Fast convergence heuristic. */
	if (cubic_data->max_cwnd < cubic_data->prev_max_cwnd) {
		cubic_data->max_cwnd = (cubic_data->max_cwnd * CUBIC_FC_FACTOR)
		    >> CUBIC_SHIFT;
	}

	/*
	 * There is a risk that if the cwnd becomes less than mss, and
	 * we do not get enough acks to drive it back up beyond mss,
	 * we will stop transmitting data altogether.
	 *
	 * The Cubic RFC defines values in terms of units of mss. Therefore
	 * we must make sure we have at least 1 mss to make progress
	 * since the algorthm is written that way.
	 */
	mss = CCV(ccv, tcp_mss);

	if (IN_FASTRECOVERY(ccv->flags)) {
		/*
		 * If inflight data is less than ssthresh, set cwnd
		 * conservatively to avoid a burst of data, as suggested in
		 * the NewReno RFC. Otherwise, use the CUBIC method.
		 */
		pipe = CCV(ccv, tcp_snxt) - CCV(ccv, tcp_suna);
		if (pipe < CCV(ccv, tcp_cwnd_ssthresh)) {
			/*
			 * Ensure that cwnd does not collapse to 1 MSS under
			 * adverse conditions. Implements RFC6582
			 */
			CCV(ccv, tcp_cwnd) = MAX(pipe, mss) + mss;
		} else {
			/* Update cwnd based on beta and adjusted max_cwnd. */
			CCV(ccv, tcp_cwnd) = max(mss, ((CUBIC_BETA *
			    cubic_data->max_cwnd) >> CUBIC_SHIFT));
		}
	} else {
		CCV(ccv, tcp_cwnd) = max(mss, CCV(ccv, tcp_cwnd));
	}

	cubic_data->t_last_cong = gethrtime();

	/* Calculate the average RTT between congestion epochs. */
	if (cubic_data->epoch_ack_count > 0 &&
	    cubic_data->sum_rtt_nsecs >= cubic_data->epoch_ack_count) {
		cubic_data->mean_rtt_nsecs =
		    (cubic_data->sum_rtt_nsecs / cubic_data->epoch_ack_count);
	}

	cubic_data->epoch_ack_count = 0;
	cubic_data->sum_rtt_nsecs = 0;
	cubic_data->K = cubic_k(cubic_data->max_cwnd / mss);
}

/*
 * Record the min RTT and sum samples for the epoch average RTT calculation.
 */
static void
cubic_record_rtt(struct cc_var *ccv)
{
	struct cubic *cubic_data;
	int t_srtt_nsecs;

	/* Ignore srtt until a min number of samples have been taken. */
	if (CCV(ccv, tcp_rtt_update) >= CUBIC_MIN_RTT_SAMPLES) {
		cubic_data = ccv->cc_data;
		/* tcp_rtt_sa is 8 * smoothed RTT in nanoseconds */
		t_srtt_nsecs = CCV(ccv, tcp_rtt_sa) >> 3;

		/*
		 * Record the current SRTT as our minrtt if it's the smallest
		 * we've seen or minrtt is currently equal to its initialized
		 * value.
		 *
		 * XXXLAS: Should there be some hysteresis for minrtt?
		 */
		if ((t_srtt_nsecs < cubic_data->min_rtt_nsecs ||
		    cubic_data->min_rtt_nsecs == TCPTV_SRTTBASE)) {
			cubic_data->min_rtt_nsecs = max(1, t_srtt_nsecs);

			/*
			 * If the connection is within its first congestion
			 * epoch, ensure we prime mean_rtt_nsecs with a
			 * reasonable value until the epoch average RTT is
			 * calculated in cubic_post_recovery().
			 */
			if (cubic_data->min_rtt_nsecs >
			    cubic_data->mean_rtt_nsecs)
				cubic_data->mean_rtt_nsecs =
				    cubic_data->min_rtt_nsecs;
		}

		/* Sum samples for epoch average RTT calculation. */
		cubic_data->sum_rtt_nsecs += t_srtt_nsecs;
		cubic_data->epoch_ack_count++;
	}
}

/*
 * Update the ssthresh in the event of congestion.
 */
static void
cubic_ssthresh_update(struct cc_var *ccv)
{
	struct cubic *cubic_data;

	cubic_data = ccv->cc_data;

	/*
	 * On the first congestion event, set ssthresh to cwnd * 0.5, on
	 * subsequent congestion events, set it to cwnd * beta.
	 */
	if (cubic_data->num_cong_events == 0)
		CCV(ccv, tcp_cwnd_ssthresh) = CCV(ccv, tcp_cwnd) >> 1;
	else
		CCV(ccv, tcp_cwnd_ssthresh) =
		    (CCV(ccv, tcp_cwnd) * CUBIC_BETA) >> CUBIC_SHIFT;
}
