/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994, 1995
 *	The Regents of the University of California.
 * Copyright (c) 2007-2008,2010
 *	Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 * Copyright 2020 RackTop Systems, Inc.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart, James
 * Healy and David Hayes, made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
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
 * This software was first released in 2007 by James Healy and Lawrence Stewart
 * whilst working on the NewTCP research project at Swinburne University of
 * Technology's Centre for Advanced Internet Architectures, Melbourne,
 * Australia, which was made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
 * More details are available at:
 *   http://caia.swin.edu.au/urp/newtcp/
 */

#include <sys/errno.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/cc.h>
#include <inet/cc/cc_module.h>

static void	newreno_ack_received(struct cc_var *ccv, uint16_t type);
static void	newreno_after_idle(struct cc_var *ccv);
static void	newreno_cong_signal(struct cc_var *ccv, uint32_t type);
static void	newreno_post_recovery(struct cc_var *ccv);

static struct modlmisc cc_newreno_modlmisc = {
	&mod_miscops,
	"New Reno Congestion Control"
};

static struct modlinkage cc_newreno_modlinkage = {
	MODREV_1,
	&cc_newreno_modlmisc,
	NULL
};

struct cc_algo newreno_cc_algo = {
	.name = "newreno",
	.ack_received = newreno_ack_received,
	.after_idle = newreno_after_idle,
	.cong_signal = newreno_cong_signal,
	.post_recovery = newreno_post_recovery,
};

int
_init(void)
{
	int err;

	if ((err = cc_register_algo(&newreno_cc_algo)) == 0) {
		if ((err = mod_install(&cc_newreno_modlinkage)) != 0)
			(void) cc_deregister_algo(&newreno_cc_algo);
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
	return (mod_info(&cc_newreno_modlinkage, modinfop));
}

static void
newreno_ack_received(struct cc_var *ccv, uint16_t type)
{
	if (type == CC_ACK && !IN_RECOVERY(ccv->flags) &&
	    (ccv->flags & CCF_CWND_LIMITED)) {
		uint_t cw = CCV(ccv, tcp_cwnd);
		uint_t incr = CCV(ccv, tcp_mss);

		/*
		 * Regular in-order ACK, open the congestion window.
		 * Method depends on which congestion control state we're
		 * in (slow start or cong avoid) and if ABC (RFC 3465) is
		 * enabled.
		 *
		 * slow start: cwnd <= ssthresh
		 * cong avoid: cwnd > ssthresh
		 *
		 * slow start and ABC (RFC 3465):
		 *   Grow cwnd exponentially by the amount of data
		 *   ACKed capping the max increment per ACK to
		 *   (abc_l_var * maxseg) bytes.
		 *
		 * slow start without ABC (RFC 5681):
		 *   Grow cwnd exponentially by maxseg per ACK.
		 *
		 * cong avoid and ABC (RFC 3465):
		 *   Grow cwnd linearly by maxseg per RTT for each
		 *   cwnd worth of ACKed data.
		 *
		 * cong avoid without ABC (RFC 5681):
		 *   Grow cwnd linearly by approximately maxseg per RTT using
		 *   maxseg^2 / cwnd per ACK as the increment.
		 *   If cwnd > maxseg^2, fix the cwnd increment at 1 byte to
		 *   avoid capping cwnd.
		 */
		if (cw > CCV(ccv, tcp_cwnd_ssthresh)) {
			if (CC_ABC(ccv)) {
				if (ccv->flags & CCF_ABC_SENTAWND)
					ccv->flags &= ~CCF_ABC_SENTAWND;
				else
					incr = 0;
			} else
				incr = max((incr * incr / cw), 1);
		} else if (CC_ABC(ccv)) {
			/*
			 * In slow-start with ABC enabled and no RTO in sight?
			 * (Must not use abc_l_var > 1 if slow starting after
			 * an RTO.
			 */
			if (ccv->flags & CCF_RTO) {
				incr = min(ccv->bytes_this_ack,
				    CCV(ccv, tcp_mss));
			} else {
				incr = min(ccv->bytes_this_ack,
				    CC_ABC_L_VAR(ccv) * CCV(ccv, tcp_mss));
			}

		}
		/* ABC is on by default, so incr equals 0 frequently. */
		if (incr > 0)
			CCV(ccv, tcp_cwnd) = min(cw + incr,
			    TCP_MAXWIN << CCV(ccv, tcp_snd_ws));
	}
}

static void
newreno_after_idle(struct cc_var *ccv)
{
	int rw;

	/*
	 * If we've been idle for more than one retransmit timeout the old
	 * congestion window is no longer current and we have to reduce it to
	 * the restart window before we can transmit again.
	 *
	 * The restart window is the initial window or the last CWND, whichever
	 * is smaller.
	 *
	 * This is done to prevent us from flooding the path with a full CWND at
	 * wirespeed, overloading router and switch buffers along the way.
	 *
	 * See RFC5681 Section 4.1. "Restarting Idle Connections".
	 */
	if (CCV(ccv, tcp_init_cwnd) != 0) {
		/*
		 * The TCP_INIT_CWND socket option was used to override the
		 * default.
		 */
		rw = CCV(ccv, tcp_init_cwnd) * CCV(ccv, tcp_mss);
	} else if (CCSV(ccv, tcps_slow_start_initial) != 0) {
		/* The _slow_start_initial tunable was explicitly set. */
		rw = min(TCP_MAX_INIT_CWND, CCSV(ccv, tcps_slow_start_initial))
		    * CCV(ccv, tcp_mss);
	} else {
		/* Do RFC 3390 */
		rw = min(4 * CCV(ccv, tcp_mss),
		    max(2 * CCV(ccv, tcp_mss), 4380));
	}

	CCV(ccv, tcp_cwnd) = min(rw, CCV(ccv, tcp_cwnd));
}

/*
 * Perform any necessary tasks before we enter congestion recovery.
 */
static void
newreno_cong_signal(struct cc_var *ccv, uint32_t type)
{
	uint32_t cwin, ssthresh_on_loss;
	uint32_t mss;

	cwin = CCV(ccv, tcp_cwnd);
	mss = CCV(ccv, tcp_mss);
	ssthresh_on_loss =
	    max((CCV(ccv, tcp_snxt) - CCV(ccv, tcp_suna)) / 2 / mss, 2)
	    * mss;

	/* Catch algos which mistakenly leak private signal types. */
	ASSERT((type & CC_SIGPRIVMASK) == 0);

	cwin = max(cwin / 2 / mss, 2) * mss;

	switch (type) {
	case CC_NDUPACK:
		if (!IN_FASTRECOVERY(ccv->flags)) {
			if (!IN_CONGRECOVERY(ccv->flags)) {
				CCV(ccv, tcp_cwnd_ssthresh) = ssthresh_on_loss;
				CCV(ccv, tcp_cwnd) = cwin;
			}
			ENTER_RECOVERY(ccv->flags);
		}
		break;
	case CC_ECN:
		if (!IN_CONGRECOVERY(ccv->flags)) {
			CCV(ccv, tcp_cwnd_ssthresh) = ssthresh_on_loss;
			CCV(ccv, tcp_cwnd) = cwin;
			ENTER_CONGRECOVERY(ccv->flags);
		}
		break;
	case CC_RTO:
		CCV(ccv, tcp_cwnd_ssthresh) = ssthresh_on_loss;
		CCV(ccv, tcp_cwnd) = mss;
		break;
	}
}

/*
 * Perform any necessary tasks before we exit congestion recovery.
 */
static void
newreno_post_recovery(struct cc_var *ccv)
{
	uint32_t pipe;

	if (IN_FASTRECOVERY(ccv->flags)) {
		/*
		 * Fast recovery will conclude after returning from this
		 * function. Window inflation should have left us with
		 * approximately cwnd_ssthresh outstanding data. But in case we
		 * would be inclined to send a burst, better to do it via the
		 * slow start mechanism.
		 */
		pipe = CCV(ccv, tcp_snxt) - CCV(ccv, tcp_suna);
		if (pipe < CCV(ccv, tcp_cwnd_ssthresh)) {
			/*
			 * Ensure that cwnd does not collapse to 1 MSS under
			 * adverse conditions. Implements RFC6582
			 */
			CCV(ccv, tcp_cwnd) = MAX(pipe, CCV(ccv, tcp_mss)) +
			    CCV(ccv, tcp_mss);
		} else if (CCV(ccv, tcp_cwnd) > CCV(ccv, tcp_cwnd_ssthresh)) {
			CCV(ccv, tcp_cwnd) = CCV(ccv, tcp_cwnd_ssthresh);
		}
	}
}
