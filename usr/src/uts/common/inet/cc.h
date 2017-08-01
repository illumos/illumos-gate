/*
 * Copyright (c) 2007-2008
 * 	Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart and
 * James Healy, made possible in part by a grant from the Cisco University
 * Research Program Fund at Community Foundation Silicon Valley.
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
 *
 * $FreeBSD$
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

#ifndef _NETINET_CC_H_
#define	_NETINET_CC_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <netinet/tcp.h>
#include <sys/queue.h>
#include <sys/rwlock.h>

#define	CC_ALGO_NAME_MAX	16	/* max congestion control name length */

#define	CC_DEFAULT_ALGO_NAME	"sunreno"

struct tcp_s;
struct sctp_s;

/* CC housekeeping functions. */
extern struct cc_algo *cc_load_algo(const char *name);
extern int	cc_register_algo(struct cc_algo *add_cc);
extern int	cc_deregister_algo(struct cc_algo *remove_cc);

/*
 * Wrapper around transport structs that contain same-named congestion
 * control variables. Allows algos to be shared amongst multiple CC aware
 * transports.
 *
 * In theory, this code (from FreeBSD) can be used to support pluggable
 * congestion control for sctp as well as tcp.  However, the support for sctp
 * in FreeBSD is incomplete, and in practice "type" is ignored.  cc_module.h
 * provides a CCV macro which implementations can use to get a variable out of
 * the protocol-appropriate structure.
 *
 * If FreeBSD eventually does extend support for pluggable congestion control
 * to sctp, we'll need to make sure we're setting "type" appropriately or use
 * a definition of CCV that ignores it.
 */
struct cc_var {
	void		*cc_data; /* Per-connection private algorithm data. */
	int		bytes_this_ack; /* # bytes acked by the current ACK. */
	int		t_bytes_acked; /* # bytes acked during current RTT */
	tcp_seq		curack; /* Most recent ACK. */
	uint32_t	flags; /* Flags for cc_var (see below) */
	int		type; /* Indicates which ptr is valid in ccvc. */
	union ccv_container {
		struct tcp_s	*tcp;
		struct sctp_s	*sctp;
	} ccvc;
	uint16_t	nsegs; /* # segments coalesced into current chain. */
};

/*
 * cc_var flags.
 *
 * CCF_ABC_SENTAWND is set when a full congestion window of data has been ACKed
 *   according to the Appropriate Byte Counting spec, defined in RFC 3465.
 */
#define	CCF_ABC_SENTAWND	0x0001	/* ABC counted cwnd worth of bytes? */
#define	CCF_CWND_LIMITED	0x0002	/* Are we currently cwnd limited? */
#define	CCF_FASTRECOVERY	0x0004	/* in NewReno Fast Recovery */
#define	CCF_WASFRECOVERY	0x0008	/* was in NewReno Fast Recovery */
#define	CCF_CONGRECOVERY	0x0010	/* congestion recovery mode */
#define	CCF_WASCRECOVERY	0x0020	/* was in congestion recovery */
/*
 * In slow-start due to a retransmission timeout. This flag is enabled for the
 * duration of the slow-start phase.
 */
#define	CCF_RTO			0x0040	/* in slow-start due to timeout */

#define	IN_FASTRECOVERY(flags)		(flags & CCF_FASTRECOVERY)
#define	ENTER_FASTRECOVERY(flags)	flags |= CCF_FASTRECOVERY
#define	EXIT_FASTRECOVERY(flags)	flags &= ~CCF_FASTRECOVERY

#define	IN_CONGRECOVERY(flags)		(flags & CCF_CONGRECOVERY)
#define	ENTER_CONGRECOVERY(flags)	flags |= CCF_CONGRECOVERY
#define	EXIT_CONGRECOVERY(flags)	flags &= ~CCF_CONGRECOVERY

#define	IN_RECOVERY(flags) (flags & (CCF_CONGRECOVERY | CCF_FASTRECOVERY))
#define	ENTER_RECOVERY(flags) flags |= (CCF_CONGRECOVERY | CCF_FASTRECOVERY)
#define	EXIT_RECOVERY(flags) flags &= ~(CCF_CONGRECOVERY | CCF_FASTRECOVERY)

/*
 * ACK types passed to the ack_received() hook.
 *
 * CC_ACK is passed when an ACK acknowledges previously unACKed data.
 * CC_DUPACK is passed when a duplicate ACK is received.  The conditions under
 *   which an ACK is considered a duplicate ACK are defined in RFC 5681.
 */
#define	CC_ACK		0x0001	/* Regular in sequence ACK. */
#define	CC_DUPACK	0x0002	/* Duplicate ACK. */
#define	CC_PARTIALACK	0x0004	/* Not yet. */
#define	CC_SACK		0x0008	/* Not yet. */

/*
 * Congestion signal types passed to the cong_signal() hook. The highest order 8
 * bits (0x01000000 - 0x80000000) are reserved for CC algos to declare their own
 * congestion signal types.
 *
 * The congestion signals defined here cover the following situations:
 * CC_ECN: A packet with an Explicit Congestion Notification was received
 *   See RFC 3168.
 * CC_RTO: A round-trip timeout occured.
 * CC_RTO_ERR: An ACK was received for a sequence number after we fired an RTO
 *   for that sequence number
 * CC_NDUPACK: Trigger fast retransmit based on the assumption that receiving
 *   N duplicate ACKs indicates packet loss rather than reordering.  Fast
 *   retransmit is followed by fast recovery.  Fast retransmit and recovery
 *   were originally described in RFC 2581 and were updated by RFC3782
 *   (NewReno).  In both RFC2581 and RFC3782, N is 3.
 */
#define	CC_ECN		0x00000001	/* ECN marked packet received. */
#define	CC_RTO		0x00000002	/* RTO fired. */
#define	CC_RTO_ERR	0x00000004	/* RTO fired in error. */
#define	CC_NDUPACK	0x00000008	/* Threshold of dupack's reached. */

#define	CC_SIGPRIVMASK	0xFF000000	/* Mask to check if sig is private. */

/*
 * Structure to hold data and function pointers that together represent a
 * congestion control algorithm.
 */
struct cc_algo {
	char	name[CC_ALGO_NAME_MAX];

	/* Init CC state for a new control block. */
	int	(*cb_init)(struct cc_var *ccv);

	/* Cleanup CC state for a terminating control block. */
	void	(*cb_destroy)(struct cc_var *ccv);

	/* Init variables for a newly established connection. */
	void	(*conn_init)(struct cc_var *ccv);

	/* Called on receipt of an ack. */
	void	(*ack_received)(struct cc_var *ccv, uint16_t type);

	/* Called on detection of a congestion signal. */
	void	(*cong_signal)(struct cc_var *ccv, uint32_t type);

	/* Called after exiting congestion recovery. */
	void	(*post_recovery)(struct cc_var *ccv);

	/* Called when data transfer resumes after an idle period. */
	void	(*after_idle)(struct cc_var *ccv);

	STAILQ_ENTRY(cc_algo) entries;
};

typedef int cc_walk_func_t(void *, struct cc_algo *);
extern int	cc_walk_algos(cc_walk_func_t *, void *);

/* Macro to obtain the CC algo's struct ptr. */
#define	CC_ALGO(tp)	((tp)->tcp_cc_algo)

/* Macro to obtain the CC algo's data ptr. */
#define	CC_DATA(tp)	((tp)->tcp_ccv.cc_data)

#ifdef	__cplusplus
}
#endif

#endif /* _NETINET_CC_H_ */
