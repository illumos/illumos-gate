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


#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/mib2.h>
#include <inet/ipclassifier.h>
#include "sctp_impl.h"
#include "sctp_asconf.h"

/* Timer block states. */
typedef enum {
	SCTP_TB_RUNNING = 1,
	SCTP_TB_IDLE,
/* Could not stop/free before mblk got queued */
	SCTP_TB_RESCHED,	/* sctp_tb_time_left contains tick count */
	SCTP_TB_CANCELLED,
	SCTP_TB_TO_BE_FREED
} timer_block_state;

typedef struct sctp_tb_s {
	timer_block_state	sctp_tb_state;
	timeout_id_t		sctp_tb_tid;
	mblk_t			*sctp_tb_mp;
	clock_t			sctp_tb_time_left;
} sctp_tb_t;

static void sctp_timer_fire(sctp_tb_t *);

/*
 *		sctp_timer mechanism.
 *
 * Each timer is represented by a timer mblk. When the
 * timer fires, and the sctp_t is busy, the timer mblk will be put on
 * the associated sctp_t timer queue so that it can be executed when
 * the thread holding the lock on the sctp_t is done with its job.
 *
 * Note that there is no lock to protect the timer mblk state.  The reason
 * is that the timer state can only be changed by a thread holding the
 * lock on the sctp_t.
 *
 * The interface consists of 4 entry points:
 *	sctp_timer_alloc	- create a timer mblk
 *	sctp_timer_free		- free a timer mblk
 *	sctp_timer		- start, restart, stop the timer
 *	sctp_timer_valid	- called by sctp_process_recvq to verify that
 *				  the timer did indeed fire.
 */


/*
 * Start, restart, stop the timer.
 * If "tim" is -1 the timer is stopped.
 * Otherwise, the timer is stopped if it is already running, and
 * set to fire tim clock ticks from now.
 */
void
sctp_timer(sctp_t *sctp, mblk_t *mp, clock_t tim)
{
	sctp_tb_t *sctp_tb;
	int state;

	ASSERT(sctp != NULL && mp != NULL);
	ASSERT((mp->b_rptr - mp->b_datap->db_base) == sizeof (sctp_tb_t));
	ASSERT(mp->b_datap->db_type == M_PCSIG);

	sctp_tb = (sctp_tb_t *)mp->b_datap->db_base;
	if (tim >= 0) {
		state = sctp_tb->sctp_tb_state;
		sctp_tb->sctp_tb_time_left = tim;
		if (state == SCTP_TB_RUNNING) {
			if (untimeout(sctp_tb->sctp_tb_tid) < 0) {
				sctp_tb->sctp_tb_state = SCTP_TB_RESCHED;
				/* sctp_timer_valid will start timer */
				return;
			}
		} else if (state != SCTP_TB_IDLE) {
			ASSERT(state != SCTP_TB_TO_BE_FREED);
			if (state == SCTP_TB_CANCELLED) {
				sctp_tb->sctp_tb_state = SCTP_TB_RESCHED;
				/* sctp_timer_valid will start timer */
				return;
			}
			if (state == SCTP_TB_RESCHED) {
				/* sctp_timer_valid will start timer */
				return;
			}
		} else {
			SCTP_REFHOLD(sctp);
		}
		sctp_tb->sctp_tb_state = SCTP_TB_RUNNING;
		sctp_tb->sctp_tb_tid =
		    timeout((pfv_t)sctp_timer_fire, sctp_tb, tim);
		return;
	}
	switch (tim) {
	case -1:
		sctp_timer_stop(mp);
		break;
	default:
		ASSERT(0);
		break;
	}
}

/*
 * sctp_timer_alloc is called by sctp_init to allocate and initialize a
 * sctp timer.
 *
 * Allocate an M_PCSIG timer message. The space between db_base and
 * b_rptr is used by the sctp_timer mechanism, and after b_rptr there is
 * space for sctpt_t.
 */
mblk_t *
sctp_timer_alloc(sctp_t *sctp, pfv_t func, int sleep)
{
	mblk_t *mp;
	sctp_tb_t *sctp_tb;
	sctpt_t	*sctpt;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (sleep == KM_SLEEP) {
		mp = allocb_wait(sizeof (sctp_t) + sizeof (sctp_tb_t), BPRI_HI,
		    STR_NOSIG, NULL);
	} else {
		mp = allocb(sizeof (sctp_t) + sizeof (sctp_tb_t), BPRI_HI);
	}
	if (mp != NULL) {
		mp->b_datap->db_type = M_PCSIG;
		sctp_tb = (sctp_tb_t *)mp->b_datap->db_base;
		mp->b_rptr = (uchar_t *)&sctp_tb[1];
		mp->b_wptr = mp->b_rptr + sizeof (sctpt_t);
		sctp_tb->sctp_tb_state = SCTP_TB_IDLE;
		sctp_tb->sctp_tb_mp = mp;

		sctpt = (sctpt_t *)mp->b_rptr;
		sctpt->sctpt_sctp = sctp;
		sctpt->sctpt_faddr = NULL;	/* set when starting timer */
		sctpt->sctpt_pfv = func;
		return (mp);
	}
	SCTP_KSTAT(sctps, sctp_add_timer);
	return (NULL);
}

/*
 * timeout() callback function.
 * Put the message on the process control block's queue.
 * If the timer is stopped or freed after
 * it has fired then sctp_timer() and sctp_timer_valid() will clean
 * things up.
 */
static void
sctp_timer_fire(sctp_tb_t *sctp_tb)
{
	mblk_t *mp;
	sctp_t *sctp;
	sctpt_t *sctpt;

	mp = sctp_tb->sctp_tb_mp;
	ASSERT(sctp_tb == (sctp_tb_t *)mp->b_datap->db_base);
	ASSERT(mp->b_datap->db_type == M_PCSIG);

	sctpt = (sctpt_t *)mp->b_rptr;
	sctp = sctpt->sctpt_sctp;
	ASSERT(sctp != NULL);

	mutex_enter(&sctp->sctp_lock);
	if (sctp->sctp_running) {
		/*
		 * Put the timer mblk to the special sctp_timer_mp list.
		 * This timer will be handled when the thread using this
		 * SCTP is done with its job.
		 */
		if (sctp->sctp_timer_mp == NULL) {
			SCTP_REFHOLD(sctp);
			sctp->sctp_timer_mp = mp;
		} else {
			linkb(sctp->sctp_timer_mp, mp);
		}
		mp->b_cont = NULL;
		mutex_exit(&sctp->sctp_lock);
	} else {
		sctp->sctp_running = B_TRUE;
		mutex_exit(&sctp->sctp_lock);

		sctp_timer_call(sctp, mp);
		WAKE_SCTP(sctp);
		sctp_process_sendq(sctp);
	}
	SCTP_REFRELE(sctp);
}

/*
 * Logically free a timer mblk (that might have a pending timeout().)
 * If the timer has fired and the mblk has been put on the queue then
 * sctp_timer_valid will free the mblk.
 */
void
sctp_timer_free(mblk_t *mp)
{
	sctp_tb_t *sctp_tb;
	int state;
	sctpt_t *sctpt;

	ASSERT(mp != NULL);
	ASSERT((mp->b_rptr - mp->b_datap->db_base) == sizeof (sctp_tb_t));
	ASSERT(mp->b_datap->db_type == M_PCSIG);

	sctp_tb = (sctp_tb_t *)mp->b_datap->db_base;
	state = sctp_tb->sctp_tb_state;

	dprint(5, ("sctp_timer_free %p state %d\n", (void *)mp, state));

	if (state == SCTP_TB_RUNNING) {
		if (untimeout(sctp_tb->sctp_tb_tid) < 0) {
			sctp_tb->sctp_tb_state = SCTP_TB_TO_BE_FREED;
			/* sctp_timer_valid will free the mblk */
			return;
		}
		sctpt = (sctpt_t *)mp->b_rptr;
		SCTP_REFRELE(sctpt->sctpt_sctp);
	} else if (state != SCTP_TB_IDLE) {
		ASSERT(state != SCTP_TB_TO_BE_FREED);
		sctp_tb->sctp_tb_state = SCTP_TB_TO_BE_FREED;
		/* sctp_timer_valid will free the mblk */
		return;
	}
	freeb(mp);
}

/*
 * Called from sctp_timer(,,-1)
 */
void
sctp_timer_stop(mblk_t *mp)
{
	sctp_tb_t *sctp_tb;
	int state;
	sctpt_t *sctpt;

	ASSERT(mp != NULL);
	ASSERT(mp->b_datap->db_type == M_PCSIG);

	sctp_tb = (sctp_tb_t *)mp->b_datap->db_base;
	state = sctp_tb->sctp_tb_state;

	dprint(5, ("sctp_timer_stop %p %d\n", (void *)mp, state));

	if (state == SCTP_TB_RUNNING) {
		if (untimeout(sctp_tb->sctp_tb_tid) < 0) {
			sctp_tb->sctp_tb_state = SCTP_TB_CANCELLED;
		} else {
			sctp_tb->sctp_tb_state = SCTP_TB_IDLE;
			sctpt = (sctpt_t *)mp->b_rptr;
			SCTP_REFRELE(sctpt->sctpt_sctp);
		}
	} else if (state == SCTP_TB_RESCHED) {
		sctp_tb->sctp_tb_state = SCTP_TB_CANCELLED;
	}
}

/*
 * The user of the sctp_timer mechanism is required to call
 * sctp_timer_valid() for each M_PCSIG message processed in the
 * service procedures.
 * sctp_timer_valid will return "true" if the timer actually did fire.
 */

static boolean_t
sctp_timer_valid(mblk_t *mp)
{
	sctp_tb_t *sctp_tb;
	int state;
	sctpt_t *sctpt;

	ASSERT(mp != NULL);
	ASSERT(mp->b_datap->db_type == M_PCSIG);

	sctp_tb = (sctp_tb_t *)DB_BASE(mp);
	sctpt = (sctpt_t *)mp->b_rptr;
	state = sctp_tb->sctp_tb_state;
	if (state != SCTP_TB_RUNNING) {
		ASSERT(state != SCTP_TB_IDLE);
		if (state == SCTP_TB_TO_BE_FREED) {
			/*
			 * sctp_timer_free was called after the message
			 * was putq'ed.
			 */
			freeb(mp);
			return (B_FALSE);
		}
		if (state == SCTP_TB_CANCELLED) {
			/* The timer was stopped after the mblk was putq'ed */
			sctp_tb->sctp_tb_state = SCTP_TB_IDLE;
			return (B_FALSE);
		}
		if (state == SCTP_TB_RESCHED) {
			/*
			 * The timer was stopped and then restarted after
			 * the mblk was putq'ed.
			 * sctp_tb_time_left contains the number of ticks that
			 * the timer was restarted with.
			 * The sctp will not be disapper between the time
			 * the sctpt_t is marked SCTP_TB_RESCHED and when
			 * we get here as sctp_add_recvq() does a refhold.
			 */
			sctp_tb->sctp_tb_state = SCTP_TB_RUNNING;
			sctp_tb->sctp_tb_tid = timeout((pfv_t)sctp_timer_fire,
			    sctp_tb, sctp_tb->sctp_tb_time_left);
			SCTP_REFHOLD(sctpt->sctpt_sctp);
			return (B_FALSE);
		}
	}
	sctp_tb->sctp_tb_state = SCTP_TB_IDLE;
	return (B_TRUE);
}

/*
 * The SCTP timer call. Calls sctp_timer_valid() to verify whether
 * timer was cancelled or not.
 */
void
sctp_timer_call(sctp_t *sctp, mblk_t *mp)
{
	sctpt_t *sctpt = (sctpt_t *)mp->b_rptr;

	if (sctp_timer_valid(mp)) {
		(*sctpt->sctpt_pfv)(sctp, sctpt->sctpt_faddr);
	}
}

/*
 * Delayed ack
 */
void
sctp_ack_timer(sctp_t *sctp)
{
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	sctp->sctp_ack_timer_running = 0;
	sctp->sctp_sack_toggle = sctps->sctps_deferred_acks_max;
	BUMP_MIB(&sctps->sctps_mib, sctpOutAckDelayed);
	(void) sctp_sack(sctp, NULL);
}

/*
 * Peer address heartbeat timer handler
 */
void
sctp_heartbeat_timer(sctp_t *sctp)
{
	sctp_faddr_t	*fp;
	int64_t		now;
	int64_t		earliest_expiry;
	int		cnt;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (sctp->sctp_strikes >= sctp->sctp_pa_max_rxt) {
		/*
		 * If there is a peer address with no strikes,
		 * don't give up yet. If enough other peer
		 * address are down, we could otherwise fail
		 * the association prematurely.  This is a
		 * byproduct of our aggressive probe approach
		 * when a heartbeat fails to connect. We may
		 * wish to revisit this...
		 */
		if (!sctp_is_a_faddr_clean(sctp)) {
			/* time to give up */
			BUMP_MIB(&sctps->sctps_mib, sctpAborted);
			BUMP_MIB(&sctps->sctps_mib, sctpTimHeartBeatDrop);
			sctp_assoc_event(sctp, SCTP_COMM_LOST, 0, NULL);
			sctp_clean_death(sctp, sctp->sctp_client_errno ?
			    sctp->sctp_client_errno : ETIMEDOUT);
			return;
		}
	}

	/* Only send heartbeats in the established state */
	if (sctp->sctp_state != SCTPS_ESTABLISHED) {
		dprint(5, ("sctp_heartbeat_timer: not in ESTABLISHED\n"));
		return;
	}

	now = lbolt64;
	earliest_expiry = 0;
	cnt = sctps->sctps_maxburst;

	/*
	 * Walk through all faddrs.  Since the timer should run infrequently
	 * and the number of peer addresses should not be big, this should
	 * be OK.
	 */
	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
		/*
		 * If the peer is unreachable because there is no available
		 * source address, call sctp_get_ire() to see if it is
		 * reachable now.  If it is OK, the state will become
		 * unconfirmed.  And the following code to handle unconfirmed
		 * address will be executed.  If it is still not OK,
		 * re-schedule.  If heartbeat is enabled, only try this
		 * up to the normal heartbeat max times.  But if heartbeat
		 * is disable, this retry may go on forever.
		 */
		if (fp->state == SCTP_FADDRS_UNREACH) {
			sctp_get_ire(sctp, fp);
			if (fp->state == SCTP_FADDRS_UNREACH) {
				if (fp->hb_enabled &&
				    ++fp->strikes > fp->max_retr &&
				    sctp_faddr_dead(sctp, fp,
				    SCTP_FADDRS_DOWN) == -1) {
					/* Assoc is dead */
					return;
				}
				fp->hb_expiry = now + SET_HB_INTVL(fp);
				goto set_expiry;
			} else {
				/* Send a heartbeat immediately. */
				fp->hb_expiry = now;
			}
		}
		/*
		 * Don't send heartbeat to this address if it is not
		 * hb_enabled and the address has been confirmed.
		 */
		if (!fp->hb_enabled && fp->state != SCTP_FADDRS_UNCONFIRMED) {
			continue;
		}

		/*
		 * The heartbeat timer is expired.  If the address is dead,
		 * we still send heartbeat to it in case it becomes alive
		 * again.  But we will only send once in a while, calculated
		 * by SET_HB_INTVL().
		 *
		 * If the address is alive and there is a hearbeat pending,
		 * resend the heartbeat and start exponential backoff on the
		 * heartbeat timeout value.  If there is no heartbeat pending,
		 * just send out one.
		 */
		if (now >= fp->hb_expiry) {
			if (fp->hb_pending) {
				/*
				 * If an address is not confirmed, no need
				 * to bump the overall counter as it doesn't
				 * matter as we will not use it to send data
				 * and it should not affect the association.
				 */
				switch (fp->state) {
				case SCTP_FADDRS_ALIVE:
					sctp->sctp_strikes++;
					/* FALLTHRU */
				case SCTP_FADDRS_UNCONFIRMED:
					/*
					 * Retransmission implies that RTO
					 * is probably not correct.
					 */
					fp->rtt_updates = 0;
					fp->strikes++;
					if (fp->strikes > fp->max_retr) {
						if (sctp_faddr_dead(sctp, fp,
						    SCTP_FADDRS_DOWN) == -1) {
							/* Assoc is dead */
							return;
						}
						/*
						 * Addr is down; keep initial
						 * RTO
						 */
						fp->rto =
						    sctp->sctp_rto_initial;
						goto dead_addr;
					} else {
						SCTP_CALC_RXT(fp,
						    sctp->sctp_rto_max);
						fp->hb_expiry = now + fp->rto;
					}
					break;
				case SCTP_FADDRS_DOWN:
dead_addr:
					fp->hb_expiry = now + SET_HB_INTVL(fp);
					break;
				default:
					continue;
				}
			} else {
				/*
				 * If there is unack'ed data, no need to
				 * send a heart beat.
				 */
				if (fp->suna > 0) {
					fp->hb_expiry = now + SET_HB_INTVL(fp);
					goto set_expiry;
				} else {
					fp->hb_expiry = now + fp->rto;
				}
			}
			/*
			 * Note that the total number of heartbeat we can send
			 * out simultaneously is limited by sctp_maxburst.  If
			 * the limit is exceeded, we need to wait for the next
			 * timeout to send them.  This should only happen if
			 * there is unconfirmed address.  Note that hb_pending
			 * is set in sctp_send_heartbeat().  So if a heartbeat
			 * is not sent, it will not affect the state of the
			 * peer address.
			 */
			if (fp->state != SCTP_FADDRS_UNCONFIRMED || cnt-- > 0)
				sctp_send_heartbeat(sctp, fp);
		}
set_expiry:
		if (fp->hb_expiry < earliest_expiry || earliest_expiry == 0)
			earliest_expiry = fp->hb_expiry;
	}
	if (sctp->sctp_autoclose != 0) {
		int64_t expire;

		expire = sctp->sctp_active + sctp->sctp_autoclose;

		if (expire <= now) {
			dprint(3, ("sctp_heartbeat_timer: autoclosing\n"));
			sctp_send_shutdown(sctp, 0);
			return;
		}
		if (expire < earliest_expiry || earliest_expiry == 0)
			earliest_expiry = expire;
	}

	earliest_expiry -= now;
	if (earliest_expiry < 0)
		earliest_expiry = 1;
	sctp_timer(sctp, sctp->sctp_heartbeat_mp, earliest_expiry);
}

void
sctp_rexmit_timer(sctp_t *sctp, sctp_faddr_t *fp)
{
	mblk_t 		*mp;
	uint32_t	rto_max = sctp->sctp_rto_max;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	ASSERT(fp != NULL);

	dprint(3, ("sctp_timer: faddr=%x:%x:%x:%x\n",
	    SCTP_PRINTADDR(fp->faddr)));

	fp->timer_running = 0;

	/* Check is we've reached the max for retries */
	if (sctp->sctp_state < SCTPS_ESTABLISHED) {
		if (fp->strikes >= sctp->sctp_max_init_rxt) {
			/* time to give up */
			BUMP_MIB(&sctps->sctps_mib, sctpAborted);
			BUMP_MIB(&sctps->sctps_mib, sctpTimRetransDrop);
			sctp_assoc_event(sctp, SCTP_CANT_STR_ASSOC, 0, NULL);
			sctp_clean_death(sctp, sctp->sctp_client_errno ?
			    sctp->sctp_client_errno : ETIMEDOUT);
			return;
		}
	} else if (sctp->sctp_state >= SCTPS_ESTABLISHED) {
		if (sctp->sctp_strikes >= sctp->sctp_pa_max_rxt) {
			/* time to give up */
			BUMP_MIB(&sctps->sctps_mib, sctpAborted);
			BUMP_MIB(&sctps->sctps_mib, sctpTimRetransDrop);
			sctp_assoc_event(sctp, SCTP_COMM_LOST, 0, NULL);
			sctp_clean_death(sctp, sctp->sctp_client_errno ?
			    sctp->sctp_client_errno : ETIMEDOUT);
			return;
		}
	}

	if (fp->strikes >= fp->max_retr) {
		if (sctp_faddr_dead(sctp, fp, SCTP_FADDRS_DOWN) == -1) {
			return;
		}
	}

	switch (sctp->sctp_state) {
	case SCTPS_SHUTDOWN_RECEIVED:
		(void) sctp_shutdown_received(sctp, NULL, B_FALSE, B_TRUE,
		    NULL);

		/* FALLTHRU */
	case SCTPS_ESTABLISHED:
	case SCTPS_SHUTDOWN_PENDING:
		if (sctp->sctp_xmit_head == NULL &&
		    sctp->sctp_xmit_unsent == NULL) {
			/* Nothing to retransmit */
			if (sctp->sctp_state == SCTPS_SHUTDOWN_PENDING) {
				sctp_send_shutdown(sctp, 1);
			}
			return;
		}

		BUMP_MIB(&sctps->sctps_mib, sctpTimRetrans);

		sctp_rexmit(sctp, fp);
		/*
		 * sctp_rexmit() will increase the strikes and restart the
		 * timer, so return here.
		 */
		return;
	case SCTPS_COOKIE_WAIT:
		BUMP_LOCAL(sctp->sctp_T1expire);
rxmit_init:
		/* retransmit init */
		/*
		 * We don't take the conn hash lock here since the source
		 * address list won't be modified (it would have been done
		 * the first time around).
		 */
		mp = sctp_init_mp(sctp);
		if (mp != NULL) {
			BUMP_MIB(&sctps->sctps_mib, sctpTimRetrans);
			sctp_add_sendq(sctp, mp);
		}
		rto_max = sctp->sctp_init_rto_max;
		break;
	case SCTPS_COOKIE_ECHOED: {
		ipha_t *iph;

		BUMP_LOCAL(sctp->sctp_T1expire);
		if (sctp->sctp_cookie_mp == NULL) {
			sctp->sctp_state = SCTPS_COOKIE_WAIT;
			goto rxmit_init;
		}
		mp = dupmsg(sctp->sctp_cookie_mp);
		if (mp == NULL)
			break;
		iph = (ipha_t *)mp->b_rptr;
		/* Reset the IP ident. */
		if (IPH_HDR_VERSION(iph) == IPV4_VERSION)
			iph->ipha_ident = 0;
		sctp_add_sendq(sctp, mp);
		BUMP_MIB(&sctps->sctps_mib, sctpTimRetrans);
		rto_max = sctp->sctp_init_rto_max;
		break;
	}
	case SCTPS_SHUTDOWN_SENT:
		BUMP_LOCAL(sctp->sctp_T2expire);
		sctp_send_shutdown(sctp, 1);
		BUMP_MIB(&sctps->sctps_mib, sctpTimRetrans);
		break;
	case SCTPS_SHUTDOWN_ACK_SENT:
		/* We shouldn't have any more outstanding data */
		ASSERT(sctp->sctp_xmit_head == NULL);
		ASSERT(sctp->sctp_xmit_unsent == NULL);

		BUMP_LOCAL(sctp->sctp_T2expire);
		(void) sctp_shutdown_received(sctp, NULL, B_FALSE, B_TRUE,
		    NULL);
		BUMP_MIB(&sctps->sctps_mib, sctpTimRetrans);
		break;
	default:
		ASSERT(0);
		break;
	}

	fp->strikes++;
	sctp->sctp_strikes++;
	SCTP_CALC_RXT(fp, rto_max);

	SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->rto);
}

/*
 * RTO calculation. timesent and now are both in ms.
 */
void
sctp_update_rtt(sctp_t *sctp, sctp_faddr_t *fp, clock_t delta)
{
	int rtt;

	/* Calculate the RTT in ms */
	rtt = (int)delta;
	rtt = rtt > 0 ? rtt : 1;

	dprint(5, ("sctp_update_rtt: fp = %p, rtt = %d\n", (void *)fp, rtt));

	/* Is this the first RTT measurement? */
	if (fp->srtt == -1) {
		fp->srtt = rtt;
		fp->rttvar = rtt / 2;
		fp->rto = 3 * rtt; /* == rtt + 4 * rttvar ( == rtt / 2) */
	} else {
		int abs;
		/*
		 * Versions of the RTO equations that use fixed-point math.
		 * alpha and beta are NOT tunable in this implementation,
		 * and so are hard-coded in. alpha = 1/8, beta = 1/4.
		 */
		abs = fp->srtt - rtt;
		abs = abs >= 0 ? abs : -abs;
		fp->rttvar = (3 * fp->rttvar + abs) >> 2;
		fp->rttvar = fp->rttvar != 0 ? fp->rttvar : 1;

		fp->srtt = (7 * fp->srtt + rtt) >> 3;
		fp->rto = fp->srtt + 4 * fp->rttvar;
	}

	dprint(5, ("sctp_update_rtt: srtt = %d, rttvar = %d, rto = %d\n",
	    fp->srtt, fp->rttvar, fp->rto));

	/* Bound the RTO by configured min and max values */
	if (fp->rto < sctp->sctp_rto_min) {
		fp->rto = sctp->sctp_rto_min;
	}
	if (fp->rto > sctp->sctp_rto_max) {
		fp->rto = sctp->sctp_rto_max;
	}

	fp->rtt_updates++;
}

void
sctp_free_faddr_timers(sctp_t *sctp)
{
	sctp_faddr_t *fp;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
		if (fp->timer_mp != NULL) {
			sctp_timer_free(fp->timer_mp);
			fp->timer_mp = NULL;
			fp->timer_running = 0;
		}
		if (fp->rc_timer_mp != NULL) {
			sctp_timer_free(fp->rc_timer_mp);
			fp->rc_timer_mp = NULL;
			fp->rc_timer_running = 0;
		}
	}
}

void
sctp_stop_faddr_timers(sctp_t *sctp)
{
	sctp_faddr_t *fp;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
		SCTP_FADDR_TIMER_STOP(fp);
		SCTP_FADDR_RC_TIMER_STOP(fp);
	}
}

void
sctp_process_timer(sctp_t *sctp)
{
	mblk_t *mp;

	ASSERT(sctp->sctp_running);
	ASSERT(MUTEX_HELD(&sctp->sctp_lock));
	while ((mp = sctp->sctp_timer_mp) != NULL) {
		ASSERT(DB_TYPE(mp) == M_PCSIG);
		/*
		 * Since the timer mblk can be freed in sctp_timer_call(),
		 * we need to grab the b_cont before that.
		 */
		sctp->sctp_timer_mp = mp->b_cont;
		mp->b_cont = NULL;
		/*
		 * We have a reference on the sctp, the lock must be
		 * dropped to avoid deadlocks with functions potentially
		 * called in this context which in turn call untimeout().
		 */
		mutex_exit(&sctp->sctp_lock);
		sctp_timer_call(sctp, mp);
		mutex_enter(&sctp->sctp_lock);
	}
	SCTP_REFRELE(sctp);
}
