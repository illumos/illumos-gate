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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Main Transport Routine for SCSA
 */
#include <sys/scsi/scsi.h>
#include <sys/thread.h>

#define	A_TO_TRAN(ap)	((ap)->a_hba_tran)
#define	P_TO_TRAN(pkt)	((pkt)->pkt_address.a_hba_tran)
#define	P_TO_ADDR(pkt)	(&((pkt)->pkt_address))

#ifdef DEBUG
#define	SCSI_POLL_STAT
#endif

#ifdef SCSI_POLL_STAT
int	scsi_poll_user;
int	scsi_poll_intr;
#endif

extern	kmutex_t	scsi_flag_nointr_mutex;
extern	kcondvar_t	scsi_flag_nointr_cv;

/*
 * we used to set the callback_done value to NULL after the callback
 * but this interfered with esp/fas drivers that also set the callback
 * to NULL to prevent callbacks during error recovery
 * to prevent confusion, create a truly unique value
 */
static int scsi_callback_done;
#define	CALLBACK_DONE ((void (*)(struct scsi_pkt *))(&scsi_callback_done))

static void
scsi_flag_nointr_comp(struct scsi_pkt *pkt)
{
	mutex_enter(&scsi_flag_nointr_mutex);
	pkt->pkt_comp = CALLBACK_DONE;
	/*
	 * We need cv_broadcast, because there can be more
	 * than one thread sleeping on the cv. We
	 * will wake all of them. The correct  one will
	 * continue and the rest will again go to sleep.
	 */
	cv_broadcast(&scsi_flag_nointr_cv);
	mutex_exit(&scsi_flag_nointr_mutex);
}

static void
scsi_consistent_comp(struct scsi_pkt *pkt)
{
	struct scsi_pkt_cache_wrapper *pcw =
		(struct scsi_pkt_cache_wrapper *)pkt;

	pkt->pkt_comp = pcw->pcw_orig_comp;
	scsi_sync_pkt(pkt);
	(*pkt->pkt_comp)(pkt);
}

/*
 * A packet can have FLAG_NOINTR set because of target driver or
 * scsi_poll(). If FLAG_NOINTR is set and we are in user context,
 * we can avoid busy waiting in HBA by replacing the callback
 * function with our own function and resetting FLAG_NOINTR. We
 * can't do this in interrupt context because cv_wait will
 * sleep with CPU priority raised high and in case of some failure,
 * the CPU will be stuck in high priority.
 */

int
scsi_transport(struct scsi_pkt *pkt)
{
	struct scsi_address	*ap = P_TO_ADDR(pkt);
	extern int do_polled_io;
	int rval = TRAN_ACCEPT;

	/* determine if we need to sync the data on the HBA's behalf */
	if ((pkt->pkt_dma_flags & DDI_DMA_CONSISTENT) &&
	    ((pkt->pkt_comp) != NULL) &&
	    ((P_TO_TRAN(pkt)->tran_setup_pkt) != NULL)) {
		struct scsi_pkt_cache_wrapper *pcw =
			(struct scsi_pkt_cache_wrapper *)pkt;

		_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", \
			scsi_pkt_cache_wrapper::pcw_orig_comp));  

		pcw->pcw_orig_comp = pkt->pkt_comp;
		pkt->pkt_comp = scsi_consistent_comp;
	}
	/*
	 * Check if we are required to do polled I/O. We can
	 * get scsi_pkts that don't have the FLAG_NOINTR bit
	 * set in the pkt_flags. When do_polled_io is set
	 * we will probably be at a high IPL and not get any
	 * command completion interrupts. We force polled I/Os
	 * for such packets and do a callback of the completion
	 * routine ourselves.
	 */
	if (!do_polled_io && ((pkt->pkt_flags & FLAG_NOINTR) == 0)) {
		return (*A_TO_TRAN(ap)->tran_start)(ap, pkt);
	} else if ((curthread->t_flag & T_INTR_THREAD) || do_polled_io) {
#ifdef SCSI_POLL_STAT
		mutex_enter(&scsi_flag_nointr_mutex);
		scsi_poll_intr++;
		mutex_exit(&scsi_flag_nointr_mutex);
#endif
		/*
		 * If its an interrupt thread or we already have the
		 * the FLAG_NOINTR flag set, we go ahead and call the
		 * the hba's start routine directly. We force polling
		 * only if we have do_polled_io set and FLAG_NOINTR
		 * not set.
		 */
		if (!do_polled_io || (pkt->pkt_flags & FLAG_NOINTR)) {
			return ((*A_TO_TRAN(ap)->tran_start)(ap, pkt));
		} else {
			uint_t		savef;
			void		(*savec)();
			/*
			 * save the completion routine and pkt_flags
			 */
			savef = pkt->pkt_flags;
			savec = pkt->pkt_comp;
			pkt->pkt_flags |= FLAG_NOINTR;
			pkt->pkt_comp = 0;

			rval = (*A_TO_TRAN(ap)->tran_start)(ap, pkt);

			/* only continue of transport accepted request */
			if (rval == TRAN_ACCEPT) {
				/*
				 * Restore the pkt_completion routine
				 * and pkt flags and call the completion
				 * routine.
				 */
				pkt->pkt_comp = savec;
				pkt->pkt_flags = savef;

				if (pkt->pkt_comp != NULL) {
					(*pkt->pkt_comp)(pkt);
				}

				return (rval);
			}

			/*
			 * rval was not TRAN_ACCEPT -- don't want command
			 * to be retried
			 */
			return (TRAN_FATAL_ERROR);
		}
	} else {
		uint_t	savef;
		void	(*savec)();
		int	status;

#ifdef SCSI_POLL_STAT
		mutex_enter(&scsi_flag_nointr_mutex);
		scsi_poll_user++;
		mutex_exit(&scsi_flag_nointr_mutex);
#endif
		savef = pkt->pkt_flags;
		savec = pkt->pkt_comp;

		pkt->pkt_comp = scsi_flag_nointr_comp;
		pkt->pkt_flags &= ~FLAG_NOINTR;
		pkt->pkt_flags |= FLAG_IMMEDIATE_CB;

		if ((status = (*A_TO_TRAN(ap)->tran_start)(ap, pkt)) ==
			TRAN_ACCEPT) {
			mutex_enter(&scsi_flag_nointr_mutex);
			while (pkt->pkt_comp != CALLBACK_DONE) {
				cv_wait(&scsi_flag_nointr_cv,
					&scsi_flag_nointr_mutex);
			}
			mutex_exit(&scsi_flag_nointr_mutex);
		}

		pkt->pkt_flags = savef;
		pkt->pkt_comp = savec;
		return (status);
	}
}
