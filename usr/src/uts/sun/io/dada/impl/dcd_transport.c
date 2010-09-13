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
 * Copyright (c) 1996,1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Main Transport Routine for DADA.
 *
 */

#include <sys/dada/dada.h>
#include <sys/thread.h>


#define	A_TO_TRAN(ap)	((ap)->a_hba_tran)
#define	P_TO_TRAN(pkt) 	((pkt)->pkt_address.a_hba_tran)
#define	P_TO_ADDR(pkt)	(&((pkt)->pkt_address))


extern	kmutex_t	dcd_flag_nointr_mutex;
extern	kcondvar_t	dcd_flag_nointr_cv;

static void
dcd_flag_nointr_comp(struct dcd_pkt *pkt)
{

	mutex_enter(&dcd_flag_nointr_mutex);

	pkt->pkt_comp = NULL;

	/*
	 * We need cv_broadcast, because there can be more than
	 * one thread sleeping on the cv. We will wake all of them.
	 * The correct one will continue and the reset will again go to
	 * sleep.
	 */
	cv_broadcast(&dcd_flag_nointr_cv);
	mutex_exit(&dcd_flag_nointr_mutex);
}


int
dcd_transport(struct dcd_pkt *pkt)
{

	struct dcd_address *ap = P_TO_ADDR(pkt);
	extern int do_polled_io;
	int rval;

	/*
	 * Check if we are required to do polled I/O. We can
	 * get dcd_pkts that don't have the FLAG_NOINTR bit
	 * set in the pkt_flags. When do_polled_io is set
	 * we will probably be at a high IPL and not get any
	 * command completion interrupts. We force polled I/Os
	 * for such packets and do a callback of the completion
	 * routine ourselves.
	 */
	if (!do_polled_io && ((pkt->pkt_flags & FLAG_NOINTR) == 0)) {
		return ((*A_TO_TRAN(ap)->tran_start)(ap, pkt));
	} else if ((curthread->t_flag & T_INTR_THREAD) || (do_polled_io) ||
			(pkt->pkt_flags & FLAG_FORCENOINTR)) {

		if (pkt->pkt_flags & FLAG_FORCENOINTR) {
			/*
			 * FLAG_FORCENOINTR means we do not want to rely on
			 * device interrupts. Set the FLAG_NOINTR
			 * so the command gets completed in polled mode.
			 */
			pkt->pkt_flags &= ~FLAG_FORCENOINTR;
			pkt->pkt_flags |= FLAG_NOINTR;
		}

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
			uint_t	savef;
			void	(*savec)();
			/*
			 * save the completion routine and pkt_flags
			 */
			savef = pkt->pkt_flags;
			savec = pkt->pkt_comp;
			pkt->pkt_flags |= FLAG_NOINTR;
			pkt->pkt_comp = 0;

			rval = (*A_TO_TRAN(ap)->tran_start)(ap, pkt);

			/*
			 * Restore the pkt_completion routine
			 * and pkt flags and call the completion
			 * routine.
			 */
			pkt->pkt_comp = savec;
			pkt->pkt_flags = savef;
			(*pkt->pkt_comp)(pkt);
			return (rval);
		}
	} else {
		uint_t	savef;
		void	(*savec)();
		int	status;

		savef = pkt->pkt_flags;
		savec = pkt->pkt_comp;

		pkt->pkt_comp = dcd_flag_nointr_comp;
		pkt->pkt_flags &= ~FLAG_NOINTR;
		pkt->pkt_flags |= FLAG_IMMEDIATE_CB;

		if ((status = (*A_TO_TRAN(ap)->tran_start)(ap, pkt)) ==
			TRAN_ACCEPT) {
			mutex_enter(& dcd_flag_nointr_mutex);
			while (pkt->pkt_comp != NULL) {
				cv_wait(&dcd_flag_nointr_cv,
					&dcd_flag_nointr_mutex);
			}
			mutex_exit(&dcd_flag_nointr_mutex);
		}
		pkt->pkt_flags = savef;
		pkt->pkt_comp = savec;
		return (status);
	}
}
