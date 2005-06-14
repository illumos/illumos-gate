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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ISSUES
 */

#include <sys/scsi/scsi.h>
#include <sys/note.h>
#include <sys/scsi/adapters/fasreg.h>
#include <sys/scsi/adapters/fasvar.h>
#include <sys/scsi/adapters/fascmd.h>

#include <sys/vtrace.h>

#ifdef	FASDEBUG
extern int  fasdebug;
extern int  fasdebug_instance; /* debug all instances */
#endif	/* FASDEBUG */

void fas_complete_arq_pkt(struct scsi_pkt *pkt);
void fas_call_pkt_comp(register struct fas *fas,
    register struct fas_cmd *sp);
void fas_empty_callbackQ(struct fas *fas);
int fas_init_callbacks(struct fas *fas);
void fas_destroy_callbacks(struct fas *fas);
void fas_printf(struct fas *fas, const char *fmt, ...);

int
fas_init_callbacks(struct fas *fas)
{
	mutex_init(&fas->f_c_mutex, NULL, MUTEX_DRIVER, fas->f_iblock);

	return (0);
}

void
fas_destroy_callbacks(struct fas *fas)
{
	mutex_destroy(&fas->f_c_mutex);
}

void
fas_empty_callbackQ(struct fas *fas)
{
	register struct fas_cmd *sp;

	TRACE_0(TR_FAC_SCSI, TR_FAS_EMPTY_CALLBACKQ_START,
	    "fas_empty_callbackQ_start");

	mutex_enter(&fas->f_c_mutex);

	/*
	 * don't recurse into calling back: the target driver
	 * may call scsi_transport() again which may call
	 * fas_empty_callbackQ again
	 */
	if (fas->f_c_in_callback) {
		goto done;
	}
	fas->f_c_in_callback = 1;

	while (fas->f_c_qf) {
		register struct fas_cmd *qf = fas->f_c_qf;

		fas->f_c_qf = fas->f_c_qb = NULL;
		mutex_exit(&fas->f_c_mutex);

		while (qf) {
			sp = qf;
			qf =   sp->cmd_forw;
			(*sp->cmd_pkt->pkt_comp)(sp->cmd_pkt);
		}

		mutex_enter(&fas->f_c_mutex);
	}

	fas->f_c_in_callback = 0;
done:
	mutex_exit(&fas->f_c_mutex);

	TRACE_0(TR_FAC_SCSI, TR_FAS_EMPTY_CALLBACKQ_END,
	    "fas_empty_callbackQ_end");
}


/*
 * fas_call_pkt_comp does sanity checking to ensure that we don't
 * call completion twice on the same packet or a packet that has been freed.
 * if there is a completion function specified, the packet is queued
 * up and it is left to the fas_callback thread to empty the queue at
 * a lower priority; note that there is one callback queue per fas
 *
 * we use a separate thread for calling back into the target driver
 * this thread unqueues packets from the callback queue
 */
void
fas_call_pkt_comp(register struct fas *fas, register struct fas_cmd *sp)
{
	TRACE_0(TR_FAC_SCSI, TR_FAS_CALL_PKT_COMP_START,
	    "fas_call_pkt_comp_start");

	ASSERT(sp != 0);
	ASSERT((sp->cmd_flags & CFLAG_COMPLETED) == 0);
	ASSERT((sp->cmd_flags & CFLAG_FREE) == 0);
	ASSERT(sp->cmd_flags & CFLAG_FINISHED);
	ASSERT(fas->f_ncmds >= fas->f_ndisc);
	ASSERT((sp->cmd_flags & CFLAG_CMDDISC) == 0);
	ASSERT(sp != fas->f_current_sp);
	ASSERT(sp != fas->f_active[sp->cmd_slot]->f_slot[sp->cmd_tag[1]]);

	sp->cmd_flags &= ~CFLAG_IN_TRANSPORT;
	sp->cmd_flags |= CFLAG_COMPLETED;
	sp->cmd_qfull_retries = 0;

	/*
	 * if this was an auto request sense, complete immediately to free
	 * the arq pkt
	 */
	if (sp->cmd_pkt->pkt_comp && !(sp->cmd_flags & CFLAG_CMDARQ)) {

		if (sp->cmd_pkt->pkt_reason != CMD_CMPLT) {
			IPRINTF6("completion for %d.%d, sp=0x%p, "
			    "reason=%s, stats=%x, state=%x\n",
				Tgt(sp), Lun(sp), (void *)sp,
				scsi_rname(sp->cmd_pkt->pkt_reason),
				sp->cmd_pkt->pkt_statistics,
				sp->cmd_pkt->pkt_state);
		} else {
			EPRINTF2("completion queued for %d.%dn",
				Tgt(sp), Lun(sp));
		}

		/*
		 * append the packet or start a new queue
		 */
		mutex_enter(&fas->f_c_mutex);
		if (fas->f_c_qf) {
			/*
			 * add to tail
			 */
			register struct fas_cmd *dp = fas->f_c_qb;
			ASSERT(dp != NULL);
			fas->f_c_qb =	sp;
			sp->cmd_forw = NULL;
			dp->cmd_forw = sp;
		} else {
			/*
			 * start new queue
			 */
			fas->f_c_qf = fas->f_c_qb = sp;
			sp->cmd_forw = NULL;
		}
		mutex_exit(&fas->f_c_mutex);

	} else if ((sp->cmd_flags & CFLAG_CMDARQ) && sp->cmd_pkt->pkt_comp) {
		/*
		 * pkt_comp may be NULL when we are aborting/resetting but then
		 * the callback will be redone later
		 */
		fas_complete_arq_pkt(sp->cmd_pkt);

	} else	{
		EPRINTF2("No completion routine for 0x%p reason %x\n",
		    (void *)sp, sp->cmd_pkt->pkt_reason);
	}
	TRACE_0(TR_FAC_SCSI, TR_FAS_CALL_PKT_COMP_END,
	    "fas_call_pkt_comp_end");
}
