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

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/note.h>

#include "ghd.h"



/*ARGSUSED*/
gtgt_t *
ghd_target_init(dev_info_t	*hba_dip,
		dev_info_t	*tgt_dip,
		ccc_t		*cccp,
		size_t		 tgt_private_size,
		void		*hba_private,
		ushort_t	 target,
		uchar_t		 lun)
{
	_NOTE(ARGUNUSED(hba_dip))
	gtgt_t	*gtgtp;
	size_t	 size = sizeof (*gtgtp) + tgt_private_size;
	gdev_t	*gdevp;
	ulong_t	 maxactive;

	gtgtp = kmem_zalloc(size, KM_SLEEP);

	/*
	 * initialize the per instance structure
	 */

	gtgtp->gt_tgt_private = (void *)(gtgtp + 1);
	gtgtp->gt_size = size;
	gtgtp->gt_hba_private = hba_private;
	gtgtp->gt_target = target;
	gtgtp->gt_lun = lun;
	gtgtp->gt_ccc = cccp;

	/*
	 * set the queue's maxactive to 1 if
	 * property not specified on target or hba devinfo node
	 */
	maxactive = ddi_getprop(DDI_DEV_T_ANY, tgt_dip, 0, "ghd-maxactive", 1);
	gtgtp->gt_maxactive = maxactive;

	/* initialize the linked list pointers */
	GTGT_INIT(gtgtp);

	/*
	 * grab both mutexes so the queue structures
	 * stay stable while adding this instance to the linked lists
	 */
	mutex_enter(&cccp->ccc_hba_mutex);
	mutex_enter(&cccp->ccc_waitq_mutex);

	/*
	 * Search the HBA's linked list of device structures.
	 *
	 * If this device is already attached then link this instance
	 * to the existing per-device-structure on the ccc_devs list.
	 *
	 */
	gdevp = CCCP2GDEVP(cccp);
	while (gdevp != NULL) {
		if (gdevp->gd_target == target && gdevp->gd_lun == lun) {
			GDBG_WAITQ(("ghd_target_init(%d,%d) found gdevp 0x%p"
			    " gtgtp 0x%p max %lu\n", target, lun,
			    (void *)gdevp, (void *)gtgtp, maxactive));

			goto foundit;
		}
		gdevp = GDEV_NEXTP(gdevp);
	}

	/*
	 * Not found. This is the first instance for this device.
	 */


	/* allocate the per-device-structure */

	gdevp = kmem_zalloc(sizeof (*gdevp), KM_SLEEP);
	gdevp->gd_target = target;
	gdevp->gd_lun = lun;

	/*
	 * link this second level queue to the HBA's first
	 * level queue
	 */
	GDEV_QATTACH(gdevp, cccp, maxactive);

	GDBG_WAITQ(("ghd_target_init(%d,%d) new gdevp 0x%p gtgtp 0x%p"
	    " max %lu\n", target, lun, (void *)gdevp, (void *)gtgtp,
	    maxactive));

foundit:

	/* save the ptr to the per device structure */
	gtgtp->gt_gdevp = gdevp;

	/* Add the per instance structure to the per device list  */
	GTGT_ATTACH(gtgtp, gdevp);

	ghd_waitq_process_and_mutex_exit(cccp);

	return (gtgtp);
}

/*ARGSUSED*/
void
ghd_target_free(dev_info_t	*hba_dip,
		dev_info_t	*tgt_dip,
		ccc_t		*cccp,
		gtgt_t		*gtgtp)
{
	_NOTE(ARGUNUSED(hba_dip,tgt_dip))

	gdev_t	*gdevp = gtgtp->gt_gdevp;

	GDBG_WAITQ(("ghd_target_free(%d,%d) gdevp-0x%p gtgtp 0x%p\n",
	    gtgtp->gt_target, gtgtp->gt_lun, (void *)gdevp, (void *)gtgtp));

	/*
	 * grab both mutexes so the queue structures
	 * stay stable while deleting this instance
	 */
	mutex_enter(&cccp->ccc_hba_mutex);
	mutex_enter(&cccp->ccc_waitq_mutex);

	ASSERT(gdevp->gd_ninstances > 0);

	/*
	 * remove this per-instance structure from the device list and
	 * free the memory
	 */
	GTGT_DEATTACH(gtgtp, gdevp);
	kmem_free((caddr_t)gtgtp, gtgtp->gt_size);

	if (gdevp->gd_ninstances == 1) {
		GDBG_WAITQ(("ghd_target_free: N=1 gdevp 0x%p\n",
		    (void *)gdevp));
		/*
		 * If there's now just one instance left attached to this
		 * device then reset the queue's max active value
		 * from that instance's saved value.
		 */
		gtgtp = GDEVP2GTGTP(gdevp);
		GDEV_MAXACTIVE(gdevp) = gtgtp->gt_maxactive;

	} else if (gdevp->gd_ninstances == 0) {
		/* else no instances left */
		GDBG_WAITQ(("ghd_target_free: N=0 gdevp 0x%p\n",
		    (void *)gdevp));

		/* detach this per-dev-structure from the HBA's dev list */
		GDEV_QDETACH(gdevp, cccp);
		kmem_free(gdevp, sizeof (*gdevp));

	}
#if defined(GHD_DEBUG) || defined(__lint)
	else {
		/* leave maxactive set to 1 */
		GDBG_WAITQ(("ghd_target_free: N>1 gdevp 0x%p\n",
		    (void *)gdevp));
	}
#endif

	ghd_waitq_process_and_mutex_exit(cccp);
}

void
ghd_waitq_shuffle_up(ccc_t *cccp, gdev_t *gdevp)
{
	gcmd_t	*gcmdp;

	ASSERT(mutex_owned(&cccp->ccc_waitq_mutex));

	GDBG_WAITQ(("ghd_waitq_shuffle_up: cccp 0x%p gdevp 0x%p N %ld "
	    "max %ld\n", (void *)cccp, (void *)gdevp, GDEV_NACTIVE(gdevp),
	    GDEV_MAXACTIVE(gdevp)));
	for (;;) {
		/*
		 * Now check the device wait queue throttle to see if I can
		 * shuffle up a request to the HBA wait queue.
		 */
		if (GDEV_NACTIVE(gdevp) >= GDEV_MAXACTIVE(gdevp)) {
			GDBG_WAITQ(("ghd_waitq_shuffle_up: N>MAX gdevp 0x%p\n",
			    (void *)gdevp));
			return;
		}

		/*
		 * single thread requests while multiple instances
		 * because the different target drives might have
		 * conflicting maxactive throttles.
		 */
		if (gdevp->gd_ninstances > 1 && GDEV_NACTIVE(gdevp) > 0) {
			GDBG_WAITQ(("ghd_waitq_shuffle_up: multi gdevp 0x%p\n",
			    (void *)gdevp));
			return;
		}

		/*
		 * promote the topmost request from the device queue to
		 * the HBA queue.
		 */
		if ((gcmdp = L2_remove_head(&GDEV_QHEAD(gdevp))) == NULL) {
			/* the device is empty so we're done */
			GDBG_WAITQ(("ghd_waitq_shuffle_up: MT gdevp 0x%p\n",
			    (void *)gdevp));
			return;
		}
		L2_add(&GHBA_QHEAD(cccp), &gcmdp->cmd_q, gcmdp);
		GDEV_NACTIVE(gdevp)++;
		gcmdp->cmd_waitq_level++;
		GDBG_WAITQ(("ghd_waitq_shuffle_up: gdevp 0x%p gcmdp 0x%p\n",
		    (void *)gdevp, (void *)gcmdp));
	}
}


void
ghd_waitq_delete(ccc_t *cccp, gcmd_t *gcmdp)
{
	gtgt_t	*gtgtp = GCMDP2GTGTP(gcmdp);
	gdev_t	*gdevp = gtgtp->gt_gdevp;
#if defined(GHD_DEBUG) || defined(__lint)
	Q_t	*qp = &gdevp->gd_waitq;
#endif

	ASSERT(mutex_owned(&cccp->ccc_hba_mutex));
	mutex_enter(&cccp->ccc_waitq_mutex);

	/*
	 * Adjust all queue counters. If this request is being aborted
	 * it might only have made it to the target queue. Otherwise,
	 * both the target and hba queue have to be adjusted when a
	 * request is completed normally. The cmd_waitq_level value
	 * indicates which queue counters need to be adjusted. It's
	 * incremented as the request progresses up the queues.
	 */
	switch (gcmdp->cmd_waitq_level) {
	case 0:
		break;
	case 1:
		/*
		 * If this is an early-timeout, or early-abort, the request
		 * is still linked onto a waitq. Remove it now. If it's
		 * an active request and no longer on the waitq then calling
		 * L2_delete a second time does no harm.
		 */
		L2_delete(&gcmdp->cmd_q);
		break;

	case 2:
		L2_delete(&gcmdp->cmd_q);
#if defined(GHD_DEBUG) || defined(__lint)
		if (GDEV_NACTIVE(gdevp) == 0)
			debug_enter("\n\nGHD WAITQ DELETE\n\n");
#endif
		GDEV_NACTIVE(gdevp)--;
		break;

	case 3:
		/* it's an active or completed command */
#if defined(GHD_DEBUG) || defined(__lint)
		if (GDEV_NACTIVE(gdevp) == 0 || GHBA_NACTIVE(cccp) == 0)
			debug_enter("\n\nGHD WAITQ DELETE\n\n");
#endif
		GDEV_NACTIVE(gdevp)--;
		GHBA_NACTIVE(cccp)--;
		break;

	default:
		/* this shouldn't happen */
#if defined(GHD_DEBUG) || defined(__lint)
		debug_enter("\n\nGHD WAITQ LEVEL > 3\n\n");
#endif
		break;
	}

	GDBG_WAITQ(("ghd_waitq_delete: gcmdp 0x%p qp 0x%p level %ld\n",
	    (void *)gcmdp, (void *)qp, gcmdp->cmd_waitq_level));


	/*
	 * There's probably now more room in the HBA queue. Move
	 * up as many requests as possible.
	 */
	ghd_waitq_shuffle_up(cccp, gdevp);

	mutex_exit(&cccp->ccc_waitq_mutex);
}


int
ghd_waitq_process_and_mutex_hold(ccc_t *cccp)
{
	gcmd_t	*gcmdp;
	int	 rc = FALSE;

	ASSERT(mutex_owned(&cccp->ccc_hba_mutex));
	ASSERT(mutex_owned(&cccp->ccc_waitq_mutex));

	for (;;) {
		if (L2_EMPTY(&GHBA_QHEAD(cccp))) {
			/* return if the list is empty */
			GDBG_WAITQ(("ghd_waitq_proc: MT cccp 0x%p qp 0x%p\n",
			    (void *)cccp, (void *)&cccp->ccc_waitq));
			break;
		}
		if (GHBA_NACTIVE(cccp) >= GHBA_MAXACTIVE(cccp)) {
			/* return if the HBA is too active */
			GDBG_WAITQ(("ghd_waitq_proc: N>M cccp 0x%p qp 0x%p"
			    " N %ld max %ld\n", (void *)cccp,
			    (void *)&cccp->ccc_waitq,
			    GHBA_NACTIVE(cccp),
			    GHBA_MAXACTIVE(cccp)));
			break;
		}

		/*
		 * bail out if the wait queue has been
		 * "held" by the HBA driver
		 */
		if (cccp->ccc_waitq_held) {
			GDBG_WAITQ(("ghd_waitq_proc: held"));
			return (rc);
		}

		if (cccp->ccc_waitq_frozen) {

			clock_t lbolt, delay_in_hz, time_to_wait;

			delay_in_hz =
			    drv_usectohz(cccp->ccc_waitq_freezedelay * 1000);

			lbolt = ddi_get_lbolt();
			time_to_wait = delay_in_hz -
			    (lbolt - cccp->ccc_waitq_freezetime);

			if (time_to_wait > 0) {
				/*
				 * stay frozen; we'll be called again
				 * by ghd_timeout_softintr()
				 */
				GDBG_WAITQ(("ghd_waitq_proc: frozen"));
				return (rc);
			} else {
				/* unfreeze and continue */
				GDBG_WAITQ(("ghd_waitq_proc: unfreezing"));
				cccp->ccc_waitq_freezetime = 0;
				cccp->ccc_waitq_freezedelay = 0;
				cccp->ccc_waitq_frozen = 0;
			}
		}

		gcmdp = (gcmd_t *)L2_remove_head(&GHBA_QHEAD(cccp));
		GHBA_NACTIVE(cccp)++;
		gcmdp->cmd_waitq_level++;
		mutex_exit(&cccp->ccc_waitq_mutex);

		/*
		 * Start up the next I/O request
		 */
		ASSERT(gcmdp != NULL);
		gcmdp->cmd_state = GCMD_STATE_ACTIVE;
		if (!(*cccp->ccc_hba_start)(cccp->ccc_hba_handle, gcmdp)) {
			/* if the HBA rejected the request, requeue it */
			gcmdp->cmd_state = GCMD_STATE_WAITQ;
			mutex_enter(&cccp->ccc_waitq_mutex);
			GHBA_NACTIVE(cccp)--;
			gcmdp->cmd_waitq_level--;
			L2_add_head(&GHBA_QHEAD(cccp), &gcmdp->cmd_q, gcmdp);
			GDBG_WAITQ(("ghd_waitq_proc: busy cccp 0x%p gcmdp 0x%p"
			    " handle 0x%p\n", (void *)cccp, (void *)gcmdp,
			    cccp->ccc_hba_handle));
			break;
		}
		rc = TRUE;
		mutex_enter(&cccp->ccc_waitq_mutex);
		GDBG_WAITQ(("ghd_waitq_proc: ++ cccp 0x%p gcmdp 0x%p N %ld\n",
		    (void *)cccp, (void *)gcmdp, GHBA_NACTIVE(cccp)));
	}
	ASSERT(mutex_owned(&cccp->ccc_hba_mutex));
	ASSERT(mutex_owned(&cccp->ccc_waitq_mutex));
	return (rc);
}

void
ghd_waitq_process_and_mutex_exit(ccc_t *cccp)
{
	ASSERT(mutex_owned(&cccp->ccc_hba_mutex));
	ASSERT(mutex_owned(&cccp->ccc_waitq_mutex));

	GDBG_WAITQ(("ghd_waitq_process_and_mutex_exit: cccp 0x%p\n",
	    (void *)cccp));

	(void) ghd_waitq_process_and_mutex_hold(cccp);

	/*
	 * Release the mutexes in the opposite order that they
	 * were acquired to prevent requests queued by
	 * ghd_transport() from getting hung up in the wait queue.
	 */
	mutex_exit(&cccp->ccc_hba_mutex);
	mutex_exit(&cccp->ccc_waitq_mutex);
}
