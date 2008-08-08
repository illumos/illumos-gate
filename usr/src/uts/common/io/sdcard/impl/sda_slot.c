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

/*
 * SD card slot support.
 *
 * NB that this file contains a fair bit of non-DDI compliant code.
 * But writing a nexus driver would be impossible to do with only DDI
 * compliant interfaces.
 */

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/callb.h>
#include <sys/sysmacros.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/varargs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sdcard/sda_impl.h>


/*
 * Prototypes.
 */

static void sda_slot_insert(void *);
static sda_err_t sda_slot_check_response(sda_cmd_t *);
static void sda_slot_handle_detect(sda_slot_t *);
static void sda_slot_handle_transfer(sda_slot_t *, sda_err_t);
static void sda_slot_handle_fault(sda_slot_t *, sda_fault_t);
static void sda_slot_abort(sda_slot_t *, sda_err_t);
static void sda_slot_halt(sda_slot_t *);
static void sda_slot_thread(void *);
static void sda_slot_vprintf(sda_slot_t *, int, const char *, va_list);

/*
 * Static Variables.
 */

static struct {
	sda_fault_t	fault;
	const char	*msg;
} sda_slot_faults[] = {
	{ SDA_FAULT_TIMEOUT,	"Data transfer timed out" },
	{ SDA_FAULT_ACMD12,	"Auto CMD12 failure" },
	{ SDA_FAULT_CRC7,	"CRC7 failure on CMD/DAT line" },
	{ SDA_FAULT_PROTO,	"SD/MMC protocol signaling error" },
	{ SDA_FAULT_INIT,	"Card initialization failure" },
	{ SDA_FAULT_HOST,	"Internal host or slot failure" },
	{ SDA_FAULT_CURRENT,	"Current overlimit detected" },
	{ SDA_FAULT_RESET,	"Failed to reset slot" },
	{ SDA_FAULT_NONE,	NULL },	/* sentinel, must be last! */
};

/*
 * Internal implementation.
 */

/*
 * These allow for recursive entry.  This is necessary to facilitate
 * simpler locking with things like the fault handler, where a caller
 * might already be "holding" the slot.
 *
 * This is modeled in part after ndi_devi_enter and ndi_devi_exit.
 */
void
sda_slot_enter(sda_slot_t *slot)
{
	kt_did_t	self = ddi_get_kt_did();
	mutex_enter(&slot->s_lock);
	if (slot->s_owner == self) {
		slot->s_circular++;
	} else {
		while ((slot->s_owner != 0) && (slot->s_owner != self)) {
			cv_wait(&slot->s_cv, &slot->s_lock);
		}
		slot->s_owner = self;
		slot->s_circular++;
	}
	mutex_exit(&slot->s_lock);
}

void
sda_slot_exit(sda_slot_t *slot)
{
	ASSERT(sda_slot_owned(slot));

	mutex_enter(&slot->s_lock);
	slot->s_circular--;
	if (slot->s_circular == 0) {
		slot->s_owner = 0;
		cv_broadcast(&slot->s_cv);
	}
	mutex_exit(&slot->s_lock);
}

boolean_t
sda_slot_owned(sda_slot_t *slot)
{
	return (slot->s_owner == ddi_get_kt_did());
}

sda_err_t
sda_slot_check_response(sda_cmd_t *cmdp)
{
	uint32_t	errs;
	switch (cmdp->sc_rtype & 0xf) {
	case R1:
		if ((errs = (cmdp->sc_response[0] & R1_ERRS)) != 0) {
			if (errs & (R1_WP_VIOLATION | R1_CSD_OVERWRITE)) {
				return (SDA_EWPROTECT);
			}
			if (errs & (R1_ADDRESS_ERROR | R1_BLOCK_LEN_ERROR |
			    R1_OUT_OF_RANGE | R1_ERASE_PARAM)) {
				return (SDA_EINVAL);
			}
			return (SDA_EIO);
		}
		break;
	case R5:
		if ((errs = (cmdp->sc_response[0] & R5_ERRS)) != 0) {
			return (SDA_EIO);
		}
		break;
	}
	return (SDA_EOK);
}

void
sda_slot_halt(sda_slot_t *slot)
{
	sda_slot_enter(slot);
	slot->s_ops.so_halt(slot->s_prv);
	drv_usecwait(1000);	/* we need to wait 1 msec for power down */
	sda_slot_exit(slot);
}

void
sda_slot_reset(sda_slot_t *slot)
{
	sda_slot_enter(slot);
	if (slot->s_ops.so_reset(slot->s_prv) != 0) {
		sda_slot_fault(slot, SDA_FAULT_RESET);
	}
	sda_slot_exit(slot);
}

int
sda_slot_power_on(sda_slot_t *slot)
{
	int		rv;
	uint32_t	ocr;

	sda_slot_enter(slot);

	/*
	 * Get the voltage supplied by the host.  Note that we expect
	 * hosts will include a range of 2.7-3.7 in their supported
	 * voltage ranges.  The spec does not allow for hosts that
	 * cannot supply a voltage in this range, yet.
	 */
	if ((rv = sda_getprop(slot, SDA_PROP_OCR, &ocr)) != 0) {
		sda_slot_err(slot, "Failed to get host OCR (%d)", rv);
		goto done;
	}
	if ((ocr & OCR_HI_MASK) == 0) {
		sda_slot_err(slot, "Host does not support standard voltages.");
		rv = ENOTSUP;
		goto done;
	}

	/*
	 * We prefer 3.3V, 3.0V, and failing that, just use the
	 * maximum that the host supports.  3.3V is preferable,
	 * because it is the typical common voltage that just about
	 * everything supports.  Otherwise we just pick the highest
	 * supported voltage.  This facilitates initial power up.
	 */
	if (ocr & OCR_32_33V) {
		slot->s_cur_ocr = OCR_32_33V;
	} else if (ocr & OCR_29_30V) {
		slot->s_cur_ocr = OCR_29_30V;
	} else {
		slot->s_cur_ocr = (1U << (ddi_fls(ocr) - 1));
	}

	/*
	 * Turn on the power.
	 */
	if ((rv = sda_setprop(slot, SDA_PROP_OCR, slot->s_cur_ocr)) != 0) {
		sda_slot_err(slot, "Failed to set OCR %x (%d)",
		    slot->s_cur_ocr, rv);
		goto done;
	}

	sda_slot_exit(slot);

	/*
	 * Wait 250 msec (per spec) for power ramp to complete.
	 */
	delay(drv_usectohz(250000));
	return (0);

done:
	sda_slot_exit(slot);
	return (rv);
}

void
sda_slot_power_off(sda_slot_t *slot)
{
	sda_slot_enter(slot);
	(void) sda_setprop(slot, SDA_PROP_OCR, 0);
	/* XXX: FMA: on failure this should cause a fault to be generated */
	/* spec requires voltage to stay low for at least 1 msec */
	drv_usecwait(1000);
	sda_slot_exit(slot);
}

void
sda_slot_insert(void *arg)
{
	sda_slot_t	*slot = arg;

	if (sda_init_card(slot) != SDA_EOK) {
		/*
		 * Remove power from the slot.  If a more severe fault
		 * occurred, then a manual reset with cfgadm will be needed.
		 */
		sda_slot_err(slot, "Unable to initialize card!");
		sda_slot_enter(slot);
		sda_slot_power_off(slot);
		sda_slot_abort(slot, SDA_ENODEV);
		sda_slot_exit(slot);
		sda_nexus_remove(slot);

	} else {
		sda_nexus_insert(slot);
	}

	slot->s_stamp = ddi_get_time();
	slot->s_intransit = 0;
}

void
sda_slot_mem_reset(sda_slot_t *slot, sda_err_t errno)
{
	sda_cmd_t	*cmdp;

	sda_slot_enter(slot);
	cmdp = list_head(&slot->s_cmdlist);
	while (cmdp != NULL) {
		sda_cmd_t	*next;
		next = list_next(&slot->s_cmdlist, cmdp);
		if (cmdp->sc_flags & SDA_CMDF_MEM) {
			list_remove(&slot->s_cmdlist, cmdp);
			sda_cmd_notify(cmdp, 0, errno);
			mutex_enter(&slot->s_evlock);
			list_insert_tail(&slot->s_abortlist, cmdp);
			mutex_exit(&slot->s_evlock);
		}
		cmdp = next;
	}
	sda_slot_exit(slot);

	/* wake up to process the abort list */
	sda_slot_wakeup(slot);
}

void
sda_slot_abort(sda_slot_t *slot, sda_err_t errno)
{
	sda_cmd_t	*cmdp;

	ASSERT(sda_slot_owned(slot));

	if ((cmdp = slot->s_xfrp) != NULL) {
		slot->s_xfrp = NULL;
		sda_cmd_notify(cmdp, SDA_CMDF_BUSY | SDA_CMDF_DAT, errno);
	}
	while ((cmdp = list_head(&slot->s_cmdlist)) != NULL) {
		list_remove(&slot->s_cmdlist, cmdp);
		sda_cmd_notify(cmdp, 0, errno);
		mutex_enter(&slot->s_evlock);
		list_insert_tail(&slot->s_abortlist, cmdp);
		mutex_exit(&slot->s_evlock);
	}

	sda_slot_wakeup(slot);
}

void
sda_slot_handle_transfer(sda_slot_t *slot, sda_err_t errno)
{
	sda_cmd_t	*cmdp;

	sda_slot_enter(slot);

	if ((cmdp = slot->s_xfrp) != NULL) {

		slot->s_xfrp = NULL;
		slot->s_xfrtmo = 0;
		(void) sda_setprop(slot, SDA_PROP_LED, 0);
		sda_slot_exit(slot);

		sda_slot_wakeup(slot);

		sda_cmd_notify(cmdp, SDA_CMDF_DAT, errno);
	} else {
		sda_slot_exit(slot);
	}
}

void
sda_slot_handle_fault(sda_slot_t *slot, sda_fault_t fault)
{
	const char	*msg;
	int		i;

	sda_slot_enter(slot);

	if ((fault == SDA_FAULT_TIMEOUT) && (slot->s_init)) {
		/*
		 * Timeouts during initialization are quite normal.
		 */
		sda_slot_exit(slot);
		return;
	}

	slot->s_failed = B_TRUE;
	sda_slot_abort(slot, SDA_EFAULT);

	msg = "Unknown fault (%d)";
	for (i = 0; sda_slot_faults[i].msg != NULL; i++) {
		if (sda_slot_faults[i].fault == fault) {
			msg = sda_slot_faults[i].msg;
			break;
		}
	}

	/*
	 * FMA would be a better choice here.
	 */
	sda_slot_err(slot, msg, fault);

	/*
	 * Shut down the slot.  Interaction from userland via cfgadm
	 * can revive it.
	 *
	 * FMA can help here.
	 */
	sda_slot_halt(slot);

	sda_slot_exit(slot);
}

void
sda_slot_handle_detect(sda_slot_t *slot)
{
	uint32_t	inserted;

	sda_slot_enter(slot);

	slot->s_stamp = ddi_get_time();
	slot->s_intransit = 1;
	slot->s_flags = 0;
	slot->s_rca = 0;
	slot->s_ready = B_FALSE;

	sda_getprop(slot, SDA_PROP_INSERTED, &inserted);
	slot->s_inserted = (inserted != 0);

	if (slot->s_inserted && !slot->s_failed) {
		/*
		 * We need to initialize the card, so we only support
		 * hipri commands for now.
		 */
		slot->s_init = B_TRUE;

		/*
		 * Card insertion occurred.  We have to run this on
		 * another task, to avoid deadlock as the task may
		 * need to dispatch commands.
		 */
		(void) ddi_taskq_dispatch(slot->s_tq, sda_slot_insert, slot,
		    DDI_SLEEP);
	} else {

		/*
		 * Nuke in-flight commands.
		 */
		sda_slot_abort(slot, SDA_ENODEV);

		/*
		 * Restart the slot (incl. power cycle).  This gets the
		 * slot to a known good state.
		 */
		sda_slot_reset(slot);

		sda_nexus_remove(slot);

		slot->s_intransit = 0;
	}
	sda_slot_exit(slot);

	sda_slot_wakeup(slot);
}

void
sda_slot_transfer(sda_slot_t *slot, sda_err_t errno)
{
	mutex_enter(&slot->s_evlock);
	slot->s_errno = errno;
	slot->s_xfrdone = B_TRUE;
	cv_broadcast(&slot->s_evcv);
	mutex_exit(&slot->s_evlock);
}

void
sda_slot_detect(sda_slot_t *slot)
{
	mutex_enter(&slot->s_evlock);
	slot->s_detect = B_TRUE;
	cv_broadcast(&slot->s_evcv);
	mutex_exit(&slot->s_evlock);
}

void
sda_slot_fault(sda_slot_t *slot, sda_fault_t fault)
{
	mutex_enter(&slot->s_evlock);
	slot->s_fault = fault;
	cv_broadcast(&slot->s_evcv);
	mutex_exit(&slot->s_evlock);
}

void
sda_slot_wakeup(sda_slot_t *slot)
{
	mutex_enter(&slot->s_evlock);
	slot->s_wake = B_TRUE;
	cv_broadcast(&slot->s_evcv);
	mutex_exit(&slot->s_evlock);
}

void
sda_slot_init(sda_slot_t *slot)
{
	mutex_init(&slot->s_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&slot->s_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&slot->s_evlock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&slot->s_evcv, NULL, CV_DRIVER, NULL);

	sda_cmd_list_init(&slot->s_cmdlist);
	sda_cmd_list_init(&slot->s_abortlist);
}

void
sda_slot_fini(sda_slot_t *slot)
{
	sda_cmd_list_fini(&slot->s_cmdlist);
	sda_cmd_list_fini(&slot->s_abortlist);
	mutex_destroy(&slot->s_lock);
	mutex_destroy(&slot->s_evlock);
	cv_destroy(&slot->s_cv);
	cv_destroy(&slot->s_evcv);
}

void
sda_slot_attach(sda_slot_t *slot)
{
	sda_host_t	*h = slot->s_host;
	char		name[16];
	kthread_t	*thr;
	uint32_t	cap;

	/*
	 * We have both a thread and a taskq.  The taskq is used for
	 * card initialization.
	 *
	 * The thread is used for the main processing loop.
	 *
	 * The reason for a separate taskq is that initialization
	 * needs to acquire locks which may be held by the slot
	 * thread, or by device driver context... use of the separate
	 * taskq breaks the deadlock.  Additionally, the
	 * initialization task may need to sleep quite a while during
	 * card initialization.
	 */

	sda_slot_enter(slot);

	(void) snprintf(name, sizeof (name), "slot_%d_tq", slot->s_slot_num);
	slot->s_tq = ddi_taskq_create(h->h_dip, name, 1, TASKQ_DEFAULTPRI, 0);
	if (slot->s_tq == NULL) {
		/* Generally, this failure should never occur */
		sda_slot_err(slot, "Unable to create slot taskq");
		sda_slot_exit(slot);
		return;
	}

	/* create the main processing thread */
	thr = thread_create(NULL, 0, sda_slot_thread, slot, 0, &p0, TS_RUN,
	    minclsyspri);
	slot->s_thrid = thr->t_did;

	/*
	 * Determine slot capabilities.
	 */
	slot->s_caps = 0;

	if ((sda_getprop(slot, SDA_PROP_CAP_NOPIO, &cap) == 0) && (cap != 0)) {
		slot->s_caps |= SLOT_CAP_NOPIO;
	}
	if ((sda_getprop(slot, SDA_PROP_CAP_4BITS, &cap) == 0) && (cap != 0)) {
		slot->s_caps |= SLOT_CAP_4BITS;
	}
	if ((sda_getprop(slot, SDA_PROP_CAP_HISPEED, &cap) == 0) &&
	    (cap != 0)) {
		slot->s_caps |= SLOT_CAP_HISPEED;
	}

	/* make sure that the host is started up */
	if (slot->s_ops.so_reset(slot->s_prv) != 0) {
		sda_slot_fault(slot, SDA_FAULT_RESET);
	}

	sda_slot_exit(slot);
}

void
sda_slot_detach(sda_slot_t *slot)
{
	/*
	 * Shut down the thread.
	 */
	if (slot->s_thrid) {
		mutex_enter(&slot->s_evlock);
		slot->s_detach = B_TRUE;
		cv_broadcast(&slot->s_evcv);
		mutex_exit(&slot->s_evlock);
	}
	thread_join(slot->s_thrid);

	/*
	 * Nuke the taskq. We do this after killing the
	 * thread, to ensure that the thread doesn't try to
	 * dispatch to it.
	 */
	if (slot->s_tq)
		ddi_taskq_destroy(slot->s_tq);
}

void
sda_slot_thread(void *arg)
{
	sda_slot_t	*slot = arg;
#ifndef	__lock_lint
	callb_cpr_t	cprinfo;

	CALLB_CPR_INIT(&cprinfo, &slot->s_evlock, callb_generic_cpr,
	    "sda_slot_thread");
#endif

	for (;;) {
		sda_cmd_t	*cmdp;
		boolean_t	datline;
		sda_err_t	rv;

		mutex_enter(&slot->s_evlock);

		/*
		 * Process any abort list first.
		 */
		if ((cmdp = list_head(&slot->s_abortlist)) != NULL) {
			list_remove(&slot->s_abortlist, cmdp);
			mutex_exit(&slot->s_evlock);
			/*
			 * EOK used here, to avoid clobbering previous
			 * error code.
			 */
			sda_cmd_notify(cmdp, SDA_CMDF_BUSY | SDA_CMDF_DAT,
			    SDA_EOK);
			continue;
		}

		if (slot->s_detach) {
			/* parent is detaching the slot, bail out */
			break;
		}

		if (slot->s_detect) {
			slot->s_detect = B_FALSE;
			mutex_exit(&slot->s_evlock);

			sda_slot_handle_detect(slot);
			continue;
		}

		if (slot->s_xfrdone) {
			sda_err_t	errno;

			errno = slot->s_errno;
			slot->s_errno = SDA_EOK;
			slot->s_xfrdone = B_FALSE;
			mutex_exit(&slot->s_evlock);

			sda_slot_handle_transfer(slot, errno);
			continue;
		}

		if (slot->s_fault != SDA_FAULT_NONE) {
			sda_fault_t	fault;

			fault = slot->s_fault;
			slot->s_fault = SDA_FAULT_NONE;
			mutex_exit(&slot->s_evlock);

			sda_slot_handle_fault(slot, fault);
			continue;
		}

		if (slot->s_reap) {
			/*
			 * Do not sleep while holding the evlock.  If this
			 * fails, we'll just try again the next cycle.
			 */
			(void) ddi_taskq_dispatch(slot->s_tq, sda_nexus_reap,
			    slot, DDI_NOSLEEP);
		}

		if ((slot->s_xfrp != NULL) && (gethrtime() > slot->s_xfrtmo)) {
			/*
			 * The device stalled processing the data request.
			 * At this point, we really have no choice but to
			 * nuke the request, and flag a fault.
			 */
			mutex_exit(&slot->s_evlock);
			sda_slot_handle_transfer(slot, SDA_ETIME);
			sda_slot_fault(slot, SDA_FAULT_TIMEOUT);
			continue;
		}

		if (!slot->s_wake) {

			/*
			 * We use a timed wait if we are waiting for a
			 * data transfer to complete, or if we might
			 * need to reap child nodes.  Otherwise we
			 * avoid the timed wait to avoid waking CPU
			 * (power savings.)
			 */
#ifndef	__lock_lint
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
#endif

			if ((slot->s_xfrp != NULL) || (slot->s_reap)) {
				/* wait 3 sec (reap attempts) */

				(void) cv_timedwait(&slot->s_evcv,
				    &slot->s_evlock,
				    ddi_get_lbolt() + drv_usectohz(3000000));
			} else {
				(void) cv_wait(&slot->s_evcv, &slot->s_evlock);
			}
#ifndef	__lock_lint
			CALLB_CPR_SAFE_END(&cprinfo, &slot->s_evlock);
#endif

			mutex_exit(&slot->s_evlock);
			continue;
		}

		slot->s_wake = B_FALSE;

		/*
		 * Possibly reap child nodes.
		 */
		if (slot->s_reap) {
			slot->s_reap = B_FALSE;
			mutex_exit(&slot->s_evlock);
			sda_nexus_reap(slot);
		} else {
			mutex_exit(&slot->s_evlock);
		}

		/*
		 * We're awake now, so look for work to do.  First
		 * acquire access to the slot.
		 */

		sda_slot_enter(slot);

		/*
		 * If no more commands to process, go back to sleep.
		 */
		if ((cmdp = list_head(&slot->s_cmdlist)) == NULL) {
			sda_slot_exit(slot);
			continue;
		}

		datline = ((cmdp->sc_flags & SDA_CMDF_DAT) != 0);

		if (datline) {
			/*
			 * If the current command has a data phase
			 * while a transfer is in progress, then go
			 * back to sleep.
			 */
			if (slot->s_xfrp != NULL) {
				sda_slot_exit(slot);
				continue;
			}

			/*
			 * Note that APP_CMD doesn't have a data phase,
			 * although the associated ACMD might.
			 */
			if (cmdp->sc_index != CMD_APP_CMD) {
				slot->s_xfrp = cmdp;
				/*
				 * All commands should complete in
				 * less than 5 seconds.  The worst
				 * case is actually somewhere around 4
				 * seconds, but that is when the clock
				 * is only 100 kHz.
				 */
				slot->s_xfrtmo = gethrtime() +
				    5000000000ULL;
				(void) sda_setprop(slot, SDA_PROP_LED, 1);
			}
		}

		/*
		 * We're committed to dispatching this command now,
		 * so remove it from the list.
		 */
		list_remove(&slot->s_cmdlist, cmdp);

		/*
		 * There could be more commands after this one, so we
		 * mark ourself so we stay awake for another cycle.
		 */
		sda_slot_wakeup(slot);

		/*
		 * Submit the command.  Note that we are holding the
		 * slot lock here, so it is critical that the caller
		 * *not* call back up into the framework.  The caller
		 * must break context.  But doing it this way prevents
		 * a critical race on card removal.
		 *
		 * During initialization, we reject any commands that
		 * are not from the initialization code.  This does
		 * have the side effect of removing them.
		 *
		 * Note that we don't resubmit memory to the device if
		 * it isn't flagged as ready (e.g. if the wrong device
		 * was inserted!)
		 */
		if (((!slot->s_ready) && (cmdp->sc_flags & SDA_CMDF_MEM)) ||
		    (slot->s_init && !(cmdp->sc_flags & SDA_CMDF_INIT))) {
			rv = SDA_ENODEV;
			if (!slot->s_warn) {
				sda_slot_err(slot,
				    "Device removed while in use.  "
				    "Please reinsert!");
				slot->s_warn = B_TRUE;
			}
		} else {
			rv = slot->s_ops.so_cmd(slot->s_prv, cmdp);
		}
		if (rv == SDA_EOK)
			rv = sda_slot_check_response(cmdp);

		if (rv == SDA_EOK) {
			/*
			 * If APP_CMD completed properly, then
			 * resubmit with ACMD index.  Note wake was
			 * already set above.
			 */
			if (cmdp->sc_index == CMD_APP_CMD) {
				if ((cmdp->sc_response[0] & R1_APP_CMD) == 0) {
					sda_slot_log(slot, "APP_CMD not set!");
				}
				sda_cmd_resubmit_acmd(slot, cmdp);
				sda_slot_exit(slot);

				continue;
			}

		} else if (datline) {
			/*
			 * If an error occurred and we were expecting
			 * a transfer phase, we have to clean up.
			 */
			(void) sda_setprop(slot, SDA_PROP_LED, 0);
			slot->s_xfrp = NULL;
			slot->s_xfrtmo = 0;

			/*
			 * And notify any waiter.
			 */
			sda_slot_exit(slot);
			sda_cmd_notify(cmdp, SDA_CMDF_BUSY | SDA_CMDF_DAT, rv);
			continue;
		}

		/*
		 * Wake any waiter.
		 */
		sda_slot_exit(slot);
		sda_cmd_notify(cmdp, SDA_CMDF_BUSY, rv);
	}

#ifdef	__lock_lint
	mutex_exit(&slot->s_evlock);
#else
	CALLB_CPR_EXIT(&cprinfo);
#endif

	thread_exit();
}

void
sda_slot_vprintf(sda_slot_t *s, int level, const char *fmt, va_list ap)
{
	char		msgbuf[256];
	const char	*pfx, *sfx;

	if (level == CE_CONT) {
		pfx = "!";
		sfx = "\n";
	} else {
		pfx = sfx = "";
	}

	if (s != NULL) {
		dev_info_t	*dip = s->s_host->h_dip;

		(void) snprintf(msgbuf, sizeof (msgbuf),
		    "%s%s%d: slot %d: %s%s", pfx,
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    s->s_slot_num, fmt, sfx);
	} else {
		(void) snprintf(msgbuf, sizeof (msgbuf), "%ssda: %s%s",
		    pfx, fmt, sfx);
	}
	vcmn_err(level, msgbuf, ap);
}

void
sda_slot_err(sda_slot_t *s, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	sda_slot_vprintf(s, CE_WARN, fmt, ap);
	va_end(ap);
}

void
sda_slot_log(sda_slot_t *s, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	sda_slot_vprintf(s, CE_CONT, fmt, ap);
	va_end(ap);
}
