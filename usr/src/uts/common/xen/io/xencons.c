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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved					*/

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 *
 * Copyright (c) 2004 Christian Limpach.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. This section intentionally left blank.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Section 3 of the above license was updated in response to bug 6379571.
 */

/*
 * Hypervisor virtual console driver
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/stream.h>
#include <sys/termio.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strtty.h>
#include <sys/debug.h>
#include <sys/kbio.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/consdev.h>
#include <sys/mkdev.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/strsun.h>
#ifdef DEBUG
#include <sys/promif.h>
#endif
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/policy.h>
#include <sys/atomic.h>
#include <sys/psm.h>
#include <xen/public/io/console.h>

#include "xencons.h"

#include <sys/hypervisor.h>
#include <sys/evtchn_impl.h>
#include <xen/sys/xenbus_impl.h>
#include <xen/sys/xendev.h>

#ifdef DEBUG
#define	XENCONS_DEBUG_INIT	0x0001	/* msgs during driver initialization. */
#define	XENCONS_DEBUG_INPUT	0x0002	/* characters received during int. */
#define	XENCONS_DEBUG_EOT	0x0004	/* msgs when wait for xmit to finish. */
#define	XENCONS_DEBUG_CLOSE	0x0008	/* msgs when driver open/close called */
#define	XENCONS_DEBUG_PROCS	0x0020	/* each proc name as it is entered. */
#define	XENCONS_DEBUG_OUT	0x0100	/* msgs about output events. */
#define	XENCONS_DEBUG_BUSY	0x0200	/* msgs when xmit is enabled/disabled */
#define	XENCONS_DEBUG_MODEM	0x0400	/* msgs about modem status & control. */
#define	XENCONS_DEBUG_MODM2	0x0800	/* msgs about modem status & control. */
#define	XENCONS_DEBUG_IOCTL	0x1000	/* Output msgs about ioctl messages. */
#define	XENCONS_DEBUG_CHIP	0x2000	/* msgs about chip identification. */
#define	XENCONS_DEBUG_SFLOW	0x4000	/* msgs when S/W flowcontrol active */
#define	XENCONS_DEBUG(x) (debug & (x))
static int debug  = 0;
#else
#define	XENCONS_DEBUG(x) B_FALSE
#endif

#define	XENCONS_WBUFSIZE	4096

static boolean_t abort_charseq_recognize(uchar_t);

/* The async interrupt entry points */
static void	xcasync_ioctl(struct asyncline *, queue_t *, mblk_t *);
static void	xcasync_reioctl(void *);
static void	xcasync_start(struct asyncline *);
static void	xenconsputchar(cons_polledio_arg_t, uchar_t);
static int	xenconsgetchar(cons_polledio_arg_t);
static boolean_t	xenconsischar(cons_polledio_arg_t);

static uint_t	xenconsintr(caddr_t);
static uint_t	xenconsintr_priv(caddr_t);
/*PRINTFLIKE2*/
static void	xenconserror(int, const char *, ...) __KPRINTFLIKE(2);
static void	xencons_soft_state_free(struct xencons *);
static boolean_t
xcasync_flowcontrol_sw_input(struct xencons *, async_flowc_action, int);
static void
xcasync_flowcontrol_sw_output(struct xencons *, async_flowc_action);

void		*xencons_soft_state;
char		*xencons_wbuf;
struct xencons	*xencons_console;

static void
xenconssetup_avintr(struct xencons *xcp, int attach)
{
	/*
	 * On xen, CPU 0 always exists and can't be taken offline,
	 * so binding this thread to it should always succeed.
	 */
	mutex_enter(&cpu_lock);
	thread_affinity_set(curthread, 0);
	mutex_exit(&cpu_lock);

	if (attach) {
		/* Setup our interrupt binding. */
		(void) add_avintr(NULL, IPL_CONS, (avfunc)xenconsintr_priv,
		    "xencons", xcp->console_irq, (caddr_t)xcp, NULL, NULL,
		    xcp->dip);
	} else {
		/*
		 * Cleanup interrupt configuration.  Note that the framework
		 * _should_ ensure that when rem_avintr() returns the interrupt
		 * service routine is not currently executing and that it won't
		 * be invoked again.
		 */
		(void) rem_avintr(NULL, IPL_CONS, (avfunc)xenconsintr_priv,
		    xcp->console_irq);
	}

	/* Notify our caller that we're done. */
	mutex_enter(&xcp->excl);
	cv_signal(&xcp->excl_cv);
	mutex_exit(&xcp->excl);

	/* Clear our binding to CPU 0 */
	thread_affinity_clear(curthread);

}

static void
xenconssetup_add_avintr(struct xencons *xcp)
{
	xenconssetup_avintr(xcp, B_TRUE);
}

static void
xenconssetup_rem_avintr(struct xencons *xcp)
{
	xenconssetup_avintr(xcp, B_FALSE);
}

static int
xenconsdetach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	struct xencons *xcp;

	if (cmd != DDI_DETACH && cmd != DDI_SUSPEND)
		return (DDI_FAILURE);

	if (cmd == DDI_SUSPEND) {
		ddi_remove_intr(devi, 0, NULL);
		return (DDI_SUCCESS);
	}

	/*
	 * We should never try to detach the console driver on a domU
	 * because it should always be held open
	 */
	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));
	if (!DOMAIN_IS_INITDOMAIN(xen_info))
		return (DDI_FAILURE);

	instance = ddi_get_instance(devi);	/* find out which unit */

	xcp = ddi_get_soft_state(xencons_soft_state, instance);
	if (xcp == NULL)
		return (DDI_FAILURE);

	/*
	 * Cleanup our interrupt bindings.  For more info on why we
	 * do this in a seperate thread, see the comments for when we
	 * setup the interrupt bindings.
	 */
	xencons_console = NULL;
	mutex_enter(&xcp->excl);
	(void) taskq_dispatch(system_taskq,
	    (void (*)(void *))xenconssetup_rem_avintr, xcp, TQ_SLEEP);
	cv_wait(&xcp->excl_cv, &xcp->excl);
	mutex_exit(&xcp->excl);

	/* remove all minor device node(s) for this device */
	ddi_remove_minor_node(devi, NULL);

	/* free up state */
	xencons_soft_state_free(xcp);
	kmem_free(xencons_wbuf, XENCONS_WBUFSIZE);

	DEBUGNOTE1(XENCONS_DEBUG_INIT, "xencons%d: shutdown complete",
	    instance);
	return (DDI_SUCCESS);
}

static void
xenconssetup(struct xencons *xcp)
{
	xcp->ifp = (volatile struct xencons_interface *)HYPERVISOR_console_page;

	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		xencons_wbuf = kmem_alloc(XENCONS_WBUFSIZE, KM_SLEEP);

		/*
		 * Activate the xen console virq.  Note that xen requires
		 * that VIRQs be bound to CPU 0 when first created.
		 */
		xcp->console_irq = ec_bind_virq_to_irq(VIRQ_CONSOLE, 0);

		/*
		 * Ok.  This is kinda ugly.  We want to register an
		 * interrupt handler for the xen console virq, but
		 * virq's are xen sepcific and currently the DDI doesn't
		 * support binding to them.  So instead we need to use
		 * add_avintr().  So to make things more complicated,
		 * we already had to bind the xen console VIRQ to CPU 0,
		 * and add_avintr() needs to be invoked on the same CPU
		 * where the VIRQ is bound, in this case on CPU 0.  We
		 * could just temporarily bind ourselves to CPU 0, but
		 * we don't want to do that since this attach thread
		 * could have been invoked in a user thread context,
		 * in which case this thread could already have some
		 * pre-existing cpu binding.  So to avoid changing our
		 * cpu binding we're going to use a taskq thread that
		 * will bind to CPU 0 and register our interrupts
		 * handler for us.
		 */
		mutex_enter(&xcp->excl);
		(void) taskq_dispatch(system_taskq,
		    (void (*)(void *))xenconssetup_add_avintr, xcp, TQ_SLEEP);
		cv_wait(&xcp->excl_cv, &xcp->excl);
		mutex_exit(&xcp->excl);
	} else {
		(void) xvdi_alloc_evtchn(xcp->dip);
		xcp->evtchn = xvdi_get_evtchn(xcp->dip);
		(void) ddi_add_intr(xcp->dip, 0, NULL, NULL, xenconsintr,
		    (caddr_t)xcp);
	}
}

static int
xenconsattach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);
	struct xencons *xcp;
	int ret;

	/* There can be only one. */
	if (instance != 0)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_RESUME:
		xcp = xencons_console;
		xenconssetup(xcp);
		return (DDI_SUCCESS);
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	ret = ddi_soft_state_zalloc(xencons_soft_state, instance);
	if (ret != DDI_SUCCESS)
		return (DDI_FAILURE);
	xcp = ddi_get_soft_state(xencons_soft_state, instance);
	ASSERT(xcp != NULL);	/* can't fail - we only just allocated it */

	/*
	 * Set up the other components of the xencons structure for this port.
	 */
	xcp->unit = instance;
	xcp->dip = devi;

	/* Fill in the polled I/O structure. */
	xcp->polledio.cons_polledio_version = CONSPOLLEDIO_V0;
	xcp->polledio.cons_polledio_argument = (cons_polledio_arg_t)xcp;
	xcp->polledio.cons_polledio_putchar = xenconsputchar;
	xcp->polledio.cons_polledio_getchar = xenconsgetchar;
	xcp->polledio.cons_polledio_ischar = xenconsischar;
	xcp->polledio.cons_polledio_enter = NULL;
	xcp->polledio.cons_polledio_exit = NULL;

	/*
	 * Initializes the asyncline structure which has TTY protocol-private
	 * data before enabling interrupts.
	 */
	xcp->priv = kmem_zalloc(sizeof (struct asyncline), KM_SLEEP);
	xcp->priv->async_common = xcp;
	cv_init(&xcp->priv->async_flags_cv, NULL, CV_DRIVER, NULL);

	/* Initialize mutexes before accessing the interface. */
	mutex_init(&xcp->excl, NULL, MUTEX_DRIVER, NULL);
	cv_init(&xcp->excl_cv, NULL, CV_DEFAULT, NULL);

	/* create minor device node for this device */
	ret = ddi_create_minor_node(devi, "xencons", S_IFCHR, instance,
	    DDI_NT_SERIAL, NULL);
	if (ret != DDI_SUCCESS) {
		ddi_remove_minor_node(devi, NULL);
		xencons_soft_state_free(xcp);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	xencons_console = xcp;
	xenconssetup(xcp);
	DEBUGCONT1(XENCONS_DEBUG_INIT, "xencons%dattach: done\n", instance);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
xenconsinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	dev_t dev = (dev_t)arg;
	int instance, error;
	struct xencons *xcp;

	instance = getminor(dev);
	xcp = ddi_get_soft_state(xencons_soft_state, instance);
	if (xcp == NULL)
		return (DDI_FAILURE);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (xcp->dip == NULL)
			error = DDI_FAILURE;
		else {
			*result = (void *) xcp->dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/* xencons_soft_state_free - local wrapper for ddi_soft_state_free(9F) */

static void
xencons_soft_state_free(struct xencons *xcp)
{
	mutex_destroy(&xcp->excl);
	cv_destroy(&xcp->excl_cv);
	kmem_free(xcp->priv, sizeof (struct asyncline));
	ddi_soft_state_free(xencons_soft_state, xcp->unit);
}

/*ARGSUSED*/
static int
xenconsopen(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr)
{
	struct xencons	*xcp;
	struct asyncline *async;
	int		unit;

	unit = getminor(*dev);
	DEBUGCONT1(XENCONS_DEBUG_CLOSE, "xencons%dopen\n", unit);
	xcp = ddi_get_soft_state(xencons_soft_state, unit);
	if (xcp == NULL)
		return (ENXIO);		/* unit not configured */
	async = xcp->priv;
	mutex_enter(&xcp->excl);

again:

	if ((async->async_flags & ASYNC_ISOPEN) == 0) {
		async->async_ttycommon.t_iflag = 0;
		async->async_ttycommon.t_iocpending = NULL;
		async->async_ttycommon.t_size.ws_row = 0;
		async->async_ttycommon.t_size.ws_col = 0;
		async->async_ttycommon.t_size.ws_xpixel = 0;
		async->async_ttycommon.t_size.ws_ypixel = 0;
		async->async_dev = *dev;
		async->async_wbufcid = 0;

		async->async_startc = CSTART;
		async->async_stopc = CSTOP;
	} else if ((async->async_ttycommon.t_flags & TS_XCLUDE) &&
	    secpolicy_excl_open(cr) != 0) {
		mutex_exit(&xcp->excl);
		return (EBUSY);
	}

	async->async_ttycommon.t_flags |= TS_SOFTCAR;

	async->async_ttycommon.t_readq = rq;
	async->async_ttycommon.t_writeq = WR(rq);
	rq->q_ptr = WR(rq)->q_ptr = (caddr_t)async;
	mutex_exit(&xcp->excl);
	/*
	 * Caution here -- qprocson sets the pointers that are used by canput
	 * called by xencons_rxint.  ASYNC_ISOPEN must *not* be set until those
	 * pointers are valid.
	 */
	qprocson(rq);
	async->async_flags |= ASYNC_ISOPEN;
	DEBUGCONT1(XENCONS_DEBUG_INIT, "asy%dopen: done\n", unit);
	return (0);
}


/*
 * Close routine.
 */
/*ARGSUSED*/
static int
xenconsclose(queue_t *q, int flag, cred_t *credp)
{
	struct asyncline *async;
	struct xencons	 *xcp;
#ifdef DEBUG
	int instance;
#endif

	async = (struct asyncline *)q->q_ptr;
	ASSERT(async != NULL);
	xcp = async->async_common;
#ifdef DEBUG
	instance = xcp->unit;
	DEBUGCONT1(XENCONS_DEBUG_CLOSE, "xencons%dclose\n", instance);
#endif

	mutex_enter(&xcp->excl);
	async->async_flags |= ASYNC_CLOSING;

	async->async_ocnt = 0;
	if (async->async_xmitblk != NULL)
		freeb(async->async_xmitblk);
	async->async_xmitblk = NULL;

out:
	ttycommon_close(&async->async_ttycommon);

	/*
	 * Cancel outstanding "bufcall" request.
	 */
	if (async->async_wbufcid != 0) {
		unbufcall(async->async_wbufcid);
		async->async_wbufcid = 0;
	}

	/* Note that qprocsoff can't be done until after interrupts are off */
	qprocsoff(q);
	q->q_ptr = WR(q)->q_ptr = NULL;
	async->async_ttycommon.t_readq = NULL;
	async->async_ttycommon.t_writeq = NULL;

	/*
	 * Clear out device state, except persistant device property flags.
	 */
	async->async_flags = 0;
	cv_broadcast(&async->async_flags_cv);
	mutex_exit(&xcp->excl);

	DEBUGCONT1(XENCONS_DEBUG_CLOSE, "xencons%dclose: done\n", instance);
	return (0);
}

#define	INBUF_IX(ix, ifp)	(DOMAIN_IS_INITDOMAIN(xen_info) ? \
	(ix) : MASK_XENCONS_IDX((ix), (ifp)->in))

/*
 * Handle a xen console rx interrupt.
 */
/*ARGSUSED*/
static void
xencons_rxint(struct xencons *xcp)
{
	struct asyncline *async;
	short	cc;
	mblk_t	*bp;
	queue_t	*q;
	uchar_t	c, buf[16];
	uchar_t	*cp;
	tty_common_t	*tp;
	int instance;
	volatile struct xencons_interface *ifp;
	XENCONS_RING_IDX cons, prod;

	DEBUGCONT0(XENCONS_DEBUG_PROCS, "xencons_rxint\n");

loop:
	mutex_enter(&xcp->excl);

	instance = xcp->unit;

	/* sanity check if we should bail */
	if (xencons_console == NULL) {
		mutex_exit(&xcp->excl);
		DEBUGCONT1(XENCONS_DEBUG_PROCS,
		    "xencons%d_rxint: xencons_console is NULL\n",
		    instance);
		goto out;
	}

	async = xcp->priv;
	ifp = xcp->ifp;
	tp = &async->async_ttycommon;
	q = tp->t_readq;

	if (async->async_flags & ASYNC_OUT_FLW_RESUME) {
		xcasync_start(async);
		async->async_flags &= ~ASYNC_OUT_FLW_RESUME;
	}

	/*
	 * If data is available, send it up the stream if there's
	 * somebody listening.
	 */
	if (!(async->async_flags & ASYNC_ISOPEN)) {
		mutex_exit(&xcp->excl);
		goto out;
	}
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		cc = HYPERVISOR_console_io(CONSOLEIO_read, 16, (char *)buf);
		cp = buf;
		cons = 0;
	} else {
		cons = ifp->in_cons;
		prod = ifp->in_prod;

		cc = prod - cons;
		cp = (uchar_t *)ifp->in;
	}
	if (cc <= 0) {
		mutex_exit(&xcp->excl);
		goto out;
	}

	/*
	 * Check for character break sequence.
	 *
	 * Note that normally asy drivers only check for a character sequence
	 * if abort_enable == KIOCABORTALTERNATE and otherwise use a break
	 * sensed on the line to do an abort_sequence_enter.  Since the
	 * hypervisor does not use a real chip for the console we default to
	 * using the alternate sequence.
	 */
	if ((abort_enable == KIOCABORTENABLE) && (xcp->flags & ASY_CONSOLE)) {
		XENCONS_RING_IDX i;

		for (i = 0; i < cc; i++) {
			c = cp[INBUF_IX(cons + i, ifp)];
			if (abort_charseq_recognize(c)) {
				/*
				 * Eat abort seg, it's not a valid debugger
				 * command.
				 */
				if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
					membar_producer();
					ifp->in_cons = cons + i;
				} else {
					cons += i;
				}
				abort_sequence_enter((char *)NULL);
				/*
				 * Back from debugger, resume normal processing
				 */
				mutex_exit(&xcp->excl);
				goto loop;
			}
		}
	}

	if (!canput(q)) {
		if (!(async->async_inflow_source & IN_FLOW_STREAMS)) {
			(void) xcasync_flowcontrol_sw_input(xcp, FLOW_STOP,
			    IN_FLOW_STREAMS);
		}
		mutex_exit(&xcp->excl);
		goto out;
	}
	if (async->async_inflow_source & IN_FLOW_STREAMS) {
		(void) xcasync_flowcontrol_sw_input(xcp, FLOW_START,
		    IN_FLOW_STREAMS);
	}
	DEBUGCONT2(XENCONS_DEBUG_INPUT,
	    "xencons%d_rxint: %d char(s) in queue.\n", instance, cc);
	if (!(bp = allocb(cc, BPRI_MED))) {
		mutex_exit(&xcp->excl);
		ttycommon_qfull(&async->async_ttycommon, q);
		goto out;
	}
	do {
		c = cp[INBUF_IX(cons++, ifp)];
		/*
		 * We handle XON/XOFF char if IXON is set,
		 * but if received char is _POSIX_VDISABLE,
		 * we left it to the up level module.
		 */
		if (tp->t_iflag & IXON) {
			if ((c == async->async_stopc) &&
			    (c != _POSIX_VDISABLE)) {
				xcasync_flowcontrol_sw_output(xcp, FLOW_STOP);
				continue;
			} else if ((c == async->async_startc) &&
			    (c != _POSIX_VDISABLE)) {
				xcasync_flowcontrol_sw_output(xcp, FLOW_START);
				continue;
			}
			if ((tp->t_iflag & IXANY) &&
			    (async->async_flags & ASYNC_SW_OUT_FLW)) {
				xcasync_flowcontrol_sw_output(xcp, FLOW_START);
			}
		}
		*bp->b_wptr++ = c;
	} while (--cc);
	membar_producer();
	if (!DOMAIN_IS_INITDOMAIN(xen_info))
		ifp->in_cons = cons;
	mutex_exit(&xcp->excl);
	if (bp->b_wptr > bp->b_rptr) {
		if (!canput(q)) {
			xenconserror(CE_NOTE, "xencons%d: local queue full",
			    instance);
			freemsg(bp);
		} else
			(void) putq(q, bp);
	} else
		freemsg(bp);
	if (DOMAIN_IS_INITDOMAIN(xen_info))
		goto loop;
out:
	DEBUGCONT1(XENCONS_DEBUG_PROCS, "xencons%d_rxint: done\n", instance);
	if (!DOMAIN_IS_INITDOMAIN(xen_info))
		ec_notify_via_evtchn(xcp->evtchn);
}


/*
 * Handle a xen console tx interrupt.
 */
/*ARGSUSED*/
static void
xencons_txint(struct xencons *xcp)
{
	struct asyncline *async;

	DEBUGCONT0(XENCONS_DEBUG_PROCS, "xencons_txint\n");

	/*
	 * prevent recursive entry
	 */
	if (mutex_owner(&xcp->excl) == curthread) {
		goto out;
	}

	mutex_enter(&xcp->excl);
	if (xencons_console == NULL) {
		mutex_exit(&xcp->excl);
		goto out;
	}

	/* make sure the device is open */
	async = xcp->priv;
	if ((async->async_flags & ASYNC_ISOPEN) != 0)
		xcasync_start(async);

	mutex_exit(&xcp->excl);
out:
	DEBUGCONT0(XENCONS_DEBUG_PROCS, "xencons_txint: done\n");
}


/*
 * Get an event when input ring becomes not empty or output ring becomes not
 * full.
 */
static uint_t
xenconsintr(caddr_t arg)
{
	struct xencons *xcp = (struct xencons *)arg;
	volatile struct xencons_interface *ifp = xcp->ifp;

	if (ifp->in_prod != ifp->in_cons)
		xencons_rxint(xcp);
	if (ifp->out_prod - ifp->out_cons < sizeof (ifp->out))
		xencons_txint(xcp);
	return (DDI_INTR_CLAIMED);
}

/*
 * Console interrupt routine for priviliged domains
 */
static uint_t
xenconsintr_priv(caddr_t arg)
{
	struct xencons *xcp = (struct xencons *)arg;

	xencons_rxint(xcp);
	xencons_txint(xcp);
	return (DDI_INTR_CLAIMED);
}

/*
 * Start output on a line, unless it's busy, frozen, or otherwise.
 */
/*ARGSUSED*/
static void
xcasync_start(struct asyncline *async)
{
	struct xencons *xcp = async->async_common;
	int cc;
	queue_t *q;
	mblk_t *bp;
	int	len, space, blen;
	mblk_t *nbp;

#ifdef DEBUG
	int instance = xcp->unit;

	DEBUGCONT1(XENCONS_DEBUG_PROCS, "async%d_nstart\n", instance);
#endif
	ASSERT(mutex_owned(&xcp->excl));

	/*
	 * Check only pended sw input flow control.
	 */
domore:
	(void) xcasync_flowcontrol_sw_input(xcp, FLOW_CHECK, IN_FLOW_NULL);

	if ((q = async->async_ttycommon.t_writeq) == NULL) {
		return;	/* not attached to a stream */
	}

	for (;;) {
		if ((bp = getq(q)) == NULL)
			return;	/* no data to transmit */

		/*
		 * We have a message block to work on.
		 * Check whether it's a break, a delay, or an ioctl (the latter
		 * occurs if the ioctl in question was waiting for the output
		 * to drain).  If it's one of those, process it immediately.
		 */
		switch (bp->b_datap->db_type) {

		case M_IOCTL:
			/*
			 * This ioctl was waiting for the output ahead of
			 * it to drain; obviously, it has.  Do it, and
			 * then grab the next message after it.
			 */
			mutex_exit(&xcp->excl);
			xcasync_ioctl(async, q, bp);
			mutex_enter(&xcp->excl);
			continue;
		}

		while (bp != NULL && (cc = bp->b_wptr - bp->b_rptr) == 0) {
			nbp = bp->b_cont;
			freeb(bp);
			bp = nbp;
		}
		if (bp != NULL)
			break;
	}

	/*
	 * We have data to transmit.  If output is stopped, put
	 * it back and try again later.
	 */
	if (async->async_flags & (ASYNC_SW_OUT_FLW | ASYNC_STOPPED)) {
		(void) putbq(q, bp);
		return;
	}


	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		len = 0;
		space = XENCONS_WBUFSIZE;
		while (bp != NULL && space) {
			blen = bp->b_wptr - bp->b_rptr;
			cc = min(blen, space);
			bcopy(bp->b_rptr, &xencons_wbuf[len], cc);
			bp->b_rptr += cc;
			if (cc == blen) {
				nbp = bp->b_cont;
				freeb(bp);
				bp = nbp;
			}
			space -= cc;
			len += cc;
		}
		mutex_exit(&xcp->excl);
		(void) HYPERVISOR_console_io(CONSOLEIO_write, len,
		    xencons_wbuf);
		mutex_enter(&xcp->excl);
		if (bp != NULL)
			(void) putbq(q, bp); /* not done with this msg yet */
		/*
		 * There are no completion interrupts when using the
		 * HYPERVISOR_console_io call to write console data
		 * so we loop here till we have sent all the data to the
		 * hypervisor.
		 */
		goto domore;
	} else {
		volatile struct xencons_interface *ifp = xcp->ifp;
		XENCONS_RING_IDX cons, prod;

		cons = ifp->out_cons;
		prod = ifp->out_prod;
		membar_enter();
		while (bp != NULL && ((prod - cons) < sizeof (ifp->out))) {
			ifp->out[MASK_XENCONS_IDX(prod++, ifp->out)] =
			    *bp->b_rptr++;
			if (bp->b_rptr == bp->b_wptr) {
				nbp = bp->b_cont;
				freeb(bp);
				bp = nbp;
			}
		}
		membar_producer();
		ifp->out_prod = prod;
		ec_notify_via_evtchn(xcp->evtchn);
		if (bp != NULL)
			(void) putbq(q, bp); /* not done with this msg yet */
	}
}


/*
 * Process an "ioctl" message sent down to us.
 * Note that we don't need to get any locks until we are ready to access
 * the hardware.  Nothing we access until then is going to be altered
 * outside of the STREAMS framework, so we should be safe.
 */
static void
xcasync_ioctl(struct asyncline *async, queue_t *wq, mblk_t *mp)
{
	struct xencons *xcp = async->async_common;
	tty_common_t  *tp = &async->async_ttycommon;
	struct iocblk *iocp;
	unsigned datasize;
	int error = 0;

#ifdef DEBUG
	int instance = xcp->unit;

	DEBUGCONT1(XENCONS_DEBUG_PROCS, "async%d_ioctl\n", instance);
#endif

	if (tp->t_iocpending != NULL) {
		/*
		 * We were holding an "ioctl" response pending the
		 * availability of an "mblk" to hold data to be passed up;
		 * another "ioctl" came through, which means that "ioctl"
		 * must have timed out or been aborted.
		 */
		freemsg(async->async_ttycommon.t_iocpending);
		async->async_ttycommon.t_iocpending = NULL;
	}

	iocp = (struct iocblk *)mp->b_rptr;

	/*
	 * For TIOCMGET and the PPS ioctls, do NOT call ttycommon_ioctl()
	 * because this function frees up the message block (mp->b_cont) that
	 * contains the user location where we pass back the results.
	 *
	 * Similarly, CONSOPENPOLLEDIO needs ioc_count, which ttycommon_ioctl
	 * zaps.  We know that ttycommon_ioctl doesn't know any CONS*
	 * ioctls, so keep the others safe too.
	 */
	DEBUGCONT2(XENCONS_DEBUG_IOCTL, "async%d_ioctl: %s\n",
	    instance,
	    iocp->ioc_cmd == TIOCMGET ? "TIOCMGET" :
	    iocp->ioc_cmd == TIOCMSET ? "TIOCMSET" :
	    iocp->ioc_cmd == TIOCMBIS ? "TIOCMBIS" :
	    iocp->ioc_cmd == TIOCMBIC ? "TIOCMBIC" : "other");

	switch (iocp->ioc_cmd) {
	case TIOCMGET:
	case TIOCGPPS:
	case TIOCSPPS:
	case TIOCGPPSEV:
	case CONSOPENPOLLEDIO:
	case CONSCLOSEPOLLEDIO:
	case CONSSETABORTENABLE:
	case CONSGETABORTENABLE:
		error = -1; /* Do Nothing */
		break;
	default:

		/*
		 * The only way in which "ttycommon_ioctl" can fail is if the
		 * "ioctl" requires a response containing data to be returned
		 * to the user, and no mblk could be allocated for the data.
		 * No such "ioctl" alters our state.  Thus, we always go ahead
		 * and do any state-changes the "ioctl" calls for.  If we
		 * couldn't allocate the data, "ttycommon_ioctl" has stashed
		 * the "ioctl" away safely, so we just call "bufcall" to
		 * request that we be called back when we stand a better
		 * chance of allocating the data.
		 */
		if ((datasize = ttycommon_ioctl(tp, wq, mp, &error)) != 0) {
			if (async->async_wbufcid)
				unbufcall(async->async_wbufcid);
			async->async_wbufcid = bufcall(datasize, BPRI_HI,
			    (void (*)(void *)) xcasync_reioctl,
			    (void *)(intptr_t)async->async_common->unit);
			return;
		}
	}

	mutex_enter(&xcp->excl);

	if (error == 0) {
		/*
		 * "ttycommon_ioctl" did most of the work; we just use the
		 * data it set up.
		 */
		switch (iocp->ioc_cmd) {

		case TCSETS:
		case TCSETSF:
		case TCSETSW:
		case TCSETA:
		case TCSETAW:
		case TCSETAF:
			break;
		}
	} else if (error < 0) {
		/*
		 * "ttycommon_ioctl" didn't do anything; we process it here.
		 */
		error = 0;
		switch (iocp->ioc_cmd) {

		case TCSBRK:
			error = miocpullup(mp, sizeof (int));
			break;

		case TIOCSBRK:
			mioc2ack(mp, NULL, 0, 0);
			break;

		case TIOCCBRK:
			mioc2ack(mp, NULL, 0, 0);
			break;

		case CONSOPENPOLLEDIO:
			error = miocpullup(mp, sizeof (cons_polledio_arg_t));
			if (error != 0)
				break;

			*(cons_polledio_arg_t *)mp->b_cont->b_rptr =
			    (cons_polledio_arg_t)&xcp->polledio;

			mp->b_datap->db_type = M_IOCACK;
			break;

		case CONSCLOSEPOLLEDIO:
			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_error = 0;
			iocp->ioc_rval = 0;
			break;

		case CONSSETABORTENABLE:
			error = secpolicy_console(iocp->ioc_cr);
			if (error != 0)
				break;

			if (iocp->ioc_count != TRANSPARENT) {
				error = EINVAL;
				break;
			}

			if (*(intptr_t *)mp->b_cont->b_rptr)
				xcp->flags |= ASY_CONSOLE;
			else
				xcp->flags &= ~ASY_CONSOLE;

			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_error = 0;
			iocp->ioc_rval = 0;
			break;

		case CONSGETABORTENABLE:
			/*CONSTANTCONDITION*/
			ASSERT(sizeof (boolean_t) <= sizeof (boolean_t *));
			/*
			 * Store the return value right in the payload
			 * we were passed.  Crude.
			 */
			mcopyout(mp, NULL, sizeof (boolean_t), NULL, NULL);
			*(boolean_t *)mp->b_cont->b_rptr =
			    (xcp->flags & ASY_CONSOLE) != 0;
			break;

		default:
			/*
			 * If we don't understand it, it's an error.  NAK it.
			 */
			error = EINVAL;
			break;
		}
	}
	if (error != 0) {
		iocp->ioc_error = error;
		mp->b_datap->db_type = M_IOCNAK;
	}
	mutex_exit(&xcp->excl);
	qreply(wq, mp);
	DEBUGCONT1(XENCONS_DEBUG_PROCS, "async%d_ioctl: done\n", instance);
}

static int
xenconsrsrv(queue_t *q)
{
	mblk_t *bp;

	while (canputnext(q) && (bp = getq(q)))
		putnext(q, bp);
	return (0);
}

/*
 * Put procedure for write queue.
 * Respond to M_STOP, M_START, M_IOCTL, and M_FLUSH messages here;
 * set the flow control character for M_STOPI and M_STARTI messages;
 * queue up M_BREAK, M_DELAY, and M_DATA messages for processing
 * by the start routine, and then call the start routine; discard
 * everything else.  Note that this driver does not incorporate any
 * mechanism to negotiate to handle the canonicalization process.
 * It expects that these functions are handled in upper module(s),
 * as we do in ldterm.
 */
static int
xenconswput(queue_t *q, mblk_t *mp)
{
	struct asyncline *async;
	struct xencons *xcp;

	async = (struct asyncline *)q->q_ptr;
	xcp = async->async_common;

	switch (mp->b_datap->db_type) {

	case M_STOP:
		mutex_enter(&xcp->excl);
		async->async_flags |= ASYNC_STOPPED;
		mutex_exit(&xcp->excl);
		freemsg(mp);
		break;

	case M_START:
		mutex_enter(&xcp->excl);
		if (async->async_flags & ASYNC_STOPPED) {
			async->async_flags &= ~ASYNC_STOPPED;
			xcasync_start(async);
		}
		mutex_exit(&xcp->excl);
		freemsg(mp);
		break;

	case M_IOCTL:
		switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {

		case TCSETSW:
		case TCSETSF:
		case TCSETAW:
		case TCSETAF:
			/*
			 * The changes do not take effect until all
			 * output queued before them is drained.
			 * Put this message on the queue, so that
			 * "xcasync_start" will see it when it's done
			 * with the output before it.  Poke the
			 * start routine, just in case.
			 */
			(void) putq(q, mp);
			mutex_enter(&xcp->excl);
			xcasync_start(async);
			mutex_exit(&xcp->excl);
			break;

		default:
			/*
			 * Do it now.
			 */
			xcasync_ioctl(async, q, mp);
			break;
		}
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			mutex_enter(&xcp->excl);
			/*
			 * Flush our write queue.
			 */
			flushq(q, FLUSHDATA);	/* XXX doesn't flush M_DELAY */
			if (async->async_xmitblk != NULL) {
				freeb(async->async_xmitblk);
				async->async_xmitblk = NULL;
			}
			mutex_exit(&xcp->excl);
			*mp->b_rptr &= ~FLUSHW;	/* it has been flushed */
		}
		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(q), FLUSHDATA);
			qreply(q, mp);	/* give the read queues a crack at it */
		} else {
			freemsg(mp);
		}

		/*
		 * We must make sure we process messages that survive the
		 * write-side flush.
		 */
		mutex_enter(&xcp->excl);
		xcasync_start(async);
		mutex_exit(&xcp->excl);
		break;

	case M_BREAK:
	case M_DELAY:
	case M_DATA:
		/*
		 * Queue the message up to be transmitted,
		 * and poke the start routine.
		 */
		(void) putq(q, mp);
		mutex_enter(&xcp->excl);
		xcasync_start(async);
		mutex_exit(&xcp->excl);
		break;

	case M_STOPI:
		mutex_enter(&xcp->excl);
		mutex_enter(&xcp->excl);
		if (!(async->async_inflow_source & IN_FLOW_USER)) {
			(void) xcasync_flowcontrol_sw_input(xcp, FLOW_STOP,
			    IN_FLOW_USER);
		}
		mutex_exit(&xcp->excl);
		mutex_exit(&xcp->excl);
		freemsg(mp);
		break;

	case M_STARTI:
		mutex_enter(&xcp->excl);
		mutex_enter(&xcp->excl);
		if (async->async_inflow_source & IN_FLOW_USER) {
			(void) xcasync_flowcontrol_sw_input(xcp, FLOW_START,
			    IN_FLOW_USER);
		}
		mutex_exit(&xcp->excl);
		mutex_exit(&xcp->excl);
		freemsg(mp);
		break;

	case M_CTL:
		if (MBLKL(mp) >= sizeof (struct iocblk) &&
		    ((struct iocblk *)mp->b_rptr)->ioc_cmd == MC_POSIXQUERY) {
			((struct iocblk *)mp->b_rptr)->ioc_cmd = MC_HAS_POSIX;
			qreply(q, mp);
		} else {
			freemsg(mp);
		}
		break;

	default:
		freemsg(mp);
		break;
	}
	return (0);
}

/*
 * Retry an "ioctl", now that "bufcall" claims we may be able to allocate
 * the buffer we need.
 */
static void
xcasync_reioctl(void *unit)
{
	int instance = (uintptr_t)unit;
	struct asyncline *async;
	struct xencons *xcp;
	queue_t	*q;
	mblk_t	*mp;

	xcp = ddi_get_soft_state(xencons_soft_state, instance);
	ASSERT(xcp != NULL);
	async = xcp->priv;

	/*
	 * The bufcall is no longer pending.
	 */
	mutex_enter(&xcp->excl);
	async->async_wbufcid = 0;
	if ((q = async->async_ttycommon.t_writeq) == NULL) {
		mutex_exit(&xcp->excl);
		return;
	}
	if ((mp = async->async_ttycommon.t_iocpending) != NULL) {
		/* not pending any more */
		async->async_ttycommon.t_iocpending = NULL;
		mutex_exit(&xcp->excl);
		xcasync_ioctl(async, q, mp);
	} else
		mutex_exit(&xcp->excl);
}


/*
 * debugger/console support routines.
 */

/*
 * put a character out
 * Do not use interrupts.  If char is LF, put out CR, LF.
 */
/*ARGSUSED*/
static void
xenconsputchar(cons_polledio_arg_t arg, uchar_t c)
{
	struct xencons *xcp = xencons_console;
	volatile struct xencons_interface *ifp = xcp->ifp;
	XENCONS_RING_IDX prod;

	if (c == '\n')
		xenconsputchar(arg, '\r');

	/*
	 * domain 0 can use the console I/O...
	 */
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		char	buffer[1];

		buffer[0] = c;
		(void) HYPERVISOR_console_io(CONSOLEIO_write, 1, buffer);
		return;
	}

	/*
	 * domU has to go through dom0 virtual console.
	 */
	while (ifp->out_prod - ifp->out_cons == sizeof (ifp->out))
		(void) HYPERVISOR_yield();

	prod = ifp->out_prod;
	ifp->out[MASK_XENCONS_IDX(prod++, ifp->out)] = c;
	membar_producer();
	ifp->out_prod = prod;
	ec_notify_via_evtchn(xcp->evtchn);
}

/*
 * See if there's a character available. If no character is
 * available, return 0. Run in polled mode, no interrupts.
 */
static boolean_t
xenconsischar(cons_polledio_arg_t arg)
{
	struct xencons *xcp = (struct xencons *)arg;
	volatile struct xencons_interface *ifp = xcp->ifp;

	if (xcp->polldix < xcp->polllen)
		return (B_TRUE);
	/*
	 * domain 0 can use the console I/O...
	 */
	xcp->polldix = 0;
	xcp->polllen = 0;
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		xcp->polllen = HYPERVISOR_console_io(CONSOLEIO_read, 1,
		    (char *)xcp->pollbuf);
		return (xcp->polllen != 0);
	}

	/*
	 * domU has to go through virtual console device.
	 */
	if (ifp->in_prod != ifp->in_cons) {
		XENCONS_RING_IDX cons;

		cons = ifp->in_cons;
		membar_enter();
		xcp->pollbuf[0] = ifp->in[MASK_XENCONS_IDX(cons++, ifp->in)];
		membar_producer();
		ifp->in_cons = cons;
		xcp->polllen = 1;
	}
	return (xcp->polllen != 0);
}

/*
 * Get a character. Run in polled mode, no interrupts.
 */
static int
xenconsgetchar(cons_polledio_arg_t arg)
{
	struct xencons *xcp = (struct xencons *)arg;

	ec_wait_on_evtchn(xcp->evtchn, (int (*)(void *))xenconsischar, arg);

	return (xcp->pollbuf[xcp->polldix++]);
}

static void
xenconserror(int level, const char *fmt, ...)
{
	va_list adx;
	static time_t	last;
	static const char *lastfmt;
	time_t now;

	/*
	 * Don't print the same error message too often.
	 * Print the message only if we have not printed the
	 * message within the last second.
	 * Note: that fmt cannot be a pointer to a string
	 * stored on the stack. The fmt pointer
	 * must be in the data segment otherwise lastfmt would point
	 * to non-sense.
	 */
	now = gethrestime_sec();
	if (last == now && lastfmt == fmt)
		return;

	last = now;
	lastfmt = fmt;

	va_start(adx, fmt);
	vcmn_err(level, fmt, adx);
	va_end(adx);
}


/*
 * Check for abort character sequence
 */
static boolean_t
abort_charseq_recognize(uchar_t ch)
{
	static int state = 0;
#define	CNTRL(c) ((c)&037)
	static char sequence[] = { '\r', '~', CNTRL('b') };

	if (ch == sequence[state]) {
		if (++state >= sizeof (sequence)) {
			state = 0;
			return (B_TRUE);
		}
	} else {
		state = (ch == sequence[0]) ? 1 : 0;
	}
	return (B_FALSE);
}

/*
 * Flow control functions
 */

/*
 * Software output flow control
 * This function can be executed sucessfully at any situation.
 * It does not handle HW, and just change the SW output flow control flag.
 * INPUT VALUE of onoff:
 *                 FLOW_START means to clear SW output flow control flag,
 *			also set ASYNC_OUT_FLW_RESUME.
 *                 FLOW_STOP means to set SW output flow control flag,
 *			also clear ASYNC_OUT_FLW_RESUME.
 */
static void
xcasync_flowcontrol_sw_output(struct xencons *xcp, async_flowc_action onoff)
{
	struct asyncline *async = xcp->priv;
	int instance = xcp->unit;

	ASSERT(mutex_owned(&xcp->excl));

	if (!(async->async_ttycommon.t_iflag & IXON))
		return;

	switch (onoff) {
	case FLOW_STOP:
		async->async_flags |= ASYNC_SW_OUT_FLW;
		async->async_flags &= ~ASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(XENCONS_DEBUG_SFLOW,
		    "xencons%d: output sflow stop\n", instance);
		break;
	case FLOW_START:
		async->async_flags &= ~ASYNC_SW_OUT_FLW;
		async->async_flags |= ASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(XENCONS_DEBUG_SFLOW,
		    "xencons%d: output sflow start\n", instance);
		break;
	default:
		break;
	}
}

/*
 * Software input flow control
 * This function can execute software input flow control
 * INPUT VALUE of onoff:
 *               FLOW_START means to send out a XON char
 *                          and clear SW input flow control flag.
 *               FLOW_STOP means to send out a XOFF char
 *                          and set SW input flow control flag.
 *               FLOW_CHECK means to check whether there is pending XON/XOFF
 *                          if it is true, send it out.
 * INPUT VALUE of type:
 *		 IN_FLOW_STREAMS means flow control is due to STREAMS
 *		 IN_FLOW_USER means flow control is due to user's commands
 * RETURN VALUE: B_FALSE means no flow control char is sent
 *               B_TRUE means one flow control char is sent
 */
static boolean_t
xcasync_flowcontrol_sw_input(struct xencons *xcp, async_flowc_action onoff,
    int type)
{
	struct asyncline *async = xcp->priv;
	int instance = xcp->unit;
	int rval = B_FALSE;

	ASSERT(mutex_owned(&xcp->excl));

	if (!(async->async_ttycommon.t_iflag & IXOFF))
		return (rval);

	/*
	 * If we get this far, then we know IXOFF is set.
	 */
	switch (onoff) {
	case FLOW_STOP:
		async->async_inflow_source |= type;

		/*
		 * We'll send an XOFF character for each of up to
		 * three different input flow control attempts to stop input.
		 * If we already send out one XOFF, but FLOW_STOP comes again,
		 * it seems that input flow control becomes more serious,
		 * then send XOFF again.
		 */
		if (async->async_inflow_source & (IN_FLOW_STREAMS |
		    IN_FLOW_USER))
			async->async_flags |= ASYNC_SW_IN_FLOW |
			    ASYNC_SW_IN_NEEDED;
		DEBUGCONT2(XENCONS_DEBUG_SFLOW, "xencons%d: input sflow stop, "
		    "type = %x\n", instance, async->async_inflow_source);
		break;
	case FLOW_START:
		async->async_inflow_source &= ~type;
		if (async->async_inflow_source == 0) {
			async->async_flags = (async->async_flags &
			    ~ASYNC_SW_IN_FLOW) | ASYNC_SW_IN_NEEDED;
			DEBUGCONT1(XENCONS_DEBUG_SFLOW, "xencons%d: "
			    "input sflow start\n", instance);
		}
		break;
	default:
		break;
	}

	if (async->async_flags & ASYNC_SW_IN_NEEDED) {
		/*
		 * If we get this far, then we know we need to send out
		 * XON or XOFF char.
		 */
		char c;

		rval = B_TRUE;
		c = (async->async_flags & ASYNC_SW_IN_FLOW) ?
		    async->async_stopc : async->async_startc;
		if (DOMAIN_IS_INITDOMAIN(xen_info)) {
			(void) HYPERVISOR_console_io(CONSOLEIO_write, 1, &c);
			async->async_flags &= ~ASYNC_SW_IN_NEEDED;
			return (rval);
		} else {
			xenconsputchar(NULL, c);
		}
	}
	return (rval);
}

struct module_info xencons_info = {
	0,
	"xencons",
	0,
	INFPSZ,
	4096,
	128
};

static struct qinit xencons_rint = {
	putq,
	xenconsrsrv,
	xenconsopen,
	xenconsclose,
	NULL,
	&xencons_info,
	NULL
};

static struct qinit xencons_wint = {
	xenconswput,
	NULL,
	NULL,
	NULL,
	NULL,
	&xencons_info,
	NULL
};

struct streamtab xencons_str_info = {
	&xencons_rint,
	&xencons_wint,
	NULL,
	NULL
};

static struct cb_ops cb_xencons_ops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&xencons_str_info,		/* cb_stream */
	D_MP			/* cb_flag */
};

struct dev_ops xencons_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	xenconsinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	xenconsattach,		/* devo_attach */
	xenconsdetach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_xencons_ops,	/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a driver */
	"virtual console driver",
	&xencons_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int rv;

	if ((rv = ddi_soft_state_init(&xencons_soft_state,
	    sizeof (struct xencons), 1)) != 0)
		return (rv);
	if ((rv = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&xencons_soft_state);
		return (rv);
	}
	DEBUGCONT2(XENCONS_DEBUG_INIT, "%s, debug = %x\n",
	    modldrv.drv_linkinfo, debug);
	return (0);
}

int
_fini(void)
{
	int rv;

	if ((rv = mod_remove(&modlinkage)) != 0)
		return (rv);

	ddi_soft_state_fini(&xencons_soft_state);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
