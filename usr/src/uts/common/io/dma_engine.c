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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * This is the implementation of the kernel DMA interface for the
 * AT Class machines using Intel 8237A DMAC.
 *
 * The following routines in the interface are implemented:
 *	i_dmae_init()
 *	_dmae_nxcookie()
 *	i_dmae_acquire()
 *	i_dmae_free()
 *	i_dmae_prog()
 *	i_dmae_swsetup()
 *	i_dmae_swstart()
 *	i_dmae_stop()
 *	i_dmae_enable()
 *	i_dmae_disable()
 *	i_dmae_get_best_mode()
 *	i_dmae_get_chan_stat()
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/dma_engine.h>
#include <sys/dma_i8237A.h>

#ifdef DEBUG
#include <sys/promif.h>
static int dmaedebug = 0;
#define	dprintf(x)	if (dmaedebug) prom_printf x
#else
#define	dprintf(x)
#endif


static struct dmae_chnl dmae_stat[NCHANS];
static uintptr_t dmae_call_list[NCHANS] = {0, 0, 0, 0, 0, 0, 0, 0};

/*
 *  routine: i_dmae_init()
 *  purpose: called to initialize the dma interface, the DMAC, and any
 *           dma data structures. Called during system initialization.
 *  caller:  main()
 *  calls:   d37A_init()
 */

int
i_dmae_init(dev_info_t *dip)
{
	int chnl;

	dprintf(("i_dmae_init: initializing dma.\n"));

	/* initialize semaphore map */
	for (chnl = 0; chnl < NCHANS; chnl++) {
		sema_init(&dmae_stat[chnl].dch_lock, 1, NULL, SEMA_DRIVER,
		    (void *)NULL);
	}
	return (d37A_init(dip));
}


/*
 *  routine: i_dmae_acquire()
 *  purpose: Request the semaphore for the indicated channel.
 *           A call_back function can be passed if caller does/cannot
 *           wait for the semaphore.
 *  caller:  drivers
 *  calls:   sema_p(), sema_tryp(), ddi_set_callback()
 */
int
i_dmae_acquire(dev_info_t *dip, int chnl, int (*dmae_waitfp)(), caddr_t arg)
{
#if defined(lint)
	dip = dip;
#endif
	dprintf(("i_dmae_acquire: channel %d, waitfp %p\n",
	    chnl, (void *)dmae_waitfp));

	if (!d37A_dma_valid(chnl))
		return (DDI_FAILURE);

	if (dmae_waitfp == DDI_DMA_SLEEP) {
		sema_p(&dmae_stat[chnl].dch_lock);
	} else if (sema_tryp(&dmae_stat[chnl].dch_lock) == 0) {
		if (dmae_waitfp == DDI_DMA_DONTWAIT) {
			dprintf(("_dma_acquire: channel %d is busy.\n", chnl));
		} else {
			ddi_set_callback(dmae_waitfp, arg,
			    &dmae_call_list[chnl]);
		}
		return (DDI_DMA_NORESOURCES);
	}

	/*
	 * XXX -  save dip for authentication later ??
	 */
	dprintf(("_dma_acquire: channel %d now allocated.\n", chnl));
	return (DDI_SUCCESS);
}


/*
 *  routine: i_dmae_free()
 *  purpose: Release the channel semaphore on chnl. Assumes caller actually
 *           owns the semaphore (no check made for this).
 *  caller:  drivers
 *  calls:   none
 */

int
i_dmae_free(dev_info_t *dip, int chnl)
{
#if defined(lint)
	dip = dip;
#endif
	dprintf(("i_dmae_free: channel %d\n", chnl));

	d37A_dma_release(chnl);
	/*
	 * XXX - should dip be authenticated as the one that did acquire?
	 */
	sema_v(&dmae_stat[chnl].dch_lock);

	if (dmae_call_list[chnl])
		ddi_run_callback(&dmae_call_list[chnl]);
	return (DDI_SUCCESS);
}

/*
 *  routine: i_dmae_get_best_mode()
 *  purpose: confirm that data is aligned for efficient flyby mode
 *  caller:  driver routines.
 *  calls:   d37A_get_best_mode.
 */

uchar_t
i_dmae_get_best_mode(dev_info_t *dip, struct ddi_dmae_req *dmaereqp)
{
#if defined(lint)
	dip = dip;
#endif
	return (d37A_get_best_mode(dmaereqp));
}

/*
 *  routine: _dmae_nxcookie()
 *  purpose: service the interrupt by calling device driver routine for next
 *		DMA cookie.
 *  caller:  d37A_intr()
 *  calls:   routine provided in request structure
 */

ddi_dma_cookie_t *
_dmae_nxcookie(int chnl)
{
	ddi_dma_cookie_t *cookiep = NULL;

	dprintf(("_dmae_nxcookie: chnl %d\n", chnl));

	if (dmae_stat[chnl].proc) {

		cookiep = dmae_stat[chnl].proc(dmae_stat[chnl].procparms);
		/*
		 * expect a cookie pointer from user's routine;
		 * null cookie pointer will terminate chaining
		 */
	}
	return (cookiep);
}


/*
 *  routine: i_dmae_prog()
 *  purpose: Program channel for the to_be_initiated_by_hardware operation.
 *           _dma_acquire is called to request the channel semaphore and
 *	     mode is passed as the sleep parameter.
 *	     The channel is enabled after it is setup.
 *	     Note that the ddi_dmae_req pointer can be to NULL if the mode
 *	     registers have already been setup by a prior call; this implements
 *	     a prog_next() to update the address and count registers.
 *  caller:  driver routines
 *  calls:   d37A_prog_chan()
 */

int
i_dmae_prog(dev_info_t *dip, struct ddi_dmae_req *dmaereqp,
    ddi_dma_cookie_t *cp, int chnl)
{
	struct dmae_chnl *dcp;
	int rval;

#if defined(lint)
	dip = dip;
#endif
	rval = d37A_prog_chan(dmaereqp, cp, chnl);
	if (rval != DDI_SUCCESS) {
		dprintf(("i_dmae_prog: failure on channel %d dmaereq=%p\n",
		    chnl, (void *)dmaereqp));
	} else {
		dprintf(("i_dmae_prog: channel %d dmaereq=%p\n",
		    chnl, (void *)dmaereqp));
		dcp = &dmae_stat[chnl];
		dcp->dch_cookiep = cp;
		if (dmaereqp) {
			dcp->proc = dmaereqp->proc;
			dcp->procparms = dmaereqp->procparms;
		}
		d37A_dma_enable(chnl);
	}
	return (rval);
}


/*
 *  routine: i_dmae_swsetup()
 *  purpose: Setup chan for the operation given in dmacbptr.
 *           _dma_acquire is first called
 *           to request the channel semaphore for chnl; mode is
 *           passed to _dma_acquire().
 *  caller:  driver routines
 *  calls:   d37A_dma_swsetup()
 */

int
i_dmae_swsetup(dev_info_t *dip, struct ddi_dmae_req *dmaereqp,
    ddi_dma_cookie_t *cp, int chnl)
{
	struct dmae_chnl *dcp;
	int rval;

#if defined(lint)
	dip = dip;
#endif
	rval = d37A_dma_swsetup(dmaereqp, cp, chnl);
	if (rval != DDI_SUCCESS) {
		dprintf(("i_dmae_swsetup: failure on channel %d dmaereq=%p\n",
		    chnl, (void *)dmaereqp));
	} else {
		dprintf(("i_dmae_swsetup: channel %d: dmaereq=%p\n",
		    chnl, (void *)dmaereqp));
		dcp = &dmae_stat[chnl];
		dcp->dch_cookiep = cp;
		dcp->proc = dmaereqp->proc;
		dcp->procparms = dmaereqp->procparms;
	}
	return (rval);
}


/*
 *  routine: i_dmae_swstart()
 *  purpose: Start the operation setup by i_dmae_swsetup().
 *  caller:  driver routines
 *  calls:   d37A_dma_swstart().
 */

void
i_dmae_swstart(dev_info_t *dip, int chnl)
{
#if defined(lint)
	dip = dip;
#endif
	dprintf(("i_dmae_swstart: channel %d.\n", chnl));

	d37A_dma_swstart(chnl);
}


/*
 *  routine: i_dmae_stop()
 *  purpose: stop DMA activity on chnl.
 *  caller:  driver routines
 *  calls:   splhi(), _dma_relse(), splx(),
 *           d37A_dma_stop().
 */

void
i_dmae_stop(dev_info_t *dip, int chnl)
{
#if defined(lint)
	dip = dip;
#endif
	dprintf(("i_dmae_stop: channel %d\n", chnl));

	/* call d37A the stop the channel */
	d37A_dma_stop(chnl);

	dmae_stat[chnl].dch_cookiep = NULL;
}


/*
 *  routine: i_dmae_enable()
 *  purpose: Allow the hardware tied to channel chnl to request service
 *           from the DMAC. i_dmae_prog() should have been called prior
 *           to this.
 *  caller:  driver routines.
 *  calls:   d37A_dma_enable()
 */

void
i_dmae_enable(dev_info_t *dip, int chnl)
{
#if defined(lint)
	dip = dip;
#endif
	dprintf(("i_dmae_enable: channel %d\n", chnl));

	d37A_dma_enable(chnl);
}


/*
 *  routine: i_dmae_disable()
 *  purpose: Called to mask off hardware requests on channel chnl. Assumes
 *           the caller owns the channel.
 *  caller:  driver routines.
 *  calls:   d37A_dma_disable()
 */

void
i_dmae_disable(dev_info_t *dip, int chnl)
{
#if defined(lint)
	dip = dip;
#endif
	/* dprintf(("i_dmae_disable: disable channel %d.\n", chnl)); */

	d37A_dma_disable(chnl);

	dmae_stat[chnl].dch_cookiep = NULL;
}


/*
 *  routine: i_dmae_get_chan_stat()
 *  purpose: Obtain the current channel status from the DMAC
 *  caller:  driver routines.
 *  calls:   d37A_get_chan_stat()
 */

void
i_dmae_get_chan_stat(dev_info_t *dip, int chnl, ulong_t *addressp, int *countp)
{
#if defined(lint)
	dip = dip;
#endif
	dprintf(("i_dmae_get_chan_stat: channel %d", chnl));

	d37A_get_chan_stat(chnl, addressp, countp);
}
