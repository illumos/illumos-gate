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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

/*
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1988, 1989 Intel Corp.			*/
/*		All Rights Reserved   				*/

#ifndef	_SYS_DMAENGINE_H
#define	_SYS_DMAENGINE_H

#include <sys/types.h>
#include <sys/dditypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	NCHANS	8

/*
 * the DMA Engine Request structure
 */
struct ddi_dmae_req {
	dev_info_t *der_rdip;	/* original requester's dev_info_t */
	uchar_t der_command;	/* Read/Write/Translate/Verify */
	uchar_t der_bufprocess;	/* NoAuto_init/Chain/Auto_init */
	uchar_t der_step;	/* Inc / Dec / Hold */
	uchar_t der_trans;	/* Single/Demand/Block/Cascade */
	uchar_t der_path;	/* 8/16/32 */
	uchar_t der_cycles;	/* 1 or 2 */
	uchar_t der_dest;	/* Memory / IO */
	uchar_t der_arbus;	/* MicroChannel arbitration reg */
	ushort_t der_ioadr;	/* MicroChannel i/o address reg */
	ddi_dma_cookie_t *(*proc)(); /* address of application call routine */
	void *procparms;	/* parameter buffer for appl call */
};

#define	DMAE_CMD_VRFY    0
#define	DMAE_CMD_WRITE   1	/* from memory to device */
#define	DMAE_CMD_READ    2	/* from device to memory */
#define	DMAE_CMD_TRAN    3

#define	DMAE_BUF_NOAUTO  0	/* default */
#define	DMAE_BUF_CHAIN   0x1
#define	DMAE_BUF_AUTO    0x2

#define	DMAE_STEP_INC    0	/* default */
#define	DMAE_STEP_DEC    1
#define	DMAE_STEP_HOLD   2

#define	DMAE_TRANS_SNGL  0	/* default */
#define	DMAE_TRANS_BLCK  1
#define	DMAE_TRANS_DMND  2
#define	DMAE_TRANS_CSCD  3


/*
 * For the EISA bus
 */
#define	DMAE_PATH_DEF	0	/* default to ISA xfer width */
#define	DMAE_PATH_8	1	/* ISA default for chnl 0..3 */
#define	DMAE_PATH_16	2	/* ISA default for chnl 5..7 */
#define	DMAE_PATH_32	3
#define	DMAE_PATH_64	4
#define	DMAE_PATH_16B	5	/* 16-bit path but byte count */

#define	DMAE_CYCLES_1	0	/* Compatible timing */
#define	DMAE_CYCLES_2	1	/* Type "A" timing */
#define	DMAE_CYCLES_3	2	/* Type "B" timing */
#define	DMAE_CYCLES_4	3	/* Burst timing */

#define	DMAE_DEST_IO	0	/* default */
#define	DMAE_DEST_MEM	1



/* public function routines */
extern int i_dmae_init(dev_info_t *);
extern ddi_dma_cookie_t *_dmae_nxcookie(int);
extern int i_dmae_acquire(dev_info_t *, int, int (*)(), caddr_t);
extern int i_dmae_free(dev_info_t *, int);
extern int i_dmae_prog(dev_info_t *, struct ddi_dmae_req *,
	ddi_dma_cookie_t *, int);
extern int i_dmae_swsetup(dev_info_t *, struct ddi_dmae_req *,
	ddi_dma_cookie_t *, int);
extern void i_dmae_swstart(dev_info_t *, int);
extern void i_dmae_stop(dev_info_t *, int);
extern void i_dmae_enable(dev_info_t *, int);
extern void i_dmae_disable(dev_info_t *, int);
extern void i_dmae_get_chan_stat(dev_info_t *dip, int chnl,
	ulong_t *addressp, int *countp);

/*
 * the DMA Channel Block structure
 */
struct dmae_chnl {
	ksema_t dch_lock;		/* semaphore for this channel */
	ddi_dma_cookie_t *dch_cookiep;	/* current dma mapping cookie */
	ddi_dma_cookie_t *(*proc)();	/* address of application call */
					/* routine */
	void *procparms;		/* parameter buffer for appl call */
};


/*
 * DMA Engine DDI functions
 */

/*
 * Get DMA engine attributes
 *
 * The attributes of the DMA engine of the parent bus-nexus are copied into
 * the provided structure. This should be called at driver attach time,
 * rather than for each DMA bind.
 */

int ddi_dmae_getattr(dev_info_t *dip, ddi_dma_attr_t *attrp);

/*
 * DMA channel allocation
 *
 * The allocation function must be called prior to any other DMA engine
 * function on a channel.  The channel should be freed after completion of the
 * DMA / device operation if the channel is to be shared.
 *
 * Specifics of arguments to ddi_dmae_alloc:
 *
 * dip - dev_info pointer, which identifies the base device that wishes
 * to use the DMA channel.
 *
 * chnl - a DMA channel number.
 *
 * dmae_waitfp - wait/callback_function pointer, which operates in the same
 * manner as in ddi_dma_setup().  The value DDI_DMA_DONTWAIT will cause an
 * immediate return if the channel cannot be acquired.  The value
 * DDI_DMA_SLEEP will will cause the thread to sleep and not return until
 * the channel has been acquired.  Any other value is assumed to be a
 * callback function address.
 *
 * When resources might be available, the callback function is called
 * (with the argument specified in arg) from interrupt context.
 *
 * When the callback function dmae_waitfp() is called, it should attempt to
 * allocate the DMA channel again. If it succeeds or does not need the
 * channel any more, it must return the value DDI_DMA_CALLBACK_DONE.
 * If it does not want to allocate the channel, but instead wishes to be
 * called back again later, it must return the value DDI_DMA_CALLBACK_LATER.
 * If it tries to allocate the channel, but fails to do so, it must return the
 * value DDI_DMA_CALLBACK_RUNOUT.
 *
 * Failure to observe this protocol will have unpredictable results.
 *
 * The callback function must provide its own data structure integrity
 * when it is invoked.
 */

int ddi_dmae_alloc(dev_info_t *dip, int chnl, int (*dmae_waitfp)(),
    caddr_t arg);

/*
 * DMA channel deallocation
 *
 * The deallocation function should be called after completion of the
 * DMA / device operation if the channel is to be shared.
 */

int ddi_dmae_release(dev_info_t *dip, int chnl);

/*
 * DMA channel used in 1st party DMA scheme
 *
 * The specified channel will be configured to operate in a "slave" mode
 * to a first_party DMA engine that also uses the channel.
 */

int ddi_dmae_1stparty(dev_info_t *dip, int chnl);

/*
 * Program DMA channel
 *
 * The DMA channel is setup for an operation using ddi_dmae_prog().
 * This function is implemented to access all capabilities of the DMA engine
 * hardware.  This function disables the channel prior to setup, and enables
 * the channel before returning.
 *
 * Specifics of arguments to ddi_dmae_prog:
 *
 * dmaereqp - pointer to a DMA engine request structure. This structure
 * is implementation specific and contains all the info necessary to
 * setup the channel, except for the memory address and count.
 * This structure is implemented with default values equal to zero,
 * so that normally only der_command has to be set with a read or write
 * command value.  Once the channel has been setup, subsequent calls to
 * ddi_dmae_prog() can have dmaereqp set to NULL if only the address and
 * count have to be updated.
 *
 * cookiep - pointer to a ddi_dma_cookie object which contains address,
 * count and intermediate memory mapping information.
 */

int ddi_dmae_prog(dev_info_t *dip, struct ddi_dmae_req *dmaereqp,
	ddi_dma_cookie_t *cookiep, int chnl);

int ddi_dmae_swsetup(dev_info_t *dip, struct ddi_dmae_req *dmaereqp,
	ddi_dma_cookie_t *cookiep, int chnl);

int ddi_dmae_swstart(dev_info_t *dip, int chnl);

/*
 * Stop DMA channel
 *
 * The DMA channel is disabled and any active operation is terminated.
 */

int ddi_dmae_stop(dev_info_t *dip, int chnl);

/*
 * Enable DMA channel
 *
 * The DMA channel is enabled for operation.  The channel is also enabled
 * after successful setup in ddi_dmae_prog().
 */

int ddi_dmae_enable(dev_info_t *dip, int chnl);

/*
 * Disable DMA channel
 *
 * The DMA channel is disabled so that transfers cannot continue.
 */

int ddi_dmae_disable(dev_info_t *dip, int chnl);

/*
 * Get remaining xfer count
 *
 * The count register of the DMA channel is read.  The channel is assumed
 * to be stopped.
 */

int ddi_dmae_getcnt(dev_info_t *dip, int chnl, int *count);

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_DMAENGINE_H */
