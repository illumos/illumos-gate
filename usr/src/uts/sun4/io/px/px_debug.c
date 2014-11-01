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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PCI nexus driver general debug support
 */
#include <sys/sysmacros.h>
#include <sys/async.h>
#include <sys/sunddi.h>		/* dev_info_t */
#include <sys/ddi_impldefs.h>
#include <sys/disp.h>
#include <sys/archsystm.h>	/* getpil() */
#include "px_obj.h"

/*LINTLIBRARY*/

#ifdef	DEBUG
uint64_t px_debug_flags = 0;

static char *px_debug_sym [] = {	/* same sequence as px_debug_bit */
	/*  0 */ "attach",
	/*  1 */ "detach",
	/*  2 */ "map",
	/*  3 */ "nex-ctlops",

	/*  4 */ "introps",
	/*  5 */ "intx-add",
	/*  6 */ "intx-rem",
	/*  7 */ "intx-intr",

	/*  8 */ "msiq",
	/*  9 */ "msiq-intr",
	/* 10 */ "msg",
	/* 11 */ "msg-intr",

	/* 12 */ "msix-add",
	/* 13 */ "msix-rem",
	/* 14 */ "msix-intr",
	/* 15 */ "err",

	/* 16 */ "dma-alloc",
	/* 17 */ "dma-free",
	/* 18 */ "dma-bind",
	/* 19 */ "dma-unbind",

	/* 20 */ "chk-dma-mode",
	/* 21 */ "bypass-dma",
	/* 22 */ "fast-dvma",
	/* 23 */ "init_child",

	/* 24 */ "dma-map",
	/* 25 */ "dma-win",
	/* 26 */ "map-win",
	/* 27 */ "unmap-win",

	/* 28 */ "dma-ctl",
	/* 29 */ "dma-sync",
	/* 30 */ NULL,
	/* 31 */ NULL,

	/* 32 */ "ib",
	/* 33 */ "cb",
	/* 34 */ "dmc",
	/* 35 */ "pec",

	/* 36 */ "ilu",
	/* 37 */ "tlu",
	/* 38 */ "lpu",
	/* 39 */ "mmu",

	/* 40 */ "open",
	/* 41 */ "close",
	/* 42 */ "ioctl",
	/* 43 */ "pwr",

	/* 44 */ "lib-cfg",
	/* 45 */ "lib-intr",
	/* 46 */ "lib-dma",
	/* 47 */ "lib-msiq",

	/* 48 */ "lib-msi",
	/* 49 */ "lib-msg",
	/* 50 */ "NULL",
	/* 51 */ "NULL",

	/* 52 */ "tools",
	/* 53 */ "phys_acc",

	/* 54 */ "hotplug",
	/* LAST */ "unknown"
};

/* Tunables */
static int px_dbg_msg_size = 16;		/* # of Qs.  Must be ^2 */

/* Non-Tunables */
static int px_dbg_qmask = 0xFFFF;		/* Mask based on Q size */
static px_dbg_msg_t *px_dbg_msgq = NULL;	/* Debug Msg Queue */
static uint8_t px_dbg_reference = 0;		/* Reference Counter */
static kmutex_t px_dbg_mutex;			/* Mutex for dequeuing */
static uint8_t px_dbg_qtail = 0;		/* Pointer to q tail */
static uint8_t px_dbg_qhead = 0;		/* Pointer to q head */
static uint_t px_dbg_qsize = 0;			/* # of pending messages */
static uint_t px_dbg_failed = 0;		/* # of overflows */

/* Forward Declarations */
static void px_dbg_print(px_debug_bit_t bit, dev_info_t *dip, char *fmt,
    va_list args);
static void px_dbg_queue(px_debug_bit_t bit, dev_info_t *dip, char *fmt,
    va_list args);
static uint_t px_dbg_drain(caddr_t arg1, caddr_t arg2);

/*
 * Print function called either directly by px_dbg or through soft interrupt.
 * This function cannot be called directly in threads with PIL above clock.
 */
static void
px_dbg_print(px_debug_bit_t bit, dev_info_t *dip, char *fmt, va_list args)
{
	int cont = bit >> DBG_BITS;

	if (cont)
		goto body;

	if (dip)
		prom_printf("%s(%d): %s: ", ddi_driver_name(dip),
		    ddi_get_instance(dip), px_debug_sym[bit]);
	else
		prom_printf("px: %s: ", px_debug_sym[bit]);
body:
	if (args)
		prom_vprintf(fmt, args);
	else
		prom_printf(fmt);
}

/*
 * Queueing mechanism to log px_dbg messages if calling thread is running with a
 * PIL above clock. It's Multithreaded safe.
 */
static void
px_dbg_queue(px_debug_bit_t bit, dev_info_t *dip, char *fmt, va_list args)
{
	int		instance = DIP_TO_INST(dip);
	px_t		*px_p = INST_TO_STATE(instance);
	uint8_t		q_no;
	px_dbg_msg_t	*msg_p;

	/* Check to make sure the queue hasn't overflowed */
	if (atomic_inc_uint_nv(&px_dbg_qsize) >= px_dbg_msg_size) {
		px_dbg_failed++;
		atomic_dec_uint(&px_dbg_qsize);
		return;
	}

	/*
	 * Grab the next available queue bucket. Incrementing the tail here
	 * doesn't need to be protected, as it is guaranteed to not overflow.
	 */
	q_no = ++px_dbg_qtail & px_dbg_qmask;
	msg_p = &px_dbg_msgq[q_no];

	ASSERT(msg_p->active == B_FALSE);

	/* Print the message in the buffer */
	vsnprintf(msg_p->msg, DBG_MSG_SIZE, fmt, args);
	msg_p->bit = bit;
	msg_p->dip = dip;
	msg_p->active = B_TRUE;

	/* Trigger Soft Int */
	ddi_intr_trigger_softint(px_p->px_dbg_hdl, (caddr_t)NULL);
}

/*
 * Callback function for queuing px_dbg in high PIL by soft intr.  This code
 * assumes it will be called serially for every msg.
 */
static uint_t
px_dbg_drain(caddr_t arg1, caddr_t arg2) {
	uint8_t		q_no;
	px_dbg_msg_t	*msg_p;
	uint_t		ret = DDI_INTR_UNCLAIMED;

	mutex_enter(&px_dbg_mutex);
	while (px_dbg_qsize) {
		atomic_dec_uint(&px_dbg_qsize);
		if (px_dbg_failed) {
			cmn_err(CE_WARN, "%d msg(s) were lost",
			    px_dbg_failed);
			px_dbg_failed = 0;
		}

		q_no = ++px_dbg_qhead & px_dbg_qmask;
		msg_p = &px_dbg_msgq[q_no];

		if (msg_p->active) {
			px_dbg_print(msg_p->bit, msg_p->dip, msg_p->msg, NULL);
			msg_p->active = B_FALSE;
		}
		ret = DDI_INTR_CLAIMED;
	}

	mutex_exit(&px_dbg_mutex);
	return (ret);
}

void
px_dbg(px_debug_bit_t bit, dev_info_t *dip, char *fmt, ...)
{
	va_list ap;

	bit &= DBG_MASK;
	if (bit >= sizeof (px_debug_sym) / sizeof (char *))
		return;
	if (!(1ull << bit & px_debug_flags))
		return;

	va_start(ap, fmt);
	if (getpil() > LOCK_LEVEL)
		px_dbg_queue(bit, dip, fmt, ap);
	else
		px_dbg_print(bit, dip, fmt, ap);
	va_end(ap);
}
#endif	/* DEBUG */

void
px_dbg_attach(dev_info_t *dip, ddi_softint_handle_t *dbg_hdl)
{
#ifdef	DEBUG
	if (px_dbg_reference++ == 0) {
		int size = px_dbg_msg_size;

		/* Check if px_dbg_msg_size is ^2 */
		/*
		 * WARNING: The bellow statement makes no sense.  If size is
		 * not a power of 2, it will set size to zero.
		 */
		size = !ISP2(size) ? ((size | ~size) + 1) : size;
		px_dbg_msg_size = size;
		px_dbg_qmask = size - 1;
		px_dbg_msgq = kmem_zalloc(sizeof (px_dbg_msg_t) * size,
		    KM_SLEEP);

		mutex_init(&px_dbg_mutex, NULL, MUTEX_DRIVER, NULL);
	}

	if (ddi_intr_add_softint(dip, dbg_hdl,
		DDI_INTR_SOFTPRI_MAX, px_dbg_drain, NULL) != DDI_SUCCESS) {
		DBG(DBG_ATTACH, dip,
		    "Unable to allocate soft int for DBG printing.\n");
		dbg_hdl = NULL;
	}
#endif	/* DEBUG */
}

/* ARGSUSED */
void
px_dbg_detach(dev_info_t *dip, ddi_softint_handle_t *dbg_hdl)
{
#ifdef	DEBUG
	if (dbg_hdl != NULL)
		(void) ddi_intr_remove_softint(*dbg_hdl);

	if (--px_dbg_reference == 0) {
		if (px_dbg_msgq != NULL)
			kmem_free(px_dbg_msgq,
			    sizeof (px_dbg_msg_t) * px_dbg_msg_size);
		mutex_destroy(&px_dbg_mutex);
	}
#endif	/* DEBUG */
}
