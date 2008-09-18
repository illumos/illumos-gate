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
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/cmn_err.h>
#include <vm/hat_sfmmu.h>

#include <sys/iommu.h>
#include <sys/iocache.h>
#include <sys/sysiosbus.h>

#include <sys/nexusdebug.h>
#include <sys/debug.h>

#define	IOCACHE_REGISTERS_DEBUG		0x1
#define	IOCACHE_SYNC_DEBUG		0x2
#define	IOCACHE_DIAG_REG_DEBUG		0x4
#define	IOCACHE_SYNC_FAIL_DEBUG		0x8

#define	MAX_RETRY			10

/* Flag which enables the streaming buffer */
int stream_buf_on = 1;
/*
 * This is the number of pages that a mapping request needs before we force
 * the streaming buffer sync code to use diagnostic registers.  This value
 * was determined through a series of test runs measuring dma mapping
 * setup performance.
 */
int stream_buf_sync_using_diag = 36;

int
stream_buf_init(struct sbus_soft_state *softsp, caddr_t address)
{
	uchar_t version;
#ifdef DEBUG
	debug_info = 1;
	debug_print_level = 0;
#endif
	version = (uchar_t)(*softsp->sysio_ctrl_reg >> SYSIO_VER_SHIFT);
	version &= 0xf;

	if (stream_buf_on == 0 || version == 0) {
		softsp->stream_buf_off = STREAM_BUF_OFF;
		if (version == 0)
			cmn_err(CE_CONT, "Disabling streaming buffer due to "
			    "SYSIO Rev %d.\n", version);
		return (DDI_SUCCESS);
	}

	/*
	 * Simply add each registers offset to the base address
	 * to calculate the already mapped virtual address of
	 * the device register...
	 *
	 * define a macro for the pointer arithmetic; all registers
	 * are 64 bits wide and are defined as uint64_t's.
	 */

#define	REG_ADDR(b, o)	(uint64_t *)((caddr_t)(b) + (o))

	softsp->str_buf_ctrl_reg = REG_ADDR(address, OFF_STR_BUF_CTRL_REG);
	softsp->str_buf_flush_reg = REG_ADDR(address, OFF_STR_BUF_FLUSH_REG);
	softsp->str_buf_sync_reg = REG_ADDR(address, OFF_STR_BUF_SYNC_REG);
	softsp->str_buf_pg_tag_diag = REG_ADDR(address, STR_BUF_PAGE_TAG_DIAG);

#undef	REG_ADDR

	DPRINTF(IOCACHE_REGISTERS_DEBUG, ("Streaming buffer control reg: 0x%p, "
	    "Streaming buffer flush reg: 0x%p, Streaming buffer sync reg: 0x%p",
	    (void *)softsp->str_buf_ctrl_reg, (void *)softsp->str_buf_flush_reg,
	    (void *)softsp->str_buf_sync_reg));

	/* Initialize stream buffer sync reg mutex */
	mutex_init(&softsp->sync_reg_lock, NULL, MUTEX_DEFAULT, NULL);

	/* Turn on per instance streaming buffer flag */
	softsp->stream_buf_off = 0;

	/* Set the hardware registers */
	(void) stream_buf_resume_init(softsp);

	return (DDI_SUCCESS);
}

int
stream_buf_uninit(struct sbus_soft_state *softsp)
{
	/* Turn off per instance streaming buffer flag */
	softsp->stream_buf_off = 1;

	/* Turn off the streaming buffer */
	*softsp->str_buf_ctrl_reg = STREAM_BUF_DISABLE;

	return (DDI_SUCCESS);
}
/*
 * Initialize stream buf hardware when the system is being resumed.
 * (Subset of stream_buf_init())
 */
int
stream_buf_resume_init(struct sbus_soft_state *softsp)
{
	uchar_t version;

	version = (uchar_t)(*softsp->sysio_ctrl_reg >> SYSIO_VER_SHIFT);
	version &= 0xf;

	if (stream_buf_on == 0 || version == 0) {
		softsp->stream_buf_off = STREAM_BUF_OFF;
		return (DDI_SUCCESS);
	}

	/* Turn on the streaming buffer */
	*softsp->str_buf_ctrl_reg = STREAM_BUF_ENABLE;

	return (DDI_SUCCESS);
}

/*
 * The SYSIO spec says that it will get back to us within 0.5 seconds,
 * but loaded systems have seen response times over 1.5 seconds.  We
 * err on the side of caution and set the timeout to be 10 seconds.
 */
#define	SCACHE_NSEC_WAIT	(10ull * NANOSEC)

/*
 * We want to avoid using gethrtime every time we check sync_flag,
 * so we take SCACHE_SPIN laps before beginning to use gethrtime.
 */
#define	SCACHE_SPIN		10000000

void
sync_stream_buf(struct sbus_soft_state *softsp, ioaddr_t addr, uint_t npages,
	int *sync_flag, uint64_t phys_sync_flag)
{
#ifndef lint
	volatile uint64_t tmp;
#endif

	int cntr = 0;

	if (softsp->stream_buf_off != 0)
		return;

	DPRINTF(IOCACHE_SYNC_DEBUG, ("sync_stream_buf: ioaddr 0x%x, page cnt "
	    "0x%x, sync flag 0x%p, sync flag pf 0x%lx\n", addr, npages,
	    (void *)sync_flag, phys_sync_flag));

	ASSERT(npages > (uint_t)0);

	/* Acquire the sync lock */
	mutex_enter(&softsp->sync_reg_lock);

	*sync_flag = 0;

	if (npages > stream_buf_sync_using_diag) {
		int i;
		volatile uint64_t *reg_addr;
		uint64_t reg;
		uint_t ioaddr;
		uint_t hiaddr = addr + (npages * IOMMU_PAGESIZE);
		int do_sync = 0;

		for (i = 0, reg_addr = softsp->str_buf_pg_tag_diag;
		    i < STREAM_CACHE_LINES; i++, reg_addr++) {

			/* Read the page tag diag reg */
			reg = *reg_addr;
#ifdef DEBUG
			{
				uint_t hi, lo;
				hi = (uint_t)(reg >> 32);
				lo = (uint_t)(reg & 0xffffffff);
				DPRINTF(IOCACHE_DIAG_REG_DEBUG,
				    ("IO cache line diag "
				    "reg addr 0x%p, hi0x%x lo0x%x\n",
				    (void *)reg_addr, hi, lo));
			}
#endif /* DEBUG */
			/* Check for a valid line */
			if (reg & STR_PG_VALID) {
				ioaddr = (uint_t)reg << STR_PG_SHIFT;

				DPRINTF(IOCACHE_DIAG_REG_DEBUG, ("ioaddr 0x%x, "
				    "range base 0x%x, range extent 0x%x\n",
				    ioaddr, addr,
				    addr + (npages * IOMMU_PAGESIZE)));
				if (ioaddr >= addr && ioaddr <= hiaddr) {
					*softsp->str_buf_flush_reg = (uint64_t)
					    ioaddr;
					do_sync = 1;
				}
			}
		}

		if (!do_sync) {
			mutex_exit(&softsp->sync_reg_lock);
			return;
		}
	} else {
		do {
			*softsp->str_buf_flush_reg = (uint64_t)addr;
			addr += IOMMU_PAGESIZE;
			npages--;
		} while (npages > (uint_t)0);
	}

	/* Ask the hardware to flag when the flush is complete */
	*softsp->str_buf_sync_reg = phys_sync_flag;

#ifndef lint
	/*
	 * Due to the sun4u memory models, this noncached load will sync the
	 * order of all prior loads and stores regardless of cacheability.
	 * No membar_stst() is needed after zeroing the flush sync flag.
	 */
	tmp = *softsp->sbus_ctrl_reg;
#endif

	/*
	 * Begin spinning on the hardware sync register.  We'll spin for
	 * a while (SCACHE_SPIN) before using gethrtime, but once that time
	 * is up we'll drop into an inner loop where we use gethrtime on
	 * every iteration.  Once SCACHE_NSEC_WAIT nanoseconds have
	 * elapsed, we'll assume a Bad Thing has happened and toss.
	 */
	while (!*((volatile int *)sync_flag)) {
		if (cntr++ == SCACHE_SPIN) {
			/*
			 * If we're here, then we've spun long enough
			 * to justify use of gethrtime each iteration.
			 */
			hrtime_t nsec_start, nsectowait, nsec_current;
			nsectowait = SCACHE_NSEC_WAIT;
			nsec_current = nsec_start = gethrtime();

			while (!*((volatile int *)sync_flag)) {
				/*
				 * Double check the sync flag again before
				 * we panic in case we get preempted.
				 * See bugid 4126896
				 */
				nsec_current = gethrtime();
				if ((nsec_current - nsec_start) > nsectowait &&
				    !*((volatile int *)sync_flag)) {
					/*
					 * Trouble.  The SYSIO chip has
					 * seemingly gone AWOL.  Vomit.
					 */
					panic("streaming buffer timed out");
				}
			}
		}
	}

	/* Finally, drop the sync lock */
	mutex_exit(&softsp->sync_reg_lock);
}
