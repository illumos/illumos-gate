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

/*
 * zuluvm module
 *
 * Provides services required by the XVR-4000 graphics accelerator (zulu)
 * that are not provided by the ddi. See PSARC 2002/231.
 *
 * Zulu has 2 dma engines with built in MMUs. zuluvm provides TLB miss
 * interrupt support obtaining virtual to physical address translations
 * using the XHAT interface PSARC/2003/517.
 *
 * The module has 3 components. This file, sun4u/vm/zulu_hat.c, and the
 * assembly language routines in sun4u/ml/zulu_asm.s and
 * sun4u/ml/zulu_hat_asm.s.
 *
 * The interrupt handler is a data bearing mondo interrupt handled at TL=1
 * If no translation is found in the zulu hat's tsb, or if the tsb is locked by
 * C code, the handler posts a soft interrupt which wakes up a parked
 * thread belonging to zuludaemon(1M).
 */

#include <sys/conf.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/intr.h>
#include <sys/ddi.h>
#include <sys/sunndi.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/machsystm.h>
#include <sys/ivintr.h>
#include <sys/tnf_probe.h>
#include <sys/intreg.h>
#include <sys/atomic.h>
#include <vm/as.h>
#include <vm/seg_enum.h>
#include <vm/faultcode.h>
#include <sys/dmv.h>
#include <sys/zulumod.h>
#include <sys/zulu_hat.h>

#define	ZULUVM_GET_PAGE(val) \
	(caddr_t)((uintptr_t)(val) & PAGEMASK)
#define	ZULUVM_GET_AS	curthread->t_procp->p_as

#define	ZULUVM_LOCK   mutex_enter(&(zdev->dev_lck))
#define	ZULUVM_UNLOCK mutex_exit(&(zdev->dev_lck))

#define	ZULUVM_SET_STATE(_z, b, c) \
	atomic_cas_32((uint32_t *)&((_z)->zvm.state), c, b)
#define	ZULUVM_GET_STATE(_z) \
	(_z)->zvm.state
#define	ZULUVM_SET_IDLE(_z) \
	(_z)->zvm.state = ZULUVM_STATE_IDLE;

#define	ZULUVM_INO_MASK ((1<<INO_SIZE)-1)
#define	ZULUVM_IGN_MASK ((1<<IGN_SIZE)-1)
#define	ZULUVM_MONDO(_zdev, _n) \
	((ZULUVM_IGN_MASK & _zdev->agentid) << INO_SIZE) | \
	(ZULUVM_INO_MASK & (_n))

static void zuluvm_stop(zuluvm_state_t *, int, char *);
static zuluvm_proc_t *zuluvm_find_proc(zuluvm_state_t *, struct as *);
static int zuluvm_proc_release(zuluvm_state_t *zdev, zuluvm_proc_t *proc);
static int zuluvm_get_intr_props(zuluvm_state_t *zdev, dev_info_t *devi);
static int zuluvm_driver_attach(zuluvm_state_t *);
static int zuluvm_driver_detach(zuluvm_state_t *);
static void zuluvm_retarget_intr(void *arg);
static void zuluvm_do_retarget(zuluvm_state_t *zdev);

extern const unsigned int _mmu_pageshift;

extern int zuluvm_base_pgsize;
static int zuluvm_pagesizes[ZULUM_MAX_PG_SIZES + 1];

int zuluvm_fast_tlb = 1;

zuluvm_state_t *zuluvm_devtab[ZULUVM_MAX_DEV];
kmutex_t zuluvm_lck;

#ifdef DEBUG
int zuluvm_debug_state = 0;
#endif

unsigned long zuluvm_ctx_locked = 0;

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,
	"sun4u support " ZULUVM_MOD_VERSION
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

int
_init(void)
{
	zuluvm_base_pgsize = (_mmu_pageshift - 13) / 3;
	if (zulu_hat_init() != 0) {
		return (ZULUVM_ERROR);
	}
	mutex_init(&zuluvm_lck, NULL, MUTEX_DEFAULT, NULL);
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	mutex_destroy(&zuluvm_lck);
	(void) zulu_hat_destroy();
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * currently the kernel driver makes the following assumptions:
 * - there is only one TLB miss per zulu device handled at
 *   any given time
 *   ==> we only need local data storage per device, not per DMA
 *   ==> a page fault will block the DMA engine until the fault
 *       is resolved
 *   ==> a pagefault will not trigger a zulu DMA context switch
 *
 * If we want to implement asynnchronous zulu page fault, then we
 * need to keep track of outstanding faults while zulu DMA runs
 * in a different context.
 */
static int
zuluvm_write_tte(zuluvm_state_t *zdev, void *arg, caddr_t addr,
    int t_pfn, int t_perm, int t_size, uint64_t tag,
    int tlbtype, int *size)
{
	int error;

	(void) addr;

	ZULUVM_STATS_MISS(zdev, t_size);

	if (tag == 0) { /* not coming from preload */
		int state = ZULUVM_SET_STATE(zdev, ZULUVM_STATE_WRITE_TTE,
				ZULUVM_STATE_INTR_PENDING);
		if (state != ZULUVM_STATE_INTR_PENDING) {
			zuluvm_stop(zdev, state, "zuluvm_write_tte");
			return (ZULUVM_MISS_CANCELED);
		}
	}

	if (!(tlbtype & ZULUVM_ITLB_FLAG) &&
	    t_size != zuluvm_base_pgsize &&
	    t_size != ZULU_TTE4M) {
		t_size = zuluvm_base_pgsize;
		TNF_PROBE_2(zuluvm_write_tte_new_pfn, "zuluvm", /* */,
		    tnf_opaque, t_pfn, t_pfn, tnf_int, pagesize, t_size);
	}
	TNF_PROBE_1(zuluvm_write_tte, "zuluvm", /* */,
	    tnf_opaque, t_pfn, t_pfn);
	/*
	 * if the caller is zuluvm_preload, then we need to pass
	 * back the page size so it can add the right offset.
	 */
	if (size)
		*size = t_size;

	error = zulud_write_tte(zdev, arg, t_size, tag, t_pfn,
		    t_perm, tlbtype);

	return (error);
}

static void
zuluvm_stop(zuluvm_state_t *zdev, int state, char *tag)
{
	int ostate = state;
	while (state != ZULUVM_STATE_STOPPED) {
		state = ZULUVM_SET_STATE(zdev,
			    ZULUVM_STATE_STOPPED, state);
#ifdef DEBUG
		if (zuluvm_debug_state)
			cmn_err(CE_NOTE, "zuluvm_stop(%s): (loop) state %d\n",
			    tag, state);
#endif
	}
	TNF_PROBE_2(zuluvm_stop, "zuluvm", /* */,
	    tnf_string, tag, tag,
	    tnf_int, state, ostate);
	ZULUVM_STATS_CANCEL(zdev);
}

/*
 * Executed with the context of the parked zulu deamon thread,
 * uses zulu_hat_load to resolve the miss.
 * The tte is loaded and miss done called by the function zuluvm_load_tte
 * which is called from zulu_hat
 *
 * This function is synchronized with the zuluvm_as_free.
 * zuluvm_as_free will block until miss servicing is complete.
 *
 * There is a race condition between as_free and the zulu tlb miss
 * soft interrupt:
 *	- queue zulu interrupt
 *	- process dies, as_free runs
 *	- interrupt gets scheduled and runs as_fault on the
 *	  already freed as.
 * This is solved by keeping track of current zulu dma processes
 * and invalidating them in zuluvm_as_free.
 */
uint_t
zuluvm_tlb_handler(caddr_t data)
{
	zuluvm_state_t *zdev = (zuluvm_state_t *)data;
	int	error;
	int	flag = 0;
	int	wait = 0;
	zuluvm_proc_t *proc = NULL;
	struct zulu_hat	*zhat = NULL;
	caddr_t	addr;
	int	tlbtype;
	void	*arg;
	int	state, newstate;

	TNF_PROBE_1(zuluvm_tlb_handler_lwp, "zuluvm", /* */,
	    tnf_opaque, lwp, ttolwp(curthread));

	ZULUVM_LOCK;
	error   = ZULUVM_GET_TLB_ERRCODE(zdev);
	addr    = (caddr_t)ZULUVM_GET_TLB_ADDR(zdev);
	tlbtype = ZULUVM_GET_TLB_TYPE(zdev);
	arg = zdev->zvm.arg;

	/*
	 * select the correct dma engine and remember the
	 * the as_free synchronization flags.
	 */
	switch (tlbtype) {
	case ZULUVM_ITLB1:
	case ZULUVM_DMA1:
		proc = zdev->zvm.proc1;
		flag |= ZULUVM_DO_INTR1;
		wait |= ZULUVM_WAIT_INTR1;
		break;
	case ZULUVM_ITLB2:
	case ZULUVM_DMA2:
		proc = zdev->zvm.proc2;
		flag |= ZULUVM_DO_INTR2;
		wait |= ZULUVM_WAIT_INTR2;
		break;
	}

	state = ZULUVM_SET_STATE(zdev, ZULUVM_STATE_INTR_PENDING,
		    ZULUVM_STATE_INTR_QUEUED);
	newstate = ZULUVM_GET_STATE(zdev);

	TNF_PROBE_2(zuluvm_tlb_handler_state, "zuluvm", /* */,
	    tnf_int, oldstate, state,
	    tnf_int, newstate, newstate);
#ifdef DEBUG
	if (zuluvm_debug_state)
		cmn_err(CE_NOTE, "zuluvm_tlb_handler: state %d\n", state);
#endif
	if (state != ZULUVM_STATE_INTR_PENDING &&
		state != ZULUVM_STATE_INTR_QUEUED) {
		ZULUVM_UNLOCK;

		zuluvm_stop(zdev, state, "softintr1");
		zulud_tlb_done(zdev, arg, tlbtype, ZULUVM_MISS_CANCELED);
		return (1);
	}

	/*
	 * block the as_free callback in case it comes in
	 */
	zdev->intr_flags |= flag;
	ZULUVM_UNLOCK;

	mutex_enter(&zdev->proc_lck);
	/*
	 * check if this as is still valid
	 */
	if (proc == NULL || proc->valid == 0 || proc->zhat == NULL) {
		mutex_exit(&zdev->proc_lck);
		/*
		 * we are on our way out, wake up the as_free
		 * callback if it is waiting for us
		 */
		ZULUVM_LOCK;
		zdev->intr_flags &= ~flag;
		if (zdev->intr_flags | wait)
			cv_broadcast(&zdev->intr_wait);
		ZULUVM_UNLOCK;
		state = ZULUVM_SET_STATE(zdev, ZULUVM_STATE_IDLE,
			    ZULUVM_STATE_INTR_PENDING);
		if (state != ZULUVM_STATE_INTR_PENDING) {
			zuluvm_stop(zdev, state, "softintr3");
		}
		zulud_tlb_done(zdev, arg, tlbtype, ZULUVM_NO_HAT);
		return (1);
	}
	zhat = proc->zhat;
	mutex_exit(&zdev->proc_lck);

	TNF_PROBE_1(zuluvm_tlb_handler, "zuluvm", /* */,
	    tnf_opaque, addr, addr);

	switch (error) {
	case ZULUVM_CTX_LOCKED:
		/*
		 * trap handler found that zulu_hat had the lock bit set
		 * rather than block in the fast trap handler, it punts
		 * in this rare instance
		 */
		++zuluvm_ctx_locked;
		TNF_PROBE_1(zuluvm_ctx_locked, "zuluvm", /* CSTYLED */,
			tnf_ulong, zuluvm_ctx_locked, zuluvm_ctx_locked);

		/*FALLTHROUGH*/

	case ZULUVM_TTE_DELAY:
		/*
		 * fast tlb handler was skipped, see zuluvm_fast_tlb flag
		 */
		/*FALLTHROUGH*/

	case ZULUVM_NO_TTE:
		/*
		 * no TSB entry and TTE in the hash
		 */
		mutex_enter(&zdev->load_lck);
		zdev->in_intr = 1;
		error = zulu_hat_load(zhat,  addr,
			(tlbtype == ZULUVM_DMA2) ? S_WRITE : S_READ, NULL);
		zdev->in_intr = 0;
		mutex_exit(&zdev->load_lck);
		if (error) {

			error = ZULUVM_NO_MAP;
		} else {
			error = ZULUVM_SUCCESS;
			TNF_PROBE_1(zuluvm_tlb_handler_done, "zuluvm", /* */,
				    tnf_int, error, error);
			return (1);
		}

	default:
		/*
		 * error case, fall through and tell zulu driver to abort DMA
		 */
		break;
	}

	if (error != ZULUVM_MISS_CANCELED) {
		state = ZULUVM_SET_STATE(zdev, ZULUVM_STATE_IDLE,
			    ZULUVM_STATE_WRITE_TTE);
		newstate = ZULUVM_GET_STATE(zdev);
		TNF_PROBE_2(zuluvm_tlb_handler_state_done, "zuluvm", /* */,
		    tnf_int, oldstate, state,
		    tnf_int, newstate, newstate);
		if (state != ZULUVM_STATE_WRITE_TTE) {
			zuluvm_stop(zdev, state, "softintr4");
		}
	}
	/*
	 * synchronize with as_free callback
	 * It will set the wait flag, in that case we send
	 * a wake up.
	 */
	ZULUVM_LOCK;
	zdev->intr_flags &= ~flag;
	if (zdev->intr_flags | wait)
		cv_broadcast(&zdev->intr_wait);
	ZULUVM_UNLOCK;

	TNF_PROBE_1(zuluvm_tlb_handler_done, "zuluvm", /* */,
	    tnf_int, error, error);

	zulud_tlb_done(zdev, arg, tlbtype, error);

	return (1);
}


void
zuluvm_load_tte(struct zulu_hat  *zhat, caddr_t addr, uint64_t pfn,
		int perm, int size)
{
	zuluvm_state_t *zdev = zhat->zdev;
	int		tlbtype = ZULUVM_GET_TLB_TYPE(zdev);

	ASSERT(MUTEX_HELD(&zdev->load_lck));
	ASSERT(pfn != 0);

	if (zdev->in_intr) {
		int		error;
		int		flag = 0;
		int		wait = 0;

		error = zuluvm_write_tte(zdev, zdev->zvm.arg, addr, pfn,
					perm, size, 0, tlbtype, NULL);

		if (error != ZULUVM_MISS_CANCELED) {
			int	state, newstate;

			state = ZULUVM_SET_STATE(zdev, ZULUVM_STATE_IDLE,
				    ZULUVM_STATE_WRITE_TTE);
			newstate = ZULUVM_GET_STATE(zdev);
			TNF_PROBE_2(zuluvm_tlb_handler_state_done, "zuluvm",
				    /* */, tnf_int, oldstate, state,
				    tnf_int, newstate, newstate);
			if (state != ZULUVM_STATE_WRITE_TTE) {
				zuluvm_stop(zdev, state, "softintr4");
			}
		}
		/*
		 * synchronize with as_free callback
		 * It will set the wait flag, in that case we send
		 * a wake up.
		 */
		switch (tlbtype) {
		case ZULUVM_ITLB1:
		case ZULUVM_DMA1:
			flag = ZULUVM_DO_INTR1;
			wait = ZULUVM_WAIT_INTR1;
			break;
		case ZULUVM_ITLB2:
		case ZULUVM_DMA2:
			flag = ZULUVM_DO_INTR2;
			wait = ZULUVM_WAIT_INTR2;
			break;
		}

		ZULUVM_LOCK;
		zdev->intr_flags &= ~flag;
		if (zdev->intr_flags | wait)
			cv_broadcast(&zdev->intr_wait);
		ZULUVM_UNLOCK;

		zulud_tlb_done(zdev, zdev->zvm.arg, tlbtype, error);
	} else {
		(void) zuluvm_write_tte(zdev, zdev->zvm.arg, addr, pfn,
					perm, size, (uint64_t)addr |
					zhat->zulu_ctx, tlbtype, NULL);
	}
}




/*
 * This function provides the faulting thread for zulu page faults
 * It is call from the device driver in response to an ioctl issued
 * by a zuludaemon thread.
 * It sits in cv_wait_sig until it gets woken up by a signal or
 * zulu tlb miss soft interrupt.
 */
int
zuluvm_park(zuluvm_info_t devp)
{
	int rval;
	zuluvm_state_t *zdev = (zuluvm_state_t *)devp;
	mutex_enter(&zdev->park_lck);
	zdev->parking = 1;
	for (;;) {
		rval = cv_wait_sig(&zdev->park_cv, &zdev->park_lck);
		if (rval == 0)
			break;
		rval = zuluvm_tlb_handler(devp);
	}
	zdev->parking = 0;
	mutex_exit(&zdev->park_lck);
	return (rval);
}

/*
 * zulu soft interrupt handler, just triggers the parked zulu fault
 * thread
 */
/*ARGSUSED*/
uint_t
zuluvm_softintr(caddr_t devp, caddr_t arg2)
{
	int tlbtype;
	void *arg;
	zuluvm_state_t *zdev = (zuluvm_state_t *)devp;
	mutex_enter(&zdev->park_lck);
	if (zdev->parking) {
		cv_signal(&zdev->park_cv);
		mutex_exit(&zdev->park_lck);
		TNF_PROBE_1(zuluvm_fast_intr, "zuluvm", /* */,
		    tnf_opaque, devp, devp);
	} else {
		mutex_exit(&zdev->park_lck);
		cmn_err(CE_NOTE, "zuluvm: no page fault thread\n");
		ZULUVM_LOCK;
		tlbtype = ZULUVM_GET_TLB_TYPE(zdev);
		arg = zdev->zvm.arg;
		ZULUVM_UNLOCK;
		TNF_PROBE_0(zuluvm_fast_intr, "zuluvm", /* */);
		zuluvm_stop(zdev, ZULUVM_STATE_INTR_QUEUED, "fast_intr");
		zulud_tlb_done(zdev, arg, tlbtype, ZULUVM_NO_TTE);
	}
	return (1);
}

/* ***** public interface for process mapping events (hat layer) ***** */

/*
 * If the page size matches the Zulu page sizes then just pass
 * it thru. If not then emulate the page demap with demaps of
 * smaller page size.
 */
/* ARGSUSED */
void
zuluvm_demap_page(void *arg, struct hat *hat_ptr, short ctx,
    caddr_t vaddr, uint_t size)
{
	void *ddarg;
	zuluvm_state_t *zdev = (zuluvm_state_t *)arg;

	if (arg == NULL)
		return;

	ZULUVM_STATS_DEMAP_PAGE(zdev);

	ddarg = zdev->zvm.arg;

	TNF_PROBE_3(zuluvm_demap_page, "zuluvm", /* */,
	    tnf_opaque, addr, vaddr,
	    tnf_int, size, size,
	    tnf_int, ctx, ctx);

	if (ddarg != NULL) {
		if (size != zuluvm_base_pgsize &&
		    size != ZULU_TTE4M) {
			int i;
			int cnt = size - zuluvm_base_pgsize;
			cnt = ZULU_HAT_SZ_SHIFT(cnt);
			for (i = 0; i < cnt; i++) {
				uintptr_t addr = (uintptr_t)vaddr |
				    i << ZULU_HAT_BP_SHIFT;
				zulud_demap_page(zdev, ddarg,
						(caddr_t)addr, ctx);
			}
		} else {
			zulud_demap_page(zdev, ddarg, vaddr, ctx);
		}
		TNF_PROBE_0(zuluvm_demap_page_done, "zuluvm", /* */);
	} else {
		TNF_PROBE_0(zuluvm_demap_page_null_ddarg, "zuluvm", /* */);
	}
}

/*
 * An entire context has gone away, just pass it thru
 */
void
zuluvm_demap_ctx(void *arg, short ctx)
{
	void *ddarg;
	zuluvm_state_t *zdev = (zuluvm_state_t *)arg;

	if (arg == NULL)
		return;

	ZULUVM_STATS_DEMAP_CTX(zdev);

	TNF_PROBE_1(zuluvm_demap_ctx, "zuluvm", /* */,
	    tnf_int, ctx, ctx);
	ddarg = zdev->zvm.arg;

	if (ddarg != NULL)
		zulud_demap_ctx(zdev, ddarg, ctx);
}

static int
zuluvm_driver_attach(zuluvm_state_t *zdev)
{
	int i;
	mutex_enter(&zuluvm_lck);
	for (i = 0; i < ZULUVM_MAX_DEV; i++) {
		if (zuluvm_devtab[i] == NULL) {
			zuluvm_devtab[i] = zdev;
			ZULUVM_SET_IDLE(zdev);
			break;
		}
	}
	mutex_exit(&zuluvm_lck);
	if (i >= ZULUVM_MAX_DEV)
		return (ZULUVM_ERROR);

	if (zulu_hat_attach((void *)zdev) != 0) {
		return (ZULUVM_ERROR);
	}

	mutex_init(&zdev->dev_lck, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&zdev->load_lck, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&zdev->proc_lck, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&zdev->park_lck, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&zdev->park_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&zdev->intr_wait, NULL, CV_DEFAULT, NULL);
	zdev->parking = 0;

#ifdef ZULUVM_STATS
	zdev->zvm.cancel	= 0;
	zdev->zvm.pagefault	= 0;
	zdev->zvm.no_mapping	= 0;
	zdev->zvm.preload	= 0;
	zdev->zvm.migrate	= 0;
	zdev->zvm.pagesize	= 0;
	zdev->zvm.tlb_miss[0]	= 0;
	zdev->zvm.tlb_miss[1]	= 0;
	zdev->zvm.tlb_miss[2]	= 0;
	zdev->zvm.tlb_miss[3]	= 0;
	zdev->zvm.itlb1miss	= 0;
	zdev->zvm.dtlb1miss	= 0;
	zdev->zvm.itlb2miss	= 0;
	zdev->zvm.dtlb2miss	= 0;
#endif
	zdev->zvm.pfncnt = 0;
	for (i = 0; i < 50; i++)
		zdev->zvm.pfnbuf[i] = 0;

	zdev->zvm.mmu_pa  	= NULL;
	zdev->zvm.proc1   	= NULL;
	zdev->zvm.proc2   	= NULL;
	zdev->procs = NULL;
	return (ZULUVM_SUCCESS);
}

static int
zuluvm_driver_detach(zuluvm_state_t *zdev)
{
	int i;
	cv_destroy(&zdev->intr_wait);
	cv_destroy(&zdev->park_cv);
	mutex_destroy(&zdev->park_lck);
	mutex_destroy(&zdev->proc_lck);
	mutex_destroy(&zdev->dev_lck);
	mutex_destroy(&zdev->load_lck);
	zdev->dops = NULL;

	mutex_enter(&zuluvm_lck);
	for (i = 0; i < ZULUVM_MAX_DEV; i++) {
		if (zuluvm_devtab[i] == zdev) {
			zuluvm_devtab[i] = NULL;
			break;
		}
	}
	mutex_exit(&zuluvm_lck);

	if (zulu_hat_detach((void *)zdev) == 0) {
		return (ZULUVM_SUCCESS);
	} else {
		return (ZULUVM_ERROR);
	}
}

zulud_ops_t *zuluvm_dops = NULL;

/*
 * init the zulu kernel driver (variables, locks, etc)
 */
int
zuluvm_init(zulud_ops_t *ops, int **pagesizes)
{
	int error = ZULUVM_SUCCESS;
	int i;
	int size = zuluvm_base_pgsize; /* MMU_PAGESIZE; */

	if (ops->version != ZULUVM_INTERFACE_VERSION)
		return (ZULUVM_VERSION_MISMATCH);

	zuluvm_dops = ops;
	for (i = 0; i < ZULUM_MAX_PG_SIZES && size <= ZULU_TTE4M; i++) {
		zuluvm_pagesizes[i] = size++;
	}
	zuluvm_pagesizes[i] = -1;
	*pagesizes = zuluvm_pagesizes;

	return (error);
}

/*
 * cleanup afterwards
 */
int
zuluvm_fini(void)
{
	zuluvm_dops = NULL;
	return (ZULUVM_SUCCESS);
}

/*
 *     allocate a zulu kernel driver instance for this zulu device
 */
int
zuluvm_alloc_device(dev_info_t *devi, void *arg, zuluvm_info_t *devp,
    caddr_t mmu, caddr_t imr)
{
	uint64_t intr_num;
	zuluvm_state_t *zdev;
	int error = ZULUVM_SUCCESS;

	TNF_PROBE_3(zuluvm_alloc_device, "zuluvm", /* */,
	    tnf_opaque, arg, arg,
	    tnf_opaque, mmu, mmu,
	    tnf_opaque, imr, imr);

	zdev = kmem_zalloc(sizeof (zuluvm_state_t), KM_SLEEP);
	zdev->dip = devi;
	zdev->dops = zuluvm_dops;
	error = zuluvm_driver_attach(zdev);
	if (error != ZULUVM_SUCCESS) {
		kmem_free(zdev, sizeof (zuluvm_state_t));
		return (ZULUVM_NO_DEV);
	}

	ZULUVM_LOCK;
	error = zuluvm_get_intr_props(zdev, devi);
	if (error != ZULUVM_SUCCESS) {
		ZULUVM_UNLOCK;
		error = zuluvm_driver_detach(zdev);
		if (error != ZULUVM_SUCCESS)
			return (error);
		kmem_free(zdev, sizeof (zuluvm_state_t));
		return (ZULUVM_NO_DEV);
	}
	zdev->zvm.arg = arg;
	zdev->zvm.mmu_pa = (uint64_t)va_to_pa((void *)mmu);
	zdev->imr = (uint64_t *)imr;
	zdev->zvm.dmv_intr = dmv_add_softintr(zuluvm_dmv_tlbmiss_tl1,
	    (void *)zdev);
	zulud_set_itlb_pc(zdev, arg, DMV_MAKE_DMV(zdev->zvm.dmv_intr,
	    (void *)zdev));
	zulud_set_dtlb_pc(zdev, arg, DMV_MAKE_DMV(zdev->zvm.dmv_intr,
	    (void *)zdev));
	intr_dist_add(zuluvm_retarget_intr, (void *)zdev);
	zuluvm_do_retarget(zdev);
	intr_num = add_softintr(ZULUVM_PIL, zuluvm_softintr,
	    (caddr_t)zdev, SOFTINT_ST);
	zdev->zvm.intr_num = intr_num;
	*devp = (caddr_t)zdev;
	ZULUVM_UNLOCK;
	TNF_PROBE_1(zuluvm_alloc_device_done, "zuluvm", /* */,
	    tnf_opaque, devp, *devp);
	return (ZULUVM_SUCCESS);
}

/*
 *    free a zulu kernel driver instance
 */
int
zuluvm_free_device(zuluvm_info_t devp)
{
	int error;
	zuluvm_state_t *zdev = (zuluvm_state_t *)devp;

	TNF_PROBE_1(zuluvm_free_device, "zuluvm", /* */,
	    tnf_opaque, zdev, zdev);

	if (zdev == NULL)
		return (ZULUVM_NO_DEV);
	ZULUVM_LOCK;
	if (zdev->zvm.arg == NULL) {
		ZULUVM_UNLOCK;
		TNF_PROBE_1(zuluvm_free_device_done, "zuluvm", /* */,
		    tnf_int, error, ZULUVM_NO_DEV);
		return (ZULUVM_NO_DEV);
	}
	(void) dmv_rem_intr(zdev->zvm.dmv_intr);
	(void) rem_softintr(zdev->zvm.intr_num);
	intr_dist_rem(zuluvm_retarget_intr, (void *)zdev);
	zdev->zvm.arg = NULL;
	ZULUVM_UNLOCK;
	error = zuluvm_driver_detach(zdev);
	if (error != ZULUVM_SUCCESS)
		return (error);
	zdev->dops = NULL;
	kmem_free(zdev, sizeof (zuluvm_state_t));

	TNF_PROBE_0(zuluvm_free_device_done, "zuluvm", /* */);
	return (ZULUVM_SUCCESS);
}

/*
 * find the as in the list of active zulu processes
 * The caller has to hold zdev->proc_lck
 */
static zuluvm_proc_t *
zuluvm_find_proc(zuluvm_state_t *zdev, struct as *asp)
{
	zuluvm_proc_t *p;
	TNF_PROBE_2(zuluvm_find_proc, "zuluvm", /* */,
	    tnf_opaque, zdev, zdev,
	    tnf_opaque, asp, asp);
	for (p = zdev->procs; p != NULL; p = p->next) {
		if (ZULU_HAT2AS(p->zhat) == asp) {
			TNF_PROBE_1(zuluvm_find_proc_done,
			    "zuluvm", /* */, tnf_opaque, proc, p);
			return (p);
		}
	}
	TNF_PROBE_0(zuluvm_find_proc_fail, "zuluvm", /* */);
	return (NULL);
}

void
zuluvm_as_free(struct as *as, void *arg, uint_t events)
{
	zuluvm_proc_t *proc = (zuluvm_proc_t *)arg;
	zuluvm_state_t *zdev = proc->zdev;
	int wait = 0;
	int flag = 0;
	int valid;

	(void) events;

	TNF_PROBE_1(zuluvm_as_free, "zuluvm", /* */,
	    tnf_opaque, arg, arg);

	(void) as_delete_callback(as, arg);
	/*
	 * if this entry is still valid, then we need to sync
	 * with zuluvm_tlb_handler rountine.
	 */
	mutex_enter(&zdev->proc_lck);
	valid = proc->valid;
	proc->valid = 0;
	mutex_exit(&zdev->proc_lck);

	if (valid) {
		ZULUVM_LOCK;
		if (proc == zdev->zvm.proc1) {
			flag |= ZULUVM_WAIT_INTR1;
			wait |= ZULUVM_DO_INTR1;
		}
		if (proc == zdev->zvm.proc2) {
			flag |= ZULUVM_WAIT_INTR2;
			wait |= ZULUVM_DO_INTR2;
		}
		if (flag) {
			zdev->intr_flags |= flag;
			/*
			 * wait until the tlb miss is resloved
			 */
			while (zdev->intr_flags & wait) {
				cv_wait(&zdev->intr_wait, &zdev->dev_lck);
			}
			zdev->intr_flags &= ~flag;
		}
		ZULUVM_UNLOCK;
	}

	if (proc->zhat != NULL) {
		/*
		 * prevent any further tlb miss processing for this hat
		 */
		zulu_hat_terminate(proc->zhat);
	}

	/*
	 * decrement the ref count and do the appropriate
	 * if it drops to zero.
	 */
	mutex_enter(&zdev->proc_lck);
	(void) zuluvm_proc_release(zdev, proc);
	mutex_exit(&zdev->proc_lck);
}

/*
 *	notify zulu vm driver about a new process going to
 *	use zulu DMA. Create a zulu_hat.
 */
int
zuluvm_dma_add_proc(zuluvm_info_t devp, uint64_t *cookie)
{
	zuluvm_proc_t *proc;
	int refcnt;
	struct as *asp = ZULUVM_GET_AS;
	zuluvm_state_t *zdev = (zuluvm_state_t *)devp;

	TNF_PROBE_1(zuluvm_dma_add_proc, "zuluvm", /* */,
	    tnf_opaque, zdev, zdev);
	mutex_enter(&zdev->proc_lck);
	proc = zuluvm_find_proc(zdev, asp);
	if (proc == NULL) {
		proc = kmem_zalloc(sizeof (zuluvm_proc_t), KM_SLEEP);
		proc->zhat = zulu_hat_proc_attach(asp, zdev);
		if (proc->zhat == NULL) {
			mutex_exit(&zdev->proc_lck);
			kmem_free(proc, sizeof (zuluvm_proc_t));
			TNF_PROBE_2(zuluvm_dma_add_proc_done, "zuluvm", /* */,
			    tnf_int, valid, 0,
			    tnf_int, error, ZULUVM_ERROR);
			return (ZULUVM_ERROR);
		}
		proc->zdev = zdev;
		proc->valid = 1;
		proc->refcnt = 1;
		proc->next = zdev->procs;
		if (zdev->procs)
			zdev->procs->prev = proc;
		proc->prev = NULL;
		zdev->procs = proc;
		proc->refcnt++;
		(void) as_add_callback(asp, zuluvm_as_free, proc,
			AS_FREE_EVENT, 0, -1, KM_SLEEP);
	} else {
		if (proc->valid == 0) {
			mutex_exit(&zdev->proc_lck);
			TNF_PROBE_2(zuluvm_dma_add_proc_done, "zuluvm", /* */,
			    tnf_int, valid, 0,
			    tnf_int, error, ZULUVM_ERROR);
			return (ZULUVM_ERROR);
		}
		proc->refcnt++;
	}
	refcnt = proc->refcnt;
	mutex_exit(&zdev->proc_lck);
	*cookie = (uint64_t)proc;
	TNF_PROBE_2(zuluvm_dma_add_proc_done, "zuluvm", /* */,
	    tnf_int, refcnt, refcnt,
	    tnf_int, error, ZULUVM_SUCCESS);
	return (ZULUVM_SUCCESS);
}

void
zuluvm_proc_hold(zuluvm_state_t *zdev, zuluvm_proc_t *proc)
{
	mutex_enter(&zdev->proc_lck);
	proc->refcnt++;
	mutex_exit(&zdev->proc_lck);
}

/*
 * decrement ref count and free data if it drops to zero
 */
static int
zuluvm_proc_release(zuluvm_state_t *zdev, zuluvm_proc_t *proc)
{
	int refcnt;
	ASSERT(MUTEX_HELD(&zdev->proc_lck));
	refcnt = --proc->refcnt;
	TNF_PROBE_3(zuluvm_proc_release, "zuluvm", /* */,
	    tnf_opaque, zdev, zdev,
	    tnf_opaque, proc, proc,
	    tnf_int, refcnt, refcnt);
	if (refcnt == 0) {
		if (proc->next)
			proc->next->prev = proc->prev;
		if (proc->prev)
			proc->prev->next = proc->next;
		else
			zdev->procs = proc->next;
		kmem_free(proc, sizeof (zuluvm_proc_t));
	}
	return (refcnt);
}

/*
 *	this process is not longer using DMA, all entries
 * 	have been removed from the TLB.
 */
int
zuluvm_dma_delete_proc(zuluvm_info_t devp, uint64_t cookie)
{
	int refcnt;
	zuluvm_proc_t *proc = (zuluvm_proc_t *)cookie;
	zuluvm_state_t *zdev = (zuluvm_state_t *)devp;

	TNF_PROBE_2(zuluvm_dma_delete_proc, "zuluvm", /* */,
	    tnf_opaque, zdev, zdev,
	    tnf_opaque, cookie, cookie);
	mutex_enter(&zdev->proc_lck);
	if (proc != NULL) {
		TNF_PROBE_1(zuluvm_dma_delete_proc, "zuluvm", /* */,
		    tnf_opaque, proc, proc);
		if (proc->zhat != NULL) {
			zulu_hat_proc_detach(proc->zhat);
			proc->zhat = NULL;
		}
		refcnt = zuluvm_proc_release(zdev, proc);
	}
	mutex_exit(&zdev->proc_lck);

	TNF_PROBE_2(zuluvm_dma_delete_proc_done, "zuluvm", /* */,
	    tnf_int, refcnt, refcnt,
	    tnf_int, error, ZULUVM_SUCCESS);
	return (ZULUVM_SUCCESS);
}

/*
 * barrier sync for device driver
 * blocks until zuluvm_tlbmiss_tl1 function is done
 */
void
zuluvm_fast_tlb_wait(caddr_t devp)
{
	int state;
	zuluvm_state_t *zdev = (zuluvm_state_t *)devp;
	int cnt = 0;

	do {
		state = ZULUVM_GET_STATE(zdev);
		cnt++;
	} while (state == ZULUVM_STATE_TLB_PENDING);
	TNF_PROBE_1(zuluvm_fast_tlb_wait, "zuluvm", /* */,
	    tnf_int, loop_cnt, cnt);
}

/*
 *     setup DMA handling for this handle
 */
int
zuluvm_dma_alloc_ctx(zuluvm_info_t devp, int dma, short *mmuctx,
    uint64_t *tsbreg)
{
	struct as	*asp = ZULUVM_GET_AS;
	int		error = ZULUVM_NO_DEV;
	zuluvm_state_t    *zdev = (zuluvm_state_t *)devp;
	int 		state, newstate;

	if (asp == NULL) {
		TNF_PROBE_1(zuluvm_dma_alloc_ctx_done, "zuluvm", /* */,
		    tnf_int, error, ZULUVM_NO_HAT);
		return (ZULUVM_NO_HAT);
	}

	*tsbreg = 0;
	state = ZULUVM_SET_STATE(zdev, ZULUVM_STATE_IDLE,
		    ZULUVM_STATE_STOPPED);
	newstate = ZULUVM_GET_STATE(zdev);
	TNF_PROBE_4(zuluvm_dma_alloc_ctx, "zuluvm", /* */,
	    tnf_opaque, devp, devp,
	    tnf_int, dma, dma,
	    tnf_int, oldstate, state,
	    tnf_int, newstate, newstate);
#ifdef DEBUG
	if (zuluvm_debug_state)
		cmn_err(CE_NOTE, "zuluvm_dma_alloc_ctx: state %d\n", state);
#endif
	if (state != ZULUVM_STATE_STOPPED && state != ZULUVM_STATE_IDLE) {
		while (state != ZULUVM_STATE_IDLE) {
			state = ZULUVM_SET_STATE(zdev, ZULUVM_STATE_IDLE,
				    ZULUVM_STATE_STOPPED);
#ifdef DEBUG
			if (zuluvm_debug_state)
				cmn_err(CE_NOTE, "zuluvm_dma_alloc_ctx: (loop)"
				    " state %d\n", state);
#endif
			if (state != ZULUVM_STATE_IDLE)
				delay(1);
		}
	}

	if (zdev->zvm.arg != NULL) {
		struct zulu_hat *zhat;
		zuluvm_proc_t *proc;

		mutex_enter(&zdev->proc_lck);
		proc = zuluvm_find_proc(zdev, asp);
		if (proc != NULL) {
			zhat = proc->zhat;
			proc->refcnt++;
		}
		mutex_exit(&zdev->proc_lck);

		switch (dma) {
		case ZULUVM_DMA1:
			ZULUVM_LOCK;
			zdev->zvm.proc1 = proc;
			ZULUVM_UNLOCK;
			error = ZULUVM_SUCCESS;
			break;
		case ZULUVM_DMA2:
			ZULUVM_LOCK;
			zdev->zvm.proc2 = proc;
			ZULUVM_UNLOCK;
			error = ZULUVM_SUCCESS;
			break;
		default:
			mutex_enter(&zdev->proc_lck);
			(void) zuluvm_proc_release(zdev, proc);
			mutex_exit(&zdev->proc_lck);
		}

		if (error == ZULUVM_SUCCESS) {
			zulu_hat_validate_ctx(zhat);
			if (zhat->zulu_ctx >= 0) {
				*mmuctx = zhat->zulu_ctx;
			} else {
				printf("invalid context value: %d\n",
					zhat->zulu_ctx);

				mutex_enter(&zdev->proc_lck);
				(void) zuluvm_proc_release(zdev, proc);
				mutex_exit(&zdev->proc_lck);

				error = ZULUVM_ERROR;
			}
		} else {
			error = ZULUVM_ERROR;
		}
	}
	TNF_PROBE_1(zuluvm_dma_alloc_ctx_done, "zuluvm", /* */,
	    tnf_int, error, error);
	return (error);
}

/*
 * preload TLB
 * this will try to pre-set the zulu tlb, mainly used for dma engine 2,
 * video read-back.
 */
int
zuluvm_dma_preload(zuluvm_info_t devp, int dma,
			int num, zulud_preload_t *list)
{
	int i;
	int error = ZULUVM_SUCCESS;
	struct zulu_hat *zhat;
	zuluvm_proc_t *proc = NULL;

	zuluvm_state_t *zdev = (zuluvm_state_t *)devp;

	TNF_PROBE_4(zuluvm_dma_preload, "zuluvm", /* */,
	    tnf_opaque, devp, devp,
	    tnf_int, dma, dma,
	    tnf_int, num, num,
	    tnf_opaque, list, list);
	ZULUVM_LOCK;
	switch (dma) {
	case ZULUVM_DMA1:
		proc = zdev->zvm.proc1;
		break;
	case ZULUVM_DMA2:
		proc = zdev->zvm.proc2;
		break;
	}

	mutex_enter(&zdev->proc_lck);
	if (proc == NULL || proc->valid == 0 || proc->zhat == NULL) {
		mutex_exit(&zdev->proc_lck);
		ZULUVM_UNLOCK;
		return (ZULUVM_NO_HAT);
	}
	mutex_exit(&zdev->proc_lck);

	zhat = proc->zhat;
	/*
	 * need to release this to avoid recursive enter in zuluvm_load_tte
	 * which gets called from zulu_hat_memload()
	 */
	ZULUVM_UNLOCK;

	mutex_enter(&zdev->load_lck);
	for (i = 0; i < num; i++) {
		int pg_size;
		int res;
		int first = 1;
		caddr_t addr = ZULUVM_GET_PAGE(list[i].addr);
		int64_t size = (int64_t)list[i].len;
		while (size > 0) {
			if (list[i].tlbtype & ~ZULUVM_DMA_MASK) {
				error = ZULUVM_INVALID_MISS;
				break;
			}
			res = zulu_hat_load(zhat, addr,
			    (list[i].tlbtype == ZULUVM_DMA2) ? S_WRITE : S_READ,
			    &pg_size);
			if ((res != 0) || (pg_size < 0)) {
				error = ZULUVM_NO_MAP;
				break;
			}
			ZULUVM_STATS_PRELOAD(zdev);
			TNF_PROBE_2(zuluvm_dma_preload_addr, "zuluvm", /* */,
			    tnf_opaque, addr, addr,
			    tnf_opaque, size, size);
			if (first) {
				first = 0;
				size -= ZULU_HAT_PGDIFF(list[i].addr,
							pg_size);
			} else {
				size -= ZULU_HAT_PGSZ(pg_size);
			}
			addr += ZULU_HAT_PGSZ(pg_size);
		}
	}
	mutex_exit(&zdev->load_lck);
	TNF_PROBE_1(zuluvm_dma_preload_done, "zuluvm", /* */,
	    tnf_int, error, error);
	return (ZULUVM_SUCCESS);
}

/*
 * destroy DMA handling for this handle
 */
int
zuluvm_dma_free_ctx(zuluvm_info_t devp, int dma)
{
	int error = ZULUVM_NO_DEV;
	zuluvm_state_t *zdev = (zuluvm_state_t *)devp;
	int state, newstate;

	state = ZULUVM_SET_STATE(zdev, ZULUVM_STATE_STOPPED,
		    ZULUVM_STATE_IDLE);
	newstate = ZULUVM_GET_STATE(zdev);
	TNF_PROBE_4(zuluvm_dma_free_ctx, "zuluvm", /* */,
	    tnf_opaque, devp, devp,
	    tnf_int, dma, dma,
	    tnf_int, oldstate, state,
	    tnf_int, newstate, newstate);
#ifdef DEBUG
	if (zuluvm_debug_state)
		cmn_err(CE_NOTE, "zuluvm_dma_free_ctx: state %d\n", state);
#endif
	if (state != ZULUVM_STATE_IDLE && state != ZULUVM_STATE_STOPPED) {
		int doit = 1;
		while (doit) {
			switch (state) {
			case ZULUVM_STATE_CANCELED:
			case ZULUVM_STATE_STOPPED:
				doit = 0;
				break;
			case ZULUVM_STATE_IDLE:
				state = ZULUVM_SET_STATE(zdev,
					    ZULUVM_STATE_STOPPED,
					    ZULUVM_STATE_IDLE);
				break;
			default:
				state = ZULUVM_SET_STATE(zdev,
					    ZULUVM_STATE_CANCELED, state);
			}
			TNF_PROBE_1(zuluvm_dma_free_ctx, "zuluvm", /* */,
			    tnf_int, state, state);
#ifdef DEBUG
			if (zuluvm_debug_state)
				cmn_err(CE_NOTE, "zuluvm_dma_free_ctx: (loop1)"
				    " state %d\n", state);
#endif
		}
	}
	TNF_PROBE_1(zuluvm_dma_free_ctx, "zuluvm", /* */,
	    tnf_int, state, state);

	error = ZULUVM_SUCCESS;
	while (state != ZULUVM_STATE_STOPPED) {
		state = ZULUVM_GET_STATE(zdev);
#ifdef DEBUG
		if (zuluvm_debug_state)
			cmn_err(CE_NOTE, "zuluvm_dma_free: (loop2) state %d\n",
			    state);
#endif
		if (state != ZULUVM_STATE_STOPPED)
			delay(1);
	}
	ZULUVM_LOCK;
	if (zdev->zvm.arg != NULL) {
		zuluvm_proc_t *proc = NULL;
		switch (dma) {
		case ZULUVM_DMA1:
			proc = zdev->zvm.proc1;
			zdev->zvm.proc1 = NULL;
			break;
		case ZULUVM_DMA2:
			proc = zdev->zvm.proc2;
			zdev->zvm.proc2 = NULL;
			break;
		default:
			error = ZULUVM_NO_DEV;
		}
		ZULUVM_UNLOCK;
		if (proc) {
			mutex_enter(&zdev->proc_lck);
			(void) zuluvm_proc_release(zdev, proc);
			mutex_exit(&zdev->proc_lck);
		}
	} else {
		ZULUVM_UNLOCK;
		error = ZULUVM_NO_DEV;
	}
	TNF_PROBE_1(zuluvm_dma_free_ctx_done, "zuluvm", /* */,
	    tnf_int, error, error);
	return (error);
}

static void
zuluvm_do_retarget(zuluvm_state_t *zdev)
{
	int i, idx;
	uint_t cpu;
	for (i = 0; i < ZULUVM_MAX_INTR; i++) {
		if (zdev->interrupts[i].ino != -1) {
			cpu = intr_dist_cpuid();
			idx = zdev->interrupts[i].offset;
			if (zdev->imr[idx] & ZULUVM_IMR_V_MASK)
				zdev->imr[idx] = ZULUVM_IMR_V_MASK |
				    (cpu<<ZULUVM_IMR_TARGET_SHIFT);
			else
				zdev->imr[idx] =
				    cpu<<ZULUVM_IMR_TARGET_SHIFT;
		}
	}
}

static void
zuluvm_retarget_intr(void *arg)
{
	zuluvm_state_t *zdev = (zuluvm_state_t *)arg;
	ZULUVM_LOCK;
	zuluvm_do_retarget(zdev);
	ZULUVM_UNLOCK;
}

int
zuluvm_add_intr(zuluvm_info_t devp, int ino,
		uint_t (*handler)(caddr_t), caddr_t arg)
{
	zuluvm_state_t *zdev = (zuluvm_state_t *)devp;
	if (devp == NULL) {
		TNF_PROBE_1(zuluvm_add_intr_done, "zuluvm", /* */,
		    tnf_int, error, ZULUVM_NO_DEV);
		return (ZULUVM_NO_DEV);
	}
	if (ddi_add_intr(zdev->dip, ino, NULL, NULL, handler, arg)
		!= DDI_SUCCESS) {
		TNF_PROBE_1(zuluvm_add_intr_done, "zuluvm", /* */,
		    tnf_int, error, ZULUVM_ERROR);
		return (ZULUVM_ERROR);
	}
	return (ZULUVM_SUCCESS);
}

int
zuluvm_rem_intr(zuluvm_info_t devp, int ino)
{
	zuluvm_state_t *zdev = (zuluvm_state_t *)devp;
	if (devp == NULL) {
		TNF_PROBE_1(zuluvm_rem_intr_done, "zuluvm", /* */,
		    tnf_int, error, ZULUVM_NO_DEV);
		return (ZULUVM_NO_DEV);
	}
	/* remove from distributin list */
	ZULUVM_LOCK;
	zdev->imr[zdev->interrupts[ino].offset] &= ~ZULUVM_IMR_V_MASK;
	ZULUVM_UNLOCK;
	ddi_remove_intr(zdev->dip, ino, NULL);
	return (ZULUVM_SUCCESS);
}

int
zuluvm_enable_intr(zuluvm_info_t devp, int num)
{
	zuluvm_state_t *zdev = (zuluvm_state_t *)devp;

	TNF_PROBE_2(zuluvm_enable_intr, "zuluvm_intr", /* */,
	    tnf_opaque, devp, devp,
	    tnf_int, num, num);
	if (devp == NULL) {
		TNF_PROBE_1(zuluvm_enable_intr_done, "zuluvm", /* */,
		    tnf_int, error, ZULUVM_NO_DEV);
		return (ZULUVM_NO_DEV);
	}
	if (num < 0 || num > ZULUVM_IMR_MAX) {
		TNF_PROBE_1(zuluvm_enable_intr_done, "zuluvm", /* */,
		    tnf_int, error, ZULUVM_BAD_IDX);
		return (ZULUVM_BAD_IDX);
	}
	ZULUVM_LOCK;
	zdev->imr[num] |= ZULUVM_IMR_V_MASK;
	ZULUVM_UNLOCK;
	TNF_PROBE_1(zuluvm_enable_intr_done, "zuluvm_intr", /* */,
	    tnf_int, error, ZULUVM_SUCCESS);
	return (ZULUVM_SUCCESS);
}

int
zuluvm_disable_intr(zuluvm_info_t devp, int num)
{
	zuluvm_state_t *zdev = (zuluvm_state_t *)devp;

	TNF_PROBE_2(zuluvm_disable_intr, "zuluvm_intr", /* */,
	    tnf_opaque, devp, devp,
	    tnf_int, num, num);
	if (devp == NULL) {
		TNF_PROBE_1(zuluvm_disable_intr_done, "zuluvm", /* */,
		    tnf_int, error, ZULUVM_NO_DEV);
		return (ZULUVM_NO_DEV);
	}
	if (num < 0 || num > ZULUVM_IMR_MAX) {
		TNF_PROBE_1(zuluvm_disable_intr_done, "zuluvm", /* */,
		    tnf_int, error, ZULUVM_BAD_IDX);
		return (ZULUVM_BAD_IDX);
	}
	ZULUVM_LOCK;
	zdev->imr[num] &= ~ZULUVM_IMR_V_MASK;
	ZULUVM_UNLOCK;
	TNF_PROBE_1(zuluvm_disable_intr_done, "zuluvm_intr", /* */,
	    tnf_int, error, ZULUVM_SUCCESS);
	return (ZULUVM_SUCCESS);
}

static int
zuluvm_get_intr_props(zuluvm_state_t *zdev,
			dev_info_t *devi)
{
	int *intr;
	int i;
	uint_t nintr;

	zdev->agentid = ddi_getprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "portid", -1);
	if (zdev->agentid == -1) {
		cmn_err(CE_WARN, "%s%d: no portid property",
		    ddi_get_name(devi),
		    ddi_get_instance(devi));
		return (ZULUVM_ERROR);
	}

	for (i = 0; i < ZULUVM_MAX_INTR; i++) {
		zdev->interrupts[i].offset = 0;
		zdev->interrupts[i].ino = -1;
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "interrupts", &intr, &nintr) == DDI_PROP_SUCCESS) {

		if (nintr == 0) {
			cmn_err(CE_WARN, "%s%d: no interrupts in property",
			    ddi_get_name(devi),
			    ddi_get_instance(devi));
			ddi_prop_free(intr);
			return (ZULUVM_ERROR);
		}
		if (nintr >= ZULUVM_MAX_INTR) {
			cmn_err(CE_WARN, "%s%d: to many interrupts (%d)",
			    ddi_get_name(devi),
			    ddi_get_instance(devi), nintr);
			ddi_prop_free(intr);
			return (ZULUVM_ERROR);
		}
		for (i = 0; i < nintr; i++) {
			zdev->interrupts[i].offset = intr[i];
			zdev->interrupts[i].ino = i;
		}
		ddi_prop_free(intr);
	} else {
		cmn_err(CE_WARN, "%s%d: no interrupts property",
		    ddi_get_name(devi),
		    ddi_get_instance(devi));
	}
	return (ZULUVM_SUCCESS);
}

/* *** enf of zulu *** */
