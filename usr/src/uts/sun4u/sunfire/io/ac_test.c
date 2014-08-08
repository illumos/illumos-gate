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

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/machparam.h>
#include <sys/modctl.h>
#include <sys/atomic.h>
#include <sys/fhc.h>
#include <sys/ac.h>
#include <sys/jtag.h>
#include <sys/cpu_module.h>
#include <sys/spitregs.h>
#include <sys/vm.h>
#include <vm/seg_kmem.h>
#include <vm/hat_sfmmu.h>

/* memory setup parameters */
#define	TEST_PAGESIZE	MMU_PAGESIZE

struct test_info {
	struct test_info	*next;		/* linked list of tests */
	struct ac_mem_info	*mem_info;
	uint_t			board;
	uint_t			bank;
	caddr_t			bufp;		/* pointer to buffer page */
	caddr_t			va;		/* test target VA */
	ac_mem_test_start_t	info;
	uint_t			in_test;	/* count of threads in test */
};

/* list of tests in progress (list protected test_mutex) */
static struct test_info 	*test_base = NULL;
static kmutex_t			test_mutex;
static int			test_mutex_initialized = FALSE;

static mem_test_handle_t	mem_test_sequence_id = 0;

void
ac_mapin(uint64_t pa, caddr_t va)
{
	pfn_t	pfn;
	tte_t	tte;

	pfn = pa >> MMU_PAGESHIFT;
	tte.tte_inthi = TTE_VALID_INT | TTE_SZ_INT(TTE8K) |
	    TTE_PFN_INTHI(pfn);
	tte.tte_intlo = TTE_PFN_INTLO(pfn) | TTE_CP_INT |
	    TTE_PRIV_INT | TTE_LCK_INT | TTE_HWWR_INT;
	sfmmu_dtlb_ld_kva(va, &tte);

}

void
ac_unmap(caddr_t va)
{
	vtag_flushpage(va, (uint64_t)ksfmmup);
}

int
ac_mem_test_start(ac_cfga_pkt_t *pkt, int flag)
{
	struct ac_soft_state	*softsp;
	struct ac_mem_info	*mem_info;
	struct bd_list		*board;
	struct test_info	*test;
	uint64_t		decode;

	/* XXX if ac ever detaches... */
	if (test_mutex_initialized == FALSE) {
		mutex_init(&test_mutex, NULL, MUTEX_DEFAULT, NULL);
		test_mutex_initialized = TRUE;
	}

	/*
	 * Is the specified bank testable?
	 */

	board = fhc_bdlist_lock(pkt->softsp->board);
	if (board == NULL || board->ac_softsp == NULL) {
		fhc_bdlist_unlock();
		AC_ERR_SET(pkt, AC_ERR_BD);
		return (EINVAL);
	}
	ASSERT(pkt->softsp == board->ac_softsp);

	/* verify the board is of the correct type */
	switch (board->sc.type) {
	case CPU_BOARD:
	case MEM_BOARD:
		break;
	default:
		fhc_bdlist_unlock();
		AC_ERR_SET(pkt, AC_ERR_BD_TYPE);
		return (EINVAL);
	}

	/*
	 * Memory must be in the spare state to be testable.
	 * However, spare memory that is testing can't be tested
	 * again, instead return the current test info.
	 */
	softsp = pkt->softsp;
	mem_info = &softsp->bank[pkt->bank];
	if (!MEM_BOARD_VISIBLE(board) ||
	    fhc_bd_busy(softsp->board) ||
	    mem_info->rstate != SYSC_CFGA_RSTATE_CONNECTED ||
	    mem_info->ostate != SYSC_CFGA_OSTATE_UNCONFIGURED) {
		fhc_bdlist_unlock();
		AC_ERR_SET(pkt, AC_ERR_BD_STATE);
		return (EINVAL);
	}
	if (mem_info->busy) {	/* oops, testing? */
		/*
		 * find the test entry
		 */
		ASSERT(test_mutex_initialized);
		mutex_enter(&test_mutex);
		for (test = test_base; test != NULL; test = test->next) {
			if (test->board == softsp->board &&
			    test->bank == pkt->bank)
				break;
		}
		if (test == NULL) {
			mutex_exit(&test_mutex);
			fhc_bdlist_unlock();
			/* Not busy testing. */
			AC_ERR_SET(pkt, AC_ERR_BD_STATE);
			return (EINVAL);
		}

		/*
		 * return the current test information to the new caller
		 */
		if (ddi_copyout(&test->info, pkt->cmd_cfga.private,
		    sizeof (ac_mem_test_start_t), flag) != 0) {
			mutex_exit(&test_mutex);
			fhc_bdlist_unlock();
			return (EFAULT);		/* !broken user app */
		}
		mutex_exit(&test_mutex);
		fhc_bdlist_unlock();
		AC_ERR_SET(pkt, AC_ERR_MEM_BK);
		return (EBUSY);				/* signal bank in use */
	}

	/*
	 * at this point, we have an available bank to test.
	 * create a test buffer
	 */
	test = kmem_zalloc(sizeof (struct test_info), KM_SLEEP);
	test->va = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);

	/* fill in all the test info details now */
	test->mem_info = mem_info;
	test->board = softsp->board;
	test->bank = pkt->bank;
	test->bufp = kmem_alloc(TEST_PAGESIZE, KM_SLEEP);
	test->info.handle = atomic_inc_32_nv(&mem_test_sequence_id);
	(void) drv_getparm(PPID, (ulong_t *)(&(test->info.tester_pid)));
	test->info.prev_condition = mem_info->condition;
	test->info.page_size = TEST_PAGESIZE;
	/* If Blackbird ever gets a variable line size, this will change. */
	test->info.line_size = cpunodes[CPU->cpu_id].ecache_linesize;
	decode = (pkt->bank == Bank0) ?
	    *softsp->ac_memdecode0 : *softsp->ac_memdecode1;
	test->info.afar_base = GRP_REALBASE(decode);
	test->info.bank_size = GRP_UK2SPAN(decode);

	/* return the information to the user */
	if (ddi_copyout(&test->info, pkt->cmd_cfga.private,
	    sizeof (ac_mem_test_start_t), flag) != 0) {

		/* oh well, tear down the test now */
		kmem_free(test->bufp, TEST_PAGESIZE);
		vmem_free(heap_arena, test->va, PAGESIZE);
		kmem_free(test, sizeof (struct test_info));

		fhc_bdlist_unlock();
		return (EFAULT);
	}

	mem_info->busy = TRUE;

	/* finally link us into the test database */
	mutex_enter(&test_mutex);
	test->next = test_base;
	test_base = test;
	mutex_exit(&test_mutex);

	fhc_bdlist_unlock();

#ifdef DEBUG
	cmn_err(CE_NOTE, "!memtest: start test[%u]: board %d, bank %d",
		test->info.handle, test->board, test->bank);
#endif /* DEBUG */
	return (DDI_SUCCESS);
}

int
ac_mem_test_stop(ac_cfga_pkt_t *pkt, int flag)
{
	struct test_info *test, **prev;
	ac_mem_test_stop_t stop;

	/* get test result information */
	if (ddi_copyin(pkt->cmd_cfga.private, &stop,
	    sizeof (ac_mem_test_stop_t), flag) != 0)
		return (EFAULT);

	/* bdlist protects all state changes... */
	(void) fhc_bdlist_lock(-1);

	/* find the test */
	mutex_enter(&test_mutex);
	prev = &test_base;
	for (test = test_base; test != NULL; test = test->next) {
		if (test->info.handle == stop.handle)
			break;			/* found the test */
		prev = &test->next;
	}
	if (test == NULL) {
		mutex_exit(&test_mutex);
		fhc_bdlist_unlock();
		AC_ERR_SET(pkt, AC_ERR_MEM_TEST);
		return (EINVAL);
	}

#ifdef DEBUG
	cmn_err(CE_NOTE,
		"!memtest: stop test[%u]: board %d, bank %d,"
		" condition %d",
		test->info.handle, test->board,
		test->bank, stop.condition);
#endif /* DEBUG */

	/* first unlink us from the test list (to allow no more entries) */
	*prev = test->next;

	/* then, wait for current tests to complete */
	while (test->in_test != 0)
		delay(1);

	mutex_exit(&test_mutex);

	/* clean up the test related allocations */
	vmem_free(heap_arena, test->va, PAGESIZE);
	kmem_free(test->bufp, TEST_PAGESIZE);

	/* update the bank condition accordingly */
	test->mem_info->condition = stop.condition;
	test->mem_info->status_change = ddi_get_time();

	test->mem_info->busy = FALSE;

	/* finally, delete the test element */
	kmem_free(test, sizeof (struct test_info));

	fhc_bdlist_unlock();

	return (DDI_SUCCESS);
}

void
ac_mem_test_stop_on_close(uint_t board, uint_t bank)
{
	struct test_info *test, **prev;
	sysc_cfga_cond_t condition = SYSC_CFGA_COND_UNKNOWN;

	/* bdlist protects all state changes... */
	(void) fhc_bdlist_lock(-1);

	/* find the test */
	mutex_enter(&test_mutex);
	prev = &test_base;
	for (test = test_base; test != NULL; test = test->next) {
		if (test->board == board && test->bank == bank)
			break;			/* found the test */
		prev = &test->next;
	}
	if (test == NULL) {
		/* No test running, nothing to do. */
		mutex_exit(&test_mutex);
		fhc_bdlist_unlock();
		return;
	}

#ifdef DEBUG
	cmn_err(CE_NOTE, "!memtest: stop test[%u] on close: "
	    "board %d, bank %d, condition %d", test->info.handle,
	    test->board, test->bank, condition);
#endif /* DEBUG */

	/* first unlink us from the test list (to allow no more entries) */
	*prev = test->next;

	ASSERT(test->in_test == 0);

	mutex_exit(&test_mutex);

	/* clean up the test related allocations */
	vmem_free(heap_arena, test->va, PAGESIZE);
	kmem_free(test->bufp, TEST_PAGESIZE);

	/* update the bank condition accordingly */
	test->mem_info->condition = condition;
	test->mem_info->status_change = ddi_get_time();

	test->mem_info->busy = FALSE;

	/* finally, delete the test element */
	kmem_free(test, sizeof (struct test_info));

	fhc_bdlist_unlock();
}

int
ac_mem_test_read(ac_cfga_pkt_t *pkt, int flag)
{
	struct test_info *test;
	uint_t page_offset;
	uint64_t page_pa;
	uint_t pstate_save;
	caddr_t	src_va, dst_va;
	uint64_t orig_err;
	int retval = DDI_SUCCESS;
	sunfire_processor_error_regs_t error_buf;
	int error_found;
	ac_mem_test_read_t t_read;

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		ac_mem_test_read32_t t_read32;

		if (ddi_copyin(pkt->cmd_cfga.private, &t_read32,
		    sizeof (ac_mem_test_read32_t), flag) != 0)
			return (EFAULT);
		t_read.handle = t_read32.handle;
		t_read.page_buf = (void *)(uintptr_t)t_read32.page_buf;
		t_read.address = t_read32.address;
		t_read.error_buf = (sunfire_processor_error_regs_t *)
		    (uintptr_t)t_read32.error_buf;
		break;
	}
	case DDI_MODEL_NONE:
		if (ddi_copyin(pkt->cmd_cfga.private, &t_read,
		    sizeof (ac_mem_test_read_t), flag) != 0)
			return (EFAULT);
		break;
	}
#else /* _MULTI_DATAMODEL */
	if (ddi_copyin(pkt->cmd_cfga.private, &t_read,
	    sizeof (ac_mem_test_read_t), flag) != 0)
		return (EFAULT);
#endif /* _MULTI_DATAMODEL */

	/* verify the handle */
	mutex_enter(&test_mutex);
	for (test = test_base; test != NULL; test = test->next) {
		if (test->info.handle == t_read.handle)
			break;
	}
	if (test == NULL) {
		mutex_exit(&test_mutex);
		AC_ERR_SET(pkt, AC_ERR_MEM_TEST);
		return (EINVAL);
	}

	/* bump the busy bit */
	atomic_inc_32(&test->in_test);
	mutex_exit(&test_mutex);

	/* verify the remaining parameters */
	if ((t_read.address.page_num >=
	    test->info.bank_size / test->info.page_size) ||
	    (t_read.address.line_count == 0) ||
	    (t_read.address.line_count >
	    test->info.page_size / test->info.line_size) ||
	    (t_read.address.line_offset >=
	    test->info.page_size / test->info.line_size) ||
	    ((t_read.address.line_offset + t_read.address.line_count) >
	    test->info.page_size / test->info.line_size)) {
		AC_ERR_SET(pkt, AC_ERR_MEM_TEST_PAR);
		retval = EINVAL;
		goto read_done;
	}

	page_offset = t_read.address.line_offset * test->info.line_size;
	page_pa = test->info.afar_base +
	    t_read.address.page_num * test->info.page_size;
	dst_va = test->bufp + page_offset;
	src_va = test->va + page_offset;

	/* time to go quiet */
	kpreempt_disable();

	/* we need a va for the block instructions */
	ac_mapin(page_pa, test->va);

	pstate_save = disable_vec_intr();

	/* disable errors */
	orig_err = get_error_enable();
	set_error_enable(orig_err & ~(EER_CEEN | EER_NCEEN));

	/* copy the data again (using our very special copy) */
	ac_blkcopy(src_va, dst_va, t_read.address.line_count,
	    test->info.line_size);

	/* process errors (if any) */
	error_buf.module_id = CPU->cpu_id;
	get_asyncflt(&(error_buf.afsr));
	get_asyncaddr(&(error_buf.afar));
	get_udb_errors(&(error_buf.udbh_error_reg),
	    &(error_buf.udbl_error_reg));

	/*
	 * clean up after our no-error copy but before enabling ints.
	 * XXX what to do about other error types?
	 */
	if (error_buf.afsr & (P_AFSR_CE | P_AFSR_UE)) {
		extern void clr_datapath(void); /* XXX */

		clr_datapath();
		set_asyncflt(error_buf.afsr);
		retval = EIO;
		error_found = TRUE;
	} else {
		error_found = FALSE;
	}

	/* errors back on */
	set_error_enable(orig_err);

	enable_vec_intr(pstate_save);

	/* tear down translation (who needs an mmu) */
	ac_unmap(test->va);

	/* we're back! */
	kpreempt_enable();

	/*
	 * If there was a data error, attempt to return the error_buf
	 * to the user.
	 */
	if (error_found) {
		if (ddi_copyout(&error_buf, t_read.error_buf,
		    sizeof (sunfire_processor_error_regs_t), flag) != 0) {
			retval = EFAULT;
			/* Keep going */
		}
	}

	/*
	 * Then, return the page to the user (always)
	 */
	if (ddi_copyout(dst_va, (caddr_t)(t_read.page_buf) + page_offset,
	    t_read.address.line_count * test->info.line_size, flag) != 0) {
		retval = EFAULT;
	}

read_done:
	atomic_dec_32(&test->in_test);
	return (retval);
}

int
ac_mem_test_write(ac_cfga_pkt_t *pkt, int flag)
{
	struct test_info *test;
	uint_t page_offset;
	uint64_t page_pa;
	uint_t pstate_save;
	caddr_t	src_va, dst_va;
	int retval = DDI_SUCCESS;
	ac_mem_test_write_t t_write;

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		ac_mem_test_write32_t t_write32;

		if (ddi_copyin(pkt->cmd_cfga.private, &t_write32,
		    sizeof (ac_mem_test_write32_t), flag) != 0)
			return (EFAULT);
		t_write.handle = t_write32.handle;
		t_write.page_buf = (void *)(uintptr_t)t_write32.page_buf;
		t_write.address = t_write32.address;
		break;
	}
	case DDI_MODEL_NONE:
		if (ddi_copyin(pkt->cmd_cfga.private, &t_write,
		    sizeof (ac_mem_test_write_t), flag) != 0)
			return (EFAULT);
		break;
	}
#else /* _MULTI_DATAMODEL */
	if (ddi_copyin(pkt->cmd_cfga.private, &t_write,
	    sizeof (ac_mem_test_write_t), flag) != 0)
		return (EFAULT);
#endif /* _MULTI_DATAMODEL */

	/* verify the handle */
	mutex_enter(&test_mutex);
	for (test = test_base; test != NULL; test = test->next) {
		if (test->info.handle == t_write.handle)
			break;
	}
	if (test == NULL) {
		mutex_exit(&test_mutex);
		return (EINVAL);
	}

	/* bump the busy bit */
	atomic_inc_32(&test->in_test);
	mutex_exit(&test_mutex);

	/* verify the remaining parameters */
	if ((t_write.address.page_num >=
	    test->info.bank_size / test->info.page_size) ||
	    (t_write.address.line_count == 0) ||
	    (t_write.address.line_count >
	    test->info.page_size / test->info.line_size) ||
	    (t_write.address.line_offset >=
	    test->info.page_size / test->info.line_size) ||
	    ((t_write.address.line_offset + t_write.address.line_count) >
	    test->info.page_size / test->info.line_size)) {
		AC_ERR_SET(pkt, AC_ERR_MEM_TEST_PAR);
		retval = EINVAL;
		goto write_done;
	}

	page_offset = t_write.address.line_offset * test->info.line_size;
	page_pa = test->info.afar_base +
	    t_write.address.page_num * test->info.page_size;
	src_va = test->bufp + page_offset;
	dst_va = test->va + page_offset;

	/* copy in the specified user data */
	if (ddi_copyin((caddr_t)(t_write.page_buf) + page_offset, src_va,
	    t_write.address.line_count * test->info.line_size, flag) != 0) {
		retval = EFAULT;
		goto write_done;
	}

	/* time to go quiet */
	kpreempt_disable();

	/* we need a va for the block instructions */
	ac_mapin(page_pa, test->va);

	pstate_save = disable_vec_intr();

	/* copy the data again (using our very special copy) */
	ac_blkcopy(src_va, dst_va, t_write.address.line_count,
	    test->info.line_size);

	enable_vec_intr(pstate_save);

	/* tear down translation (who needs an mmu) */
	ac_unmap(test->va);

	/* we're back! */
	kpreempt_enable();

write_done:
	atomic_dec_32(&test->in_test);
	return (retval);
}
