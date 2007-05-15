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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/machparam.h>
#include <sys/modctl.h>
#include <sys/fhc.h>
#include <sys/ac.h>
#include <sys/vm.h>
#include <sys/cpu_module.h>
#include <vm/seg_kmem.h>
#include <vm/hat_sfmmu.h>
#include <sys/mem_config.h>
#include <sys/mem_cage.h>

/*
 * Default to always clean memory on add to reduce chance
 * of uncorrectable errors.
 */
int ac_add_clean = 1;

#define	ADD_PAGESIZE	MMU_PAGESIZE

ac_err_t
ac_kpm_err_cvt(int err)
{
	switch (err) {
	case KPHYSM_ESPAN:
		return (AC_ERR_KPM_SPAN);
	case KPHYSM_EFAULT:
		return (AC_ERR_KPM_FAULT);
	case KPHYSM_ERESOURCE:
		return (AC_ERR_KPM_RESOURCE);
	case KPHYSM_ENOTSUP:
		return (AC_ERR_KPM_NOTSUP);
	case KPHYSM_ENOHANDLES:
		return (AC_ERR_KPM_NOHANDLES);
	case KPHYSM_ENONRELOC:
		return (AC_ERR_KPM_NONRELOC);
	case KPHYSM_EHANDLE:
		return (AC_ERR_KPM_HANDLE);
	case KPHYSM_EBUSY:
		return (AC_ERR_KPM_BUSY);
	case KPHYSM_ENOTVIABLE:
		return (AC_ERR_KPM_NOTVIABLE);
	case KPHYSM_ESEQUENCE:
		return (AC_ERR_KPM_SEQUENCE);
	case KPHYSM_ENOWORK:
		return (AC_ERR_KPM_NOWORK);
	case KPHYSM_ECANCELLED:
		return (AC_ERR_KPM_CANCELLED);
	case KPHYSM_ENOTFINISHED:
		return (AC_ERR_KPM_NOTFINISHED);
	case KPHYSM_ENOTRUNNING:
		return (AC_ERR_KPM_NOTRUNNING);
	case KPHYSM_EREFUSED:
		return (AC_ERR_KPM_REFUSED);
	case KPHYSM_EDUP:
		return (AC_ERR_KPM_DUP);
	default:
		return (AC_ERR_DEFAULT);
	}
}

static int
ac_add_bank(struct bd_list *add, ac_cfga_pkt_t *pkt)
{
	uint64_t		decode;
	uint64_t		base_pa;
	uint64_t		limit_pa;
	uint64_t		current_pa;
	int			errs;
	uint64_t		bank_size;
	struct ac_mem_info	*mem_info;
	struct ac_soft_state	*asp = pkt->softsp;
	uint_t			ilv;

	/*
	 * Cannot add interleaved banks at the moment.
	 */
	ilv = (pkt->bank == Bank0) ?
	    INTLV0(*asp->ac_memctl) : INTLV1(*asp->ac_memctl);
	if (ilv != 1) {
		AC_ERR_SET(pkt, AC_ERR_MEM_DEINTLV);
		return (EINVAL);
	}
	/*
	 * Determine the physical location of the selected bank
	 */
	decode = (pkt->bank == Bank0) ?
	    *asp->ac_memdecode0 : *asp->ac_memdecode1;
	base_pa = GRP_REALBASE(decode);
	bank_size = GRP_UK2SPAN(decode);
	limit_pa = base_pa + bank_size;

	mem_info = &asp->bank[pkt->bank];
	if (ac_add_clean || mem_info->condition != SYSC_CFGA_COND_OK) {
		caddr_t			base_va;
		caddr_t			fill_buf;
		int			linesize;

		/*
		 * We need a page_va and a fill buffer for this operation
		 */
		base_va = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);
		fill_buf = kmem_zalloc(ADD_PAGESIZE, KM_SLEEP);
		linesize = cpunodes[CPU->cpu_id].ecache_linesize;

		/*
		 * zero fill the memory -- indirectly initializes the ECC
		 */
		kpreempt_disable();
		for (current_pa = base_pa; current_pa < limit_pa;
		    current_pa += ADD_PAGESIZE) {

			/* map current pa */
			ac_mapin(current_pa, base_va);

			/* fill the target page */
			ac_blkcopy(fill_buf, base_va,
				ADD_PAGESIZE/linesize, linesize);

			/* tear down translation */
			ac_unmap(base_va);
		}
		kpreempt_enable();

		/*
		 * clean up temporary resources
		 */
		kmem_free(fill_buf, ADD_PAGESIZE);
		vmem_free(heap_arena, base_va, PAGESIZE);
	}

	/*
	 * give the memory to Solaris
	 */
	errs = kphysm_add_memory_dynamic(base_pa >> PAGESHIFT,
	    bank_size >> PAGESHIFT);

	if (errs != KPHYSM_OK) {
		AC_ERR_SET(pkt, ac_kpm_err_cvt(errs));
		return (EINVAL);
	}

	/*
	 * Add the board to the cage growth list.
	 */
	errs = kcage_range_add(btop(base_pa), btop(bank_size), KCAGE_DOWN);
	/* TODO: deal with error return. */
	if (errs != 0)
		cmn_err(CE_NOTE, "ac_add_bank(): board %d, bank %d, "
		    "kcage_range_add() returned %d",
		    add->sc.board, pkt->bank, errs);

	return (0);
}

int
ac_add_memory(ac_cfga_pkt_t *pkt)
{
	struct bd_list *board;
	struct ac_mem_info *mem_info;
	int force = pkt->cmd_cfga.force;
	int retval;

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

	/* verify the memory condition is acceptable */
	mem_info = &pkt->softsp->bank[pkt->bank];
	if (!MEM_BOARD_VISIBLE(board) || mem_info->busy ||
	    fhc_bd_busy(pkt->softsp->board) ||
	    mem_info->rstate != SYSC_CFGA_RSTATE_CONNECTED ||
	    mem_info->ostate != SYSC_CFGA_OSTATE_UNCONFIGURED ||
	    (!force && mem_info->condition != SYSC_CFGA_COND_OK)) {
		fhc_bdlist_unlock();
		AC_ERR_SET(pkt, AC_ERR_BD_STATE);
		return (EINVAL);
	}

	/*
	 * at this point, we have an available bank to add.
	 * mark it busy and initiate the add function.
	 */
	mem_info->busy = TRUE;
	fhc_bdlist_unlock();

	retval = ac_add_bank(board, pkt);

	/*
	 * We made it!  Update the status and get out of here.
	 */
	(void) fhc_bdlist_lock(-1);
	mem_info->busy = FALSE;
	if (retval == 0) {
		mem_info->ostate = SYSC_CFGA_OSTATE_CONFIGURED;
		mem_info->status_change = ddi_get_time();
	}

	fhc_bdlist_unlock();

	if (retval != 0) {
		return (retval);
	}
	return (DDI_SUCCESS);
}
