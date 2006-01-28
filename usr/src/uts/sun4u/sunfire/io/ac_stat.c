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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/machparam.h>
#include <sys/modctl.h>
#include <sys/fhc.h>
#include <sys/ac.h>
#include <sys/vm.h>
#include <sys/cpu_module.h>
#include <vm/hat_sfmmu.h>
#include <sys/mem_config.h>
#include <sys/mem_cage.h>

extern ac_err_t ac_kpm_err_cvt(int);

#ifdef DEBUG
static void query_checker(pfn_t, pgcnt_t, memquery_t *);
static int ac_do_query_check = 0;
#endif /* DEBUG */

int
ac_mem_stat(ac_cfga_pkt_t *pkt, int flag)
{
	ac_stat_t		*statp;
	memquery_t		memq;
	struct ac_mem_info	*mem_info;
	struct bd_list		*board;
	struct ac_soft_state	*ac;
	uint64_t		decode;
	uint64_t		base_pa;
	uint64_t		bank_size;
	pfn_t			base;
	pgcnt_t			npgs;
	int			ret;
	int			retval;

	/*
	 * Is the specified bank present?
	 */

	board = fhc_bdlist_lock(pkt->softsp->board);
	if (board == NULL || board->ac_softsp == NULL) {
		fhc_bdlist_unlock();
		AC_ERR_SET(pkt, AC_ERR_BD);
		return (EINVAL);
	}

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
	ASSERT(pkt->softsp == board->ac_softsp);

	ac = pkt->softsp;
	mem_info = &ac->bank[pkt->bank];

	statp = kmem_zalloc(sizeof (ac_stat_t), KM_SLEEP);

	statp->rstate = mem_info->rstate;
	statp->ostate = mem_info->ostate;
	statp->condition = mem_info->condition;
	statp->status_time = mem_info->status_change;
	statp->board = ac->board;
	statp->real_size = mem_info->real_size;
	statp->use_size = mem_info->use_size;
	statp->ac_memctl = *(ac->ac_memctl);
	statp->ac_decode0 = *(ac->ac_memdecode0);
	statp->ac_decode1 = *(ac->ac_memdecode1);

	statp->page_size = PAGESIZE;

	/*
	 * Busy could also be set for fhc_bd_busy(ac->board)
	 * however, this is just advisory information so limit it
	 * to memory operation in progress.
	 */
	statp->busy = (mem_info->busy != FALSE);

	/*
	 * Determine the physical location of the selected bank
	 */
	decode = (pkt->bank == Bank0) ?
	    *(ac->ac_memdecode0) : *(ac->ac_memdecode1);
	base_pa = GRP_REALBASE(decode);
	bank_size = GRP_UK2SPAN(decode);

	base = base_pa >> PAGESHIFT;
	npgs = bank_size >> PAGESHIFT;

	if (mem_info->ostate == SYSC_CFGA_OSTATE_CONFIGURED) {
		bzero(&memq, sizeof (memq));

		ret = kphysm_del_span_query(base, npgs, &memq);

		if (ret != KPHYSM_OK) {
			fhc_bdlist_unlock();
			AC_ERR_SET(pkt, ac_kpm_err_cvt(ret));
			retval = EINVAL;
			goto out;
		}
#ifdef DEBUG
		if (ac_do_query_check) {
			query_checker(base, npgs, &memq);
			if (memq.phys_pages != npgs) {
				/*
				 * This can happen in normal concurrent
				 * operation.
				 */
				cmn_err(CE_WARN, "ac_mem_stat(): "
				    "memq.phys_pages != npgs (%ld != %ld)",
				    (u_long)memq.phys_pages, (u_long)npgs);
			}
		}
#endif /* DEBUG */

		statp->phys_pages = memq.phys_pages;
		statp->managed = memq.managed;
		if (!kcage_on)
			statp->nonrelocatable = memq.phys_pages;
		else
			statp->nonrelocatable = memq.nonrelocatable;
	} else
	if (mem_info->rstate == SYSC_CFGA_RSTATE_CONNECTED) {
		/* Bank is in state Spare */
		statp->phys_pages = npgs;
	}

	fhc_bdlist_unlock();

	retval = DDI_SUCCESS;
	/* return the information to the user */
#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		ac_stat32_t *stat32p;

		stat32p = kmem_zalloc(sizeof (ac_stat32_t), KM_SLEEP);

		stat32p->rstate = statp->rstate;
		stat32p->ostate = statp->ostate;
		stat32p->condition = statp->condition;
		stat32p->status_time = (time32_t)statp->status_time;
		stat32p->board = statp->board;
		stat32p->real_size = statp->real_size;
		stat32p->use_size = statp->use_size;
		stat32p->busy = statp->busy;
		stat32p->page_size = statp->page_size;
		stat32p->phys_pages = statp->phys_pages;
		stat32p->managed = statp->managed;
		stat32p->nonrelocatable = statp->nonrelocatable;
		stat32p->ac_memctl = statp->ac_memctl;
		stat32p->ac_decode0 = statp->ac_decode0;
		stat32p->ac_decode1 = statp->ac_decode1;

		if (ddi_copyout(stat32p, pkt->cmd_cfga.private,
		    sizeof (ac_stat32_t), flag) != 0) {
			retval = EFAULT;
		}
		kmem_free(stat32p, sizeof (ac_stat32_t));
		break;
	}
	case DDI_MODEL_NONE:
		if (ddi_copyout(statp, pkt->cmd_cfga.private,
		    sizeof (ac_stat_t), flag) != 0) {
			retval = EFAULT;
		}
		break;
	}
#else /* _MULTI_DATAMODEL */
	if (ddi_copyout(statp, pkt->cmd_cfga.private,
	    sizeof (ac_stat_t), flag) != 0) {
		retval = EFAULT;
	}
#endif /* _MULTI_DATAMODEL */

out:
	kmem_free(statp, sizeof (ac_stat_t));

	return (retval);
}

#ifdef DEBUG

static void
query_checker(
	pfn_t base,
	pgcnt_t npgs,
	memquery_t *mqp)
{
	memquery_t memq;
	memquery_t amemq;
	int done_first_nonreloc;
	int all_pop;
	pfn_t abase;
	pgcnt_t n;
	int ret;

	all_pop = (mqp->phys_pages == npgs);
	memq.phys_pages = 0;
	memq.managed = 0;
	memq.nonrelocatable = 0;
	memq.first_nonrelocatable = 0;
	memq.last_nonrelocatable = 0;
	done_first_nonreloc = 0;
	for (abase = base, n = npgs; n != 0; abase++, n--) {
		ret = kphysm_del_span_query(abase, 1, &amemq);
		if (ret != KPHYSM_OK) {
			printf("%ld: ret = %d\n", abase, ret);
			continue;
		}
		if (all_pop && amemq.phys_pages != 1) {
			printf("%ld: phys_pages = %ld, expected 1\n",
			    abase, amemq.phys_pages);
		} else
		if (amemq.phys_pages != 0 && amemq.phys_pages != 1) {
			printf("%ld: phys_pages = %ld, expected 0 or 1\n",
			    abase, amemq.phys_pages);
		}
		memq.phys_pages += amemq.phys_pages;
		if (amemq.managed != 0 && amemq.managed != 1) {
			printf("%ld: managed = %ld, expected 0 or 1\n",
			    abase, amemq.managed);
		}
		memq.managed += amemq.managed;
		if (amemq.nonrelocatable != 0 && amemq.nonrelocatable != 1) {
			printf("%ld: nonrelocatable = %ld, expected 0 or 1\n",
			    abase, amemq.nonrelocatable);
		}
		memq.nonrelocatable += amemq.nonrelocatable;
		if (amemq.nonrelocatable != 0) {
			if (amemq.first_nonrelocatable != abase) {
				printf("%ld: first_nonrelocatable = %ld\n",
				    abase, amemq.first_nonrelocatable);
			}
			if (amemq.last_nonrelocatable != abase) {
				printf("%ld: last_nonrelocatable = %ld\n",
				    abase, amemq.last_nonrelocatable);
			}
			if (!done_first_nonreloc) {
				memq.first_nonrelocatable = abase;
				done_first_nonreloc = 1;
			}
			memq.last_nonrelocatable = abase;
		}
	}
	if (mqp->phys_pages != memq.phys_pages) {
		printf("query phys_pages: %ld != %ld\n",
		    mqp->phys_pages, memq.phys_pages);
	}
	if (mqp->managed != memq.managed) {
		printf("query managed: %ld != %ld\n",
		    mqp->managed, memq.managed);
	}
	if (mqp->nonrelocatable != memq.nonrelocatable) {
		printf("query nonrelocatable: %ld != %ld\n",
		    mqp->nonrelocatable, memq.nonrelocatable);
	}
	if (mqp->first_nonrelocatable != memq.first_nonrelocatable) {
		printf("query first_nonrelocatable: %ld != %ld\n",
		    mqp->first_nonrelocatable, memq.first_nonrelocatable);
	}
	if (mqp->last_nonrelocatable != memq.last_nonrelocatable) {
		printf("query last_nonrelocatable: %ld != %ld\n",
		    mqp->last_nonrelocatable, memq.last_nonrelocatable);
	}
}
#endif /* DEBUG */
