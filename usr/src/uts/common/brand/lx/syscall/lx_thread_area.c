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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/cpuvar.h>
#include <sys/archsystm.h>
#include <sys/proc.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_ldt.h>
#include <sys/lx_misc.h>
#include <sys/x86_archext.h>
#include <sys/controlregs.h>
#include <lx_syscall.h>

/* ARGSUSED */
long
lx_arch_prctl(int code, ulong_t addr)
{
#if defined(__amd64)
	klwp_t *lwp = ttolwp(curthread);
	lx_lwp_data_t *llwp = lwptolxlwp(lwp);
	pcb_t *pcb = &lwp->lwp_pcb;

	switch (code) {
	case LX_ARCH_GET_FS:
		if (copyout(&llwp->br_lx_fsbase, (void *)addr,
		    sizeof (llwp->br_lx_fsbase)) != 0) {
			return (set_errno(EFAULT));
		}
		break;

	case LX_ARCH_SET_FS:
		llwp->br_lx_fsbase = addr;

		kpreempt_disable();
		if (pcb->pcb_fsbase != llwp->br_lx_fsbase) {
			pcb->pcb_fsbase = llwp->br_lx_fsbase;

			/*
			 * Ensure we go out via update_sregs.
			 */
			pcb->pcb_rupdate = 1;
		}
		kpreempt_enable();
		break;

	case LX_ARCH_GET_GS:
		if (copyout(&llwp->br_lx_gsbase, (void *)addr,
		    sizeof (llwp->br_lx_gsbase)) != 0) {
			return (set_errno(EFAULT));
		}
		break;

	case LX_ARCH_SET_GS:
		llwp->br_lx_gsbase = addr;

		kpreempt_disable();
		if (pcb->pcb_gsbase != llwp->br_lx_gsbase) {
			pcb->pcb_gsbase = llwp->br_lx_gsbase;

			/*
			 * Ensure we go out via update_sregs.
			 */
			pcb->pcb_rupdate = 1;
		}
		kpreempt_enable();
		break;

	default:
		return (set_errno(EINVAL));
	}
#endif

	return (0);
}

long
lx_get_thread_area(struct ldt_info *inf)
{
	struct lx_lwp_data *jlwp = ttolxlwp(curthread);
	struct ldt_info ldt_inf;
	user_desc_t *dscrp;
	int entry;

	if (fuword32(&inf->entry_number, (uint32_t *)&entry))
		return (set_errno(EFAULT));

	if (entry < GDT_TLSMIN || entry > GDT_TLSMAX)
		return (set_errno(EINVAL));

	dscrp = jlwp->br_tls + entry - GDT_TLSMIN;

	/*
	 * convert the solaris ldt to the linux format expected by the
	 * caller
	 */
	DESC_TO_LDT_INFO(dscrp, &ldt_inf);
	ldt_inf.entry_number = entry;

	if (copyout(&ldt_inf, inf, sizeof (struct ldt_info)))
		return (set_errno(EFAULT));

	return (0);
}

long
lx_set_thread_area(struct ldt_info *inf)
{
	struct lx_lwp_data *jlwp = ttolxlwp(curthread);
	struct ldt_info ldt_inf;
	user_desc_t *dscrp;
	int entry;
	int i;

	if (copyin(inf, &ldt_inf, sizeof (ldt_inf)))
		return (set_errno(EFAULT));

	entry = ldt_inf.entry_number;
	if (entry == -1) {
		/*
		 * Find an empty entry in the tls for this thread.
		 * The casts assume each user_desc_t entry is 8 bytes.
		 */
		for (i = 0, dscrp = jlwp->br_tls; i < LX_TLSNUM; i++, dscrp++) {
			if (((uint_t *)dscrp)[0] == 0 &&
			    ((uint_t *)dscrp)[1] == 0)
				break;
		}

		if (i < LX_TLSNUM) {
			/*
			 * found one
			 */
			entry = i + GDT_TLSMIN;
			if (suword32(&inf->entry_number, entry))
				return (set_errno(EFAULT));
		} else {
			return (set_errno(ESRCH));
		}
	}

	if (entry < GDT_TLSMIN || entry > GDT_TLSMAX)
		return (set_errno(EINVAL));

	/*
	 * convert the linux ldt info to standard intel descriptor
	 */
	dscrp = jlwp->br_tls + entry - GDT_TLSMIN;

	if (LDT_INFO_EMPTY(&ldt_inf)) {
		((uint_t *)dscrp)[0] = 0;
		((uint_t *)dscrp)[1] = 0;
	} else {
		LDT_INFO_TO_DESC(&ldt_inf, dscrp);
	}

	/*
	 * update the gdt with the new descriptor
	 */
	kpreempt_disable();

	for (i = 0, dscrp = jlwp->br_tls; i < LX_TLSNUM; i++, dscrp++)
		lx_set_gdt(GDT_TLSMIN + i, dscrp);

	kpreempt_enable();

	return (0);
}
