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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/disp.h>
#include <sys/sysmacros.h>
#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/lwp.h>
#include <sys/segments.h>
#include <sys/privregs.h>
#include <sys/cmn_err.h>

int
lwp_setprivate(klwp_t *lwp, int which, uintptr_t base)
{
	pcb_t *pcb = &lwp->lwp_pcb;
	struct regs *rp = lwptoregs(lwp);
	kthread_t *t = lwptot(lwp);
	int thisthread = t == curthread;
	int rval;

	if (thisthread)
		kpreempt_disable();

#if defined(__amd64)

	/*
	 * 32-bit compatibility processes point to the per-cpu GDT segment
	 * descriptors that are virtualized to the lwp.  That allows 32-bit
	 * programs to mess with %fs and %gs; in particular it allows
	 * things like this:
	 *
	 *	movw	%gs, %ax
	 *	...
	 *	movw	%ax, %gs
	 *
	 * to work, which is needed by emulators for legacy application
	 * environments ..
	 *
	 * 64-bit processes may also point to a per-cpu GDT segment descriptor
	 * virtualized to the lwp.  However the descriptor base is forced
	 * to zero (because we can't express the full 64-bit address range
	 * in a long mode descriptor), so don't reload segment registers
	 * in a 64-bit program! 64-bit processes must have selector values
	 * of zero for %fs and %gs to use the 64-bit fs_base and gs_base
	 * respectively.
	 */
	if (!PCB_NEED_UPDATE_SEGS(pcb)) {
		pcb->pcb_ds = rp->r_ds;
		pcb->pcb_es = rp->r_es;
		pcb->pcb_fs = rp->r_fs;
		pcb->pcb_gs = rp->r_gs;
		PCB_SET_UPDATE_SEGS(pcb);
		t->t_post_sys = 1;
	}
	ASSERT(t->t_post_sys);

	switch (which) {
	case _LWP_FSBASE:
		if (lwp_getdatamodel(lwp) == DATAMODEL_NATIVE) {
			set_usegd(&pcb->pcb_fsdesc, SDP_LONG, 0, 0,
			    SDT_MEMRWA, SEL_UPL, SDP_BYTES, SDP_OP32);
			rval = pcb->pcb_fs = 0;	/* null gdt descriptor */
		} else {
			set_usegd(&pcb->pcb_fsdesc, SDP_SHORT, (void *)base, -1,
			    SDT_MEMRWA, SEL_UPL, SDP_PAGES, SDP_OP32);
			rval = pcb->pcb_fs = LWPFS_SEL;
		}
		if (thisthread)
			gdt_update_usegd(GDT_LWPFS, &pcb->pcb_fsdesc);

		pcb->pcb_fsbase = base;
		break;
	case _LWP_GSBASE:
		if (lwp_getdatamodel(lwp) == DATAMODEL_NATIVE) {
			set_usegd(&pcb->pcb_gsdesc, SDP_LONG, 0, 0,
			    SDT_MEMRWA, SEL_UPL, SDP_BYTES, SDP_OP32);
			rval = pcb->pcb_gs = 0;	/* null gdt descriptor */
		} else {
			set_usegd(&pcb->pcb_gsdesc, SDP_SHORT, (void *)base, -1,
			    SDT_MEMRWA, SEL_UPL, SDP_PAGES, SDP_OP32);
			rval = pcb->pcb_gs = LWPGS_SEL;
		}
		if (thisthread)
			gdt_update_usegd(GDT_LWPGS, &pcb->pcb_gsdesc);

		pcb->pcb_gsbase = base;
		break;
	default:
		rval = -1;
		break;
	}

#elif defined(__i386)

	/*
	 * 32-bit processes point to the per-cpu GDT segment
	 * descriptors that are virtualized to the lwp.
	 */

	switch	(which) {
	case _LWP_FSBASE:
		set_usegd(&pcb->pcb_fsdesc, (void *)base, -1,
		    SDT_MEMRWA, SEL_UPL, SDP_PAGES, SDP_OP32);
		if (thisthread)
			gdt_update_usegd(GDT_LWPFS, &pcb->pcb_fsdesc);

		rval = rp->r_fs = LWPFS_SEL;
		break;
	case _LWP_GSBASE:
		set_usegd(&pcb->pcb_gsdesc, (void *)base, -1,
		    SDT_MEMRWA, SEL_UPL, SDP_PAGES, SDP_OP32);
		if (thisthread)
			gdt_update_usegd(GDT_LWPGS, &pcb->pcb_gsdesc);

		rval = rp->r_gs = LWPGS_SEL;
		break;
	default:
		rval = -1;
		break;
	}

#endif	/* __i386 */

	if (thisthread)
		kpreempt_enable();
	return (rval);
}

static int
lwp_getprivate(klwp_t *lwp, int which, uintptr_t base)
{
	pcb_t *pcb = &lwp->lwp_pcb;
	struct regs *rp = lwptoregs(lwp);
	uintptr_t sbase;
	int error = 0;

	ASSERT(lwptot(lwp) == curthread);

	kpreempt_disable();
	switch (which) {
#if defined(__amd64)

	case _LWP_FSBASE:
		if ((sbase = pcb->pcb_fsbase) != 0) {
			if (lwp_getdatamodel(lwp) == DATAMODEL_NATIVE) {
				if (PCB_NEED_UPDATE_SEGS(pcb)) {
					if (pcb->pcb_fs == 0)
						break;
				} else {
					if (rp->r_fs == 0)
						break;
				}
			} else {
				if (PCB_NEED_UPDATE_SEGS(pcb)) {
					if (pcb->pcb_fs == LWPFS_SEL)
						break;
				} else {
					if (rp->r_fs == LWPFS_SEL)
						break;
				}
			}
		}
		error = EINVAL;
		break;
	case _LWP_GSBASE:
		if ((sbase = pcb->pcb_gsbase) != 0) {
			if (lwp_getdatamodel(lwp) == DATAMODEL_NATIVE) {
				if (PCB_NEED_UPDATE_SEGS(pcb)) {
					if (pcb->pcb_gs == 0)
						break;
				} else {
					if (rp->r_gs == 0)
						break;
				}
			} else {
				if (PCB_NEED_UPDATE_SEGS(pcb)) {
					if (pcb->pcb_gs == LWPGS_SEL)
						break;
				} else {
					if (rp->r_gs == LWPGS_SEL)
						break;
				}
			}
		}
		error = EINVAL;
		break;

#elif defined(__i386)

	case _LWP_FSBASE:
		if (rp->r_fs == LWPFS_SEL) {
			sbase = USEGD_GETBASE(&pcb->pcb_fsdesc);
			break;
		}
		error = EINVAL;
		break;
	case _LWP_GSBASE:
		if (rp->r_gs == LWPGS_SEL) {
			sbase = USEGD_GETBASE(&pcb->pcb_gsdesc);
			break;
		}
		error = EINVAL;
		break;

#endif	/* __i386 */

	default:
		error = ENOTSUP;
		break;
	}
	kpreempt_enable();

	if (error != 0)
		return (error);

	if (lwp_getdatamodel(lwp) == DATAMODEL_NATIVE) {
		if (sulword((void *)base, sbase) == -1)
			error = EFAULT;
#if defined(_SYSCALL32_IMPL)
	} else {
		if (suword32((void *)base, (uint32_t)sbase) == -1)
			error = EFAULT;
#endif
	}
	return (error);
}

/*
 * libc-private syscall for managing per-lwp %gs and %fs segment base values.
 */
int
syslwp_private(int cmd, int which, uintptr_t base)
{
	klwp_t *lwp = ttolwp(curthread);
	int res, error;

	switch (cmd) {
	case _LWP_SETPRIVATE:
		res = lwp_setprivate(lwp, which, base);
		return (res < 0 ? set_errno(ENOTSUP) : res);
	case _LWP_GETPRIVATE:
		error = lwp_getprivate(lwp, which, base);
		return (error != 0 ? set_errno(error) : error);
	default:
		return (set_errno(ENOTSUP));
	}
}
