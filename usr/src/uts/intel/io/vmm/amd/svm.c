/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2013, Anish Gupta (akgupt3@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2018 Joyent, Inc.
 * Copyright 2022 Oxide Computer Company
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/sysctl.h>

#include <sys/x86_archext.h>
#include <sys/trap.h>

#include <machine/cpufunc.h>
#include <machine/psl.h>
#include <machine/md_var.h>
#include <machine/reg.h>
#include <machine/specialreg.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <sys/vmm_instruction_emul.h>
#include <sys/vmm_vm.h>
#include <sys/vmm_kernel.h>

#include "vmm_lapic.h"
#include "vmm_stat.h"
#include "vmm_ioport.h"
#include "vatpic.h"
#include "vlapic.h"
#include "vlapic_priv.h"

#include "vmcb.h"
#include "svm.h"
#include "svm_softc.h"
#include "svm_msr.h"

SYSCTL_DECL(_hw_vmm);
SYSCTL_NODE(_hw_vmm, OID_AUTO, svm, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    NULL);

/*
 * SVM CPUID function 0x8000_000A, edx bit decoding.
 */
#define	AMD_CPUID_SVM_NP		BIT(0)  /* Nested paging or RVI */
#define	AMD_CPUID_SVM_LBR		BIT(1)  /* Last branch virtualization */
#define	AMD_CPUID_SVM_SVML		BIT(2)  /* SVM lock */
#define	AMD_CPUID_SVM_NRIP_SAVE		BIT(3)  /* Next RIP is saved */
#define	AMD_CPUID_SVM_TSC_RATE		BIT(4)  /* TSC rate control. */
#define	AMD_CPUID_SVM_VMCB_CLEAN	BIT(5)  /* VMCB state caching */
#define	AMD_CPUID_SVM_FLUSH_BY_ASID	BIT(6)  /* Flush by ASID */
#define	AMD_CPUID_SVM_DECODE_ASSIST	BIT(7)  /* Decode assist */
#define	AMD_CPUID_SVM_PAUSE_INC		BIT(10) /* Pause intercept filter. */
#define	AMD_CPUID_SVM_PAUSE_FTH		BIT(12) /* Pause filter threshold */
#define	AMD_CPUID_SVM_AVIC		BIT(13)	/* AVIC present */

#define	VMCB_CACHE_DEFAULT	(VMCB_CACHE_ASID	|	\
				VMCB_CACHE_IOPM		|	\
				VMCB_CACHE_I		|	\
				VMCB_CACHE_TPR		|	\
				VMCB_CACHE_CR2		|	\
				VMCB_CACHE_CR		|	\
				VMCB_CACHE_DR		|	\
				VMCB_CACHE_DT		|	\
				VMCB_CACHE_SEG		|	\
				VMCB_CACHE_NP)

static uint32_t vmcb_clean = VMCB_CACHE_DEFAULT;
SYSCTL_INT(_hw_vmm_svm, OID_AUTO, vmcb_clean, CTLFLAG_RDTUN, &vmcb_clean,
    0, NULL);

/* SVM features advertised by CPUID.8000000AH:EDX */
static uint32_t svm_feature = ~0U;	/* AMD SVM features. */

static int disable_npf_assist;

static VMM_STAT_AMD(VCPU_EXITINTINFO, "VM exits during event delivery");
static VMM_STAT_AMD(VCPU_INTINFO_INJECTED, "Events pending at VM entry");
static VMM_STAT_AMD(VMEXIT_VINTR, "VM exits due to interrupt window");

static int svm_setreg(void *arg, int vcpu, int ident, uint64_t val);
static int svm_getreg(void *arg, int vcpu, int ident, uint64_t *val);
static void flush_asid(struct svm_softc *sc, int vcpuid);

static __inline bool
flush_by_asid(void)
{
	return ((svm_feature & AMD_CPUID_SVM_FLUSH_BY_ASID) != 0);
}

static __inline bool
decode_assist(void)
{
	return ((svm_feature & AMD_CPUID_SVM_DECODE_ASSIST) != 0);
}

static int
svm_cleanup(void)
{
	/* This is taken care of by the hma registration */
	return (0);
}

static int
svm_init(void)
{
	vmcb_clean &= VMCB_CACHE_DEFAULT;

	svm_msr_init();

	return (0);
}

static void
svm_restore(void)
{
	/* No-op on illumos */
}

/* Pentium compatible MSRs */
#define	MSR_PENTIUM_START	0
#define	MSR_PENTIUM_END		0x1FFF
/* AMD 6th generation and Intel compatible MSRs */
#define	MSR_AMD6TH_START	0xC0000000UL
#define	MSR_AMD6TH_END		0xC0001FFFUL
/* AMD 7th and 8th generation compatible MSRs */
#define	MSR_AMD7TH_START	0xC0010000UL
#define	MSR_AMD7TH_END		0xC0011FFFUL

/*
 * Get the index and bit position for a MSR in permission bitmap.
 * Two bits are used for each MSR: lower bit for read and higher bit for write.
 */
static int
svm_msr_index(uint64_t msr, int *index, int *bit)
{
	uint32_t base, off;

	*index = -1;
	*bit = (msr % 4) * 2;
	base = 0;

	if (msr <= MSR_PENTIUM_END) {
		*index = msr / 4;
		return (0);
	}

	base += (MSR_PENTIUM_END - MSR_PENTIUM_START + 1);
	if (msr >= MSR_AMD6TH_START && msr <= MSR_AMD6TH_END) {
		off = (msr - MSR_AMD6TH_START);
		*index = (off + base) / 4;
		return (0);
	}

	base += (MSR_AMD6TH_END - MSR_AMD6TH_START + 1);
	if (msr >= MSR_AMD7TH_START && msr <= MSR_AMD7TH_END) {
		off = (msr - MSR_AMD7TH_START);
		*index = (off + base) / 4;
		return (0);
	}

	return (EINVAL);
}

/*
 * Allow vcpu to read or write the 'msr' without trapping into the hypervisor.
 */
static void
svm_msr_perm(uint8_t *perm_bitmap, uint64_t msr, bool read, bool write)
{
	int index, bit, error;

	error = svm_msr_index(msr, &index, &bit);
	KASSERT(error == 0, ("%s: invalid msr %lx", __func__, msr));
	KASSERT(index >= 0 && index < SVM_MSR_BITMAP_SIZE,
	    ("%s: invalid index %d for msr %lx", __func__, index, msr));
	KASSERT(bit >= 0 && bit <= 6, ("%s: invalid bit position %d "
	    "msr %lx", __func__, bit, msr));

	if (read)
		perm_bitmap[index] &= ~(1UL << bit);

	if (write)
		perm_bitmap[index] &= ~(2UL << bit);
}

static void
svm_msr_rw_ok(uint8_t *perm_bitmap, uint64_t msr)
{

	svm_msr_perm(perm_bitmap, msr, true, true);
}

static void
svm_msr_rd_ok(uint8_t *perm_bitmap, uint64_t msr)
{

	svm_msr_perm(perm_bitmap, msr, true, false);
}

static __inline int
svm_get_intercept(struct svm_softc *sc, int vcpu, int idx, uint32_t bitmask)
{
	struct vmcb_ctrl *ctrl;

	KASSERT(idx >= 0 && idx < 5, ("invalid intercept index %d", idx));

	ctrl = svm_get_vmcb_ctrl(sc, vcpu);
	return (ctrl->intercept[idx] & bitmask ? 1 : 0);
}

static __inline void
svm_set_intercept(struct svm_softc *sc, int vcpu, int idx, uint32_t bitmask,
    int enabled)
{
	struct vmcb_ctrl *ctrl;
	uint32_t oldval;

	KASSERT(idx >= 0 && idx < 5, ("invalid intercept index %d", idx));

	ctrl = svm_get_vmcb_ctrl(sc, vcpu);
	oldval = ctrl->intercept[idx];

	if (enabled)
		ctrl->intercept[idx] |= bitmask;
	else
		ctrl->intercept[idx] &= ~bitmask;

	if (ctrl->intercept[idx] != oldval) {
		svm_set_dirty(sc, vcpu, VMCB_CACHE_I);
	}
}

static __inline void
svm_disable_intercept(struct svm_softc *sc, int vcpu, int off, uint32_t bitmask)
{

	svm_set_intercept(sc, vcpu, off, bitmask, 0);
}

static __inline void
svm_enable_intercept(struct svm_softc *sc, int vcpu, int off, uint32_t bitmask)
{

	svm_set_intercept(sc, vcpu, off, bitmask, 1);
}

static void
vmcb_init(struct svm_softc *sc, int vcpu, uint64_t iopm_base_pa,
    uint64_t msrpm_base_pa, uint64_t np_pml4)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	uint32_t mask;
	int n;

	ctrl = svm_get_vmcb_ctrl(sc, vcpu);
	state = svm_get_vmcb_state(sc, vcpu);

	ctrl->iopm_base_pa = iopm_base_pa;
	ctrl->msrpm_base_pa = msrpm_base_pa;

	/* Enable nested paging */
	ctrl->np_ctrl = NP_ENABLE;
	ctrl->n_cr3 = np_pml4;

	/*
	 * Intercept accesses to the control registers that are not shadowed
	 * in the VMCB - i.e. all except cr0, cr2, cr3, cr4 and cr8.
	 */
	for (n = 0; n < 16; n++) {
		mask = (BIT(n) << 16) | BIT(n);
		if (n == 0 || n == 2 || n == 3 || n == 4 || n == 8)
			svm_disable_intercept(sc, vcpu, VMCB_CR_INTCPT, mask);
		else
			svm_enable_intercept(sc, vcpu, VMCB_CR_INTCPT, mask);
	}

	/*
	 * Selectively intercept writes to %cr0.  This triggers on operations
	 * which would change bits other than TS or MP.
	 */
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
	    VMCB_INTCPT_CR0_WRITE);

	/*
	 * Intercept everything when tracing guest exceptions otherwise
	 * just intercept machine check exception.
	 */
	if (vcpu_trace_exceptions(sc->vm, vcpu)) {
		for (n = 0; n < 32; n++) {
			/*
			 * Skip unimplemented vectors in the exception bitmap.
			 */
			if (n == 2 || n == 9) {
				continue;
			}
			svm_enable_intercept(sc, vcpu, VMCB_EXC_INTCPT, BIT(n));
		}
	} else {
		svm_enable_intercept(sc, vcpu, VMCB_EXC_INTCPT, BIT(IDT_MC));
	}

	/* Intercept various events (for e.g. I/O, MSR and CPUID accesses) */
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_IO);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_MSR);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_CPUID);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_INTR);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_INIT);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_NMI);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_SMI);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_SHUTDOWN);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
	    VMCB_INTCPT_FERR_FREEZE);

	/* Enable exit-on-hlt by default */
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_HLT);

	svm_enable_intercept(sc, vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_MONITOR);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_MWAIT);

	/* Intercept privileged invalidation instructions. */
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_INVD);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_INVLPGA);

	/*
	 * Intercept all virtualization-related instructions.
	 *
	 * From section "Canonicalization and Consistency Checks" in APMv2
	 * the VMRUN intercept bit must be set to pass the consistency check.
	 */
	svm_enable_intercept(sc, vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_VMRUN);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_VMMCALL);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_VMLOAD);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_VMSAVE);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_STGI);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_CLGI);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_SKINIT);
	if (vcpu_trap_wbinvd(sc->vm, vcpu) != 0) {
		svm_enable_intercept(sc, vcpu, VMCB_CTRL2_INTCPT,
		    VMCB_INTCPT_WBINVD);
	}

	/*
	 * The ASID will be set to a non-zero value just before VMRUN.
	 */
	ctrl->asid = 0;

	/*
	 * Section 15.21.1, Interrupt Masking in EFLAGS
	 * Section 15.21.2, Virtualizing APIC.TPR
	 *
	 * This must be set for %rflag and %cr8 isolation of guest and host.
	 */
	ctrl->v_intr_ctrl |= V_INTR_MASKING;

	/* Enable Last Branch Record aka LBR for debugging */
	ctrl->misc_ctrl |= LBR_VIRT_ENABLE;
	state->dbgctl = BIT(0);

	/* EFER_SVM must always be set when the guest is executing */
	state->efer = EFER_SVM;

	/* Set up the PAT to power-on state */
	state->g_pat = PAT_VALUE(0, PAT_WRITE_BACK)	|
	    PAT_VALUE(1, PAT_WRITE_THROUGH)	|
	    PAT_VALUE(2, PAT_UNCACHED)		|
	    PAT_VALUE(3, PAT_UNCACHEABLE)	|
	    PAT_VALUE(4, PAT_WRITE_BACK)	|
	    PAT_VALUE(5, PAT_WRITE_THROUGH)	|
	    PAT_VALUE(6, PAT_UNCACHED)		|
	    PAT_VALUE(7, PAT_UNCACHEABLE);

	/* Set up DR6/7 to power-on state */
	state->dr6 = DBREG_DR6_RESERVED1;
	state->dr7 = DBREG_DR7_RESERVED1;
}

/*
 * Initialize a virtual machine.
 */
static void *
svm_vminit(struct vm *vm)
{
	struct svm_softc *svm_sc;
	struct svm_vcpu *vcpu;
	vm_paddr_t msrpm_pa, iopm_pa, pml4_pa;
	int i;
	uint16_t maxcpus;

	svm_sc = kmem_zalloc(sizeof (*svm_sc), KM_SLEEP);
	VERIFY3U(((uintptr_t)svm_sc & PAGE_MASK),  ==,  0);

	svm_sc->msr_bitmap = vmm_contig_alloc(SVM_MSR_BITMAP_SIZE);
	if (svm_sc->msr_bitmap == NULL)
		panic("contigmalloc of SVM MSR bitmap failed");
	svm_sc->iopm_bitmap = vmm_contig_alloc(SVM_IO_BITMAP_SIZE);
	if (svm_sc->iopm_bitmap == NULL)
		panic("contigmalloc of SVM IO bitmap failed");

	svm_sc->vm = vm;
	svm_sc->nptp = vmspace_table_root(vm_get_vmspace(vm));

	/*
	 * Intercept read and write accesses to all MSRs.
	 */
	memset(svm_sc->msr_bitmap, 0xFF, SVM_MSR_BITMAP_SIZE);

	/*
	 * Access to the following MSRs is redirected to the VMCB when the
	 * guest is executing. Therefore it is safe to allow the guest to
	 * read/write these MSRs directly without hypervisor involvement.
	 */
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_GSBASE);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_FSBASE);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_KGSBASE);

	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_STAR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_LSTAR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_CSTAR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_SF_MASK);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_SYSENTER_CS_MSR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_SYSENTER_ESP_MSR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_SYSENTER_EIP_MSR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_PAT);

	svm_msr_rd_ok(svm_sc->msr_bitmap, MSR_TSC);

	/*
	 * Intercept writes to make sure that the EFER_SVM bit is not cleared.
	 */
	svm_msr_rd_ok(svm_sc->msr_bitmap, MSR_EFER);

	/* Intercept access to all I/O ports. */
	memset(svm_sc->iopm_bitmap, 0xFF, SVM_IO_BITMAP_SIZE);

	iopm_pa = vtophys(svm_sc->iopm_bitmap);
	msrpm_pa = vtophys(svm_sc->msr_bitmap);
	pml4_pa = svm_sc->nptp;
	maxcpus = vm_get_maxcpus(svm_sc->vm);
	for (i = 0; i < maxcpus; i++) {
		vcpu = svm_get_vcpu(svm_sc, i);
		vcpu->nextrip = ~0;
		vcpu->lastcpu = NOCPU;
		vcpu->vmcb_pa = vtophys(&vcpu->vmcb);
		vmcb_init(svm_sc, i, iopm_pa, msrpm_pa, pml4_pa);
		svm_msr_guest_init(svm_sc, i);
	}
	return (svm_sc);
}

/*
 * Collateral for a generic SVM VM-exit.
 */
static void
vm_exit_svm(struct vm_exit *vme, uint64_t code, uint64_t info1, uint64_t info2)
{

	vme->exitcode = VM_EXITCODE_SVM;
	vme->u.svm.exitcode = code;
	vme->u.svm.exitinfo1 = info1;
	vme->u.svm.exitinfo2 = info2;
}

static int
svm_cpl(struct vmcb_state *state)
{

	/*
	 * From APMv2:
	 *   "Retrieve the CPL from the CPL field in the VMCB, not
	 *    from any segment DPL"
	 */
	return (state->cpl);
}

static enum vm_cpu_mode
svm_vcpu_mode(struct vmcb *vmcb)
{
	struct vmcb_state *state;

	state = &vmcb->state;

	if (state->efer & EFER_LMA) {
		struct vmcb_segment *seg;

		/*
		 * Section 4.8.1 for APM2, check if Code Segment has
		 * Long attribute set in descriptor.
		 */
		seg = vmcb_segptr(vmcb, VM_REG_GUEST_CS);
		if (seg->attrib & VMCB_CS_ATTRIB_L)
			return (CPU_MODE_64BIT);
		else
			return (CPU_MODE_COMPATIBILITY);
	} else  if (state->cr0 & CR0_PE) {
		return (CPU_MODE_PROTECTED);
	} else {
		return (CPU_MODE_REAL);
	}
}

static enum vm_paging_mode
svm_paging_mode(uint64_t cr0, uint64_t cr4, uint64_t efer)
{

	if ((cr0 & CR0_PG) == 0)
		return (PAGING_MODE_FLAT);
	if ((cr4 & CR4_PAE) == 0)
		return (PAGING_MODE_32);
	if (efer & EFER_LME)
		return (PAGING_MODE_64);
	else
		return (PAGING_MODE_PAE);
}

/*
 * ins/outs utility routines
 */

static void
svm_paging_info(struct vmcb *vmcb, struct vm_guest_paging *paging)
{
	struct vmcb_state *state;

	state = &vmcb->state;
	paging->cr3 = state->cr3;
	paging->cpl = svm_cpl(state);
	paging->cpu_mode = svm_vcpu_mode(vmcb);
	paging->paging_mode = svm_paging_mode(state->cr0, state->cr4,
	    state->efer);
}

#define	UNHANDLED 0

/*
 * Handle guest I/O intercept.
 */
static int
svm_handle_inout(struct svm_softc *svm_sc, int vcpu, struct vm_exit *vmexit)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	struct vm_inout *inout;
	struct vie *vie;
	uint64_t info1;
	struct vm_guest_paging paging;

	state = svm_get_vmcb_state(svm_sc, vcpu);
	ctrl = svm_get_vmcb_ctrl(svm_sc, vcpu);
	inout = &vmexit->u.inout;
	info1 = ctrl->exitinfo1;

	inout->bytes = (info1 >> 4) & 0x7;
	inout->flags = 0;
	inout->flags |= (info1 & BIT(0)) ? INOUT_IN : 0;
	inout->flags |= (info1 & BIT(3)) ? INOUT_REP : 0;
	inout->flags |= (info1 & BIT(2)) ? INOUT_STR : 0;
	inout->port = (uint16_t)(info1 >> 16);
	inout->eax = (uint32_t)(state->rax);

	if ((inout->flags & INOUT_STR) != 0) {
		/*
		 * The effective segment number in EXITINFO1[12:10] is populated
		 * only if the processor has the DecodeAssist capability.
		 *
		 * This is not specified explicitly in APMv2 but can be verified
		 * empirically.
		 */
		if (!decode_assist()) {
			/*
			 * Without decoding assistance, force the task of
			 * emulating the ins/outs on userspace.
			 */
			vmexit->exitcode = VM_EXITCODE_INST_EMUL;
			bzero(&vmexit->u.inst_emul,
			    sizeof (vmexit->u.inst_emul));
			return (UNHANDLED);
		}

		/*
		 * Bits 7-9 encode the address size of ins/outs operations where
		 * the 1/2/4 values correspond to 16/32/64 bit sizes.
		 */
		inout->addrsize = 2 * ((info1 >> 7) & 0x7);
		VERIFY(inout->addrsize == 2 || inout->addrsize == 4 ||
		    inout->addrsize == 8);

		if (inout->flags & INOUT_IN) {
			/*
			 * For INS instructions, %es (encoded as 0) is the
			 * implied segment for the operation.
			 */
			inout->segment = 0;
		} else {
			/*
			 * Bits 10-12 encode the segment for OUTS.
			 * This value follows the standard x86 segment order.
			 */
			inout->segment = (info1 >> 10) & 0x7;
		}
	}

	vmexit->exitcode = VM_EXITCODE_INOUT;
	svm_paging_info(svm_get_vmcb(svm_sc, vcpu), &paging);
	vie = vm_vie_ctx(svm_sc->vm, vcpu);
	vie_init_inout(vie, inout, vmexit->inst_length, &paging);

	/* The in/out emulation will handle advancing %rip */
	vmexit->inst_length = 0;

	return (UNHANDLED);
}

static int
npf_fault_type(uint64_t exitinfo1)
{

	if (exitinfo1 & VMCB_NPF_INFO1_W)
		return (PROT_WRITE);
	else if (exitinfo1 & VMCB_NPF_INFO1_ID)
		return (PROT_EXEC);
	else
		return (PROT_READ);
}

static bool
svm_npf_emul_fault(uint64_t exitinfo1)
{
	if (exitinfo1 & VMCB_NPF_INFO1_ID) {
		return (false);
	}

	if (exitinfo1 & VMCB_NPF_INFO1_GPT) {
		return (false);
	}

	if ((exitinfo1 & VMCB_NPF_INFO1_GPA) == 0) {
		return (false);
	}

	return (true);
}

static void
svm_handle_mmio_emul(struct svm_softc *svm_sc, int vcpu, struct vm_exit *vmexit,
    uint64_t gpa)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb *vmcb;
	struct vie *vie;
	struct vm_guest_paging paging;
	struct vmcb_segment *seg;
	char *inst_bytes = NULL;
	uint8_t inst_len = 0;

	vmcb = svm_get_vmcb(svm_sc, vcpu);
	ctrl = &vmcb->ctrl;

	vmexit->exitcode = VM_EXITCODE_MMIO_EMUL;
	vmexit->u.mmio_emul.gpa = gpa;
	vmexit->u.mmio_emul.gla = VIE_INVALID_GLA;
	svm_paging_info(vmcb, &paging);

	switch (paging.cpu_mode) {
	case CPU_MODE_REAL:
		seg = vmcb_segptr(vmcb, VM_REG_GUEST_CS);
		vmexit->u.mmio_emul.cs_base = seg->base;
		vmexit->u.mmio_emul.cs_d = 0;
		break;
	case CPU_MODE_PROTECTED:
	case CPU_MODE_COMPATIBILITY:
		seg = vmcb_segptr(vmcb, VM_REG_GUEST_CS);
		vmexit->u.mmio_emul.cs_base = seg->base;

		/*
		 * Section 4.8.1 of APM2, Default Operand Size or D bit.
		 */
		vmexit->u.mmio_emul.cs_d = (seg->attrib & VMCB_CS_ATTRIB_D) ?
		    1 : 0;
		break;
	default:
		vmexit->u.mmio_emul.cs_base = 0;
		vmexit->u.mmio_emul.cs_d = 0;
		break;
	}

	/*
	 * Copy the instruction bytes into 'vie' if available.
	 */
	if (decode_assist() && !disable_npf_assist) {
		inst_len = ctrl->inst_len;
		inst_bytes = (char *)ctrl->inst_bytes;
	}
	vie = vm_vie_ctx(svm_sc->vm, vcpu);
	vie_init_mmio(vie, inst_bytes, inst_len, &paging, gpa);
}

/*
 * Do not allow CD, NW, or invalid high bits to be asserted in the value of cr0
 * which is live in the guest.  They are visible via the shadow instead.
 */
#define	SVM_CR0_MASK	~(CR0_CD | CR0_NW | 0xffffffff00000000)

static void
svm_set_cr0(struct svm_softc *svm_sc, int vcpu, uint64_t val, bool guest_write)
{
	struct vmcb_state *state;
	struct svm_regctx *regctx;
	uint64_t masked, old, diff;

	state = svm_get_vmcb_state(svm_sc, vcpu);
	regctx = svm_get_guest_regctx(svm_sc, vcpu);

	old = state->cr0 | (regctx->sctx_cr0_shadow & ~SVM_CR0_MASK);
	diff = old ^ val;

	/* No further work needed if register contents remain the same */
	if (diff == 0) {
		return;
	}

	/* Flush the TLB if the paging or write-protect bits are changing */
	if ((diff & CR0_PG) != 0 || (diff & CR0_WP) != 0) {
		flush_asid(svm_sc, vcpu);
	}

	/*
	 * If the change in %cr0 is due to a guest action (via interception)
	 * then other CPU state updates may be required.
	 */
	if (guest_write) {
		if ((diff & CR0_PG) != 0) {
			uint64_t efer = state->efer;

			/* Keep the long-mode state in EFER in sync */
			if ((val & CR0_PG) != 0 && (efer & EFER_LME) != 0) {
				state->efer |= EFER_LMA;
			}
			if ((val & CR0_PG) == 0 && (efer & EFER_LME) != 0) {
				state->efer &= ~EFER_LMA;
			}
		}
	}

	masked = val & SVM_CR0_MASK;
	regctx->sctx_cr0_shadow = val;
	state->cr0 = masked;
	svm_set_dirty(svm_sc, vcpu, VMCB_CACHE_CR);

	if ((masked ^ val) != 0) {
		/*
		 * The guest has set bits in %cr0 which we are masking out and
		 * exposing via shadow.
		 *
		 * We must intercept %cr0 reads in order to make the shadowed
		 * view available to the guest.
		 *
		 * Writes to %cr0 must also be intercepted (unconditionally,
		 * unlike the VMCB_INTCPT_CR0_WRITE mechanism) so we can catch
		 * if/when the guest clears those shadowed bits.
		 */
		svm_enable_intercept(svm_sc, vcpu, VMCB_CR_INTCPT,
		    BIT(0) | BIT(16));
	} else {
		/*
		 * When no bits remain in %cr0 which require shadowing, the
		 * unconditional intercept of reads/writes to %cr0 can be
		 * disabled.
		 *
		 * The selective write intercept (VMCB_INTCPT_CR0_WRITE) remains
		 * in place so we can be notified of operations which change
		 * bits other than TS or MP.
		 */
		svm_disable_intercept(svm_sc, vcpu, VMCB_CR_INTCPT,
		    BIT(0) | BIT(16));
	}
	svm_set_dirty(svm_sc, vcpu, VMCB_CACHE_I);
}

static void
svm_get_cr0(struct svm_softc *svm_sc, int vcpu, uint64_t *val)
{
	struct vmcb *vmcb;
	struct svm_regctx *regctx;

	vmcb = svm_get_vmcb(svm_sc, vcpu);
	regctx = svm_get_guest_regctx(svm_sc, vcpu);

	/*
	 * Include the %cr0 bits which exist only in the shadow along with those
	 * in the running vCPU state.
	 */
	*val = vmcb->state.cr0 | (regctx->sctx_cr0_shadow & ~SVM_CR0_MASK);
}

static void
svm_handle_cr0_read(struct svm_softc *svm_sc, int vcpu, enum vm_reg_name reg)
{
	uint64_t val;
	int err __maybe_unused;

	svm_get_cr0(svm_sc, vcpu, &val);
	err = svm_setreg(svm_sc, vcpu, reg, val);
	ASSERT(err == 0);
}

static void
svm_handle_cr0_write(struct svm_softc *svm_sc, int vcpu, enum vm_reg_name reg)
{
	struct vmcb_state *state;
	uint64_t val;
	int err __maybe_unused;

	state = svm_get_vmcb_state(svm_sc, vcpu);

	err = svm_getreg(svm_sc, vcpu, reg, &val);
	ASSERT(err == 0);

	if ((val & CR0_NW) != 0 && (val & CR0_CD) == 0) {
		/* NW without CD is nonsensical */
		vm_inject_gp(svm_sc->vm, vcpu);
		return;
	}
	if ((val & CR0_PG) != 0 && (val & CR0_PE) == 0) {
		/* PG requires PE */
		vm_inject_gp(svm_sc->vm, vcpu);
		return;
	}
	if ((state->cr0 & CR0_PG) == 0 && (val & CR0_PG) != 0) {
		/* When enabling paging, PAE must be enabled if LME is. */
		if ((state->efer & EFER_LME) != 0 &&
		    (state->cr4 & CR4_PAE) == 0) {
			vm_inject_gp(svm_sc->vm, vcpu);
			return;
		}
	}

	svm_set_cr0(svm_sc, vcpu, val, true);
}

static void
svm_inst_emul_other(struct svm_softc *svm_sc, int vcpu, struct vm_exit *vmexit)
{
	struct vie *vie;
	struct vm_guest_paging paging;

	/* Let the instruction emulation (hopefully in-kernel) handle it */
	vmexit->exitcode = VM_EXITCODE_INST_EMUL;
	bzero(&vmexit->u.inst_emul, sizeof (vmexit->u.inst_emul));
	vie = vm_vie_ctx(svm_sc->vm, vcpu);
	svm_paging_info(svm_get_vmcb(svm_sc, vcpu), &paging);
	vie_init_other(vie, &paging);

	/* The instruction emulation will handle advancing %rip */
	vmexit->inst_length = 0;
}

static void
svm_update_virqinfo(struct svm_softc *sc, int vcpu)
{
	struct vm *vm;
	struct vlapic *vlapic;
	struct vmcb_ctrl *ctrl;

	vm = sc->vm;
	vlapic = vm_lapic(vm, vcpu);
	ctrl = svm_get_vmcb_ctrl(sc, vcpu);

	/* Update %cr8 in the emulated vlapic */
	vlapic_set_cr8(vlapic, ctrl->v_tpr);

	/* Virtual interrupt injection is not used. */
	KASSERT(ctrl->v_intr_vector == 0, ("%s: invalid "
	    "v_intr_vector %d", __func__, ctrl->v_intr_vector));
}

CTASSERT(VMCB_EVENTINJ_TYPE_INTR	== VM_INTINFO_HWINTR);
CTASSERT(VMCB_EVENTINJ_TYPE_NMI		== VM_INTINFO_NMI);
CTASSERT(VMCB_EVENTINJ_TYPE_EXCEPTION	== VM_INTINFO_HWEXCP);
CTASSERT(VMCB_EVENTINJ_TYPE_INTn	== VM_INTINFO_SWINTR);
CTASSERT(VMCB_EVENTINJ_EC_VALID		== VM_INTINFO_DEL_ERRCODE);
CTASSERT(VMCB_EVENTINJ_VALID		== VM_INTINFO_VALID);

/*
 * Store SVM-specific event injection info for later handling.  This depends on
 * the bhyve-internal event definitions matching those in the VMCB, as ensured
 * by the above CTASSERTs.
 */
static void
svm_stash_intinfo(struct svm_softc *svm_sc, int vcpu, uint64_t intinfo)
{
	ASSERT(VMCB_EXITINTINFO_VALID(intinfo));

	/*
	 * If stashing an NMI pending injection, ensure that it bears the
	 * correct vector which exit_intinfo expects.
	 */
	if (VM_INTINFO_TYPE(intinfo) == VM_INTINFO_NMI) {
		intinfo &= ~VM_INTINFO_MASK_VECTOR;
		intinfo |= IDT_NMI;
	}

	VERIFY0(vm_exit_intinfo(svm_sc->vm, vcpu, intinfo));
}

static void
svm_save_exitintinfo(struct svm_softc *svm_sc, int vcpu)
{
	struct vmcb_ctrl *ctrl  = svm_get_vmcb_ctrl(svm_sc, vcpu);
	uint64_t intinfo = ctrl->exitintinfo;

	if (VMCB_EXITINTINFO_VALID(intinfo)) {
		/*
		 * If a #VMEXIT happened during event delivery then record the
		 * event that was being delivered.
		 */
		vmm_stat_incr(svm_sc->vm, vcpu, VCPU_EXITINTINFO, 1);

		svm_stash_intinfo(svm_sc, vcpu, intinfo);
	}
}

static __inline int
vintr_intercept_enabled(struct svm_softc *sc, int vcpu)
{

	return (svm_get_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
	    VMCB_INTCPT_VINTR));
}

static void
svm_enable_intr_window_exiting(struct svm_softc *sc, int vcpu)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;

	ctrl = svm_get_vmcb_ctrl(sc, vcpu);
	state = svm_get_vmcb_state(sc, vcpu);

	if ((ctrl->v_irq & V_IRQ) != 0 && ctrl->v_intr_vector == 0) {
		KASSERT(ctrl->v_intr_prio & V_IGN_TPR,
		    ("%s: invalid v_ign_tpr", __func__));
		KASSERT(vintr_intercept_enabled(sc, vcpu),
		    ("%s: vintr intercept should be enabled", __func__));
		return;
	}

	/*
	 * We use V_IRQ in conjunction with the VINTR intercept to trap into the
	 * hypervisor as soon as a virtual interrupt can be delivered.
	 *
	 * Since injected events are not subject to intercept checks we need to
	 * ensure that the V_IRQ is not actually going to be delivered on VM
	 * entry.
	 */
	VERIFY((ctrl->eventinj & VMCB_EVENTINJ_VALID) != 0 ||
	    (state->rflags & PSL_I) == 0 || ctrl->intr_shadow);

	ctrl->v_irq |= V_IRQ;
	ctrl->v_intr_prio |= V_IGN_TPR;
	ctrl->v_intr_vector = 0;
	svm_set_dirty(sc, vcpu, VMCB_CACHE_TPR);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_VINTR);
}

static void
svm_disable_intr_window_exiting(struct svm_softc *sc, int vcpu)
{
	struct vmcb_ctrl *ctrl;

	ctrl = svm_get_vmcb_ctrl(sc, vcpu);

	if ((ctrl->v_irq & V_IRQ) == 0 && ctrl->v_intr_vector == 0) {
		KASSERT(!vintr_intercept_enabled(sc, vcpu),
		    ("%s: vintr intercept should be disabled", __func__));
		return;
	}

	ctrl->v_irq &= ~V_IRQ;
	ctrl->v_intr_vector = 0;
	svm_set_dirty(sc, vcpu, VMCB_CACHE_TPR);
	svm_disable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_VINTR);
}

/*
 * Once an NMI is injected it blocks delivery of further NMIs until the handler
 * executes an IRET. The IRET intercept is enabled when an NMI is injected to
 * to track when the vcpu is done handling the NMI.
 */
static int
svm_nmi_blocked(struct svm_softc *sc, int vcpu)
{
	return (svm_get_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
	    VMCB_INTCPT_IRET));
}

static void
svm_clear_nmi_blocking(struct svm_softc *sc, int vcpu)
{
	struct vmcb_ctrl *ctrl;

	KASSERT(svm_nmi_blocked(sc, vcpu), ("vNMI already unblocked"));
	/*
	 * When the IRET intercept is cleared the vcpu will attempt to execute
	 * the "iret" when it runs next. However, it is possible to inject
	 * another NMI into the vcpu before the "iret" has actually executed.
	 *
	 * For e.g. if the "iret" encounters a #NPF when accessing the stack
	 * it will trap back into the hypervisor. If an NMI is pending for
	 * the vcpu it will be injected into the guest.
	 *
	 * XXX this needs to be fixed
	 */
	svm_disable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_IRET);

	/*
	 * Set an interrupt shadow to prevent an NMI from being immediately
	 * injected on the next VMRUN.
	 */
	ctrl = svm_get_vmcb_ctrl(sc, vcpu);
	ctrl->intr_shadow = 1;
}

static void
svm_inject_event(struct vmcb_ctrl *ctrl, uint64_t info)
{
	ASSERT(VM_INTINFO_PENDING(info));

	uint8_t vector = VM_INTINFO_VECTOR(info);
	uint32_t type = VM_INTINFO_TYPE(info);

	/*
	 * Correct behavior depends on bhyve intinfo event types lining up with
	 * those defined by AMD for event injection in the VMCB.  The CTASSERTs
	 * above svm_save_exitintinfo() ensure it.
	 */
	switch (type) {
	case VM_INTINFO_NMI:
		/* Ensure vector for injected event matches its type (NMI) */
		vector = IDT_NMI;
		break;
	case VM_INTINFO_HWINTR:
	case VM_INTINFO_SWINTR:
		break;
	case VM_INTINFO_HWEXCP:
		if (vector == IDT_NMI) {
			/*
			 * NMIs are expected to be injected with
			 * VMCB_EVENTINJ_TYPE_NMI, rather than as an exception
			 * with the NMI vector.
			 */
			type = VM_INTINFO_NMI;
		}
		VERIFY(vector < 32);
		break;
	default:
		/*
		 * Since there is not strong validation for injected event types
		 * at this point, fall back to software interrupt for those we
		 * do not recognized.
		 */
		type = VM_INTINFO_SWINTR;
		break;
	}

	ctrl->eventinj = VMCB_EVENTINJ_VALID | type | vector;
	if (VM_INTINFO_HAS_ERRCODE(info)) {
		ctrl->eventinj |= VMCB_EVENTINJ_EC_VALID;
		ctrl->eventinj |= (uint64_t)VM_INTINFO_ERRCODE(info) << 32;
	}
}

static void
svm_inject_nmi(struct svm_softc *sc, int vcpu)
{
	struct vmcb_ctrl *ctrl = svm_get_vmcb_ctrl(sc, vcpu);

	ASSERT(!svm_nmi_blocked(sc, vcpu));

	ctrl->eventinj = VMCB_EVENTINJ_VALID | VMCB_EVENTINJ_TYPE_NMI;
	vm_nmi_clear(sc->vm, vcpu);

	/*
	 * Virtual NMI blocking is now in effect.
	 *
	 * Not only does this block a subsequent NMI injection from taking
	 * place, it also configures an intercept on the IRET so we can track
	 * when the next injection can take place.
	 */
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_IRET);
}

static void
svm_inject_irq(struct svm_softc *sc, int vcpu, int vector)
{
	struct vmcb_ctrl *ctrl = svm_get_vmcb_ctrl(sc, vcpu);

	ASSERT(vector >= 0 && vector <= 255);

	ctrl->eventinj = VMCB_EVENTINJ_VALID | vector;
}

#define	EFER_MBZ_BITS	0xFFFFFFFFFFFF0200UL

static vm_msr_result_t
svm_write_efer(struct svm_softc *sc, int vcpu, uint64_t newval)
{
	struct vmcb_state *state = svm_get_vmcb_state(sc, vcpu);
	uint64_t lma;
	int error;

	newval &= ~0xFE;		/* clear the Read-As-Zero (RAZ) bits */

	if (newval & EFER_MBZ_BITS) {
		return (VMR_GP);
	}

	/* APMv2 Table 14-5 "Long-Mode Consistency Checks" */
	const uint64_t changed = state->efer ^ newval;
	if (changed & EFER_LME) {
		if (state->cr0 & CR0_PG) {
			return (VMR_GP);
		}
	}

	/* EFER.LMA = EFER.LME & CR0.PG */
	if ((newval & EFER_LME) != 0 && (state->cr0 & CR0_PG) != 0) {
		lma = EFER_LMA;
	} else {
		lma = 0;
	}
	if ((newval & EFER_LMA) != lma) {
		return (VMR_GP);
	}

	if ((newval & EFER_NXE) != 0 &&
	    !vm_cpuid_capability(sc->vm, vcpu, VCC_NO_EXECUTE)) {
		return (VMR_GP);
	}
	if ((newval & EFER_FFXSR) != 0 &&
	    !vm_cpuid_capability(sc->vm, vcpu, VCC_FFXSR)) {
		return (VMR_GP);
	}
	if ((newval & EFER_TCE) != 0 &&
	    !vm_cpuid_capability(sc->vm, vcpu, VCC_TCE)) {
		return (VMR_GP);
	}

	/*
	 * Until bhyve has proper support for long-mode segment limits, just
	 * toss a #GP at the guest if they attempt to use it.
	 */
	if (newval & EFER_LMSLE) {
		return (VMR_GP);
	}

	error = svm_setreg(sc, vcpu, VM_REG_GUEST_EFER, newval);
	VERIFY0(error);
	return (VMR_OK);
}

static int
svm_handle_msr(struct svm_softc *svm_sc, int vcpu, struct vm_exit *vmexit,
    bool is_wrmsr)
{
	struct vmcb_state *state = svm_get_vmcb_state(svm_sc, vcpu);
	struct svm_regctx *ctx = svm_get_guest_regctx(svm_sc, vcpu);
	const uint32_t ecx = ctx->sctx_rcx;
	vm_msr_result_t res;
	uint64_t val = 0;

	if (is_wrmsr) {
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_WRMSR, 1);
		val = ctx->sctx_rdx << 32 | (uint32_t)state->rax;

		if (vlapic_owned_msr(ecx)) {
			struct vlapic *vlapic = vm_lapic(svm_sc->vm, vcpu);

			res = vlapic_wrmsr(vlapic, ecx, val);
		} else if (ecx == MSR_EFER) {
			res = svm_write_efer(svm_sc, vcpu, val);
		} else {
			res = svm_wrmsr(svm_sc, vcpu, ecx, val);
		}
	} else {
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_RDMSR, 1);

		if (vlapic_owned_msr(ecx)) {
			struct vlapic *vlapic = vm_lapic(svm_sc->vm, vcpu);

			res = vlapic_rdmsr(vlapic, ecx, &val);
		} else {
			res = svm_rdmsr(svm_sc, vcpu, ecx, &val);
		}
	}

	switch (res) {
	case VMR_OK:
		/* Store rdmsr result in the appropriate registers */
		if (!is_wrmsr) {
			state->rax = (uint32_t)val;
			ctx->sctx_rdx = val >> 32;
		}
		return (1);
	case VMR_GP:
		vm_inject_gp(svm_sc->vm, vcpu);
		return (1);
	case VMR_UNHANLDED:
		vmexit->exitcode = is_wrmsr ?
		    VM_EXITCODE_WRMSR : VM_EXITCODE_RDMSR;
		vmexit->u.msr.code = ecx;
		vmexit->u.msr.wval = val;
		return (0);
	default:
		panic("unexpected msr result %u\n", res);
	}
}

/*
 * From section "State Saved on Exit" in APMv2: nRIP is saved for all #VMEXITs
 * that are due to instruction intercepts as well as MSR and IOIO intercepts
 * and exceptions caused by INT3, INTO and BOUND instructions.
 *
 * Return 1 if the nRIP is valid and 0 otherwise.
 */
static int
nrip_valid(uint64_t exitcode)
{
	switch (exitcode) {
	case 0x00 ... 0x0F:	/* read of CR0 through CR15 */
	case 0x10 ... 0x1F:	/* write of CR0 through CR15 */
	case 0x20 ... 0x2F:	/* read of DR0 through DR15 */
	case 0x30 ... 0x3F:	/* write of DR0 through DR15 */
	case 0x43:		/* INT3 */
	case 0x44:		/* INTO */
	case 0x45:		/* BOUND */
	case 0x65 ... 0x7C:	/* VMEXIT_CR0_SEL_WRITE ... VMEXIT_MSR */
	case 0x80 ... 0x8D:	/* VMEXIT_VMRUN ... VMEXIT_XSETBV */
		return (1);
	default:
		return (0);
	}
}

static int
svm_vmexit(struct svm_softc *svm_sc, int vcpu, struct vm_exit *vmexit)
{
	struct vmcb *vmcb;
	struct vmcb_state *state;
	struct vmcb_ctrl *ctrl;
	struct svm_regctx *ctx;
	uint64_t code, info1, info2;
	int handled;

	ctx = svm_get_guest_regctx(svm_sc, vcpu);
	vmcb = svm_get_vmcb(svm_sc, vcpu);
	state = &vmcb->state;
	ctrl = &vmcb->ctrl;

	handled = 0;
	code = ctrl->exitcode;
	info1 = ctrl->exitinfo1;
	info2 = ctrl->exitinfo2;

	vmexit->exitcode = VM_EXITCODE_BOGUS;
	vmexit->rip = state->rip;
	vmexit->inst_length = nrip_valid(code) ? ctrl->nrip - state->rip : 0;

	vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_COUNT, 1);

	/*
	 * #VMEXIT(INVALID) needs to be handled early because the VMCB is
	 * in an inconsistent state and can trigger assertions that would
	 * never happen otherwise.
	 */
	if (code == VMCB_EXIT_INVALID) {
		vm_exit_svm(vmexit, code, info1, info2);
		return (0);
	}

	KASSERT((ctrl->eventinj & VMCB_EVENTINJ_VALID) == 0, ("%s: event "
	    "injection valid bit is set %lx", __func__, ctrl->eventinj));

	KASSERT(vmexit->inst_length >= 0 && vmexit->inst_length <= 15,
	    ("invalid inst_length %d: code (%lx), info1 (%lx), info2 (%lx)",
	    vmexit->inst_length, code, info1, info2));

	svm_update_virqinfo(svm_sc, vcpu);
	svm_save_exitintinfo(svm_sc, vcpu);

	switch (code) {
	case VMCB_EXIT_CR0_READ:
		if (VMCB_CRx_INFO1_VALID(info1) != 0) {
			svm_handle_cr0_read(svm_sc, vcpu,
			    vie_regnum_map(VMCB_CRx_INFO1_GPR(info1)));
			handled = 1;
		} else {
			/*
			 * If SMSW is used to read the contents of %cr0, then
			 * the VALID bit will not be set in `info1`, since the
			 * handling is different from the mov-to-reg case.
			 *
			 * Punt to the instruction emulation to handle it.
			 */
			svm_inst_emul_other(svm_sc, vcpu, vmexit);
		}
		break;
	case VMCB_EXIT_CR0_WRITE:
	case VMCB_EXIT_CR0_SEL_WRITE:
		if (VMCB_CRx_INFO1_VALID(info1) != 0) {
			svm_handle_cr0_write(svm_sc, vcpu,
			    vie_regnum_map(VMCB_CRx_INFO1_GPR(info1)));
			handled = 1;
		} else {
			/*
			 * Writes to %cr0 without VALID being set in `info1` are
			 * initiated by the LMSW and CLTS instructions.  While
			 * LMSW (like SMSW) sees little use in modern OSes and
			 * bootloaders, CLTS is still used for handling FPU
			 * state transitions.
			 *
			 * Punt to the instruction emulation to handle them.
			 */
			svm_inst_emul_other(svm_sc, vcpu, vmexit);
		}
		break;
	case VMCB_EXIT_IRET:
		/*
		 * Restart execution at "iret" but with the intercept cleared.
		 */
		vmexit->inst_length = 0;
		svm_clear_nmi_blocking(svm_sc, vcpu);
		handled = 1;
		break;
	case VMCB_EXIT_VINTR:	/* interrupt window exiting */
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_VINTR, 1);
		svm_disable_intr_window_exiting(svm_sc, vcpu);
		handled = 1;
		break;
	case VMCB_EXIT_INTR:	/* external interrupt */
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_EXTINT, 1);
		handled = 1;
		break;
	case VMCB_EXIT_NMI:
	case VMCB_EXIT_SMI:
	case VMCB_EXIT_INIT:
		/*
		 * For external NMI/SMI and physical INIT interrupts, simply
		 * continue execution, as those host events will be handled by
		 * the physical CPU.
		 */
		handled = 1;
		break;
	case VMCB_EXIT_EXCP0 ... VMCB_EXIT_EXCP31: {
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_EXCEPTION, 1);

		const uint8_t idtvec = code - VMCB_EXIT_EXCP0;
		uint32_t errcode = 0;
		bool reflect = true;
		bool errcode_valid = false;

		switch (idtvec) {
		case IDT_MC:
			/* The host will handle the MCE itself. */
			reflect = false;
			vmm_call_trap(T_MCE);
			break;
		case IDT_PF:
			VERIFY0(svm_setreg(svm_sc, vcpu, VM_REG_GUEST_CR2,
			    info2));
			/* fallthru */
		case IDT_NP:
		case IDT_SS:
		case IDT_GP:
		case IDT_AC:
		case IDT_TS:
			errcode_valid = true;
			errcode = info1;
			break;

		case IDT_DF:
			errcode_valid = true;
			break;

		case IDT_BP:
		case IDT_OF:
		case IDT_BR:
			/*
			 * The 'nrip' field is populated for INT3, INTO and
			 * BOUND exceptions and this also implies that
			 * 'inst_length' is non-zero.
			 *
			 * Reset 'inst_length' to zero so the guest %rip at
			 * event injection is identical to what it was when
			 * the exception originally happened.
			 */
			vmexit->inst_length = 0;
			/* fallthru */
		default:
			errcode_valid = false;
			break;
		}
		VERIFY0(vmexit->inst_length);

		if (reflect) {
			/* Reflect the exception back into the guest */
			VERIFY0(vm_inject_exception(svm_sc->vm, vcpu, idtvec,
			    errcode_valid, errcode, false));
		}
		handled = 1;
		break;
		}
	case VMCB_EXIT_MSR:
		handled = svm_handle_msr(svm_sc, vcpu, vmexit, info1 != 0);
		break;
	case VMCB_EXIT_IO:
		handled = svm_handle_inout(svm_sc, vcpu, vmexit);
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_INOUT, 1);
		break;
	case VMCB_EXIT_SHUTDOWN:
		(void) vm_suspend(svm_sc->vm, VM_SUSPEND_TRIPLEFAULT);
		handled = 1;
		break;
	case VMCB_EXIT_INVLPGA:
		/* privileged invalidation instructions */
		vm_inject_ud(svm_sc->vm, vcpu);
		handled = 1;
		break;
	case VMCB_EXIT_VMRUN:
	case VMCB_EXIT_VMLOAD:
	case VMCB_EXIT_VMSAVE:
	case VMCB_EXIT_STGI:
	case VMCB_EXIT_CLGI:
	case VMCB_EXIT_SKINIT:
		/* privileged vmm instructions */
		vm_inject_ud(svm_sc->vm, vcpu);
		handled = 1;
		break;
	case VMCB_EXIT_INVD:
	case VMCB_EXIT_WBINVD:
		/* ignore exit */
		handled = 1;
		break;
	case VMCB_EXIT_VMMCALL:
		/* No handlers make use of VMMCALL for now */
		vm_inject_ud(svm_sc->vm, vcpu);
		handled = 1;
		break;
	case VMCB_EXIT_CPUID:
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_CPUID, 1);
		vcpu_emulate_cpuid(svm_sc->vm, vcpu, &state->rax,
		    &ctx->sctx_rbx, &ctx->sctx_rcx, &ctx->sctx_rdx);
		handled = 1;
		break;
	case VMCB_EXIT_HLT:
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_HLT, 1);
		vmexit->exitcode = VM_EXITCODE_HLT;
		vmexit->u.hlt.rflags = state->rflags;
		break;
	case VMCB_EXIT_PAUSE:
		vmexit->exitcode = VM_EXITCODE_PAUSE;
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_PAUSE, 1);
		break;
	case VMCB_EXIT_NPF:
		/* EXITINFO2 contains the faulting guest physical address */
		if (info1 & VMCB_NPF_INFO1_RSV) {
			/* nested fault with reserved bits set */
		} else if (vm_mem_allocated(svm_sc->vm, vcpu, info2)) {
			vmexit->exitcode = VM_EXITCODE_PAGING;
			vmexit->u.paging.gpa = info2;
			vmexit->u.paging.fault_type = npf_fault_type(info1);
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_NESTED_FAULT, 1);
		} else if (svm_npf_emul_fault(info1)) {
			svm_handle_mmio_emul(svm_sc, vcpu, vmexit, info2);
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_MMIO_EMUL, 1);
		}
		break;
	case VMCB_EXIT_MONITOR:
		vmexit->exitcode = VM_EXITCODE_MONITOR;
		break;
	case VMCB_EXIT_MWAIT:
		vmexit->exitcode = VM_EXITCODE_MWAIT;
		break;
	default:
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_UNKNOWN, 1);
		break;
	}

	DTRACE_PROBE3(vmm__vexit, int, vcpu, uint64_t, vmexit->rip, uint32_t,
	    code);

	if (handled) {
		vmexit->rip += vmexit->inst_length;
		vmexit->inst_length = 0;
		state->rip = vmexit->rip;
	} else {
		if (vmexit->exitcode == VM_EXITCODE_BOGUS) {
			/*
			 * If this VM exit was not claimed by anybody then
			 * treat it as a generic SVM exit.
			 */
			vm_exit_svm(vmexit, code, info1, info2);
		} else {
			/*
			 * The exitcode and collateral have been populated.
			 * The VM exit will be processed further in userland.
			 */
		}
	}
	return (handled);
}

/*
 * Inject exceptions, NMIs, and ExtINTs.
 *
 * The logic behind these are complicated and may involve mutex contention, so
 * the injection is performed without the protection of host CPU interrupts
 * being disabled.  This means a racing notification could be "lost",
 * necessitating a later call to svm_inject_recheck() to close that window
 * of opportunity.
 */
static enum event_inject_state
svm_inject_events(struct svm_softc *sc, int vcpu)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	struct svm_vcpu *vcpustate;
	uint64_t intinfo;
	enum event_inject_state ev_state;

	state = svm_get_vmcb_state(sc, vcpu);
	ctrl  = svm_get_vmcb_ctrl(sc, vcpu);
	vcpustate = svm_get_vcpu(sc, vcpu);
	ev_state = EIS_CAN_INJECT;

	/* Clear any interrupt shadow if guest %rip has changed */
	if (vcpustate->nextrip != state->rip) {
		ctrl->intr_shadow = 0;
	}

	/*
	 * An event is already pending for injection.  This can occur when the
	 * vCPU exits prior to VM entry (like for an AST).
	 */
	if (ctrl->eventinj & VMCB_EVENTINJ_VALID) {
		return (EIS_EV_EXISTING | EIS_REQ_EXIT);
	}

	/*
	 * Inject pending events or exceptions for this vcpu.
	 *
	 * An event might be pending because the previous #VMEXIT happened
	 * during event delivery (i.e. ctrl->exitintinfo).
	 *
	 * An event might also be pending because an exception was injected
	 * by the hypervisor (e.g. #PF during instruction emulation).
	 */
	if (vm_entry_intinfo(sc->vm, vcpu, &intinfo)) {
		svm_inject_event(ctrl, intinfo);
		vmm_stat_incr(sc->vm, vcpu, VCPU_INTINFO_INJECTED, 1);
		ev_state = EIS_EV_INJECTED;
	}

	/* NMI event has priority over interrupts. */
	if (vm_nmi_pending(sc->vm, vcpu) && !svm_nmi_blocked(sc, vcpu)) {
		if (ev_state == EIS_CAN_INJECT) {
			/* Can't inject NMI if vcpu is in an intr_shadow. */
			if (ctrl->intr_shadow) {
				return (EIS_GI_BLOCK);
			}

			svm_inject_nmi(sc, vcpu);
			ev_state = EIS_EV_INJECTED;
		} else {
			return (ev_state | EIS_REQ_EXIT);
		}
	}

	if (vm_extint_pending(sc->vm, vcpu)) {
		int vector;

		if (ev_state != EIS_CAN_INJECT) {
			return (ev_state | EIS_REQ_EXIT);
		}

		/*
		 * If the guest has disabled interrupts or is in an interrupt
		 * shadow then we cannot inject the pending interrupt.
		 */
		if ((state->rflags & PSL_I) == 0 || ctrl->intr_shadow) {
			return (EIS_GI_BLOCK);
		}

		/* Ask the legacy pic for a vector to inject */
		vatpic_pending_intr(sc->vm, &vector);
		KASSERT(vector >= 0 && vector <= 255,
		    ("invalid vector %d from INTR", vector));

		svm_inject_irq(sc, vcpu, vector);
		vm_extint_clear(sc->vm, vcpu);
		vatpic_intr_accepted(sc->vm, vector);
		ev_state = EIS_EV_INJECTED;
	}

	return (ev_state);
}

/*
 * Synchronize vLAPIC state and inject any interrupts pending on it.
 *
 * This is done with host CPU interrupts disabled so notification IPIs will be
 * queued on the host APIC and recognized when entering SVM guest context.
 */
static enum event_inject_state
svm_inject_vlapic(struct svm_softc *sc, int vcpu, struct vlapic *vlapic,
    enum event_inject_state ev_state)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	int vector;
	uint8_t v_tpr;

	state = svm_get_vmcb_state(sc, vcpu);
	ctrl  = svm_get_vmcb_ctrl(sc, vcpu);

	/*
	 * The guest can modify the TPR by writing to %cr8. In guest mode the
	 * CPU reflects this write to V_TPR without hypervisor intervention.
	 *
	 * The guest can also modify the TPR by writing to it via the memory
	 * mapped APIC page. In this case, the write will be emulated by the
	 * hypervisor. For this reason V_TPR must be updated before every
	 * VMRUN.
	 */
	v_tpr = vlapic_get_cr8(vlapic);
	KASSERT(v_tpr <= 15, ("invalid v_tpr %x", v_tpr));
	if (ctrl->v_tpr != v_tpr) {
		ctrl->v_tpr = v_tpr;
		svm_set_dirty(sc, vcpu, VMCB_CACHE_TPR);
	}

	/* If an event cannot otherwise be injected, we are done for now */
	if (ev_state != EIS_CAN_INJECT) {
		return (ev_state);
	}

	if (!vlapic_pending_intr(vlapic, &vector)) {
		return (EIS_CAN_INJECT);
	}
	KASSERT(vector >= 16 && vector <= 255,
	    ("invalid vector %d from local APIC", vector));

	/*
	 * If the guest has disabled interrupts or is in an interrupt shadow
	 * then we cannot inject the pending interrupt.
	 */
	if ((state->rflags & PSL_I) == 0 || ctrl->intr_shadow) {
		return (EIS_GI_BLOCK);
	}

	svm_inject_irq(sc, vcpu, vector);
	vlapic_intr_accepted(vlapic, vector);
	return (EIS_EV_INJECTED);
}

/*
 * Re-check for events to be injected.
 *
 * Once host CPU interrupts are disabled, check for the presence of any events
 * which require injection processing.  If an exit is required upon injection,
 * or once the guest becomes interruptable, that will be configured too.
 */
static bool
svm_inject_recheck(struct svm_softc *sc, int vcpu,
    enum event_inject_state ev_state)
{
	struct vmcb_ctrl *ctrl;

	ctrl  = svm_get_vmcb_ctrl(sc, vcpu);

	if (ev_state == EIS_CAN_INJECT) {
		/*
		 * An active interrupt shadow would preclude us from injecting
		 * any events picked up during a re-check.
		 */
		if (ctrl->intr_shadow != 0) {
			return (false);
		}

		if (vm_nmi_pending(sc->vm, vcpu) &&
		    !svm_nmi_blocked(sc, vcpu)) {
			/* queued NMI not blocked by NMI-window-exiting */
			return (true);
		}
		if (vm_extint_pending(sc->vm, vcpu)) {
			/* queued ExtINT not blocked by existing injection */
			return (true);
		}
	} else {
		if ((ev_state & EIS_REQ_EXIT) != 0) {
			/*
			 * Use a self-IPI to force an immediate exit after
			 * event injection has occurred.
			 */
			poke_cpu(CPU->cpu_id);
		} else {
			/*
			 * If any event is being injected, an exit immediately
			 * upon becoming interruptable again will allow pending
			 * or newly queued events to be injected in a timely
			 * manner.
			 */
			svm_enable_intr_window_exiting(sc, vcpu);
		}
	}
	return (false);
}


static void
check_asid(struct svm_softc *sc, int vcpuid, uint_t thiscpu, uint64_t nptgen)
{
	struct svm_vcpu *vcpustate = svm_get_vcpu(sc, vcpuid);
	struct vmcb_ctrl *ctrl = svm_get_vmcb_ctrl(sc, vcpuid);
	uint8_t flush;

	flush = hma_svm_asid_update(&vcpustate->hma_asid, flush_by_asid(),
	    vcpustate->nptgen != nptgen);

	if (flush != VMCB_TLB_FLUSH_NOTHING) {
		ctrl->asid = vcpustate->hma_asid.hsa_asid;
		svm_set_dirty(sc, vcpuid, VMCB_CACHE_ASID);
	}
	ctrl->tlb_ctrl = flush;
	vcpustate->nptgen = nptgen;
}

static void
flush_asid(struct svm_softc *sc, int vcpuid)
{
	struct svm_vcpu *vcpustate = svm_get_vcpu(sc, vcpuid);
	struct vmcb_ctrl *ctrl = svm_get_vmcb_ctrl(sc, vcpuid);
	uint8_t flush;

	flush = hma_svm_asid_update(&vcpustate->hma_asid, flush_by_asid(),
	    true);

	ASSERT(flush != VMCB_TLB_FLUSH_NOTHING);
	ctrl->asid = vcpustate->hma_asid.hsa_asid;
	ctrl->tlb_ctrl = flush;
	svm_set_dirty(sc, vcpuid, VMCB_CACHE_ASID);
	/*
	 * A potential future optimization: We could choose to update the nptgen
	 * associated with the vCPU, since any pending nptgen change requiring a
	 * flush will be satisfied by the one which has just now been queued.
	 */
}

static __inline void
disable_gintr(void)
{
	__asm __volatile("clgi");
}

static __inline void
enable_gintr(void)
{
	__asm __volatile("stgi");
}

static __inline void
svm_dr_enter_guest(struct svm_regctx *gctx)
{

	/* Save host control debug registers. */
	gctx->host_dr7 = rdr7();
	gctx->host_debugctl = rdmsr(MSR_DEBUGCTLMSR);

	/*
	 * Disable debugging in DR7 and DEBUGCTL to avoid triggering
	 * exceptions in the host based on the guest DRx values.  The
	 * guest DR6, DR7, and DEBUGCTL are saved/restored in the
	 * VMCB.
	 */
	load_dr7(0);
	wrmsr(MSR_DEBUGCTLMSR, 0);

	/* Save host debug registers. */
	gctx->host_dr0 = rdr0();
	gctx->host_dr1 = rdr1();
	gctx->host_dr2 = rdr2();
	gctx->host_dr3 = rdr3();
	gctx->host_dr6 = rdr6();

	/* Restore guest debug registers. */
	load_dr0(gctx->sctx_dr0);
	load_dr1(gctx->sctx_dr1);
	load_dr2(gctx->sctx_dr2);
	load_dr3(gctx->sctx_dr3);
}

static __inline void
svm_dr_leave_guest(struct svm_regctx *gctx)
{

	/* Save guest debug registers. */
	gctx->sctx_dr0 = rdr0();
	gctx->sctx_dr1 = rdr1();
	gctx->sctx_dr2 = rdr2();
	gctx->sctx_dr3 = rdr3();

	/*
	 * Restore host debug registers.  Restore DR7 and DEBUGCTL
	 * last.
	 */
	load_dr0(gctx->host_dr0);
	load_dr1(gctx->host_dr1);
	load_dr2(gctx->host_dr2);
	load_dr3(gctx->host_dr3);
	load_dr6(gctx->host_dr6);
	wrmsr(MSR_DEBUGCTLMSR, gctx->host_debugctl);
	load_dr7(gctx->host_dr7);
}

static void
svm_apply_tsc_adjust(struct svm_softc *svm_sc, int vcpuid)
{
	const uint64_t offset = vcpu_tsc_offset(svm_sc->vm, vcpuid, true);
	struct vmcb_ctrl *ctrl = svm_get_vmcb_ctrl(svm_sc, vcpuid);

	if (ctrl->tsc_offset != offset) {
		ctrl->tsc_offset = offset;
		svm_set_dirty(svm_sc, vcpuid, VMCB_CACHE_I);
	}
}


/*
 * Start vcpu with specified RIP.
 */
static int
svm_vmrun(void *arg, int vcpu, uint64_t rip)
{
	struct svm_regctx *gctx;
	struct svm_softc *svm_sc;
	struct svm_vcpu *vcpustate;
	struct vmcb_state *state;
	struct vmcb_ctrl *ctrl;
	struct vm_exit *vmexit;
	struct vlapic *vlapic;
	vm_client_t *vmc;
	struct vm *vm;
	uint64_t vmcb_pa;
	int handled;
	uint16_t ldt_sel;

	svm_sc = arg;
	vm = svm_sc->vm;

	vcpustate = svm_get_vcpu(svm_sc, vcpu);
	state = svm_get_vmcb_state(svm_sc, vcpu);
	ctrl = svm_get_vmcb_ctrl(svm_sc, vcpu);
	vmexit = vm_exitinfo(vm, vcpu);
	vlapic = vm_lapic(vm, vcpu);
	vmc = vm_get_vmclient(vm, vcpu);

	gctx = svm_get_guest_regctx(svm_sc, vcpu);
	vmcb_pa = svm_sc->vcpu[vcpu].vmcb_pa;

	if (vcpustate->lastcpu != curcpu) {
		/*
		 * Force new ASID allocation by invalidating the generation.
		 */
		vcpustate->hma_asid.hsa_gen = 0;

		/*
		 * Invalidate the VMCB state cache by marking all fields dirty.
		 */
		svm_set_dirty(svm_sc, vcpu, 0xffffffff);

		/*
		 * XXX
		 * Setting 'vcpustate->lastcpu' here is bit premature because
		 * we may return from this function without actually executing
		 * the VMRUN  instruction. This could happen if an AST or yield
		 * condition is pending on the first time through the loop.
		 *
		 * This works for now but any new side-effects of vcpu
		 * migration should take this case into account.
		 */
		vcpustate->lastcpu = curcpu;
		vmm_stat_incr(vm, vcpu, VCPU_MIGRATIONS, 1);
	}

	svm_apply_tsc_adjust(svm_sc, vcpu);

	svm_msr_guest_enter(svm_sc, vcpu);

	VERIFY(!vcpustate->loaded && curthread->t_preempt != 0);
	vcpustate->loaded = B_TRUE;

	/* Update Guest RIP */
	state->rip = rip;

	do {
		enum event_inject_state inject_state;
		uint64_t nptgen;

		/*
		 * Initial event injection is complex and may involve mutex
		 * contention, so it must be performed with global interrupts
		 * still enabled.
		 */
		inject_state = svm_inject_events(svm_sc, vcpu);
		handled = 0;

		/*
		 * Disable global interrupts to guarantee atomicity during
		 * loading of guest state. This includes not only the state
		 * loaded by the "vmrun" instruction but also software state
		 * maintained by the hypervisor: suspended and rendezvous
		 * state, NPT generation number, vlapic interrupts etc.
		 */
		disable_gintr();

		/*
		 * Synchronizing and injecting vlapic state is lock-free and is
		 * safe (and prudent) to perform with interrupts disabled.
		 */
		inject_state = svm_inject_vlapic(svm_sc, vcpu, vlapic,
		    inject_state);

		/*
		 * Check for vCPU bail-out conditions.  This must be done after
		 * svm_inject_events() to detect a triple-fault condition.
		 */
		if (vcpu_entry_bailout_checks(vm, vcpu, state->rip)) {
			enable_gintr();
			break;
		}

		if (vcpu_run_state_pending(vm, vcpu)) {
			enable_gintr();
			vm_exit_run_state(vm, vcpu, state->rip);
			break;
		}

		/*
		 * If subsequent activity queued events which require injection
		 * handling, take another lap to handle them.
		 */
		if (svm_inject_recheck(svm_sc, vcpu, inject_state)) {
			enable_gintr();
			handled = 1;
			continue;
		}

		/*
		 * #VMEXIT resumes the host with the guest LDTR, so
		 * save the current LDT selector so it can be restored
		 * after an exit.  The userspace hypervisor probably
		 * doesn't use a LDT, but save and restore it to be
		 * safe.
		 */
		ldt_sel = sldt();

		/*
		 * Check the vmspace and ASID generations to ensure that the
		 * vcpu does not use stale TLB mappings.
		 */
		nptgen = vmc_table_enter(vmc);
		check_asid(svm_sc, vcpu, curcpu, nptgen);

		ctrl->vmcb_clean = vmcb_clean & ~vcpustate->dirty;
		vcpustate->dirty = 0;

		/* Launch Virtual Machine. */
		vcpu_ustate_change(vm, vcpu, VU_RUN);
		svm_dr_enter_guest(gctx);
		svm_launch(vmcb_pa, gctx, get_pcpu());
		svm_dr_leave_guest(gctx);
		vcpu_ustate_change(vm, vcpu, VU_EMU_KERN);

		/* Restore host LDTR. */
		lldt(ldt_sel);

		/* #VMEXIT disables interrupts so re-enable them here. */
		enable_gintr();

		vmc_table_exit(vmc);

		/* Update 'nextrip' */
		vcpustate->nextrip = state->rip;

		/* Handle #VMEXIT and if required return to user space. */
		handled = svm_vmexit(svm_sc, vcpu, vmexit);
	} while (handled);

	svm_msr_guest_exit(svm_sc, vcpu);

	VERIFY(vcpustate->loaded && curthread->t_preempt != 0);
	vcpustate->loaded = B_FALSE;

	return (0);
}

static void
svm_vmcleanup(void *arg)
{
	struct svm_softc *sc = arg;

	vmm_contig_free(sc->iopm_bitmap, SVM_IO_BITMAP_SIZE);
	vmm_contig_free(sc->msr_bitmap, SVM_MSR_BITMAP_SIZE);
	kmem_free(sc, sizeof (*sc));
}

static uint64_t *
swctx_regptr(struct svm_regctx *regctx, int reg)
{
	switch (reg) {
	case VM_REG_GUEST_RBX:
		return (&regctx->sctx_rbx);
	case VM_REG_GUEST_RCX:
		return (&regctx->sctx_rcx);
	case VM_REG_GUEST_RDX:
		return (&regctx->sctx_rdx);
	case VM_REG_GUEST_RDI:
		return (&regctx->sctx_rdi);
	case VM_REG_GUEST_RSI:
		return (&regctx->sctx_rsi);
	case VM_REG_GUEST_RBP:
		return (&regctx->sctx_rbp);
	case VM_REG_GUEST_R8:
		return (&regctx->sctx_r8);
	case VM_REG_GUEST_R9:
		return (&regctx->sctx_r9);
	case VM_REG_GUEST_R10:
		return (&regctx->sctx_r10);
	case VM_REG_GUEST_R11:
		return (&regctx->sctx_r11);
	case VM_REG_GUEST_R12:
		return (&regctx->sctx_r12);
	case VM_REG_GUEST_R13:
		return (&regctx->sctx_r13);
	case VM_REG_GUEST_R14:
		return (&regctx->sctx_r14);
	case VM_REG_GUEST_R15:
		return (&regctx->sctx_r15);
	case VM_REG_GUEST_DR0:
		return (&regctx->sctx_dr0);
	case VM_REG_GUEST_DR1:
		return (&regctx->sctx_dr1);
	case VM_REG_GUEST_DR2:
		return (&regctx->sctx_dr2);
	case VM_REG_GUEST_DR3:
		return (&regctx->sctx_dr3);
	default:
		return (NULL);
	}
}

static int
svm_getreg(void *arg, int vcpu, int ident, uint64_t *val)
{
	struct svm_softc *sc;
	struct vmcb *vmcb;
	uint64_t *regp;
	uint64_t *fieldp;
	struct vmcb_segment *seg;

	sc = arg;
	vmcb = svm_get_vmcb(sc, vcpu);

	regp = swctx_regptr(svm_get_guest_regctx(sc, vcpu), ident);
	if (regp != NULL) {
		*val = *regp;
		return (0);
	}

	switch (ident) {
	case VM_REG_GUEST_INTR_SHADOW:
		*val = (vmcb->ctrl.intr_shadow != 0) ? 1 : 0;
		break;

	case VM_REG_GUEST_CR0:
		svm_get_cr0(sc, vcpu, val);
		break;
	case VM_REG_GUEST_CR2:
	case VM_REG_GUEST_CR3:
	case VM_REG_GUEST_CR4:
	case VM_REG_GUEST_DR6:
	case VM_REG_GUEST_DR7:
	case VM_REG_GUEST_EFER:
	case VM_REG_GUEST_RAX:
	case VM_REG_GUEST_RFLAGS:
	case VM_REG_GUEST_RIP:
	case VM_REG_GUEST_RSP:
		fieldp = vmcb_regptr(vmcb, ident, NULL);
		*val = *fieldp;
		break;

	case VM_REG_GUEST_CS:
	case VM_REG_GUEST_DS:
	case VM_REG_GUEST_ES:
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_SS:
	case VM_REG_GUEST_LDTR:
	case VM_REG_GUEST_TR:
		seg = vmcb_segptr(vmcb, ident);
		*val = seg->selector;
		break;

	case VM_REG_GUEST_GDTR:
	case VM_REG_GUEST_IDTR:
		/* GDTR and IDTR don't have segment selectors */
		return (EINVAL);

	case VM_REG_GUEST_PDPTE0:
	case VM_REG_GUEST_PDPTE1:
	case VM_REG_GUEST_PDPTE2:
	case VM_REG_GUEST_PDPTE3:
		/*
		 * Unlike VMX, where the PDPTEs are explicitly cached as part of
		 * several well-defined events related to paging (such as
		 * loading %cr3), SVM walks the PDPEs (their PDPTE) as part of
		 * nested paging lookups.  This makes these registers
		 * effectively irrelevant on SVM.
		 *
		 * Rather than tossing an error, emit zeroed values so casual
		 * consumers do not need to be as careful about that difference.
		 */
		*val = 0;
		break;

	default:
		return (EINVAL);
	}

	return (0);
}

static int
svm_setreg(void *arg, int vcpu, int ident, uint64_t val)
{
	struct svm_softc *sc;
	struct vmcb *vmcb;
	uint64_t *regp;
	uint64_t *fieldp;
	uint32_t dirty;
	struct vmcb_segment *seg;

	sc = arg;
	vmcb = svm_get_vmcb(sc, vcpu);

	regp = swctx_regptr(svm_get_guest_regctx(sc, vcpu), ident);
	if (regp != NULL) {
		*regp = val;
		return (0);
	}

	dirty = VMCB_CACHE_NONE;
	switch (ident) {
	case VM_REG_GUEST_INTR_SHADOW:
		vmcb->ctrl.intr_shadow = (val != 0) ? 1 : 0;
		break;

	case VM_REG_GUEST_EFER:
		fieldp = vmcb_regptr(vmcb, ident, &dirty);
		/* EFER_SVM must always be set when the guest is executing */
		*fieldp = val | EFER_SVM;
		dirty |= VMCB_CACHE_CR;
		break;

	case VM_REG_GUEST_CR0:
		svm_set_cr0(sc, vcpu, val, false);
		break;
	case VM_REG_GUEST_CR2:
	case VM_REG_GUEST_CR3:
	case VM_REG_GUEST_CR4:
	case VM_REG_GUEST_DR6:
	case VM_REG_GUEST_DR7:
	case VM_REG_GUEST_RAX:
	case VM_REG_GUEST_RFLAGS:
	case VM_REG_GUEST_RIP:
	case VM_REG_GUEST_RSP:
		fieldp = vmcb_regptr(vmcb, ident, &dirty);
		*fieldp = val;
		break;

	case VM_REG_GUEST_CS:
	case VM_REG_GUEST_DS:
	case VM_REG_GUEST_ES:
	case VM_REG_GUEST_SS:
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_LDTR:
	case VM_REG_GUEST_TR:
		dirty |= VMCB_CACHE_SEG;
		seg = vmcb_segptr(vmcb, ident);
		seg->selector = (uint16_t)val;
		break;

	case VM_REG_GUEST_GDTR:
	case VM_REG_GUEST_IDTR:
		/* GDTR and IDTR don't have segment selectors */
		return (EINVAL);

	case VM_REG_GUEST_PDPTE0:
	case VM_REG_GUEST_PDPTE1:
	case VM_REG_GUEST_PDPTE2:
	case VM_REG_GUEST_PDPTE3:
		/*
		 * PDPEs (AMD's PDPTE) are not cached under SVM, so we can
		 * ignore attempts to set them.  See handler in svm_getreg() for
		 * more details.
		 */
		break;

	default:
		return (EINVAL);
	}

	if (dirty != VMCB_CACHE_NONE) {
		svm_set_dirty(sc, vcpu, dirty);
	}

	/*
	 * XXX deal with CR3 and invalidate TLB entries tagged with the
	 * vcpu's ASID. This needs to be treated differently depending on
	 * whether 'running' is true/false.
	 */

	return (0);
}

static int
svm_setdesc(void *arg, int vcpu, int reg, const struct seg_desc *desc)
{
	struct vmcb *vmcb;
	struct svm_softc *sc;
	struct vmcb_segment *seg;

	sc = arg;
	vmcb = svm_get_vmcb(sc, vcpu);

	switch (reg) {
	case VM_REG_GUEST_CS:
	case VM_REG_GUEST_DS:
	case VM_REG_GUEST_ES:
	case VM_REG_GUEST_SS:
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_LDTR:
	case VM_REG_GUEST_TR:
		svm_set_dirty(sc, vcpu, VMCB_CACHE_SEG);
		seg = vmcb_segptr(vmcb, reg);
		/*
		 * Map seg_desc access to VMCB attribute format.
		 *
		 * SVM uses the 'P' bit in the segment attributes to indicate a
		 * NULL segment so clear it if the segment is marked unusable.
		 */
		seg->attrib = VMCB_ACCESS2ATTR(desc->access);
		if (SEG_DESC_UNUSABLE(desc->access)) {
			seg->attrib &= ~0x80;
		}
		/*
		 * Keep CPL synced with the DPL specified for %ss.
		 *
		 * KVM notes that a SYSRET to non-cpl-3 is possible on AMD
		 * (unlike Intel), but accepts such a possible deviation for
		 * what is otherwise unreasonable behavior for a guest OS, since
		 * they do the same synchronization.
		 */
		if (reg == VM_REG_GUEST_SS) {
			vmcb->state.cpl = SEG_DESC_DPL(desc->access);
		}
		break;

	case VM_REG_GUEST_GDTR:
	case VM_REG_GUEST_IDTR:
		svm_set_dirty(sc, vcpu, VMCB_CACHE_DT);
		seg = vmcb_segptr(vmcb, reg);
		break;

	default:
		return (EINVAL);
	}

	ASSERT(seg != NULL);
	seg->base = desc->base;
	seg->limit = desc->limit;

	return (0);
}

static int
svm_getdesc(void *arg, int vcpu, int reg, struct seg_desc *desc)
{
	struct vmcb *vmcb;
	struct svm_softc *sc;
	struct vmcb_segment *seg;

	sc = arg;
	vmcb = svm_get_vmcb(sc, vcpu);

	switch (reg) {
	case VM_REG_GUEST_DS:
	case VM_REG_GUEST_ES:
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_SS:
	case VM_REG_GUEST_LDTR:
		seg = vmcb_segptr(vmcb, reg);
		desc->access = VMCB_ATTR2ACCESS(seg->attrib);
		/*
		 * VT-x uses bit 16 to indicate a segment that has been loaded
		 * with a NULL selector (aka unusable). The 'desc->access'
		 * field is interpreted in the VT-x format by the
		 * processor-independent code.
		 *
		 * SVM uses the 'P' bit to convey the same information so
		 * convert it into the VT-x format. For more details refer to
		 * section "Segment State in the VMCB" in APMv2.
		 */
		if ((desc->access & 0x80) == 0) {
			/* Unusable segment */
			desc->access |= 0x10000;
		}
		break;

	case VM_REG_GUEST_CS:
	case VM_REG_GUEST_TR:
		seg = vmcb_segptr(vmcb, reg);
		desc->access = VMCB_ATTR2ACCESS(seg->attrib);
		break;

	case VM_REG_GUEST_GDTR:
	case VM_REG_GUEST_IDTR:
		seg = vmcb_segptr(vmcb, reg);
		/*
		 * Since there are no access bits associated with the GDTR or
		 * the IDTR, zero out the field to ensure it does not contain
		 * garbage which might confuse the consumer.
		 */
		desc->access = 0;
		break;

	default:
		return (EINVAL);
	}

	ASSERT(seg != NULL);
	desc->base = seg->base;
	desc->limit = seg->limit;
	return (0);
}

static int
svm_get_msr(void *arg, int vcpu, uint32_t msr, uint64_t *valp)
{
	struct svm_softc *sc = arg;
	struct vmcb *vmcb = svm_get_vmcb(sc, vcpu);
	const uint64_t *msrp = vmcb_msr_ptr(vmcb, msr, NULL);

	if (msrp != NULL) {
		*valp = *msrp;
		return (0);
	}

	return (EINVAL);
}

static int
svm_set_msr(void *arg, int vcpu, uint32_t msr, uint64_t val)
{
	struct svm_softc *sc = arg;
	struct vmcb *vmcb = svm_get_vmcb(sc, vcpu);

	uint32_t dirty = 0;
	uint64_t *msrp = vmcb_msr_ptr(vmcb, msr, &dirty);
	if (msrp == NULL) {
		return (EINVAL);
	}
	switch (msr) {
	case MSR_EFER:
		/*
		 * For now, just clone the logic from
		 * svm_setreg():
		 *
		 * EFER_SVM must always be set when the guest is
		 * executing
		 */
		*msrp = val | EFER_SVM;
		break;
	/* TODO: other necessary MSR masking */
	default:
		*msrp = val;
		break;
	}
	if (dirty != 0) {
		svm_set_dirty(sc, vcpu, dirty);
	}
	return (0);

}

static int
svm_setcap(void *arg, int vcpu, int type, int val)
{
	struct svm_softc *sc;
	int error;

	sc = arg;
	error = 0;
	switch (type) {
	case VM_CAP_HALT_EXIT:
		svm_set_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_HLT, val);
		break;
	case VM_CAP_PAUSE_EXIT:
		svm_set_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_PAUSE, val);
		break;
	default:
		error = ENOENT;
		break;
	}
	return (error);
}

static int
svm_getcap(void *arg, int vcpu, int type, int *retval)
{
	struct svm_softc *sc;
	int error;

	sc = arg;
	error = 0;

	switch (type) {
	case VM_CAP_HALT_EXIT:
		*retval = svm_get_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_HLT);
		break;
	case VM_CAP_PAUSE_EXIT:
		*retval = svm_get_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_PAUSE);
		break;
	default:
		error = ENOENT;
		break;
	}
	return (error);
}

static struct vlapic *
svm_vlapic_init(void *arg, int vcpuid)
{
	struct svm_softc *svm_sc;
	struct vlapic *vlapic;

	svm_sc = arg;
	vlapic = kmem_zalloc(sizeof (struct vlapic), KM_SLEEP);
	vlapic->vm = svm_sc->vm;
	vlapic->vcpuid = vcpuid;
	vlapic->apic_page = (struct LAPIC *)&svm_sc->apic_page[vcpuid];

	vlapic_init(vlapic);

	return (vlapic);
}

static void
svm_vlapic_cleanup(void *arg, struct vlapic *vlapic)
{
	vlapic_cleanup(vlapic);
	kmem_free(vlapic, sizeof (struct vlapic));
}

static void
svm_pause(void *arg, int vcpu)
{
	struct svm_softc *sc = arg;
	struct vmcb_ctrl *ctrl = svm_get_vmcb_ctrl(sc, vcpu);

	/*
	 * If an event is pending injection in the VMCB, stash it in
	 * exit_intinfo as if it were deferred by an exit from guest context.
	 */
	const uint64_t intinfo = ctrl->eventinj;
	if ((intinfo & VMCB_EVENTINJ_VALID) != 0) {
		svm_stash_intinfo(sc, vcpu, intinfo);
		ctrl->eventinj = 0;
	}

	/*
	 * Now that no event is pending injection, interrupt-window exiting and
	 * NMI-blocking can be disabled.  If/when this vCPU is made to run
	 * again, those conditions will be reinstated when the now-queued events
	 * are re-injected.
	 */
	svm_disable_intr_window_exiting(sc, vcpu);
	svm_disable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_IRET);
}

static void
svm_savectx(void *arg, int vcpu)
{
	struct svm_softc *sc = arg;

	if (sc->vcpu[vcpu].loaded) {
		svm_msr_guest_exit(sc, vcpu);
	}
}

static void
svm_restorectx(void *arg, int vcpu)
{
	struct svm_softc *sc = arg;

	if (sc->vcpu[vcpu].loaded) {
		svm_msr_guest_enter(sc, vcpu);
	}
}

struct vmm_ops vmm_ops_amd = {
	.init		= svm_init,
	.cleanup	= svm_cleanup,
	.resume		= svm_restore,

	.vminit		= svm_vminit,
	.vmrun		= svm_vmrun,
	.vmcleanup	= svm_vmcleanup,
	.vmgetreg	= svm_getreg,
	.vmsetreg	= svm_setreg,
	.vmgetdesc	= svm_getdesc,
	.vmsetdesc	= svm_setdesc,
	.vmgetcap	= svm_getcap,
	.vmsetcap	= svm_setcap,
	.vlapic_init	= svm_vlapic_init,
	.vlapic_cleanup	= svm_vlapic_cleanup,
	.vmpause	= svm_pause,

	.vmsavectx	= svm_savectx,
	.vmrestorectx	= svm_restorectx,

	.vmgetmsr	= svm_get_msr,
	.vmsetmsr	= svm_set_msr,
};
