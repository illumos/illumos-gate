/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 * Copyright (c) 2018 Joyent, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
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
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2022 Oxide Computer Company
 * Copyright 2022 MNX Cloud, Inc.
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
#include <sys/smp_impldefs.h>
#include <sys/smt.h>
#include <sys/hma.h>
#include <sys/trap.h>
#include <sys/archsystm.h>

#include <machine/psl.h>
#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/reg.h>
#include <machine/segments.h>
#include <machine/specialreg.h>
#include <machine/vmparam.h>
#include <sys/vmm_vm.h>
#include <sys/vmm_kernel.h>

#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <sys/vmm_instruction_emul.h>
#include "vmm_lapic.h"
#include "vmm_host.h"
#include "vmm_ioport.h"
#include "vmm_stat.h"
#include "vatpic.h"
#include "vlapic.h"
#include "vlapic_priv.h"

#include "vmcs.h"
#include "vmx.h"
#include "vmx_msr.h"
#include "vmx_controls.h"

#define	PINBASED_CTLS_ONE_SETTING					\
	(PINBASED_EXTINT_EXITING	|				\
	PINBASED_NMI_EXITING		|				\
	PINBASED_VIRTUAL_NMI)
#define	PINBASED_CTLS_ZERO_SETTING	0

#define	PROCBASED_CTLS_WINDOW_SETTING					\
	(PROCBASED_INT_WINDOW_EXITING	|				\
	PROCBASED_NMI_WINDOW_EXITING)

/*
 * Distinct from FreeBSD bhyve, we consider several additional proc-based
 * controls necessary:
 * - TSC offsetting
 * - HLT exiting
 */
#define	PROCBASED_CTLS_ONE_SETTING					\
	(PROCBASED_SECONDARY_CONTROLS	|				\
	PROCBASED_TSC_OFFSET		|				\
	PROCBASED_HLT_EXITING		|				\
	PROCBASED_MWAIT_EXITING		|				\
	PROCBASED_MONITOR_EXITING	|				\
	PROCBASED_IO_EXITING		|				\
	PROCBASED_MSR_BITMAPS		|				\
	PROCBASED_CTLS_WINDOW_SETTING	|				\
	PROCBASED_CR8_LOAD_EXITING	|				\
	PROCBASED_CR8_STORE_EXITING)

#define	PROCBASED_CTLS_ZERO_SETTING	\
	(PROCBASED_CR3_LOAD_EXITING |	\
	PROCBASED_CR3_STORE_EXITING |	\
	PROCBASED_IO_BITMAPS)

/*
 * EPT and Unrestricted Guest are considered necessities.  The latter is not a
 * requirement on FreeBSD, where grub2-bhyve is used to load guests directly
 * without a bootrom starting in real mode.
 */
#define	PROCBASED_CTLS2_ONE_SETTING		\
	(PROCBASED2_ENABLE_EPT |		\
	PROCBASED2_UNRESTRICTED_GUEST)
#define	PROCBASED_CTLS2_ZERO_SETTING	0

#define	VM_EXIT_CTLS_ONE_SETTING					\
	(VM_EXIT_SAVE_DEBUG_CONTROLS		|			\
	VM_EXIT_HOST_LMA			|			\
	VM_EXIT_LOAD_PAT			|			\
	VM_EXIT_SAVE_EFER			|			\
	VM_EXIT_LOAD_EFER			|			\
	VM_EXIT_ACKNOWLEDGE_INTERRUPT)

#define	VM_EXIT_CTLS_ZERO_SETTING	0

#define	VM_ENTRY_CTLS_ONE_SETTING					\
	(VM_ENTRY_LOAD_DEBUG_CONTROLS		|			\
	VM_ENTRY_LOAD_EFER)

#define	VM_ENTRY_CTLS_ZERO_SETTING					\
	(VM_ENTRY_INTO_SMM			|			\
	VM_ENTRY_DEACTIVATE_DUAL_MONITOR)

/*
 * Cover the EPT capabilities used by bhyve at present:
 * - 4-level page walks
 * - write-back memory type
 * - INVEPT operations (all types)
 * - INVVPID operations (single-context only)
 */
#define	EPT_CAPS_REQUIRED			\
	(IA32_VMX_EPT_VPID_PWL4 |		\
	IA32_VMX_EPT_VPID_TYPE_WB |		\
	IA32_VMX_EPT_VPID_INVEPT |		\
	IA32_VMX_EPT_VPID_INVEPT_SINGLE |	\
	IA32_VMX_EPT_VPID_INVEPT_ALL |		\
	IA32_VMX_EPT_VPID_INVVPID |		\
	IA32_VMX_EPT_VPID_INVVPID_SINGLE)

#define	HANDLED		1
#define	UNHANDLED	0

SYSCTL_DECL(_hw_vmm);
SYSCTL_NODE(_hw_vmm, OID_AUTO, vmx, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    NULL);

static uint32_t pinbased_ctls, procbased_ctls, procbased_ctls2;
static uint32_t exit_ctls, entry_ctls;

static uint64_t cr0_ones_mask, cr0_zeros_mask;

static uint64_t cr4_ones_mask, cr4_zeros_mask;

static int vmx_initialized;

/*
 * Optional capabilities
 */

/* PAUSE triggers a VM-exit */
static int cap_pause_exit;

/* WBINVD triggers a VM-exit */
static int cap_wbinvd_exit;

/* Monitor trap flag */
static int cap_monitor_trap;

/* Guests are allowed to use INVPCID */
static int cap_invpcid;

/* Extra capabilities (VMX_CAP_*) beyond the minimum */
static enum vmx_caps vmx_capabilities;

/* APICv posted interrupt vector */
static int pirvec = -1;

static uint_t vpid_alloc_failed;

int guest_l1d_flush;
int guest_l1d_flush_sw;

/* MSR save region is composed of an array of 'struct msr_entry' */
struct msr_entry {
	uint32_t	index;
	uint32_t	reserved;
	uint64_t	val;
};

static struct msr_entry msr_load_list[1] __aligned(16);

/*
 * The definitions of SDT probes for VMX.
 */

/* BEGIN CSTYLED */
SDT_PROBE_DEFINE3(vmm, vmx, exit, entry,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, taskswitch,
    "struct vmx *", "int", "struct vm_exit *", "struct vm_task_switch *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, craccess,
    "struct vmx *", "int", "struct vm_exit *", "uint64_t");

SDT_PROBE_DEFINE4(vmm, vmx, exit, rdmsr,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t");

SDT_PROBE_DEFINE5(vmm, vmx, exit, wrmsr,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t", "uint64_t");

SDT_PROBE_DEFINE3(vmm, vmx, exit, halt,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, mtrap,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, pause,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, intrwindow,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, interrupt,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t");

SDT_PROBE_DEFINE3(vmm, vmx, exit, nmiwindow,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, inout,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, cpuid,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE5(vmm, vmx, exit, exception,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t", "int");

SDT_PROBE_DEFINE5(vmm, vmx, exit, nestedfault,
    "struct vmx *", "int", "struct vm_exit *", "uint64_t", "uint64_t");

SDT_PROBE_DEFINE4(vmm, vmx, exit, mmiofault,
    "struct vmx *", "int", "struct vm_exit *", "uint64_t");

SDT_PROBE_DEFINE3(vmm, vmx, exit, eoi,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, apicaccess,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, apicwrite,
    "struct vmx *", "int", "struct vm_exit *", "struct vlapic *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, xsetbv,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, monitor,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, mwait,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, vminsn,
    "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, unknown,
    "struct vmx *", "int", "struct vm_exit *", "uint32_t");

SDT_PROBE_DEFINE4(vmm, vmx, exit, return,
    "struct vmx *", "int", "struct vm_exit *", "int");
/* END CSTYLED */

static int vmx_getdesc(void *arg, int vcpu, int reg, struct seg_desc *desc);
static int vmx_getreg(void *arg, int vcpu, int reg, uint64_t *retval);
static void vmx_apply_tsc_adjust(struct vmx *, int);
static void vmx_apicv_sync_tmr(struct vlapic *vlapic);
static void vmx_tpr_shadow_enter(struct vlapic *vlapic);
static void vmx_tpr_shadow_exit(struct vlapic *vlapic);

static void
vmx_allow_x2apic_msrs(struct vmx *vmx, int vcpuid)
{
	/*
	 * Allow readonly access to the following x2APIC MSRs from the guest.
	 */
	guest_msr_ro(vmx, vcpuid, MSR_APIC_ID);
	guest_msr_ro(vmx, vcpuid, MSR_APIC_VERSION);
	guest_msr_ro(vmx, vcpuid, MSR_APIC_LDR);
	guest_msr_ro(vmx, vcpuid, MSR_APIC_SVR);

	for (uint_t i = 0; i < 8; i++) {
		guest_msr_ro(vmx, vcpuid, MSR_APIC_ISR0 + i);
		guest_msr_ro(vmx, vcpuid, MSR_APIC_TMR0 + i);
		guest_msr_ro(vmx, vcpuid, MSR_APIC_IRR0 + i);
	}

	guest_msr_ro(vmx, vcpuid, MSR_APIC_ESR);
	guest_msr_ro(vmx, vcpuid, MSR_APIC_LVT_TIMER);
	guest_msr_ro(vmx, vcpuid, MSR_APIC_LVT_THERMAL);
	guest_msr_ro(vmx, vcpuid, MSR_APIC_LVT_PCINT);
	guest_msr_ro(vmx, vcpuid, MSR_APIC_LVT_LINT0);
	guest_msr_ro(vmx, vcpuid, MSR_APIC_LVT_LINT1);
	guest_msr_ro(vmx, vcpuid, MSR_APIC_LVT_ERROR);
	guest_msr_ro(vmx, vcpuid, MSR_APIC_ICR_TIMER);
	guest_msr_ro(vmx, vcpuid, MSR_APIC_DCR_TIMER);
	guest_msr_ro(vmx, vcpuid, MSR_APIC_ICR);

	/*
	 * Allow TPR, EOI and SELF_IPI MSRs to be read and written by the guest.
	 *
	 * These registers get special treatment described in the section
	 * "Virtualizing MSR-Based APIC Accesses".
	 */
	guest_msr_rw(vmx, vcpuid, MSR_APIC_TPR);
	guest_msr_rw(vmx, vcpuid, MSR_APIC_EOI);
	guest_msr_rw(vmx, vcpuid, MSR_APIC_SELF_IPI);
}

static ulong_t
vmx_fix_cr0(ulong_t cr0)
{
	return ((cr0 | cr0_ones_mask) & ~cr0_zeros_mask);
}

/*
 * Given a live (VMCS-active) cr0 value, and its shadow counterpart, calculate
 * the value observable from the guest.
 */
static ulong_t
vmx_unshadow_cr0(uint64_t cr0, uint64_t shadow)
{
	return ((cr0 & ~cr0_ones_mask) |
	    (shadow & (cr0_zeros_mask | cr0_ones_mask)));
}

static ulong_t
vmx_fix_cr4(ulong_t cr4)
{
	return ((cr4 | cr4_ones_mask) & ~cr4_zeros_mask);
}

/*
 * Given a live (VMCS-active) cr4 value, and its shadow counterpart, calculate
 * the value observable from the guest.
 */
static ulong_t
vmx_unshadow_cr4(uint64_t cr4, uint64_t shadow)
{
	return ((cr4 & ~cr4_ones_mask) |
	    (shadow & (cr4_zeros_mask | cr4_ones_mask)));
}

static void
vpid_free(int vpid)
{
	if (vpid < 0 || vpid > 0xffff)
		panic("vpid_free: invalid vpid %d", vpid);

	/*
	 * VPIDs [0,VM_MAXCPU] are special and are not allocated from
	 * the unit number allocator.
	 */

	if (vpid > VM_MAXCPU)
		hma_vmx_vpid_free((uint16_t)vpid);
}

static void
vpid_alloc(uint16_t *vpid, int num)
{
	int i, x;

	if (num <= 0 || num > VM_MAXCPU)
		panic("invalid number of vpids requested: %d", num);

	/*
	 * If the "enable vpid" execution control is not enabled then the
	 * VPID is required to be 0 for all vcpus.
	 */
	if ((procbased_ctls2 & PROCBASED2_ENABLE_VPID) == 0) {
		for (i = 0; i < num; i++)
			vpid[i] = 0;
		return;
	}

	/*
	 * Allocate a unique VPID for each vcpu from the unit number allocator.
	 */
	for (i = 0; i < num; i++) {
		uint16_t tmp;

		tmp = hma_vmx_vpid_alloc();
		x = (tmp == 0) ? -1 : tmp;

		if (x == -1)
			break;
		else
			vpid[i] = x;
	}

	if (i < num) {
		atomic_add_int(&vpid_alloc_failed, 1);

		/*
		 * If the unit number allocator does not have enough unique
		 * VPIDs then we need to allocate from the [1,VM_MAXCPU] range.
		 *
		 * These VPIDs are not be unique across VMs but this does not
		 * affect correctness because the combined mappings are also
		 * tagged with the EP4TA which is unique for each VM.
		 *
		 * It is still sub-optimal because the invvpid will invalidate
		 * combined mappings for a particular VPID across all EP4TAs.
		 */
		while (i-- > 0)
			vpid_free(vpid[i]);

		for (i = 0; i < num; i++)
			vpid[i] = i + 1;
	}
}

static int
vmx_cleanup(void)
{
	/* This is taken care of by the hma registration */
	return (0);
}

static void
vmx_restore(void)
{
	/* No-op on illumos */
}

static int
vmx_init(void)
{
	int error;
	uint64_t fixed0, fixed1;
	uint32_t tmp;
	enum vmx_caps avail_caps = VMX_CAP_NONE;

	/* Check support for primary processor-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
	    MSR_VMX_TRUE_PROCBASED_CTLS,
	    PROCBASED_CTLS_ONE_SETTING,
	    PROCBASED_CTLS_ZERO_SETTING, &procbased_ctls);
	if (error) {
		printf("vmx_init: processor does not support desired primary "
		    "processor-based controls\n");
		return (error);
	}

	/*
	 * Clear interrupt-window/NMI-window exiting from the default proc-based
	 * controls. They are set and cleared based on runtime vCPU events.
	 */
	procbased_ctls &= ~PROCBASED_CTLS_WINDOW_SETTING;

	/* Check support for secondary processor-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
	    MSR_VMX_PROCBASED_CTLS2,
	    PROCBASED_CTLS2_ONE_SETTING,
	    PROCBASED_CTLS2_ZERO_SETTING, &procbased_ctls2);
	if (error) {
		printf("vmx_init: processor does not support desired secondary "
		    "processor-based controls\n");
		return (error);
	}

	/* Check support for VPID */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
	    MSR_VMX_PROCBASED_CTLS2,
	    PROCBASED2_ENABLE_VPID,
	    0, &tmp);
	if (error == 0)
		procbased_ctls2 |= PROCBASED2_ENABLE_VPID;

	/* Check support for pin-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PINBASED_CTLS,
	    MSR_VMX_TRUE_PINBASED_CTLS,
	    PINBASED_CTLS_ONE_SETTING,
	    PINBASED_CTLS_ZERO_SETTING, &pinbased_ctls);
	if (error) {
		printf("vmx_init: processor does not support desired "
		    "pin-based controls\n");
		return (error);
	}

	/* Check support for VM-exit controls */
	error = vmx_set_ctlreg(MSR_VMX_EXIT_CTLS, MSR_VMX_TRUE_EXIT_CTLS,
	    VM_EXIT_CTLS_ONE_SETTING,
	    VM_EXIT_CTLS_ZERO_SETTING,
	    &exit_ctls);
	if (error) {
		printf("vmx_init: processor does not support desired "
		    "exit controls\n");
		return (error);
	}

	/* Check support for VM-entry controls */
	error = vmx_set_ctlreg(MSR_VMX_ENTRY_CTLS, MSR_VMX_TRUE_ENTRY_CTLS,
	    VM_ENTRY_CTLS_ONE_SETTING, VM_ENTRY_CTLS_ZERO_SETTING,
	    &entry_ctls);
	if (error) {
		printf("vmx_init: processor does not support desired "
		    "entry controls\n");
		return (error);
	}

	/*
	 * Check support for optional features by testing them
	 * as individual bits
	 */
	cap_monitor_trap = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
	    MSR_VMX_PROCBASED_CTLS,
	    PROCBASED_MTF, 0,
	    &tmp) == 0);

	cap_pause_exit = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
	    MSR_VMX_TRUE_PROCBASED_CTLS,
	    PROCBASED_PAUSE_EXITING, 0,
	    &tmp) == 0);

	cap_wbinvd_exit = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
	    MSR_VMX_PROCBASED_CTLS2,
	    PROCBASED2_WBINVD_EXITING, 0,
	    &tmp) == 0);

	cap_invpcid = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
	    MSR_VMX_PROCBASED_CTLS2, PROCBASED2_ENABLE_INVPCID, 0,
	    &tmp) == 0);

	/*
	 * Check for APIC virtualization capabilities:
	 * - TPR shadowing
	 * - Full APICv (with or without x2APIC support)
	 * - Posted interrupt handling
	 */
	if (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS, MSR_VMX_TRUE_PROCBASED_CTLS,
	    PROCBASED_USE_TPR_SHADOW, 0, &tmp) == 0) {
		avail_caps |= VMX_CAP_TPR_SHADOW;

		const uint32_t apicv_bits =
		    PROCBASED2_VIRTUALIZE_APIC_ACCESSES |
		    PROCBASED2_APIC_REGISTER_VIRTUALIZATION |
		    PROCBASED2_VIRTUALIZE_X2APIC_MODE |
		    PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY;
		if (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
		    MSR_VMX_PROCBASED_CTLS2, apicv_bits, 0, &tmp) == 0) {
			avail_caps |= VMX_CAP_APICV;

			/*
			 * It may make sense in the future to differentiate
			 * hardware (or software) configurations with APICv but
			 * no support for accelerating x2APIC mode.
			 */
			avail_caps |= VMX_CAP_APICV_X2APIC;

			error = vmx_set_ctlreg(MSR_VMX_PINBASED_CTLS,
			    MSR_VMX_TRUE_PINBASED_CTLS,
			    PINBASED_POSTED_INTERRUPT, 0, &tmp);
			if (error == 0) {
				/*
				 * If the PSM-provided interfaces for requesting
				 * and using a PIR IPI vector are present, use
				 * them for posted interrupts.
				 */
				if (psm_get_pir_ipivect != NULL &&
				    psm_send_pir_ipi != NULL) {
					pirvec = psm_get_pir_ipivect();
					avail_caps |= VMX_CAP_APICV_PIR;
				}
			}
		}
	}

	/*
	 * Check for necessary EPT capabilities
	 *
	 * TODO: Properly handle when IA32_VMX_EPT_VPID_HW_AD is missing and the
	 * hypervisor intends to utilize dirty page tracking.
	 */
	uint64_t ept_caps = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	if ((ept_caps & EPT_CAPS_REQUIRED) != EPT_CAPS_REQUIRED) {
		cmn_err(CE_WARN, "!Inadequate EPT capabilities: %lx", ept_caps);
		return (EINVAL);
	}

#ifdef __FreeBSD__
	guest_l1d_flush = (cpu_ia32_arch_caps &
	    IA32_ARCH_CAP_SKIP_L1DFL_VMENTRY) == 0;
	TUNABLE_INT_FETCH("hw.vmm.l1d_flush", &guest_l1d_flush);

	/*
	 * L1D cache flush is enabled.  Use IA32_FLUSH_CMD MSR when
	 * available.  Otherwise fall back to the software flush
	 * method which loads enough data from the kernel text to
	 * flush existing L1D content, both on VMX entry and on NMI
	 * return.
	 */
	if (guest_l1d_flush) {
		if ((cpu_stdext_feature3 & CPUID_STDEXT3_L1D_FLUSH) == 0) {
			guest_l1d_flush_sw = 1;
			TUNABLE_INT_FETCH("hw.vmm.l1d_flush_sw",
			    &guest_l1d_flush_sw);
		}
		if (guest_l1d_flush_sw) {
			if (nmi_flush_l1d_sw <= 1)
				nmi_flush_l1d_sw = 1;
		} else {
			msr_load_list[0].index = MSR_IA32_FLUSH_CMD;
			msr_load_list[0].val = IA32_FLUSH_CMD_L1D;
		}
	}
#else
	/* L1D flushing is taken care of by smt_acquire() and friends */
	guest_l1d_flush = 0;
#endif /* __FreeBSD__ */

	/*
	 * Stash the cr0 and cr4 bits that must be fixed to 0 or 1
	 */
	fixed0 = rdmsr(MSR_VMX_CR0_FIXED0);
	fixed1 = rdmsr(MSR_VMX_CR0_FIXED1);
	cr0_ones_mask = fixed0 & fixed1;
	cr0_zeros_mask = ~fixed0 & ~fixed1;

	/*
	 * Since Unrestricted Guest was already verified present, CR0_PE and
	 * CR0_PG are allowed to be set to zero in VMX non-root operation
	 */
	cr0_ones_mask &= ~(CR0_PG | CR0_PE);

	/*
	 * Do not allow the guest to set CR0_NW or CR0_CD.
	 */
	cr0_zeros_mask |= (CR0_NW | CR0_CD);

	fixed0 = rdmsr(MSR_VMX_CR4_FIXED0);
	fixed1 = rdmsr(MSR_VMX_CR4_FIXED1);
	cr4_ones_mask = fixed0 & fixed1;
	cr4_zeros_mask = ~fixed0 & ~fixed1;

	vmx_msr_init();

	vmx_capabilities = avail_caps;
	vmx_initialized = 1;

	return (0);
}

static void
vmx_trigger_hostintr(int vector)
{
	VERIFY(vector >= 32 && vector <= 255);
	vmx_call_isr(vector - 32);
}

static void *
vmx_vminit(struct vm *vm)
{
	uint16_t vpid[VM_MAXCPU];
	int i, error, datasel;
	struct vmx *vmx;
	uint32_t exc_bitmap;
	uint16_t maxcpus;
	uint32_t proc_ctls, proc2_ctls, pin_ctls;
	uint64_t apic_access_pa = UINT64_MAX;

	vmx = kmem_zalloc(sizeof (struct vmx), KM_SLEEP);
	VERIFY3U((uintptr_t)vmx & PAGE_MASK, ==, 0);

	vmx->vm = vm;
	vmx->eptp = vmspace_table_root(vm_get_vmspace(vm));

	/*
	 * Clean up EP4TA-tagged guest-physical and combined mappings
	 *
	 * VMX transitions are not required to invalidate any guest physical
	 * mappings. So, it may be possible for stale guest physical mappings
	 * to be present in the processor TLBs.
	 *
	 * Combined mappings for this EP4TA are also invalidated for all VPIDs.
	 */
	hma_vmx_invept_allcpus((uintptr_t)vmx->eptp);

	vmx_msr_bitmap_initialize(vmx);

	vpid_alloc(vpid, VM_MAXCPU);

	/* Grab the established defaults */
	proc_ctls = procbased_ctls;
	proc2_ctls = procbased_ctls2;
	pin_ctls = pinbased_ctls;
	/* For now, default to the available capabilities */
	vmx->vmx_caps = vmx_capabilities;

	if (vmx_cap_en(vmx, VMX_CAP_TPR_SHADOW)) {
		proc_ctls |= PROCBASED_USE_TPR_SHADOW;
		proc_ctls &= ~PROCBASED_CR8_LOAD_EXITING;
		proc_ctls &= ~PROCBASED_CR8_STORE_EXITING;
	}
	if (vmx_cap_en(vmx, VMX_CAP_APICV)) {
		ASSERT(vmx_cap_en(vmx, VMX_CAP_TPR_SHADOW));

		proc2_ctls |= (PROCBASED2_VIRTUALIZE_APIC_ACCESSES |
		    PROCBASED2_APIC_REGISTER_VIRTUALIZATION |
		    PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY);

		/*
		 * Allocate a page of memory to back the APIC access address for
		 * when APICv features are in use.  Guest MMIO accesses should
		 * never actually reach this page, but rather be intercepted.
		 */
		vmx->apic_access_page = kmem_zalloc(PAGESIZE, KM_SLEEP);
		VERIFY3U((uintptr_t)vmx->apic_access_page & PAGEOFFSET, ==, 0);
		apic_access_pa = vtophys(vmx->apic_access_page);

		error = vm_map_mmio(vm, DEFAULT_APIC_BASE, PAGE_SIZE,
		    apic_access_pa);
		/* XXX this should really return an error to the caller */
		KASSERT(error == 0, ("vm_map_mmio(apicbase) error %d", error));
	}
	if (vmx_cap_en(vmx, VMX_CAP_APICV_PIR)) {
		ASSERT(vmx_cap_en(vmx, VMX_CAP_APICV));

		pin_ctls |= PINBASED_POSTED_INTERRUPT;
	}

	/* Reflect any enabled defaults in the cap set */
	int cap_defaults = 0;
	if ((proc_ctls & PROCBASED_HLT_EXITING) != 0) {
		cap_defaults |= (1 << VM_CAP_HALT_EXIT);
	}
	if ((proc_ctls & PROCBASED_PAUSE_EXITING) != 0) {
		cap_defaults |= (1 << VM_CAP_PAUSE_EXIT);
	}
	if ((proc_ctls & PROCBASED_MTF) != 0) {
		cap_defaults |= (1 << VM_CAP_MTRAP_EXIT);
	}
	if ((proc2_ctls & PROCBASED2_ENABLE_INVPCID) != 0) {
		cap_defaults |= (1 << VM_CAP_ENABLE_INVPCID);
	}

	maxcpus = vm_get_maxcpus(vm);
	datasel = vmm_get_host_datasel();
	for (i = 0; i < maxcpus; i++) {
		/*
		 * Cache physical address lookups for various components which
		 * may be required inside the critical_enter() section implied
		 * by VMPTRLD() below.
		 */
		vm_paddr_t msr_bitmap_pa = vtophys(vmx->msr_bitmap[i]);
		vm_paddr_t apic_page_pa = vtophys(&vmx->apic_page[i]);
		vm_paddr_t pir_desc_pa = vtophys(&vmx->pir_desc[i]);

		vmx->vmcs_pa[i] = (uintptr_t)vtophys(&vmx->vmcs[i]);
		vmcs_initialize(&vmx->vmcs[i], vmx->vmcs_pa[i]);

		vmx_msr_guest_init(vmx, i);

		vmcs_load(vmx->vmcs_pa[i]);

		vmcs_write(VMCS_HOST_IA32_PAT, vmm_get_host_pat());
		vmcs_write(VMCS_HOST_IA32_EFER, vmm_get_host_efer());

		/* Load the control registers */
		vmcs_write(VMCS_HOST_CR0, vmm_get_host_cr0());
		vmcs_write(VMCS_HOST_CR4, vmm_get_host_cr4() | CR4_VMXE);

		/* Load the segment selectors */
		vmcs_write(VMCS_HOST_CS_SELECTOR, vmm_get_host_codesel());

		vmcs_write(VMCS_HOST_ES_SELECTOR, datasel);
		vmcs_write(VMCS_HOST_SS_SELECTOR, datasel);
		vmcs_write(VMCS_HOST_DS_SELECTOR, datasel);

		vmcs_write(VMCS_HOST_FS_SELECTOR, vmm_get_host_fssel());
		vmcs_write(VMCS_HOST_GS_SELECTOR, vmm_get_host_gssel());
		vmcs_write(VMCS_HOST_TR_SELECTOR, vmm_get_host_tsssel());

		/*
		 * Configure host sysenter MSRs to be restored on VM exit.
		 * The thread-specific MSR_INTC_SEP_ESP value is loaded in
		 * vmx_run.
		 */
		vmcs_write(VMCS_HOST_IA32_SYSENTER_CS, KCS_SEL);
		vmcs_write(VMCS_HOST_IA32_SYSENTER_EIP,
		    rdmsr(MSR_SYSENTER_EIP_MSR));

		/* instruction pointer */
		vmcs_write(VMCS_HOST_RIP, (uint64_t)vmx_exit_guest);

		/* link pointer */
		vmcs_write(VMCS_LINK_POINTER, ~0);

		vmcs_write(VMCS_EPTP, vmx->eptp);
		vmcs_write(VMCS_PIN_BASED_CTLS, pin_ctls);
		vmcs_write(VMCS_PRI_PROC_BASED_CTLS, proc_ctls);

		uint32_t use_proc2_ctls = proc2_ctls;
		if (cap_wbinvd_exit && vcpu_trap_wbinvd(vm, i) != 0)
			use_proc2_ctls |= PROCBASED2_WBINVD_EXITING;
		vmcs_write(VMCS_SEC_PROC_BASED_CTLS, use_proc2_ctls);

		vmcs_write(VMCS_EXIT_CTLS, exit_ctls);
		vmcs_write(VMCS_ENTRY_CTLS, entry_ctls);
		vmcs_write(VMCS_MSR_BITMAP, msr_bitmap_pa);
		vmcs_write(VMCS_VPID, vpid[i]);

		if (guest_l1d_flush && !guest_l1d_flush_sw) {
			vmcs_write(VMCS_ENTRY_MSR_LOAD,
			    vtophys(&msr_load_list[0]));
			vmcs_write(VMCS_ENTRY_MSR_LOAD_COUNT,
			    nitems(msr_load_list));
			vmcs_write(VMCS_EXIT_MSR_STORE, 0);
			vmcs_write(VMCS_EXIT_MSR_STORE_COUNT, 0);
		}

		/* exception bitmap */
		if (vcpu_trace_exceptions(vm, i))
			exc_bitmap = 0xffffffff;
		else
			exc_bitmap = 1 << IDT_MC;
		vmcs_write(VMCS_EXCEPTION_BITMAP, exc_bitmap);

		vmx->ctx[i].guest_dr6 = DBREG_DR6_RESERVED1;
		vmcs_write(VMCS_GUEST_DR7, DBREG_DR7_RESERVED1);

		if (vmx_cap_en(vmx, VMX_CAP_TPR_SHADOW)) {
			vmcs_write(VMCS_VIRTUAL_APIC, apic_page_pa);
		}

		if (vmx_cap_en(vmx, VMX_CAP_APICV)) {
			vmcs_write(VMCS_APIC_ACCESS, apic_access_pa);
			vmcs_write(VMCS_EOI_EXIT0, 0);
			vmcs_write(VMCS_EOI_EXIT1, 0);
			vmcs_write(VMCS_EOI_EXIT2, 0);
			vmcs_write(VMCS_EOI_EXIT3, 0);
		}
		if (vmx_cap_en(vmx, VMX_CAP_APICV_PIR)) {
			vmcs_write(VMCS_PIR_VECTOR, pirvec);
			vmcs_write(VMCS_PIR_DESC, pir_desc_pa);
		}

		/*
		 * Set up the CR0/4 masks and configure the read shadow state
		 * to the power-on register value from the Intel Sys Arch.
		 *  CR0 - 0x60000010
		 *  CR4 - 0
		 */
		vmcs_write(VMCS_CR0_MASK, cr0_ones_mask | cr0_zeros_mask);
		vmcs_write(VMCS_CR0_SHADOW, 0x60000010);
		vmcs_write(VMCS_CR4_MASK, cr4_ones_mask | cr4_zeros_mask);
		vmcs_write(VMCS_CR4_SHADOW, 0);

		vmcs_clear(vmx->vmcs_pa[i]);

		vmx->cap[i].set = cap_defaults;
		vmx->cap[i].proc_ctls = proc_ctls;
		vmx->cap[i].proc_ctls2 = proc2_ctls;
		vmx->cap[i].exc_bitmap = exc_bitmap;

		vmx->state[i].nextrip = ~0;
		vmx->state[i].lastcpu = NOCPU;
		vmx->state[i].vpid = vpid[i];
	}

	return (vmx);
}

static VMM_STAT_INTEL(VCPU_INVVPID_SAVED, "Number of vpid invalidations saved");
static VMM_STAT_INTEL(VCPU_INVVPID_DONE, "Number of vpid invalidations done");

#define	INVVPID_TYPE_ADDRESS		0UL
#define	INVVPID_TYPE_SINGLE_CONTEXT	1UL
#define	INVVPID_TYPE_ALL_CONTEXTS	2UL

struct invvpid_desc {
	uint16_t	vpid;
	uint16_t	_res1;
	uint32_t	_res2;
	uint64_t	linear_addr;
};
CTASSERT(sizeof (struct invvpid_desc) == 16);

static __inline void
invvpid(uint64_t type, struct invvpid_desc desc)
{
	int error;

	DTRACE_PROBE3(vmx__invvpid, uint64_t, type, uint16_t, desc.vpid,
	    uint64_t, desc.linear_addr);

	__asm __volatile("invvpid %[desc], %[type];"
	    VMX_SET_ERROR_CODE_ASM
	    : [error] "=r" (error)
	    : [desc] "m" (desc), [type] "r" (type)
	    : "memory");

	if (error) {
		panic("invvpid error %d", error);
	}
}

/*
 * Invalidate guest mappings identified by its VPID from the TLB.
 *
 * This is effectively a flush of the guest TLB, removing only "combined
 * mappings" (to use the VMX parlance).  Actions which modify the EPT structures
 * for the instance (such as unmapping GPAs) would require an 'invept' flush.
 */
static void
vmx_invvpid(struct vmx *vmx, int vcpu, int running)
{
	struct vmxstate *vmxstate;
	struct vmspace *vms;

	vmxstate = &vmx->state[vcpu];
	if (vmxstate->vpid == 0) {
		return;
	}

	if (!running) {
		/*
		 * Set the 'lastcpu' to an invalid host cpu.
		 *
		 * This will invalidate TLB entries tagged with the vcpu's
		 * vpid the next time it runs via vmx_set_pcpu_defaults().
		 */
		vmxstate->lastcpu = NOCPU;
		return;
	}

	/*
	 * Invalidate all mappings tagged with 'vpid'
	 *
	 * This is done when a vCPU moves between host CPUs, where there may be
	 * stale TLB entries for this VPID on the target, or if emulated actions
	 * in the guest CPU have incurred an explicit TLB flush.
	 */
	vms = vm_get_vmspace(vmx->vm);
	if (vmspace_table_gen(vms) == vmx->eptgen[curcpu]) {
		struct invvpid_desc invvpid_desc = {
			.vpid = vmxstate->vpid,
			.linear_addr = 0,
			._res1 = 0,
			._res2 = 0,
		};

		invvpid(INVVPID_TYPE_SINGLE_CONTEXT, invvpid_desc);
		vmm_stat_incr(vmx->vm, vcpu, VCPU_INVVPID_DONE, 1);
	} else {
		/*
		 * The INVVPID can be skipped if an INVEPT is going to be
		 * performed before entering the guest.  The INVEPT will
		 * invalidate combined mappings for the EP4TA associated with
		 * this guest, in all VPIDs.
		 */
		vmm_stat_incr(vmx->vm, vcpu, VCPU_INVVPID_SAVED, 1);
	}
}

static __inline void
invept(uint64_t type, uint64_t eptp)
{
	int error;
	struct invept_desc {
		uint64_t eptp;
		uint64_t _resv;
	} desc = { eptp, 0 };

	DTRACE_PROBE2(vmx__invept, uint64_t, type, uint64_t, eptp);

	__asm __volatile("invept %[desc], %[type];"
	    VMX_SET_ERROR_CODE_ASM
	    : [error] "=r" (error)
	    : [desc] "m" (desc), [type] "r" (type)
	    : "memory");

	if (error != 0) {
		panic("invvpid error %d", error);
	}
}

static void
vmx_set_pcpu_defaults(struct vmx *vmx, int vcpu)
{
	struct vmxstate *vmxstate;

	/*
	 * Regardless of whether the VM appears to have migrated between CPUs,
	 * save the host sysenter stack pointer.  As it points to the kernel
	 * stack of each thread, the correct value must be maintained for every
	 * trip into the critical section.
	 */
	vmcs_write(VMCS_HOST_IA32_SYSENTER_ESP, rdmsr(MSR_SYSENTER_ESP_MSR));

	/*
	 * Perform any needed TSC_OFFSET adjustment based on TSC_MSR writes or
	 * migration between host CPUs with differing TSC values.
	 */
	vmx_apply_tsc_adjust(vmx, vcpu);

	vmxstate = &vmx->state[vcpu];
	if (vmxstate->lastcpu == curcpu)
		return;

	vmxstate->lastcpu = curcpu;

	vmm_stat_incr(vmx->vm, vcpu, VCPU_MIGRATIONS, 1);

	/* Load the per-CPU IDT address */
	vmcs_write(VMCS_HOST_IDTR_BASE, vmm_get_host_idtrbase());
	vmcs_write(VMCS_HOST_TR_BASE, vmm_get_host_trbase());
	vmcs_write(VMCS_HOST_GDTR_BASE, vmm_get_host_gdtrbase());
	vmcs_write(VMCS_HOST_GS_BASE, vmm_get_host_gsbase());
	vmx_invvpid(vmx, vcpu, 1);
}

static __inline bool
vmx_int_window_exiting(struct vmx *vmx, int vcpu)
{
	return ((vmx->cap[vcpu].proc_ctls & PROCBASED_INT_WINDOW_EXITING) != 0);
}

static __inline void
vmx_set_int_window_exiting(struct vmx *vmx, int vcpu)
{
	if (!vmx_int_window_exiting(vmx, vcpu)) {
		/* Enable interrupt window exiting */
		vmx->cap[vcpu].proc_ctls |= PROCBASED_INT_WINDOW_EXITING;
		vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
	}
}

static __inline void
vmx_clear_int_window_exiting(struct vmx *vmx, int vcpu)
{
	/* Disable interrupt window exiting */
	vmx->cap[vcpu].proc_ctls &= ~PROCBASED_INT_WINDOW_EXITING;
	vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
}

static __inline bool
vmx_nmi_window_exiting(struct vmx *vmx, int vcpu)
{
	return ((vmx->cap[vcpu].proc_ctls & PROCBASED_NMI_WINDOW_EXITING) != 0);
}

static __inline void
vmx_set_nmi_window_exiting(struct vmx *vmx, int vcpu)
{
	if (!vmx_nmi_window_exiting(vmx, vcpu)) {
		vmx->cap[vcpu].proc_ctls |= PROCBASED_NMI_WINDOW_EXITING;
		vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
	}
}

static __inline void
vmx_clear_nmi_window_exiting(struct vmx *vmx, int vcpu)
{
	vmx->cap[vcpu].proc_ctls &= ~PROCBASED_NMI_WINDOW_EXITING;
	vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
}

/*
 * Set the TSC adjustment, taking into account the offsets measured between
 * host physical CPUs.  This is required even if the guest has not set a TSC
 * offset since vCPUs inherit the TSC offset of whatever physical CPU it has
 * migrated onto.  Without this mitigation, un-synched host TSCs will convey
 * the appearance of TSC time-travel to the guest as its vCPUs migrate.
 */
static void
vmx_apply_tsc_adjust(struct vmx *vmx, int vcpu)
{
	const uint64_t offset = vcpu_tsc_offset(vmx->vm, vcpu, true);

	ASSERT(vmx->cap[vcpu].proc_ctls & PROCBASED_TSC_OFFSET);

	if (vmx->tsc_offset_active[vcpu] != offset) {
		vmcs_write(VMCS_TSC_OFFSET, offset);
		vmx->tsc_offset_active[vcpu] = offset;
	}
}

CTASSERT(VMCS_INTR_T_HWINTR		== VM_INTINFO_HWINTR);
CTASSERT(VMCS_INTR_T_NMI		== VM_INTINFO_NMI);
CTASSERT(VMCS_INTR_T_HWEXCEPTION	== VM_INTINFO_HWEXCP);
CTASSERT(VMCS_INTR_T_SWINTR		== VM_INTINFO_SWINTR);
CTASSERT(VMCS_INTR_T_PRIV_SWEXCEPTION	== VM_INTINFO_RESV5);
CTASSERT(VMCS_INTR_T_SWEXCEPTION	== VM_INTINFO_RESV6);
CTASSERT(VMCS_IDT_VEC_ERRCODE_VALID	== VM_INTINFO_DEL_ERRCODE);
CTASSERT(VMCS_INTR_T_MASK		== VM_INTINFO_MASK_TYPE);

static uint64_t
vmx_idtvec_to_intinfo(uint32_t info, uint32_t errcode)
{
	ASSERT(info & VMCS_IDT_VEC_VALID);

	const uint32_t type = info & VMCS_INTR_T_MASK;
	const uint8_t vec = info & 0xff;

	switch (type) {
	case VMCS_INTR_T_HWINTR:
	case VMCS_INTR_T_NMI:
	case VMCS_INTR_T_HWEXCEPTION:
	case VMCS_INTR_T_SWINTR:
	case VMCS_INTR_T_PRIV_SWEXCEPTION:
	case VMCS_INTR_T_SWEXCEPTION:
		break;
	default:
		panic("unexpected event type 0x%03x", type);
	}

	uint64_t intinfo = VM_INTINFO_VALID | type | vec;
	if (info & VMCS_IDT_VEC_ERRCODE_VALID) {
		intinfo |= (uint64_t)errcode << 32;
	}

	return (intinfo);
}

CTASSERT(VMCS_INTR_DEL_ERRCODE		== VMCS_IDT_VEC_ERRCODE_VALID);
CTASSERT(VMCS_INTR_VALID		== VMCS_IDT_VEC_VALID);

/*
 * Store VMX-specific event injection info for later handling.  This depends on
 * the bhyve-internal event definitions matching those in the VMCS, as ensured
 * by the vmx_idtvec_to_intinfo() and the related CTASSERTs.
 */
static void
vmx_stash_intinfo(struct vmx *vmx, int vcpu)
{
	uint64_t info = vmcs_read(VMCS_ENTRY_INTR_INFO);
	if ((info & VMCS_INTR_VALID) != 0) {
		uint32_t errcode = 0;

		if ((info & VMCS_INTR_DEL_ERRCODE) != 0) {
			errcode = vmcs_read(VMCS_ENTRY_EXCEPTION_ERROR);
		}

		VERIFY0(vm_exit_intinfo(vmx->vm, vcpu,
		    vmx_idtvec_to_intinfo(info, errcode)));

		vmcs_write(VMCS_ENTRY_INTR_INFO, 0);
		vmcs_write(VMCS_ENTRY_EXCEPTION_ERROR, 0);
	}
}

static void
vmx_inject_intinfo(uint64_t info)
{
	ASSERT(VM_INTINFO_PENDING(info));
	ASSERT0(info & VM_INTINFO_MASK_RSVD);

	/*
	 * The bhyve format matches that of the VMCS, which is ensured by the
	 * CTASSERTs above.
	 */
	uint32_t inject = info;
	switch (VM_INTINFO_VECTOR(info)) {
	case IDT_BP:
	case IDT_OF:
		/*
		 * VT-x requires #BP and #OF to be injected as software
		 * exceptions.
		 */
		inject &= ~VMCS_INTR_T_MASK;
		inject |= VMCS_INTR_T_SWEXCEPTION;
		break;
	default:
		break;
	}

	if (VM_INTINFO_HAS_ERRCODE(info)) {
		vmcs_write(VMCS_ENTRY_EXCEPTION_ERROR,
		    VM_INTINFO_ERRCODE(info));
	}
	vmcs_write(VMCS_ENTRY_INTR_INFO, inject);
}

#define	NMI_BLOCKING	(VMCS_INTERRUPTIBILITY_NMI_BLOCKING |		\
			VMCS_INTERRUPTIBILITY_MOVSS_BLOCKING)
#define	HWINTR_BLOCKING	(VMCS_INTERRUPTIBILITY_STI_BLOCKING |		\
			VMCS_INTERRUPTIBILITY_MOVSS_BLOCKING)

static void
vmx_inject_nmi(struct vmx *vmx, int vcpu)
{
	ASSERT0(vmcs_read(VMCS_GUEST_INTERRUPTIBILITY) & NMI_BLOCKING);
	ASSERT0(vmcs_read(VMCS_ENTRY_INTR_INFO) & VMCS_INTR_VALID);

	/*
	 * Inject the virtual NMI. The vector must be the NMI IDT entry
	 * or the VMCS entry check will fail.
	 */
	vmcs_write(VMCS_ENTRY_INTR_INFO,
	    IDT_NMI | VMCS_INTR_T_NMI | VMCS_INTR_VALID);

	/* Clear the request */
	vm_nmi_clear(vmx->vm, vcpu);
}

/*
 * Inject exceptions, NMIs, and ExtINTs.
 *
 * The logic behind these are complicated and may involve mutex contention, so
 * the injection is performed without the protection of host CPU interrupts
 * being disabled.  This means a racing notification could be "lost",
 * necessitating a later call to vmx_inject_recheck() to close that window
 * of opportunity.
 */
static enum event_inject_state
vmx_inject_events(struct vmx *vmx, int vcpu, uint64_t rip)
{
	uint64_t entryinfo;
	uint32_t gi, info;
	int vector;
	enum event_inject_state state;

	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	info = vmcs_read(VMCS_ENTRY_INTR_INFO);
	state = EIS_CAN_INJECT;

	/* Clear any interrupt blocking if the guest %rip has changed */
	if (vmx->state[vcpu].nextrip != rip && (gi & HWINTR_BLOCKING) != 0) {
		gi &= ~HWINTR_BLOCKING;
		vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
	}

	/*
	 * It could be that an interrupt is already pending for injection from
	 * the VMCS.  This would be the case if the vCPU exited for conditions
	 * such as an AST before a vm-entry delivered the injection.
	 */
	if ((info & VMCS_INTR_VALID) != 0) {
		return (EIS_EV_EXISTING | EIS_REQ_EXIT);
	}

	if (vm_entry_intinfo(vmx->vm, vcpu, &entryinfo)) {
		vmx_inject_intinfo(entryinfo);
		state = EIS_EV_INJECTED;
	}

	if (vm_nmi_pending(vmx->vm, vcpu)) {
		/*
		 * If there are no conditions blocking NMI injection then inject
		 * it directly here otherwise enable "NMI window exiting" to
		 * inject it as soon as we can.
		 *
		 * According to the Intel manual, some CPUs do not allow NMI
		 * injection when STI_BLOCKING is active.  That check is
		 * enforced here, regardless of CPU capability.  If running on a
		 * CPU without such a restriction it will immediately exit and
		 * the NMI will be injected in the "NMI window exiting" handler.
		 */
		if ((gi & (HWINTR_BLOCKING | NMI_BLOCKING)) == 0) {
			if (state == EIS_CAN_INJECT) {
				vmx_inject_nmi(vmx, vcpu);
				state = EIS_EV_INJECTED;
			} else {
				return (state | EIS_REQ_EXIT);
			}
		} else {
			vmx_set_nmi_window_exiting(vmx, vcpu);
		}
	}

	if (vm_extint_pending(vmx->vm, vcpu)) {
		if (state != EIS_CAN_INJECT) {
			return (state | EIS_REQ_EXIT);
		}
		if ((gi & HWINTR_BLOCKING) != 0 ||
		    (vmcs_read(VMCS_GUEST_RFLAGS) & PSL_I) == 0) {
			return (EIS_GI_BLOCK);
		}

		/* Ask the legacy pic for a vector to inject */
		vatpic_pending_intr(vmx->vm, &vector);

		/*
		 * From the Intel SDM, Volume 3, Section "Maskable
		 * Hardware Interrupts":
		 * - maskable interrupt vectors [0,255] can be delivered
		 *   through the INTR pin.
		 */
		KASSERT(vector >= 0 && vector <= 255,
		    ("invalid vector %d from INTR", vector));

		/* Inject the interrupt */
		vmcs_write(VMCS_ENTRY_INTR_INFO,
		    VMCS_INTR_T_HWINTR | VMCS_INTR_VALID | vector);

		vm_extint_clear(vmx->vm, vcpu);
		vatpic_intr_accepted(vmx->vm, vector);
		state = EIS_EV_INJECTED;
	}

	return (state);
}

/*
 * Inject any interrupts pending on the vLAPIC.
 *
 * This is done with host CPU interrupts disabled so notification IPIs, either
 * from the standard vCPU notification or APICv posted interrupts, will be
 * queued on the host APIC and recognized when entering VMX context.
 */
static enum event_inject_state
vmx_inject_vlapic(struct vmx *vmx, int vcpu, struct vlapic *vlapic)
{
	int vector;

	if (!vlapic_pending_intr(vlapic, &vector)) {
		return (EIS_CAN_INJECT);
	}

	/*
	 * From the Intel SDM, Volume 3, Section "Maskable
	 * Hardware Interrupts":
	 * - maskable interrupt vectors [16,255] can be delivered
	 *   through the local APIC.
	 */
	KASSERT(vector >= 16 && vector <= 255,
	    ("invalid vector %d from local APIC", vector));

	if (vmx_cap_en(vmx, VMX_CAP_APICV)) {
		uint16_t status_old = vmcs_read(VMCS_GUEST_INTR_STATUS);
		uint16_t status_new = (status_old & 0xff00) | vector;

		/*
		 * The APICv state will have been synced into the vLAPIC
		 * as part of vlapic_pending_intr().  Prepare the VMCS
		 * for the to-be-injected pending interrupt.
		 */
		if (status_new > status_old) {
			vmcs_write(VMCS_GUEST_INTR_STATUS, status_new);
		}

		/*
		 * Ensure VMCS state regarding EOI traps is kept in sync
		 * with the TMRs in the vlapic.
		 */
		vmx_apicv_sync_tmr(vlapic);

		/*
		 * The rest of the injection process for injecting the
		 * interrupt(s) is handled by APICv. It does not preclude other
		 * event injection from occurring.
		 */
		return (EIS_CAN_INJECT);
	}

	ASSERT0(vmcs_read(VMCS_ENTRY_INTR_INFO) & VMCS_INTR_VALID);

	/* Does guest interruptability block injection? */
	if ((vmcs_read(VMCS_GUEST_INTERRUPTIBILITY) & HWINTR_BLOCKING) != 0 ||
	    (vmcs_read(VMCS_GUEST_RFLAGS) & PSL_I) == 0) {
		return (EIS_GI_BLOCK);
	}

	/* Inject the interrupt */
	vmcs_write(VMCS_ENTRY_INTR_INFO,
	    VMCS_INTR_T_HWINTR | VMCS_INTR_VALID | vector);

	/* Update the Local APIC ISR */
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
vmx_inject_recheck(struct vmx *vmx, int vcpu, enum event_inject_state state)
{
	if (state == EIS_CAN_INJECT) {
		if (vm_nmi_pending(vmx->vm, vcpu) &&
		    !vmx_nmi_window_exiting(vmx, vcpu)) {
			/* queued NMI not blocked by NMI-window-exiting */
			return (true);
		}
		if (vm_extint_pending(vmx->vm, vcpu)) {
			/* queued ExtINT not blocked by existing injection */
			return (true);
		}
	} else {
		if ((state & EIS_REQ_EXIT) != 0) {
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
			vmx_set_int_window_exiting(vmx, vcpu);
		}
	}
	return (false);
}

/*
 * If the Virtual NMIs execution control is '1' then the logical processor
 * tracks virtual-NMI blocking in the Guest Interruptibility-state field of
 * the VMCS. An IRET instruction in VMX non-root operation will remove any
 * virtual-NMI blocking.
 *
 * This unblocking occurs even if the IRET causes a fault. In this case the
 * hypervisor needs to restore virtual-NMI blocking before resuming the guest.
 */
static void
vmx_restore_nmi_blocking(struct vmx *vmx, int vcpuid)
{
	uint32_t gi;

	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	gi |= VMCS_INTERRUPTIBILITY_NMI_BLOCKING;
	vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
}

static void
vmx_clear_nmi_blocking(struct vmx *vmx, int vcpuid)
{
	uint32_t gi;

	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	gi &= ~VMCS_INTERRUPTIBILITY_NMI_BLOCKING;
	vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
}

static void
vmx_assert_nmi_blocking(struct vmx *vmx, int vcpuid)
{
	uint32_t gi;

	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	KASSERT(gi & VMCS_INTERRUPTIBILITY_NMI_BLOCKING,
	    ("NMI blocking is not in effect %x", gi));
}

static int
vmx_emulate_xsetbv(struct vmx *vmx, int vcpu, struct vm_exit *vmexit)
{
	struct vmxctx *vmxctx;
	uint64_t xcrval;
	const struct xsave_limits *limits;

	vmxctx = &vmx->ctx[vcpu];
	limits = vmm_get_xsave_limits();

	/*
	 * Note that the processor raises a GP# fault on its own if
	 * xsetbv is executed for CPL != 0, so we do not have to
	 * emulate that fault here.
	 */

	/* Only xcr0 is supported. */
	if (vmxctx->guest_rcx != 0) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	/* We only handle xcr0 if both the host and guest have XSAVE enabled. */
	if (!limits->xsave_enabled ||
	    !(vmcs_read(VMCS_GUEST_CR4) & CR4_XSAVE)) {
		vm_inject_ud(vmx->vm, vcpu);
		return (HANDLED);
	}

	xcrval = vmxctx->guest_rdx << 32 | (vmxctx->guest_rax & 0xffffffff);
	if ((xcrval & ~limits->xcr0_allowed) != 0) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	if (!(xcrval & XFEATURE_ENABLED_X87)) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	/* AVX (YMM_Hi128) requires SSE. */
	if (xcrval & XFEATURE_ENABLED_AVX &&
	    (xcrval & XFEATURE_AVX) != XFEATURE_AVX) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	/*
	 * AVX512 requires base AVX (YMM_Hi128) as well as OpMask,
	 * ZMM_Hi256, and Hi16_ZMM.
	 */
	if (xcrval & XFEATURE_AVX512 &&
	    (xcrval & (XFEATURE_AVX512 | XFEATURE_AVX)) !=
	    (XFEATURE_AVX512 | XFEATURE_AVX)) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	/*
	 * Intel MPX requires both bound register state flags to be
	 * set.
	 */
	if (((xcrval & XFEATURE_ENABLED_BNDREGS) != 0) !=
	    ((xcrval & XFEATURE_ENABLED_BNDCSR) != 0)) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	/*
	 * This runs "inside" vmrun() with the guest's FPU state, so
	 * modifying xcr0 directly modifies the guest's xcr0, not the
	 * host's.
	 */
	load_xcr(0, xcrval);
	return (HANDLED);
}

static uint64_t
vmx_get_guest_reg(struct vmx *vmx, int vcpu, int ident)
{
	const struct vmxctx *vmxctx;

	vmxctx = &vmx->ctx[vcpu];

	switch (ident) {
	case 0:
		return (vmxctx->guest_rax);
	case 1:
		return (vmxctx->guest_rcx);
	case 2:
		return (vmxctx->guest_rdx);
	case 3:
		return (vmxctx->guest_rbx);
	case 4:
		return (vmcs_read(VMCS_GUEST_RSP));
	case 5:
		return (vmxctx->guest_rbp);
	case 6:
		return (vmxctx->guest_rsi);
	case 7:
		return (vmxctx->guest_rdi);
	case 8:
		return (vmxctx->guest_r8);
	case 9:
		return (vmxctx->guest_r9);
	case 10:
		return (vmxctx->guest_r10);
	case 11:
		return (vmxctx->guest_r11);
	case 12:
		return (vmxctx->guest_r12);
	case 13:
		return (vmxctx->guest_r13);
	case 14:
		return (vmxctx->guest_r14);
	case 15:
		return (vmxctx->guest_r15);
	default:
		panic("invalid vmx register %d", ident);
	}
}

static void
vmx_set_guest_reg(struct vmx *vmx, int vcpu, int ident, uint64_t regval)
{
	struct vmxctx *vmxctx;

	vmxctx = &vmx->ctx[vcpu];

	switch (ident) {
	case 0:
		vmxctx->guest_rax = regval;
		break;
	case 1:
		vmxctx->guest_rcx = regval;
		break;
	case 2:
		vmxctx->guest_rdx = regval;
		break;
	case 3:
		vmxctx->guest_rbx = regval;
		break;
	case 4:
		vmcs_write(VMCS_GUEST_RSP, regval);
		break;
	case 5:
		vmxctx->guest_rbp = regval;
		break;
	case 6:
		vmxctx->guest_rsi = regval;
		break;
	case 7:
		vmxctx->guest_rdi = regval;
		break;
	case 8:
		vmxctx->guest_r8 = regval;
		break;
	case 9:
		vmxctx->guest_r9 = regval;
		break;
	case 10:
		vmxctx->guest_r10 = regval;
		break;
	case 11:
		vmxctx->guest_r11 = regval;
		break;
	case 12:
		vmxctx->guest_r12 = regval;
		break;
	case 13:
		vmxctx->guest_r13 = regval;
		break;
	case 14:
		vmxctx->guest_r14 = regval;
		break;
	case 15:
		vmxctx->guest_r15 = regval;
		break;
	default:
		panic("invalid vmx register %d", ident);
	}
}

static void
vmx_sync_efer_state(struct vmx *vmx, int vcpu, uint64_t efer)
{
	uint64_t ctrl;

	/*
	 * If the "load EFER" VM-entry control is 1 (which we require) then the
	 * value of EFER.LMA must be identical to "IA-32e mode guest" bit in the
	 * VM-entry control.
	 */
	ctrl = vmcs_read(VMCS_ENTRY_CTLS);
	if ((efer & EFER_LMA) != 0) {
		ctrl |= VM_ENTRY_GUEST_LMA;
	} else {
		ctrl &= ~VM_ENTRY_GUEST_LMA;
	}
	vmcs_write(VMCS_ENTRY_CTLS, ctrl);
}

static int
vmx_emulate_cr0_access(struct vmx *vmx, int vcpu, uint64_t exitqual)
{
	uint64_t crval, regval;

	/* We only handle mov to %cr0 at this time */
	if ((exitqual & 0xf0) != 0x00)
		return (UNHANDLED);

	regval = vmx_get_guest_reg(vmx, vcpu, (exitqual >> 8) & 0xf);

	vmcs_write(VMCS_CR0_SHADOW, regval);

	crval = regval | cr0_ones_mask;
	crval &= ~cr0_zeros_mask;

	const uint64_t old = vmcs_read(VMCS_GUEST_CR0);
	const uint64_t diff = crval ^ old;
	/* Flush the TLB if the paging or write-protect bits are changing */
	if ((diff & CR0_PG) != 0 || (diff & CR0_WP) != 0) {
		vmx_invvpid(vmx, vcpu, 1);
	}

	vmcs_write(VMCS_GUEST_CR0, crval);

	if (regval & CR0_PG) {
		uint64_t efer;

		/* Keep EFER.LMA properly updated if paging is enabled */
		efer = vmcs_read(VMCS_GUEST_IA32_EFER);
		if (efer & EFER_LME) {
			efer |= EFER_LMA;
			vmcs_write(VMCS_GUEST_IA32_EFER, efer);
			vmx_sync_efer_state(vmx, vcpu, efer);
		}
	}

	return (HANDLED);
}

static int
vmx_emulate_cr4_access(struct vmx *vmx, int vcpu, uint64_t exitqual)
{
	uint64_t crval, regval;

	/* We only handle mov to %cr4 at this time */
	if ((exitqual & 0xf0) != 0x00)
		return (UNHANDLED);

	regval = vmx_get_guest_reg(vmx, vcpu, (exitqual >> 8) & 0xf);

	vmcs_write(VMCS_CR4_SHADOW, regval);

	crval = regval | cr4_ones_mask;
	crval &= ~cr4_zeros_mask;
	vmcs_write(VMCS_GUEST_CR4, crval);

	return (HANDLED);
}

static int
vmx_emulate_cr8_access(struct vmx *vmx, int vcpu, uint64_t exitqual)
{
	struct vlapic *vlapic;
	uint64_t cr8;
	int regnum;

	/* We only handle mov %cr8 to/from a register at this time. */
	if ((exitqual & 0xe0) != 0x00) {
		return (UNHANDLED);
	}

	vlapic = vm_lapic(vmx->vm, vcpu);
	regnum = (exitqual >> 8) & 0xf;
	if (exitqual & 0x10) {
		cr8 = vlapic_get_cr8(vlapic);
		vmx_set_guest_reg(vmx, vcpu, regnum, cr8);
	} else {
		cr8 = vmx_get_guest_reg(vmx, vcpu, regnum);
		vlapic_set_cr8(vlapic, cr8);
	}

	return (HANDLED);
}

/*
 * From section "Guest Register State" in the Intel SDM: CPL = SS.DPL
 */
static int
vmx_cpl(void)
{
	uint32_t ssar;

	ssar = vmcs_read(VMCS_GUEST_SS_ACCESS_RIGHTS);
	return ((ssar >> 5) & 0x3);
}

static enum vm_cpu_mode
vmx_cpu_mode(void)
{
	uint32_t csar;

	if (vmcs_read(VMCS_GUEST_IA32_EFER) & EFER_LMA) {
		csar = vmcs_read(VMCS_GUEST_CS_ACCESS_RIGHTS);
		if (csar & 0x2000)
			return (CPU_MODE_64BIT);	/* CS.L = 1 */
		else
			return (CPU_MODE_COMPATIBILITY);
	} else if (vmcs_read(VMCS_GUEST_CR0) & CR0_PE) {
		return (CPU_MODE_PROTECTED);
	} else {
		return (CPU_MODE_REAL);
	}
}

static enum vm_paging_mode
vmx_paging_mode(void)
{

	if (!(vmcs_read(VMCS_GUEST_CR0) & CR0_PG))
		return (PAGING_MODE_FLAT);
	if (!(vmcs_read(VMCS_GUEST_CR4) & CR4_PAE))
		return (PAGING_MODE_32);
	if (vmcs_read(VMCS_GUEST_IA32_EFER) & EFER_LME)
		return (PAGING_MODE_64);
	else
		return (PAGING_MODE_PAE);
}

static void
vmx_paging_info(struct vm_guest_paging *paging)
{
	paging->cr3 = vmcs_read(VMCS_GUEST_CR3);
	paging->cpl = vmx_cpl();
	paging->cpu_mode = vmx_cpu_mode();
	paging->paging_mode = vmx_paging_mode();
}

static void
vmexit_mmio_emul(struct vm_exit *vmexit, struct vie *vie, uint64_t gpa,
    uint64_t gla)
{
	struct vm_guest_paging paging;
	uint32_t csar;

	vmexit->exitcode = VM_EXITCODE_MMIO_EMUL;
	vmexit->inst_length = 0;
	vmexit->u.mmio_emul.gpa = gpa;
	vmexit->u.mmio_emul.gla = gla;
	vmx_paging_info(&paging);

	switch (paging.cpu_mode) {
	case CPU_MODE_REAL:
		vmexit->u.mmio_emul.cs_base = vmcs_read(VMCS_GUEST_CS_BASE);
		vmexit->u.mmio_emul.cs_d = 0;
		break;
	case CPU_MODE_PROTECTED:
	case CPU_MODE_COMPATIBILITY:
		vmexit->u.mmio_emul.cs_base = vmcs_read(VMCS_GUEST_CS_BASE);
		csar = vmcs_read(VMCS_GUEST_CS_ACCESS_RIGHTS);
		vmexit->u.mmio_emul.cs_d = SEG_DESC_DEF32(csar);
		break;
	default:
		vmexit->u.mmio_emul.cs_base = 0;
		vmexit->u.mmio_emul.cs_d = 0;
		break;
	}

	vie_init_mmio(vie, NULL, 0, &paging, gpa);
}

static void
vmexit_inout(struct vm_exit *vmexit, struct vie *vie, uint64_t qual,
    uint32_t eax)
{
	struct vm_guest_paging paging;
	struct vm_inout *inout;

	inout = &vmexit->u.inout;

	inout->bytes = (qual & 0x7) + 1;
	inout->flags = 0;
	inout->flags |= (qual & 0x8) ? INOUT_IN : 0;
	inout->flags |= (qual & 0x10) ? INOUT_STR : 0;
	inout->flags |= (qual & 0x20) ? INOUT_REP : 0;
	inout->port = (uint16_t)(qual >> 16);
	inout->eax = eax;
	if (inout->flags & INOUT_STR) {
		uint64_t inst_info;

		inst_info = vmcs_read(VMCS_EXIT_INSTRUCTION_INFO);

		/*
		 * According to the SDM, bits 9:7 encode the address size of the
		 * ins/outs operation, but only values 0/1/2 are expected,
		 * corresponding to 16/32/64 bit sizes.
		 */
		inout->addrsize = 2 << BITX(inst_info, 9, 7);
		VERIFY(inout->addrsize == 2 || inout->addrsize == 4 ||
		    inout->addrsize == 8);

		if (inout->flags & INOUT_IN) {
			/*
			 * The bits describing the segment in INSTRUCTION_INFO
			 * are not defined for ins, leaving it to system
			 * software to assume %es (encoded as 0)
			 */
			inout->segment = 0;
		} else {
			/*
			 * Bits 15-17 encode the segment for OUTS.
			 * This value follows the standard x86 segment order.
			 */
			inout->segment = (inst_info >> 15) & 0x7;
		}
	}

	vmexit->exitcode = VM_EXITCODE_INOUT;
	vmx_paging_info(&paging);
	vie_init_inout(vie, inout, vmexit->inst_length, &paging);

	/* The in/out emulation will handle advancing %rip */
	vmexit->inst_length = 0;
}

static int
ept_fault_type(uint64_t ept_qual)
{
	int fault_type;

	if (ept_qual & EPT_VIOLATION_DATA_WRITE)
		fault_type = PROT_WRITE;
	else if (ept_qual & EPT_VIOLATION_INST_FETCH)
		fault_type = PROT_EXEC;
	else
		fault_type = PROT_READ;

	return (fault_type);
}

static bool
ept_emulation_fault(uint64_t ept_qual)
{
	int read, write;

	/* EPT fault on an instruction fetch doesn't make sense here */
	if (ept_qual & EPT_VIOLATION_INST_FETCH)
		return (false);

	/* EPT fault must be a read fault or a write fault */
	read = ept_qual & EPT_VIOLATION_DATA_READ ? 1 : 0;
	write = ept_qual & EPT_VIOLATION_DATA_WRITE ? 1 : 0;
	if ((read | write) == 0)
		return (false);

	/*
	 * The EPT violation must have been caused by accessing a
	 * guest-physical address that is a translation of a guest-linear
	 * address.
	 */
	if ((ept_qual & EPT_VIOLATION_GLA_VALID) == 0 ||
	    (ept_qual & EPT_VIOLATION_XLAT_VALID) == 0) {
		return (false);
	}

	return (true);
}

static __inline int
apic_access_virtualization(struct vmx *vmx, int vcpuid)
{
	uint32_t proc_ctls2;

	proc_ctls2 = vmx->cap[vcpuid].proc_ctls2;
	return ((proc_ctls2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES) ? 1 : 0);
}

static __inline int
x2apic_virtualization(struct vmx *vmx, int vcpuid)
{
	uint32_t proc_ctls2;

	proc_ctls2 = vmx->cap[vcpuid].proc_ctls2;
	return ((proc_ctls2 & PROCBASED2_VIRTUALIZE_X2APIC_MODE) ? 1 : 0);
}

static int
vmx_handle_apic_write(struct vmx *vmx, int vcpuid, struct vlapic *vlapic,
    uint64_t qual)
{
	const uint_t offset = APIC_WRITE_OFFSET(qual);

	if (!apic_access_virtualization(vmx, vcpuid)) {
		/*
		 * In general there should not be any APIC write VM-exits
		 * unless APIC-access virtualization is enabled.
		 *
		 * However self-IPI virtualization can legitimately trigger
		 * an APIC-write VM-exit so treat it specially.
		 */
		if (x2apic_virtualization(vmx, vcpuid) &&
		    offset == APIC_OFFSET_SELF_IPI) {
			const uint32_t *apic_regs =
			    (uint32_t *)(vlapic->apic_page);
			const uint32_t vector =
			    apic_regs[APIC_OFFSET_SELF_IPI / 4];

			vlapic_self_ipi_handler(vlapic, vector);
			return (HANDLED);
		} else
			return (UNHANDLED);
	}

	switch (offset) {
	case APIC_OFFSET_ID:
		vlapic_id_write_handler(vlapic);
		break;
	case APIC_OFFSET_LDR:
		vlapic_ldr_write_handler(vlapic);
		break;
	case APIC_OFFSET_DFR:
		vlapic_dfr_write_handler(vlapic);
		break;
	case APIC_OFFSET_SVR:
		vlapic_svr_write_handler(vlapic);
		break;
	case APIC_OFFSET_ESR:
		vlapic_esr_write_handler(vlapic);
		break;
	case APIC_OFFSET_ICR_LOW:
		vlapic_icrlo_write_handler(vlapic);
		break;
	case APIC_OFFSET_CMCI_LVT:
	case APIC_OFFSET_TIMER_LVT ... APIC_OFFSET_ERROR_LVT:
		vlapic_lvt_write_handler(vlapic, offset);
		break;
	case APIC_OFFSET_TIMER_ICR:
		vlapic_icrtmr_write_handler(vlapic);
		break;
	case APIC_OFFSET_TIMER_DCR:
		vlapic_dcr_write_handler(vlapic);
		break;
	default:
		return (UNHANDLED);
	}
	return (HANDLED);
}

static bool
apic_access_fault(struct vmx *vmx, int vcpuid, uint64_t gpa)
{

	if (apic_access_virtualization(vmx, vcpuid) &&
	    (gpa >= DEFAULT_APIC_BASE && gpa < DEFAULT_APIC_BASE + PAGE_SIZE))
		return (true);
	else
		return (false);
}

static int
vmx_handle_apic_access(struct vmx *vmx, int vcpuid, struct vm_exit *vmexit)
{
	uint64_t qual;
	int access_type, offset, allowed;
	struct vie *vie;

	if (!apic_access_virtualization(vmx, vcpuid))
		return (UNHANDLED);

	qual = vmexit->u.vmx.exit_qualification;
	access_type = APIC_ACCESS_TYPE(qual);
	offset = APIC_ACCESS_OFFSET(qual);

	allowed = 0;
	if (access_type == 0) {
		/*
		 * Read data access to the following registers is expected.
		 */
		switch (offset) {
		case APIC_OFFSET_APR:
		case APIC_OFFSET_PPR:
		case APIC_OFFSET_RRR:
		case APIC_OFFSET_CMCI_LVT:
		case APIC_OFFSET_TIMER_CCR:
			allowed = 1;
			break;
		default:
			break;
		}
	} else if (access_type == 1) {
		/*
		 * Write data access to the following registers is expected.
		 */
		switch (offset) {
		case APIC_OFFSET_VER:
		case APIC_OFFSET_APR:
		case APIC_OFFSET_PPR:
		case APIC_OFFSET_RRR:
		case APIC_OFFSET_ISR0 ... APIC_OFFSET_ISR7:
		case APIC_OFFSET_TMR0 ... APIC_OFFSET_TMR7:
		case APIC_OFFSET_IRR0 ... APIC_OFFSET_IRR7:
		case APIC_OFFSET_CMCI_LVT:
		case APIC_OFFSET_TIMER_CCR:
			allowed = 1;
			break;
		default:
			break;
		}
	}

	if (allowed) {
		vie = vm_vie_ctx(vmx->vm, vcpuid);
		vmexit_mmio_emul(vmexit, vie, DEFAULT_APIC_BASE + offset,
		    VIE_INVALID_GLA);
	}

	/*
	 * Regardless of whether the APIC-access is allowed this handler
	 * always returns UNHANDLED:
	 * - if the access is allowed then it is handled by emulating the
	 *   instruction that caused the VM-exit (outside the critical section)
	 * - if the access is not allowed then it will be converted to an
	 *   exitcode of VM_EXITCODE_VMX and will be dealt with in userland.
	 */
	return (UNHANDLED);
}

static enum task_switch_reason
vmx_task_switch_reason(uint64_t qual)
{
	int reason;

	reason = (qual >> 30) & 0x3;
	switch (reason) {
	case 0:
		return (TSR_CALL);
	case 1:
		return (TSR_IRET);
	case 2:
		return (TSR_JMP);
	case 3:
		return (TSR_IDT_GATE);
	default:
		panic("%s: invalid reason %d", __func__, reason);
	}
}

static int
vmx_handle_msr(struct vmx *vmx, int vcpuid, struct vm_exit *vmexit,
    bool is_wrmsr)
{
	struct vmxctx *vmxctx = &vmx->ctx[vcpuid];
	const uint32_t ecx = vmxctx->guest_rcx;
	vm_msr_result_t res;
	uint64_t val = 0;

	if (is_wrmsr) {
		vmm_stat_incr(vmx->vm, vcpuid, VMEXIT_WRMSR, 1);
		val = vmxctx->guest_rdx << 32 | (uint32_t)vmxctx->guest_rax;

		if (vlapic_owned_msr(ecx)) {
			struct vlapic *vlapic = vm_lapic(vmx->vm, vcpuid);

			res = vlapic_wrmsr(vlapic, ecx, val);
		} else {
			res = vmx_wrmsr(vmx, vcpuid, ecx, val);
		}
	} else {
		vmm_stat_incr(vmx->vm, vcpuid, VMEXIT_RDMSR, 1);

		if (vlapic_owned_msr(ecx)) {
			struct vlapic *vlapic = vm_lapic(vmx->vm, vcpuid);

			res = vlapic_rdmsr(vlapic, ecx, &val);
		} else {
			res = vmx_rdmsr(vmx, vcpuid, ecx, &val);
		}
	}

	switch (res) {
	case VMR_OK:
		/* Store rdmsr result in the appropriate registers */
		if (!is_wrmsr) {
			vmxctx->guest_rax = (uint32_t)val;
			vmxctx->guest_rdx = val >> 32;
		}
		return (HANDLED);
	case VMR_GP:
		vm_inject_gp(vmx->vm, vcpuid);
		return (HANDLED);
	case VMR_UNHANLDED:
		vmexit->exitcode = is_wrmsr ?
		    VM_EXITCODE_WRMSR : VM_EXITCODE_RDMSR;
		vmexit->u.msr.code = ecx;
		vmexit->u.msr.wval = val;
		return (UNHANDLED);
	default:
		panic("unexpected msr result %u\n", res);
	}
}

static int
vmx_exit_process(struct vmx *vmx, int vcpu, struct vm_exit *vmexit)
{
	int error, errcode, errcode_valid, handled;
	struct vmxctx *vmxctx;
	struct vie *vie;
	struct vlapic *vlapic;
	struct vm_task_switch *ts;
	uint32_t idtvec_info, intr_info;
	uint32_t intr_type, intr_vec, reason;
	uint64_t qual, gpa;

	CTASSERT((PINBASED_CTLS_ONE_SETTING & PINBASED_VIRTUAL_NMI) != 0);
	CTASSERT((PINBASED_CTLS_ONE_SETTING & PINBASED_NMI_EXITING) != 0);

	handled = UNHANDLED;
	vmxctx = &vmx->ctx[vcpu];

	qual = vmexit->u.vmx.exit_qualification;
	reason = vmexit->u.vmx.exit_reason;
	vmexit->exitcode = VM_EXITCODE_BOGUS;

	vmm_stat_incr(vmx->vm, vcpu, VMEXIT_COUNT, 1);
	SDT_PROBE3(vmm, vmx, exit, entry, vmx, vcpu, vmexit);

	/*
	 * VM-entry failures during or after loading guest state.
	 *
	 * These VM-exits are uncommon but must be handled specially
	 * as most VM-exit fields are not populated as usual.
	 */
	if (reason == EXIT_REASON_MCE_DURING_ENTRY) {
		vmm_call_trap(T_MCE);
		return (1);
	}

	/*
	 * VM exits that can be triggered during event delivery need to
	 * be handled specially by re-injecting the event if the IDT
	 * vectoring information field's valid bit is set.
	 *
	 * See "Information for VM Exits During Event Delivery" in Intel SDM
	 * for details.
	 */
	idtvec_info = vmcs_read(VMCS_IDT_VECTORING_INFO);
	if (idtvec_info & VMCS_IDT_VEC_VALID) {
		uint32_t errcode = 0;
		if (idtvec_info & VMCS_IDT_VEC_ERRCODE_VALID) {
			errcode = vmcs_read(VMCS_IDT_VECTORING_ERROR);
		}

		/* Record exit intinfo */
		VERIFY0(vm_exit_intinfo(vmx->vm, vcpu,
		    vmx_idtvec_to_intinfo(idtvec_info, errcode)));

		/*
		 * If 'virtual NMIs' are being used and the VM-exit
		 * happened while injecting an NMI during the previous
		 * VM-entry, then clear "blocking by NMI" in the
		 * Guest Interruptibility-State so the NMI can be
		 * reinjected on the subsequent VM-entry.
		 *
		 * However, if the NMI was being delivered through a task
		 * gate, then the new task must start execution with NMIs
		 * blocked so don't clear NMI blocking in this case.
		 */
		intr_type = idtvec_info & VMCS_INTR_T_MASK;
		if (intr_type == VMCS_INTR_T_NMI) {
			if (reason != EXIT_REASON_TASK_SWITCH)
				vmx_clear_nmi_blocking(vmx, vcpu);
			else
				vmx_assert_nmi_blocking(vmx, vcpu);
		}

		/*
		 * Update VM-entry instruction length if the event being
		 * delivered was a software interrupt or software exception.
		 */
		if (intr_type == VMCS_INTR_T_SWINTR ||
		    intr_type == VMCS_INTR_T_PRIV_SWEXCEPTION ||
		    intr_type == VMCS_INTR_T_SWEXCEPTION) {
			vmcs_write(VMCS_ENTRY_INST_LENGTH, vmexit->inst_length);
		}
	}

	switch (reason) {
	case EXIT_REASON_TRIPLE_FAULT:
		(void) vm_suspend(vmx->vm, VM_SUSPEND_TRIPLEFAULT);
		handled = HANDLED;
		break;
	case EXIT_REASON_TASK_SWITCH:
		ts = &vmexit->u.task_switch;
		ts->tsssel = qual & 0xffff;
		ts->reason = vmx_task_switch_reason(qual);
		ts->ext = 0;
		ts->errcode_valid = 0;
		vmx_paging_info(&ts->paging);
		/*
		 * If the task switch was due to a CALL, JMP, IRET, software
		 * interrupt (INT n) or software exception (INT3, INTO),
		 * then the saved %rip references the instruction that caused
		 * the task switch. The instruction length field in the VMCS
		 * is valid in this case.
		 *
		 * In all other cases (e.g., NMI, hardware exception) the
		 * saved %rip is one that would have been saved in the old TSS
		 * had the task switch completed normally so the instruction
		 * length field is not needed in this case and is explicitly
		 * set to 0.
		 */
		if (ts->reason == TSR_IDT_GATE) {
			KASSERT(idtvec_info & VMCS_IDT_VEC_VALID,
			    ("invalid idtvec_info %x for IDT task switch",
			    idtvec_info));
			intr_type = idtvec_info & VMCS_INTR_T_MASK;
			if (intr_type != VMCS_INTR_T_SWINTR &&
			    intr_type != VMCS_INTR_T_SWEXCEPTION &&
			    intr_type != VMCS_INTR_T_PRIV_SWEXCEPTION) {
				/* Task switch triggered by external event */
				ts->ext = 1;
				vmexit->inst_length = 0;
				if (idtvec_info & VMCS_IDT_VEC_ERRCODE_VALID) {
					ts->errcode_valid = 1;
					ts->errcode =
					    vmcs_read(VMCS_IDT_VECTORING_ERROR);
				}
			}
		}
		vmexit->exitcode = VM_EXITCODE_TASK_SWITCH;
		SDT_PROBE4(vmm, vmx, exit, taskswitch, vmx, vcpu, vmexit, ts);
		break;
	case EXIT_REASON_CR_ACCESS:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_CR_ACCESS, 1);
		SDT_PROBE4(vmm, vmx, exit, craccess, vmx, vcpu, vmexit, qual);
		switch (qual & 0xf) {
		case 0:
			handled = vmx_emulate_cr0_access(vmx, vcpu, qual);
			break;
		case 4:
			handled = vmx_emulate_cr4_access(vmx, vcpu, qual);
			break;
		case 8:
			handled = vmx_emulate_cr8_access(vmx, vcpu, qual);
			break;
		}
		break;
	case EXIT_REASON_RDMSR:
	case EXIT_REASON_WRMSR:
		handled = vmx_handle_msr(vmx, vcpu, vmexit,
		    reason == EXIT_REASON_WRMSR);
		break;
	case EXIT_REASON_HLT:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_HLT, 1);
		SDT_PROBE3(vmm, vmx, exit, halt, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_HLT;
		vmexit->u.hlt.rflags = vmcs_read(VMCS_GUEST_RFLAGS);
		break;
	case EXIT_REASON_MTF:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_MTRAP, 1);
		SDT_PROBE3(vmm, vmx, exit, mtrap, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_MTRAP;
		vmexit->inst_length = 0;
		break;
	case EXIT_REASON_PAUSE:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_PAUSE, 1);
		SDT_PROBE3(vmm, vmx, exit, pause, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_PAUSE;
		break;
	case EXIT_REASON_INTR_WINDOW:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_INTR_WINDOW, 1);
		SDT_PROBE3(vmm, vmx, exit, intrwindow, vmx, vcpu, vmexit);
		ASSERT(vmx_int_window_exiting(vmx, vcpu));
		vmx_clear_int_window_exiting(vmx, vcpu);
		return (1);
	case EXIT_REASON_EXT_INTR:
		/*
		 * External interrupts serve only to cause VM exits and allow
		 * the host interrupt handler to run.
		 *
		 * If this external interrupt triggers a virtual interrupt
		 * to a VM, then that state will be recorded by the
		 * host interrupt handler in the VM's softc. We will inject
		 * this virtual interrupt during the subsequent VM enter.
		 */
		intr_info = vmcs_read(VMCS_EXIT_INTR_INFO);
		SDT_PROBE4(vmm, vmx, exit, interrupt,
		    vmx, vcpu, vmexit, intr_info);

		/*
		 * XXX: Ignore this exit if VMCS_INTR_VALID is not set.
		 * This appears to be a bug in VMware Fusion?
		 */
		if (!(intr_info & VMCS_INTR_VALID))
			return (1);
		KASSERT((intr_info & VMCS_INTR_VALID) != 0 &&
		    (intr_info & VMCS_INTR_T_MASK) == VMCS_INTR_T_HWINTR,
		    ("VM exit interruption info invalid: %x", intr_info));
		vmx_trigger_hostintr(intr_info & 0xff);

		/*
		 * This is special. We want to treat this as an 'handled'
		 * VM-exit but not increment the instruction pointer.
		 */
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_EXTINT, 1);
		return (1);
	case EXIT_REASON_NMI_WINDOW:
		SDT_PROBE3(vmm, vmx, exit, nmiwindow, vmx, vcpu, vmexit);
		/* Exit to allow the pending virtual NMI to be injected */
		if (vm_nmi_pending(vmx->vm, vcpu))
			vmx_inject_nmi(vmx, vcpu);
		ASSERT(vmx_nmi_window_exiting(vmx, vcpu));
		vmx_clear_nmi_window_exiting(vmx, vcpu);
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_NMI_WINDOW, 1);
		return (1);
	case EXIT_REASON_INOUT:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_INOUT, 1);
		vie = vm_vie_ctx(vmx->vm, vcpu);
		vmexit_inout(vmexit, vie, qual, (uint32_t)vmxctx->guest_rax);
		SDT_PROBE3(vmm, vmx, exit, inout, vmx, vcpu, vmexit);
		break;
	case EXIT_REASON_CPUID:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_CPUID, 1);
		SDT_PROBE3(vmm, vmx, exit, cpuid, vmx, vcpu, vmexit);
		vcpu_emulate_cpuid(vmx->vm, vcpu,
		    (uint64_t *)&vmxctx->guest_rax,
		    (uint64_t *)&vmxctx->guest_rbx,
		    (uint64_t *)&vmxctx->guest_rcx,
		    (uint64_t *)&vmxctx->guest_rdx);
		handled = HANDLED;
		break;
	case EXIT_REASON_EXCEPTION:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_EXCEPTION, 1);
		intr_info = vmcs_read(VMCS_EXIT_INTR_INFO);
		KASSERT((intr_info & VMCS_INTR_VALID) != 0,
		    ("VM exit interruption info invalid: %x", intr_info));

		intr_vec = intr_info & 0xff;
		intr_type = intr_info & VMCS_INTR_T_MASK;

		/*
		 * If Virtual NMIs control is 1 and the VM-exit is due to a
		 * fault encountered during the execution of IRET then we must
		 * restore the state of "virtual-NMI blocking" before resuming
		 * the guest.
		 *
		 * See "Resuming Guest Software after Handling an Exception".
		 * See "Information for VM Exits Due to Vectored Events".
		 */
		if ((idtvec_info & VMCS_IDT_VEC_VALID) == 0 &&
		    (intr_vec != IDT_DF) &&
		    (intr_info & EXIT_QUAL_NMIUDTI) != 0)
			vmx_restore_nmi_blocking(vmx, vcpu);

		/*
		 * The NMI has already been handled in vmx_exit_handle_nmi().
		 */
		if (intr_type == VMCS_INTR_T_NMI)
			return (1);

		/*
		 * Call the machine check handler by hand. Also don't reflect
		 * the machine check back into the guest.
		 */
		if (intr_vec == IDT_MC) {
			vmm_call_trap(T_MCE);
			return (1);
		}

		/*
		 * If the hypervisor has requested user exits for
		 * debug exceptions, bounce them out to userland.
		 */
		if (intr_type == VMCS_INTR_T_SWEXCEPTION &&
		    intr_vec == IDT_BP &&
		    (vmx->cap[vcpu].set & (1 << VM_CAP_BPT_EXIT))) {
			vmexit->exitcode = VM_EXITCODE_BPT;
			vmexit->u.bpt.inst_length = vmexit->inst_length;
			vmexit->inst_length = 0;
			break;
		}

		if (intr_vec == IDT_PF) {
			vmxctx->guest_cr2 = qual;
		}

		/*
		 * Software exceptions exhibit trap-like behavior. This in
		 * turn requires populating the VM-entry instruction length
		 * so that the %rip in the trap frame is past the INT3/INTO
		 * instruction.
		 */
		if (intr_type == VMCS_INTR_T_SWEXCEPTION)
			vmcs_write(VMCS_ENTRY_INST_LENGTH, vmexit->inst_length);

		/* Reflect all other exceptions back into the guest */
		errcode_valid = errcode = 0;
		if (intr_info & VMCS_INTR_DEL_ERRCODE) {
			errcode_valid = 1;
			errcode = vmcs_read(VMCS_EXIT_INTR_ERRCODE);
		}
		SDT_PROBE5(vmm, vmx, exit, exception,
		    vmx, vcpu, vmexit, intr_vec, errcode);
		error = vm_inject_exception(vmx->vm, vcpu, intr_vec,
		    errcode_valid, errcode, 0);
		KASSERT(error == 0, ("%s: vm_inject_exception error %d",
		    __func__, error));
		return (1);

	case EXIT_REASON_EPT_FAULT:
		/*
		 * If 'gpa' lies within the address space allocated to
		 * memory then this must be a nested page fault otherwise
		 * this must be an instruction that accesses MMIO space.
		 */
		gpa = vmcs_read(VMCS_GUEST_PHYSICAL_ADDRESS);
		if (vm_mem_allocated(vmx->vm, vcpu, gpa) ||
		    apic_access_fault(vmx, vcpu, gpa)) {
			vmexit->exitcode = VM_EXITCODE_PAGING;
			vmexit->inst_length = 0;
			vmexit->u.paging.gpa = gpa;
			vmexit->u.paging.fault_type = ept_fault_type(qual);
			vmm_stat_incr(vmx->vm, vcpu, VMEXIT_NESTED_FAULT, 1);
			SDT_PROBE5(vmm, vmx, exit, nestedfault,
			    vmx, vcpu, vmexit, gpa, qual);
		} else if (ept_emulation_fault(qual)) {
			vie = vm_vie_ctx(vmx->vm, vcpu);
			vmexit_mmio_emul(vmexit, vie, gpa,
			    vmcs_read(VMCS_GUEST_LINEAR_ADDRESS));
			vmm_stat_incr(vmx->vm, vcpu, VMEXIT_MMIO_EMUL, 1);
			SDT_PROBE4(vmm, vmx, exit, mmiofault,
			    vmx, vcpu, vmexit, gpa);
		}
		/*
		 * If Virtual NMIs control is 1 and the VM-exit is due to an
		 * EPT fault during the execution of IRET then we must restore
		 * the state of "virtual-NMI blocking" before resuming.
		 *
		 * See description of "NMI unblocking due to IRET" in
		 * "Exit Qualification for EPT Violations".
		 */
		if ((idtvec_info & VMCS_IDT_VEC_VALID) == 0 &&
		    (qual & EXIT_QUAL_NMIUDTI) != 0)
			vmx_restore_nmi_blocking(vmx, vcpu);
		break;
	case EXIT_REASON_VIRTUALIZED_EOI:
		vmexit->exitcode = VM_EXITCODE_IOAPIC_EOI;
		vmexit->u.ioapic_eoi.vector = qual & 0xFF;
		SDT_PROBE3(vmm, vmx, exit, eoi, vmx, vcpu, vmexit);
		vmexit->inst_length = 0;	/* trap-like */
		break;
	case EXIT_REASON_APIC_ACCESS:
		SDT_PROBE3(vmm, vmx, exit, apicaccess, vmx, vcpu, vmexit);
		handled = vmx_handle_apic_access(vmx, vcpu, vmexit);
		break;
	case EXIT_REASON_APIC_WRITE:
		/*
		 * APIC-write VM exit is trap-like so the %rip is already
		 * pointing to the next instruction.
		 */
		vmexit->inst_length = 0;
		vlapic = vm_lapic(vmx->vm, vcpu);
		SDT_PROBE4(vmm, vmx, exit, apicwrite,
		    vmx, vcpu, vmexit, vlapic);
		handled = vmx_handle_apic_write(vmx, vcpu, vlapic, qual);
		break;
	case EXIT_REASON_XSETBV:
		SDT_PROBE3(vmm, vmx, exit, xsetbv, vmx, vcpu, vmexit);
		handled = vmx_emulate_xsetbv(vmx, vcpu, vmexit);
		break;
	case EXIT_REASON_MONITOR:
		SDT_PROBE3(vmm, vmx, exit, monitor, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_MONITOR;
		break;
	case EXIT_REASON_MWAIT:
		SDT_PROBE3(vmm, vmx, exit, mwait, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_MWAIT;
		break;
	case EXIT_REASON_TPR:
		vlapic = vm_lapic(vmx->vm, vcpu);
		vlapic_sync_tpr(vlapic);
		vmexit->inst_length = 0;
		handled = HANDLED;
		break;
	case EXIT_REASON_VMCALL:
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
		SDT_PROBE3(vmm, vmx, exit, vminsn, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_VMINSN;
		break;
	case EXIT_REASON_INVD:
	case EXIT_REASON_WBINVD:
		/* ignore exit */
		handled = HANDLED;
		break;
	default:
		SDT_PROBE4(vmm, vmx, exit, unknown,
		    vmx, vcpu, vmexit, reason);
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_UNKNOWN, 1);
		break;
	}

	if (handled) {
		/*
		 * It is possible that control is returned to userland
		 * even though we were able to handle the VM exit in the
		 * kernel.
		 *
		 * In such a case we want to make sure that the userland
		 * restarts guest execution at the instruction *after*
		 * the one we just processed. Therefore we update the
		 * guest rip in the VMCS and in 'vmexit'.
		 */
		vmexit->rip += vmexit->inst_length;
		vmexit->inst_length = 0;
		vmcs_write(VMCS_GUEST_RIP, vmexit->rip);
	} else {
		if (vmexit->exitcode == VM_EXITCODE_BOGUS) {
			/*
			 * If this VM exit was not claimed by anybody then
			 * treat it as a generic VMX exit.
			 */
			vmexit->exitcode = VM_EXITCODE_VMX;
			vmexit->u.vmx.status = VM_SUCCESS;
			vmexit->u.vmx.inst_type = 0;
			vmexit->u.vmx.inst_error = 0;
		} else {
			/*
			 * The exitcode and collateral have been populated.
			 * The VM exit will be processed further in userland.
			 */
		}
	}

	SDT_PROBE4(vmm, vmx, exit, return,
	    vmx, vcpu, vmexit, handled);
	return (handled);
}

static void
vmx_exit_inst_error(struct vmxctx *vmxctx, int rc, struct vm_exit *vmexit)
{

	KASSERT(vmxctx->inst_fail_status != VM_SUCCESS,
	    ("vmx_exit_inst_error: invalid inst_fail_status %d",
	    vmxctx->inst_fail_status));

	vmexit->inst_length = 0;
	vmexit->exitcode = VM_EXITCODE_VMX;
	vmexit->u.vmx.status = vmxctx->inst_fail_status;
	vmexit->u.vmx.inst_error = vmcs_read(VMCS_INSTRUCTION_ERROR);
	vmexit->u.vmx.exit_reason = ~0;
	vmexit->u.vmx.exit_qualification = ~0;

	switch (rc) {
	case VMX_VMRESUME_ERROR:
	case VMX_VMLAUNCH_ERROR:
	case VMX_INVEPT_ERROR:
	case VMX_VMWRITE_ERROR:
		vmexit->u.vmx.inst_type = rc;
		break;
	default:
		panic("vm_exit_inst_error: vmx_enter_guest returned %d", rc);
	}
}

/*
 * If the NMI-exiting VM execution control is set to '1' then an NMI in
 * non-root operation causes a VM-exit. NMI blocking is in effect so it is
 * sufficient to simply vector to the NMI handler via a software interrupt.
 * However, this must be done before maskable interrupts are enabled
 * otherwise the "iret" issued by an interrupt handler will incorrectly
 * clear NMI blocking.
 */
static __inline void
vmx_exit_handle_possible_nmi(struct vm_exit *vmexit)
{
	ASSERT(!interrupts_enabled());

	if (vmexit->u.vmx.exit_reason == EXIT_REASON_EXCEPTION) {
		uint32_t intr_info = vmcs_read(VMCS_EXIT_INTR_INFO);
		ASSERT(intr_info & VMCS_INTR_VALID);

		if ((intr_info & VMCS_INTR_T_MASK) == VMCS_INTR_T_NMI) {
			ASSERT3U(intr_info & 0xff, ==, IDT_NMI);
			vmm_call_trap(T_NMIFLT);
		}
	}
}

static __inline void
vmx_dr_enter_guest(struct vmxctx *vmxctx)
{
	uint64_t rflags;

	/* Save host control debug registers. */
	vmxctx->host_dr7 = rdr7();
	vmxctx->host_debugctl = rdmsr(MSR_DEBUGCTLMSR);

	/*
	 * Disable debugging in DR7 and DEBUGCTL to avoid triggering
	 * exceptions in the host based on the guest DRx values.  The
	 * guest DR7 and DEBUGCTL are saved/restored in the VMCS.
	 */
	load_dr7(0);
	wrmsr(MSR_DEBUGCTLMSR, 0);

	/*
	 * Disable single stepping the kernel to avoid corrupting the
	 * guest DR6.  A debugger might still be able to corrupt the
	 * guest DR6 by setting a breakpoint after this point and then
	 * single stepping.
	 */
	rflags = read_rflags();
	vmxctx->host_tf = rflags & PSL_T;
	write_rflags(rflags & ~PSL_T);

	/* Save host debug registers. */
	vmxctx->host_dr0 = rdr0();
	vmxctx->host_dr1 = rdr1();
	vmxctx->host_dr2 = rdr2();
	vmxctx->host_dr3 = rdr3();
	vmxctx->host_dr6 = rdr6();

	/* Restore guest debug registers. */
	load_dr0(vmxctx->guest_dr0);
	load_dr1(vmxctx->guest_dr1);
	load_dr2(vmxctx->guest_dr2);
	load_dr3(vmxctx->guest_dr3);
	load_dr6(vmxctx->guest_dr6);
}

static __inline void
vmx_dr_leave_guest(struct vmxctx *vmxctx)
{

	/* Save guest debug registers. */
	vmxctx->guest_dr0 = rdr0();
	vmxctx->guest_dr1 = rdr1();
	vmxctx->guest_dr2 = rdr2();
	vmxctx->guest_dr3 = rdr3();
	vmxctx->guest_dr6 = rdr6();

	/*
	 * Restore host debug registers.  Restore DR7, DEBUGCTL, and
	 * PSL_T last.
	 */
	load_dr0(vmxctx->host_dr0);
	load_dr1(vmxctx->host_dr1);
	load_dr2(vmxctx->host_dr2);
	load_dr3(vmxctx->host_dr3);
	load_dr6(vmxctx->host_dr6);
	wrmsr(MSR_DEBUGCTLMSR, vmxctx->host_debugctl);
	load_dr7(vmxctx->host_dr7);
	write_rflags(read_rflags() | vmxctx->host_tf);
}

static int
vmx_run(void *arg, int vcpu, uint64_t rip)
{
	int rc, handled, launched;
	struct vmx *vmx;
	struct vm *vm;
	struct vmxctx *vmxctx;
	uintptr_t vmcs_pa;
	struct vm_exit *vmexit;
	struct vlapic *vlapic;
	uint32_t exit_reason;
	bool tpr_shadow_active;
	vm_client_t *vmc;

	vmx = arg;
	vm = vmx->vm;
	vmcs_pa = vmx->vmcs_pa[vcpu];
	vmxctx = &vmx->ctx[vcpu];
	vlapic = vm_lapic(vm, vcpu);
	vmexit = vm_exitinfo(vm, vcpu);
	vmc = vm_get_vmclient(vm, vcpu);
	launched = 0;
	tpr_shadow_active = vmx_cap_en(vmx, VMX_CAP_TPR_SHADOW) &&
	    !vmx_cap_en(vmx, VMX_CAP_APICV) &&
	    (vmx->cap[vcpu].proc_ctls & PROCBASED_USE_TPR_SHADOW) != 0;

	vmx_msr_guest_enter(vmx, vcpu);

	vmcs_load(vmcs_pa);

	VERIFY(vmx->vmcs_state[vcpu] == VS_NONE && curthread->t_preempt != 0);
	vmx->vmcs_state[vcpu] = VS_LOADED;

	/*
	 * XXX
	 * We do this every time because we may setup the virtual machine
	 * from a different process than the one that actually runs it.
	 *
	 * If the life of a virtual machine was spent entirely in the context
	 * of a single process we could do this once in vmx_vminit().
	 */
	vmcs_write(VMCS_HOST_CR3, rcr3());

	vmcs_write(VMCS_GUEST_RIP, rip);
	vmx_set_pcpu_defaults(vmx, vcpu);
	do {
		enum event_inject_state inject_state;
		uint64_t eptgen;

		ASSERT3U(vmcs_read(VMCS_GUEST_RIP), ==, rip);

		handled = UNHANDLED;

		/*
		 * Perform initial event/exception/interrupt injection before
		 * host CPU interrupts are disabled.
		 */
		inject_state = vmx_inject_events(vmx, vcpu, rip);

		/*
		 * Interrupts are disabled from this point on until the
		 * guest starts executing. This is done for the following
		 * reasons:
		 *
		 * If an AST is asserted on this thread after the check below,
		 * then the IPI_AST notification will not be lost, because it
		 * will cause a VM exit due to external interrupt as soon as
		 * the guest state is loaded.
		 *
		 * A posted interrupt after vmx_inject_vlapic() will not be
		 * "lost" because it will be held pending in the host APIC
		 * because interrupts are disabled. The pending interrupt will
		 * be recognized as soon as the guest state is loaded.
		 *
		 * The same reasoning applies to the IPI generated by vmspace
		 * invalidation.
		 */
		disable_intr();

		/*
		 * If not precluded by existing events, inject any interrupt
		 * pending on the vLAPIC.  As a lock-less operation, it is safe
		 * (and prudent) to perform with host CPU interrupts disabled.
		 */
		if (inject_state == EIS_CAN_INJECT) {
			inject_state = vmx_inject_vlapic(vmx, vcpu, vlapic);
		}

		/*
		 * Check for vCPU bail-out conditions.  This must be done after
		 * vmx_inject_events() to detect a triple-fault condition.
		 */
		if (vcpu_entry_bailout_checks(vmx->vm, vcpu, rip)) {
			enable_intr();
			break;
		}

		if (vcpu_run_state_pending(vm, vcpu)) {
			enable_intr();
			vm_exit_run_state(vmx->vm, vcpu, rip);
			break;
		}

		/*
		 * If subsequent activity queued events which require injection
		 * handling, take another lap to handle them.
		 */
		if (vmx_inject_recheck(vmx, vcpu, inject_state)) {
			enable_intr();
			handled = HANDLED;
			continue;
		}

		if ((rc = smt_acquire()) != 1) {
			enable_intr();
			vmexit->rip = rip;
			vmexit->inst_length = 0;
			if (rc == -1) {
				vmexit->exitcode = VM_EXITCODE_HT;
			} else {
				vmexit->exitcode = VM_EXITCODE_BOGUS;
				handled = HANDLED;
			}
			break;
		}

		/*
		 * If this thread has gone off-cpu due to mutex operations
		 * during vmx_run, the VMCS will have been unloaded, forcing a
		 * re-VMLAUNCH as opposed to VMRESUME.
		 */
		launched = (vmx->vmcs_state[vcpu] & VS_LAUNCHED) != 0;
		/*
		 * Restoration of the GDT limit is taken care of by
		 * vmx_savectx().  Since the maximum practical index for the
		 * IDT is 255, restoring its limits from the post-VMX-exit
		 * default of 0xffff is not a concern.
		 *
		 * Only 64-bit hypervisor callers are allowed, which forgoes
		 * the need to restore any LDT descriptor.  Toss an error to
		 * anyone attempting to break that rule.
		 */
		if (curproc->p_model != DATAMODEL_LP64) {
			smt_release();
			enable_intr();
			bzero(vmexit, sizeof (*vmexit));
			vmexit->rip = rip;
			vmexit->exitcode = VM_EXITCODE_VMX;
			vmexit->u.vmx.status = VM_FAIL_INVALID;
			handled = UNHANDLED;
			break;
		}

		if (tpr_shadow_active) {
			vmx_tpr_shadow_enter(vlapic);
		}

		/*
		 * Indicate activation of vmspace (EPT) table just prior to VMX
		 * entry, checking for the necessity of an invept invalidation.
		 */
		eptgen = vmc_table_enter(vmc);
		if (vmx->eptgen[curcpu] != eptgen) {
			/*
			 * VMspace generation does not match what was previously
			 * used on this host CPU, so all mappings associated
			 * with this EP4TA must be invalidated.
			 */
			invept(1, vmx->eptp);
			vmx->eptgen[curcpu] = eptgen;
		}

		vcpu_ustate_change(vm, vcpu, VU_RUN);
		vmx_dr_enter_guest(vmxctx);

		/* Perform VMX entry */
		rc = vmx_enter_guest(vmxctx, vmx, launched);

		vmx_dr_leave_guest(vmxctx);
		vcpu_ustate_change(vm, vcpu, VU_EMU_KERN);

		vmx->vmcs_state[vcpu] |= VS_LAUNCHED;
		smt_release();

		if (tpr_shadow_active) {
			vmx_tpr_shadow_exit(vlapic);
		}

		/* Collect some information for VM exit processing */
		vmexit->rip = rip = vmcs_read(VMCS_GUEST_RIP);
		vmexit->inst_length = vmcs_read(VMCS_EXIT_INSTRUCTION_LENGTH);
		vmexit->u.vmx.exit_reason = exit_reason =
		    (vmcs_read(VMCS_EXIT_REASON) & BASIC_EXIT_REASON_MASK);
		vmexit->u.vmx.exit_qualification =
		    vmcs_read(VMCS_EXIT_QUALIFICATION);
		/* Update 'nextrip' */
		vmx->state[vcpu].nextrip = rip;

		if (rc == VMX_GUEST_VMEXIT) {
			vmx_exit_handle_possible_nmi(vmexit);
		}
		enable_intr();
		vmc_table_exit(vmc);

		if (rc == VMX_GUEST_VMEXIT) {
			handled = vmx_exit_process(vmx, vcpu, vmexit);
		} else {
			vmx_exit_inst_error(vmxctx, rc, vmexit);
		}
		DTRACE_PROBE3(vmm__vexit, int, vcpu, uint64_t, rip,
		    uint32_t, exit_reason);
		rip = vmexit->rip;
	} while (handled);

	/* If a VM exit has been handled then the exitcode must be BOGUS */
	if (handled && vmexit->exitcode != VM_EXITCODE_BOGUS) {
		panic("Non-BOGUS exitcode (%d) unexpected for handled VM exit",
		    vmexit->exitcode);
	}

	vmcs_clear(vmcs_pa);
	vmx_msr_guest_exit(vmx, vcpu);

	VERIFY(vmx->vmcs_state[vcpu] != VS_NONE && curthread->t_preempt != 0);
	vmx->vmcs_state[vcpu] = VS_NONE;

	return (0);
}

static void
vmx_vmcleanup(void *arg)
{
	int i;
	struct vmx *vmx = arg;
	uint16_t maxcpus;

	if (vmx_cap_en(vmx, VMX_CAP_APICV)) {
		(void) vm_unmap_mmio(vmx->vm, DEFAULT_APIC_BASE, PAGE_SIZE);
		kmem_free(vmx->apic_access_page, PAGESIZE);
	} else {
		VERIFY3P(vmx->apic_access_page, ==, NULL);
	}

	vmx_msr_bitmap_destroy(vmx);

	maxcpus = vm_get_maxcpus(vmx->vm);
	for (i = 0; i < maxcpus; i++)
		vpid_free(vmx->state[i].vpid);

	kmem_free(vmx, sizeof (*vmx));
}

/*
 * Ensure that the VMCS for this vcpu is loaded.
 * Returns true if a VMCS load was required.
 */
static bool
vmx_vmcs_access_ensure(struct vmx *vmx, int vcpu)
{
	int hostcpu;

	if (vcpu_is_running(vmx->vm, vcpu, &hostcpu)) {
		if (hostcpu != curcpu) {
			panic("unexpected vcpu migration %d != %d",
			    hostcpu, curcpu);
		}
		/* Earlier logic already took care of the load */
		return (false);
	} else {
		vmcs_load(vmx->vmcs_pa[vcpu]);
		return (true);
	}
}

static void
vmx_vmcs_access_done(struct vmx *vmx, int vcpu)
{
	int hostcpu;

	if (vcpu_is_running(vmx->vm, vcpu, &hostcpu)) {
		if (hostcpu != curcpu) {
			panic("unexpected vcpu migration %d != %d",
			    hostcpu, curcpu);
		}
		/* Later logic will take care of the unload */
	} else {
		vmcs_clear(vmx->vmcs_pa[vcpu]);
	}
}

static uint64_t *
vmxctx_regptr(struct vmxctx *vmxctx, int reg)
{
	switch (reg) {
	case VM_REG_GUEST_RAX:
		return (&vmxctx->guest_rax);
	case VM_REG_GUEST_RBX:
		return (&vmxctx->guest_rbx);
	case VM_REG_GUEST_RCX:
		return (&vmxctx->guest_rcx);
	case VM_REG_GUEST_RDX:
		return (&vmxctx->guest_rdx);
	case VM_REG_GUEST_RSI:
		return (&vmxctx->guest_rsi);
	case VM_REG_GUEST_RDI:
		return (&vmxctx->guest_rdi);
	case VM_REG_GUEST_RBP:
		return (&vmxctx->guest_rbp);
	case VM_REG_GUEST_R8:
		return (&vmxctx->guest_r8);
	case VM_REG_GUEST_R9:
		return (&vmxctx->guest_r9);
	case VM_REG_GUEST_R10:
		return (&vmxctx->guest_r10);
	case VM_REG_GUEST_R11:
		return (&vmxctx->guest_r11);
	case VM_REG_GUEST_R12:
		return (&vmxctx->guest_r12);
	case VM_REG_GUEST_R13:
		return (&vmxctx->guest_r13);
	case VM_REG_GUEST_R14:
		return (&vmxctx->guest_r14);
	case VM_REG_GUEST_R15:
		return (&vmxctx->guest_r15);
	case VM_REG_GUEST_CR2:
		return (&vmxctx->guest_cr2);
	case VM_REG_GUEST_DR0:
		return (&vmxctx->guest_dr0);
	case VM_REG_GUEST_DR1:
		return (&vmxctx->guest_dr1);
	case VM_REG_GUEST_DR2:
		return (&vmxctx->guest_dr2);
	case VM_REG_GUEST_DR3:
		return (&vmxctx->guest_dr3);
	case VM_REG_GUEST_DR6:
		return (&vmxctx->guest_dr6);
	default:
		break;
	}
	return (NULL);
}

static int
vmx_getreg(void *arg, int vcpu, int reg, uint64_t *retval)
{
	struct vmx *vmx = arg;
	uint64_t *regp;

	/* VMCS access not required for ctx reads */
	if ((regp = vmxctx_regptr(&vmx->ctx[vcpu], reg)) != NULL) {
		*retval = *regp;
		return (0);
	}

	bool vmcs_loaded = vmx_vmcs_access_ensure(vmx, vcpu);
	int err = 0;

	if (reg == VM_REG_GUEST_INTR_SHADOW) {
		uint64_t gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
		*retval = (gi & HWINTR_BLOCKING) ? 1 : 0;
	} else {
		uint32_t encoding;

		encoding = vmcs_field_encoding(reg);
		switch (encoding) {
		case VMCS_GUEST_CR0:
			/* Take the shadow bits into account */
			*retval = vmx_unshadow_cr0(vmcs_read(encoding),
			    vmcs_read(VMCS_CR0_SHADOW));
			break;
		case VMCS_GUEST_CR4:
			/* Take the shadow bits into account */
			*retval = vmx_unshadow_cr4(vmcs_read(encoding),
			    vmcs_read(VMCS_CR4_SHADOW));
			break;
		case VMCS_INVALID_ENCODING:
			err = EINVAL;
			break;
		default:
			*retval = vmcs_read(encoding);
			break;
		}
	}

	if (vmcs_loaded) {
		vmx_vmcs_access_done(vmx, vcpu);
	}
	return (err);
}

static int
vmx_setreg(void *arg, int vcpu, int reg, uint64_t val)
{
	struct vmx *vmx = arg;
	uint64_t *regp;

	/* VMCS access not required for ctx writes */
	if ((regp = vmxctx_regptr(&vmx->ctx[vcpu], reg)) != NULL) {
		*regp = val;
		return (0);
	}

	bool vmcs_loaded = vmx_vmcs_access_ensure(vmx, vcpu);
	int err = 0;

	if (reg == VM_REG_GUEST_INTR_SHADOW) {
		if (val != 0) {
			/*
			 * Forcing the vcpu into an interrupt shadow is not
			 * presently supported.
			 */
			err = EINVAL;
		} else {
			uint64_t gi;

			gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
			gi &= ~HWINTR_BLOCKING;
			vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
			err = 0;
		}
	} else {
		uint32_t encoding;

		err = 0;
		encoding = vmcs_field_encoding(reg);
		switch (encoding) {
		case VMCS_GUEST_IA32_EFER:
			vmcs_write(encoding, val);
			vmx_sync_efer_state(vmx, vcpu, val);
			break;
		case VMCS_GUEST_CR0:
			/*
			 * The guest is not allowed to modify certain bits in
			 * %cr0 and %cr4.  To maintain the illusion of full
			 * control, they have shadow versions which contain the
			 * guest-perceived (via reads from the register) values
			 * as opposed to the guest-effective values.
			 *
			 * This is detailed in the SDM: Vol. 3 Ch. 24.6.6.
			 */
			vmcs_write(VMCS_CR0_SHADOW, val);
			vmcs_write(encoding, vmx_fix_cr0(val));
			break;
		case VMCS_GUEST_CR4:
			/* See above for detail on %cr4 shadowing */
			vmcs_write(VMCS_CR4_SHADOW, val);
			vmcs_write(encoding, vmx_fix_cr4(val));
			break;
		case VMCS_GUEST_CR3:
			vmcs_write(encoding, val);
			/*
			 * Invalidate the guest vcpu's TLB mappings to emulate
			 * the behavior of updating %cr3.
			 *
			 * XXX the processor retains global mappings when %cr3
			 * is updated but vmx_invvpid() does not.
			 */
			vmx_invvpid(vmx, vcpu,
			    vcpu_is_running(vmx->vm, vcpu, NULL));
			break;
		case VMCS_INVALID_ENCODING:
			err = EINVAL;
			break;
		default:
			vmcs_write(encoding, val);
			break;
		}
	}

	if (vmcs_loaded) {
		vmx_vmcs_access_done(vmx, vcpu);
	}
	return (err);
}

static int
vmx_getdesc(void *arg, int vcpu, int seg, struct seg_desc *desc)
{
	struct vmx *vmx = arg;
	uint32_t base, limit, access;

	bool vmcs_loaded = vmx_vmcs_access_ensure(vmx, vcpu);

	vmcs_seg_desc_encoding(seg, &base, &limit, &access);
	desc->base = vmcs_read(base);
	desc->limit = vmcs_read(limit);
	if (access != VMCS_INVALID_ENCODING) {
		desc->access = vmcs_read(access);
	} else {
		desc->access = 0;
	}

	if (vmcs_loaded) {
		vmx_vmcs_access_done(vmx, vcpu);
	}
	return (0);
}

static int
vmx_setdesc(void *arg, int vcpu, int seg, const struct seg_desc *desc)
{
	struct vmx *vmx = arg;
	uint32_t base, limit, access;

	bool vmcs_loaded = vmx_vmcs_access_ensure(vmx, vcpu);

	vmcs_seg_desc_encoding(seg, &base, &limit, &access);
	vmcs_write(base, desc->base);
	vmcs_write(limit, desc->limit);
	if (access != VMCS_INVALID_ENCODING) {
		vmcs_write(access, desc->access);
	}

	if (vmcs_loaded) {
		vmx_vmcs_access_done(vmx, vcpu);
	}
	return (0);
}

static uint64_t *
vmx_msr_ptr(struct vmx *vmx, int vcpu, uint32_t msr)
{
	uint64_t *guest_msrs = vmx->guest_msrs[vcpu];

	switch (msr) {
	case MSR_LSTAR:
		return (&guest_msrs[IDX_MSR_LSTAR]);
	case MSR_CSTAR:
		return (&guest_msrs[IDX_MSR_CSTAR]);
	case MSR_STAR:
		return (&guest_msrs[IDX_MSR_STAR]);
	case MSR_SF_MASK:
		return (&guest_msrs[IDX_MSR_SF_MASK]);
	case MSR_KGSBASE:
		return (&guest_msrs[IDX_MSR_KGSBASE]);
	case MSR_PAT:
		return (&guest_msrs[IDX_MSR_PAT]);
	default:
		return (NULL);
	}
}

static int
vmx_msr_get(void *arg, int vcpu, uint32_t msr, uint64_t *valp)
{
	struct vmx *vmx = arg;

	ASSERT(valp != NULL);

	const uint64_t *msrp = vmx_msr_ptr(vmx, vcpu, msr);
	if (msrp != NULL) {
		*valp = *msrp;
		return (0);
	}

	const uint32_t vmcs_enc = vmcs_msr_encoding(msr);
	if (vmcs_enc != VMCS_INVALID_ENCODING) {
		bool vmcs_loaded = vmx_vmcs_access_ensure(vmx, vcpu);

		*valp = vmcs_read(vmcs_enc);

		if (vmcs_loaded) {
			vmx_vmcs_access_done(vmx, vcpu);
		}
		return (0);
	}

	return (EINVAL);
}

static int
vmx_msr_set(void *arg, int vcpu, uint32_t msr, uint64_t val)
{
	struct vmx *vmx = arg;

	/* TODO: mask value */

	uint64_t *msrp = vmx_msr_ptr(vmx, vcpu, msr);
	if (msrp != NULL) {
		*msrp = val;
		return (0);
	}

	const uint32_t vmcs_enc = vmcs_msr_encoding(msr);
	if (vmcs_enc != VMCS_INVALID_ENCODING) {
		bool vmcs_loaded = vmx_vmcs_access_ensure(vmx, vcpu);

		vmcs_write(vmcs_enc, val);

		if (msr == MSR_EFER) {
			vmx_sync_efer_state(vmx, vcpu, val);
		}

		if (vmcs_loaded) {
			vmx_vmcs_access_done(vmx, vcpu);
		}
		return (0);
	}
	return (EINVAL);
}

static int
vmx_getcap(void *arg, int vcpu, int type, int *retval)
{
	struct vmx *vmx = arg;
	int vcap;
	int ret;

	ret = ENOENT;

	vcap = vmx->cap[vcpu].set;

	switch (type) {
	case VM_CAP_HALT_EXIT:
		ret = 0;
		break;
	case VM_CAP_PAUSE_EXIT:
		if (cap_pause_exit)
			ret = 0;
		break;
	case VM_CAP_MTRAP_EXIT:
		if (cap_monitor_trap)
			ret = 0;
		break;
	case VM_CAP_ENABLE_INVPCID:
		if (cap_invpcid)
			ret = 0;
		break;
	case VM_CAP_BPT_EXIT:
		ret = 0;
		break;
	default:
		break;
	}

	if (ret == 0)
		*retval = (vcap & (1 << type)) ? 1 : 0;

	return (ret);
}

static int
vmx_setcap(void *arg, int vcpu, int type, int val)
{
	struct vmx *vmx = arg;
	uint32_t baseval, reg, flag;
	uint32_t *pptr;
	int error;

	error = ENOENT;
	pptr = NULL;

	switch (type) {
	case VM_CAP_HALT_EXIT:
		error = 0;
		pptr = &vmx->cap[vcpu].proc_ctls;
		baseval = *pptr;
		flag = PROCBASED_HLT_EXITING;
		reg = VMCS_PRI_PROC_BASED_CTLS;
		break;
	case VM_CAP_MTRAP_EXIT:
		if (cap_monitor_trap) {
			error = 0;
			pptr = &vmx->cap[vcpu].proc_ctls;
			baseval = *pptr;
			flag = PROCBASED_MTF;
			reg = VMCS_PRI_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_PAUSE_EXIT:
		if (cap_pause_exit) {
			error = 0;
			pptr = &vmx->cap[vcpu].proc_ctls;
			baseval = *pptr;
			flag = PROCBASED_PAUSE_EXITING;
			reg = VMCS_PRI_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_ENABLE_INVPCID:
		if (cap_invpcid) {
			error = 0;
			pptr = &vmx->cap[vcpu].proc_ctls2;
			baseval = *pptr;
			flag = PROCBASED2_ENABLE_INVPCID;
			reg = VMCS_SEC_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_BPT_EXIT:
		error = 0;

		/* Don't change the bitmap if we are tracing all exceptions. */
		if (vmx->cap[vcpu].exc_bitmap != 0xffffffff) {
			pptr = &vmx->cap[vcpu].exc_bitmap;
			baseval = *pptr;
			flag = (1 << IDT_BP);
			reg = VMCS_EXCEPTION_BITMAP;
		}
		break;
	default:
		break;
	}

	if (error != 0) {
		return (error);
	}

	if (pptr != NULL) {
		if (val) {
			baseval |= flag;
		} else {
			baseval &= ~flag;
		}
		vmcs_load(vmx->vmcs_pa[vcpu]);
		vmcs_write(reg, baseval);
		vmcs_clear(vmx->vmcs_pa[vcpu]);

		/*
		 * Update optional stored flags, and record
		 * setting
		 */
		*pptr = baseval;
	}

	if (val) {
		vmx->cap[vcpu].set |= (1 << type);
	} else {
		vmx->cap[vcpu].set &= ~(1 << type);
	}

	return (0);
}

struct vlapic_vtx {
	struct vlapic	vlapic;

	/* Align to the nearest cacheline */
	uint8_t		_pad[64 - (sizeof (struct vlapic) % 64)];

	/* TMR handling state for posted interrupts */
	uint32_t	tmr_active[8];
	uint32_t	pending_level[8];
	uint32_t	pending_edge[8];

	struct pir_desc	*pir_desc;
	struct vmx	*vmx;
	uint_t	pending_prio;
	boolean_t	tmr_sync;
};

CTASSERT((offsetof(struct vlapic_vtx, tmr_active) & 63) == 0);

#define	VPR_PRIO_BIT(vpr)	(1 << ((vpr) >> 4))

static vcpu_notify_t
vmx_apicv_set_ready(struct vlapic *vlapic, int vector, bool level)
{
	struct vlapic_vtx *vlapic_vtx;
	struct pir_desc *pir_desc;
	uint32_t mask, tmrval;
	int idx;
	vcpu_notify_t notify = VCPU_NOTIFY_NONE;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	pir_desc = vlapic_vtx->pir_desc;
	idx = vector / 32;
	mask = 1UL << (vector % 32);

	/*
	 * If the currently asserted TMRs do not match the state requested by
	 * the incoming interrupt, an exit will be required to reconcile those
	 * bits in the APIC page.  This will keep the vLAPIC behavior in line
	 * with the architecturally defined expectations.
	 *
	 * If actors of mixed types (edge and level) are racing against the same
	 * vector (toggling its TMR bit back and forth), the results could
	 * inconsistent.  Such circumstances are considered a rare edge case and
	 * are never expected to be found in the wild.
	 */
	tmrval = atomic_load_acq_int(&vlapic_vtx->tmr_active[idx]);
	if (!level) {
		if ((tmrval & mask) != 0) {
			/* Edge-triggered interrupt needs TMR de-asserted */
			atomic_set_int(&vlapic_vtx->pending_edge[idx], mask);
			atomic_store_rel_long(&pir_desc->pending, 1);
			return (VCPU_NOTIFY_EXIT);
		}
	} else {
		if ((tmrval & mask) == 0) {
			/* Level-triggered interrupt needs TMR asserted */
			atomic_set_int(&vlapic_vtx->pending_level[idx], mask);
			atomic_store_rel_long(&pir_desc->pending, 1);
			return (VCPU_NOTIFY_EXIT);
		}
	}

	/*
	 * If the interrupt request does not require manipulation of the TMRs
	 * for delivery, set it in PIR descriptor.  It cannot be inserted into
	 * the APIC page while the vCPU might be running.
	 */
	atomic_set_int(&pir_desc->pir[idx], mask);

	/*
	 * A notification is required whenever the 'pending' bit makes a
	 * transition from 0->1.
	 *
	 * Even if the 'pending' bit is already asserted, notification about
	 * the incoming interrupt may still be necessary.  For example, if a
	 * vCPU is HLTed with a high PPR, a low priority interrupt would cause
	 * the 0->1 'pending' transition with a notification, but the vCPU
	 * would ignore the interrupt for the time being.  The same vCPU would
	 * need to then be notified if a high-priority interrupt arrived which
	 * satisfied the PPR.
	 *
	 * The priorities of interrupts injected while 'pending' is asserted
	 * are tracked in a custom bitfield 'pending_prio'.  Should the
	 * to-be-injected interrupt exceed the priorities already present, the
	 * notification is sent.  The priorities recorded in 'pending_prio' are
	 * cleared whenever the 'pending' bit makes another 0->1 transition.
	 */
	if (atomic_cmpset_long(&pir_desc->pending, 0, 1) != 0) {
		notify = VCPU_NOTIFY_APIC;
		vlapic_vtx->pending_prio = 0;
	} else {
		const uint_t old_prio = vlapic_vtx->pending_prio;
		const uint_t prio_bit = VPR_PRIO_BIT(vector & APIC_TPR_INT);

		if ((old_prio & prio_bit) == 0 && prio_bit > old_prio) {
			atomic_set_int(&vlapic_vtx->pending_prio, prio_bit);
			notify = VCPU_NOTIFY_APIC;
		}
	}

	return (notify);
}

static void
vmx_apicv_accepted(struct vlapic *vlapic, int vector)
{
	/*
	 * When APICv is enabled for an instance, the traditional interrupt
	 * injection method (populating ENTRY_INTR_INFO in the VMCS) is not
	 * used and the CPU does the heavy lifting of virtual interrupt
	 * delivery.  For that reason vmx_intr_accepted() should never be called
	 * when APICv is enabled.
	 */
	panic("vmx_intr_accepted: not expected to be called");
}

static void
vmx_apicv_sync_tmr(struct vlapic *vlapic)
{
	struct vlapic_vtx *vlapic_vtx;
	const uint32_t *tmrs;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	tmrs = &vlapic_vtx->tmr_active[0];

	if (!vlapic_vtx->tmr_sync) {
		return;
	}

	vmcs_write(VMCS_EOI_EXIT0, ((uint64_t)tmrs[1] << 32) | tmrs[0]);
	vmcs_write(VMCS_EOI_EXIT1, ((uint64_t)tmrs[3] << 32) | tmrs[2]);
	vmcs_write(VMCS_EOI_EXIT2, ((uint64_t)tmrs[5] << 32) | tmrs[4]);
	vmcs_write(VMCS_EOI_EXIT3, ((uint64_t)tmrs[7] << 32) | tmrs[6]);
	vlapic_vtx->tmr_sync = B_FALSE;
}

static void
vmx_enable_x2apic_mode_ts(struct vlapic *vlapic)
{
	struct vmx *vmx;
	uint32_t proc_ctls;
	int vcpuid;

	vcpuid = vlapic->vcpuid;
	vmx = ((struct vlapic_vtx *)vlapic)->vmx;

	proc_ctls = vmx->cap[vcpuid].proc_ctls;
	proc_ctls &= ~PROCBASED_USE_TPR_SHADOW;
	proc_ctls |= PROCBASED_CR8_LOAD_EXITING;
	proc_ctls |= PROCBASED_CR8_STORE_EXITING;
	vmx->cap[vcpuid].proc_ctls = proc_ctls;

	vmcs_load(vmx->vmcs_pa[vcpuid]);
	vmcs_write(VMCS_PRI_PROC_BASED_CTLS, proc_ctls);
	vmcs_clear(vmx->vmcs_pa[vcpuid]);
}

static void
vmx_enable_x2apic_mode_vid(struct vlapic *vlapic)
{
	struct vmx *vmx;
	uint32_t proc_ctls2;
	int vcpuid;

	vcpuid = vlapic->vcpuid;
	vmx = ((struct vlapic_vtx *)vlapic)->vmx;

	proc_ctls2 = vmx->cap[vcpuid].proc_ctls2;
	KASSERT((proc_ctls2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES) != 0,
	    ("%s: invalid proc_ctls2 %x", __func__, proc_ctls2));

	proc_ctls2 &= ~PROCBASED2_VIRTUALIZE_APIC_ACCESSES;
	proc_ctls2 |= PROCBASED2_VIRTUALIZE_X2APIC_MODE;
	vmx->cap[vcpuid].proc_ctls2 = proc_ctls2;

	vmcs_load(vmx->vmcs_pa[vcpuid]);
	vmcs_write(VMCS_SEC_PROC_BASED_CTLS, proc_ctls2);
	vmcs_clear(vmx->vmcs_pa[vcpuid]);

	vmx_allow_x2apic_msrs(vmx, vcpuid);
}

static void
vmx_apicv_notify(struct vlapic *vlapic, int hostcpu)
{
	psm_send_pir_ipi(hostcpu);
}

static void
vmx_apicv_sync(struct vlapic *vlapic)
{
	struct vlapic_vtx *vlapic_vtx;
	struct pir_desc *pir_desc;
	struct LAPIC *lapic;
	uint_t i;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	pir_desc = vlapic_vtx->pir_desc;
	lapic = vlapic->apic_page;

	if (atomic_cmpset_long(&pir_desc->pending, 1, 0) == 0) {
		return;
	}

	vlapic_vtx->pending_prio = 0;

	/* Make sure the invalid (0-15) vectors are not set */
	ASSERT0(vlapic_vtx->pending_level[0] & 0xffff);
	ASSERT0(vlapic_vtx->pending_edge[0] & 0xffff);
	ASSERT0(pir_desc->pir[0] & 0xffff);

	for (i = 0; i <= 7; i++) {
		uint32_t *tmrp = &lapic->tmr0 + (i * 4);
		uint32_t *irrp = &lapic->irr0 + (i * 4);

		const uint32_t pending_level =
		    atomic_readandclear_int(&vlapic_vtx->pending_level[i]);
		const uint32_t pending_edge =
		    atomic_readandclear_int(&vlapic_vtx->pending_edge[i]);
		const uint32_t pending_inject =
		    atomic_readandclear_int(&pir_desc->pir[i]);

		if (pending_level != 0) {
			/*
			 * Level-triggered interrupts assert their corresponding
			 * bit in the TMR when queued in IRR.
			 */
			*tmrp |= pending_level;
			*irrp |= pending_level;
		}
		if (pending_edge != 0) {
			/*
			 * When queuing an edge-triggered interrupt in IRR, the
			 * corresponding bit in the TMR is cleared.
			 */
			*tmrp &= ~pending_edge;
			*irrp |= pending_edge;
		}
		if (pending_inject != 0) {
			/*
			 * Interrupts which do not require a change to the TMR
			 * (because it already matches the necessary state) can
			 * simply be queued in IRR.
			 */
			*irrp |= pending_inject;
		}

		if (*tmrp != vlapic_vtx->tmr_active[i]) {
			/* Check if VMX EOI triggers require updating. */
			vlapic_vtx->tmr_active[i] = *tmrp;
			vlapic_vtx->tmr_sync = B_TRUE;
		}
	}
}

static void
vmx_tpr_shadow_enter(struct vlapic *vlapic)
{
	/*
	 * When TPR shadowing is enabled, VMX will initiate a guest exit if its
	 * TPR falls below a threshold priority.  That threshold is set to the
	 * current TPR priority, since guest interrupt status should be
	 * re-evaluated if its TPR is set lower.
	 */
	vmcs_write(VMCS_TPR_THRESHOLD, vlapic_get_cr8(vlapic));
}

static void
vmx_tpr_shadow_exit(struct vlapic *vlapic)
{
	/*
	 * Unlike full APICv, where changes to the TPR are reflected in the PPR,
	 * with TPR shadowing, that duty is relegated to the VMM.  Upon exit,
	 * the PPR is updated to reflect any change in the TPR here.
	 */
	vlapic_sync_tpr(vlapic);
}

static struct vlapic *
vmx_vlapic_init(void *arg, int vcpuid)
{
	struct vmx *vmx = arg;
	struct vlapic_vtx *vlapic_vtx;
	struct vlapic *vlapic;

	vlapic_vtx = kmem_zalloc(sizeof (struct vlapic_vtx), KM_SLEEP);
	vlapic_vtx->pir_desc = &vmx->pir_desc[vcpuid];
	vlapic_vtx->vmx = vmx;

	vlapic = &vlapic_vtx->vlapic;
	vlapic->vm = vmx->vm;
	vlapic->vcpuid = vcpuid;
	vlapic->apic_page = (struct LAPIC *)&vmx->apic_page[vcpuid];

	if (vmx_cap_en(vmx, VMX_CAP_TPR_SHADOW)) {
		vlapic->ops.enable_x2apic_mode = vmx_enable_x2apic_mode_ts;
	}
	if (vmx_cap_en(vmx, VMX_CAP_APICV)) {
		vlapic->ops.set_intr_ready = vmx_apicv_set_ready;
		vlapic->ops.sync_state = vmx_apicv_sync;
		vlapic->ops.intr_accepted = vmx_apicv_accepted;
		vlapic->ops.enable_x2apic_mode = vmx_enable_x2apic_mode_vid;

		if (vmx_cap_en(vmx, VMX_CAP_APICV_PIR)) {
			vlapic->ops.post_intr = vmx_apicv_notify;
		}
	}

	vlapic_init(vlapic);

	return (vlapic);
}

static void
vmx_vlapic_cleanup(void *arg, struct vlapic *vlapic)
{
	vlapic_cleanup(vlapic);
	kmem_free(vlapic, sizeof (struct vlapic_vtx));
}

static void
vmx_pause(void *arg, int vcpuid)
{
	struct vmx *vmx = arg;

	VERIFY(vmx_vmcs_access_ensure(vmx, vcpuid));

	/* Stash any interrupt/exception pending injection. */
	vmx_stash_intinfo(vmx, vcpuid);

	/*
	 * Now that no event is pending injection, interrupt-window exiting and
	 * NMI-window exiting can be disabled.  If/when this vCPU is made to run
	 * again, those conditions will be reinstated when the now-queued events
	 * are re-injected.
	 */
	vmx_clear_nmi_window_exiting(vmx, vcpuid);
	vmx_clear_int_window_exiting(vmx, vcpuid);

	vmx_vmcs_access_done(vmx, vcpuid);
}

static void
vmx_savectx(void *arg, int vcpu)
{
	struct vmx *vmx = arg;

	if ((vmx->vmcs_state[vcpu] & VS_LOADED) != 0) {
		vmcs_clear(vmx->vmcs_pa[vcpu]);
		vmx_msr_guest_exit(vmx, vcpu);
		/*
		 * Having VMCLEARed the VMCS, it can no longer be re-entered
		 * with VMRESUME, but must be VMLAUNCHed again.
		 */
		vmx->vmcs_state[vcpu] &= ~VS_LAUNCHED;
	}

	reset_gdtr_limit();
}

static void
vmx_restorectx(void *arg, int vcpu)
{
	struct vmx *vmx = arg;

	ASSERT0(vmx->vmcs_state[vcpu] & VS_LAUNCHED);

	if ((vmx->vmcs_state[vcpu] & VS_LOADED) != 0) {
		vmx_msr_guest_enter(vmx, vcpu);
		vmcs_load(vmx->vmcs_pa[vcpu]);
	}
}

struct vmm_ops vmm_ops_intel = {
	.init		= vmx_init,
	.cleanup	= vmx_cleanup,
	.resume		= vmx_restore,

	.vminit		= vmx_vminit,
	.vmrun		= vmx_run,
	.vmcleanup	= vmx_vmcleanup,
	.vmgetreg	= vmx_getreg,
	.vmsetreg	= vmx_setreg,
	.vmgetdesc	= vmx_getdesc,
	.vmsetdesc	= vmx_setdesc,
	.vmgetcap	= vmx_getcap,
	.vmsetcap	= vmx_setcap,
	.vlapic_init	= vmx_vlapic_init,
	.vlapic_cleanup	= vmx_vlapic_cleanup,
	.vmpause	= vmx_pause,

	.vmsavectx	= vmx_savectx,
	.vmrestorectx	= vmx_restorectx,

	.vmgetmsr	= vmx_msr_get,
	.vmsetmsr	= vmx_msr_set,
};

/* Side-effect free HW validation derived from checks in vmx_init. */
int
vmx_x86_supported(const char **msg)
{
	int error;
	uint32_t tmp;

	ASSERT(msg != NULL);

	/* Check support for primary processor-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS,
	    MSR_VMX_TRUE_PROCBASED_CTLS, PROCBASED_CTLS_ONE_SETTING,
	    PROCBASED_CTLS_ZERO_SETTING, &tmp);
	if (error) {
		*msg = "processor does not support desired primary "
		    "processor-based controls";
		return (error);
	}

	/* Check support for secondary processor-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2,
	    MSR_VMX_PROCBASED_CTLS2, PROCBASED_CTLS2_ONE_SETTING,
	    PROCBASED_CTLS2_ZERO_SETTING, &tmp);
	if (error) {
		*msg = "processor does not support desired secondary "
		    "processor-based controls";
		return (error);
	}

	/* Check support for pin-based VM-execution controls */
	error = vmx_set_ctlreg(MSR_VMX_PINBASED_CTLS,
	    MSR_VMX_TRUE_PINBASED_CTLS, PINBASED_CTLS_ONE_SETTING,
	    PINBASED_CTLS_ZERO_SETTING, &tmp);
	if (error) {
		*msg = "processor does not support desired pin-based controls";
		return (error);
	}

	/* Check support for VM-exit controls */
	error = vmx_set_ctlreg(MSR_VMX_EXIT_CTLS, MSR_VMX_TRUE_EXIT_CTLS,
	    VM_EXIT_CTLS_ONE_SETTING, VM_EXIT_CTLS_ZERO_SETTING, &tmp);
	if (error) {
		*msg = "processor does not support desired exit controls";
		return (error);
	}

	/* Check support for VM-entry controls */
	error = vmx_set_ctlreg(MSR_VMX_ENTRY_CTLS, MSR_VMX_TRUE_ENTRY_CTLS,
	    VM_ENTRY_CTLS_ONE_SETTING, VM_ENTRY_CTLS_ZERO_SETTING, &tmp);
	if (error) {
		*msg = "processor does not support desired entry controls";
		return (error);
	}

	/* Unrestricted guest is nominally optional, but not for us. */
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2, MSR_VMX_PROCBASED_CTLS2,
	    PROCBASED2_UNRESTRICTED_GUEST, 0, &tmp);
	if (error) {
		*msg = "processor does not support desired unrestricted guest "
		    "controls";
		return (error);
	}

	return (0);
}
