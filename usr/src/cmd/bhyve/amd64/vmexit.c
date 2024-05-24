/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
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
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>

#ifndef __FreeBSD__
#include <sys/cpuset.h>
#include <intel/vmcs.h>
#endif

#include <machine/atomic.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <pthread_np.h>
#include <sysexits.h>
#include <stdbool.h>
#include <stdint.h>

#include <machine/vmm.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "gdb.h"
#include "inout.h"
#include "mem.h"
#include "spinup_ap.h"
#include "vmexit.h"
#include "xmsr.h"

#ifndef __FreeBSD__
static struct vm_entry *vmentry;

int
vmentry_init(int ncpus)
{
	vmentry = calloc(ncpus, sizeof(*vmentry));
	return (vmentry == NULL ? -1 : 0);
}

struct vm_entry *
vmentry_vcpu(int vcpuid)
{
	return (&vmentry[vcpuid]);
}

static void
vmentry_mmio_read(struct vcpu *vcpu, uint64_t gpa, uint8_t bytes, uint64_t data)
{
	struct vm_entry *entry = &vmentry[vcpu_id(vcpu)];
	struct vm_mmio *mmio = &entry->u.mmio;

	assert(entry->cmd == VEC_DEFAULT);

	entry->cmd = VEC_FULFILL_MMIO;
	mmio->bytes = bytes;
	mmio->read = 1;
	mmio->gpa = gpa;
	mmio->data = data;
}

static void
vmentry_mmio_write(struct vcpu *vcpu, uint64_t gpa, uint8_t bytes)
{
	struct vm_entry *entry = &vmentry[vcpu_id(vcpu)];
	struct vm_mmio *mmio = &entry->u.mmio;

	assert(entry->cmd == VEC_DEFAULT);

	entry->cmd = VEC_FULFILL_MMIO;
	mmio->bytes = bytes;
	mmio->read = 0;
	mmio->gpa = gpa;
	mmio->data = 0;
}

static void
vmentry_inout_read(struct vcpu *vcpu, uint16_t port, uint8_t bytes,
    uint32_t data)
{
	struct vm_entry *entry = &vmentry[vcpu_id(vcpu)];
	struct vm_inout *inout = &entry->u.inout;

	assert(entry->cmd == VEC_DEFAULT);

	entry->cmd = VEC_FULFILL_INOUT;
	inout->bytes = bytes;
	inout->flags = INOUT_IN;
	inout->port = port;
	inout->eax = data;
}

static void
vmentry_inout_write(struct vcpu *vcpu, uint16_t port, uint8_t bytes)
{
	struct vm_entry *entry = &vmentry[vcpu_id(vcpu)];
	struct vm_inout *inout = &entry->u.inout;

	assert(entry->cmd == VEC_DEFAULT);

	entry->cmd = VEC_FULFILL_INOUT;
	inout->bytes = bytes;
	inout->flags = 0;
	inout->port = port;
	inout->eax = 0;
}
#endif

#ifdef	__FreeBSD__
void
vm_inject_fault(struct vcpu *vcpu, int vector, int errcode_valid,
    int errcode)
{
	int error, restart_instruction;

	restart_instruction = 1;

	error = vm_inject_exception(vcpu, vector, errcode_valid, errcode,
	    restart_instruction);
	assert(error == 0);
}
#endif

static int
vmexit_inout(struct vmctx *ctx, struct vcpu *vcpu, struct vm_exit *vme)
{
	int error;
	struct vm_inout inout;
	bool in;
	uint8_t bytes;

	inout = vme->u.inout;
	in = (inout.flags & INOUT_IN) != 0;
	bytes = inout.bytes;

	error = emulate_inout(ctx, vcpu, &inout);
	if (error) {
		EPRINTLN("Unhandled %s%c 0x%04x at 0x%lx",
		    in ? "in" : "out",
		    bytes == 1 ? 'b' : (bytes == 2 ? 'w' : 'l'),
		    inout.port, vme->rip);
		return (VMEXIT_ABORT);
	} else {
		/*
		 * Communicate the status of the inout operation back to the
		 * in-kernel instruction emulation.
		 */
		if (in) {
			vmentry_inout_read(vcpu, inout.port, bytes, inout.eax);
		} else {
			vmentry_inout_write(vcpu, inout.port, bytes);
		}
		return (VMEXIT_CONTINUE);
	}
}

static int
vmexit_rdmsr(struct vmctx *ctx __unused, struct vcpu *vcpu, struct vm_exit *vme)
{
	uint64_t val;
	uint32_t eax, edx;
	int error;

	val = 0;
	error = emulate_rdmsr(vcpu, vme->u.msr.code, &val);
	if (error != 0) {
		EPRINTLN("rdmsr to register %#x on vcpu %d",
		    vme->u.msr.code, vcpu_id(vcpu));
		if (get_config_bool("x86.strictmsr")) {
			vm_inject_gp(vcpu);
			return (VMEXIT_CONTINUE);
		}
	}

	eax = val;
	error = vm_set_register(vcpu, VM_REG_GUEST_RAX, eax);
	assert(error == 0);

	edx = val >> 32;
	error = vm_set_register(vcpu, VM_REG_GUEST_RDX, edx);
	assert(error == 0);

	return (VMEXIT_CONTINUE);
}

static int
vmexit_wrmsr(struct vmctx *ctx __unused, struct vcpu *vcpu, struct vm_exit *vme)
{
	int error;

	error = emulate_wrmsr(vcpu, vme->u.msr.code, vme->u.msr.wval);
	if (error != 0) {
		EPRINTLN("wrmsr to register %#x(%#lx) on vcpu %d",
		    vme->u.msr.code, vme->u.msr.wval, vcpu_id(vcpu));
		if (get_config_bool("x86.strictmsr")) {
			vm_inject_gp(vcpu);
			return (VMEXIT_CONTINUE);
		}
	}
	return (VMEXIT_CONTINUE);
}

static const char * const vmx_exit_reason_desc[] = {
	[EXIT_REASON_EXCEPTION] = "Exception or non-maskable interrupt (NMI)",
	[EXIT_REASON_EXT_INTR] = "External interrupt",
	[EXIT_REASON_TRIPLE_FAULT] = "Triple fault",
	[EXIT_REASON_INIT] = "INIT signal",
	[EXIT_REASON_SIPI] = "Start-up IPI (SIPI)",
	[EXIT_REASON_IO_SMI] = "I/O system-management interrupt (SMI)",
	[EXIT_REASON_SMI] = "Other SMI",
	[EXIT_REASON_INTR_WINDOW] = "Interrupt window",
	[EXIT_REASON_NMI_WINDOW] = "NMI window",
	[EXIT_REASON_TASK_SWITCH] = "Task switch",
	[EXIT_REASON_CPUID] = "CPUID",
	[EXIT_REASON_GETSEC] = "GETSEC",
	[EXIT_REASON_HLT] = "HLT",
	[EXIT_REASON_INVD] = "INVD",
	[EXIT_REASON_INVLPG] = "INVLPG",
	[EXIT_REASON_RDPMC] = "RDPMC",
	[EXIT_REASON_RDTSC] = "RDTSC",
	[EXIT_REASON_RSM] = "RSM",
	[EXIT_REASON_VMCALL] = "VMCALL",
	[EXIT_REASON_VMCLEAR] = "VMCLEAR",
	[EXIT_REASON_VMLAUNCH] = "VMLAUNCH",
	[EXIT_REASON_VMPTRLD] = "VMPTRLD",
	[EXIT_REASON_VMPTRST] = "VMPTRST",
	[EXIT_REASON_VMREAD] = "VMREAD",
	[EXIT_REASON_VMRESUME] = "VMRESUME",
	[EXIT_REASON_VMWRITE] = "VMWRITE",
	[EXIT_REASON_VMXOFF] = "VMXOFF",
	[EXIT_REASON_VMXON] = "VMXON",
	[EXIT_REASON_CR_ACCESS] = "Control-register accesses",
	[EXIT_REASON_DR_ACCESS] = "MOV DR",
	[EXIT_REASON_INOUT] = "I/O instruction",
	[EXIT_REASON_RDMSR] = "RDMSR",
	[EXIT_REASON_WRMSR] = "WRMSR",
	[EXIT_REASON_INVAL_VMCS] =
	    "VM-entry failure due to invalid guest state",
	[EXIT_REASON_INVAL_MSR] = "VM-entry failure due to MSR loading",
	[EXIT_REASON_MWAIT] = "MWAIT",
	[EXIT_REASON_MTF] = "Monitor trap flag",
	[EXIT_REASON_MONITOR] = "MONITOR",
	[EXIT_REASON_PAUSE] = "PAUSE",
	[EXIT_REASON_MCE_DURING_ENTRY] =
	    "VM-entry failure due to machine-check event",
	[EXIT_REASON_TPR] = "TPR below threshold",
	[EXIT_REASON_APIC_ACCESS] = "APIC access",
	[EXIT_REASON_VIRTUALIZED_EOI] = "Virtualized EOI",
	[EXIT_REASON_GDTR_IDTR] = "Access to GDTR or IDTR",
	[EXIT_REASON_LDTR_TR] = "Access to LDTR or TR",
	[EXIT_REASON_EPT_FAULT] = "EPT violation",
	[EXIT_REASON_EPT_MISCONFIG] = "EPT misconfiguration",
	[EXIT_REASON_INVEPT] = "INVEPT",
	[EXIT_REASON_RDTSCP] = "RDTSCP",
	[EXIT_REASON_VMX_PREEMPT] = "VMX-preemption timer expired",
	[EXIT_REASON_INVVPID] = "INVVPID",
	[EXIT_REASON_WBINVD] = "WBINVD",
	[EXIT_REASON_XSETBV] = "XSETBV",
	[EXIT_REASON_APIC_WRITE] = "APIC write",
	[EXIT_REASON_RDRAND] = "RDRAND",
	[EXIT_REASON_INVPCID] = "INVPCID",
	[EXIT_REASON_VMFUNC] = "VMFUNC",
	[EXIT_REASON_ENCLS] = "ENCLS",
	[EXIT_REASON_RDSEED] = "RDSEED",
	[EXIT_REASON_PM_LOG_FULL] = "Page-modification log full",
	[EXIT_REASON_XSAVES] = "XSAVES",
	[EXIT_REASON_XRSTORS] = "XRSTORS"
};

#ifndef __FreeBSD__
static int
vmexit_run_state(struct vmctx *ctx __unused, struct vcpu *vcpu __unused,
    struct vm_exit *vme __unused)
{
	/*
	 * Run-state transitions (INIT, SIPI, etc) are handled in-kernel, so an
	 * exit to userspace with that code is not expected.
	 */
	fprintf(stderr, "unexpected run-state VM exit");
	return (VMEXIT_ABORT);
}

static int
vmexit_paging(struct vmctx *ctx __unused, struct vcpu *vcpu,
    struct vm_exit *vme)
{
	fprintf(stderr, "vm exit[%d]\n", vcpu_id(vcpu));
	fprintf(stderr, "\treason\t\tPAGING\n");
	fprintf(stderr, "\trip\t\t0x%016lx\n", vme->rip);
	fprintf(stderr, "\tgpa\t\t0x%016lx\n", vme->u.paging.gpa);
	fprintf(stderr, "\tfault_type\t\t%d\n", vme->u.paging.fault_type);

	return (VMEXIT_ABORT);
}
#endif /* __FreeBSD__ */

#ifdef __FreeBSD__
#define	DEBUG_EPT_MISCONFIG
#else
/* EPT misconfig debugging not possible now that raw VMCS access is gone */
#endif

#ifdef DEBUG_EPT_MISCONFIG
#define	VMCS_GUEST_PHYSICAL_ADDRESS	0x00002400

static uint64_t ept_misconfig_gpa, ept_misconfig_pte[4];
static int ept_misconfig_ptenum;
#endif

static const char *
vmexit_vmx_desc(uint32_t exit_reason)
{

	if (exit_reason >= nitems(vmx_exit_reason_desc) ||
	    vmx_exit_reason_desc[exit_reason] == NULL)
		return ("Unknown");
	return (vmx_exit_reason_desc[exit_reason]);
}

static int
vmexit_vmx(struct vmctx *ctx, struct vcpu *vcpu, struct vm_exit *vme)
{

	EPRINTLN("vm exit[%d]", vcpu_id(vcpu));
	EPRINTLN("\treason\t\tVMX");
	EPRINTLN("\trip\t\t0x%016lx", vme->rip);
	EPRINTLN("\tinst_length\t%d", vme->inst_length);
	EPRINTLN("\tstatus\t\t%d", vme->u.vmx.status);
	EPRINTLN("\texit_reason\t%u (%s)", vme->u.vmx.exit_reason,
	    vmexit_vmx_desc(vme->u.vmx.exit_reason));
	EPRINTLN("\tqualification\t0x%016lx",
	    vme->u.vmx.exit_qualification);
	EPRINTLN("\tinst_type\t\t%d", vme->u.vmx.inst_type);
	EPRINTLN("\tinst_error\t\t%d", vme->u.vmx.inst_error);
#ifdef DEBUG_EPT_MISCONFIG
	if (vme->u.vmx.exit_reason == EXIT_REASON_EPT_MISCONFIG) {
		vm_get_register(vcpu,
		    VMCS_IDENT(VMCS_GUEST_PHYSICAL_ADDRESS),
		    &ept_misconfig_gpa);
		vm_get_gpa_pmap(ctx, ept_misconfig_gpa, ept_misconfig_pte,
		    &ept_misconfig_ptenum);
		EPRINTLN("\tEPT misconfiguration:");
		EPRINTLN("\t\tGPA: %#lx", ept_misconfig_gpa);
		EPRINTLN("\t\tPTE(%d): %#lx %#lx %#lx %#lx",
		    ept_misconfig_ptenum, ept_misconfig_pte[0],
		    ept_misconfig_pte[1], ept_misconfig_pte[2],
		    ept_misconfig_pte[3]);
	}
#endif	/* DEBUG_EPT_MISCONFIG */
	return (VMEXIT_ABORT);
}

static int
vmexit_svm(struct vmctx *ctx __unused, struct vcpu *vcpu, struct vm_exit *vme)
{
	EPRINTLN("vm exit[%d]", vcpu_id(vcpu));
	EPRINTLN("\treason\t\tSVM");
	EPRINTLN("\trip\t\t0x%016lx", vme->rip);
	EPRINTLN("\tinst_length\t%d", vme->inst_length);
	EPRINTLN("\texitcode\t%#lx", vme->u.svm.exitcode);
	EPRINTLN("\texitinfo1\t%#lx", vme->u.svm.exitinfo1);
	EPRINTLN("\texitinfo2\t%#lx", vme->u.svm.exitinfo2);
	return (VMEXIT_ABORT);
}

static int
vmexit_bogus(struct vmctx *ctx __unused, struct vcpu *vcpu __unused,
    struct vm_exit *vme)
{

	assert(vme->inst_length == 0);

	return (VMEXIT_CONTINUE);
}

static int
vmexit_hlt(struct vmctx *ctx __unused, struct vcpu *vcpu __unused,
    struct vm_exit *vme __unused)
{

	/*
	 * Just continue execution with the next instruction. We use
	 * the HLT VM exit as a way to be friendly with the host
	 * scheduler.
	 */
	return (VMEXIT_CONTINUE);
}

static int
vmexit_pause(struct vmctx *ctx __unused, struct vcpu *vcpu __unused,
    struct vm_exit *vme __unused)
{
	return (VMEXIT_CONTINUE);
}

static int
vmexit_mtrap(struct vmctx *ctx __unused, struct vcpu *vcpu, struct vm_exit *vme)
{

	assert(vme->inst_length == 0);

	gdb_cpu_mtrap(vcpu);

	return (VMEXIT_CONTINUE);
}

static int
vmexit_inst_emul(struct vmctx *ctx __unused, struct vcpu *vcpu,
    struct vm_exit *vme)
{
	uint8_t i, valid;

	fprintf(stderr, "Failed to emulate instruction sequence ");

	valid = vme->u.inst_emul.num_valid;
	if (valid != 0) {
		assert(valid <= sizeof (vme->u.inst_emul.inst));
		fprintf(stderr, "[");
		for (i = 0; i < valid; i++) {
			if (i == 0) {
				fprintf(stderr, "%02x",
				    vme->u.inst_emul.inst[i]);
			} else {
				fprintf(stderr, ", %02x",
				    vme->u.inst_emul.inst[i]);
			}
		}
		fprintf(stderr, "] ");
	}
	fprintf(stderr, "@ %rip = %x\n", vme->rip);

	return (VMEXIT_ABORT);
}

#ifndef	__FreeBSD__
static int
vmexit_mmio(struct vmctx *ctx __unused, struct vcpu *vcpu, struct vm_exit *vme)
{
	int err;
	struct vm_mmio mmio;
	bool is_read;

	mmio = vme->u.mmio;
	is_read = (mmio.read != 0);

	err = emulate_mem(vcpu, &mmio);

	if (err == ESRCH) {
		fprintf(stderr, "Unhandled memory access to 0x%lx\n", mmio.gpa);

		/*
		 * Access to non-existent physical addresses is not likely to
		 * result in fatal errors on hardware machines, but rather reads
		 * of all-ones or discarded-but-acknowledged writes.
		 */
		mmio.data = ~0UL;
		err = 0;
	}

	if (err == 0) {
		if (is_read) {
			vmentry_mmio_read(vcpu, mmio.gpa, mmio.bytes,
			    mmio.data);
		} else {
			vmentry_mmio_write(vcpu, mmio.gpa, mmio.bytes);
		}
		return (VMEXIT_CONTINUE);
	}

	fprintf(stderr, "Unhandled mmio error to 0x%lx: %d\n", mmio.gpa, err);
	return (VMEXIT_ABORT);
}
#endif /* !__FreeBSD__ */

static int
vmexit_suspend(struct vmctx *ctx, struct vcpu *vcpu, struct vm_exit *vme)
{
	enum vm_suspend_how how;
	int vcpuid = vcpu_id(vcpu);

	how = vme->u.suspended.how;

	fbsdrun_deletecpu(vcpuid);

	switch (how) {
	case VM_SUSPEND_RESET:
		exit(0);
	case VM_SUSPEND_POWEROFF:
		if (get_config_bool_default("destroy_on_poweroff", false))
			vm_destroy(ctx);
		exit(1);
	case VM_SUSPEND_HALT:
		exit(2);
	case VM_SUSPEND_TRIPLEFAULT:
		exit(3);
	default:
		EPRINTLN("vmexit_suspend: invalid reason %d", how);
		exit(100);
	}
	return (0);	/* NOTREACHED */
}

static int
vmexit_debug(struct vmctx *ctx __unused, struct vcpu *vcpu,
    struct vm_exit *vme __unused)
{
	gdb_cpu_suspend(vcpu);
	/*
	 * Sleep for a short period to avoid chewing up the CPU in the
	 * window between activation of the vCPU thread and the STARTUP IPI.
	 */
	usleep(1000);
	return (VMEXIT_CONTINUE);
}

static int
vmexit_breakpoint(struct vmctx *ctx __unused, struct vcpu *vcpu,
    struct vm_exit *vme)
{

	gdb_cpu_breakpoint(vcpu, vme);
	return (VMEXIT_CONTINUE);
}

#ifdef	__FreeBSD__
static int
vmexit_ipi(struct vmctx *ctx __unused, struct vcpu *vcpu __unused,
    struct vm_exit *vme)
{
	int error = -1;
	int i;
	switch (vme->u.ipi.mode) {
	case APIC_DELMODE_INIT:
		CPU_FOREACH_ISSET(i, &vme->u.ipi.dmask) {
			error = vm_suspend_cpu(vcpu_info[i].vcpu);
			if (error) {
				warnx("%s: failed to suspend cpu %d\n",
				    __func__, i);
				break;
			}
		}
		break;
	case APIC_DELMODE_STARTUP:
		CPU_FOREACH_ISSET(i, &vme->u.ipi.dmask) {
			spinup_ap(vcpu_info[i].vcpu,
			    vme->u.ipi.vector << PAGE_SHIFT);
		}
		error = 0;
		break;
	default:
		break;
	}

	return (error);
}
#endif

const vmexit_handler_t vmexit_handlers[VM_EXITCODE_MAX] = {
	[VM_EXITCODE_INOUT]  = vmexit_inout,
#ifndef __FreeBSD__
	[VM_EXITCODE_MMIO]  = vmexit_mmio,
#endif
	[VM_EXITCODE_VMX]    = vmexit_vmx,
	[VM_EXITCODE_SVM]    = vmexit_svm,
	[VM_EXITCODE_BOGUS]  = vmexit_bogus,
	[VM_EXITCODE_RDMSR]  = vmexit_rdmsr,
	[VM_EXITCODE_WRMSR]  = vmexit_wrmsr,
	[VM_EXITCODE_MTRAP]  = vmexit_mtrap,
	[VM_EXITCODE_INST_EMUL] = vmexit_inst_emul,
#ifndef __FreeBSD__
	[VM_EXITCODE_RUN_STATE] = vmexit_run_state,
	[VM_EXITCODE_PAGING] = vmexit_paging,
#endif
	[VM_EXITCODE_SUSPENDED] = vmexit_suspend,
	[VM_EXITCODE_TASK_SWITCH] = vmexit_task_switch,
	[VM_EXITCODE_DEBUG] = vmexit_debug,
	[VM_EXITCODE_BPT] = vmexit_breakpoint,
#ifdef	__FreeBSD__
	[VM_EXITCODE_IPI] = vmexit_ipi,
#endif
	[VM_EXITCODE_HLT] = vmexit_hlt,
	[VM_EXITCODE_PAUSE] = vmexit_pause,
};
