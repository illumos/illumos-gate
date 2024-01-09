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

#include <sys/cdefs.h>

#include <sys/types.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/mman.h>
#include <sys/time.h>

#ifdef __FreeBSD__
#include <amd64/vmm/intel/vmcs.h>
#else
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
#ifndef WITHOUT_CAPSICUM
#include <machine/vmm_dev.h>
#endif
#ifdef	__FreeBSD__
#include <machine/vmm_instruction_emul.h>
#endif
#include <vmmapi.h>

#ifndef __FreeBSD__
#include <sys/stat.h>
#endif

#include "bhyverun.h"
#include "acpi.h"
#include "atkbdc.h"
#include "bootrom.h"
#include "config.h"
#include "inout.h"
#include "debug.h"
#include "e820.h"
#include "fwctl.h"
#include "gdb.h"
#include "ioapic.h"
#include "kernemu_dev.h"
#include "mem.h"
#include "mevent.h"
#include "mptbl.h"
#include "pci_emul.h"
#include "pci_irq.h"
#include "pci_lpc.h"
#include "qemu_fwcfg.h"
#include "smbiostbl.h"
#include "tpm_device.h"
#include "xmsr.h"
#include "spinup_ap.h"
#include "rtc.h"
#include "vmgenc.h"
#ifndef __FreeBSD__
#include "privileges.h"
#endif

#define MB		(1024UL * 1024)
#define GB		(1024UL * MB)

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

typedef int (*vmexit_handler_t)(struct vmctx *, struct vcpu *, struct vm_exit *);

int guest_ncpus;
uint16_t cpu_cores, cpu_sockets, cpu_threads;

int raw_stdio = 0;

static char *progname;
static const int BSP = 0;

static cpuset_t cpumask;

static void vm_loop(struct vmctx *ctx, struct vcpu *vcpu);

#ifndef __FreeBSD__
static struct vm_entry *vmentry;
#endif

static struct vcpu_info {
	struct vmctx    *ctx;
	struct vcpu     *vcpu;
	int             vcpuid;
} *vcpu_info;

#ifdef	__FreeBSD__
static cpuset_t **vcpumap;
#endif

static void
usage(int code)
{

	fprintf(stderr,
#ifdef	__FreeBSD__
		"Usage: %s [-AaCDeHhPSuWwxY]\n"
#else
		"Usage: %s [-aCDdeHhPSuWwxY]\n"
#endif
		"       %*s [-c [[cpus=]numcpus][,sockets=n][,cores=n][,threads=n]]\n"
#ifdef	__FreeBSD__
		"       %*s [-G port] [-k config_file] [-l lpc] [-m mem] [-o var=value]\n"
		"       %*s [-p vcpu:hostcpu] [-r file] [-s pci] [-U uuid] vmname\n"

		"       -A: create ACPI tables\n"
#else
		"       %*s [-k <config_file>] [-l <lpc>] [-m mem] [-o <var>=<value>]\n"
		"       %*s [-s <pci>] [-U uuid] vmname\n"
#endif
		"       -a: local apic is in xAPIC mode (deprecated)\n"
#ifndef __FreeBSD__
		"       -B type,key=value,...: set SMBIOS information\n"
#endif
		"       -C: include guest memory in core file\n"
		"       -c: number of CPUs and/or topology specification\n"
		"       -D: destroy on power-off\n"
#ifndef __FreeBSD__
		"       -d: suspend cpu at boot\n"
#endif
		"       -e: exit on unhandled I/O access\n"
#ifdef	__FreeBSD__
		"       -G: start a debug server\n"
#endif
		"       -H: vmexit from the guest on HLT\n"
		"       -h: help\n"
		"       -k: key=value flat config file\n"
		"       -K: PS2 keyboard layout\n"
		"       -l: LPC device configuration\n"
		"       -m: memory size\n"
		"       -o: set config 'var' to 'value'\n"
		"       -P: vmexit from the guest on pause\n"
#ifdef	__FreeBSD__
		"       -p: pin 'vcpu' to 'hostcpu'\n"
#endif
		"       -S: guest memory cannot be swapped\n"
		"       -s: <slot,driver,configinfo> PCI slot config\n"
		"       -U: UUID\n"
		"       -u: RTC keeps UTC time\n"
		"       -W: force virtio to use single-vector MSI\n"
		"       -w: ignore unimplemented MSRs\n"
		"       -x: local APIC is in x2APIC mode\n"
		"       -Y: disable MPtable generation\n",
		progname, (int)strlen(progname), "", (int)strlen(progname), "",
		(int)strlen(progname), "");

	exit(code);
}

/*
 * XXX This parser is known to have the following issues:
 * 1.  It accepts null key=value tokens ",," as setting "cpus" to an
 *     empty string.
 *
 * The acceptance of a null specification ('-c ""') is by design to match the
 * manual page syntax specification, this results in a topology of 1 vCPU.
 */
static int
topology_parse(const char *opt)
{
	char *cp, *str, *tofree;

	if (*opt == '\0') {
		set_config_value("sockets", "1");
		set_config_value("cores", "1");
		set_config_value("threads", "1");
		set_config_value("cpus", "1");
		return (0);
	}

	tofree = str = strdup(opt);
	if (str == NULL)
		errx(4, "Failed to allocate memory");

	while ((cp = strsep(&str, ",")) != NULL) {
		if (strncmp(cp, "cpus=", strlen("cpus=")) == 0)
			set_config_value("cpus", cp + strlen("cpus="));
		else if (strncmp(cp, "sockets=", strlen("sockets=")) == 0)
			set_config_value("sockets", cp + strlen("sockets="));
		else if (strncmp(cp, "cores=", strlen("cores=")) == 0)
			set_config_value("cores", cp + strlen("cores="));
		else if (strncmp(cp, "threads=", strlen("threads=")) == 0)
			set_config_value("threads", cp + strlen("threads="));
		else if (strchr(cp, '=') != NULL)
			goto out;
		else
			set_config_value("cpus", cp);
	}
	free(tofree);
	return (0);

out:
	free(tofree);
	return (-1);
}

static int
parse_int_value(const char *key, const char *value, int minval, int maxval)
{
	char *cp;
	long lval;

	errno = 0;
	lval = strtol(value, &cp, 0);
	if (errno != 0 || *cp != '\0' || cp == value || lval < minval ||
	    lval > maxval)
		errx(4, "Invalid value for %s: '%s'", key, value);
	return (lval);
}

/*
 * Set the sockets, cores, threads, and guest_cpus variables based on
 * the configured topology.
 *
 * The limits of UINT16_MAX are due to the types passed to
 * vm_set_topology().  vmm.ko may enforce tighter limits.
 */
static void
calc_topology(void)
{
	const char *value;
	bool explicit_cpus;
	uint64_t ncpus;

	value = get_config_value("cpus");
	if (value != NULL) {
		guest_ncpus = parse_int_value("cpus", value, 1, UINT16_MAX);
		explicit_cpus = true;
	} else {
		guest_ncpus = 1;
		explicit_cpus = false;
	}
	value = get_config_value("cores");
	if (value != NULL)
		cpu_cores = parse_int_value("cores", value, 1, UINT16_MAX);
	else
		cpu_cores = 1;
	value = get_config_value("threads");
	if (value != NULL)
		cpu_threads = parse_int_value("threads", value, 1, UINT16_MAX);
	else
		cpu_threads = 1;
	value = get_config_value("sockets");
	if (value != NULL)
		cpu_sockets = parse_int_value("sockets", value, 1, UINT16_MAX);
	else
		cpu_sockets = guest_ncpus;

	/*
	 * Compute sockets * cores * threads avoiding overflow.  The
	 * range check above insures these are 16 bit values.
	 */
	ncpus = (uint64_t)cpu_sockets * cpu_cores * cpu_threads;
	if (ncpus > UINT16_MAX)
		errx(4, "Computed number of vCPUs too high: %ju",
		    (uintmax_t)ncpus);

	if (explicit_cpus) {
		if (guest_ncpus != (int)ncpus)
			errx(4, "Topology (%d sockets, %d cores, %d threads) "
			    "does not match %d vCPUs",
			    cpu_sockets, cpu_cores, cpu_threads,
			    guest_ncpus);
	} else
		guest_ncpus = ncpus;
}

#ifdef	__FreeBSD__
static int
pincpu_parse(const char *opt)
{
	int vcpu, pcpu;
	const char *value;
	char *newval;
	char key[16];

	if (sscanf(opt, "%d:%d", &vcpu, &pcpu) != 2) {
		fprintf(stderr, "invalid format: %s\n", opt);
		return (-1);
	}

	if (vcpu < 0) {
		fprintf(stderr, "invalid vcpu '%d'\n", vcpu);
		return (-1);
	}

	if (pcpu < 0 || pcpu >= CPU_SETSIZE) {
		fprintf(stderr, "hostcpu '%d' outside valid range from "
		    "0 to %d\n", pcpu, CPU_SETSIZE - 1);
		return (-1);
	}

	snprintf(key, sizeof(key), "vcpu.%d.cpuset", vcpu);
	value = get_config_value(key);

	if (asprintf(&newval, "%s%s%d", value != NULL ? value : "",
	    value != NULL ? "," : "", pcpu) == -1) {
		perror("failed to build new cpuset string");
		return (-1);
	}

	set_config_value(key, newval);
	free(newval);
	return (0);
}

static void
parse_cpuset(int vcpu, const char *list, cpuset_t *set)
{
	char *cp, *token;
	int pcpu, start;

	CPU_ZERO(set);
	start = -1;
	token = __DECONST(char *, list);
	for (;;) {
		pcpu = strtoul(token, &cp, 0);
		if (cp == token)
			errx(4, "invalid cpuset for vcpu %d: '%s'", vcpu, list);
		if (pcpu < 0 || pcpu >= CPU_SETSIZE)
			errx(4, "hostcpu '%d' outside valid range from 0 to %d",
			    pcpu, CPU_SETSIZE - 1);
		switch (*cp) {
		case ',':
		case '\0':
			if (start >= 0) {
				if (start > pcpu)
					errx(4, "Invalid hostcpu range %d-%d",
					    start, pcpu);
				while (start < pcpu) {
					CPU_SET(start, set);
					start++;
				}
				start = -1;
			}
			CPU_SET(pcpu, set);
			break;
		case '-':
			if (start >= 0)
				errx(4, "invalid cpuset for vcpu %d: '%s'",
				    vcpu, list);
			start = pcpu;
			break;
		default:
			errx(4, "invalid cpuset for vcpu %d: '%s'", vcpu, list);
		}
		if (*cp == '\0')
			break;
		token = cp + 1;
	}
}

static void
build_vcpumaps(void)
{
	char key[16];
	const char *value;
	int vcpu;

	vcpumap = calloc(guest_ncpus, sizeof(*vcpumap));
	for (vcpu = 0; vcpu < guest_ncpus; vcpu++) {
		snprintf(key, sizeof(key), "vcpu.%d.cpuset", vcpu);
		value = get_config_value(key);
		if (value == NULL)
			continue;
		vcpumap[vcpu] = malloc(sizeof(cpuset_t));
		if (vcpumap[vcpu] == NULL)
			err(4, "Failed to allocate cpuset for vcpu %d", vcpu);
		parse_cpuset(vcpu, value, vcpumap[vcpu]);
	}
}

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
#endif /* __FreeBSD__ */

void *
paddr_guest2host(struct vmctx *ctx, uintptr_t gaddr, size_t len)
{

	return (vm_map_gpa(ctx, gaddr, len));
}

int
fbsdrun_virtio_msix(void)
{

	return (get_config_bool_default("virtio_msix", true));
}

static void *
fbsdrun_start_thread(void *param)
{
	char tname[MAXCOMLEN + 1];
	struct vcpu_info *vi = param;
#ifdef	__FreeBSD__
	int error;
#endif

	snprintf(tname, sizeof(tname), "vcpu %d", vi->vcpuid);
	pthread_set_name_np(pthread_self(), tname);

#ifdef	__FreeBSD__
	if (vcpumap[vi->vcpuid] != NULL) {
		error = pthread_setaffinity_np(pthread_self(),
		    sizeof(cpuset_t), vcpumap[vi->vcpuid]);
		assert(error == 0);
	}
#endif

	gdb_cpu_add(vi->vcpu);

	vm_loop(vi->ctx, vi->vcpu);

	/* not reached */
	exit(1);
	return (NULL);
}

void
fbsdrun_addcpu(struct vcpu_info *vi, bool suspend)
{
	pthread_t thr;
	int error;

	error = vm_activate_cpu(vi->vcpu);
	if (error != 0)
		err(EX_OSERR, "could not activate CPU %d", vi->vcpuid);

	CPU_SET_ATOMIC(vi->vcpuid, &cpumask);

	if (suspend)
		(void) vm_suspend_cpu(vi->vcpu);

	error = pthread_create(&thr, NULL, fbsdrun_start_thread, vi);
	assert(error == 0);
}

static void
fbsdrun_deletecpu(int vcpu)
{
	static pthread_mutex_t resetcpu_mtx = PTHREAD_MUTEX_INITIALIZER;
	static pthread_cond_t resetcpu_cond = PTHREAD_COND_INITIALIZER;

	pthread_mutex_lock(&resetcpu_mtx);
	if (!CPU_ISSET(vcpu, &cpumask)) {
		fprintf(stderr, "Attempting to delete unknown cpu %d\n", vcpu);
		exit(4);
	}

	CPU_CLR(vcpu, &cpumask);

	if (vcpu != BSP) {
		pthread_cond_signal(&resetcpu_cond);
		pthread_mutex_unlock(&resetcpu_mtx);
		pthread_exit(NULL);
		/* NOTREACHED */
	}

	while (!CPU_EMPTY(&cpumask)) {
		pthread_cond_wait(&resetcpu_cond, &resetcpu_mtx);
	}
	pthread_mutex_unlock(&resetcpu_mtx);
}

#ifndef	__FreeBSD__
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
		fprintf(stderr, "Unhandled %s%c 0x%04x at 0x%lx\n",
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
		fprintf(stderr, "rdmsr to register %#x on vcpu %d\n",
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
		fprintf(stderr, "wrmsr to register %#x(%#lx) on vcpu %d\n",
		    vme->u.msr.code, vme->u.msr.wval, vcpu_id(vcpu));
		if (get_config_bool("x86.strictmsr")) {
			vm_inject_gp(vcpu);
			return (VMEXIT_CONTINUE);
		}
	}
	return (VMEXIT_CONTINUE);
}

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

	fprintf(stderr, "vm exit[%d]\n", vcpu_id(vcpu));
	fprintf(stderr, "\treason\t\tVMX\n");
	fprintf(stderr, "\trip\t\t0x%016lx\n", vme->rip);
	fprintf(stderr, "\tinst_length\t%d\n", vme->inst_length);
	fprintf(stderr, "\tstatus\t\t%d\n", vme->u.vmx.status);
	fprintf(stderr, "\texit_reason\t%u (%s)\n", vme->u.vmx.exit_reason,
	    vmexit_vmx_desc(vme->u.vmx.exit_reason));
	fprintf(stderr, "\tqualification\t0x%016lx\n",
	    vme->u.vmx.exit_qualification);
	fprintf(stderr, "\tinst_type\t\t%d\n", vme->u.vmx.inst_type);
	fprintf(stderr, "\tinst_error\t\t%d\n", vme->u.vmx.inst_error);
#ifdef DEBUG_EPT_MISCONFIG
	if (vme->u.vmx.exit_reason == EXIT_REASON_EPT_MISCONFIG) {
		vm_get_register(vcpu,
		    VMCS_IDENT(VMCS_GUEST_PHYSICAL_ADDRESS),
		    &ept_misconfig_gpa);
		vm_get_gpa_pmap(ctx, ept_misconfig_gpa, ept_misconfig_pte,
		    &ept_misconfig_ptenum);
		fprintf(stderr, "\tEPT misconfiguration:\n");
		fprintf(stderr, "\t\tGPA: %#lx\n", ept_misconfig_gpa);
		fprintf(stderr, "\t\tPTE(%d): %#lx %#lx %#lx %#lx\n",
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

	fprintf(stderr, "vm exit[%d]\n", vcpu_id(vcpu));
	fprintf(stderr, "\treason\t\tSVM\n");
	fprintf(stderr, "\trip\t\t0x%016lx\n", vme->rip);
	fprintf(stderr, "\tinst_length\t%d\n", vme->inst_length);
	fprintf(stderr, "\texitcode\t%#lx\n", vme->u.svm.exitcode);
	fprintf(stderr, "\texitinfo1\t%#lx\n", vme->u.svm.exitinfo1);
	fprintf(stderr, "\texitinfo2\t%#lx\n", vme->u.svm.exitinfo2);
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
		fprintf(stderr, "vmexit_suspend: invalid reason %d\n", how);
		exit(100);
	}
	return (0);	/* NOTREACHED */
}

static int
vmexit_debug(struct vmctx *ctx __unused, struct vcpu *vcpu,
    struct vm_exit *vme __unused)
{

	gdb_cpu_suspend(vcpu);
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

static const vmexit_handler_t handler[VM_EXITCODE_MAX] = {
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

static void
vm_loop(struct vmctx *ctx, struct vcpu *vcpu)
{
	struct vm_exit vme;
	int error, rc;
	enum vm_exitcode exitcode;
	cpuset_t active_cpus;
	struct vm_entry *ventry;

	error = vm_active_cpus(ctx, &active_cpus);
	assert(CPU_ISSET(vcpu_id(vcpu), &active_cpus));

	ventry = &vmentry[vcpu_id(vcpu)];

	while (1) {
		error = vm_run(vcpu, ventry, &vme);
		if (error != 0)
			break;

		if (ventry->cmd != VEC_DEFAULT) {
			/*
			 * Discard any lingering entry state after it has been
			 * submitted via vm_run().
			 */
			bzero(ventry, sizeof (*ventry));
		}

		exitcode = vme.exitcode;
		if (exitcode >= VM_EXITCODE_MAX || handler[exitcode] == NULL) {
			fprintf(stderr, "vm_loop: unexpected exitcode 0x%x\n",
			    exitcode);
			exit(4);
		}

		rc = (*handler[exitcode])(ctx, vcpu, &vme);

		switch (rc) {
		case VMEXIT_CONTINUE:
			break;
		case VMEXIT_ABORT:
			abort();
		default:
			exit(4);
		}
	}
	fprintf(stderr, "vm_run error %d, errno %d\n", error, errno);
}

static int
num_vcpus_allowed(struct vmctx *ctx, struct vcpu *vcpu)
{
	uint16_t sockets, cores, threads, maxcpus;
#ifdef __FreeBSD__
	int tmp, error;

	/*
	 * The guest is allowed to spinup more than one processor only if the
	 * UNRESTRICTED_GUEST capability is available.
	 */
	error = vm_get_capability(vcpu, VM_CAP_UNRESTRICTED_GUEST, &tmp);
	if (error != 0)
		return (1);
#else
	int error;
	/* Unrestricted Guest is always enabled on illumos */

#endif /* __FreeBSD__ */

	error = vm_get_topology(ctx, &sockets, &cores, &threads, &maxcpus);
	if (error == 0)
		return (maxcpus);
	else
		return (1);
}

static void
fbsdrun_set_capabilities(struct vcpu *vcpu)
{
	int err, tmp;

#ifdef	__FreeBSD__
	if (get_config_bool_default("x86.vmexit_on_hlt", false)) {
		err = vm_get_capability(vcpu, VM_CAP_HALT_EXIT, &tmp);
		if (err < 0) {
			fprintf(stderr, "VM exit on HLT not supported\n");
			exit(4);
		}
		vm_set_capability(vcpu, VM_CAP_HALT_EXIT, 1);
	}
#else
	/*
	 * We insist that vmexit-on-hlt is available on the host CPU, and enable
	 * it by default.  Configuration of that feature is done with both of
	 * those facts in mind.
	 */
	tmp = (int)get_config_bool_default("x86.vmexit_on_hlt", true);
	err = vm_set_capability(vcpu, VM_CAP_HALT_EXIT, tmp);
	if (err < 0) {
		fprintf(stderr, "VM exit on HLT not supported\n");
		exit(4);
	}
#endif /* __FreeBSD__ */

	if (get_config_bool_default("x86.vmexit_on_pause", false)) {
		/*
		 * pause exit support required for this mode
		 */
		err = vm_get_capability(vcpu, VM_CAP_PAUSE_EXIT, &tmp);
		if (err < 0) {
			fprintf(stderr,
			    "SMP mux requested, no pause support\n");
			exit(4);
		}
		vm_set_capability(vcpu, VM_CAP_PAUSE_EXIT, 1);
	}

	if (get_config_bool_default("x86.x2apic", false))
		err = vm_set_x2apic_state(vcpu, X2APIC_ENABLED);
	else
		err = vm_set_x2apic_state(vcpu, X2APIC_DISABLED);

	if (err) {
		fprintf(stderr, "Unable to set x2apic state (%d)\n", err);
		exit(4);
	}

#ifdef	__FreeBSD__
	vm_set_capability(vcpu, VM_CAP_ENABLE_INVPCID, 1);

	err = vm_set_capability(vcpu, VM_CAP_IPI_EXIT, 1);
	assert(err == 0);
#endif
}

static struct vmctx *
do_open(const char *vmname)
{
	struct vmctx *ctx;
	int error;
	bool reinit, romboot;

	reinit = romboot = false;

	if (lpc_bootrom())
		romboot = true;
#ifndef __FreeBSD__
	uint64_t create_flags = 0;
	if (get_config_bool_default("memory.use_reservoir", false)) {
		create_flags |= VCF_RESERVOIR_MEM;
	}
	error = vm_create(vmname, create_flags);
#else
	error = vm_create(vmname);
#endif /* __FreeBSD__ */
	if (error) {
		if (errno == EEXIST) {
			if (romboot) {
				reinit = true;
			} else {
				/*
				 * The virtual machine has been setup by the
				 * userspace bootloader.
				 */
			}
		} else {
			perror("vm_create");
			exit(4);
		}
	} else {
		if (!romboot) {
			/*
			 * If the virtual machine was just created then a
			 * bootrom must be configured to boot it.
			 */
			fprintf(stderr, "virtual machine cannot be booted\n");
			exit(4);
		}
	}

	ctx = vm_open(vmname);
	if (ctx == NULL) {
		perror("vm_open");
		exit(4);
	}

#ifndef WITHOUT_CAPSICUM
	if (vm_limit_rights(ctx) != 0)
		err(EX_OSERR, "vm_limit_rights");
#endif

	if (reinit) {
#ifndef __FreeBSD__
		error = vm_reinit(ctx, 0);
#else
		error = vm_reinit(ctx);
#endif
		if (error) {
			perror("vm_reinit");
			exit(4);
		}
	}
	error = vm_set_topology(ctx, cpu_sockets, cpu_cores, cpu_threads, 0);
	if (error)
		errx(EX_OSERR, "vm_set_topology");
	return (ctx);
}

#ifndef __FreeBSD__

#define	FILE_PROVISIONING	"/var/svc/provisioning"
#define	FILE_PROVISION_SUCCESS	"/var/svc/provision_success"

static void
mark_provisioned(void)
{
	struct stat stbuf;

	if (lstat(FILE_PROVISIONING, &stbuf) != 0)
		return;

	if (rename(FILE_PROVISIONING, FILE_PROVISION_SUCCESS) != 0) {
		(void) fprintf(stderr, "Cannot rename %s to %s: %s\n",
		    FILE_PROVISIONING, FILE_PROVISION_SUCCESS,
		    strerror(errno));
	}
}

#endif

static void
spinup_vcpu(struct vcpu_info *vi, bool bsp, bool suspend)
{
	int error;

	if (!bsp) {
#ifndef	__FreeBSD__
		/*
		 * On illumos, all APs are spun up halted and run-state
		 * transitions (INIT, SIPI, etc) are handled in-kernel.
		 */
		spinup_ap(vi->vcpu, 0);
#endif

		fbsdrun_set_capabilities(vi->vcpu);

#ifdef	__FreeBSD__
		/*
		 * Enable the 'unrestricted guest' mode for APs.
		 *
		 * APs startup in power-on 16-bit mode.
		 */
		error = vm_set_capability(vi->vcpu, VM_CAP_UNRESTRICTED_GUEST, 1);
		assert(error == 0);
#endif
	}

#ifndef	__FreeBSD__
	/*
	 * The value of 'suspend' for the BSP depends on whether the -d
	 * (suspend_at_boot) flag was given to bhyve. Regardless of that
	 * value we always want to set the BSP to VRS_RUN and all others to
	 * VRS_HALT.
	 */
	error = vm_set_run_state(vi->vcpu, bsp ? VRS_RUN : VRS_HALT, 0);
	assert(error == 0);
#endif

	fbsdrun_addcpu(vi, suspend);
}

static bool
parse_config_option(const char *option)
{
	const char *value;
	char *path;

	value = strchr(option, '=');
	if (value == NULL || value[1] == '\0')
		return (false);
	path = strndup(option, value - option);
	if (path == NULL)
		err(4, "Failed to allocate memory");
	set_config_value(path, value + 1);
	return (true);
}

static void
parse_simple_config_file(const char *path)
{
	FILE *fp;
	char *line, *cp;
	size_t linecap;
	unsigned int lineno;

	fp = fopen(path, "r");
	if (fp == NULL)
		err(4, "Failed to open configuration file %s", path);
	line = NULL;
	linecap = 0;
	lineno = 1;
	for (lineno = 1; getline(&line, &linecap, fp) > 0; lineno++) {
		if (*line == '#' || *line == '\n')
			continue;
		cp = strchr(line, '\n');
		if (cp != NULL)
			*cp = '\0';
		if (!parse_config_option(line))
			errx(4, "%s line %u: invalid config option '%s'", path,
			    lineno, line);
	}
	free(line);
	fclose(fp);
}

static void
parse_gdb_options(const char *opt)
{
	const char *sport;
	char *colon;

	if (opt[0] == 'w') {
		set_config_bool("gdb.wait", true);
		opt++;
	}

	colon = strrchr(opt, ':');
	if (colon == NULL) {
		sport = opt;
	} else {
		*colon = '\0';
		colon++;
		sport = colon;
		set_config_value("gdb.address", opt);
	}

	set_config_value("gdb.port", sport);
}

static void
set_defaults(void)
{

	set_config_bool("acpi_tables", false);
	set_config_bool("acpi_tables_in_memory", true);
	set_config_value("memory.size", "256M");
	set_config_bool("x86.strictmsr", true);
	set_config_value("lpc.fwcfg", "bhyve");
}

int
main(int argc, char *argv[])
{
	int c, error;
	int max_vcpus, memflags;
	struct vcpu *bsp;
	struct vmctx *ctx;
	struct qemu_fwcfg_item *e820_fwcfg_item;
	size_t memsize;
	const char *optstr, *value, *vmname;

	init_config();
	set_defaults();
	progname = basename(argv[0]);

#ifdef	__FreeBSD__
	optstr = "aehuwxACDHIPSWYk:f:o:p:G:c:s:m:l:K:U:";
#else
	/* +d, +B, -p */
	optstr = "adehuwxACDHIPSWYk:f:o:G:c:s:m:l:B:K:U:";
#endif
	while ((c = getopt(argc, argv, optstr)) != -1) {
		switch (c) {
		case 'a':
			set_config_bool("x86.x2apic", false);
			break;
		case 'A':
			set_config_bool("acpi_tables", true);
			break;
		case 'D':
			set_config_bool("destroy_on_poweroff", true);
			break;
#ifndef	__FreeBSD__
		case 'B':
			if (smbios_parse(optarg) != 0) {
				errx(EX_USAGE, "invalid SMBIOS "
				    "configuration '%s'", optarg);
			}
			break;
		case 'd':
			set_config_bool("suspend_at_boot", true);
			break;
#endif
#ifdef	__FreeBSD__
		case 'p':
			if (pincpu_parse(optarg) != 0) {
				errx(EX_USAGE, "invalid vcpu pinning "
				    "configuration '%s'", optarg);
			}
			break;
#endif
		case 'c':
			if (topology_parse(optarg) != 0) {
			    errx(EX_USAGE, "invalid cpu topology "
				"'%s'", optarg);
			}
			break;
		case 'C':
			set_config_bool("memory.guest_in_core", true);
			break;
		case 'f':
			if (qemu_fwcfg_parse_cmdline_arg(optarg) != 0) {
			    errx(EX_USAGE, "invalid fwcfg item '%s'", optarg);
			}
			break;
		case 'G':
			parse_gdb_options(optarg);
			break;
		case 'k':
			parse_simple_config_file(optarg);
			break;
		case 'K':
			set_config_value("keyboard.layout", optarg);
			break;
		case 'l':
			if (strncmp(optarg, "help", strlen(optarg)) == 0) {
				lpc_print_supported_devices();
				exit(0);
			} else if (lpc_device_parse(optarg) != 0) {
				errx(EX_USAGE, "invalid lpc device "
				    "configuration '%s'", optarg);
			}
			break;
		case 's':
			if (strncmp(optarg, "help", strlen(optarg)) == 0) {
				pci_print_supported_devices();
				exit(0);
			} else if (pci_parse_slot(optarg) != 0)
				exit(4);
			else
				break;
		case 'S':
			set_config_bool("memory.wired", true);
			break;
		case 'm':
			set_config_value("memory.size", optarg);
			break;
		case 'o':
			if (!parse_config_option(optarg))
				errx(EX_USAGE, "invalid configuration option '%s'", optarg);
			break;
		case 'H':
			set_config_bool("x86.vmexit_on_hlt", true);
			break;
		case 'I':
			/*
			 * The "-I" option was used to add an ioapic to the
			 * virtual machine.
			 *
			 * An ioapic is now provided unconditionally for each
			 * virtual machine and this option is now deprecated.
			 */
			break;
		case 'P':
			set_config_bool("x86.vmexit_on_pause", true);
			break;
		case 'e':
			set_config_bool("x86.strictio", true);
			break;
		case 'u':
			set_config_bool("rtc.use_localtime", false);
			break;
		case 'U':
			set_config_value("uuid", optarg);
			break;
		case 'w':
			set_config_bool("x86.strictmsr", false);
			break;
		case 'W':
			set_config_bool("virtio_msix", false);
			break;
		case 'x':
			set_config_bool("x86.x2apic", true);
			break;
		case 'Y':
			set_config_bool("x86.mptable", false);
			break;
		case 'h':
			usage(0);
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage(1);

	if (argc == 1)
		set_config_value("name", argv[0]);

	vmname = get_config_value("name");
	if (vmname == NULL)
		usage(1);

	if (get_config_bool_default("config.dump", false)) {
		dump_config();
		exit(1);
	}

#ifndef __FreeBSD__
	illumos_priv_init();
#endif

	calc_topology();

#ifdef __FreeBSD__
	build_vcpumaps();
#endif

	value = get_config_value("memory.size");
	error = vm_parse_memsize(value, &memsize);
	if (error)
		errx(EX_USAGE, "invalid memsize '%s'", value);

	ctx = do_open(vmname);

	bsp = vm_vcpu_open(ctx, BSP);
	max_vcpus = num_vcpus_allowed(ctx, bsp);
	if (guest_ncpus > max_vcpus) {
		fprintf(stderr, "%d vCPUs requested but only %d available\n",
			guest_ncpus, max_vcpus);
		exit(4);
	}

	fbsdrun_set_capabilities(bsp);

       /* Allocate per-VCPU resources. */
	vcpu_info = calloc(guest_ncpus, sizeof(*vcpu_info));
	for (int vcpuid = 0; vcpuid < guest_ncpus; vcpuid++) {
		vcpu_info[vcpuid].ctx = ctx;
		vcpu_info[vcpuid].vcpuid = vcpuid;
		if (vcpuid == BSP)
			vcpu_info[vcpuid].vcpu = bsp;
		else
			vcpu_info[vcpuid].vcpu = vm_vcpu_open(ctx, vcpuid);
	}

	memflags = 0;
	if (get_config_bool_default("memory.wired", false))
		memflags |= VM_MEM_F_WIRED;
	if (get_config_bool_default("memory.guest_in_core", false))
		memflags |= VM_MEM_F_INCORE;
	vm_set_memflags(ctx, memflags);
#ifdef	__FreeBSD__
	error = vm_setup_memory(ctx, memsize, VM_MMAP_ALL);
#else
	int _errno;
	do {
		errno = 0;
		error = vm_setup_memory(ctx, memsize, VM_MMAP_ALL);
		_errno = errno;
		if (error != 0 && _errno == ENOMEM) {
			(void) fprintf(stderr, "Unable to allocate memory "
			    "(%llu), retrying in 1 second\n", memsize);
			sleep(1);
		}
	} while (_errno == ENOMEM);
#endif
	if (error) {
		fprintf(stderr, "Unable to set up memory (%d)\n", errno);
		exit(4);
	}

	error = init_msr();
	if (error) {
		fprintf(stderr, "init_msr error %d", error);
		exit(4);
	}

	init_mem(guest_ncpus);
	init_inout();
#ifdef	__FreeBSD__
	kernemu_dev_init();
#endif
	init_bootrom(ctx);
	atkbdc_init(ctx);
	pci_irq_init(ctx);
	ioapic_init(ctx);

	rtc_init(ctx);
	sci_init(ctx);
#ifndef	__FreeBSD__
	pmtmr_init(ctx);
#endif

	if (qemu_fwcfg_init(ctx) != 0) {
		fprintf(stderr, "qemu fwcfg initialization error");
		exit(4);
	}

	if (qemu_fwcfg_add_file("opt/bhyve/hw.ncpu", sizeof(guest_ncpus),
	    &guest_ncpus) != 0) {
		fprintf(stderr, "Could not add qemu fwcfg opt/bhyve/hw.ncpu");
		exit(4);
	}

	if (e820_init(ctx) != 0) {
		fprintf(stderr, "Unable to setup E820");
		exit(4);
	}

#ifndef	__FreeBSD__
	if (get_config_bool_default("e820.debug", false))
		e820_dump_table();
#endif

	/*
	 * Exit if a device emulation finds an error in its initialization
	 */
	if (init_pci(ctx) != 0) {
		perror("device emulation initialization error");
		exit(4);
	}
	if (init_tpm(ctx) != 0) {
		fprintf(stderr, "Failed to init TPM device");
		exit(4);
	}

	/*
	 * Initialize after PCI, to allow a bootrom file to reserve the high
	 * region.
	 */
	if (get_config_bool("acpi_tables"))
		vmgenc_init(ctx);

#ifdef __FreeBSD__
	init_gdb(ctx);
#else
	if (value != NULL) {
		int port = atoi(value);

		if (port < 0)
			init_mdb(ctx);
		else
			init_gdb(ctx);
	}
#endif

	if (lpc_bootrom()) {
#ifdef __FreeBSD__
		if (vm_set_capability(bsp, VM_CAP_UNRESTRICTED_GUEST, 1)) {
			fprintf(stderr, "ROM boot failed: unrestricted guest "
			    "capability not available\n");
			exit(4);
		}
#else
		/* Unrestricted Guest is always enabled on illumos */
#endif
		error = vcpu_reset(bsp);
		assert(error == 0);
	}

	/*
	 * build the guest tables, MP etc.
	 */
	if (get_config_bool_default("x86.mptable", true)) {
		error = mptable_build(ctx, guest_ncpus);
		if (error) {
			perror("error to build the guest tables");
			exit(4);
		}
	}

	error = smbios_build(ctx);
	if (error != 0)
		exit(4);

	if (get_config_bool("acpi_tables")) {
		error = acpi_build(ctx, guest_ncpus);
		assert(error == 0);
	}

	e820_fwcfg_item = e820_get_fwcfg_item();
	if (e820_fwcfg_item == NULL) {
		fprintf(stderr, "invalid e820 table");
		exit(4);
	}
	if (qemu_fwcfg_add_file("etc/e820", e820_fwcfg_item->size,
		e820_fwcfg_item->data) != 0) {
		fprintf(stderr, "could not add qemu fwcfg etc/e820");
		exit(4);
	}
	free(e820_fwcfg_item);

	if (lpc_bootrom() && strcmp(lpc_fwcfg(), "bhyve") == 0) {
		fwctl_init();
	}

	/*
	 * Change the proc title to include the VM name.
	 */
	setproctitle("%s", vmname);

#ifndef WITHOUT_CAPSICUM
	caph_cache_catpages();

	if (caph_limit_stdout() == -1 || caph_limit_stderr() == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");

	if (caph_enter() == -1)
		errx(EX_OSERR, "cap_enter() failed");
#endif

/* XXX SmartOS:  Upstream drops privs here, but we can't yet.  See below... */

#ifndef	__FreeBSD__
	vmentry = calloc(guest_ncpus, sizeof(*vmentry));
#endif

	/*
	 * Add all vCPUs.
	 */
	for (int vcpuid = 0; vcpuid < guest_ncpus; vcpuid++) {
#ifdef	__FreeBSD__
		bool suspend = (vcpuid != BSP);
#else
		bool suspend = vcpuid == BSP &&
		    get_config_bool_default("suspend_at_boot", false);
#endif
		spinup_vcpu(&vcpu_info[vcpuid], vcpuid == BSP, suspend);
	}
#ifndef __FreeBSD__
	mark_provisioned();
	/*
	 * XXX SmartOS:  The mark_provisioned() call above required file-access
	 * privileges that are dropped by illumos_priv_lock.  We must widen the
	 * full-privilege window a bit.  A better solution might be to have
	 * a way to keep file-access a bit longer, and only have THAT privilege
	 * to drop here.
	 */
	illumos_priv_lock();
#endif

	/*
	 * Head off to the main event dispatch loop
	 */
	mevent_dispatch();

	exit(4);
}
