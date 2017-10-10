/*-
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
 *
 * $FreeBSD: head/lib/libvmmapi/vmmapi.c 280929 2015-04-01 00:15:31Z tychon $
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/lib/libvmmapi/vmmapi.c 280929 2015-04-01 00:15:31Z tychon $");

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/_iovec.h>
#include <sys/cpuset.h>

#include <machine/specialreg.h>

#ifndef	__FreeBSD__
#include <errno.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <libutil.h>

#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#ifndef	__FreeBSD__
#include <sys/vmm_impl.h>
#endif

#include "vmmapi.h"

#define	KB	(1024UL)
#define	MB	(1024 * 1024UL)
#define	GB	(1024 * 1024 * 1024UL)

struct vmctx {
	int	fd;
	uint32_t lowmem_limit;
	enum vm_mmap_style vms;
	char	*lowermem_addr;
	char	*biosmem_addr;
	size_t	lowmem;
	char	*lowmem_addr;
	size_t	highmem;
	char	*highmem_addr;
	uint64_t rombase;
	uint64_t romlimit;
	char	*rom_addr;
	char	*name;
};

#ifdef	__FreeBSD__
#define	CREATE(x)  sysctlbyname("hw.vmm.create", NULL, NULL, (x), strlen((x)))
#define	DESTROY(x) sysctlbyname("hw.vmm.destroy", NULL, NULL, (x), strlen((x)))
#else
#define	CREATE(x)	vmm_vm_create(x)
#define	DESTROY(x)	vmm_vm_destroy(x)
#endif

static int
vm_device_open(const char *name)
{
        int fd, len;
        char *vmfile;

#ifdef	__FreeBSD__
	len = strlen("/dev/vmm/") + strlen(name) + 1;
#else
	len = strlen("/devices/pseudo/vmm@0:") + strlen(name) + 1;
#endif
	vmfile = malloc(len);
	assert(vmfile != NULL);
#ifdef	__FreeBSD__
	snprintf(vmfile, len, "/dev/vmm/%s", name);
#else
	snprintf(vmfile, len, "/devices/pseudo/vmm@0:%s", name);
#endif

        /* Open the device file */
        fd = open(vmfile, O_RDWR, 0);

	free(vmfile);
        return (fd);
}

#ifndef	__FreeBSD__
static int
vmm_vm_create(const char *name)
{
	const char vmm_ctl[] = "/devices/pseudo/vmm@0:ctl";
	struct vmm_ioctl vi;
	int err = 0;
	int ctl_fd;

	(void) strlcpy(vi.vmm_name, name, sizeof (vi.vmm_name) - 1);

	ctl_fd = open(vmm_ctl, O_EXCL | O_RDWR);
	if (ctl_fd == -1) {
		err = errno;
		if ((errno == EPERM) || (errno == EACCES)) {
			fprintf(stderr, "you do not have permission to "
				"perform that operation.\n");
		} else {
			fprintf(stderr, "open: %s: %s\n", vmm_ctl,
				strerror(errno));
		}
		return (err);
	}
	if (ioctl(ctl_fd, VMM_CREATE_VM, &vi) == -1) {
		err = errno;
		fprintf(stderr, "couldn't create vm \"%s\"", name);
	}
	close (ctl_fd);

	return (err);
}
#endif

int
vm_create(const char *name)
{

	return (CREATE((char *)name));
}

struct vmctx *
vm_open(const char *name)
{
	struct vmctx *vm;

	vm = malloc(sizeof(struct vmctx) + strlen(name) + 1);
	assert(vm != NULL);

	vm->fd = -1;
	vm->lowmem_limit = 3 * GB;
	vm->name = (char *)(vm + 1);
	strcpy(vm->name, name);

	if ((vm->fd = vm_device_open(vm->name)) < 0)
		goto err;

	return (vm);
err:
	(void) vm_destroy(vm);
	return (NULL);
}

#ifndef	__FreeBSD__
static int
vmm_vm_destroy(const char *name)
{
	const char vmm_ctl[] = "/devices/pseudo/vmm@0:ctl";
	struct vmm_ioctl vi;	
	int ctl_fd;
	int err = 0;

	(void) strlcpy(vi.vmm_name, name, sizeof (vi.vmm_name) - 1);

	ctl_fd = open(vmm_ctl, O_EXCL | O_RDWR);
	if (ctl_fd == -1) {
		err = errno;
		if ((errno == EPERM) || (errno == EACCES)) {
			fprintf(stderr, "you do not have permission to "
				"perform that operation.\n");
		} else {
			fprintf(stderr, "open: %s: %s\n", vmm_ctl,
				strerror(errno));
		}
		return (err);
	}
	if (ioctl(ctl_fd, VMM_DESTROY_VM, &vi) == -1) {
		err = errno;
		fprintf(stderr, "couldn't destroy vm \"%s\"", name);
	}
	close (ctl_fd);
	return (err);
}
#endif

int
vm_destroy(struct vmctx *vm)
{
	int err;
	assert(vm != NULL);

	if (vm->fd >= 0)
		close(vm->fd);
	err = DESTROY(vm->name);

	free(vm);
	return (err);
}

int
vm_parse_memsize(const char *optarg, size_t *ret_memsize)
{
	char *endptr;
	size_t optval;
	int error;

	optval = strtoul(optarg, &endptr, 0);
	if (*optarg != '\0' && *endptr == '\0') {
		/*
		 * For the sake of backward compatibility if the memory size
		 * specified on the command line is less than a megabyte then
		 * it is interpreted as being in units of MB.
		 */
		if (optval < MB)
			optval *= MB;
		*ret_memsize = optval;
		error = 0;
	} else
		error = expand_number(optarg, ret_memsize);

	return (error);
}

#ifdef	__FreeBSD__
size_t
vmm_get_mem_total(void)
{
	size_t mem_total = 0;
	size_t oldlen = sizeof(mem_total);
	int error;
	error = sysctlbyname("hw.vmm.mem_total", &mem_total, &oldlen, NULL, 0);
	if (error)
		return -1;
	return mem_total;
}

size_t
vmm_get_mem_free(void)
{
	size_t mem_free = 0;
	size_t oldlen = sizeof(mem_free);
	int error;
	error = sysctlbyname("hw.vmm.mem_free", &mem_free, &oldlen, NULL, 0);
	if (error)
		return -1;
	return mem_free;
}
#endif

int
vm_get_memory_seg(struct vmctx *ctx, vm_paddr_t gpa, size_t *ret_len,
		  int *wired)
{
	int error;
	struct vm_memory_segment seg;

	bzero(&seg, sizeof(seg));
	seg.gpa = gpa;
	error = ioctl(ctx->fd, VM_GET_MEMORY_SEG, &seg);
	*ret_len = seg.len;
	if (wired != NULL)
		*wired = seg.wired;
	return (error);
}

uint32_t
vm_get_lowmem_limit(struct vmctx *ctx)
{

	return (ctx->lowmem_limit);
}

void
vm_set_lowmem_limit(struct vmctx *ctx, uint32_t limit)
{

	ctx->lowmem_limit = limit;
}

static int
setup_memory_segment(struct vmctx *ctx, vm_paddr_t gpa, size_t len, char **addr)
{
	int error;
	struct vm_memory_segment seg;

	/*
	 * Create and optionally map 'len' bytes of memory at guest
	 * physical address 'gpa'
	 */
	bzero(&seg, sizeof(seg));
	seg.gpa = gpa;
	seg.len = len;
	error = ioctl(ctx->fd, VM_MAP_MEMORY, &seg);
	if (error == 0 && addr != NULL) {
		*addr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED,
				ctx->fd, gpa);
	}
	return (error);
}

int
vm_setup_memory(struct vmctx *ctx, size_t memsize, enum vm_mmap_style vms)
{
	char **addr;
	int error;

	/* XXX VM_MMAP_SPARSE not implemented yet */
	assert(vms == VM_MMAP_NONE || vms == VM_MMAP_ALL);
	ctx->vms = vms;

	/*
	 * If 'memsize' cannot fit entirely in the 'lowmem' segment then
	 * create another 'highmem' segment above 4GB for the remainder.
	 */
	if (memsize > ctx->lowmem_limit) {
		ctx->lowmem = ctx->lowmem_limit;
		ctx->highmem = memsize - ctx->lowmem;
	} else {
		ctx->lowmem = memsize;
		ctx->highmem = 0;
	}

	if (ctx->lowmem > 0) {
		addr = (vms == VM_MMAP_ALL) ? &ctx->lowermem_addr : NULL;
		error = setup_memory_segment(ctx, 0, 640*KB, addr);
		if (error)
			return (error);

		addr = (vms == VM_MMAP_ALL) ? &ctx->biosmem_addr : NULL;
		error = setup_memory_segment(ctx, 768*KB, 256*KB, addr);
		if (error)
			return (error);

		addr = (vms == VM_MMAP_ALL) ? &ctx->lowmem_addr : NULL;
		error = setup_memory_segment(ctx, 1*MB, ctx->lowmem - 1*MB, addr);
		if (error)
			return (error);
	}

	if (ctx->highmem > 0) {
		addr = (vms == VM_MMAP_ALL) ? &ctx->highmem_addr : NULL;
		error = setup_memory_segment(ctx, 4*GB, ctx->highmem, addr);
		if (error)
			return (error);
	}

	return (0);
}

int
vm_setup_rom(struct vmctx *ctx, vm_paddr_t gpa, size_t len)
{
	ctx->rombase = gpa;
	ctx->romlimit = gpa + len;

	return (setup_memory_segment(ctx, gpa, len, &ctx->rom_addr));
}

void *
vm_map_gpa(struct vmctx *ctx, vm_paddr_t gaddr, size_t len)
{

	/* XXX VM_MMAP_SPARSE not implemented yet */
	assert(ctx->vms == VM_MMAP_ALL);

	if (gaddr + len <= 1*MB) {
		if (gaddr + len <= 640*KB)
			return ((void *)(ctx->lowermem_addr + gaddr));

		if (768*KB <= gaddr && gaddr + len <= 1*MB) {
			gaddr -= 768*KB;
			return ((void *)(ctx->biosmem_addr + gaddr));
		}

		return (NULL);
	}

	if (gaddr < ctx->lowmem && gaddr + len <= ctx->lowmem) {
		gaddr -= 1*MB;
		return ((void *)(ctx->lowmem_addr + gaddr));
	}

	if (ctx->rombase <= gaddr && gaddr + len <= ctx->romlimit) {
		gaddr -= ctx->rombase;
		return ((void *)(ctx->rom_addr + gaddr));
	}

	if (gaddr >= 4*GB) {
		gaddr -= 4*GB;
		if (gaddr < ctx->highmem && gaddr + len <= ctx->highmem)
			return ((void *)(ctx->highmem_addr + gaddr));
	}

	return (NULL);
}

size_t
vm_get_lowmem_size(struct vmctx *ctx)
{

	return (ctx->lowmem);
}

size_t
vm_get_highmem_size(struct vmctx *ctx)
{

	return (ctx->highmem);
}

int
vm_set_desc(struct vmctx *ctx, int vcpu, int reg,
	    uint64_t base, uint32_t limit, uint32_t access)
{
	int error;
	struct vm_seg_desc vmsegdesc;

	bzero(&vmsegdesc, sizeof(vmsegdesc));
	vmsegdesc.cpuid = vcpu;
	vmsegdesc.regnum = reg;
	vmsegdesc.desc.base = base;
	vmsegdesc.desc.limit = limit;
	vmsegdesc.desc.access = access;

	error = ioctl(ctx->fd, VM_SET_SEGMENT_DESCRIPTOR, &vmsegdesc);
	return (error);
}

int
vm_get_desc(struct vmctx *ctx, int vcpu, int reg,
	    uint64_t *base, uint32_t *limit, uint32_t *access)
{
	int error;
	struct vm_seg_desc vmsegdesc;

	bzero(&vmsegdesc, sizeof(vmsegdesc));
	vmsegdesc.cpuid = vcpu;
	vmsegdesc.regnum = reg;

	error = ioctl(ctx->fd, VM_GET_SEGMENT_DESCRIPTOR, &vmsegdesc);
	if (error == 0) {
		*base = vmsegdesc.desc.base;
		*limit = vmsegdesc.desc.limit;
		*access = vmsegdesc.desc.access;
	}
	return (error);
}

int
vm_get_seg_desc(struct vmctx *ctx, int vcpu, int reg, struct seg_desc *seg_desc)
{
	int error;

	error = vm_get_desc(ctx, vcpu, reg, &seg_desc->base, &seg_desc->limit,
	    &seg_desc->access);
	return (error);
}

int
vm_set_register(struct vmctx *ctx, int vcpu, int reg, uint64_t val)
{
	int error;
	struct vm_register vmreg;

	bzero(&vmreg, sizeof(vmreg));
	vmreg.cpuid = vcpu;
	vmreg.regnum = reg;
	vmreg.regval = val;

	error = ioctl(ctx->fd, VM_SET_REGISTER, &vmreg);
	return (error);
}

int
vm_get_register(struct vmctx *ctx, int vcpu, int reg, uint64_t *ret_val)
{
	int error;
	struct vm_register vmreg;

	bzero(&vmreg, sizeof(vmreg));
	vmreg.cpuid = vcpu;
	vmreg.regnum = reg;

	error = ioctl(ctx->fd, VM_GET_REGISTER, &vmreg);
	*ret_val = vmreg.regval;
	return (error);
}

int
vm_run(struct vmctx *ctx, int vcpu, struct vm_exit *vmexit)
{
	int error;
	struct vm_run vmrun;

	bzero(&vmrun, sizeof(vmrun));
	vmrun.cpuid = vcpu;

	error = ioctl(ctx->fd, VM_RUN, &vmrun);
	bcopy(&vmrun.vm_exit, vmexit, sizeof(struct vm_exit));
	return (error);
}

/* XXX: unused static */
#if notyet
static int
vm_inject_exception_real(struct vmctx *ctx, int vcpu, int vector,
    int error_code, int error_code_valid)
{
	struct vm_exception exc;

	bzero(&exc, sizeof(exc));
	exc.cpuid = vcpu;
	exc.vector = vector;
	exc.error_code = error_code;
	exc.error_code_valid = error_code_valid;

	return (ioctl(ctx->fd, VM_INJECT_EXCEPTION, &exc));
}
#endif

int
vm_inject_exception(struct vmctx *ctx, int vcpu, int vector, int errcode_valid,
    uint32_t errcode, int restart_instruction)
{
	struct vm_exception exc;

	exc.cpuid = vcpu;
	exc.vector = vector;
	exc.error_code = errcode;
	exc.error_code_valid = errcode_valid;
	exc.restart_instruction = restart_instruction;

	return (ioctl(ctx->fd, VM_INJECT_EXCEPTION, &exc));
}

int
vm_apicid2vcpu(struct vmctx *ctx, int apicid)
{
	/*
	 * The apic id associated with the 'vcpu' has the same numerical value
	 * as the 'vcpu' itself.
	 */
	return (apicid);
}

int
vm_lapic_irq(struct vmctx *ctx, int vcpu, int vector)
{
	struct vm_lapic_irq vmirq;

	bzero(&vmirq, sizeof(vmirq));
	vmirq.cpuid = vcpu;
	vmirq.vector = vector;

	return (ioctl(ctx->fd, VM_LAPIC_IRQ, &vmirq));
}

int
vm_lapic_local_irq(struct vmctx *ctx, int vcpu, int vector)
{
	struct vm_lapic_irq vmirq;

	bzero(&vmirq, sizeof(vmirq));
	vmirq.cpuid = vcpu;
	vmirq.vector = vector;

	return (ioctl(ctx->fd, VM_LAPIC_LOCAL_IRQ, &vmirq));
}

int
vm_lapic_msi(struct vmctx *ctx, uint64_t addr, uint64_t msg)
{
	struct vm_lapic_msi vmmsi;

	bzero(&vmmsi, sizeof(vmmsi));
	vmmsi.addr = addr;
	vmmsi.msg = msg;

	return (ioctl(ctx->fd, VM_LAPIC_MSI, &vmmsi));
}

int
vm_ioapic_assert_irq(struct vmctx *ctx, int irq)
{
	struct vm_ioapic_irq ioapic_irq;

	bzero(&ioapic_irq, sizeof(struct vm_ioapic_irq));
	ioapic_irq.irq = irq;

	return (ioctl(ctx->fd, VM_IOAPIC_ASSERT_IRQ, &ioapic_irq));
}

int
vm_ioapic_deassert_irq(struct vmctx *ctx, int irq)
{
	struct vm_ioapic_irq ioapic_irq;

	bzero(&ioapic_irq, sizeof(struct vm_ioapic_irq));
	ioapic_irq.irq = irq;

	return (ioctl(ctx->fd, VM_IOAPIC_DEASSERT_IRQ, &ioapic_irq));
}

int
vm_ioapic_pulse_irq(struct vmctx *ctx, int irq)
{
	struct vm_ioapic_irq ioapic_irq;

	bzero(&ioapic_irq, sizeof(struct vm_ioapic_irq));
	ioapic_irq.irq = irq;

	return (ioctl(ctx->fd, VM_IOAPIC_PULSE_IRQ, &ioapic_irq));
}

int
vm_ioapic_pincount(struct vmctx *ctx, int *pincount)
{

	return (ioctl(ctx->fd, VM_IOAPIC_PINCOUNT, pincount));
}

int
vm_isa_assert_irq(struct vmctx *ctx, int atpic_irq, int ioapic_irq)
{
	struct vm_isa_irq isa_irq;

	bzero(&isa_irq, sizeof(struct vm_isa_irq));
	isa_irq.atpic_irq = atpic_irq;
	isa_irq.ioapic_irq = ioapic_irq;

	return (ioctl(ctx->fd, VM_ISA_ASSERT_IRQ, &isa_irq));
}

int
vm_isa_deassert_irq(struct vmctx *ctx, int atpic_irq, int ioapic_irq)
{
	struct vm_isa_irq isa_irq;

	bzero(&isa_irq, sizeof(struct vm_isa_irq));
	isa_irq.atpic_irq = atpic_irq;
	isa_irq.ioapic_irq = ioapic_irq;

	return (ioctl(ctx->fd, VM_ISA_DEASSERT_IRQ, &isa_irq));
}

int
vm_isa_pulse_irq(struct vmctx *ctx, int atpic_irq, int ioapic_irq)
{
	struct vm_isa_irq isa_irq;

	bzero(&isa_irq, sizeof(struct vm_isa_irq));
	isa_irq.atpic_irq = atpic_irq;
	isa_irq.ioapic_irq = ioapic_irq;

	return (ioctl(ctx->fd, VM_ISA_PULSE_IRQ, &isa_irq));
}

int
vm_isa_set_irq_trigger(struct vmctx *ctx, int atpic_irq,
    enum vm_intr_trigger trigger)
{
	struct vm_isa_irq_trigger isa_irq_trigger;

	bzero(&isa_irq_trigger, sizeof(struct vm_isa_irq_trigger));
	isa_irq_trigger.atpic_irq = atpic_irq;
	isa_irq_trigger.trigger = trigger;

	return (ioctl(ctx->fd, VM_ISA_SET_IRQ_TRIGGER, &isa_irq_trigger));
}

int
vm_inject_nmi(struct vmctx *ctx, int vcpu)
{
	struct vm_nmi vmnmi;

	bzero(&vmnmi, sizeof(vmnmi));
	vmnmi.cpuid = vcpu;

	return (ioctl(ctx->fd, VM_INJECT_NMI, &vmnmi));
}

static struct {
	const char	*name;
	int		type;
} capstrmap[] = {
	{ "hlt_exit",		VM_CAP_HALT_EXIT },
	{ "mtrap_exit",		VM_CAP_MTRAP_EXIT },
	{ "pause_exit",		VM_CAP_PAUSE_EXIT },
	{ "unrestricted_guest",	VM_CAP_UNRESTRICTED_GUEST },
	{ "enable_invpcid",	VM_CAP_ENABLE_INVPCID },
	{ 0 }
};

int
vm_capability_name2type(const char *capname)
{
	int i;

	for (i = 0; capstrmap[i].name != NULL && capname != NULL; i++) {
		if (strcmp(capstrmap[i].name, capname) == 0)
			return (capstrmap[i].type);
	}

	return (-1);
}

const char *
vm_capability_type2name(int type)
{
	int i;

	for (i = 0; capstrmap[i].name != NULL; i++) {
		if (capstrmap[i].type == type)
			return (capstrmap[i].name);
	}

	return (NULL);
}

int
vm_get_capability(struct vmctx *ctx, int vcpu, enum vm_cap_type cap,
		  int *retval)
{
	int error;
	struct vm_capability vmcap;

	bzero(&vmcap, sizeof(vmcap));
	vmcap.cpuid = vcpu;
	vmcap.captype = cap;

	error = ioctl(ctx->fd, VM_GET_CAPABILITY, &vmcap);
	*retval = vmcap.capval;
	return (error);
}

int
vm_set_capability(struct vmctx *ctx, int vcpu, enum vm_cap_type cap, int val)
{
	struct vm_capability vmcap;

	bzero(&vmcap, sizeof(vmcap));
	vmcap.cpuid = vcpu;
	vmcap.captype = cap;
	vmcap.capval = val;
	
	return (ioctl(ctx->fd, VM_SET_CAPABILITY, &vmcap));
}

int
vm_assign_pptdev(struct vmctx *ctx, int bus, int slot, int func)
{
	struct vm_pptdev pptdev;

	bzero(&pptdev, sizeof(pptdev));
	pptdev.bus = bus;
	pptdev.slot = slot;
	pptdev.func = func;

	return (ioctl(ctx->fd, VM_BIND_PPTDEV, &pptdev));
}

int
vm_unassign_pptdev(struct vmctx *ctx, int bus, int slot, int func)
{
	struct vm_pptdev pptdev;

	bzero(&pptdev, sizeof(pptdev));
	pptdev.bus = bus;
	pptdev.slot = slot;
	pptdev.func = func;

	return (ioctl(ctx->fd, VM_UNBIND_PPTDEV, &pptdev));
}

int
vm_map_pptdev_mmio(struct vmctx *ctx, int bus, int slot, int func,
		   vm_paddr_t gpa, size_t len, vm_paddr_t hpa)
{
	struct vm_pptdev_mmio pptmmio;

	bzero(&pptmmio, sizeof(pptmmio));
	pptmmio.bus = bus;
	pptmmio.slot = slot;
	pptmmio.func = func;
	pptmmio.gpa = gpa;
	pptmmio.len = len;
	pptmmio.hpa = hpa;

	return (ioctl(ctx->fd, VM_MAP_PPTDEV_MMIO, &pptmmio));
}

int
vm_setup_pptdev_msi(struct vmctx *ctx, int vcpu, int bus, int slot, int func,
    uint64_t addr, uint64_t msg, int numvec)
{
	struct vm_pptdev_msi pptmsi;

	bzero(&pptmsi, sizeof(pptmsi));
	pptmsi.vcpu = vcpu;
	pptmsi.bus = bus;
	pptmsi.slot = slot;
	pptmsi.func = func;
	pptmsi.msg = msg;
	pptmsi.addr = addr;
	pptmsi.numvec = numvec;

	return (ioctl(ctx->fd, VM_PPTDEV_MSI, &pptmsi));
}

int	
vm_setup_pptdev_msix(struct vmctx *ctx, int vcpu, int bus, int slot, int func,
    int idx, uint64_t addr, uint64_t msg, uint32_t vector_control)
{
	struct vm_pptdev_msix pptmsix;

	bzero(&pptmsix, sizeof(pptmsix));
	pptmsix.vcpu = vcpu;
	pptmsix.bus = bus;
	pptmsix.slot = slot;
	pptmsix.func = func;
	pptmsix.idx = idx;
	pptmsix.msg = msg;
	pptmsix.addr = addr;
	pptmsix.vector_control = vector_control;

	return ioctl(ctx->fd, VM_PPTDEV_MSIX, &pptmsix);
}

#ifdef	__FreeBSD__
uint64_t *
vm_get_stats(struct vmctx *ctx, int vcpu, struct timeval *ret_tv,
	     int *ret_entries)
{
	int error;

	static struct vm_stats vmstats;

	vmstats.cpuid = vcpu;

	error = ioctl(ctx->fd, VM_STATS, &vmstats);
	if (error == 0) {
		if (ret_entries)
			*ret_entries = vmstats.num_entries;
		if (ret_tv)
			*ret_tv = vmstats.tv;
		return (vmstats.statbuf);
	} else
		return (NULL);
}

const char *
vm_get_stat_desc(struct vmctx *ctx, int index)
{
	static struct vm_stat_desc statdesc;

	statdesc.index = index;
	if (ioctl(ctx->fd, VM_STAT_DESC, &statdesc) == 0)
		return (statdesc.desc);
	else
		return (NULL);
}
#endif

int
vm_get_x2apic_state(struct vmctx *ctx, int vcpu, enum x2apic_state *state)
{
	int error;
	struct vm_x2apic x2apic;

	bzero(&x2apic, sizeof(x2apic));
	x2apic.cpuid = vcpu;

	error = ioctl(ctx->fd, VM_GET_X2APIC_STATE, &x2apic);
	*state = x2apic.state;
	return (error);
}

int
vm_set_x2apic_state(struct vmctx *ctx, int vcpu, enum x2apic_state state)
{
	int error;
	struct vm_x2apic x2apic;

	bzero(&x2apic, sizeof(x2apic));
	x2apic.cpuid = vcpu;
	x2apic.state = state;

	error = ioctl(ctx->fd, VM_SET_X2APIC_STATE, &x2apic);

	return (error);
}

/*
 * From Intel Vol 3a:
 * Table 9-1. IA-32 Processor States Following Power-up, Reset or INIT
 */
int
vcpu_reset(struct vmctx *vmctx, int vcpu)
{
	int error;
	uint64_t rflags, rip, cr0, cr4, zero, desc_base, rdx;
	uint32_t desc_access, desc_limit;
	uint16_t sel;

	zero = 0;

	rflags = 0x2;
	error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_RFLAGS, rflags);
	if (error)
		goto done;

	rip = 0xfff0;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_RIP, rip)) != 0)
		goto done;

	cr0 = CR0_NE;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_CR0, cr0)) != 0)
		goto done;

	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_CR3, zero)) != 0)
		goto done;
	
	cr4 = 0;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_CR4, cr4)) != 0)
		goto done;

	/*
	 * CS: present, r/w, accessed, 16-bit, byte granularity, usable
	 */
	desc_base = 0xffff0000;
	desc_limit = 0xffff;
	desc_access = 0x0093;
	error = vm_set_desc(vmctx, vcpu, VM_REG_GUEST_CS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	sel = 0xf000;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_CS, sel)) != 0)
		goto done;

	/*
	 * SS,DS,ES,FS,GS: present, r/w, accessed, 16-bit, byte granularity
	 */
	desc_base = 0;
	desc_limit = 0xffff;
	desc_access = 0x0093;
	error = vm_set_desc(vmctx, vcpu, VM_REG_GUEST_SS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(vmctx, vcpu, VM_REG_GUEST_DS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(vmctx, vcpu, VM_REG_GUEST_ES,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(vmctx, vcpu, VM_REG_GUEST_FS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(vmctx, vcpu, VM_REG_GUEST_GS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	sel = 0;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_SS, sel)) != 0)
		goto done;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_DS, sel)) != 0)
		goto done;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_ES, sel)) != 0)
		goto done;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_FS, sel)) != 0)
		goto done;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_GS, sel)) != 0)
		goto done;

	/* General purpose registers */
	rdx = 0xf00;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_RAX, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_RBX, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_RCX, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_RDX, rdx)) != 0)
		goto done;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_RSI, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_RDI, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_RBP, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_RSP, zero)) != 0)
		goto done;

	/* GDTR, IDTR */
	desc_base = 0;
	desc_limit = 0xffff;
	desc_access = 0;
	error = vm_set_desc(vmctx, vcpu, VM_REG_GUEST_GDTR,
			    desc_base, desc_limit, desc_access);
	if (error != 0)
		goto done;

	error = vm_set_desc(vmctx, vcpu, VM_REG_GUEST_IDTR,
			    desc_base, desc_limit, desc_access);
	if (error != 0)
		goto done;

	/* TR */
	desc_base = 0;
	desc_limit = 0xffff;
	desc_access = 0x0000008b;
	error = vm_set_desc(vmctx, vcpu, VM_REG_GUEST_TR, 0, 0, desc_access);
	if (error)
		goto done;

	sel = 0;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_TR, sel)) != 0)
		goto done;

	/* LDTR */
	desc_base = 0;
	desc_limit = 0xffff;
	desc_access = 0x00000082;
	error = vm_set_desc(vmctx, vcpu, VM_REG_GUEST_LDTR, desc_base,
			    desc_limit, desc_access);
	if (error)
		goto done;

	sel = 0;
	if ((error = vm_set_register(vmctx, vcpu, VM_REG_GUEST_LDTR, 0)) != 0)
		goto done;

	/* XXX cr2, debug registers */

	error = 0;
done:
	return (error);
}

int
vm_get_gpa_pmap(struct vmctx *ctx, uint64_t gpa, uint64_t *pte, int *num)
{
	int error, i;
	struct vm_gpa_pte gpapte;

	bzero(&gpapte, sizeof(gpapte));
	gpapte.gpa = gpa;

	error = ioctl(ctx->fd, VM_GET_GPA_PMAP, &gpapte);

	if (error == 0) {
		*num = gpapte.ptenum;
		for (i = 0; i < gpapte.ptenum; i++)
			pte[i] = gpapte.pte[i];
	}

	return (error);
}

int
vm_get_hpet_capabilities(struct vmctx *ctx, uint32_t *capabilities)
{
	int error;
	struct vm_hpet_cap cap;

	bzero(&cap, sizeof(struct vm_hpet_cap));
	error = ioctl(ctx->fd, VM_GET_HPET_CAPABILITIES, &cap);
	if (capabilities != NULL)
		*capabilities = cap.capabilities;
	return (error);
}

static int
gla2gpa(struct vmctx *ctx, int vcpu, struct vm_guest_paging *paging,
    uint64_t gla, int prot, int *fault, uint64_t *gpa)
{
	struct vm_gla2gpa gg;
	int error;

	bzero(&gg, sizeof(struct vm_gla2gpa));
	gg.vcpuid = vcpu;
	gg.prot = prot;
	gg.gla = gla;
	gg.paging = *paging;

	error = ioctl(ctx->fd, VM_GLA2GPA, &gg);
	if (error == 0) {
		*fault = gg.fault;
		*gpa = gg.gpa;
	}
	return (error);
}

int
vm_gla2gpa(struct vmctx *ctx, int vcpu, struct vm_guest_paging *paging,
    uint64_t gla, int prot, uint64_t *gpa)
{
	int error, fault;

	error = gla2gpa(ctx, vcpu, paging, gla, prot, &fault, gpa);
	if (fault)
		error = fault;
	return (error);
}

#ifndef min
#define	min(a,b)	(((a) < (b)) ? (a) : (b))
#endif

int
vm_copy_setup(struct vmctx *ctx, int vcpu, struct vm_guest_paging *paging,
    uint64_t gla, size_t len, int prot, struct iovec *iov, int iovcnt)
{
	void *va;
	uint64_t gpa;
	int error, fault, i, n, off;

	for (i = 0; i < iovcnt; i++) {
		iov[i].iov_base = 0;
		iov[i].iov_len = 0;
	}

	while (len) {
		assert(iovcnt > 0);
		error = gla2gpa(ctx, vcpu, paging, gla, prot, &fault, &gpa);
		if (error)
			return (-1);
		if (fault)
			return (1);

		off = gpa & PAGE_MASK;
		n = min(len, PAGE_SIZE - off);

		va = vm_map_gpa(ctx, gpa, n);
		if (va == NULL)
			return (-1);

		iov->iov_base = va;
		iov->iov_len = n;
		iov++;
		iovcnt--;

		gla += n;
		len -= n;
	}
	return (0);
}

void
vm_copy_teardown(struct vmctx *ctx, int vcpu, struct iovec *iov, int iovcnt)
{

	return;
}

void
vm_copyin(struct vmctx *ctx, int vcpu, struct iovec *iov, void *vp, size_t len)
{
	const char *src;
	char *dst;
	size_t n;

	dst = vp;
	while (len) {
		assert(iov->iov_len);
		n = min(len, iov->iov_len);
		src = iov->iov_base;
		bcopy(src, dst, n);

		iov++;
		dst += n;
		len -= n;
	}
}

void
vm_copyout(struct vmctx *ctx, int vcpu, const void *vp, struct iovec *iov,
    size_t len)
{
	const char *src;
	char *dst;
	size_t n;

	src = vp;
	while (len) {
		assert(iov->iov_len);
		n = min(len, iov->iov_len);
		dst = iov->iov_base;
		bcopy(src, dst, n);

		iov++;
		src += n;
		len -= n;
	}
}

int
vm_activate_cpu(struct vmctx *ctx, int vcpu)
{
	struct vm_activate_cpu ac;
	int error;

	bzero(&ac, sizeof(struct vm_activate_cpu));
	ac.vcpuid = vcpu;
	error = ioctl(ctx->fd, VM_ACTIVATE_CPU, &ac);
	return (error);
}

int
vm_restart_instruction(void *arg, int vcpu)
{
	struct vmctx *ctx = arg;

	return (ioctl(ctx->fd, VM_RESTART_INSTRUCTION, &vcpu));
}
