/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 * Copyright 2023 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * Library for native code to access bhyve VMs, without the need to use
 * FreeBSD compat headers
 */

#include <sys/param.h>
#include <sys/list.h>
#include <sys/stddef.h>
#include <sys/mman.h>
#include <sys/kdi_regs.h>
#include <sys/sysmacros.h>
#include <sys/controlregs.h>
#include <sys/note.h>
#include <sys/debug.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>

#include <machine/vmm.h>
#include <vmmapi.h>

#include <libvmm.h>

typedef struct vmm_memseg vmm_memseg_t;

#define	VMM_MEMSEG_DEVMEM	0x1

struct vmm_memseg {
	list_node_t vms_list;
	int vms_segid;
	int vms_prot;
	int vms_flags;
	uintptr_t vms_gpa;
	off_t vms_segoff;
	size_t vms_seglen;
	size_t vms_maplen;
	char vms_name[64];
};

struct vmm {
	struct vmctx *vmm_ctx;
	list_t vmm_memlist;
	char *vmm_mem;
	size_t vmm_memsize;
	size_t vmm_ncpu;
	struct vcpu **vmm_vcpu;
};


/*
 * This code relies on two assumptions:
 * - CPUs are never removed from the "active set", not even when suspended.
 *   A CPU being active just means that it has been used by the guest OS.
 * - The CPU numbering is consecutive.
 */
static void
vmm_update_ncpu(vmm_t *vmm)
{
	cpuset_t cpuset;

	assert(vm_active_cpus(vmm->vmm_ctx, &cpuset) == 0);

	for (vmm->vmm_ncpu = 0;
	    CPU_ISSET(vmm->vmm_ncpu, &cpuset) == 1;
	    vmm->vmm_ncpu++)
		;
}

vmm_t *
vmm_open_vm(const char *name)
{
	vmm_t *vmm = NULL;
	int _errno;
	int i;

	vmm = malloc(sizeof (vmm_t));
	if (vmm == NULL)
		return (NULL);

	bzero(vmm, sizeof (vmm_t));
	vmm->vmm_mem = MAP_FAILED;

	list_create(&vmm->vmm_memlist, sizeof (vmm_memseg_t),
	    offsetof(vmm_memseg_t, vms_list));

	vmm->vmm_ctx = vm_open(name);
	if (vmm->vmm_ctx == NULL) {
		list_destroy(&vmm->vmm_memlist);
		free(vmm);
		return (NULL);
	}

	vmm_update_ncpu(vmm);

	/*
	 * If we open a VM that has just been created we may see a state
	 * where it has no CPUs configured yet. We'll just wait for 10ms
	 * and retry until we get a non-zero CPU count.
	 */
	if (vmm->vmm_ncpu == 0) {
		do {
			(void) usleep(10000);
			vmm_update_ncpu(vmm);
		} while (vmm->vmm_ncpu == 0);
	}

	vmm->vmm_vcpu = calloc(vmm->vmm_ncpu, sizeof (struct vcpu *));
	if (vmm->vmm_vcpu == NULL)
		goto fail;
	for (i = 0; i < vmm->vmm_ncpu; i++) {
		vmm->vmm_vcpu[i] = vm_vcpu_open(vmm->vmm_ctx, i);
		if (vmm->vmm_vcpu[i] == NULL) {
			_errno = errno;
			while (i-- >= 0)
				vm_vcpu_close(vmm->vmm_vcpu[i]);
			free(vmm->vmm_vcpu);
			errno = _errno;
			goto fail;
		}
	}

	return (vmm);

fail:
	_errno = errno;
	vmm_close_vm(vmm);
	errno = _errno;

	return (NULL);
}

void
vmm_close_vm(vmm_t *vmm)
{
	uint_t i;

	vmm_unmap(vmm);

	for (i = 0; i < vmm->vmm_ncpu; i++)
		vm_vcpu_close(vmm->vmm_vcpu[i]);
	free(vmm->vmm_vcpu);

	list_destroy(&vmm->vmm_memlist);

	if (vmm->vmm_ctx != NULL)
		vm_close(vmm->vmm_ctx);

	free(vmm);
}

static vmm_memseg_t *
vmm_get_memseg(vmm_t *vmm, uintptr_t gpa)
{
	vmm_memseg_t ms, *ret;
	int error, flags;

	bzero(&ms, sizeof (vmm_memseg_t));
	ms.vms_gpa = gpa;
	error = vm_mmap_getnext(vmm->vmm_ctx, &ms.vms_gpa, &ms.vms_segid,
	    &ms.vms_segoff, &ms.vms_maplen, &ms.vms_prot, &flags);
	if (error)
		return (NULL);

	error = vm_get_memseg(vmm->vmm_ctx, ms.vms_segid, &ms.vms_seglen,
	    ms.vms_name, sizeof (ms.vms_name));
	if (error)
		return (NULL);

	/*
	 * Regular memory segments don't have a name, but devmem segments do.
	 * We can use that information to set the DEVMEM flag if necessary.
	 */
	ms.vms_flags = ms.vms_name[0] != '\0' ? VMM_MEMSEG_DEVMEM : 0;

	ret = malloc(sizeof (vmm_memseg_t));
	if (ret == NULL)
		return (NULL);

	*ret = ms;

	return (ret);
}

int
vmm_map(vmm_t *vmm, boolean_t writable)
{
	uintptr_t last_gpa = 0;
	vmm_memseg_t *ms;
	int prot_write = writable ? PROT_WRITE : 0;

	if (vmm->vmm_mem != MAP_FAILED) {
		errno = EINVAL;
		return (-1);
	}

	assert(list_is_empty(&vmm->vmm_memlist));

	for (;;) {
		ms = vmm_get_memseg(vmm, last_gpa);

		if (ms == NULL)
			break;

		last_gpa = ms->vms_gpa + ms->vms_maplen;
		list_insert_tail(&vmm->vmm_memlist, ms);
	}

	vmm->vmm_mem = mmap(NULL, last_gpa, PROT_NONE,
	    MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);

	if (vmm->vmm_mem == MAP_FAILED)
		goto fail;

	for (ms = list_head(&vmm->vmm_memlist);
	    ms != NULL;
	    ms = list_next(&vmm->vmm_memlist, ms)) {
		off_t mapoff;

		if ((ms->vms_flags & VMM_MEMSEG_DEVMEM) == 0) {
			/*
			 * sysmem segments will be located at an offset
			 * equivalent to their GPA.
			 */
			mapoff = ms->vms_gpa;
		} else {
			/*
			 * devmem segments are located in a special region away
			 * from the normal GPA space.
			 */
			if (vm_get_devmem_offset(vmm->vmm_ctx, ms->vms_segid,
			    &mapoff) != 0) {
				goto fail;
			}
		}

		/*
		 * While 'mapoff' points to the front of the segment, the actual
		 * mapping may be at some offset beyond that.
		 */
		VERIFY(ms->vms_segoff >= 0);
		mapoff += ms->vms_segoff;

		vmm->vmm_memsize += ms->vms_maplen;

		if (mmap(vmm->vmm_mem + ms->vms_gpa, ms->vms_maplen,
		    PROT_READ | prot_write, MAP_SHARED | MAP_FIXED,
		    vm_get_device_fd(vmm->vmm_ctx), mapoff) == MAP_FAILED)
			goto fail;
	}

	return (0);

fail:
	vmm_unmap(vmm);

	return (-1);
}

void
vmm_unmap(vmm_t *vmm)
{
	while (!list_is_empty(&vmm->vmm_memlist)) {
		vmm_memseg_t *ms = list_remove_head(&vmm->vmm_memlist);

		if (vmm->vmm_mem != MAP_FAILED) {
			(void) munmap(vmm->vmm_mem + ms->vms_gpa,
			    ms->vms_maplen);
		}

		free(ms);
	}

	if (vmm->vmm_mem != MAP_FAILED)
		(void) munmap(vmm->vmm_mem, vmm->vmm_memsize);

	vmm->vmm_mem = MAP_FAILED;
	vmm->vmm_memsize = 0;
}

ssize_t
vmm_pread(vmm_t *vmm, void *buf, size_t len, uintptr_t addr)
{
	ssize_t count = 0;
	vmm_memseg_t *ms;
	ssize_t res = len;

	for (ms = list_head(&vmm->vmm_memlist);
	    ms != NULL && len != 0;
	    ms = list_next(&vmm->vmm_memlist, ms)) {

		if (addr >= ms->vms_gpa &&
		    addr < ms->vms_gpa + ms->vms_maplen) {
			res = (addr + len) - (ms->vms_gpa + ms->vms_maplen);

			if (res < 0)
				res = 0;

			bcopy(vmm->vmm_mem + addr, buf, len - res);
			count += len - res;
			addr += len - res;
			len = res;
		}
	}

	if (res)
		errno = EFAULT;
	else
		errno = 0;

	return (count);
}

ssize_t
vmm_pwrite(vmm_t *vmm, const void *buf, size_t len, uintptr_t addr)
{
	ssize_t count = 0;
	vmm_memseg_t *ms;
	ssize_t res = len;

	for (ms = list_head(&vmm->vmm_memlist);
	    ms != NULL;
	    ms = list_next(&vmm->vmm_memlist, ms)) {
		if (addr >= ms->vms_gpa &&
		    addr < ms->vms_gpa + ms->vms_maplen) {
			res = (addr + len) - (ms->vms_gpa + ms->vms_maplen);

			if (res < 0)
				res = 0;

			bcopy(buf, vmm->vmm_mem + addr, len - res);
			count += len - res;
			addr += len - res;
			len = res;
		}
	}

	if (res)
		errno = EFAULT;
	else
		errno = 0;

	return (count);
}

size_t
vmm_ncpu(vmm_t *vmm)
{
	return (vmm->vmm_ncpu);
}

size_t
vmm_memsize(vmm_t *vmm)
{
	return (vmm->vmm_memsize);
}

int
vmm_cont(vmm_t *vmm)
{
	return (vm_resume_all_cpus(vmm->vmm_ctx));
}

int
vmm_step(vmm_t *vmm, int vcpuid)
{
	cpuset_t cpuset;
	int ret;

	if (vcpuid >= vmm->vmm_ncpu) {
		errno = EINVAL;
		return (-1);
	}

	ret = vm_set_capability(vmm->vmm_vcpu[vcpuid], VM_CAP_MTRAP_EXIT, 1);
	if (ret != 0)
		return (-1);

	assert(vm_resume_cpu(vmm->vmm_vcpu[vcpuid]) == 0);

	do {
		(void) vm_debug_cpus(vmm->vmm_ctx, &cpuset);
	} while (!CPU_ISSET(vcpuid, &cpuset));

	(void) vm_set_capability(vmm->vmm_vcpu[vcpuid], VM_CAP_MTRAP_EXIT, 0);

	return (ret);
}

int
vmm_stop(vmm_t *vmm)
{
	int ret = vm_suspend_all_cpus(vmm->vmm_ctx);

	if (ret == 0)
		vmm_update_ncpu(vmm);

	return (ret);
}

/*
 * Mapping of KDI-defined registers to vmmapi-defined registers.
 * Registers not known to vmmapi use VM_REG_LAST, which is invalid and
 * causes an error in vm_{get,set}_register_set().
 *
 * This array must be kept in sync with the definitions in kdi_regs.h.
 */
static int vmm_kdi_regmap[] = {
	VM_REG_LAST,		/* KDIREG_SAVFP */
	VM_REG_LAST,		/* KDIREG_SAVPC */
	VM_REG_GUEST_RDI,	/* KDIREG_RDI */
	VM_REG_GUEST_RSI,	/* KDIREG_RSI */
	VM_REG_GUEST_RDX,	/* KDIREG_RDX */
	VM_REG_GUEST_RCX,	/* KDIREG_RCX */
	VM_REG_GUEST_R8,	/* KDIREG_R8 */
	VM_REG_GUEST_R9,	/* KDIREG_R9 */
	VM_REG_GUEST_RAX,	/* KDIREG_RAX */
	VM_REG_GUEST_RBX,	/* KDIREG_RBX */
	VM_REG_GUEST_RBP,	/* KDIREG_RBP */
	VM_REG_GUEST_R10,	/* KDIREG_R10 */
	VM_REG_GUEST_R11,	/* KDIREG_R11 */
	VM_REG_GUEST_R12,	/* KDIREG_R12 */
	VM_REG_GUEST_R13,	/* KDIREG_R13 */
	VM_REG_GUEST_R14,	/* KDIREG_R14 */
	VM_REG_GUEST_R15,	/* KDIREG_R15 */
	VM_REG_LAST,		/* KDIREG_FSBASE */
	VM_REG_LAST,		/* KDIREG_GSBASE */
	VM_REG_LAST,		/* KDIREG_KGSBASE */
	VM_REG_GUEST_CR2,	/* KDIREG_CR2 */
	VM_REG_GUEST_CR3,	/* KDIREG_CR3 */
	VM_REG_GUEST_DS,	/* KDIREG_DS */
	VM_REG_GUEST_ES,	/* KDIREG_ES */
	VM_REG_GUEST_FS,	/* KDIREG_FS */
	VM_REG_GUEST_GS,	/* KDIREG_GS */
	VM_REG_LAST,		/* KDIREG_TRAPNO */
	VM_REG_LAST,		/* KDIREG_ERR */
	VM_REG_GUEST_RIP,	/* KDIREG_RIP */
	VM_REG_GUEST_CS,	/* KDIREG_CS */
	VM_REG_GUEST_RFLAGS,	/* KDIREG_RFLAGS */
	VM_REG_GUEST_RSP,	/* KDIREG_RSP */
	VM_REG_GUEST_SS		/* KDIREG_SS */
};
CTASSERT(ARRAY_SIZE(vmm_kdi_regmap) == KDIREG_NGREG);

/*
 * Mapping of libvmm-defined registers to vmmapi-defined registers.
 *
 * This array must be kept in sync with the definitions in libvmm.h
 */
static int vmm_sys_regmap[] = {
	VM_REG_GUEST_CR0,	/* VMM_REG_CR0 */
	VM_REG_GUEST_CR2,	/* VMM_REG_CR2 */
	VM_REG_GUEST_CR3,	/* VMM_REG_CR3 */
	VM_REG_GUEST_CR4,	/* VMM_REG_CR4 */
	VM_REG_GUEST_DR0,	/* VMM_REG_DR0 */
	VM_REG_GUEST_DR1,	/* VMM_REG_DR1 */
	VM_REG_GUEST_DR2,	/* VMM_REG_DR2 */
	VM_REG_GUEST_DR3,	/* VMM_REG_DR3 */
	VM_REG_GUEST_DR6,	/* VMM_REG_DR6 */
	VM_REG_GUEST_DR7,	/* VMM_REG_DR7 */
	VM_REG_GUEST_EFER,	/* VMM_REG_EFER */
	VM_REG_GUEST_PDPTE0,	/* VMM_REG_PDPTE0 */
	VM_REG_GUEST_PDPTE1,	/* VMM_REG_PDPTE1 */
	VM_REG_GUEST_PDPTE2,	/* VMM_REG_PDPTE2 */
	VM_REG_GUEST_PDPTE3,	/* VMM_REG_PDPTE3 */
	VM_REG_GUEST_INTR_SHADOW, /* VMM_REG_INTR_SHADOW */
};

/*
 * Mapping of libvmm-defined descriptors to vmmapi-defined descriptors.
 *
 * This array must be kept in sync with the definitions in libvmm.h
 */
static int vmm_descmap[] = {
	VM_REG_GUEST_GDTR,
	VM_REG_GUEST_LDTR,
	VM_REG_GUEST_IDTR,
	VM_REG_GUEST_TR,
	VM_REG_GUEST_CS,
	VM_REG_GUEST_DS,
	VM_REG_GUEST_ES,
	VM_REG_GUEST_FS,
	VM_REG_GUEST_GS,
	VM_REG_GUEST_SS
};

static int
vmm_mapreg(int reg)
{
	errno = 0;

	if (reg < 0)
		goto fail;

	if (reg < KDIREG_NGREG)
		return (vmm_kdi_regmap[reg]);

	if (reg >= VMM_REG_OFFSET &&
	    reg < VMM_REG_OFFSET + ARRAY_SIZE(vmm_sys_regmap))
		return (vmm_sys_regmap[reg - VMM_REG_OFFSET]);

fail:
	errno = EINVAL;
	return (VM_REG_LAST);
}

static int
vmm_mapdesc(int desc)
{
	errno = 0;

	if (desc >= VMM_DESC_OFFSET &&
	    desc < VMM_DESC_OFFSET + ARRAY_SIZE(vmm_descmap))
		return (vmm_descmap[desc - VMM_DESC_OFFSET]);

	errno = EINVAL;
	return (VM_REG_LAST);
}

int
vmm_getreg(vmm_t *vmm, int vcpuid, int reg, uint64_t *val)
{
	reg = vmm_mapreg(reg);

	if (reg == VM_REG_LAST)
		return (-1);

	return (vm_get_register(vmm->vmm_vcpu[vcpuid], reg, val));
}

int
vmm_setreg(vmm_t *vmm, int vcpuid, int reg, uint64_t val)
{
	reg = vmm_mapreg(reg);

	if (reg == VM_REG_LAST)
		return (-1);

	return (vm_set_register(vmm->vmm_vcpu[vcpuid], reg, val));
}

int
vmm_get_regset(vmm_t *vmm, int vcpuid, size_t nregs, const int *regnums,
    uint64_t *regvals)
{
	int *vm_regnums;
	int i;
	int ret = -1;

	vm_regnums = malloc(sizeof (int) * nregs);
	if (vm_regnums == NULL)
		return (ret);

	for (i = 0; i != nregs; i++) {
		vm_regnums[i] = vmm_mapreg(regnums[i]);
		if (vm_regnums[i] == VM_REG_LAST)
			goto fail;
	}

	ret = vm_get_register_set(vmm->vmm_vcpu[vcpuid], nregs, vm_regnums,
	    regvals);

fail:
	free(vm_regnums);
	return (ret);
}

int
vmm_set_regset(vmm_t *vmm, int vcpuid, size_t nregs, const int *regnums,
    uint64_t *regvals)
{
	int *vm_regnums;
	int i;
	int ret = -1;

	vm_regnums = malloc(sizeof (int) * nregs);
	if (vm_regnums == NULL)
		return (ret);

	for (i = 0; i != nregs; i++) {
		vm_regnums[i] = vmm_mapreg(regnums[i]);
		if (vm_regnums[i] == VM_REG_LAST)
			goto fail;
	}

	ret = vm_set_register_set(vmm->vmm_vcpu[vcpuid], nregs, vm_regnums,
	    regvals);

fail:
	free(vm_regnums);
	return (ret);
}

int
vmm_get_desc(vmm_t *vmm, int vcpuid, int desc, vmm_desc_t *vd)
{
	desc = vmm_mapdesc(desc);
	if (desc == VM_REG_LAST)
		return (-1);

	return (vm_get_desc(vmm->vmm_vcpu[vcpuid], desc, &vd->vd_base,
	    &vd->vd_lim,
	    &vd->vd_acc));
}

int
vmm_set_desc(vmm_t *vmm, int vcpuid, int desc, vmm_desc_t *vd)
{
	desc = vmm_mapdesc(desc);
	if (desc == VM_REG_LAST)
		return (-1);

	return (vm_set_desc(vmm->vmm_vcpu[vcpuid], desc, vd->vd_base,
	    vd->vd_lim, vd->vd_acc));
}

/*
 * Structure to hold MMU state during address translation.
 * The contents of vmm_mmu_regnum[] must be kept in sync with this.
 */
typedef struct vmm_mmu {
	uint64_t vm_cr0;
	uint64_t vm_cr3;
	uint64_t vm_cr4;
	uint64_t vm_efer;
} vmm_mmu_t;

static const int vmm_mmu_regnum[] = {
	VMM_REG_CR0,
	VMM_REG_CR3,
	VMM_REG_CR4,
	VMM_REG_EFER
};

#define	X86_PTE_P		0x001ULL
#define	X86_PTE_PS		0x080ULL

#define	X86_PTE_PHYSMASK	0x000ffffffffff000ULL
#define	X86_PAGE_SHIFT		12
#define	X86_PAGE_SIZE		(1ULL << X86_PAGE_SHIFT)

#define	X86_SEG_CODE_DATA	(1ULL << 4)
#define	X86_SEG_PRESENT		(1ULL << 7)
#define	X86_SEG_LONG		(1ULL << 13)
#define	X86_SEG_BIG		(1ULL << 14)
#define	X86_SEG_GRANULARITY	(1ULL << 15)
#define	X86_SEG_UNUSABLE	(1ULL << 16)

#define	X86_SEG_USABLE		(X86_SEG_PRESENT | X86_SEG_CODE_DATA)
#define	X86_SEG_USABLE_MASK	(X86_SEG_UNUSABLE | X86_SEG_USABLE)

/*
 * vmm_pte2paddr:
 *
 * Recursively calculate the physical address from a virtual address,
 * starting at the given PTE level using the given PTE.
 */
static int
vmm_pte2paddr(vmm_t *vmm, uint64_t pte, boolean_t ia32, int level,
    uint64_t vaddr, uint64_t *paddr)
{
	int pte_size = ia32 ? sizeof (uint32_t) : sizeof (uint64_t);
	int off_bits = ia32 ? 10 : 9;
	boolean_t hugepage = B_FALSE;
	uint64_t offset;
	uint64_t off_mask, off_shift;

	if (level < 4 && (pte & X86_PTE_P) == 0) {
		errno = EFAULT;
		return (-1);
	}

	off_shift = X86_PAGE_SHIFT + off_bits * level;
	off_mask = (1ULL << off_shift) - 1;

	offset = vaddr & off_mask;

	if ((level == 1 || level == 2) && (pte & X86_PTE_PS) != 0) {
		hugepage = B_TRUE;
	} else {
		if (level > 0) {
			offset >>= off_shift - off_bits;
			offset <<= X86_PAGE_SHIFT - off_bits;
		}
		off_mask = 0xfff;
	}

	*paddr = (pte & X86_PTE_PHYSMASK & ~off_mask) + offset;

	if (level == 0 || hugepage)
		return (0);

	pte = 0;
	if (vmm_pread(vmm, &pte,  pte_size, *paddr) != pte_size)
		return (-1);
	return (vmm_pte2paddr(vmm, pte, ia32, level - 1, vaddr, paddr));
}

static vmm_mode_t
vmm_vcpu_mmu_mode(vmm_t *vmm, int vcpuid __unused, vmm_mmu_t *mmu)
{
	if ((mmu->vm_cr0 & CR0_PE) == 0)
		return (VMM_MODE_REAL);
	else if ((mmu->vm_cr4 & CR4_PAE) == 0)
		return (VMM_MODE_PROT);
	else if ((mmu->vm_efer & AMD_EFER_LME) == 0)
		return (VMM_MODE_PAE);
	else
		return (VMM_MODE_LONG);
}

vmm_mode_t
vmm_vcpu_mode(vmm_t *vmm, int vcpuid)
{
	vmm_mmu_t mmu = { 0 };

	if (vmm_get_regset(vmm, vcpuid, ARRAY_SIZE(vmm_mmu_regnum),
	    vmm_mmu_regnum, (uint64_t *)&mmu) != 0)
		return (VMM_MODE_UNKNOWN);

	return (vmm_vcpu_mmu_mode(vmm, vcpuid, &mmu));
}

vmm_isa_t
vmm_vcpu_isa(vmm_t *vmm, int vcpuid)
{
	vmm_desc_t cs;

	if (vmm_get_desc(vmm, vcpuid, VMM_DESC_CS, &cs) != 0)
		return (VMM_ISA_UNKNOWN);

	switch (cs.vd_acc & (X86_SEG_BIG | X86_SEG_LONG)) {
	case 0x0:		/* 16b code segment */
		return (VMM_ISA_16);
	case X86_SEG_LONG:	/* 64b code segment */
		return (VMM_ISA_64);
	case X86_SEG_BIG:	/* 32b code segment */
		return (VMM_ISA_32);
	}

	return (VMM_ISA_UNKNOWN);
}

/*
 * vmm_vtol:
 *
 * Translate a virtual address to a physical address on a certain vCPU,
 * using the specified segment register or descriptor according to the mode.
 *
 */
int
vmm_vtol(vmm_t *vmm, int vcpuid, int seg, uint64_t vaddr, uint64_t *laddr)
{
	vmm_desc_t desc;
	uint64_t limit;

	if (vmm_get_desc(vmm, vcpuid, seg, &desc) != 0)
		return (-1);

	switch (vmm_vcpu_mode(vmm, vcpuid)) {
	case VMM_MODE_REAL:
		if (seg == VMM_DESC_FS || seg == VMM_DESC_GS)
			goto fault;
		/* FALLTHRU */
	case VMM_MODE_PROT:
	case VMM_MODE_PAE:
		if ((desc.vd_acc & X86_SEG_USABLE_MASK) != X86_SEG_USABLE)
			/* unusable, system segment, or not present */
			goto fault;

		limit = desc.vd_lim;
		if (desc.vd_acc & X86_SEG_GRANULARITY)
			limit *= 4096;

		if (vaddr > limit)
			goto fault;
		/* FALLTHRU */
	case VMM_MODE_LONG:
		*laddr = desc.vd_base + vaddr;
		return (0);

	default:
	fault:
		errno = EFAULT;
		return (-1);
	}

}

/*
 * vmm_vtop:
 *
 * Translate a virtual address to a guest physical address on a certain vCPU,
 * according to the mode the vCPU is in.
 */
int
vmm_vtop(vmm_t *vmm, int vcpuid, int seg, uint64_t vaddr, uint64_t *paddr)
{
	vmm_mmu_t mmu = { 0 };
	int ret = 0;

	if (vmm_vtol(vmm, vcpuid, seg, vaddr, &vaddr) != 0)
		return (-1);

	if (vmm_get_regset(vmm, vcpuid, ARRAY_SIZE(vmm_mmu_regnum),
	    vmm_mmu_regnum, (uint64_t *)&mmu) != 0)
		return (-1);

	if ((mmu.vm_cr0 & CR0_PG) == 0) {
		/* no paging, physical equals virtual */
		*paddr = vaddr;
		return (0);
	}

	switch (vmm_vcpu_mmu_mode(vmm, vcpuid, &mmu)) {
	case VMM_MODE_PROT:
		/* protected mode, no PAE: 2-level paging, 32bit PTEs */
		ret = vmm_pte2paddr(vmm, mmu.vm_cr3, B_TRUE, 2, vaddr, paddr);
		break;
	case VMM_MODE_PAE:
		/* protected mode with PAE: 3-level paging, 64bit PTEs */
		ret = vmm_pte2paddr(vmm, mmu.vm_cr3, B_FALSE, 3, vaddr, paddr);
		break;
	case VMM_MODE_LONG:
		/* long mode: 4-level paging, 64bit PTEs */
		ret = vmm_pte2paddr(vmm, mmu.vm_cr3, B_FALSE, 4, vaddr, paddr);
		break;
	default:
		ret = -1;
	}

	return (ret);
}

ssize_t
vmm_vread(vmm_t *vmm, int vcpuid, int seg, void *buf, size_t len, uintptr_t
    addr)
{
	ssize_t res = 0;
	uint64_t paddr;
	size_t plen;
	uint64_t boundary;

	while (len != 0) {
		if (vmm_vtop(vmm, vcpuid, seg, addr, &paddr) != 0) {
			errno = EFAULT;
			return (0);
		}

		boundary = (addr + X86_PAGE_SIZE) & ~(X86_PAGE_SIZE - 1);
		if (addr + len > boundary)
			plen = boundary - addr;
		else
			plen = len;

		if (vmm_pread(vmm, buf, plen, paddr) != plen)
			return (0);
		len -= plen;
		addr += plen;
		buf += plen;
		res += plen;
	}

	return (res);
}

ssize_t
vmm_vwrite(vmm_t *vmm, int vcpuid, int seg, const void *buf, size_t len,
    uintptr_t addr)
{
	ssize_t res = 0;
	uint64_t paddr;
	size_t plen;
	uint64_t boundary;

	while (len != 0) {
		if (vmm_vtop(vmm, vcpuid, seg, addr, &paddr) != 0) {
			errno = EFAULT;
			return (0);
		}

		boundary = (addr + X86_PAGE_SIZE) & ~(X86_PAGE_SIZE - 1);
		if (addr + len > boundary)
			plen = boundary - addr;
		else
			plen = len;

		if (vmm_pwrite(vmm, buf, plen, paddr) != plen)
			return (0);
		len -= plen;
		addr += plen;
		buf += plen;
		res += plen;
	}

	return (res);
}
