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
 */

#ifndef _LIBVMM_H
#define	_LIBVMM_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vmm vmm_t;

typedef struct vmm_desc {
	uint64_t vd_base;
	uint32_t vd_lim;
	uint32_t vd_acc;
} vmm_desc_t;


/*
 * This enum must be kept in sync with vmm_sys_regmap[] in libvmm.c.
 */
#define	VMM_REG_OFFSET	0x100
enum vmm_regs {
	VMM_REG_CR0 = VMM_REG_OFFSET,
	VMM_REG_CR2,
	VMM_REG_CR3,
	VMM_REG_CR4,
	VMM_REG_DR0,
	VMM_REG_DR1,
	VMM_REG_DR2,
	VMM_REG_DR3,
	VMM_REG_DR6,
	VMM_REG_DR7,
	VMM_REG_EFER,
	VMM_REG_PDPTE0,
	VMM_REG_PDPTE1,
	VMM_REG_PDPTE2,
	VMM_REG_PDPTE3,
	VMM_REG_INTR_SHADOW
};

/*
 * This enum must be kept in sync with vmm_descmap[] in libvmm.c.
 */
#define	VMM_DESC_OFFSET	0x200
enum vmm_descs {
	VMM_DESC_GDTR = VMM_DESC_OFFSET,
	VMM_DESC_LDTR,
	VMM_DESC_IDTR,
	VMM_DESC_TR,
	VMM_DESC_CS,
	VMM_DESC_DS,
	VMM_DESC_ES,
	VMM_DESC_FS,
	VMM_DESC_GS,
	VMM_DESC_SS
};

typedef enum {
	VMM_MODE_UNKNOWN = 0,
	VMM_MODE_REAL,
	VMM_MODE_PROT,
	VMM_MODE_PAE,
	VMM_MODE_LONG
} vmm_mode_t;

typedef enum {
	VMM_ISA_UNKNOWN = 0,
	VMM_ISA_16,
	VMM_ISA_32,
	VMM_ISA_64
} vmm_isa_t;

vmm_t *vmm_open_vm(const char *);
void vmm_close_vm(vmm_t *);

int vmm_map(vmm_t *, boolean_t);
void vmm_unmap(vmm_t *);

ssize_t vmm_pread(vmm_t *, void *, size_t, uintptr_t);
ssize_t vmm_pwrite(vmm_t *, const void *, size_t, uintptr_t);
ssize_t vmm_vread(vmm_t *, int, int, void *, size_t, uintptr_t);
ssize_t vmm_vwrite(vmm_t *, int, int, const void *, size_t, uintptr_t);

size_t vmm_ncpu(vmm_t *);
size_t vmm_memsize(vmm_t *);

int vmm_cont(vmm_t *);
int vmm_step(vmm_t *, int);
int vmm_stop(vmm_t *);

int vmm_getreg(vmm_t *, int, int, uint64_t *);
int vmm_setreg(vmm_t *, int, int, uint64_t);
int vmm_get_regset(vmm_t *, int, size_t, const int *, uint64_t *);
int vmm_set_regset(vmm_t *, int, size_t, const int *, uint64_t *);

int vmm_get_desc(vmm_t *, int, int, vmm_desc_t *);
int vmm_set_desc(vmm_t *, int, int, vmm_desc_t *);

vmm_mode_t vmm_vcpu_mode(vmm_t *, int);
vmm_isa_t vmm_vcpu_isa(vmm_t *, int);
int vmm_vtol(vmm_t *, int, int, uint64_t, uint64_t *);
int vmm_vtop(vmm_t *, int, int, uint64_t, uint64_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBVMM_H */
