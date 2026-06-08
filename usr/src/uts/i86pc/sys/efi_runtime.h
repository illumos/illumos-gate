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
 * Copyright 2026 Argo Technology East
 */

/*
 * Private kernel-internal API for the efi(4D) driver.
 *
 * efi_pt_t is a freestanding amd64 4-level page table whose high half
 * is a snapshot of the kernel's PML4 (so kernel virtual addresses
 * keep working after CR3 is loaded with this table) and whose low
 * half holds 1:1 identity mappings for the EFI runtime ranges.
 * Switching CR3 to efi_pt_root_pa() lets the CPU dispatch through
 * Runtime Services function pointers that hold physical addresses,
 * while leaving kernel code, data and the current thread's stack
 * still reachable.
 */

#ifndef	_SYS_EFI_RUNTIME_H
#define	_SYS_EFI_RUNTIME_H

#include <sys/types.h>
#include <sys/efi.h>
#include <sys/uuid.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * UEFI calls use the Microsoft x64 calling convention (rcx, rdx, r8,
 * r9, ...).  Mark every Runtime Services function pointer so the
 * compiler emits the correct prologue at the call site.
 */
#if defined(__x86_64__) || defined(__amd64)
#define	EFIAPI	__attribute__((ms_abi))
#else
#define	EFIAPI
#endif

/*
 * Subset of UEFI types we need to talk to Runtime Services.  Names
 * mirror the UEFI 2.10 specification.
 */
typedef uintptr_t	EFI_STATUS;
typedef uint16_t	CHAR16;
typedef uint64_t	UINTN;
typedef struct uuid	EFI_GUID;

#define	EFI_ERROR(s)		(((EFI_STATUS)(s) >> 63) != 0)
#define	EFI_SUCCESS		((EFI_STATUS)0)

/*
 * Status codes used by Variable Services.  Numeric values come from
 * Appendix D of the UEFI 2.10 specification (high bit set marks
 * errors).
 */
#define	EFI_INVALID_PARAMETER	(((EFI_STATUS)1 << 63) | 2)
#define	EFI_BUFFER_TOO_SMALL	(((EFI_STATUS)1 << 63) | 5)
#define	EFI_DEVICE_ERROR	(((EFI_STATUS)1 << 63) | 7)
#define	EFI_WRITE_PROTECTED	(((EFI_STATUS)1 << 63) | 8)
#define	EFI_OUT_OF_RESOURCES	(((EFI_STATUS)1 << 63) | 9)
#define	EFI_NOT_FOUND		(((EFI_STATUS)1 << 63) | 14)
#define	EFI_SECURITY_VIOLATION	(((EFI_STATUS)1 << 63) | 26)

/* BEGIN CSTYLED */
typedef EFI_STATUS (EFIAPI *EFI_GET_VARIABLE)(CHAR16 *, EFI_GUID *,
    uint32_t *, UINTN *, void *);
typedef EFI_STATUS (EFIAPI *EFI_GET_NEXT_VARIABLE_NAME)(UINTN *, CHAR16 *,
    EFI_GUID *);
typedef EFI_STATUS (EFIAPI *EFI_SET_VARIABLE)(CHAR16 *, EFI_GUID *,
    uint32_t, UINTN, void *);
/* END CSTYLED */

/*
 * EFI Runtime Services Table (UEFI 2.10, section 4.5).  We only need
 * to call into Variable Services, but the layout above the variable
 * pointers must be preserved so the offsets line up with what the
 * firmware published.  Untyped pointers are used for the entries we
 * never invoke.
 */
typedef struct efi_runtime_services {
	EFI_TABLE_HEADER	rs_hdr;
	void			*rs_get_time;
	void			*rs_set_time;
	void			*rs_get_wakeup_time;
	void			*rs_set_wakeup_time;
	void			*rs_set_virtual_address_map;
	void			*rs_convert_pointer;
	EFI_GET_VARIABLE	rs_get_variable;
	EFI_GET_NEXT_VARIABLE_NAME rs_get_next_variable_name;
	EFI_SET_VARIABLE	rs_set_variable;
	void			*rs_get_next_high_monotonic_count;
	void			*rs_reset_system;
	void			*rs_update_capsule;
	void			*rs_query_capsule_capabilities;
	void			*rs_query_variable_info;
} efi_runtime_services_t;

typedef struct efi_pt efi_pt_t;

/*
 * Page table lifecycle.
 *
 * efi_pt_create() allocates a new PML4, copies the kernel half of the
 * current CR3 into entries 256..511 and returns 0.  efi_pt_destroy()
 * releases the PML4 along with every PDPT/PD/PT page that was added
 * via efi_pt_map().
 */
extern int efi_pt_create(efi_pt_t **);
extern void efi_pt_destroy(efi_pt_t *);

/*
 * Identity-map [pa, pa + size) into the table with the supplied PTE
 * permission flags (PT_WRITABLE, PT_NX, ...).  PT_VALID is always
 * applied; pa and size are rounded to PAGESIZE.  Returns 0 or an errno.
 */
extern int efi_pt_map(efi_pt_t *, paddr_t pa, size_t size, uint64_t flags);

/*
 * Walk the EFI memory map exposed by fakebop on the root node
 * (properties "efi-mmap" / "efi-mmap-descsize") and add an identity
 * mapping for every descriptor that carries the EFI_MEMORY_RUNTIME
 * attribute.  Returns 0 on success, ENOENT if the property is missing,
 * or EINVAL/ENOMEM as appropriate.  *nrangesp is set to the number of
 * ranges that were actually mapped.
 */
extern int efi_pt_apply_mmap(efi_pt_t *, uint_t *nrangesp);

/*
 * Physical address suitable for setcr3().
 */
extern paddr_t efi_pt_root_pa(const efi_pt_t *);

/*
 * Invoke a Runtime Services function via the alternate page table.
 * Around the call the wrapper masks interrupts, claims the FPU for
 * kernel use (UEFI is allowed to touch SSE/AVX state), saves the
 * current CR3 and reloads it from the supplied efi_pt_t.  These
 * routines are the only sanctioned way for the rest of the driver to
 * dispatch into firmware.
 */
extern EFI_STATUS efi_call_get_variable(efi_pt_t *, efi_runtime_services_t *,
    CHAR16 *name, EFI_GUID *vendor, uint32_t *attrib, UINTN *datasize,
    void *data);

extern EFI_STATUS efi_call_get_next_variable_name(efi_pt_t *,
    efi_runtime_services_t *, UINTN *namesize, CHAR16 *name, EFI_GUID *vendor);

extern EFI_STATUS efi_call_set_variable(efi_pt_t *, efi_runtime_services_t *,
    CHAR16 *name, EFI_GUID *vendor, uint32_t attrib, UINTN datasize,
    void *data);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_EFI_RUNTIME_H */
