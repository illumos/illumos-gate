/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef __ACSOLARIS_H__
#define	__ACSOLARIS_H__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/varargs.h>
#include <sys/cpu.h>

#define	strtoul simple_strtoul

uint32_t __acpi_acquire_global_lock(uint32_t *);
uint32_t __acpi_release_global_lock(uint32_t *);
void	 __acpi_wbinvd(void);

#ifdef	_ILP32
#define	ACPI_MACHINE_WIDTH	32
#elif	defined(_LP64)
#define	ACPI_MACHINE_WIDTH	64
#endif

#define	COMPILER_DEPENDENT_INT64	int64_t
#define	COMPILER_DEPENDENT_UINT64	uint64_t

#define	ACPI_PRINTF_LIKE_FUNC
#define	ACPI_UNUSED_VAR
#define	ACPI_USE_NATIVE_DIVIDE
#define	ACPI_FLUSH_CPU_CACHE()	(__acpi_wbinvd())

/*
 * Calling conventions:
 *
 * ACPI_SYSTEM_XFACE        - Interfaces to host OS (handlers, threads)
 * ACPI_EXTERNAL_XFACE      - External ACPI interfaces
 * ACPI_INTERNAL_XFACE      - Internal ACPI interfaces
 * ACPI_INTERNAL_VAR_XFACE  - Internal variable-parameter list interfaces
 */
#define	ACPI_SYSTEM_XFACE
#define	ACPI_EXTERNAL_XFACE
#define	ACPI_INTERNAL_XFACE
#define	ACPI_INTERNAL_VAR_XFACE

#define	ACPI_ASM_MACROS
#define	BREAKPOINT3
#define	ACPI_DISABLE_IRQS()	cli()
#define	ACPI_ENABLE_IRQS()	sti()
#define	ACPI_ACQUIRE_GLOBAL_LOCK(GLptr, Acq)	\
	((Acq) = __acpi_acquire_global_lock(GLptr))

#define	ACPI_RELEASE_GLOBAL_LOCK(GLptr, Acq)	\
	((Acq) = __acpi_release_global_lock(GLptr))

#ifdef __cplusplus
}
#endif

#endif /* __ACSOLARIS_H__ */
