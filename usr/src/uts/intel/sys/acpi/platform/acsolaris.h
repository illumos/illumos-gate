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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ACSOLARIS_H_
#define	_ACSOLARIS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/varargs.h>
#include <sys/cpu.h>

#define	strtoul simple_strtoul

uint32_t __acpi_acquire_global_lock(void *);
uint32_t __acpi_release_global_lock(void *);
void	 __acpi_wbinvd(void);

#ifdef	_ILP32
#define	ACPI_MACHINE_WIDTH	32
#elif	defined(_LP64)
#define	ACPI_MACHINE_WIDTH	64
#endif

#define	COMPILER_DEPENDENT_INT64	int64_t
#define	COMPILER_DEPENDENT_UINT64	uint64_t

#define	ACPI_THREAD_ID		kt_did_t

#define	ACPI_PRINTF_LIKE_FUNC
#define	ACPI_UNUSED_VAR
#define	ACPI_USE_NATIVE_DIVIDE
#define	ACPI_FLUSH_CPU_CACHE()	(__acpi_wbinvd())

#define	ACPI_DISASSEMBLER
#define	ACPI_PACKED_POINTERS_NOT_SUPPORTED

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
#define	ACPI_ACQUIRE_GLOBAL_LOCK(Facs, Acq)	\
	((Acq) = __acpi_acquire_global_lock(Facs))

#define	ACPI_RELEASE_GLOBAL_LOCK(Facs, Acq)	\
	((Acq) = __acpi_release_global_lock(Facs))

#ifdef __cplusplus
}
#endif

#endif /* _ACSOLARIS_H_ */
