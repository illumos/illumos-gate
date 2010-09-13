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

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>

#if defined(lint) || defined(__lint)
#include <sys/types.h>
#include "acpi.h"
#endif	/* lint */

/*
 * Implementation as specific by ACPI 3.0 specification
 * section 5.2.10.1
 *
 * Global Lock Structure within the FACS 
 *
 * |-----------------------------------------------------------------------| 
 * |  Field  | Bit Length | Bit Offset |           Description             |
 * |---------|------------|------------|-----------------------------------| 
 * | Pending |     1      |     0      | Non-zero indicates that a request |
 * |         |            |            | for ownership of the global lock  |
 * |         |            |            | is pending.                       |
 * |---------|------------|------------|-----------------------------------| 
 * | Owned   |     1      |     1      | Non-zero indicates that the Global|
 * |         |            |            | lock is owned.                    |
 * |---------|------------|------------|-----------------------------------| 
 * | Reserved|     30     |     2      | Reserved for future use           |
 * |---------|------------|------------|-----------------------------------| 
 */

/* Offset of GlobalLock element in FACS structure */
#define	GlobalLock	0x10

#if defined(lint) || defined(__lint)

/* ARGSUSED */
UINT32
__acpi_acquire_global_lock(void *Facs)
{ return (0); }

#else	/* lint */

#if defined(__amd64)
	ENTRY(__acpi_acquire_global_lock)
	movq	$0xff, %rax		/ error return if FACS is null
	orq	%rdi, %rdi		/ %rdi contains pointer to FACS
	jz	1f
	leaq	GlobalLock(%rdi), %rdi	/ make %rdi point at the lock
0:
	movl	(%rdi), %eax		/ get current value of Global Lock
	movl	%eax, %edx
	andl	$0xFFFFFFFE, %edx	/ Clear pending bit
	btsl	$1, %edx		/ Check and set owner bit
	adcl	$0, %edx		/ If owned, set pending bit
	lock
	cmpxchgl %edx, (%rdi)		/ Attempt to set new value
	jnz	0b			/ If not set, try again
	cmpb	$3, %dl			/ Was it acquired or marked pending?
	sbbq	%rax, %rax		/ acquired = -1, pending = 0
1:
	ret
	SET_SIZE(__acpi_acquire_global_lock)

#elif defined(__i386)

	ENTRY(__acpi_acquire_global_lock)
	movl	$0xff, %eax		/ error return if FACS is null
	movl	4(%esp), %ecx		/ %ecx contains pointer to FACS
	orl	%ecx, %ecx
	jz	1f
	leal	GlobalLock(%ecx), %ecx	/ make %ecx point at the lock
0:
	movl	(%ecx), %eax
	movl	%eax, %edx
	andl	$0xFFFFFFFE, %edx
	btsl	$1, %edx
	adcl	$0, %edx
	lock
	cmpxchgl %edx, (%ecx)
	jnz	0b
	cmpb	$3, %dl
	sbbl	%eax, %eax
1:
	ret
	SET_SIZE(__acpi_acquire_global_lock)

#endif	/* i386 */

#endif	/* lint */


#if defined(lint) || defined(__lint)

/* ARGSUSED */
UINT32
__acpi_release_global_lock(void *Facs)
{ return (0); }

#else	/* lint */

#if defined(__amd64)
	ENTRY(__acpi_release_global_lock)
	xorq	%rax, %rax	/ error return if FACS is null
	orq	%rdi, %rdi	/ %rdi contains pointer to FACS
	jz	1f
	leaq	GlobalLock(%rdi), %rdi	/ make %rdi point at the lock
0:
	movl	(%rdi), %eax
	movl	%eax, %edx
	andl	$0xFFFFFFFC, %edx
	lock
	cmpxchgl %edx, (%rdi)
	jnz	0b
	andq	$1, %rax
1:
	ret
	SET_SIZE(__acpi_release_global_lock)

#elif defined(__i386)

	ENTRY(__acpi_release_global_lock)
	xorl	%eax, %eax		/ error return if FACS is null
	movl	4(%esp), %ecx		/ %ecx contains pointer to FACS
	orl	%ecx, %ecx
	jz	1f
	leal	GlobalLock(%ecx), %ecx	/ make %ecx point at the lock
0:
	movl	(%ecx), %eax
	movl	%eax, %edx
	andl	$0xFFFFFFFC, %edx
	lock
	cmpxchgl %edx, (%ecx)
	jnz	0b
	andl	$1, %eax
1:
	ret
	SET_SIZE(__acpi_release_global_lock)

#endif	/* i386 */

#endif	/* lint */


/*
 * execute WBINVD instruction
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
void
__acpi_wbinvd(void)
{ }

#else	/* lint */

	ENTRY(__acpi_wbinvd)
	wbinvd
	ret
	SET_SIZE(__acpi_wbinvd)

#endif	/* lint */

