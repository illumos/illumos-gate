/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/regset.h>
#include <sys/psw.h>
#include <sys/privregs.h>
#include "../common/cpu_id.h"

#ifdef	__lint
int is486(void) { return (1); }
#else

	.file   "cpu_id.s"

	.ident	"%Z%%M%	%I%	%E% SMI"

	.text

/       We only support 486 or better. So just return 1.

	.globl  is486
is486:
	movl	$1, %eax
	ret

#endif	/* !lint */

#ifdef	lint
/*
 * Enable cpuid. Set max_std_cpuid_level and cpu_vendor appropriately. Returns
 * 1 if cpuid present and enabled, 0 otherwise.
 */
int enable_cpuid(void) { return(1); }
int max_std_cpuid_level; 
unsigned int cpu_vendor; 
#else
	.text
	.globl	enable_cpuid
enable_cpuid:
	/ Since no documented Cyrix cpu supports PSE, we do not care about
	/ enabling cpuid, yet. This routine is currently only responsible
	/ for setting max_std_cpuid_level and cpu_vendor.
	pushl	%esp
	pushfl
	popl	%eax
	movl	%eax, %ecx
	xorl	$PS_ID, %eax
	pushl	%eax
	popfl
	pushfl
	popl	%eax		/ The above all lifted from locore.s
	cmpl	%eax, %ecx
	jne	has_it
	movl	$0, %eax	/ cpuid is not present or enabled
	jmp	enable_cpuid_out
has_it:
	/ store maxium standard cpuid level
	movl	$0, %eax
	cpuid
	movl	%eax, max_std_cpuid_level

	/ check to see if we are a GenuineIntel
	cmpl	$Genu, %ebx
	jne	not_intel
	cmpl	$ineI, %edx
	jne	not_intel
	cmpl	$ntel, %ecx
	jne	not_intel
	movl	$GenuineIntel, cpu_vendor
	jmp	vendor_done
not_intel:
	/ check to see if we are an AuthenticAMD
	cmpl	$Auth, %ebx
	jne	not_amd
	cmpl	$enti, %edx
	jne	not_amd
	cmpl	$cAMD, %ecx
	jne	not_amd
	movl	$AuthenticAMD, cpu_vendor
not_amd:
vendor_done:
	movl	$1, %eax	/ cpuid present and enabled
enable_cpuid_out:
	popl	%esp
	ret

	.data
	.align	4
	.globl	max_std_cpuid_level
	.globl	cpu_vendor
max_std_cpuid_level:	.long 0xffffffff
cpu_vendor:		.long 0
#endif

#ifdef	lint
int largepage_supported(void) { return(1); }
#else
	.text
	.globl	largepage_supported
largepage_supported:
	pushl	%esp		/ save our stack value

	/ test to see if cpuid level 1 supported
	cmpl	$1, max_std_cpuid_level
	jl	no

	/ are we a vendor for which we know how to test for PSE
	testl	$[GenuineIntel|AuthenticAMD], cpu_vendor
	jz	no

	movl	$1, %eax	/ capability test. Mov 1 to eax for cpuid
	cpuid
	andl	$0x8, %edx 	/ do you have large pages?
	jz	no
	movl	$1, %eax	/ yes we do have large pages
	popl	%esp
	ret
no:	
	movl	$0, %eax	/ no we don't have large pages
	popl	%esp
	ret
#endif

#ifdef	lint
int enable_large_pages(void) { return(1); }
#else
	.text
	.globl	enable_large_pages
enable_large_pages:
	movl	%cr4, %eax
	orl	$CR4_PSE, %eax / since we have large pages enable them
	movl	%eax, %cr4
#endif

#ifdef	lint
int global_bit(void) { return(1); }
#else
	.text
	.globl	global_bit
global_bit:
	pushl	%esp		/ save our stack value

	/ test to see if cpuid level 1 supported
	cmpl	$1, max_std_cpuid_level
	jl	nogbit

	/ are we a vendor for which we know how to test for PGE
	testl	$[GenuineIntel|AuthenticAMD], cpu_vendor
	jz	nogbit

	movl	$1, %eax	/ capability test. Mov 1 to eax for cpuid
	cpuid

	/ are we an AMD
	testl	$AuthenticAMD, cpu_vendor
	jz	pge_at_13

	/ test to see if we are an AMD-K5 model 0
	andw	$0xff0, %ax
	cmpw	$0x500, %ax
	jl	nogbit
	jne	pge_at_13

	/ we are an AMD-K5 model 0, so GPE is at bit 9
	testl	$0x200, %edx 	/ do you have GPE?
	jmp	test_pge

pge_at_13:
	testl	$0x2000, %edx 	/ do you have PGE?
test_pge:
	jnz	hasgbit
nogbit:
	movl	$0, %eax	/ no we don't have global pdtes
	jmp	global_bit_out
hasgbit:
	movl	$1, %eax	/ yes we do have global pdtes
global_bit_out:
	popl	%esp
	ret
#endif

#ifdef	lint
int enable_global_pages(void) { return(1); }
#else
	.text
	.globl	enable_global_pages
enable_global_pages:
	movl	%cr4, %eax
	orl	$CR4_PGE, %eax / since we have global pages enable them
	movl	%eax, %cr4
#endif

#ifdef	lint
int pae_supported(void) { return (1); }
#else
.set PAE_AND_CXS, 0x140		/ PAE = 0x40 & CXS = 0x100

	.text
	.globl	pae_supported
pae_supported:
	pushl	%esp		/ save our stack value

	/ test to see if cpuid level 1 supported
	cmpl	$1, max_std_cpuid_level
	jl	nopae

	/ are we a vendor for which we know how to test for PAE and CXS
	testl	$[GenuineIntel|AuthenticAMD], cpu_vendor
	jz	nopae

	movl	$1, %eax	/ capability test. Mov 1 to eax for cpuid
	cpuid
	andl	$PAE_AND_CXS, %edx 	/ do you support pae and cmpxchg8b?
	cmpl	$PAE_AND_CXS, %edx
	jne	nopae
	movl	$1, %eax	/ yes we do support pae and cmpxchg8b
	popl	%esp
	ret
nopae:
	movl	$0, %eax	/ no we don't support pae and cmpxchg8b
	popl	%esp
	ret
#endif
