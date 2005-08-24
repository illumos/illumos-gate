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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>

/*
 * biosint.s - installed by kernel to make bios calls
 * 
 * The kernel jumps here from protected mode to make a bios service call.
 * Calling syntax:	bios_doint(int intnum, struct int_pb *ic)
 */
	.globl	_start
_start:
	pushl	%ebp
	movl	%esp, %ebp

	/ Save segment registers of caller.
	movw	%cs, call_cs 
	movw    %ds, call_ds
	movw    %es, call_es
	movw    %fs, call_fs
	movw    %gs, call_gs
	movw    %ss, call_ss
	movl	%esp, call_esp
	movl	%esi, call_esi
	movl	%ebx, call_ebx
	movl	%ecx, call_ecx
	movl	%edx, call_edx
	movl	%edi, call_edi
	/
	/ We need to save cr0 here and restore it after we return
	/ from BIOS call to avoid unexpectedly modification to cr0
	/ by the buggy firmware of some storage HBAs
	/
	movl	%cr0, %eax
	movl	%eax, call_cr0

	/ switch stack to 0x5000
	movl    $0x5000, %eax
	movl	%eax, %esp
	jmp     donelowstack
donelowstack:

	/ copy args from high memory to low memory
	pushl	12(%ebp)
	pushl   8(%ebp)
	call	copyin_args
	addl	$8, %esp

	/ insert proper interrupt for later.
	movl    ic_int, %eax
	movb    %al, newintcode+1

	/ Jump here for P5 94 byte instruction prefetch queue
	jmp     qflush1
qflush1:

	/ call	print_regs

	/ Switch interrupt descriptor tables.
	cli
	sidt    kernIDTptr
	lidt    bioIDTptr

	/ Save global descriptor table
	sgdt    kernGDTptr

	call    goreal

/
/ NOW in REAL MODE
/
	/ Clear the upper (extended) half of all registers.
	/ Having stray high bits on causes strange
	/ and unpredictable failures to occur in real mode.
	/
	D16		xorl %eax, %eax
		A16	movw ic_ds, %ax
			push %eax		/ save for later
	D16	A16	movw ic_ax, %ax
	D16		xorl %ebx, %ebx
		A16	mov ic_bx, %ebx
	D16		xorl %ecx, %ecx
		A16	mov ic_cx, %ecx
	D16		xorl %edx, %edx
		A16	mov ic_dx, %edx
	D16		xorl %ebp, %ebp
		A16	mov ic_bp, %ebp
	D16		xorl %edi,%edi
		A16	mov ic_di, %edi
	D16		xorl %esi,%esi
		A16	mov ic_si, %esi
		A16	movw ic_es, %es

			sti
		A16	pop %ds			/ set effective ds
newintcode:
 			int	$0x10		/ do BIOS call
			cli
			pushf			/ save carry for later

	/ save results of the BIOS call
	/
	A16		movw %ax, ic_ax
	A16		movw %bx, ic_bx
	A16		movw %cx, ic_cx
	A16		movw %dx, ic_dx
	A16		movw %bp, ic_bp
	A16		movw %si, ic_si
	A16		movw %di, ic_di
	A16		movw %ds, ic_ds		/ real mode - stack 2-bytes word
	A16		movw %es, ic_es

	D16		movw    %cs, %ax
			movw    %ax, %ds       / restore entry ds, es
			movw    %ax, %es

	D16	 call    goprot	  / protect mode

/
/ NOW back in PROTECTED MODE.
/
	/ copy results to caller's location
	movl	call_esp, %eax
	pushl	12(%eax)
	call	copyout_args
	addl	$4, %esp

	xorl	%eax, %eax	/ initialize return to zero
	popw	%ax		/ get eflags

	/ Interrupt descriptor table
	lidt    kernIDTptr

	/ Returned from BIOS call, restore cr0 here
	movl	call_cr0, %edx
	movl	%edx, %cr0
	movl    call_edx, %edx
	movl    call_ecx, %ecx
	movl    call_ebx, %ebx
	movl    call_edi, %edi
	movl    call_esi, %esi

	/ switch back to caller's stack
	movl    call_esp, %esp
	popl	%ebp
	ret

/ ----------------------------------------------------
/ Enter real mode.
/
/ Real mode GDT descriptors are always present as code 0x18, data 0x20
/
	.globl  goreal
goreal:

	/ Transfer control to a 16 bit code segment
	/ This relies on knowledge of kernel's GDT
	ljmp	$0x18, $set16cs
set16cs:

	/ need to have all segment regs sane
	/ before we can enter real mode
	D16		movl	$0x20, %eax
			movw	%ax, %es
			movw	%ax, %ds
			movw	%ax, %fs
			movw	%ax, %gs

	/ clear the protection and paging bits
	/ jump should clear prefetch q
			mov     %cr0, %eax
	D16		and	$0x7ffffffe, %eax
			mov	%eax, %cr0

	/ Do a long jump here to establish %cs in real mode.
	/ It appears that this has to be a ljmp as opposed to
	/ a lret probably due to the way Intel fixed errata #25
	/ on the A2 step. This leads to self modifying code.

			ljmp    $0x0, $restorecs
restorecs:
	/ flush tlb
			mov     %cr3, %eax
			mov     %eax, %cr3

	/ we are loading in first 64K, so all segment reg should be zero
			movw    %cs, %ax
			movw    %ax, %ss
			movw    %ax, %ds
			movw    %ax, %es
			movw    %ax, %fs
			movw    %ax, %gs
	D16	 	ret

/ ----------------------------------------------------
/ Enter protected mode.
/
	.globl	goprot
goprot:

	/ Workaround for BIOSes that mess with GDT during INT call without
	/ restoring original value on the way back. Hence restore it here.

	D16 A16		lgdt    kernGDTptr

	D16		popl	%ebx	/ get return %eip, for later use

	/ set protect mode and page mode
			mov	%cr0, %eax
	D16	A16	orl	$0x80000001, %eax
			mov	%eax, %cr0

			jmp	qflush2	  / flush the prefetch queue
qflush2:

	/ Restore caller's segment registers.
	/ Still in 16-bit mode till %cs is restored
		A16	movw	call_ds, %ds
		A16	movw	call_es, %es
		A16	movw	call_fs, %fs
		A16	movw	call_gs, %gs
		A16	movw	call_ss, %ss

	/ Now, set up %cs by fiddling with the return stack and doing an lret

	D16	A16	movw	call_cs, %ax	/ push %cs
	D16		pushl	%eax
	D16		pushl	%ebx		/ push %eip
	D16		lret

/ Data definitions
	.align 4
bioIDTptr:
bioIDTlimit:
	.value	0x3ff
bioIDTbase:
	.long	0

kernGDTptr:
kernGDTlimit:
	.value	0
kernGDTbase:
	.long	0

kernIDTptr:
kernIDTlimit:
	.value	0
kernIDTbase:
	.long	0

/ BIOS int call arguments
.globl ic_int
ic_int:
	.long	0
.globl ic_ax
ic_ax:
	.value	0
.globl ic_bx
ic_bx:
	.value	0
.globl ic_cx
ic_cx:
	.value	0
.globl ic_dx
ic_dx:
	.value	0
.globl ic_bp
ic_bp:
	.value	0
.globl ic_si
ic_si:
	.value	0
.globl ic_di
ic_di:
	.value	0
.globl ic_ds
ic_ds:
	.value	0
.globl ic_es
ic_es:
	.value	0

/ Caller's registers
.globl call_cs
call_cs:
	.value	0
call_ds:
	.value	0
call_es:
	.value	0
call_fs:
	.value	0
call_gs:
	.value	0
.globl call_ss
call_ss:
	.value	0
.globl call_cr0
call_cr0:
	.long	0
.globl call_esp
call_esp:
	.long	0
call_ebp:
	.long	0
call_esi:
	.long	0
call_edi:
	.long	0
call_ebx:
	.long	0
call_ecx:
	.long	0
call_edx:
	.long	0
