/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2000, 2001 Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* This is stolen from arch/i386/boot/setup.S in Linux 2.2.17 */
/*
!       setup.S         Copyright (C) 1991, 1992 Linus Torvalds
*/

ENTRY(get_apm_info)
	pushl	%ebp
	pushl	%ebx
	pushl	%edi
	pushl	%esi

	call	EXT_C(prot_to_real)
	.code16
	
	/* APM BIOS installation check */
	movw	$0x5300, %ax
	xorw	%bx, %bx
	int	$0x15
	/* error -> no APM BIOS */
	jc	done_apm_bios

	/* check for "PM" signature */
	cmpw	$0x504d, %bx
	/* no signature -> no APM BIOS */
	jne	done_apm_bios

	/* Is 32 bit supported? */
	andw	$0x0002, %cx
	/* no ... */
	je	done_apm_bios

	/* Disconnect first just in case */
	movw	$0x5304, %ax
	xorw	%bx, %bx
	/* ignore return code */
	int	$0x15

	/* 32 bit connect */
	movw	$0x5303, %ax
	xorl	%ebx, %ebx
	/* paranoia */
	xorw	%cx, %cx
	xorw	%dx, %dx
	xorl	%esi, %esi
	xorw	%di, %di
	int	$0x15
	/* error */
	jc	no_32_apm_bios

	/* BIOS code segment */
	movw	%ax, ABS(EXT_C(apm_bios_info)) + 2
	/* BIOS entry point offset */
	movl	%ebx, ABS(EXT_C(apm_bios_info)) + 4
	/* BIOS 16 bit code segment */
	movw	%cx, ABS(EXT_C(apm_bios_info)) + 8
	/* BIOS data segment */
	movw	%dx, ABS(EXT_C(apm_bios_info)) + 10
	/* BIOS code segment length */
	movl	%esi, ABS(EXT_C(apm_bios_info)) + 14
	/* BIOS data segment length */
	movw	%di, ABS(EXT_C(apm_bios_info)) + 18

	/*
	 * Redo the installation check as the 32 bit connect
	 * modifies the flags returned on some BIOSs
	 */

	/* APM BIOS installation check */
	movw	$0x5300, %ax
	xorw	%bx, %bx
	/* paranoia */
	xorw	%cx, %cx
	int     $0x15
	/* error -> should not happen, tidy up */
	jc	done_apm_bios

	/* check for "PM" signature */
	cmpw	$0x504d, %bx
	/* no signature -> should not happen, tidy up */
	jne	done_apm_bios

	/* record the APM BIOS version */
	movw	%ax, ABS(EXT_C(apm_bios_info))
	/* and flags */
	movw	%cx, ABS(EXT_C(apm_bios_info)) + 12
	jmp	done_apm_bios

no_32_apm_bios:
	/* remove 32 bit support bit */
	andw     $0xfffd, ABS(EXT_C(apm_bios_info)) + 12

done_apm_bios:
	/* Some paranoia here: Always Disconnect from APM */
	movw	$0x5304, %ax
	xorw	%bx, %bx
	/* ignore return code */
	int     $0x15

	DATA32	call	EXT_C(real_to_prot)
	.code32

	popl	%esi
	popl	%edi
	popl	%ebx
	popl	%ebp
	ret
