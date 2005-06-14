/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2000 Free Software Foundation, Inc.
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

/* This is stolen from libc/x86/setjmp.S in the OSKit */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 * C library -- _setjmp, _longjmp
 *
 *      _longjmp(a,v)
 * will generate a "return(v)" from
 * the last call to
 *      _setjmp(a)
 * by restoring registers from the stack,
 * The previous signal state is NOT restored.
 *
 */
	
ENTRY(grub_setjmp)
	movl	4(%esp), %ecx		/* fetch buffer */
	movl	%ebx, 0(%ecx)
	movl	%esi, 4(%ecx)
	movl	%edi, 8(%ecx)
	movl	%ebp, 12(%ecx)		/* save frame pointer of caller */
	popl	%edx
	movl	%esp, 16(%ecx)		/* save stack pointer of caller */
	movl	%edx, 20(%ecx)		/* save pc of caller */
	xorl	%eax, %eax
        jmp     *%edx

ENTRY(grub_longjmp)
	movl	8(%esp), %eax		/* return(v) */
	movl	4(%esp), %ecx		/* fetch buffer */
	movl	0(%ecx), %ebx
	movl	4(%ecx), %esi
	movl	8(%ecx), %edi
	movl	12(%ecx), %ebp
	movl	16(%ecx), %esp
	orl	%eax, %eax
	jnz	0f
	incl	%eax
0:	jmp	*20(%ecx)		/* done, return.... */
