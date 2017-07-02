/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_TSS_H
#define	_SYS_TSS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)tss.h	5.4 (Berkeley) 1/18/91
 * $FreeBSD: src/sys/i386/include/tss.h,v 1.13 2002/09/23 05:04:05 peter Exp $
 */
/*
 * Copyright 2011 Joyent, Inc. All rights reserved.
 */

/*
 * Maximum I/O address that will be in TSS bitmap
 */
#define	MAXTSSIOADDR	0x3ff	/* XXX - needs to support 64K I/O space */

#ifndef _ASM

/*
 * Task state segment (tss). Holds the processor state assoicated with a task.
 *
 * Historically, this header only exposed a struct tss that was relevant to the
 * specific Intel architecture that we were deploying on. However, the tss
 * structures are defined by the Intel Architecture and other consumers would
 * like to use them. Rather than requiring them to duplicate all of this
 * information, we instead expose each version under different names but in a
 * backwards compatible manner.
 */

#pragma	pack(4)
struct tss64 {
	uint32_t	tss_rsvd0;	/* reserved, ignored */
	uint64_t	tss_rsp0; 	/* stack pointer CPL = 0 */
	uint64_t	tss_rsp1; 	/* stack pointer CPL = 1 */
	uint64_t	tss_rsp2; 	/* stack pointer CPL = 2 */
	uint64_t	tss_rsvd1;	/* reserved, ignored */
	uint64_t	tss_ist1;	/* Interrupt stack table 1 */
	uint64_t	tss_ist2;	/* Interrupt stack table 2 */
	uint64_t	tss_ist3;	/* Interrupt stack table 3 */
	uint64_t	tss_ist4;	/* Interrupt stack table 4 */
	uint64_t	tss_ist5;	/* Interrupt stack table 5 */
	uint64_t	tss_ist6;	/* Interrupt stack table 6 */
	uint64_t	tss_ist7;	/* Interrupt stack table 7 */
	uint64_t	tss_rsvd2;	/* reserved, ignored */
	uint16_t	tss_rsvd3;	/* reserved, ignored */
	uint16_t	tss_bitmapbase;	/* io permission bitmap base address */
};
#pragma	pack()

struct tss32 {
	uint16_t	tss_link;	/* 16-bit prior TSS selector */
	uint16_t	tss_rsvd0;	/* reserved, ignored */
	uint32_t	tss_esp0;
	uint16_t	tss_ss0;
	uint16_t	tss_rsvd1;	/* reserved, ignored */
	uint32_t	tss_esp1;
	uint16_t	tss_ss1;
	uint16_t	tss_rsvd2;	/* reserved, ignored */
	uint32_t	tss_esp2;
	uint16_t	tss_ss2;
	uint16_t	tss_rsvd3;	/* reserved, ignored */
	uint32_t	tss_cr3;
	uint32_t	tss_eip;
	uint32_t	tss_eflags;
	uint32_t	tss_eax;
	uint32_t	tss_ecx;
	uint32_t	tss_edx;
	uint32_t	tss_ebx;
	uint32_t	tss_esp;
	uint32_t	tss_ebp;
	uint32_t	tss_esi;
	uint32_t	tss_edi;
	uint16_t	tss_es;
	uint16_t	tss_rsvd4;	/* reserved, ignored */
	uint16_t	tss_cs;
	uint16_t	tss_rsvd5;	/* reserved, ignored */
	uint16_t	tss_ss;
	uint16_t	tss_rsvd6;	/* reserved, ignored */
	uint16_t	tss_ds;
	uint16_t	tss_rsvd7;	/* reserved, ignored */
	uint16_t	tss_fs;
	uint16_t	tss_rsvd8;	/* reserved, ignored */
	uint16_t	tss_gs;
	uint16_t	tss_rsvd9;	/* reserved, ignored */
	uint16_t	tss_ldt;
	uint16_t	tss_rsvd10;	/* reserved, ignored */
	uint16_t	tss_rsvd11;	/* reserved, ignored */
	uint16_t	tss_bitmapbase;	/* io permission bitmap base address */
};

struct tss16 {
	uint16_t	tss_link;
	uint16_t	tss_sp0;
	uint16_t	tss_ss0;
	uint16_t	tss_sp1;
	uint16_t	tss_ss1;
	uint16_t	tss_sp2;
	uint16_t	tss_ss2;
	uint16_t	tss_ip;
	uint16_t	tss_flag;
	uint16_t	tss_ax;
	uint16_t	tss_cx;
	uint16_t	tss_dx;
	uint16_t	tss_bx;
	uint16_t	tss_sp;
	uint16_t	tss_bp;
	uint16_t	tss_si;
	uint16_t	tss_di;
	uint16_t	tss_es;
	uint16_t	tss_cs;
	uint16_t	tss_ss;
	uint16_t	tss_ds;
	uint16_t	tss_ldt;
};

#if defined(__amd64)

typedef	struct tss64	tss_t;

#elif defined(__i386)

typedef	struct tss32	tss_t;

#endif	/* __i386 */

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TSS_H */
