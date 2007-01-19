/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AMD64_SEGMENTS_H
#define	_AMD64_SEGMENTS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Copyright (c) 1989, 1990 William F. Jolitz
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
 *	from: @(#)segments.h	7.1 (Berkeley) 5/9/91
 * $FreeBSD: src/sys/i386/include/segments.h,v 1.34 2003/09/10 01:07:04
 * jhb Exp $
 *
 * 386 Segmentation Data Structures and definitions
 *	William F. Jolitz (william@ernie.berkeley.edu) 6/20/1989
 */

/*
 * Selector register format
 * CS, DS, ES, FS, GS, SS
 *
 *  15                  3  2  1 0
 * +---------------------+---+----+
 * |          SI         |TI |RPL |
 * +---------------------+---+----+
 *
 * SI  = selector index
 * TI  = table indicator (0 = GDT, 1 = LDT)
 * RPL = requestor privilege level
 */
#define	SELTOIDX(s)	((s) >> 3)	/* selector to index */
#define	IDXTOSEL(s)	((s) << 3)	/* index to selector */
#define	SEL_KPL		0		/* kernel priority level */
#define	SEL_UPL		3		/* user priority level */
#define	SEL_TI_LDT	4		/* local descriptor table */
#define	SEL_LDT(s)	(IDXTOSEL(s) | SEL_TI_LDT | SEL_UPL)	/* local sel */
#define	SEL_GDT(s, r)	(IDXTOSEL(s) | r)			/* global sel */
#define	SELISLDT(s)	(((s) & SEL_TI_LDT) == SEL_TI_LDT)
#define	CPL_MASK	3		/* RPL mask for selector */

#ifndef	_ASM

typedef	uint16_t	selector_t;	/* selector reigster */

/*
 * Hardware descriptor table register format for GDT and IDT.
 */
#pragma	pack(2)
typedef struct descriptor_table_register64 {
	uint16_t dtr_limit;	/* table limit */
	uint64_t dtr_base;	/* table base address  */
} desctbr64_t;
#pragma pack()

#pragma pack(2)
typedef struct descriptor_table_register {
	uint16_t dtr_limit;	/* table limit */
	uint32_t dtr_base;	/* table base address  */
} desctbr_t;
#pragma pack()


/*
 * Functions for loading and storing descriptor table
 * registers.
 */
extern void rd_idtr(desctbr_t *);
extern void wr_idtr(desctbr_t *);
extern void rd_gdtr(desctbr_t *);
extern void wr_gdtr(desctbr_t *);
extern void wr_ldtr(selector_t);
extern void wr_tsr(selector_t);

/*
 * User segment descirptors (code and data).
 * Legacy mode 64-bits wide.
 */
typedef struct	user_segment_descriptor	{
	uint32_t usd_lolimit:16;	/* segment limit 15:0 */
	uint32_t usd_lobase:16;		/* segment base 15:0 */
	uint32_t usd_midbase:8;		/* segment base 23:16 */
	uint32_t usd_type:5;		/* segment type, includes S bit */
	uint32_t usd_dpl:2;		/* segment descriptor priority level */
	uint32_t usd_p:1;		/* segment descriptor present */
	uint32_t usd_hilimit:4;		/* segment limit 19:16 */
	uint32_t usd_avl:1;		/* available to sw, but not used */
	uint32_t usd_reserved:1;	/* unsued, ignored */
	uint32_t usd_def32:1;		/* default 32 vs 16 bit operand */
	uint32_t usd_gran:1;		/* limit unit (bytes vs pages) */
	uint32_t usd_hibase:8;		/* segment base 31:24 */
} user_desc_t;

/*
 * User segment descriptors.
 * Long mode 64-bits wide.
 *
 * In 32-bit compatibility mode (%cs:usd_long=0) all fields are interpreted
 * as in legacy mode for both code and data.
 *
 * In 64-bit mode (%cs:usd_long=1) code segments only have the conforming
 * bit in usd_type, usd_dpl, usd_p, usd_long and usd_def32=0. usd_def32
 * must be zero in 64-bit mode. Setting it to 1 is reserved for future use.
 * All other fields are loaded but ignored by hardware.
 *
 * 64-bit data segments only have usd_p. All other fields are loaded but
 * ignored by hardware when in 64-bit mode.
 */
typedef struct	user_segment_descriptor64 {
	uint32_t usd_lolimit:16;	/* segment limit 15:0 */
	uint32_t usd_lobase:16;		/* segment base 15:0 */
	uint32_t usd_midbase:8;		/* segment base 23:16 */
	uint32_t usd_type:5;		/* segment type, includes S bit */
	uint32_t usd_dpl:2;		/* segment descriptor priority level */
	uint32_t usd_p:1;		/* segment descriptor present */
	uint32_t usd_hilimit:4;		/* segment limit 19:16 */
	uint32_t usd_avl:1;		/* available to sw, but not used */
	uint32_t usd_long:1;		/* long mode (%cs only) */
	uint32_t usd_def32:1;		/* default 32 vs 16 bit operand */
	uint32_t usd_gran:1;		/* limit gran (byte/page units) */
	uint32_t usd_hibase:8;		/* segment base 31:24 */
} user_desc64_t;

/*
 * System segment descriptors for LDT and TSS segments.
 * Legacy mode 64-bits wide.
 */
typedef struct	system_segment_descriptor	{
	uint32_t ssd_lolimit:16;	/* segment limit 15:0 */
	uint32_t ssd_lobase:16;		/* segment base 15:0 */
	uint32_t ssd_midbase:8;		/* segment base 23:16 */
	uint32_t ssd_type:4;		/* segment type */
	uint32_t ssd_zero:1;		/* must be zero */
	uint32_t ssd_dpl:2;		/* segment descriptor priority level */
	uint32_t ssd_p:1;		/* segment descriptor present */
	uint32_t ssd_hilimit:4;		/* segment limit 19:16 */
	uint32_t ssd_avl:1;		/* available to sw, but not used */
	uint32_t ssd_reserved:2;	/* unused, ignored */
	uint32_t ssd_gran:1;		/* limit unit (bytes vs pages) */
	uint32_t ssd_hibase:8;		/* segment base 31:24 */
} system_desc_t;

/*
 * System segment descriptors for LDT and TSS segments.
 * Long mode 128-bits wide.
 *
 * 32-bit LDT and TSS descriptor types are redefined to 64-bit equivalents.
 * All other legacy types are reserved and illegal.
 */
typedef struct	system_segment_descriptor64 {
	uint32_t ssd_lolimit:16;	/* segment limit 15:0 */
	uint32_t ssd_lobase:16;		/* segment base 15:0 */
	uint32_t ssd_midbase:8;		/* segment base 23:16 */
	uint32_t ssd_type:4;		/* segment type */
	uint32_t ssd_zero1:1;		/* must be zero */
	uint32_t ssd_dpl:2;		/* segment descriptor priority level */
	uint32_t ssd_p:1;		/* segment descriptor present */
	uint32_t ssd_hilimit:4;		/* segment limit 19:16 */
	uint32_t ssd_avl:1;		/* available to sw, but not used */
	uint32_t ssd_resv1:2;		/* unused, ignored */
	uint32_t ssd_gran:1;		/* limit unit (bytes vs pages) */
	uint32_t ssd_hibase:8;		/* segment base 31:24 */
	uint32_t ssd_hi64base:32;	/* segment base 63:32 */
	uint32_t ssd_resv2:8;		/* unused, ignored */
	uint32_t ssd_zero2:5;		/* must be zero */
	uint32_t ssd_resv3:19;		/* unused, ignored */
} system_desc64_t;

/*
 * System gate segment descriptors for interrupt, trap, call and task gates.
 * Legacy mode 64-bits wide.
 */
typedef struct	gate_segment_descriptor	{
	uint32_t sgd_looffset:16;	/* segment code offset 15:0 */
	uint32_t sgd_selector:16;	/* target code or task selector */
	uint32_t sgd_stkcpy:5;		/* number of stack wds to cpy */
	uint32_t sgd_resv:3;		/* unused, ignored */
	uint32_t sgd_type:5;		/* segment type, includes S bit */
	uint32_t sgd_dpl:2;		/* segment descriptor priority level */
	uint32_t sgd_p:1;		/* segment descriptor present */
	uint32_t sgd_hioffset:16;	/* code seg off 31:16 */
} gate_desc_t;

/*
 * System segment descriptors for interrupt, trap and call gates.
 * Long mode 128-bits wide.
 *
 * 32-bit interrupt, trap and call gate types are redefined to 64-bit
 * equivalents. Task gates along with all other legacy types are reserved
 * and illegal.
 */
typedef struct	gate_segment_descriptor64	{
	uint32_t sgd_looffset:16;	/* segment code offset 15:0 */
	uint32_t sgd_selector:16;	/* target code or task selector */
	uint32_t sgd_ist:3;		/* IST table index */
	uint32_t sgd_resv1:5;		/* unused, ignored */
	uint32_t sgd_type:5;		/* segment type, includes S bit */
	uint32_t sgd_dpl:2;		/* segment descriptor priority level */
	uint32_t sgd_p:1;		/* segment descriptor present */
	uint32_t sgd_hioffset:16;	/* segment code offset 31:16 */
	uint32_t sgd_hi64offset:32;	/* segment code offset 63:32 */
	uint32_t sgd_resv2:8;		/* unused, ignored */
	uint32_t sgd_zero:5;		/* call gate only: must be zero */
	uint32_t sgd_resv3:19;		/* unused, ignored */
} gate_desc64_t;

#undef  BYTES
#define	BYTES   0

#undef  PAGES
#define	PAGES   1

#undef  OP32
#define	OP32    1

#undef  LONG
#define	LONG    1

#undef  SHORT
#define	SHORT   0

/*
 * functions for initializing and updating segment descriptors.
 */
extern void set_usegd64(user_desc64_t *, uint_t, void *, size_t, uint_t, uint_t,
    uint_t, uint_t);
extern void set_gatesegd64(gate_desc64_t *, void (*)(void), selector_t, uint_t,
    uint_t, uint_t);
void set_syssegd64(system_desc64_t *, void *, size_t, uint_t, uint_t);

extern void set_usegd(user_desc_t *, void *, size_t, uint_t, uint_t,
    uint_t, uint_t);
extern void set_gatesegd(gate_desc_t *, void (*)(void), selector_t,
    uint_t, uint_t, uint_t);
void set_syssegd(system_desc_t *, void *, size_t, uint_t, uint_t);

#endif	/* _ASM */

/*
 * System segments and gate types.
 *
 * In long mode i386 32-bit ldt, tss, call, interrupt and trap gate
 * types are redefined into 64-bit equivalents.
 */
#define	SDT_SYSNULL	 0	/* system null */
#define	SDT_SYS286TSS	 1	/* system 286 TSS available */
#define	SDT_SYSLDT	 2	/* system local descriptor table */
#define	SDT_SYS286BSY	 3	/* system 286 TSS busy */
#define	SDT_SYS286CGT	 4	/* system 286 call gate */
#define	SDT_SYSTASKGT	 5	/* system task gate */
#define	SDT_SYS286IGT	 6	/* system 286 interrupt gate */
#define	SDT_SYS286TGT	 7	/* system 286 trap gate */
#define	SDT_SYSNULL2	 8	/* system null again */
#define	SDT_SYSTSS	 9	/* system TSS available */
#define	SDT_SYSNULL3	10	/* system null again */
#define	SDT_SYSTSSBSY	11	/* system TSS busy */
#define	SDT_SYSCGT	12	/* system call gate */
#define	SDT_SYSNULL4	13	/* system null again */
#define	SDT_SYSIGT	14	/* system interrupt gate */
#define	SDT_SYSTGT	15	/* system trap gate */

/*
 * Memory segment types.
 *
 * While in long mode expand-down, writable and accessed type field
 * attributes are ignored. Only the conforming bit is loaded by hardware
 * for long mode code segment descriptors.
 */
#define	SDT_MEMRO	16	/* read only */
#define	SDT_MEMROA	17	/* read only accessed */
#define	SDT_MEMRW	18	/* read write */
#define	SDT_MEMRWA	19	/* read write accessed */
#define	SDT_MEMROD	20	/* read only expand dwn limit */
#define	SDT_MEMRODA	21	/* read only expand dwn limit accessed */
#define	SDT_MEMRWD	22	/* read write expand dwn limit */
#define	SDT_MEMRWDA	23	/* read write expand dwn limit accessed */
#define	SDT_MEME	24	/* execute only */
#define	SDT_MEMEA	25	/* execute only accessed */
#define	SDT_MEMER	26	/* execute read */
#define	SDT_MEMERA	27	/* execute read accessed */
#define	SDT_MEMEC	28	/* execute only conforming */
#define	SDT_MEMEAC	29	/* execute only accessed conforming */
#define	SDT_MEMERC	30	/* execute read conforming */
#define	SDT_MEMERAC	31	/* execute read accessed conforming */


/*
 * Entries in the Interrupt Descriptor Table (IDT)
 */
#define	IDT_DE		0	/* #DE: Divide Error */
#define	IDT_DB		1	/* #DB: Debug */
#define	IDT_NMI		2	/* Nonmaskable External Interrupt */
#define	IDT_BP		3	/* #BP: Breakpoint */
#define	IDT_OF		4	/* #OF: Overflow */
#define	IDT_BR		5	/* #BR: Bound Range Exceeded */
#define	IDT_UD		6	/* #UD: Undefined/Invalid Opcode */
#define	IDT_NM		7	/* #NM: No Math Coprocessor */
#define	IDT_DF		8	/* #DF: Double Fault */
#define	IDT_FPUGP	9	/* Coprocessor Segment Overrun */
#define	IDT_TS		10	/* #TS: Invalid TSS */
#define	IDT_NP		11	/* #NP: Segment Not Present */
#define	IDT_SS		12	/* #SS: Stack Segment Fault */
#define	IDT_GP		13	/* #GP: General Protection Fault */
#define	IDT_PF		14	/* #PF: Page Fault */
#define	IDT_MF		16	/* #MF: FPU Floating-Point Error */
#define	IDT_AC		17	/* #AC: Alignment Check */
#define	IDT_MC		18	/* #MC: Machine Check */
#define	IDT_XF		19	/* #XF: SIMD Floating-Point Exception */
#define	IDT_SYSCALL	0x80	/* System Call Interrupt Vector */
#define	NIDT		256	/* size in entries of IDT */

/*
 * Entries in the Global Descriptor Table (GDT) for VMX (stretch)
 *
 * We make sure to space the system descriptors (LDT's, TSS')
 * such that they are double gdt slot aligned. This is because
 * in long mode system segment decriptors expand to 128 bits.
 */
#define	GDT_NULL 	0	/* null */
#define	GDT_DATA32 	1	/* 32-bit data */
#define	GDT_CODE32 	2	/* 32-bit code */
#define	GDT_DATA64 	3	/* 64-bit data */
#define	GDT_CODE64 	4	/* 64-bit code */
#define	GDT_NULL1 	5	/* null */
#define	GDT_TSS64	6	/* 64-bit tss */
#define	GDT_NULL2	7	/* null */

#define	NGDT	8

#ifndef	_ASM

extern void amd64_div0trap(), amd64_dbgtrap(), amd64_nmiint(), amd64_brktrap();
extern void amd64_ovflotrap(), amd64_boundstrap(), amd64_invoptrap();
extern void amd64_ndptrap(), amd64_doublefault();
extern void amd64_invaltrap(), amd64_invtsstrap(), amd64_segnptrap();
extern void amd64_stktrap(), amd64_gptrap(), amd64_pftrap(), amd64_ndperr();
extern void amd64_overrun(), amd64_resvtrap(), amd64_achktrap();
extern void amd64_mcetrap(), amd64_xmtrap();

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _AMD64_SEGMENTS_H */
