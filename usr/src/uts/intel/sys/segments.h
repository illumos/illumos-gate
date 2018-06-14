/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2018 Joyent, Inc.
 */

#ifndef	_SYS_SEGMENTS_H
#define	_SYS_SEGMENTS_H

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

#include <sys/tss.h>

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
#if !defined(_ASM) || defined(__GNUC_AS__)
#define	IDXTOSEL(s)	((s) << 3)		/* index to selector */
#define	SEL_GDT(s, r)	(IDXTOSEL(s) | r)	/* global sel */
#else
#define	IDXTOSEL(s)	[s << 3]
#define	SEL_GDT(s, r)	[IDXTOSEL(s) | r]
#endif

#define	SELTOIDX(s)	((s) >> 3)	/* selector to index */

/*
 * SEL_(KPL,UPL,XPL) is the RPL or DPL value for code and data selectors
 * and their descriptors respectively.
 *
 * TRP_(KPL,UPL,XPL) is used to indicate the DPL for system gates only.
 *
 * This distinction is important to support para-virt guests on the
 * 64-bit hypervisor. Both guest kernel and user run in ring 3 and the
 * hypervisor runs in ring 0. When the kernel creates its trap and
 * interrupt gates it needs a way to prevent any arbitrary int $n
 * instruction from entering a gate that is not expected. The hypervisor
 * allows these gates to have a DPL from 1 to 3. By creating gates
 * with a DPL below user (ring 3) the int $n will generate a #gp fault
 * which the hypervisor catches and forwards to the guest.
 */
#if defined(__xpv)

#define	SEL_XPL		0		/* hypervisor privilege level */
#define	SEL_KPL		3		/* both kernel and user in ring 3 */
#define	TRP_KPL		1		/* system gate priv (user blocked) */
#define	TRP_XPL		0		/* system gate priv (hypervisor) */

#define	IST_DBG		0

#else	/* __xpv */

#define	SEL_KPL		0		/* kernel privilege level on metal */
#define	TRP_KPL		SEL_KPL		/* system gate priv (user blocked) */


#define	IST_DF		1
#define	IST_NMI		2
#define	IST_MCE		3
#define	IST_DBG		4
#define	IST_NESTABLE	5
#define	IST_DEFAULT	6

#endif	/* __xpv */

#define	IST_NONE	0

#define	SEL_UPL		3		/* user priority level */
#define	TRP_UPL		3		/* system gate priv (user allowed) */
#define	SEL_TI_LDT	4		/* local descriptor table */
#define	SEL_LDT(s)	(IDXTOSEL(s) | SEL_TI_LDT | SEL_UPL)	/* local sel */
#define	CPL_MASK	3		/* RPL mask for selector */
#define	SELISLDT(s)	(((s) & SEL_TI_LDT) == SEL_TI_LDT)
#define	SELISUPL(s)	(((s) & CPL_MASK) == SEL_UPL)

#ifndef	_ASM

typedef	uint16_t	selector_t;	/* selector reigster */

/*
 * Hardware descriptor table register format for GDT and IDT.
 */
#if defined(__amd64)

#pragma pack(2)
typedef struct {
	uint16_t dtr_limit;	/* table limit */
	uint64_t dtr_base;	/* table base address  */
} desctbr_t;
#pragma	pack()

#elif defined(__i386)

#pragma pack(2)
typedef struct {
	uint16_t dtr_limit;	/* table limit */
	uint32_t dtr_base;	/* table base address  */
} desctbr_t;
#pragma	pack()

#endif	/* __i386 */

/*
 * Functions for loading and storing descriptor table
 * registers.
 */
extern void rd_idtr(desctbr_t *);
extern void wr_idtr(desctbr_t *);
extern void rd_gdtr(desctbr_t *);
extern void wr_gdtr(desctbr_t *);
extern void wr_ldtr(selector_t);
extern selector_t rd_ldtr(void);
extern void wr_tsr(selector_t);
extern void kmdb_enter(void);

#if defined(__amd64)

/*
 * inlines for update_segregs
 */
extern void __set_ds(selector_t);
extern void __set_es(selector_t);
extern void __set_fs(selector_t);
extern void __set_gs(selector_t);
extern void __swapgs(void);
#endif	/* __amd64 */

#if defined(__amd64)
extern void load_segment_registers(selector_t, selector_t, selector_t,
    selector_t);	/* (alphabetical) */
#elif defined(__i386)
extern void load_segment_registers(selector_t, selector_t, selector_t,
    selector_t, selector_t, selector_t);	/* (alphabetical) */
#endif	/* __i386 */

selector_t get_cs_register();

#if !defined(__amd64)

/*
 * User segment descriptors (code and data).
 * Legacy mode 64-bits wide.
 */
typedef struct user_desc {
	uint32_t usd_lolimit:16;	/* segment limit 15:0 */
	uint32_t usd_lobase:16;		/* segment base 15:0 */
	uint32_t usd_midbase:8;		/* segment base 23:16 */
	uint32_t usd_type:5;		/* segment type, includes S bit */
	uint32_t usd_dpl:2;		/* segment descriptor priority level */
	uint32_t usd_p:1;		/* segment descriptor present */
	uint32_t usd_hilimit:4;		/* segment limit 19:16 */
	uint32_t usd_avl:1;		/* available to sw, but not used */
	uint32_t usd_reserved:1;	/* unused, ignored */
	uint32_t usd_def32:1;		/* default 32 vs 16 bit operand */
	uint32_t usd_gran:1;		/* limit units (bytes vs pages) */
	uint32_t usd_hibase:8;		/* segment base 31:24 */
} user_desc_t;

#define	USEGD_GETBASE(usd)		((usd)->usd_lobase |		\
					(usd)->usd_midbase << 16 |	\
					(usd)->usd_hibase << (16 + 8))

#define	USEGD_SETBASE(usd, b)		((usd)->usd_lobase = (b),	\
					(usd)->usd_midbase = (b) >> 16, \
					(usd)->usd_hibase = (b) >> (16 + 8))

#define	USEGD_GETLIMIT(usd)		((usd)->usd_lolimit |		\
					(usd)->usd_hilimit << 16)

#define	USEGD_SETLIMIT(usd, lim)	((usd)->usd_lolimit = lim,	\
					(usd)->usd_hilimit = lim >> 16)

#define	USD_TYPESHIFT			5	/* size of usd_type field */

#else	/* __amd64 */

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
typedef struct user_desc {
	uint64_t usd_lolimit:16;	/* segment limit 15:0 */
	uint64_t usd_lobase:16;		/* segment base 15:0 */
	uint64_t usd_midbase:8;		/* segment base 23:16 */
	uint64_t usd_type:5;		/* segment type, includes S bit */
	uint64_t usd_dpl:2;		/* segment descriptor priority level */
	uint64_t usd_p:1;		/* segment descriptor present */
	uint64_t usd_hilimit:4;		/* segment limit 19:16 */
	uint64_t usd_avl:1;		/* available to sw, but not used */
	uint64_t usd_long:1;		/* long mode (%cs only) */
	uint64_t usd_def32:1;		/* default 32 vs 16 bit operand */
	uint64_t usd_gran:1;		/* limit units (bytes vs page) */
	uint64_t usd_hibase:8;		/* segment base 31:24 */
} user_desc_t;

#define	USEGD_GETBASE(usd)		((usd)->usd_lobase |		\
					(usd)->usd_midbase << 16 |	\
					(usd)->usd_hibase << (16 + 8))

#define	USEGD_SETBASE(usd, b)		((usd)->usd_lobase = (b),	\
					(usd)->usd_midbase = (b) >> 16, \
					(usd)->usd_hibase = (b) >> (16 + 8))

#define	USEGD_GETLIMIT(usd)		((usd)->usd_lolimit |		\
					(usd)->usd_hilimit << 16)

#define	USEGD_SETLIMIT(usd, lim)	((usd)->usd_lolimit = lim,	\
					(usd)->usd_hilimit = lim >> 16)

#define	USD_TYPESHIFT			5	/* size of usd_type field */

#endif /* __amd64 */

#if !defined(__amd64)

/*
 * System segment descriptors for LDT and TSS segments.
 * Legacy mode 64-bits wide.
 */
typedef struct system_desc {
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

#else	/* __amd64 */

/*
 * System segment descriptors for LDT and TSS segments.
 * Long mode 128-bits wide.
 *
 * 32-bit LDT and TSS descriptor types are redefined to 64-bit equivalents.
 * All other legacy types are reserved and illegal.
 */
typedef struct system_desc {
	uint64_t ssd_lolimit:16;	/* segment limit 15:0 */
	uint64_t ssd_lobase:16;		/* segment base 15:0 */
	uint64_t ssd_midbase:8;		/* segment base 23:16 */
	uint64_t ssd_type:4;		/* segment type */
	uint64_t ssd_zero1:1;		/* must be zero */
	uint64_t ssd_dpl:2;		/* segment descriptor priority level */
	uint64_t ssd_p:1;		/* segment descriptor present */
	uint64_t ssd_hilimit:4;		/* segment limit 19:16 */
	uint64_t ssd_avl:1;		/* available to sw, but not used */
	uint64_t ssd_resv1:2;		/* unused, ignored */
	uint64_t ssd_gran:1;		/* limit unit (bytes vs pages) */
	uint64_t ssd_hibase:8;		/* segment base 31:24 */
	uint64_t ssd_hi64base:32;	/* segment base 63:32 */
	uint64_t ssd_resv2:8;		/* unused, ignored */
	uint64_t ssd_zero2:5;		/* must be zero */
	uint64_t ssd_resv3:19;		/* unused, ignored */
} system_desc_t;

#endif	/* __amd64 */

#define	SYSSEGD_SETLIMIT(ssd, lim)	((ssd)->ssd_lolimit = lim,	\
					(ssd)->ssd_hilimit = lim >> 16)

#define	SYSSEGD_GETLIMIT(ssd)		(((ssd)->ssd_hilimit << 16) |   \
					(ssd)->ssd_lolimit)

#if !defined(__amd64)

/*
 * System gate segment descriptors for interrupt, trap, call and task gates.
 * Legacy mode 64-bits wide.
 */
typedef struct gate_desc {
	uint32_t sgd_looffset:16;	/* segment code offset 15:0 */
	uint32_t sgd_selector:16;	/* target code or task selector */
	uint32_t sgd_stkcpy:5;		/* number of stack wds to cpy */
	uint32_t sgd_resv:3;		/* unused, ignored */
	uint32_t sgd_type:5;		/* segment type, includes S bit */
	uint32_t sgd_dpl:2;		/* segment descriptor priority level */
	uint32_t sgd_p:1;		/* segment descriptor present */
	uint32_t sgd_hioffset:16;	/* code seg off 31:16 */
} gate_desc_t;

#define	GATESEG_GETOFFSET(sgd)	((uintptr_t)((sgd)->sgd_looffset |	\
				(sgd)->sgd_hioffset << 16))

#else	/* __amd64 */

/*
 * System segment descriptors for interrupt, trap and call gates.
 * Long mode 128-bits wide.
 *
 * 32-bit interrupt, trap and call gate types are redefined to 64-bit
 * equivalents. Task gates along with all other legacy types are reserved
 * and illegal.
 */
typedef struct gate_desc {
	uint64_t sgd_looffset:16;	/* segment code offset 15:0 */
	uint64_t sgd_selector:16;	/* target code or task selector */
	uint64_t sgd_ist:3;		/* IST table index */
	uint64_t sgd_resv1:5;		/* unused, ignored */
	uint64_t sgd_type:5;		/* segment type, includes S bit */
	uint64_t sgd_dpl:2;		/* segment descriptor priority level */
	uint64_t sgd_p:1;		/* segment descriptor present */
	uint64_t sgd_hioffset:16;	/* segment code offset 31:16 */
	uint64_t sgd_hi64offset:32;	/* segment code offset 63:32 */
	uint64_t sgd_resv2:8;		/* unused, ignored */
	uint64_t sgd_zero:5;		/* call gate only: must be zero */
	uint64_t sgd_resv3:19;		/* unused, ignored */
} gate_desc_t;

#define	GATESEG_GETOFFSET(sgd)	((uintptr_t)((sgd)->sgd_looffset |	\
				(sgd)->sgd_hioffset << 16 |		\
				(uint64_t)((sgd)->sgd_hi64offset) << 32))

#endif	/* __amd64 */

/*
 * functions for initializing and updating segment descriptors.
 */
#if defined(__amd64)

extern void set_usegd(user_desc_t *, uint_t, void *, size_t, uint_t, uint_t,
    uint_t, uint_t);

#elif defined(__i386)

extern void set_usegd(user_desc_t *, void *, size_t, uint_t, uint_t,
    uint_t, uint_t);

#endif	/* __i386 */

extern uint_t idt_vector_to_ist(uint_t);

extern void set_gatesegd(gate_desc_t *, void (*)(void), selector_t,
    uint_t, uint_t, uint_t);

extern void set_syssegd(system_desc_t *, void *, size_t, uint_t, uint_t);

extern void *get_ssd_base(system_desc_t *);

extern void gdt_update_usegd(uint_t, user_desc_t *);

extern int ldt_update_segd(user_desc_t *, user_desc_t *);

#if defined(__xpv)

extern int xen_idt_to_trap_info(uint_t, gate_desc_t *, void *);
extern void xen_idt_write(gate_desc_t *, uint_t);

#endif	/* __xen */

void init_boot_gdt(user_desc_t *);

#endif	/* _ASM */

/*
 * Common segment parameter defintions for granularity, default
 * operand size and operaton mode.
 */
#define	SDP_BYTES	0	/* segment limit scaled to bytes */
#define	SDP_PAGES	1	/* segment limit scaled to pages */
#define	SDP_OP32	1	/* code and data default operand = 32 bits */
#define	SDP_LONG	1	/* long mode code segment (64 bits) */
#define	SDP_SHORT	0	/* compat/legacy code segment (32 bits) */
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

/* These bits are within the "type" field, like the values above. */
#define	SDT_A		0x01	/* accessed bit */
#define	SDT_S		0x10	/* S-bit at the top of "type" for usegs */

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
#define	NIDT		256	/* size in entries of IDT */

/*
 * Entries in the Global Descriptor Table (GDT)
 *
 * We make sure to space the system descriptors (LDT's, TSS')
 * such that they are double gdt slot aligned. This is because
 * in long mode system segment decriptors expand to 128 bits.
 *
 * GDT_LWPFS and GDT_LWPGS must be the same for both 32 and 64-bit
 * kernels. See setup_context in libc. 64-bit processes must set
 * %fs or %gs to null selector to use 64-bit fsbase or gsbase
 * respectively.
 */
#define	GDT_NULL	0	/* null */
#define	GDT_B32DATA	1	/* dboot 32 bit data descriptor */
#define	GDT_B32CODE	2	/* dboot 32 bit code descriptor */
#define	GDT_B16CODE	3	/* bios call 16 bit code descriptor */
#define	GDT_B16DATA	4	/* bios call 16 bit data descriptor */
#define	GDT_B64CODE	5	/* dboot 64 bit code descriptor */
#define	GDT_BGSTMP	7	/* kmdb descriptor only used early in boot */
#define	GDT_CPUID	16	/* store numeric id of current CPU */

#if defined(__amd64)

#define	GDT_KCODE	6	/* kernel code seg %cs */
#define	GDT_KDATA	7	/* kernel data seg %ds */
#define	GDT_U32CODE	8	/* 32-bit process on 64-bit kernel %cs */
#define	GDT_UDATA	9	/* user data seg %ds (32 and 64 bit) */
#define	GDT_UCODE	10	/* native user code  seg %cs */
#define	GDT_LDT		12	/* (12-13) LDT for current process */
#define	GDT_KTSS	14	/* (14-15) kernel tss */
#define	GDT_FS		GDT_NULL /* kernel %fs segment selector */
#define	GDT_GS		GDT_NULL /* kernel %gs segment selector */
#define	GDT_LWPFS	55	/* lwp private %fs segment selector (32-bit) */
#define	GDT_LWPGS	56	/* lwp private %gs segment selector (32-bit) */
#define	GDT_BRANDMIN	57	/* first entry in GDT for brand usage */
#define	GDT_BRANDMAX	61	/* last entry in GDT for brand usage */
#define	NGDT		62	/* number of entries in GDT */

/*
 * This selector is only used in the temporary GDT used to bring additional
 * CPUs from 16-bit real mode into long mode in real_mode_start().
 */
#define	TEMPGDT_KCODE64	1	/* 64-bit code selector */

#elif defined(__i386)

#define	GDT_LDT		40	/* LDT for current process */
#define	GDT_KTSS	42	/* kernel tss */
#define	GDT_KCODE	43	/* kernel code seg %cs */
#define	GDT_KDATA	44	/* kernel data seg %ds */
#define	GDT_UCODE	45	/* native user code  seg %cs */
#define	GDT_UDATA	46	/* user data seg %ds (32 and 64 bit) */
#define	GDT_DBFLT	47	/* double fault #DF selector */
#define	GDT_FS		53	/* kernel %fs segment selector */
#define	GDT_GS		54	/* kernel %gs segment selector */
#define	GDT_LWPFS	55	/* lwp private %fs segment selector */
#define	GDT_LWPGS	56	/* lwp private %gs segment selector */
#define	GDT_BRANDMIN	57	/* first entry in GDT for brand usage */
#define	GDT_BRANDMAX	61	/* last entry in GDT for brand usage */
#if !defined(__xpv)
#define	NGDT		90	/* number of entries in GDT */
#else
#define	NGDT		512	/* single 4K page for the hypervisor */
#endif

#endif	/* __i386 */

/*
 * Convenient selector definitions.
 */

/*
 * XXPV	64 bit Xen only allows the guest %cs/%ss be the private ones it
 * provides, not the ones we create for ourselves.  See FLAT_RING3_CS64 in
 * public/arch-x86_64.h
 *
 * 64-bit Xen runs paravirtual guests in ring 3 but emulates them running in
 * ring 0 by clearing CPL in %cs value pushed on guest exception stacks.
 * Therefore we will have KCS_SEL value indicate ring 0 and use that everywhere
 * in the kernel. But in the few files where we initialize segment registers or
 * create and update descriptors we will explicity OR in SEL_KPL (ring 3) for
 * kernel %cs. See desctbls.c for an example.
 */

#if defined(__xpv) && defined(__amd64)
#define	KCS_SEL		0xe030		/* FLAT_RING3_CS64 & 0xFFF0 */
#define	KDS_SEL		0xe02b		/* FLAT_RING3_SS64 */
#else
#define	KCS_SEL		SEL_GDT(GDT_KCODE, SEL_KPL)
#define	KDS_SEL		SEL_GDT(GDT_KDATA, SEL_KPL)
#endif

#define	UCS_SEL		SEL_GDT(GDT_UCODE, SEL_UPL)
#if defined(__amd64)
#define	TEMP_CS64_SEL	SEL_GDT(TEMPGDT_KCODE64, SEL_KPL)
#define	U32CS_SEL	SEL_GDT(GDT_U32CODE, SEL_UPL)
#endif

#define	UDS_SEL		SEL_GDT(GDT_UDATA, SEL_UPL)
#define	ULDT_SEL	SEL_GDT(GDT_LDT, SEL_KPL)
#define	KTSS_SEL	SEL_GDT(GDT_KTSS, SEL_KPL)
#define	DFTSS_SEL	SEL_GDT(GDT_DBFLT, SEL_KPL)
#define	KFS_SEL		0
#define	KGS_SEL		SEL_GDT(GDT_GS, SEL_KPL)
#define	LWPFS_SEL	SEL_GDT(GDT_LWPFS, SEL_UPL)
#define	LWPGS_SEL	SEL_GDT(GDT_LWPGS, SEL_UPL)
#define	BRANDMIN_SEL	SEL_GDT(GDT_BRANDMIN, SEL_UPL)
#define	BRANDMAX_SEL	SEL_GDT(GDT_BRANDMAX, SEL_UPL)

#define	B64CODE_SEL	SEL_GDT(GDT_B64CODE, SEL_KPL)
#define	B32CODE_SEL	SEL_GDT(GDT_B32CODE, SEL_KPL)
#define	B32DATA_SEL	SEL_GDT(GDT_B32DATA, SEL_KPL)
#define	B16CODE_SEL	SEL_GDT(GDT_B16CODE, SEL_KPL)
#define	B16DATA_SEL	SEL_GDT(GDT_B16DATA, SEL_KPL)

/*
 * Temporary %gs descriptor used by kmdb with -d option. Only lives
 * in boot's GDT and is not copied into kernel's GDT from boot.
 */
#define	KMDBGS_SEL	SEL_GDT(GDT_BGSTMP, SEL_KPL)

/*
 * Selector used for kdi_idt when kmdb has taken over the IDT.
 */
#if defined(__amd64)
#define	KMDBCODE_SEL	B64CODE_SEL
#else
#define	KMDBCODE_SEL	B32CODE_SEL
#endif

/*
 * Entries in default Local Descriptor Table (LDT) for every process.
 */
#define	LDT_SYSCALL	0	/* call gate for libc.a (obsolete) */
#define	LDT_SIGCALL	1	/* EOL me, call gate for static sigreturn */
#define	LDT_RESVD1	2	/* old user %cs */
#define	LDT_RESVD2	3	/* old user %ds */
#define	LDT_ALTSYSCALL	4	/* alternate call gate for system calls */
#define	LDT_ALTSIGCALL	5	/* EOL me, alternate call gate for sigreturn */
#define	LDT_UDBASE	6	/* user descriptor base index */
#define	MINNLDT		512	/* Current min solaris ldt size (1 4K page) */
#define	MAXNLDT		8192	/* max solaris ldt size (16 4K pages) */

#ifdef _KERNEL
#define	LDT_CPU_SIZE	(16 * 4096)	/* Size of kernel per-CPU allocation */
#endif

#ifndef	_ASM

extern	gate_desc_t	*idt0;
extern	desctbr_t	idt0_default_reg;
extern	user_desc_t	*gdt0;

extern user_desc_t	zero_udesc;
extern user_desc_t	null_udesc;
extern system_desc_t	null_sdesc;

#if defined(__amd64)
extern user_desc_t	zero_u32desc;
#endif
#if defined(__amd64)
extern user_desc_t	ucs_on;
extern user_desc_t	ucs_off;
extern user_desc_t	ucs32_on;
extern user_desc_t	ucs32_off;
#endif  /* __amd64 */

extern tss_t *ktss0;

#if defined(__i386)
extern tss_t *dftss0;
#endif	/* __i386 */

extern void div0trap(), dbgtrap(), nmiint(), brktrap(), ovflotrap();
extern void boundstrap(), invoptrap(), ndptrap();
#if !defined(__xpv)
extern void syserrtrap();
#endif
extern void invaltrap(), invtsstrap(), segnptrap(), stktrap();
extern void gptrap(), pftrap(), ndperr();
extern void overrun(), resvtrap();
extern void _start(), cmnint();
extern void achktrap(), mcetrap();
extern void xmtrap();
extern void fasttrap();
extern void dtrace_ret();

/* KPTI trampolines */
extern void tr_invaltrap();
extern void tr_div0trap(), tr_dbgtrap(), tr_nmiint(), tr_brktrap();
extern void tr_ovflotrap(), tr_boundstrap(), tr_invoptrap(), tr_ndptrap();
#if !defined(__xpv)
extern void tr_syserrtrap();
#endif
extern void tr_invaltrap(), tr_invtsstrap(), tr_segnptrap(), tr_stktrap();
extern void tr_gptrap(), tr_pftrap(), tr_ndperr();
extern void tr_overrun(), tr_resvtrap();
extern void tr_achktrap(), tr_mcetrap();
extern void tr_xmtrap();
extern void tr_fasttrap();
extern void tr_dtrace_ret();

#if !defined(__amd64)
extern void pentium_pftrap();
#endif

extern uint64_t kpti_enable;

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SEGMENTS_H */
