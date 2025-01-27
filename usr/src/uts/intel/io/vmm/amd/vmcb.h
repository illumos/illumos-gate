/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013 Anish Gupta (akgupt3@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2022 Oxide Computer Company
 */

#ifndef _VMCB_H_
#define	_VMCB_H_

struct svm_softc;

#define	BIT(n)			(1ULL << n)

/*
 * Secure Virtual Machine: AMD64 Programmer's Manual Vol2, Chapter 15
 * Layout of VMCB: AMD64 Programmer's Manual Vol2, Appendix B
 */

/* vmcb_ctrl->intercept[] array indices */
#define	VMCB_CR_INTCPT		0
#define	VMCB_DR_INTCPT		1
#define	VMCB_EXC_INTCPT		2
#define	VMCB_CTRL1_INTCPT	3
#define	VMCB_CTRL2_INTCPT	4

/* intercept[VMCB_CTRL1_INTCPT] fields */
#define	VMCB_INTCPT_INTR		BIT(0)
#define	VMCB_INTCPT_NMI			BIT(1)
#define	VMCB_INTCPT_SMI			BIT(2)
#define	VMCB_INTCPT_INIT		BIT(3)
#define	VMCB_INTCPT_VINTR		BIT(4)
#define	VMCB_INTCPT_CR0_WRITE		BIT(5)
#define	VMCB_INTCPT_IDTR_READ		BIT(6)
#define	VMCB_INTCPT_GDTR_READ		BIT(7)
#define	VMCB_INTCPT_LDTR_READ		BIT(8)
#define	VMCB_INTCPT_TR_READ		BIT(9)
#define	VMCB_INTCPT_IDTR_WRITE		BIT(10)
#define	VMCB_INTCPT_GDTR_WRITE		BIT(11)
#define	VMCB_INTCPT_LDTR_WRITE		BIT(12)
#define	VMCB_INTCPT_TR_WRITE		BIT(13)
#define	VMCB_INTCPT_RDTSC		BIT(14)
#define	VMCB_INTCPT_RDPMC		BIT(15)
#define	VMCB_INTCPT_PUSHF		BIT(16)
#define	VMCB_INTCPT_POPF		BIT(17)
#define	VMCB_INTCPT_CPUID		BIT(18)
#define	VMCB_INTCPT_RSM			BIT(19)
#define	VMCB_INTCPT_IRET		BIT(20)
#define	VMCB_INTCPT_INTn		BIT(21)
#define	VMCB_INTCPT_INVD		BIT(22)
#define	VMCB_INTCPT_PAUSE		BIT(23)
#define	VMCB_INTCPT_HLT			BIT(24)
#define	VMCB_INTCPT_INVLPG		BIT(25)
#define	VMCB_INTCPT_INVLPGA		BIT(26)
#define	VMCB_INTCPT_IO			BIT(27)
#define	VMCB_INTCPT_MSR			BIT(28)
#define	VMCB_INTCPT_TASK_SWITCH		BIT(29)
#define	VMCB_INTCPT_FERR_FREEZE		BIT(30)
#define	VMCB_INTCPT_SHUTDOWN		BIT(31)

/* intercept[VMCB_CTRL2_INTCPT] fields */
#define	VMCB_INTCPT_VMRUN		BIT(0)
#define	VMCB_INTCPT_VMMCALL		BIT(1)
#define	VMCB_INTCPT_VMLOAD		BIT(2)
#define	VMCB_INTCPT_VMSAVE		BIT(3)
#define	VMCB_INTCPT_STGI		BIT(4)
#define	VMCB_INTCPT_CLGI		BIT(5)
#define	VMCB_INTCPT_SKINIT		BIT(6)
#define	VMCB_INTCPT_RDTSCP		BIT(7)
#define	VMCB_INTCPT_ICEBP		BIT(8)
#define	VMCB_INTCPT_WBINVD		BIT(9)
#define	VMCB_INTCPT_MONITOR		BIT(10)
#define	VMCB_INTCPT_MWAIT		BIT(11)
#define	VMCB_INTCPT_MWAIT_ARMED		BIT(12)
#define	VMCB_INTCPT_XSETBV		BIT(13)

/* VMCB TLB control */
#define	VMCB_TLB_FLUSH_NOTHING		0	/* Flush nothing */
#define	VMCB_TLB_FLUSH_ALL		1	/* Flush entire TLB */
#define	VMCB_TLB_FLUSH_GUEST		3	/* Flush all guest entries */
#define	VMCB_TLB_FLUSH_GUEST_NONGLOBAL	7	/* Flush guest non-PG entries */

/* VMCB state caching */
#define	VMCB_CACHE_NONE		0	/* No caching */
#define	VMCB_CACHE_I		BIT(0)	/* Intercept, TSC off, Pause filter */
#define	VMCB_CACHE_IOPM		BIT(1)	/* I/O and MSR permission */
#define	VMCB_CACHE_ASID		BIT(2)	/* ASID */
#define	VMCB_CACHE_TPR		BIT(3)	/* V_TPR to V_INTR_VECTOR */
#define	VMCB_CACHE_NP		BIT(4)	/* Nested Paging */
#define	VMCB_CACHE_CR		BIT(5)	/* CR0, CR3, CR4 & EFER */
#define	VMCB_CACHE_DR		BIT(6)	/* Debug registers */
#define	VMCB_CACHE_DT		BIT(7)	/* GDT/IDT */
#define	VMCB_CACHE_SEG		BIT(8)	/* User segments, CPL */
#define	VMCB_CACHE_CR2		BIT(9)	/* page fault address */
#define	VMCB_CACHE_LBR		BIT(10)	/* Last branch */

/* VMCB control event injection */
#define	VMCB_EVENTINJ_EC_VALID		BIT(11)	/* Error Code valid */
#define	VMCB_EVENTINJ_VALID		BIT(31)	/* Event valid */

/* Event types that can be injected */
#define	VMCB_EVENTINJ_TYPE_INTR		0
#define	VMCB_EVENTINJ_TYPE_NMI		(2 << 8)
#define	VMCB_EVENTINJ_TYPE_EXCEPTION	(3 << 8)
#define	VMCB_EVENTINJ_TYPE_INTn		(4 << 8)

/* VMCB exit code, APM vol2 Appendix C */
#define	VMCB_EXIT_CR0_READ		0x00
#define	VMCB_EXIT_CR15_READ		0x0f
#define	VMCB_EXIT_CR0_WRITE		0x10
#define	VMCB_EXIT_CR15_WRITE		0x1f
#define	VMCB_EXIT_EXCP0			0x40
#define	VMCB_EXIT_EXCP31		0x5f
#define	VMCB_EXIT_INTR			0x60
#define	VMCB_EXIT_NMI			0x61
#define	VMCB_EXIT_SMI			0x62
#define	VMCB_EXIT_INIT			0x63
#define	VMCB_EXIT_VINTR			0x64
#define	VMCB_EXIT_CR0_SEL_WRITE		0x65
#define	VMCB_EXIT_RDPMC			0x6f
#define	VMCB_EXIT_PUSHF			0x70
#define	VMCB_EXIT_POPF			0x71
#define	VMCB_EXIT_CPUID			0x72
#define	VMCB_EXIT_IRET			0x74
#define	VMCB_EXIT_INVD			0x76
#define	VMCB_EXIT_PAUSE			0x77
#define	VMCB_EXIT_HLT			0x78
#define	VMCB_EXIT_INVLPG		0x79
#define	VMCB_EXIT_INVLPGA		0x7A
#define	VMCB_EXIT_IO			0x7B
#define	VMCB_EXIT_MSR			0x7C
#define	VMCB_EXIT_SHUTDOWN		0x7F
#define	VMCB_EXIT_VMRUN			0x80
#define	VMCB_EXIT_VMMCALL		0x81
#define	VMCB_EXIT_VMLOAD		0x82
#define	VMCB_EXIT_VMSAVE		0x83
#define	VMCB_EXIT_STGI			0x84
#define	VMCB_EXIT_CLGI			0x85
#define	VMCB_EXIT_SKINIT		0x86
#define	VMCB_EXIT_WBINVD		0x89
#define	VMCB_EXIT_MONITOR		0x8A
#define	VMCB_EXIT_MWAIT			0x8B
#define	VMCB_EXIT_NPF			0x400
#define	VMCB_EXIT_INVALID		-1

/*
 * Move to/from CRx
 * Bit definitions to decode EXITINFO1
 */
#define	VMCB_CRx_INFO1_GPR(x)		((x) & 0xf)
#define	VMCB_CRx_INFO1_VALID(x)		((x) & (1UL << 63))

/*
 * Nested page fault.
 * Bit definitions to decode EXITINFO1.
 */
#define	VMCB_NPF_INFO1_P		BIT(0) /* Nested page present. */
#define	VMCB_NPF_INFO1_W		BIT(1) /* Access was write. */
#define	VMCB_NPF_INFO1_U		BIT(2) /* Access was user access. */
#define	VMCB_NPF_INFO1_RSV		BIT(3) /* Reserved bits present. */
#define	VMCB_NPF_INFO1_ID		BIT(4) /* Code read. */

#define	VMCB_NPF_INFO1_GPA		BIT(32) /* Guest physical address. */
#define	VMCB_NPF_INFO1_GPT		BIT(33) /* Guest page table. */

/*
 * EXITINTINFO, Interrupt exit info for all intrecepts.
 * Section 15.7.2, Intercepts during IDT Interrupt Delivery.
 */
#define	VMCB_EXITINTINFO_VECTOR(x)	((x) & 0xFF)
#define	VMCB_EXITINTINFO_TYPE(x)	((x) & (0x7 << 8))
#define	VMCB_EXITINTINFO_EC_VALID(x)	(((x) & BIT(11)) != 0)
#define	VMCB_EXITINTINFO_VALID(x)	(((x) & BIT(31)) != 0)
#define	VMCB_EXITINTINFO_EC(x)		(((x) >> 32) & 0xFFFFFFFF)

/* Offset of various VMCB fields. */
#define	VMCB_OFF_CTRL(x)		(x)
#define	VMCB_OFF_STATE(x)		((x) + 0x400)

#define	VMCB_OFF_CR_INTERCEPT		VMCB_OFF_CTRL(0x0)
#define	VMCB_OFF_DR_INTERCEPT		VMCB_OFF_CTRL(0x4)
#define	VMCB_OFF_EXC_INTERCEPT		VMCB_OFF_CTRL(0x8)
#define	VMCB_OFF_INST1_INTERCEPT	VMCB_OFF_CTRL(0xC)
#define	VMCB_OFF_INST2_INTERCEPT	VMCB_OFF_CTRL(0x10)
#define	VMCB_OFF_IO_PERM		VMCB_OFF_CTRL(0x40)
#define	VMCB_OFF_MSR_PERM		VMCB_OFF_CTRL(0x48)
#define	VMCB_OFF_TSC_OFFSET		VMCB_OFF_CTRL(0x50)
#define	VMCB_OFF_ASID			VMCB_OFF_CTRL(0x58)
#define	VMCB_OFF_TLB_CTRL		VMCB_OFF_CTRL(0x5C)
#define	VMCB_OFF_VIRQ			VMCB_OFF_CTRL(0x60)
#define	VMCB_OFF_EXIT_REASON		VMCB_OFF_CTRL(0x70)
#define	VMCB_OFF_EXITINFO1		VMCB_OFF_CTRL(0x78)
#define	VMCB_OFF_EXITINFO2		VMCB_OFF_CTRL(0x80)
#define	VMCB_OFF_EXITINTINFO		VMCB_OFF_CTRL(0x88)
#define	VMCB_OFF_AVIC_BAR		VMCB_OFF_CTRL(0x98)
#define	VMCB_OFF_NPT_BASE		VMCB_OFF_CTRL(0xB0)
#define	VMCB_OFF_AVIC_PAGE		VMCB_OFF_CTRL(0xE0)
#define	VMCB_OFF_AVIC_LT		VMCB_OFF_CTRL(0xF0)
#define	VMCB_OFF_AVIC_PT		VMCB_OFF_CTRL(0xF8)
#define	VMCB_OFF_SYSENTER_CS		VMCB_OFF_STATE(0x228)
#define	VMCB_OFF_SYSENTER_ESP		VMCB_OFF_STATE(0x230)
#define	VMCB_OFF_SYSENTER_EIP		VMCB_OFF_STATE(0x238)
#define	VMCB_OFF_GUEST_PAT		VMCB_OFF_STATE(0x268)

#ifdef _KERNEL
/* VMCB save state area segment format */
struct vmcb_segment {
	uint16_t	selector;
	uint16_t	attrib;
	uint32_t	limit;
	uint64_t	base;
};
CTASSERT(sizeof (struct vmcb_segment) == 16);

/* Convert to/from vmcb segment access to generic (VMX) access */
#define	VMCB_ATTR2ACCESS(attr)	((((attr) & 0xf00) << 4) | ((attr) & 0xff))
#define	VMCB_ACCESS2ATTR(acc)	((((acc) & 0xf000) >> 4) | ((acc) & 0xff))

/* Code segment descriptor attribute in 12 bit format as saved by VMCB. */
#define	VMCB_CS_ATTRIB_L		BIT(9)	/* Long mode. */
#define	VMCB_CS_ATTRIB_D		BIT(10)	/* OPerand size bit. */

/* Fields for Virtual Interrupt Control (v_irq) */
#define	V_IRQ		BIT(0)	/* Offset 0x60 bit 8 (0x61 bit 0) */
#define	V_VGIF_VALUE	BIT(1)	/* Offset 0x60 bit 9 (0x61 bit 1) */

/* Fields for Virtual Interrupt Control (v_intr_prio) */
#define	V_INTR_PRIO	0xf	/* Offset 0x60 bits 16-19 (0x62 bits 0-3) */
#define	V_IGN_TPR	BIT(4)	/* Offset 0x60 bit 20 (0x62 bit 4) */

/* Fields for Virtual Interrupt Control (v_intr_ctrl) */
#define	V_INTR_MASKING	BIT(0)	/* Offset 0x60 bit 24 (0x63 bit 0) */
#define	V_VGIF_ENABLE	BIT(1)	/* Offset 0x60 bit 25 (0x63 bit 1) */
#define	V_AVIC_ENABLE	BIT(7)	/* Offset 0x60 bit 31 (0x63 bit 7) */

/* Fields in Interrupt Shadow, offset 0x68 */
#define	VIRTUAL_INTR_SHADOW	BIT(0)
#define	GUEST_INTERRUPT_MASK	BIT(1)

/* Fields in Nested Paging, offset 0x90 */
#define	NP_ENABLE		BIT(0)	/* Enable nested paging */
#define	SEV_ENABLE		BIT(1)	/* Enable SEV */
#define	SEV_ES_ENABLE		BIT(2)	/* Enable SEV-ES */
#define	GUEST_MODE_EXEC_TRAP	BIT(3)	/* Guest mode execute trap */
#define	VIRT_TRANSPAR_ENCRYPT	BIT(5)	/* Virtual transparent encryption */

/* Fields in Misc virt controls, offset 0xB8 */
#define	LBR_VIRT_ENABLE		BIT(0)	/* Enable LBR virtualization accel */
#define	VIRT_VMSAVE_VMLOAD	BIT(1)	/* Virtualized VMSAVE/VMLOAD */

/*
 * The VMCB is divided into two areas - the first one contains various
 * control bits including the intercept vector and the second one contains
 * the guest state.
 */

/* VMCB control area - padded up to 1024 bytes */
struct vmcb_ctrl {
	uint32_t intercept[5];	/* 0x00-0x13: all intercepts */
	uint32_t _pad1[10];	/* 0x14-0x3B: Reserved. */
	uint32_t pause_ctrl;	/* 0x3C, PAUSE filter thresh/count */
	uint64_t iopm_base_pa;	/* 0x40: IOPM_BASE_PA */
	uint64_t msrpm_base_pa; /* 0x48: MSRPM_BASE_PA */
	uint64_t tsc_offset;	/* 0x50: TSC_OFFSET */
	uint32_t asid;		/* 0x58: Guest ASID */
	uint8_t tlb_ctrl;	/* 0x5C: TLB_CONTROL */
	uint8_t _pad2[3];	/* 0x5D-0x5F: Reserved. */
	uint8_t v_tpr;		/* 0x60: Virtual TPR */
	uint8_t v_irq;		/* 0x61: V_IRQ, V_GIF_VALUE + Reserved */
	uint8_t v_intr_prio;	/* 0x62: V_INTR_PRIO, V_IGN_TPR */
	uint8_t v_intr_ctrl;	/* 0x63: V_INTR_MASKING, vGIF and AVIC enable */
	uint8_t v_intr_vector;	/* 0x64: Virtual interrupt vector */
	uint8_t _pad3[3];	/* 0x65-0x67: Reserved */
	uint64_t intr_shadow;	/* 0x68: Interrupt shadow (and more) */
	uint64_t exitcode;	/* 0x70, Exitcode */
	uint64_t exitinfo1;	/* 0x78, EXITINFO1 */
	uint64_t exitinfo2;	/* 0x80, EXITINFO2 */
	uint64_t exitintinfo;	/* 0x88, Interrupt exit value. */
	uint64_t np_ctrl;	/* 0x90, Nested paging control. */
	uint64_t _pad4[2];	/* 0x98-0xA7 reserved. */
	uint64_t eventinj;	/* 0xA8, Event injection. */
	uint64_t n_cr3;		/* 0xB0, Nested page table. */
	uint64_t misc_ctrl;	/* 0xB8, Misc virt controls */
	uint32_t vmcb_clean;	/* 0xC0: VMCB clean bits for caching */
	uint32_t _pad5;		/* 0xC4: Reserved */
	uint64_t nrip;		/* 0xC8: Guest next nRIP. */
	uint8_t inst_len;	/* 0xD0: #NPF decode assist */
	uint8_t inst_bytes[15]; /* 0xD1-0xDF: guest instr bytes */
	uint64_t avic_page_pa;	/* 0xEO: AVIC backing page */
	uint64_t _pad6;		/* 0xE8-0xEF: Reserved */
	uint64_t avic_log_tbl;	/* 0xFO: AVIC logical table */
	uint64_t avic_phys_tbl;	/* 0xF8: AVIC physical page */
	uint64_t _pad7;		/* 0x100-0x107: Reserved */
	uint64_t vmsa_pa;	/* 0x108: VMSA pointer */
	uint64_t _pad8[94];	/* 0x110-0x3FF: Reserved */
};
CTASSERT(sizeof (struct vmcb_ctrl) == 1024);
CTASSERT(offsetof(struct vmcb_ctrl, vmsa_pa) == 0x108);

struct vmcb_state {
	struct vmcb_segment es;		/* 0x00: 32bit base */
	struct vmcb_segment cs;		/* 0x10: 32bit base */
	struct vmcb_segment ss;		/* 0x20: 32bit base */
	struct vmcb_segment ds;		/* 0x30: 32bit base */
	struct vmcb_segment fs;		/* 0x40 */
	struct vmcb_segment gs;		/* 0x50 */
	struct vmcb_segment gdt;	/* 0x60: base + 16bit limit */
	struct vmcb_segment ldt;	/* 0x70 */
	struct vmcb_segment idt;	/* 0x80: base + 16bit limit */
	struct vmcb_segment tr;		/* 0x90 */
	uint8_t _pad1[43];		/* 0xA0-0xCA: Reserved */
	uint8_t cpl;			/* 0xCB: CPL (real mode: 0, virt: 3) */
	uint32_t _pad2;			/* 0xCC-0xCF: Reserved */
	uint64_t efer;			/* 0xD0 */
	uint64_t _pad3[14];		/* 0xD8-0x147: Reserved */
	uint64_t cr4;			/* 0x148 */
	uint64_t cr3;			/* 0x150 */
	uint64_t cr0;			/* 0x158 */
	uint64_t dr7;			/* 0x160 */
	uint64_t dr6;			/* 0x168 */
	uint64_t rflags;		/* 0x170 */
	uint64_t rip;			/* 0x178 */
	uint64_t _pad4[11];		/* 0x180-0x1D7: Reserved */
	uint64_t rsp;			/* 0x1D8 */
	uint64_t _pad5[3];		/* 0x1E0-0x1F7: Reserved */
	uint64_t rax;			/* 0x1F8 */
	uint64_t star;			/* 0x200 */
	uint64_t lstar;			/* 0x208 */
	uint64_t cstar;			/* 0x210 */
	uint64_t sfmask;		/* 0x218 */
	uint64_t kernelgsbase;		/* 0x220 */
	uint64_t sysenter_cs;		/* 0x228 */
	uint64_t sysenter_esp;		/* 0x230 */
	uint64_t sysenter_eip;		/* 0x238 */
	uint64_t cr2;			/* 0x240 */
	uint64_t _pad6[4];		/* 0x248-0x267: Reserved */
	uint64_t g_pat;			/* 0x268 */
	uint64_t dbgctl;		/* 0x270 */
	uint64_t br_from;		/* 0x278 */
	uint64_t br_to;			/* 0x280 */
	uint64_t int_from;		/* 0x288 */
	uint64_t int_to;		/* 0x290 */
	uint64_t _pad7[301];		/* Reserved up to end of VMCB */
};
CTASSERT(sizeof (struct vmcb_state) == 0xC00);
CTASSERT(offsetof(struct vmcb_state, int_to) == 0x290);

/*
 * The VMCB aka Virtual Machine Control Block is a 4KB aligned page
 * in memory that describes the virtual machine.
 *
 * The VMCB contains:
 * - instructions or events in the guest to intercept
 * - control bits that modify execution environment of the guest
 * - guest processor state (e.g. general purpose registers)
 */
struct vmcb {
	struct vmcb_ctrl ctrl;
	struct vmcb_state state;
};
CTASSERT(sizeof (struct vmcb) == PAGE_SIZE);
CTASSERT(offsetof(struct vmcb, state) == 0x400);

struct vmcb_segment *vmcb_segptr(struct vmcb *vmcb, int type);
uint64_t *vmcb_regptr(struct vmcb *vmcb, int ident, uint32_t *dirtyp);
uint64_t *vmcb_msr_ptr(struct vmcb *vmcb, uint32_t ident, uint32_t *dirtyp);

#endif /* _KERNEL */
#endif /* _VMCB_H_ */
