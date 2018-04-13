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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Companion to kdi_asm.s - the implementation of the trap and interrupt
 * handlers.  For the most part, these handlers do the same thing - they
 * push a trap number onto the stack, followed by a jump to kdi_cmnint.
 * Each trap and interrupt has its own handler because each one pushes a
 * different number.
 */

#if defined(__lint)
#include <sys/types.h>
#else

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/machprivregs.h>
#include <sys/privregs.h>
#include <sys/kdi_regs.h>
#include <sys/trap.h>
#include <sys/param.h>

#include <kdi_assym.h>
#include <assym.h>

/*
 * The default ASM_ENTRY_ALIGN (16) wastes far too much space.
 */
#undef	ASM_ENTRY_ALIGN
#define	ASM_ENTRY_ALIGN	8

/*
 * Generic trap and interrupt handlers.
 */

#if defined(__xpv)

#define	INTERRUPT_TRAMPOLINE

#else

/*
 * If we're !xpv, then we will need to support KPTI (kernel page table
 * isolation), where we have separate page tables for user and kernel modes.
 * There's more detail about this in kpti_trampolines.s and hat_i86.c
 */

#define	INTERRUPT_TRAMPOLINE			\
	pushq	%r13;				\
	pushq	%r14;				\
	subq	$KPTI_R14, %rsp;		\
	/* Check for clobbering */		\
	cmp	$0, KPTI_FLAG(%rsp);		\
	je	1f;				\
	/* Don't worry, this totally works */	\
	int	$8;				\
1:						\
	movq	$1, KPTI_FLAG(%rsp);		\
	/* Save current %cr3. */		\
	mov	%cr3, %r14;			\
	mov	%r14, KPTI_TR_CR3(%rsp);	\
	/* Switch to paranoid %cr3. */		\
	mov	kpti_safe_cr3, %r14;		\
	mov	%r14, %cr3;			\
						\
	cmpw	$KCS_SEL, KPTI_CS(%rsp);	\
	je	3f;				\
2:						\
	/* Get our cpu_t in %r13 */		\
	mov	%rsp, %r13;			\
	and	$(~(MMU_PAGESIZE - 1)), %r13;	\
	subq	$CPU_KPTI_START, %r13;		\
	/* Use top of the kthread stk */	\
	mov	CPU_THREAD(%r13), %r14;		\
	mov	T_STACK(%r14), %r14;		\
	addq	$REGSIZE+MINFRAME, %r14;	\
	jmp	5f;				\
3:						\
	/* Check the %rsp in the frame. */	\
	/* Is it above kernel base? */		\
	mov	kpti_kbase, %r14;		\
	cmp	%r14, KPTI_RSP(%rsp);		\
	jb	2b;				\
	/* Is it within the kpti_frame page? */	\
	mov	%rsp, %r13;			\
	and	$(~(MMU_PAGESIZE - 1)), %r13;	\
	mov	KPTI_RSP(%rsp), %r14;		\
	and	$(~(MMU_PAGESIZE - 1)), %r14;	\
	cmp	%r13, %r14;			\
	je	2b;				\
	/* Use the %rsp from the trap frame. */	\
	/* We already did %cr3. */		\
	mov	KPTI_RSP(%rsp), %r14;		\
	and	$(~0xf), %r14;			\
5:						\
	mov	%rsp, %r13;			\
	/* %r14 contains our destination stk */	\
	mov	%r14, %rsp;			\
	pushq	KPTI_SS(%r13);			\
	pushq	KPTI_RSP(%r13);			\
	pushq	KPTI_RFLAGS(%r13);		\
	pushq	KPTI_CS(%r13);			\
	pushq	KPTI_RIP(%r13);			\
	pushq	KPTI_ERR(%r13);			\
	mov	KPTI_R14(%r13), %r14;		\
	movq	$0, KPTI_FLAG(%r13);		\
	mov	KPTI_R13(%r13), %r13

#endif	/* !__xpv */


#define	MKIVCT(n) \
	ENTRY_NP(kdi_ivct/**/n/**/);	\
	XPV_TRAP_POP;			\
	push	$0; /* err */		\
	INTERRUPT_TRAMPOLINE;		\
	push	$n;			\
	jmp	kdi_cmnint;		\
	SET_SIZE(kdi_ivct/**/n/**/)

#define	MKTRAPHDLR(n) \
	ENTRY_NP(kdi_trap/**/n);	\
	XPV_TRAP_POP;			\
	push	$0; /* err */		\
	INTERRUPT_TRAMPOLINE;		\
	push	$n;			\
	jmp	kdi_cmnint;		\
	SET_SIZE(kdi_trap/**/n/**/)

#define	MKTRAPERRHDLR(n) \
	ENTRY_NP(kdi_traperr/**/n);	\
	XPV_TRAP_POP;			\
	INTERRUPT_TRAMPOLINE;		\
	push	$n;			\
	jmp	kdi_cmnint;		\
	SET_SIZE(kdi_traperr/**/n)

#if !defined(__xpv)
#define	MKNMIHDLR \
	ENTRY_NP(kdi_int2);		\
	push	$0;			\
	push	$2;			\
	pushq	%r13;			\
	mov	kpti_safe_cr3, %r13;	\
	mov	%r13, %cr3;		\
	popq	%r13;			\
	jmp	kdi_nmiint;		\
	SET_SIZE(kdi_int2)

#define	MKMCEHDLR \
	ENTRY_NP(kdi_trap18);		\
	push	$0;			\
	push	$18;			\
	pushq	%r13;			\
	mov	kpti_safe_cr3, %r13;	\
	mov	%r13, %cr3;		\
	popq	%r13;			\
	jmp	kdi_cmnint;		\
	SET_SIZE(kdi_trap18)
#else
#define	MKNMIHDLR \
	ENTRY_NP(kdi_int2);		\
	push	$0;			\
	push	$2;			\
	jmp	kdi_nmiint;		\
	SET_SIZE(kdi_int2)

#define	MKMCEHDLR \
	ENTRY_NP(kdi_trap18);		\
	push	$0;			\
	push	$18;			\
	jmp	kdi_cmnint;		\
	SET_SIZE(kdi_trap18)
#endif

/*
 * The only way we should reach here is by an explicit "int 0x.." which is
 * defined not to push an error code.
 */
#define	MKINVALHDLR \
	ENTRY_NP(kdi_invaltrap);	\
	XPV_TRAP_POP;			\
	push	$0; /* err */		\
	INTERRUPT_TRAMPOLINE;		\
	push	$255;			\
	jmp	kdi_cmnint;		\
	SET_SIZE(kdi_invaltrap)

	.data
	DGDEF3(kdi_idt, 16 * NIDT, MMU_PAGESIZE)
	.fill	MMU_PAGESIZE, 1, 0

#if !defined(__xpv)
.section ".text"
.align MMU_PAGESIZE
.global kdi_isr_start
kdi_isr_start:
	nop

.global kpti_safe_cr3
.global kpti_kbase
#endif

/*
 * The handlers themselves
 */

	MKINVALHDLR
	MKTRAPHDLR(0)
	MKTRAPHDLR(1)
	MKNMIHDLR/*2*/
	MKTRAPHDLR(3)
	MKTRAPHDLR(4)
	MKTRAPHDLR(5)
	MKTRAPHDLR(6)
	MKTRAPHDLR(7)
	MKTRAPHDLR(9)
	MKTRAPHDLR(15)
	MKTRAPHDLR(16)
	MKMCEHDLR/*18*/
	MKTRAPHDLR(19)
	MKTRAPHDLR(20)

	MKTRAPERRHDLR(8)
	MKTRAPERRHDLR(10)
	MKTRAPERRHDLR(11)
	MKTRAPERRHDLR(12)
	MKTRAPERRHDLR(13)
	MKTRAPERRHDLR(14)
	MKTRAPERRHDLR(17)

	.globl	kdi_ivct_size
kdi_ivct_size:
	.NWORD [kdi_ivct33-kdi_ivct32]

	/* 10 billion and one interrupt handlers */
kdi_ivct_base:
	MKIVCT(32);	MKIVCT(33);	MKIVCT(34);	MKIVCT(35);
	MKIVCT(36);	MKIVCT(37);	MKIVCT(38);	MKIVCT(39);
	MKIVCT(40);	MKIVCT(41);	MKIVCT(42);	MKIVCT(43);
	MKIVCT(44);	MKIVCT(45);	MKIVCT(46);	MKIVCT(47);
	MKIVCT(48);	MKIVCT(49);	MKIVCT(50);	MKIVCT(51);
	MKIVCT(52);	MKIVCT(53);	MKIVCT(54);	MKIVCT(55);
	MKIVCT(56);	MKIVCT(57);	MKIVCT(58);	MKIVCT(59);
	MKIVCT(60);	MKIVCT(61);	MKIVCT(62);	MKIVCT(63);
	MKIVCT(64);	MKIVCT(65);	MKIVCT(66);	MKIVCT(67);
	MKIVCT(68);	MKIVCT(69);	MKIVCT(70);	MKIVCT(71);
	MKIVCT(72);	MKIVCT(73);	MKIVCT(74);	MKIVCT(75);
	MKIVCT(76);	MKIVCT(77);	MKIVCT(78);	MKIVCT(79);
	MKIVCT(80);	MKIVCT(81);	MKIVCT(82);	MKIVCT(83);
	MKIVCT(84);	MKIVCT(85);	MKIVCT(86);	MKIVCT(87);
	MKIVCT(88);	MKIVCT(89);	MKIVCT(90);	MKIVCT(91);
	MKIVCT(92);	MKIVCT(93);	MKIVCT(94);	MKIVCT(95);
	MKIVCT(96);	MKIVCT(97);	MKIVCT(98);	MKIVCT(99);
	MKIVCT(100);	MKIVCT(101);	MKIVCT(102);	MKIVCT(103);
	MKIVCT(104);	MKIVCT(105);	MKIVCT(106);	MKIVCT(107);
	MKIVCT(108);	MKIVCT(109);	MKIVCT(110);	MKIVCT(111);
	MKIVCT(112);	MKIVCT(113);	MKIVCT(114);	MKIVCT(115);
	MKIVCT(116);	MKIVCT(117);	MKIVCT(118);	MKIVCT(119);
	MKIVCT(120);	MKIVCT(121);	MKIVCT(122);	MKIVCT(123);
	MKIVCT(124);	MKIVCT(125);	MKIVCT(126);	MKIVCT(127);
	MKIVCT(128);	MKIVCT(129);	MKIVCT(130);	MKIVCT(131);
	MKIVCT(132);	MKIVCT(133);	MKIVCT(134);	MKIVCT(135);
	MKIVCT(136);	MKIVCT(137);	MKIVCT(138);	MKIVCT(139);
	MKIVCT(140);	MKIVCT(141);	MKIVCT(142);	MKIVCT(143);
	MKIVCT(144);	MKIVCT(145);	MKIVCT(146);	MKIVCT(147);
	MKIVCT(148);	MKIVCT(149);	MKIVCT(150);	MKIVCT(151);
	MKIVCT(152);	MKIVCT(153);	MKIVCT(154);	MKIVCT(155);
	MKIVCT(156);	MKIVCT(157);	MKIVCT(158);	MKIVCT(159);
	MKIVCT(160);	MKIVCT(161);	MKIVCT(162);	MKIVCT(163);
	MKIVCT(164);	MKIVCT(165);	MKIVCT(166);	MKIVCT(167);
	MKIVCT(168);	MKIVCT(169);	MKIVCT(170);	MKIVCT(171);
	MKIVCT(172);	MKIVCT(173);	MKIVCT(174);	MKIVCT(175);
	MKIVCT(176);	MKIVCT(177);	MKIVCT(178);	MKIVCT(179);
	MKIVCT(180);	MKIVCT(181);	MKIVCT(182);	MKIVCT(183);
	MKIVCT(184);	MKIVCT(185);	MKIVCT(186);	MKIVCT(187);
	MKIVCT(188);	MKIVCT(189);	MKIVCT(190);	MKIVCT(191);
	MKIVCT(192);	MKIVCT(193);	MKIVCT(194);	MKIVCT(195);
	MKIVCT(196);	MKIVCT(197);	MKIVCT(198);	MKIVCT(199);
	MKIVCT(200);	MKIVCT(201);	MKIVCT(202);	MKIVCT(203);
	MKIVCT(204);	MKIVCT(205);	MKIVCT(206);	MKIVCT(207);
	MKIVCT(208);	MKIVCT(209);	MKIVCT(210);	MKIVCT(211);
	MKIVCT(212);	MKIVCT(213);	MKIVCT(214);	MKIVCT(215);
	MKIVCT(216);	MKIVCT(217);	MKIVCT(218);	MKIVCT(219);
	MKIVCT(220);	MKIVCT(221);	MKIVCT(222);	MKIVCT(223);
	MKIVCT(224);	MKIVCT(225);	MKIVCT(226);	MKIVCT(227);
	MKIVCT(228);	MKIVCT(229);	MKIVCT(230);	MKIVCT(231);
	MKIVCT(232);	MKIVCT(233);	MKIVCT(234);	MKIVCT(235);
	MKIVCT(236);	MKIVCT(237);	MKIVCT(238);	MKIVCT(239);
	MKIVCT(240);	MKIVCT(241);	MKIVCT(242);	MKIVCT(243);
	MKIVCT(244);	MKIVCT(245);	MKIVCT(246);	MKIVCT(247);
	MKIVCT(248);	MKIVCT(249);	MKIVCT(250);	MKIVCT(251);
	MKIVCT(252);	MKIVCT(253);	MKIVCT(254);	MKIVCT(255);

#if !defined(__xpv)
.section ".text"
.align MMU_PAGESIZE
.global kdi_isr_end
kdi_isr_end:
	nop
#endif

#endif /* !__lint */
