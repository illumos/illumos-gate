/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Test SSE 3 related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	addsubpd	%xmm0, %xmm1
	addsubpd	(%rdx), %xmm2
	addsubpd	0x23(%rsp), %xmm2
	addsubps	%xmm0, %xmm1
	addsubps	(%rdx), %xmm2
	addsubps	0x23(%rsp), %xmm2
	haddpd		%xmm0, %xmm1
	haddpd		(%rdx), %xmm2
	haddpd		0x23(%rsp), %xmm2
	haddps		%xmm0, %xmm1
	haddps		(%rdx), %xmm2
	haddps		0x23(%rsp), %xmm2
	hsubpd		%xmm0, %xmm1
	hsubpd		(%rdx), %xmm2
	hsubpd		0x23(%rsp), %xmm2
	hsubps		%xmm0, %xmm1
	hsubps		(%rdx), %xmm2
	hsubps		0x23(%rsp), %xmm2
	lddqu		(%rax), %xmm3
	movddup		%xmm4, %xmm5
	movddup		(%rax), %xmm6
	movddup		0x42(%rbx), %xmm7
	movshdup	%xmm4, %xmm5
	movshdup	(%rax), %xmm6
	movshdup	0x42(%rbx), %xmm7
	movsldup	%xmm4, %xmm5
	movsldup	(%rax), %xmm6
	movsldup	0x42(%rbx), %xmm7
	fisttp		0x1234(%rax)
	fisttpl		0x1234(%rax)
	fisttpll	0x1234(%rax)
.size libdis_test, [.-libdis_test]
