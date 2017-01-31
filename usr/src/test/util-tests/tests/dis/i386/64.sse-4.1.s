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
 * Test SSE 4.2 related instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	blendpd		$0x42, %xmm0, %xmm1
	blendpd		$0x42, (%rbx), %xmm1
	blendps		$0x42, %xmm0, %xmm1
	blendps		$0x42, (%rbx), %xmm1
	blendvpd	%xmm1, %xmm2
	blendvpd	(%rbx), %xmm2
	blendvpd	0x42(%rbx), %xmm2
	blendvps	%xmm1, %xmm2
	blendvps	(%rbx), %xmm2
	blendvps	0x42(%rbx), %xmm2
	dppd		$0x42, %xmm0, %xmm1
	dppd		$0x42, (%rbx), %xmm1
	dpps		$0x42, %xmm0, %xmm1
	dpps		$0x42, (%rbx), %xmm1
	extractps	$0x23, %xmm6, %rbx
	extractps	$0x23, %xmm6, (%rbx)
	insertps	$0x23, %xmm1, %xmm2
	insertps	$0x23, (%rbx), %xmm2
	insertps	$0x23, 0x42(%rbx), %xmm2
	movntdqa	(%rbx), %xmm0
	mpsadbw		$0x23, %xmm1, %xmm2
	mpsadbw		$0x23, (%rbx), %xmm2
	mpsadbw		$0x23, 0x42(%rbx), %xmm2
	packusdw	%xmm1, %xmm2
	packusdw	(%rbx), %xmm2
	packusdw	0x42(%rbx), %xmm2
	pblendvb	%xmm1, %xmm2
	pblendvb	(%rbx), %xmm2
	pblendvb	0x42(%rbx), %xmm2
	pblendw		$0x23, %xmm1, %xmm2
	pblendw		$0x23, (%rbx), %xmm2
	pblendw		$0x23, 0x42(%rbx), %xmm2
	pcmpeqq		%xmm1, %xmm2
	pcmpeqq		(%rbx), %xmm2
	pcmpeqq		0x42(%rbx), %xmm2
	pextrb		$0x23, %xmm4, %rdx
	pextrb		$0x23, %xmm4, (%rdx)
	pextrd		$0x23, %xmm4, %edx
	pextrd		$0x23, %xmm4, (%rdx)
	pextrq		$0x23, %xmm4, %rdx
	pextrq		$0x23, %xmm4, (%rdx)
	pextrw		$0x23, %xmm4, %rdx
	pextrw		$0x23, %xmm4, (%rdx)
	phminposuw	%xmm1, %xmm2
	phminposuw	(%rbx), %xmm2
	phminposuw	0x42(%rbx), %xmm2
	pinsrb		$0x23, %rbx, %xmm2
	pinsrb		$0x23, (%rbx), %xmm2
	pinsrb		$0x23, 0x42(%rbx), %xmm2
	pinsrd		$0x23, %ebx, %xmm2
	pinsrd		$0x23, (%rbx), %xmm2
	pinsrd		$0x23, 0x42(%rbx), %xmm2
	pinsrq		$0x23, %rbx, %xmm2
	pinsrq		$0x23, (%rbx), %xmm2
	pinsrq		$0x23, 0x42(%rbx), %xmm2
	pmaxsb		%xmm1, %xmm2
	pmaxsb		(%rbx), %xmm2
	pmaxsb		0x42(%rbx), %xmm2
	pmaxsd		%xmm1, %xmm2
	pmaxsd		(%rbx), %xmm2
	pmaxsd		0x42(%rbx), %xmm2
	pmaxud		%xmm1, %xmm2
	pmaxud		(%rbx), %xmm2
	pmaxud		0x42(%rbx), %xmm2
	pmaxuw		%xmm1, %xmm2
	pmaxuw		(%rbx), %xmm2
	pmaxuw		0x42(%rbx), %xmm2
	pminsb		%xmm1, %xmm2
	pminsb		(%rbx), %xmm2
	pminsb		0x42(%rbx), %xmm2
	pminsd		%xmm1, %xmm2
	pminsd		(%rbx), %xmm2
	pminsd		0x42(%rbx), %xmm2
	pminud		%xmm1, %xmm2
	pminud		(%rbx), %xmm2
	pminud		0x42(%rbx), %xmm2
	pminuw		%xmm1, %xmm2
	pminuw		(%rbx), %xmm2
	pminuw		0x42(%rbx), %xmm2
	pmovsxbd	%xmm1, %xmm2
	pmovsxbd	(%rbx), %xmm2
	pmovsxbd	0x42(%rbx), %xmm2
	pmovsxbq	%xmm1, %xmm2
	pmovsxbq	(%rbx), %xmm2
	pmovsxbq	0x42(%rbx), %xmm2
	pmovsxbw	%xmm1, %xmm2
	pmovsxbw	(%rbx), %xmm2
	pmovsxbw	0x42(%rbx), %xmm2
	pmovsxdq	%xmm1, %xmm2
	pmovsxdq	(%rbx), %xmm2
	pmovsxdq	0x42(%rbx), %xmm2
	pmovsxwd	%xmm1, %xmm2
	pmovsxwd	(%rbx), %xmm2
	pmovsxwd	0x42(%rbx), %xmm2
	pmovsxwq	%xmm1, %xmm2
	pmovsxwq	(%rbx), %xmm2
	pmovsxwq	0x42(%rbx), %xmm2
	pmovzxbd	%xmm1, %xmm2
	pmovzxbd	(%rbx), %xmm2
	pmovzxbd	0x42(%rbx), %xmm2
	pmovzxbq	%xmm1, %xmm2
	pmovzxbq	(%rbx), %xmm2
	pmovzxbq	0x42(%rbx), %xmm2
	pmovzxbw	%xmm1, %xmm2
	pmovzxbw	(%rbx), %xmm2
	pmovzxbw	0x42(%rbx), %xmm2
	pmovzxdq	%xmm1, %xmm2
	pmovzxdq	(%rbx), %xmm2
	pmovzxdq	0x42(%rbx), %xmm2
	pmovzxwd	%xmm1, %xmm2
	pmovzxwd	(%rbx), %xmm2
	pmovzxwd	0x42(%rbx), %xmm2
	pmovzxwq	%xmm1, %xmm2
	pmovzxwq	(%rbx), %xmm2
	pmovzxwq	0x42(%rbx), %xmm2
	pmuldq		%xmm1, %xmm2
	pmuldq		(%rbx), %xmm2
	pmuldq		0x42(%rbx), %xmm2
	pmulld		%xmm1, %xmm2
	pmulld		(%rbx), %xmm2
	pmulld		0x42(%rbx), %xmm2
	ptest		%xmm1, %xmm2
	ptest		(%rbx), %xmm2
	ptest		0x42(%rbx), %xmm2
	roundpd		$0x23, %xmm1, %xmm2
	roundpd		$0x23, (%rbx), %xmm2
	roundpd		$0x23, 0x42(%rbx), %xmm2
	roundps		$0x23, %xmm1, %xmm2
	roundps		$0x23, (%rbx), %xmm2
	roundps		$0x23, 0x42(%rbx), %xmm2
	roundsd		$0x23, %xmm1, %xmm2
	roundsd		$0x23, (%rbx), %xmm2
	roundsd		$0x23, 0x42(%rbx), %xmm2
	roundss		$0x23, %xmm1, %xmm2
	roundss		$0x23, (%rbx), %xmm2
	roundss		$0x23, 0x42(%rbx), %xmm2
.size libdis_test, [.-libdis_test]
