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
	blendpd		$0x42, (%ebx), %xmm1
	blendps		$0x42, %xmm0, %xmm1
	blendps		$0x42, (%ebx), %xmm1
	blendvpd	%xmm1, %xmm2
	blendvpd	(%ebx), %xmm2
	blendvpd	0x42(%ebx), %xmm2
	blendvps	%xmm1, %xmm2
	blendvps	(%ebx), %xmm2
	blendvps	0x42(%ebx), %xmm2
	dppd		$0x42, %xmm0, %xmm1
	dppd		$0x42, (%ebx), %xmm1
	dpps		$0x42, %xmm0, %xmm1
	dpps		$0x42, (%ebx), %xmm1
	extractps	$0x23, %xmm6, %ebx
	extractps	$0x23, %xmm6, (%ebx)
	insertps	$0x23, %xmm1, %xmm2
	insertps	$0x23, (%ebx), %xmm2
	insertps	$0x23, 0x42(%ebx), %xmm2
	movntdqa	(%ebx), %xmm0
	mpsadbw		$0x23, %xmm1, %xmm2
	mpsadbw		$0x23, (%ebx), %xmm2
	mpsadbw		$0x23, 0x42(%ebx), %xmm2
	packusdw	%xmm1, %xmm2
	packusdw	(%ebx), %xmm2
	packusdw	0x42(%ebx), %xmm2
	pblendvb	%xmm1, %xmm2
	pblendvb	(%ebx), %xmm2
	pblendvb	0x42(%ebx), %xmm2
	pblendw		$0x23, %xmm1, %xmm2
	pblendw		$0x23, (%ebx), %xmm2
	pblendw		$0x23, 0x42(%ebx), %xmm2
	pcmpeqq		%xmm1, %xmm2
	pcmpeqq		(%ebx), %xmm2
	pcmpeqq		0x42(%ebx), %xmm2
	pextrb		$0x23, %xmm4, %edx
	pextrb		$0x23, %xmm4, (%edx)
	pextrd		$0x23, %xmm4, %edx
	pextrd		$0x23, %xmm4, (%edx)
	pextrw		$0x23, %xmm4, %edx
	pextrw		$0x23, %xmm4, (%edx)
	phminposuw	%xmm1, %xmm2
	phminposuw	(%ebx), %xmm2
	phminposuw	0x42(%ebx), %xmm2
	pinsrb		$0x23, %ebx, %xmm2
	pinsrb		$0x23, (%ebx), %xmm2
	pinsrb		$0x23, 0x42(%ebx), %xmm2
	pinsrd		$0x23, %ebx, %xmm2
	pinsrd		$0x23, (%ebx), %xmm2
	pinsrd		$0x23, 0x42(%ebx), %xmm2
	pmaxsb		%xmm1, %xmm2
	pmaxsb		(%ebx), %xmm2
	pmaxsb		0x42(%ebx), %xmm2
	pmaxsd		%xmm1, %xmm2
	pmaxsd		(%ebx), %xmm2
	pmaxsd		0x42(%ebx), %xmm2
	pmaxud		%xmm1, %xmm2
	pmaxud		(%ebx), %xmm2
	pmaxud		0x42(%ebx), %xmm2
	pmaxuw		%xmm1, %xmm2
	pmaxuw		(%ebx), %xmm2
	pmaxuw		0x42(%ebx), %xmm2
	pminsb		%xmm1, %xmm2
	pminsb		(%ebx), %xmm2
	pminsb		0x42(%ebx), %xmm2
	pminsd		%xmm1, %xmm2
	pminsd		(%ebx), %xmm2
	pminsd		0x42(%ebx), %xmm2
	pminud		%xmm1, %xmm2
	pminud		(%ebx), %xmm2
	pminud		0x42(%ebx), %xmm2
	pminuw		%xmm1, %xmm2
	pminuw		(%ebx), %xmm2
	pminuw		0x42(%ebx), %xmm2
	pmovsxbd	%xmm1, %xmm2
	pmovsxbd	(%ebx), %xmm2
	pmovsxbd	0x42(%ebx), %xmm2
	pmovsxbq	%xmm1, %xmm2
	pmovsxbq	(%ebx), %xmm2
	pmovsxbq	0x42(%ebx), %xmm2
	pmovsxbw	%xmm1, %xmm2
	pmovsxbw	(%ebx), %xmm2
	pmovsxbw	0x42(%ebx), %xmm2
	pmovsxdq	%xmm1, %xmm2
	pmovsxdq	(%ebx), %xmm2
	pmovsxdq	0x42(%ebx), %xmm2
	pmovsxwd	%xmm1, %xmm2
	pmovsxwd	(%ebx), %xmm2
	pmovsxwd	0x42(%ebx), %xmm2
	pmovsxwq	%xmm1, %xmm2
	pmovsxwq	(%ebx), %xmm2
	pmovsxwq	0x42(%ebx), %xmm2
	pmovzxbd	%xmm1, %xmm2
	pmovzxbd	(%ebx), %xmm2
	pmovzxbd	0x42(%ebx), %xmm2
	pmovzxbq	%xmm1, %xmm2
	pmovzxbq	(%ebx), %xmm2
	pmovzxbq	0x42(%ebx), %xmm2
	pmovzxbw	%xmm1, %xmm2
	pmovzxbw	(%ebx), %xmm2
	pmovzxbw	0x42(%ebx), %xmm2
	pmovzxdq	%xmm1, %xmm2
	pmovzxdq	(%ebx), %xmm2
	pmovzxdq	0x42(%ebx), %xmm2
	pmovzxwd	%xmm1, %xmm2
	pmovzxwd	(%ebx), %xmm2
	pmovzxwd	0x42(%ebx), %xmm2
	pmovzxwq	%xmm1, %xmm2
	pmovzxwq	(%ebx), %xmm2
	pmovzxwq	0x42(%ebx), %xmm2
	pmuldq		%xmm1, %xmm2
	pmuldq		(%ebx), %xmm2
	pmuldq		0x42(%ebx), %xmm2
	pmulld		%xmm1, %xmm2
	pmulld		(%ebx), %xmm2
	pmulld		0x42(%ebx), %xmm2
	ptest		%xmm1, %xmm2
	ptest		(%ebx), %xmm2
	ptest		0x42(%ebx), %xmm2
	roundpd		$0x23, %xmm1, %xmm2
	roundpd		$0x23, (%ebx), %xmm2
	roundpd		$0x23, 0x42(%ebx), %xmm2
	roundps		$0x23, %xmm1, %xmm2
	roundps		$0x23, (%ebx), %xmm2
	roundps		$0x23, 0x42(%ebx), %xmm2
	roundsd		$0x23, %xmm1, %xmm2
	roundsd		$0x23, (%ebx), %xmm2
	roundsd		$0x23, 0x42(%ebx), %xmm2
	roundss		$0x23, %xmm1, %xmm2
	roundss		$0x23, (%ebx), %xmm2
	roundss		$0x23, 0x42(%ebx), %xmm2
.size libdis_test, [.-libdis_test]
