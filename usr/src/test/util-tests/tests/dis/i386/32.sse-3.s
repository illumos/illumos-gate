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
	addsubpd	(%edx), %xmm2
	addsubpd	0x23(%esp), %xmm2
	addsubps	%xmm0, %xmm1
	addsubps	(%edx), %xmm2
	addsubps	0x23(%esp), %xmm2
	haddpd		%xmm0, %xmm1
	haddpd		(%edx), %xmm2
	haddpd		0x23(%esp), %xmm2
	haddps		%xmm0, %xmm1
	haddps		(%edx), %xmm2
	haddps		0x23(%esp), %xmm2
	hsubpd		%xmm0, %xmm1
	hsubpd		(%edx), %xmm2
	hsubpd		0x23(%esp), %xmm2
	hsubps		%xmm0, %xmm1
	hsubps		(%edx), %xmm2
	hsubps		0x23(%esp), %xmm2
	lddqu		(%eax), %xmm3
	movddup		%xmm4, %xmm5
	movddup		(%eax), %xmm6
	movddup		0x42(%ebx), %xmm7
	movshdup	%xmm4, %xmm5
	movshdup	(%eax), %xmm6
	movshdup	0x42(%ebx), %xmm7
	movsldup	%xmm4, %xmm5
	movsldup	(%eax), %xmm6
	movsldup	0x42(%ebx), %xmm7
	fisttp		0x1234(%eax)
	fisttpl		0x1234(%eax)
	fisttpll	0x1234(%eax)
.size libdis_test, [.-libdis_test]
