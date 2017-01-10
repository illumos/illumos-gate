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
	crc32b		%al, %ebx
	crc32b		%al, %rbx
	crc32b		(%rax), %ebx
	crc32w		%ax, %ebx
	crc32w		(%rax), %ebx
	crc32l		%eax, %ebx
	crc32l		(%rax), %ebx
	crc32q		%rax, %rbx
	crc32q		(%rax), %rbx
	pcmpestri	$0x23, %xmm0, %xmm1
	pcmpestri	$0x23, (%rax), %xmm1
	pcmpestrm	$0x23, %xmm0, %xmm1
	pcmpestrm	$0x23, (%rax), %xmm1
	pcmpgtq		%xmm0, %xmm1
	pcmpgtq		(%rax), %xmm1
	pcmpistri	$0x23, %xmm0, %xmm1
	pcmpistri	$0x23, (%rax), %xmm1
	pcmpistrm	$0x23, %xmm0, %xmm1
	pcmpistrm	$0x23, (%rax), %xmm1
.size libdis_test, [.-libdis_test]
