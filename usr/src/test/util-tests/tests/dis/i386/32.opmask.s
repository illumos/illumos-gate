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
 * Copyright 2017 Joyent, Inc.
 */

/*
 * Test opmask instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	kaddw		%k0, %k1, %k2
	kaddb		%k3, %k4, %k5
	kaddd		%k6, %k7, %k0
	kaddq		%k1, %k2, %k3

	kandw		%k0, %k1, %k2
	kandb		%k3, %k4, %k5
	kandd		%k6, %k7, %k0
	kandq		%k1, %k2, %k3

	kandnw		%k0, %k1, %k2
	kandnb		%k3, %k4, %k5
	kandnd		%k6, %k7, %k0
	kandnq		%k1, %k2, %k3

	korw		%k0, %k1, %k2
	korb		%k3, %k4, %k5
	kord		%k6, %k7, %k0
	korq		%k1, %k2, %k3

	kxnorw		%k0, %k1, %k2
	kxnorb		%k3, %k4, %k5
	kxnord		%k6, %k7, %k0
	kxnorq		%k1, %k2, %k3

	kxorw		%k0, %k1, %k2
	kxorb		%k3, %k4, %k5
	kxord		%k6, %k7, %k0
	kxorq		%k1, %k2, %k3

	kunpckbw	%k0, %k1, %k2
	kunpckwd	%k3, %k4, %k5
	kunpckdq	%k6, %k7, %k0

	knotw		%k0, %k1
	knotb		%k2, %k3
	knotd		%k4, %k5
	knotq		%k6, %k7

	kortestw	%k0, %k1
	kortestb	%k2, %k3
	kortestd	%k4, %k5
	kortestq	%k6, %k7

	ktestw		%k0, %k1
	ktestb		%k2, %k3
	ktestd		%k4, %k5
	ktestq		%k6, %k7

	kshiftlw	$1, %k0, %k1
	kshiftlb	$1, %k2, %k3
	kshiftld	$1, %k4, %k5
	kshiftlq	$1, %k6, %k7

	kshiftrw	$1, %k0, %k1
	kshiftrb	$1, %k2, %k3
	kshiftrd	$1, %k4, %k5
	kshiftrq	$1, %k6, %k7

	kmovw		%eax, %k7
	kmovb		%ebx, %k5
	kmovd		%ecx, %k3

	kmovw		%k0, %edx
	kmovb		%k2, %ecx
	kmovd		%k4, %ebx

	kmovw		%k0, (%edx)
	kmovb		%k2, (%ecx)
	kmovd		%k4, (%ebx)
	kmovq		%k6, (%eax)

	kmovw		%k2, %k6
	kmovb		%k3, %k7
	kmovd		%k4, %k0
	kmovq		%k5, %k1

	kmovw		(%eax), %k7
	kmovb		(%ebx), %k6
	kmovd		(%ecx), %k5
	kmovq		(%edx), %k4

	kmovw		%k7, 0x400(%esp)
	kmovw		0x400(%esp), %k2
	kmovw		0x123(%eax, %ebx, 8), %k5
	kmovw		%k5, 0x123(%eax, %ebx, 8)

.size libdis_test, [.-libdis_test]
