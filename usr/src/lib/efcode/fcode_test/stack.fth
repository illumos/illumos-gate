\ #ident	"%Z%%M%	%I%	%E% SMI"
\ purpose: 
\ copyright: Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
\ copyright: Use is subject to license terms.
\ copyright:
\ copyright: CDDL HEADER START
\ copyright:
\ copyright: The contents of this file are subject to the terms of the
\ copyright: Common Development and Distribution License, Version 1.0 only
\ copyright: (the "License").  You may not use this file except in compliance
\ copyright: with the License.
\ copyright:
\ copyright: You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
\ copyright: or http://www.opensolaris.org/os/licensing.
\ copyright: See the License for the specific language governing permissions
\ copyright: and limitations under the License.
\ copyright:
\ copyright: When distributing Covered Code, include this CDDL HEADER in each
\ copyright: file and include the License file at usr/src/OPENSOLARIS.LICENSE.
\ copyright: If applicable, add the following below this CDDL HEADER, with the
\ copyright: fields enclosed by brackets "[]" replaced with your own identifying
\ copyright: information: Portions Copyright [yyyy] [name of copyright owner]
\ copyright:
\ copyright: CDDL HEADER END
\ copyright:

." Stack Manipulation: "
	" drop"		1 0 drop		.passed?
	" swap"		1 2 1 swap drop =	.passed?
	" nip"		1 0 1 nip - 0=		.passed?
	" over"		1 2 over 1 = nip nip	.passed?
	" dup"		1 dup =			.passed?
	" tuck"		2 1 tuck nip =		.passed?
	" rot"		3 2 1 rot 3 = nip nip	.passed?
	" -rot"		3 2 1 -rot 2 = nip nip	.passed?
	" 2rot"		1 2 3 4 5 6 2rot 2 = swap 1 = and swap 6 = and swap
			   5 = and swap 4 = and swap 3 = and .passed?
	" 2dup"		1 -1 2dup + 0= nip nip	.passed?
	" ?dup"		0 1 ?dup = nip 		.passed?
	" 2swap"	1 1 0 0 2swap and nip nip .passed?
	" 2drop"	1 1 0 0 2drop and	.passed?
	" 2over"	1 2 0 0 2over 2swap 2drop rot = -rot = = .passed?
	" roll"		1 2 3 4 3 roll 1 = nip nip nip .passed?
	" depth"	0 0 depth 4 = nip nip .passed?
cr

." Return Stack: "
: test-rs
	" >r"		3 1 >r 2 >r 3 =		.passed?
	" r@"		3 r@ 2 = nip		.passed?
	" r>"		3 r> 2 = r> 1 = and nip	.passed?
;  test-rs
: bail-test ( -- )	r> drop  ;
: bail ( -- )		1 bail-test drop 0 ;
	" Manipulate"	bail			.passed?
cr
