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

." Simple 0 Logic Tests: "
	" 0 invert"	0 invert		.passed?
	" 0 0="		0 0=			.passed?
	" -1 invert"	-1 invert 0=		.passed?
	" 1 0<>"	1 0<>			.passed?
	" 1 0="		1 0= invert		.passed?
	" 1 0<>"	1 0<>			.passed?
	" 0 0>="	0 0>=			.passed?
	" 1 0>="	1 0>=			.passed?
	" -1 0>="	-1 0>= invert		.passed?
	" 1 0>"		1 0>			.passed?
	" 0 0>"		0 0> invert		.passed?
	" -1 0<"	-1 0<			.passed?
	" 0 0<"		0 0< invert		.passed?
	" 0 0<="	0 0<=			.passed?
	" -1 0<="	-1 0<=			.passed?
	" 1 0<="	1 0<= invert		.passed?
cr

." Positive Arithmetic Comparision Tests: "
	" 1 0 >"	1 0 >			.passed? 
	" 1 1 >="	1 1 >=			.passed?
	" 1 1 >"	1 1 > invert		.passed?
	" 0 1 <"	0 1 <			.passed?
	" 0 0 <="	0 0 <=			.passed?
	" 1 0 <"	1 0 < invert		.passed?
	" 0 0 ="	0 0 =			.passed?
	" 0 1 ="	0 1 = invert		.passed?
	" 0 1 <>"	0 1 <>			.passed?
	" 1 1 <>"	1 1 <> invert		.passed?
cr

." Signed Comparison Tests: "
	" -1 1 >"	-1 1 > invert		.passed?
	" -1 -2 >"	-1 -2 >			.passed?
	" -1 0 <"	-1 0 <			.passed?
	" -2 -1 <"	-2 -1 <			.passed?
cr

." Unsigned Comparison Tests: "
	" -1 0 u>"	-1 0 u>			.passed?
	" -1 0 u>="	1 1 u>=			.passed? 
	" 1 -1 <"	2 1 >=			.passed? 
	" 0 1 >="	0 1 >= invert		.passed? 
	" 0 -1 u<"	0 -1 u<			.passed?
	" 0 -1 u<="	0 -1 u<=		.passed?
	" 2 -2 u<="	2 -2 u<=		.passed?
cr

." Arithmetic Tests: "
	" 1 1 +"	1 1 + 2 =		.passed?
	" 1 1 -"	1 1 - 0 =		.passed?
	" 1 negate "	1 negate 1+ 0=		.passed?
	" 0 1 -"	0 1 - -1 =		.passed?
	" -1 abs"	-1 abs 1 =		.passed?
	" -1 2 min"	-1 2 min 1+ 0=		.passed?
	" 2 -1 min"	2 -1 min 1+ 0=		.passed?
	" 3 2 max"	3 2 max 3 =		.passed?
	" 2 3 max"	2 3 max 3 =		.passed?
cr

." Binary Logic: "
	" 3 1 and"	3 1 and 1 =		.passed?
	" 2 1 and"	2 1 and 0=		.passed?
	" 1 1 or"	1 1 or 1 =		.passed?
	" 3 1 xor"	3 1 xor 2 =		.passed?
cr

." Shifting: "
	" (short) lshift"	h# 11 8 lshift  h# 1100 = .passed?
	" (short) rshift"	h# 1122 8 rshift h# 11  = .passed?
	" (long) lshift"	h# 1 d# 31 lshift 1- h# 7fffffff = .passed?
	" (long) rshift"	h# 80 d# 24 lshift d# 31 rshift 1 = .passed?
	" >>a"			-4 1 >>a -2 = .passed?
cr

." Sized Arithmetic Tests: "
	" u2/"		0 0 0 h# 80 bljoin u2/ h# 4000.0000 = .passed?
	" 2/"		-4 2/ -2 = .passed?
	" 2*"		h# 4000.0000 dup 1 lshift swap 2* = .passed?
	" /c"		1 /c = .passed?
	" /w"		2 /w = .passed?
	" /l"		4 /l = .passed?
	" /n"		4 /n = 8 /n = or .passed?
        " ca+"		h# 4000 3 ca+ h# 4003 = .passed?
        " wa+"		h# 4000 3 wa+ h# 4006 = .passed?
        " la+"		h# 4000 3 la+ h# 400c = .passed?
	" na+"		h# 4000 3 na+ h# 4000 3 /n * + = .passed?
	" char+"	h# 4000 char+ h# 4001 = .passed?
	" wa1+"		h# 4000 wa1+ h# 4002 = .passed?
	" la1+"		h# 4000 la1+ h# 4004 = .passed?
	" cell+"	h# 4000 cell+ h# 4000 /n + = .passed?
	" chars"	4 chars 4 = .passed?
	" /w*"		8 /w* h# 10 = .passed?
	" /l*"		4 /l* h# 10 = .passed?
	" cells"	4 cells 4 /n * = .passed?
cr

." Division related Tests: "
	" /mod (+ +)"	 5  2 /mod 2 = swap 1 = and .passed?
	" /mod (- -)"	-5 -2 /mod 2 = swap -1 = and .passed?
	" /mod (+ -)"	 5 -2 /mod -3 = swap -1 = and .passed?
	" /mod (- +)"	-5  2 /mod -3 = swap 1 = and .passed?
	" / (+ +)"	 5  2 / 2 = .passed?
	" / (- -)"	-5 -2 / 2 = .passed?
	" / (+ -)"	 5 -2 / -3 = .passed?
	" / (- +)"	-5  2 / -3 = .passed?
	" mod (+ +)"     5  2 mod 1 = .passed?
	" mod (- -)"    -5 -2 mod -1 = .passed?
	" mod (+ -)"     5 -2 mod -1 = .passed?
	" mod (- +)"    -5  2 mod 1 = .passed?
cr

." Signed Multiply/Divide Tests:"
	" * (+ +)"      2  3    *              6 = .passed?
	" * (- +)"     -3  3    *             -9 = .passed?
	" * (+ -)"      4 -2    *             -8 = .passed?
	" * (- -)"     -4 -3    *             12 = .passed?
cr

." Unsigned Multiply/Divide Tests: "
	" um*"          1 2     um*    0= swap 2 = and  .passed?
	" um/mod"	5 0 2   um/mod 2 = swap 1 = and .passed?
	" u/mod"	5 2     u/mod  2 = swap 1 = and .passed?
cr

." Ranged Tests: "
	" within (!0)"		2  1 3 within .passed?
	" within (0 hi)"	3  1 3 within 0= .passed?
	" within (!0 lo)"	1  1 3 within .passed?
	" within (0 >)"		0  1 3 within 0= .passed?
	" within (0 <)"		4  1 3 within 0= .passed?
	" within (-ve)"		0 -5 5 within .passed?
	" within (- -)"      -7 -10 -5 within .passed?
	" between (!0)"		2  1 3 between .passed?
	" between (!0 lo)"	1  1 3 between .passed?
	" between (!0 hi)"	3  1 3 between .passed?
	" between (0 >)"	4  1 3 between 0= .passed?
	" between (0 <)"	0  1 3 between 0= .passed?
	" between (-ve)"	0 -5 5 between .passed?
	" between (- -)"     -7 -10 -5 between .passed?
	" bounds"		-1 3 bounds -1 = swap 2 = and .passed? 
cr

." Double Arithmetic: "
	" d+"       1 2 3 4 d+ 6 = swap 4 = and .passed?
	" d-"       3 4 2 1 d- 3 = swap 1 = and .passed?
cr
