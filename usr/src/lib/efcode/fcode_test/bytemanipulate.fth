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

." Byte Split tests: "
	" lbsplit"	h# 11223344 lbsplit
			h# 11 = swap  h# 22 = and swap
			h# 33 = and swap h# 44 = and .passed?
	" lwsplit"	h# 11223344 lwsplit
			h# 1122 = swap h# 3344 = and .passed?
	" wbsplit"	h# 31122 wbsplit
			h# 11 = swap h# 22 = and .passed?
	" wljoin"	h# beef h# dead wljoin h# deadbeef = .passed?
	" bljoin"	h# 111 h# 222 h# 333 h# 444 bljoin
			h# 44332211 = .passed?
	" bwjoin"	h# 111 h# 222 bwjoin  h# 2211 = .passed?
	" lbflip"	h# 11223344 lbflip h# 44332211 = .passed?
	" lwflip"	h# 11223344 lwflip h# 33441122 = .passed?
	" wbflip"	h# 31122 wbflip h# 2211 = .passed?
create flip-area
	h# 01020304 l,
	" wbflips"	flip-area /l wbflips flip-area l@ h# 02010403 = .passed?
	" lwflips"	flip-area /l lwflips flip-area l@ h# 04030201 = .passed?
	" lbflips"	flip-area /l lbflips flip-area l@ h# 01020304 = .passed?
cr

." Memory ops: "
	" comp +"	" abcde" drop " abcd" drop 5 comp 1 = .passed?
	" comp -"	" abcd" drop " abcde" comp -1 = .passed?
	" comp ="	" abcdef" drop " abcdef" comp 0= .passed?
	" alloc-mem"	h# 100 dup alloc-mem ?dup
			if 2swap -1 else drop false then .passed?
	" free-mem"	2swap swap free-mem 1 .passed?
cr
