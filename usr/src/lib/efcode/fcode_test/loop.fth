\ #ident	"%Z%%M%	%I%	%E% SMI"
\ Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
\ Use is subject to license terms.
\
\ CDDL HEADER START
\
\ The contents of this file are subject to the terms of the
\ Common Development and Distribution License, Version 1.0 only
\ (the "License").  You may not use this file except in compliance
\ with the License.
\
\ You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
\ or http://www.opensolaris.org/os/licensing.
\ See the License for the specific language governing permissions
\ and limitations under the License.
\
\ When distributing Covered Code, include this CDDL HEADER in each
\ file and include the License file at usr/src/OPENSOLARIS.LICENSE.
\ If applicable, add the following below this CDDL HEADER, with the
\ fields enclosed by brackets "[]" replaced with your own identifying
\ information: Portions Copyright [yyyy] [name of copyright owner]
\
\ CDDL HEADER END
\

." Interactive begin .. while .. repeat: "
	" no loop (1) "		1 begin 0 while 1- repeat .passed?
	" loop to 0 (1)"	9 begin dup while 1- repeat  0= .passed? 
cr
." Compiled begin .. while .. repeat: "
	: btest1		1 begin 0 while 1- repeat .passed? ;
	: btest2		9 begin dup while 1- repeat 0= .passed? ;
	" no loop (2) "		btest1
	" loop to 0 (2)"	btest2
cr
." Interactive begin..until: "
	" no loop (3)"		1 begin  dup until .passed?
	" loop to 0 (3)"	9 begin  1- dup 0= until 0= .passed?
cr
." Compiled begin..until: "
	: btest3		1 begin  dup until .passed? ;
	: btest4		9 begin  1- dup 0= until 0= .passed? ;
	" no loop (4)"		btest3
	" loop to 0 (4)"	btest4
cr
." Interactive do .. loop: "
	" loop (1)"	0 h# 10 0 do drop i loop h# f = .passed?
	" no loop (1)"	1 0 0 ?do 1- loop .passed?
	" leave (1)"	h# 10 0 do i 5 = if 1 leave drop 0 then loop .passed?
cr
." Compiled do .. loop: "
	: loop1			do drop i loop h# f = .passed? ;
	: loop2			?do 1- loop .passed? ;
	: loop3			do i 3 = if drop i leave 0 then loop ;
	: loop7			do i 4 = if drop i unloop exit then loop ;
	" loop (2)"		0 h# 10 0 loop1
	" no loop (2)"		1 0 0 loop2
	" leave (2)"		3 4 0 loop3 3 = .passed?
	" unloop"		5 6 0 loop7 4 = .passed?
cr
." Interactive do .. +loop: "
	" loop by 2"		0 h# 10 0 do drop i 2 +loop h# e = .passed?
	" loop down by 2"	0 -2 h# 10 do drop i -2 +loop h# -2 = .passed?
cr
." Compiled do .. +loop: "
	: loop4			0 h# 10  0 do drop i 2 +loop h# e = .passed? ;
	: loop5			0 -2 h# 10 do drop i -2 +loop -2 = .passed? ;
	" loop (4)"		loop4
	" loop (5)"		loop5
cr
." Nested loops: "
	: loop6		0 h# 4 0 do 8 0 do 1 j 3 lshift i + lshift xor loop loop ;
	" i,j sum"		loop6 lwsplit over = swap h# ffff = and .passed?
cr
." Negative Limit Loops: "
	" loop.7"       h# 10 -37 8 bounds do drop i loop -30 = .passed?
	" loop.8"       h# 10 -37 -30 do drop i -1 +loop  -37 = .passed?
cr
." Compiled begin...again: "
	: loop9 begin true exit again false ; loop9 " loop9" rot .passed?
	0 value in-count
	0 value out-count
	: loop10
	   begin
	      out-count 1+ to out-count
 	      begin
	         in-count 10 >= if
	            exit
	         then in-count 1+ to in-count
	      again
	      -1 to in-count
	      exit
	   again
	   -2 to in-count
	;
	" loop.10" loop10 in-count 10 = out-count 1 = and  .passed?
cr
