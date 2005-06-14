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

fcode-version1
." 64-bit Fcode operation tests" cr
 
 : .failed ." failed!" ;

 : .passed ." OK"  ;

 : .chkstk  depth if ." Stack Changed: " .s cr then ;

 : .passed?  ( str,len flag )
    if if then if then .passed  space else  cr type space .failed cr then 
 ;

\ comparisons only 32-bit...
: xl=  ( xv lh ll -- flag )
   swap rot xlsplit rot = -rot = and
;

: x=  ( xv1 xv2 -- flag )
   xlsplit rot xlsplit rot = -rot = and
;
create test-64
	h# 01020304 l,
	h# 05060708 l,
	h# 81121314 l,
	h# 85161718 l,
        h# ffffffff l,
        h# 80000000 l,

." 64-bit access tests: "
   " /x.1"     /x 8                                               = .passed?
   " xa1+.1"   test-64 xa1+  test-64 /x +                         = .passed?
   " xa+.1"    test-64 2 xa+ test-64 /x 2 * +                     = .passed?
   " x@.1"     test-64 x@ h# 01020304 h# 05060708               xl= .passed?
   " x@.2"     test-64 xa1+ x@ h# 81121314 h# 85161718          xl= .passed?
   " <l@.1"    test-64 2 xa+ dup la1+ <l@ swap x@                x= .passed?
   " bxjoin.1" 8 7 6 5 4 3 2 1 bxjoin test-64 x@                 x= .passed?
   " wxjoin.1" h# 0708 h# 0506 h# 0304 h# 0102 wxjoin test-64 x@ x= .passed?
   " lxjoin.1" h# 05060708 h# 01020304 lxjoin test-64 x@         x= .passed?
   " x!.1"     h# 85161718 h# 81121314 lxjoin test-64 x!
               test-64 x@ h# 81121314 h# 85161718               xl= .passed?
   " x!.2"     h# 05060708 h# 01020304 lxjoin test-64 x!
               test-64 x@ h# 01020304 h# 05060708               xl= .passed?
cr
." 64-bit flips: "
   " xbflip.1" test-64 x@ xbflip h# 08070605 h# 04030201        xl= .passed?
   " xwflip.1" test-64 x@ xwflip h# 07080506 h# 03040102        xl= .passed?
   " xlflip.1" test-64 x@ xlflip h# 05060708 h# 01020304        xl= .passed?
   " xbsplit.1" test-64 x@ xbsplit bxjoin test-64 x@             x= .passed?
   " xwsplit.1" test-64 x@ xwsplit wxjoin test-64 x@             x= .passed?
   " xlsplit.1" test-64 x@ xlsplit lxjoin test-64 x@             x= .passed?
   " xbflips.1" test-64 /x xbflips test-64 x@
                                        h# 08070605 h# 04030201 xl= .passed?
   " xbflips.2" test-64 /x xbflips test-64 x@
                                        h# 01020304 h# 05060708 xl= .passed?
   " xwflips.1" test-64 /x xwflips test-64 x@
                                        h# 07080506 h# 03040102 xl= .passed?
   " xwflips.2" test-64 /x xwflips test-64 x@
                                        h# 01020304 h# 05060708 xl= .passed?
   " xlflips.1" test-64 /x xlflips test-64 x@
					h# 05060708 h# 01020304 xl= .passed?
   " xlflips.2" test-64 /x xlflips test-64 x@
                                        h# 01020304 h# 05060708 xl= .passed?
cr


0 value commatest-64-end
create commatest-64
	h# 01020304 h# 05060708 swap lxjoin x,
	h# 81121314 h# 85161718 swap lxjoin x,
	h# ffffffff h# 80000000 swap lxjoin x,
	here to commatest-64-end

." 64-bit xcomma: "
    " x,.1"    commatest-64 3 xa+ commatest-64-end               = .passed?
    " x,.2"    test-64 x@ commatest-64 x@                       x= .passed?
    " x,.3"    test-64 xa1+ x@ commatest-64 xa1+ x@             x= .passed?
    " x,.4"    test-64 2 xa+ x@ commatest-64 2 xa+ x@           x= .passed?
cr

." 64-bit constant/value/variable: "
1 2 lxjoin constant const-64
1 2 lxjoin value value-64
variable var-64
   " const.1"  const-64                                    2 1 xl= .passed?
   " value.1"  value-64                                    2 1 xl= .passed?
   " value.2"  3 4 lxjoin to value-64 value-64             4 3 xl= .passed?
   " var.1"    const-64 var-64 ! var-64 @                  2 1 xl= .passed?
cr

." 64-bit comparisions: "
   \ FCode comparators are 32-bit only, upper 32-bits are ignored.
   " 64comp.1" 1 2 lxjoin  1 = .passed?
   " 64comp.2" 1 2 lxjoin  2 < .passed?
   " 64comp.3" 2 1 2 lxjoin  > .passed?
   " 64comp.4" 0 2 lxjoin   0= .passed?
   " 64comp.5" 1 2 lxjoin   0> .passed?
cr

end0
