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

." Case: "
: case1  ( n -- str )
   case
      0 of " zero" >r >r  endof
      1 of " one"  >r >r endof
      2 of " two"  >r >r endof
      dup <# u#s u#> >r >r
   endcase
   r> r>
;
  " case.1" 0 case1 drop " zero" comp invert       .passed?
  " case.2" 1 case1 drop " one"  comp invert       .passed?
  " case.3" 2 case1 drop " two"  comp invert       .passed?
  " case.4" 3 case1 drop " 3"    comp invert       .passed?
  " case.5" 4 case1 drop " 4"    comp invert       .passed?
cr
