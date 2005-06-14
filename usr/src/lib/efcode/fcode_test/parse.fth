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

 ." parse:"
 : $=  ( str1 len1 str2 len2 -- true/false )
   2 pick <> if
      3drop false
   else
      swap dup 0= if
         3drop true
      else
         true swap 0 do
            2 pick i + c@
            2 pick i + c@
            = and
         loop nip nip
      then
   then
 ;
 : parse-test
   " $= test.1" " abcd" " abcd" $= .passed?
   " $= test.2" " abdc" " abcd" $= invert .passed?
   " $= test.3" " abc"  " abcd" $= invert .passed?
   " 9600,8,n,1,-"
   ascii , left-parse-string " 9600" $= " left-parse.1" rot .passed?
   ascii , left-parse-string " 8"    $= " left-parse.2" rot .passed?
   ascii , left-parse-string " n"    $= " left-parse.3" rot .passed?
   ascii , left-parse-string " 1"    $= " left-parse.4" rot .passed?
   ascii , left-parse-string " -"    $= " left-parse.5" rot .passed?
   2drop
 ;
 parse-test
 cr
