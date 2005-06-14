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

cr ." Simple interpreted IF THEN test: "
1 if .passed then space 
0 if .failed then space
cr

." Simple interpreted IF ELSE THEN test: "
0 if .failed else .passed then space
1 if .passed else .failed then space
cr

." Nested interpreted IF test: "
1 1 1 0 0 1 0 0
if	if .failed	else .failed	then space
else	if .failed	else .passed	then space
then
if	if .failed	else .passed	then space
else	if .failed	else .failed	then space
then
if	if .failed	else .failed	then space
else	if .passed	else .failed	then space
then
if	if .passed	else .failed	then space
else	if .failed	else .failed	then space
then
cr

." Compiled single IF tests:" space
: if-true?	if .passed space 0 exit	then .failed space 0 ;	1 if-true?
: if-false?	if .failed space 1 exit	then .passed space 1 ;	if-false?
: true?		if .passed else .failed then space 0 ;		true?
: false?	if .failed else .passed then space ;		false?

cr

." Nested compiled IF test: "
: if-test1 ( -- )
   0 1 0 if
      .failed
   else
      if
         dup if .failed then
         if .failed else .passed then
      else
         .failed
      then
   then
; if-test1 space

: .passed?  ( str,len flag )
   if if then if then .passed  space else  cr type space .failed cr then 
;

: if-test2 ( x x x -- )
   if
      if
         if
            7
         else
            6
         then
      else
         if
            5
         else
            4
         then
      then
   else
      if
         if
            3
         else
            2
         then
      else
         if
            1
         else
            0
         then
      then
   then
;

 " if-test2.0"   0 0 0 if-test2 0 = .passed?
 " if-test2.1"   1 0 0 if-test2 1 = .passed?
 " if-test2.2"   0 1 0 if-test2 2 = .passed?
 " if-test2.3"   1 1 0 if-test2 3 = .passed?
 " if-test2.4"   0 0 1 if-test2 4 = .passed?
 " if-test2.5"   1 0 1 if-test2 5 = .passed?
 " if-test2.6"   0 1 1 if-test2 6 = .passed?
 " if-test2.7"   1 1 1 if-test2 7 = .passed?
cr
