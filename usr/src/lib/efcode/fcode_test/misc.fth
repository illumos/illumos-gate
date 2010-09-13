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

." Buffer: "
 h# 20 buffer: my-unit-str
 " abcd" my-unit-str pack drop
 " pack.1" my-unit-str     c@ 4       = .passed?
 " pack.2" my-unit-str 1 + c@ ascii a = .passed?
 " pack.3" my-unit-str 2 + c@ ascii b = .passed?
 " pack.4" my-unit-str 3 + c@ ascii c = .passed?
 " pack.5" my-unit-str 4 + c@ ascii d = .passed?
 " count.1" my-unit-str count " abcd" $= .passed?
cr

." Formatting: "
 " fmt.1" 1 h# 23 <# #s #>        " 2300000001" $= .passed?
 " fmt.2" 1 h# 23 <# # # #>               " 01" $= .passed?
 " fmt.3" h# 123  <# u#s u#>             " 123" $= .passed?
 " fmt.4" h# 123  <# u# ascii X hold u# u#> " 2X3" $= .passed?
 d# 10 base !
 " fmt.5" d# -123 <# dup abs u#s swap sign u#> " -123" $= .passed?
 " fmt.6" d# 123  <# dup abs u#s swap sign u#>  " 123" $= .passed?
 " fmt.7" " -123" $number invert swap d# -123 = and .passed?
 d# 16 base !
 " fmt.8" " 32a" $number invert swap h# 32a = and .passed?
 " fmt.9" " xyzzy" $number                        .passed?
 : dnumber   ( n -- str len )
    base @ >r d# 10 base !
    <# dup abs u#s swap sign u#>
    r> base !
 ;
 " fmt.10" d# 12345678 dnumber " 12345678"     $= .passed?
 " fmt.11" d# -87654321 dnumber " -87654321"   $= .passed?
 " fmt.12" #out @ space #out @ 1 - = .passed?
 " fmt.13" #line @ cr #out @ #line @ rot 1 + = swap 0= and .passed?
 " fmt.14" #line @ (cr #out @ #line @ rot = swap 0= and .passed?
 " fmt.15" bs h# 8                              = .passed?
 " fmt.16" bell h# 7                            = .passed?
 " fmt.17" bl h# 20                             = .passed?
 " fmt.18" ascii 5 d# 10 digit swap 5 = and       .passed?
 " fmt.19" ascii x d# 16 digit invert swap ascii x = and .passed?
cr

." (is-user-word): "
 : xyzzy 1 2 3 ;
 " xx" ' xyzzy (is-user-word)
 " xx" $find if .passed space execute else .failed then
 " iuw.1"  2 pick 3               = .passed?
 " iuw.2"  3 pick 2               = .passed?
 " iuw.3"  4 pick 1               = .passed?
 drop drop drop
cr

." Move/Fill/Upper/Lower:"
 " xyzzy" my-unit-str swap move
 " move.1" my-unit-str " xyzzy" comp          0= .passed?
 my-unit-str 9 ascii A fill
 my-unit-str 6 ascii X fill
 " fill.1" my-unit-str " XXXXXXAAA" comp      0= .passed?
 9 0 do my-unit-str i + dup c@ lcc swap c! loop
 " lcc.1"  my-unit-str " xxxxxxaaa" comp      0= .passed?
 9 0 do my-unit-str i + dup c@ upc swap c! loop
 " upc.1"  my-unit-str " XXXXXXAAA" comp      0= .passed?
cr

." >body/body>: "
external
 : xx 1 2 3 ;
headers
 " >body" ' xx >body ' xx /n + = .passed?
 " body>" ' xx dup >body body> = .passed?
cr

." Fcode-revision: "
 " Fcode-revision" fcode-revision h# 30000 = .passed?
cr

." Defer/Behavior: "
 defer defer-word
 ' xx to defer-word
 " defer.1" defer-word 3 = swap 2 = and swap 1 = and .passed?
 " behavior.1" ' defer-word behavior ' xx = .passed?
cr

." Aligned: "
 variable alvar
 " align.1" alvar aligned alvar = .passed?
 " align.2" alvar /c - aligned alvar = .passed?
 " align.3" alvar char+ aligned alvar la1+ = .passed?
cr

." Field: "
struct
 /n field >x1 
 /l field >x2
 /w field >x3
 /c field >x4
constant /field-test
 " field.1" /field-test /n /l /w /c + + + = .passed?
 " field.2" 0 >x1 0 = .passed?
 " field.3" 0 >x2 /n = .passed?
 " field.4" 0 >x3 /n /l + = .passed?
 " field.5" 0 >x4 /n /l /w + + = .passed?
cr


." Properties: "
 0 value root-phandle
 " use-fake-handles" $find if execute else 2drop then
 " /" " (cd)" $find if execute else 2drop then
 " /" find-package if to root-phandle then
 1 encode-int " int-prop" property
 1 2 encode-phys " phys-prop" property
 1 2 3 reg
 " XYZZY" model
 1 encode-int 2 encode-int encode+ " 2int-prop" property
 " abcd" encode-string " string-prop" property
 " wxyz" encode-bytes " bytes-prop" property
 " prop.1" " bytes-prop" root-phandle get-package-property if
    .failed
 else
    " wxyz" $= .passed?
 then
 " prop.2" " string-prop" root-phandle get-package-property if
    .failed
 else
   decode-string " abcd" $= nip nip .passed?
 then
 " prop.3" " int-prop" root-phandle get-package-property if
    .failed
 else
   decode-int 1 = nip nip .passed?
 then
 " prop.4" " phys-prop" root-phandle get-package-property if
    .failed
 else
   decode-phys 2 = swap 1 = and nip nip .passed?
 then
 " prop.5" 0 0 root-phandle next-property if
    " bytes-prop" $= .passed?
 else
    .failed
 then
 " prop.6" " string-prop" root-phandle next-property if
    " 2int-prop" $= .passed?
 else
    .failed
 then
cr
 " .properties" $find if execute else 2drop then
cr

." Timing/Alarm: "
 " ms.1" get-msecs h# 100 ms get-msecs swap - h# 80 h# 150 between .passed?
\ 0 value alarm-happened
\ : alarm-word 1 to alarm-happened ." OK " ;
\ ' alarm-word 10 alarm
\ 0
\ begin
\    1 + dup 1000000 > alarm-happened 0<> or
\ until
\ drop
\ 0 0 alarm
\ " alarm.1" alarm-happened .passed?
cr
