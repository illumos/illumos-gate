\
\ CDDL HEADER START
\
\ The contents of this file are subject to the terms of the
\ Common Development and Distribution License (the "License").
\ You may not use this file except in compliance with the License.
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
\
\ ident	"%Z%%M%	%I%	%E% SMI"
\ Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
\ Use is subject to license terms.
\

id: %Z%%M%	%I%	%E% SMI
purpose: simplified ramdisk driver
copyright: Copyright 2007 Sun Microsystems, Inc. All Rights Reserved

headerless

" block"          device-type
" SUNW,ramdisk"   encode-string " compatible" property

0 instance value current-offset

0 value ramdisk-base-va
0 value ramdisk-size
0 value alloc-size

: set-props
   ramdisk-size     encode-int  " size"        property
   ramdisk-base-va  encode-int  " address"     property
   alloc-size       encode-int  " alloc-size"  property
;
set-props

: current-va  ( -- adr )  ramdisk-base-va current-offset +  ;

external

: open  ( -- okay? )
   true
;

: close  ( -- )
;

: seek  ( off.low off.high -- error? )
   drop  dup  ramdisk-size  >  if
      drop true  exit         ( failed )
   then
   to current-offset  false   ( succeeded )
;

: read  ( addr len -- actual-len )
   dup  current-offset  +            ( addr len new-off )
   dup  ramdisk-size  >  if
      ramdisk-size -  -              ( addr len' )
      ramdisk-size                   ( addr len new-off )
   then  -rot                        ( new-off addr len )
   tuck  current-va  -rot  move      ( new-off len )
   swap  to current-offset           ( len )
;

: create ( base size alloc-sz -- )
   to alloc-size
   to ramdisk-size
   to ramdisk-base-va
   set-props
;

