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
purpose: utility words
copyright: Copyright 2007 Sun Microsystems, Inc. All Rights Reserved


[ifdef] doheaders
headers
[else]
headerless
[then]

d# 256  constant  /buf-len

\
\	useful counting words
\
: roundup ( x y -- x' )  1- tuck +  swap invert and  ;


\
\	various useful string manipulation words
\

: cstrlen ( cstr -- len )
   dup begin
      dup c@
   while
      char+
   repeat swap -
;

: cscount ( cstr -- adr,len )  dup cstrlen  ;

\ Append str1 to the end of str2
: $append ( adr,len1 adr,len2 -- )
   2over 2over  ca+ swap move   ( adr,len1 adr,len2 )
   rot + ca+ 0 swap c!  drop    (  )
;

: $=  ( str1$ str2$ -- same? )
   rot tuck <>  if
      3drop false exit
   then  comp 0=
;

\ advance str by 1
: str++  ( adr len --  adr' len' )
   swap 1+  swap 1-
;

: diag-cr?  ( -- )  diagnostic-mode?  if  cr  then  ;


: find-abort ( name$ -- )
   ." Can't find " type abort
;

: get-package ( pkg$ -- ph )
   2dup  find-package 0=  if
      find-abort
   then                       ( pkg$ ph )
   nip nip                    ( ph )
;


\
\	CIF words for I/O and memory
\
" /openprom/client-services" get-package  constant cif-ph

instance defer cif-open     ( dev$ -- ihandle|0 )
instance defer cif-close    ( ihandle -- )
instance defer cif-read     ( len adr ihandle -- #read )
instance defer cif-seek     ( low high ihandle -- -1|0|1 )
instance defer cif-release  ( size virt -- )

: find-cif-method ( adr,len -- acf )
   2dup  cif-ph find-method 0=  if    ( adr,len )
      find-abort
   then                               ( adr,len acf )
   nip nip                            ( acf )
;

" open"     find-cif-method to cif-open
" close"    find-cif-method to cif-close
" read"     find-cif-method to cif-read
" seek"     find-cif-method to cif-seek
" release"  find-cif-method to cif-release


" /chosen" get-package  constant chosen-ph

: get-property  ( name$ ph -- prop$ )
   >r 2dup  r>  get-package-property  if   ( name$ )
      find-abort
   then                                    ( name$ prop$ )
   2swap  2drop                            ( prop$ )
;

: get-string-prop  ( name$ ph -- val$ )
   get-property decode-string            ( prop$' val$ )
   2swap 2drop                           ( val$ )
;

: get-int-prop  ( name$ ph -- n )
   get-property decode-int               ( prop$' n ) 
   nip nip                               ( n )
;

\
\	memory allocation
\	we bypass cif claim so we can do large page
\	allocations like promif can
\

" mmu"    chosen-ph  get-int-prop  constant mmu-ih

" memory" chosen-ph  get-int-prop  constant mem-ih

: mmu-claim  ( [ virt ] size align -- base )
   " claim" mmu-ih $call-method
;

: mmu-map  ( phys.lo phys.hi virt size -- )
   -1  " map" mmu-ih $call-method
;

: mem-claim  ( size align -- phys.lo phys.hi )
   " claim" mem-ih $call-method
;

: (mem-alloc)   ( size virt align -- virt )
   \ claim memory first since it may throw if fragmented
   rot  2dup swap  mem-claim           ( virt align size phys.lo phys.hi )
   >r >r  rot ?dup  if                 ( align size virt  r: phys.lo phys.hi )
      \ we picked virt - zero alignment
      over 0  mmu-claim                ( align size virt  r: phys.lo phys.hi )
   else                                ( align size  r: phys.lo phys.hi )
      \ OBP picks virt - pass alignment
      2dup swap  mmu-claim             ( align size virt  r: phys.lo phys.hi )
   then                                ( align size virt  r: phys.lo phys.hi )
   r> r>  2over swap  mmu-map          ( align size virt )
   nip nip                             ( virt )
;

: vmem-alloc ( size virt -- virt )
   swap  h# 2000 roundup  swap
   1 (mem-alloc)
;

: mem-alloc ( size -- virt )
   h# 2000  roundup
   0 1 (mem-alloc)
;

: mem-free  ( virt size -- ) 
   h# 2000  roundup
   swap  cif-release    (  )
;



\ put ramdisk fcode 256 bytes from end of bootblk
\ (currently 244 bytes in size)
d# 256               constant /rd-fcode
d# 8192 /rd-fcode -  constant rd-offset

: open-abort  ( file$ -- )
   ." Can't open "  type  abort
;

/buf-len  buffer: open-cstr

: dev-open ( dev$ -- ih | 0 )
   \ copy to C string for open
   0  over open-cstr +  c!
   open-cstr swap  move
   open-cstr  cif-open
;

: dev-close ( ih -- )
   cif-close
;

: read-disk    ( adr len off ih -- )
   dup >r  0 swap  cif-seek  if     ( adr len  r: ih )
      ." seek failed"  abort
   then

   tuck  swap r>  cif-read  <>  if  (  )
      ." read failed"  abort
   then
;
