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
\ Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
\ Use is subject to license terms.
\


purpose: CPIO file system support package
copyright: Copyright 2021 Toomas Soome <tsoome@me.com>

\ This implementation is based on UFS bootblk code.

headers
" /packages" get-package  push-package

new-device
   fs-pkg$  device-name  diag-cr?

   \
   \	CPIO low-level block routines
   \

   h# 2000  constant  /max-bsize
   d# 512   constant  /disk-block


   0 instance value dev-ih

   h# 2000  constant  /cpio-start

   \
   \	cpio header
   \

   d# 256 constant /max-namelen
   d# 76 constant /cpio-header
   0 instance value cpio-header
   0 instance value /temp-block
   0 instance value temp-block

   \
   \ convert ascii octal number stream to integer
   \
   : get-uint ( addr len -- v )
      0				( addr len v )
      begin over 0> while
         8 *			( addr len v*8 )
         rot			( len v addr )
         dup c@ ascii 0 -	( len v addr n )
         rot +			( len addr n+v )
         swap 1+		( len v addr+1 )
         rot 1-			( v addr len-1 )
         rot			( addr len v )
       repeat
       >R 2drop R>
   ;

   : magic?     ( -- flag ) cpio-header
      dup c@ ascii 0 = swap 1 +
      dup c@ ascii 7 = swap 1 +
      dup c@ ascii 0 = swap 1 +
      dup c@ ascii 7 = swap 1 +
      dup c@ ascii 0 = swap 1 +
      c@ ascii 7 =
      and and and and and
   ;
   : dev       ( -- addr len ) cpio-header 6 + 6 get-uint ;
   : ino       ( -- addr len ) cpio-header d# 12 + 6 get-uint ;
   : mode      ( -- addr len ) cpio-header d# 18 + 6 get-uint ;
   : uid       ( -- addr len ) cpio-header d# 24 + 6 get-uint ;
   : gid       ( -- addr len ) cpio-header d# 30 + 6 get-uint ;
   : nlink     ( -- addr len ) cpio-header d# 36 + 6 get-uint ;
   : rdev      ( -- addr len ) cpio-header d# 42 + 6 get-uint ;
   : mtime     ( -- addr len ) cpio-header d# 48 + d# 11 get-uint ;
   : namesize  ( -- addr len ) cpio-header d# 59 + 6 get-uint ;
   : filesize  ( -- addr len ) cpio-header d# 65 + d# 11 get-uint ;
   : filename  ( -- addr ) cpio-header d# 76 + ;
   : data      ( -- addr ) cpio-header d# 76 + namesize + ;

   : get-cpio-header ( offset -- )
      cpio-header /disk-block 2 * rot	( adr len offset )
      dev-ih read-disk
   ;

   : ftype	( -- n ) mode h# f000 and ;
   : dir?	( -- flag ) ftype h# 4000 = ;
   : symlink?	( -- flag ) ftype h# a000 = ;
   : regular?	( -- flag ) ftype h# 8000 = ;
   : comp?	( -- flag ) data dup c@ h# 1f = swap c@ h# 8b = and ;

   \
   \	CPIO routines
   \

   0 instance value current-file

   h# 200 constant /fpath-buf
   /fpath-buf instance buffer: fpath-buf
   : clr-fpath-buf ( -- ) fpath-buf /fpath-buf erase ;
   : fpath-buf$ ( -- path$ ) fpath-buf cscount ;

   : cut-tail ( path$ -- path$' )
     2dup + 1-			( addr len addr+len-- )
     begin
       dup c@ ascii / <>
     while
       1-			( addr len addr'-- )
       swap 1- swap		( addr len-- addr' )
     repeat
     drop			( addr len )
   ;

   : cut-head ( addr n -- )
      dup /temp-block swap - to /temp-block
      + to temp-block
   ;

   : follow-symlink ( path$ -- path$' )
      clr-fpath-buf

      \ is it absolute link?
      temp-block c@ ascii / = if
         2drop
         temp-block /temp-block exit
      then

      \ if it does start with "./", remove it from link
      temp-block c@ ascii . = temp-block 1+ c@ ascii / = and if
         temp-block 2 cut-head
      then

      \ if it does not start with '.', remove last component from path$
      temp-block c@ ascii . <> if
         cut-tail
      then

      \ if it does start with "../", remove last component from path$
      \ and remove "../" from the head of link
      begin
         temp-block 3 s" ../" $=
      while
         cut-tail
         temp-block 3 cut-head
      repeat

      over c@ ascii / <> if
         s" /" fpath-buf$ $append
      then
      fpath-buf$ $append
      temp-block /temp-block fpath-buf$ $append
      fpath-buf$
   ;

   : lookup  ( path$ -- true | offset false ) tokenizer[ reveal ]tokenizer
      \ all paths should start with '/', but cpio archive does omit
      \ leading '/', skip it.
      over c@ ascii / = if
         str++
      else
         2drop true exit
      then

      /cpio-start
      begin
          dup get-cpio-header		( path$ offset )
      magic? while
             -rot			( offset path$ )

             \ check EOF of cpio archive
             filename namesize 1- s" TRAILER!!!"
             $= if
                3drop true exit
             then

             2dup
             filename namesize 1-
             $= if
                symlink? if			( offset path$ )
                   rot drop			( path$ )
                   data to temp-block
                   filesize to /temp-block
                   follow-symlink
                   lookup exit
                then
                2drop /cpio-header + namesize +
                false exit		( offset false )
             then
             rot			( path$ offset )
             /cpio-header + namesize + filesize +
      repeat

      3drop  true                          ( failed )
   ;

   \
   \	CPIO installation routines
   \

   /disk-block 2 *
   constant alloc-size

   \ **** Allocate memory for necessary data structures
   : allocate-buffers  ( -- )
      alloc-size mem-alloc  dup 0=  if
         ." no memory"  abort
      then						( adr )
      to cpio-header					( adr )
   ;

   : release-buffers  ( -- )
      cpio-header alloc-size mem-free
   ;

   \ CPIO file interface
   \ I am not really sure we do need open file list. Testing
   \ does seem to indicate, we do have one file open at a time.
   \ However, I keep it for time being.

   struct
      /x     field >busy
      /x     field >offset
      /x     field >addr
      /x     field >size
   constant /file-record

   d# 10                  constant #opens
   #opens /file-record *  constant /file-records

   /file-records  instance buffer: file-records

   -1 instance value current-fd
   : fd>record  ( fd -- record )  /file-record *  file-records +  ;

   : file-size@  ( -- size )
      current-fd fd>record >size x@
   ;

   : file-addr@  ( -- addr )
      current-fd fd>record >addr x@
   ;

   : file-offset@  ( -- off )
      current-fd fd>record >offset  x@
   ;

   : file-offset!  ( off -- )
      current-fd fd>record >offset  x!
   ;

   : get-slot  ( -- fd false | true )
      #opens 0  do
         i fd>record >busy x@  0=  if
            i false  unloop exit
         then
      loop  true
   ;

   : free-slot  ( fd -- )
      0 swap  fd>record >busy  x!
   ;

   : init-fd  ( offset fd -- )
      fd>record			( offset rec )
      swap over			( rec offset rec )
      >addr x!			( rec )
      dup >busy 1 swap x!
      dup >size filesize swap x!
      >offset 0 swap x!
   ;

   : set-fd  ( fd -- error? )
      dup fd>record >busy x@ 0= if	( fd )
         drop true exit			( failed )
      then
      to current-fd false		( succeeded )
   ;


   \ advance file io stack by n
   : fio+  ( # adr len n -- #+n adr+n len-n )
      dup file-offset@ +  file-offset!
      dup >r  -  -rot   ( len' # adr  r: n )
      r@  +  -rot       ( adr' len' #  r: n )
      r>  +  -rot       ( #' adr' len' )
   ;

   external

   : open ( -- okay? )
      my-args dev-open  dup 0=  if       ( 0 )
         exit                            ( failed )
      then  to dev-ih

      allocate-buffers
      file-records /file-records  erase
      true                               ( succeeded )
   ;

   : close  ( -- )
      dev-ih dev-close
      0 to dev-ih
      release-buffers
   ;

   : open-file  ( path$ -- fd true | false )
      get-slot  if
         2drop false exit		( failed )
      then -rot				( fd path$ )

      lookup if				( fd offset )
         drop false exit		( failed )
      then

      over				( fd offset fd )
      init-fd true			( fd succeeded )
   ;

   : close-file  ( fd -- )
      free-slot   (  )
   ;

   : size-file  ( fd -- size )
      set-fd if 0 else file-size@ then
   ;

   : seek-file  ( off fd -- off true | false )
      set-fd  if                ( off )
         drop false  exit       ( failed )
      then                      ( off )

      dup file-size@ >  if       ( off )
         drop false  exit       ( failed )
      then                      ( off )
      dup  file-offset!  true   ( off succeeded )
   ;

   : read-file  ( adr len fd -- #read )
      set-fd if			( adr len )
         2drop 0 exit		( 0 )
      then			( adr len )

      \ adjust len if reading past eof
      dup file-offset@ + file-size@ > if
         dup file-offset@ + file-size@ -  -
      then
      dup 0= if 2drop 0 exit then

      dup -rot			( #read adr len )
      file-addr@ file-offset@ + dev-ih read-disk
      dup file-offset@ + file-offset!
   ;

   : cinfo-file  ( fd -- bsize fsize comp? )
      set-fd if 0 0 0 else /max-bsize file-size@ comp?  then
   ;

   \ read ramdisk fcode at rd-offset
   : get-rd   ( adr len -- )
      rd-offset dev-ih  read-disk
   ;

   \ no additional props needed for cpio
   : bootprop  ( -- )  false  ;

finish-device
pop-package
