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
\ Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
\ Use is subject to license terms.
\
\ ident	"%Z%%M%	%I%	%E% SMI"
\
\ Unix 4.2 file system reader
\

\ When debugging, the sign on banner is on the stack
\ #ifdef DEBUG_BOOTBLK
\ type
\ #endif /* DEBUG_BOOTBLK */

decimal
headerless

\
\	Forth utility routines
\
\ : $find  2dup type cr $find ;

: boot-eval  ( adr len -- )  
   $find if
      execute
   else
      type  ."  ?" cr exit
   then
;

\ " romvec" boot-eval constant romvec
variable boot-romvec

: find-romvec
   " romvec" $find  if 
     execute 
  else 
    2drop h# ffe8.0010
  then
  boot-romvec !
;

find-romvec

: roment  ( offset -- adr )  boot-romvec @ + l@  ;

" load-base"     $find drop constant 'loadbase
\ " (is"           $find drop constant '(is
\ " $="            $find drop constant '$=
" call"          $find drop constant 'call

: loadbase ( -- adr ) 'loadbase execute  ;
\ : (is ( val acf -- ) '(is execute  ;
\ : $=  ( str1 str2 -- [ -1 | 0 | 1 ] ) '$= execute  ;
: call ( ... addr -- ??? ) 'call execute ;
: loadbase! ( value -- ) 'loadbase " (is" boot-eval ;
 
: devr_next  ( nodeid  -- next-nodeid ) h# 1c roment l@ call nip  ;
: devr_getprop  ( adr namecstr nodeid  -- len|-1 )  h# 1c roment 3 la+ l@ call nip nip nip ;

: boot-/string  ( adr len size -- adr+size len-size )  tuck - >r + r>  ;

\ Splits a string around a delimiter.  If the delimiter is found,
\ two strings are returned under true, otherwise one string under false.
: boot-$split ( adr len char -- remaining-adr len [ initial-adr len ] found? )
   2 pick  2 pick  bounds  ?do
      dup i c@  =  if  i nip -1  then 
   loop                                    ( adr len   adr' -1  |  char )
   -1 =  if   ( adr len  adr' )
      swap >r            ( adr adr' )  ( r: len )
      2dup swap - swap   ( adr [adr'-adr] adr' )  ( r: len )
      1+  r>             ( adr [adr'-adr] adr'+1 len )
      2 pick - 1-        ( adr [adr'-adr]  adr'+1  len-[adr'-adr-1] )
      2swap true         ( rem-adr,len initial-adr,len true )
   else
      false
   then
;

\
\	Device and driver section
\

512 constant ublock

variable devid
variable nextblock	\ holds seek target for V1 read-blocks

: devname  ( -- cstr )
      h# 88 roment @			\ bootpath
;

\ Debug V2 or later PROMs
\ : devname " disk" drop ;


\ Debug V0 PROMS
\ : devname " sd(0,0,0)" drop ;

: open-disk  ( -- error? )
   devname
   " op-open"
   boot-eval dup if
      dup devid !
   then
   0=			( invert sense of error flag )
;

: close-disk  ( -- )
   devid @  " op-close" boot-eval drop
;

: read-blks  ( adr len -- error? )
   ( len adr devid -- #bytes_read )
   tuck swap devid @ " op-read" boot-eval <>
;

: seek  ( low high -- error? )
   ( low high devid -- ? )
   devid @ " op-seek" boot-eval  0<
;

\
\	UFS low-level block routines
\

512 constant /super-block
8 constant ndaddr
16 constant super-block#  ( -- n )

0 constant temp-block
0 constant indirect-block
0 constant inode
0 constant super-block

: quad@  ( adr -- l )
\ For little-endian machines
\  l@
\ For big-endian machines
   la1+ l@
;

: +sb  ( index -- value )  super-block  swap la+ l@  ;
: iblkno    ( -- n )   4 +sb  ;
: cgoffset  ( -- n )   6 +sb  ;
: cgmask    ( -- n )   7 +sb  ;
: bsize     ( -- n )  12 +sb  ;
: fragshift ( -- n )  24 +sb  ;
: fsbtodbc  ( -- n )  25 +sb  ;
: inopb     ( -- n )  30 +sb  ;
: ipg       ( -- n )  46 +sb  ;
: fpg       ( -- n )  47 +sb  ;

: read-ublocks  ( adr len dev-block# -- error? )
   ublock * 0  seek ?dup if exit then
   ( adr len )  read-blks
;

: get-super-block  ( -- error? )
   super-block /super-block super-block# read-ublocks
;

: cgstart   ( cg -- block# )
   dup cgmask not and  cgoffset *   swap fpg *  +
;
: cgimin    ( cg -- block# )  cgstart  iblkno +  ;

: blkstofrags  ( #blocks -- #frags )  fragshift <<  ;

: fsbtodb  ( fs-blk# -- dev-blk# )  fsbtodbc <<  ;

: read-fs-blocks  ( adr len fs-blk# -- error? )  fsbtodb read-ublocks ;
   
\
\	UFS inode routines
\

h# 80 constant /inode

variable blkptr
variable blklim
variable indirptr

: itoo  ( n -- offset )  inopb mod  ;
: itog  ( n -- group )  ipg /  ;
: itod  ( n -- block# )
   dup itog cgimin  swap ipg mod  inopb /  blkstofrags  +
;

: +i  ( n -- )  inode +  ;
: dir?  ( -- flag )  0 +i  w@  h# 4000 and  0<>  ;  \ ****
: filesize   ( -- n )     8 +i quad@  ;   \ ****
: direct0    ( -- adr )  40 +i  ;
: indirect0  ( -- adr )  88 +i  ;

\ **** Select the indicated file for subsequent accesses
: select-file  ( file-handle -- error? )
   dup temp-block bsize  rot  itod
   read-fs-blocks ?dup if exit then
   itoo /inode * temp-block +   inode /inode move
   direct0 blkptr !   indirect0 blklim !  indirect0 indirptr !
   false
;

: l@++  ( ptr -- value )  dup @ l@  /l rot +!  ;

\ **** Locate the next block within the current file
: next-block#  ( -- n )
   blkptr @  blklim @ =  if
      indirect-block bsize indirptr l@++ 
      read-fs-blocks drop ( XXX - what about the error? )
      indirect-block  blkptr !   indirect-block bsize +  blklim !
   then
   blkptr l@++  ( blk# )
;
: get-dirblk  ( -- error? )  temp-block bsize  next-block#  read-fs-blocks  ;

\
\	UFS directory routines
\

variable diroff
variable totoff
variable current-dir

\ **** Select the directory file
: init-dir  ( file-handle -- error? )
   dup current-dir ! 
   select-file ?dup if exit then
   get-dirblk ?dup if exit then
   0 diroff !  0 totoff !
   false
;

\ **** Return the address of the current directory entry
: dirent  ( -- adr )  temp-block diroff @ +  ;

\ **** Select the next directory entry
: next-dirent  ( -- end? )
   dirent  la1+ w@  dup diroff +!  totoff +!
   totoff @  filesize >=  if  true exit  then
   diroff @  bsize =  if
      get-dirblk ?dup if exit then
      diroff off
   then
   false
;

\ **** From directory, get handle of the file or subdir that it references
\ For Unix, file handle is the inode #
: file-handle  ( -- file-handle )  dirent l@  ;

\ **** From directory, get name of file
: file-name  ( -- adr len )  dirent la1+ wa1+ dup wa1+  swap w@  ;

\ **** Select the root directory
: froot  ( -- error? )  2 init-dir  ;

\
\	UFS high-level routines
\
\       After this point, the code should be independent of the disk format!

: dir  ( -- )  begin   file-name type cr  next-dirent until  ;

: lookup  ( adr len -- not-found? )
   begin
      2dup file-name " $=" boot-eval  if  2drop false exit  then
      next-dirent
   until
   2drop true
;
: path-lookup  ( adr len -- not-found? )
   dup 0=  if  2drop true exit  then
   over c@ ascii /  =  if  1 boot-/string  then
   froot if 2drop true exit then
   begin
      ascii / boot-$split  ( rem-adr len [ adr len ] delim-found? )
   while
      lookup if  2drop true exit  then
      dir? 0=  if  2drop true exit  then
      file-handle init-dir if 2drop true exit then
   repeat   ( rem-adr len )

   \ Now we have found the directory containing the file
   lookup ?dup if exit then
   file-handle select-file
;

\
\	File reading, loading, etc.
\	ELF-specific routines go here.
\

: read-file  ( adr -- error? )
   filesize  begin   ( adr remaining )
      dup 0>
   while
      over bsize  next-block# 
      read-fs-blocks ?dup if exit then
      ( adr remaining ) bsize boot-/string
   repeat
   2drop false
;

\
\ ELF support
\

0 constant elfhdr
0 constant phdr

: +w_elfhdr	( index -- value )  elfhdr swap ca+ w@  ;
: +l_elfhdr	( index -- value )  elfhdr swap ca+ l@  ;
: e_entry	( -- n )  24 +l_elfhdr  ;
: e_phoff	( -- n )  28 +l_elfhdr  ;
: e_phentsize	( -- n )  42 +w_elfhdr  ;
: e_phnum	( -- n )  44 +w_elfhdr  ;

1 constant pt_load
: +phdr		( index -- value )  phdr swap la+ l@ ;
: p_type	( -- n )  0 +phdr ;
: p_offset	( -- n )  1 +phdr ;
: p_vaddr	( -- n )  2 +phdr ;
: p_filesz	( -- n )  4 +phdr ;
: p_memsz	( -- n )  5 +phdr ;
: p_flags	( -- n )  6 +phdr ;
: p_align	( -- n )  7 +phdr ;

: check-elf ( filebase -- is-elf? )
   l@ h# 7f454c46 ( \x7fELF ) =
;

: get-phdr ( filebase index -- )
   e_phentsize * e_phoff + +
   phdr e_phentsize move
;

: load-elf ( filebase -- entry-point )
   dup is elfhdr
   e_phentsize alloc-mem is phdr
   e_phnum 0 ?do
      dup i get-phdr
      p_type pt_load = if
	 ( read it )
	 dup p_offset + p_vaddr p_filesz move
	 p_memsz p_filesz > if
	    ( zero the bss )
	    p_vaddr p_filesz +  p_memsz p_filesz -  0 fill
	 then
      then
   loop drop
   phdr e_phentsize free-mem
   e_entry
;

\
\	UFS installation routines
\

\ **** Allocate memory for necessary data structures
: allocate-ufs-buffers  ( -- error? )
   /super-block alloc-mem is super-block
   get-super-block ?dup if
      ." failed to read super block" cr
      super-block /super-block free-mem close-disk exit
   then
   bsize  alloc-mem is temp-block
   bsize  alloc-mem is indirect-block
   /inode alloc-mem is inode
   false
;

: release  ( -- )
   inode           /inode         free-mem
   indirect-block  bsize          free-mem
   temp-block      bsize          free-mem
   super-block     /super-block   free-mem
   close-disk
;

: initialize  ( -- error? )
   open-disk ?dup if exit then
   allocate-ufs-buffers
;

hex
headers
( external )

: get-file  ( load-adr name-adr name-len -- error? )
   initialize ?dup if  nip nip nip  exit  then           (  )
   path-lookup ?dup if nip release exit then             (  )
   dir?  ?dup  if                                        ( load-adr error? )
      nip ." File is a directory." cr release exit  
   then                                                  ( load-adr )
   read-file ?dup if ." File read failed." cr exit then  (  )
   \ Set FORTH file-size variable
   filesize " file-size" boot-eval !
   release false                                         ( ok )
;

: reloc&go ( -- )
   loadbase
   \ Is it ELF?
   dup check-elf if          ( base-adr )
      load-elf               ( entry-point )
      loadbase!
      " init-program" boot-eval
   else                      ( base-adr )
\ Let FORTH handle anything else
     " adjust-header" boot-eval  if  " init-program" boot-eval  then  ( entry-point )
     loadbase!
   then                     
   4000 loadbase!
   " ?go" boot-eval
;

d# 128 buffer: boot-name

: get-boot-name ( -- adr,len )
   boot-name d# 128 erase
   " /platform/" boot-name swap dup >r cmove r>  ( len0 )
   boot-name over + " name" drop                 ( len0 bufadr namestr )
   0 devr_next devr_getprop                      ( len0 len )
   1- + boot-name over +                         ( len1 adr )
   " /ufsboot"                                   ( len1 adr adr,len )
   >r swap r@ cmove r>                           ( len1 len )
   + boot-name swap 
;

\ 
\ The boot stuff itself
\
: do-boot
   4000 loadbase!
   loadbase get-boot-name get-file  if
        ." Boot load failed." cr exit
   then
   reloc&go
;

do-boot
