\ ident	"%Z%%M%	%I%	%E% SMI"
\ purpose: Rock Ridge Boot Block
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

\ High Sierra, Rock Ridge (CD-ROM) file system reader and boot block
\ Original HSFS code from Mitch Bradley, RR extensions by Sam Cramer

\ There's some code in there that would be a shame to throw out,
\ but which currently doesn't fit in the boot block.  This code is commented
\ out, with #ifdef style comment lines.  The "options" are:
\	HSFSNAMES -- look at hsfs names if you can't find Rock Ridge names
\	PROCESS_CE -- process continuation (CE) signatures; this is
\			potentially useful, but it looks like the RR disks
\			we're dealing with don't use them, and it is a bit
\			of work to implement continuations.
\	PATHLOOKUP -- handle pathnames, not just filenames which are in
\			the root directory

\ FIXME need some way of returning exceptions cleanly
\ The culprit is the "abort" in read-blocks

\ Fcode-version1
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


\ defer open-disk  ( -- )
\ defer read-dev-bytes  ( adr len byte# -- error? )
\ defer close-disk  ( -- )


: devname  ( -- cstr )
     h# 88 roment @			\ bootpath
;

\ Debug V2 or later PROMs
\ : devname " /sbus/esp/sd@3,0:b" drop ;


\ Debug V0 PROMS
\ : devname " sd(0,0,0)" drop ;

variable devid
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

: read-dev-bytes ( adr len byte# -- error? )
	0 seek ?dup if exit then
	( adr len ) read-blks
;

\ : xl@  ( adr -- l )  la1+ unaligned-l@  ;	\ For big-endian machines
\ unaligned-l@ is not define in OBP...
: xl@  ( adr -- l )  				\ For big-endian machines
	dup c@ swap 	( c1 adr )
	1+ dup c@ swap 	( c0 c1 adr+1 )
	1+ dup c@ swap  ( c0 c1 c2 adr+2 )
	1+ c@		( c0 c1 c2 c3 )
	8 << + 8 << + 8 << +
;

\ : xl@  ( adr -- l )  unaligned-l@  ;	\ For little-endian machines
: xw@  ( adr -- w )  dup c@  swap 1+ c@ 8 << +  ;

\ compare two strings for equality
: $=  ( adr1 len1  adr2 len2  -- same?  )
   rot over  =  if   ( adr1 adr2 len2 )
      comp 0=
   else
      2drop drop false
   then
;

0 value dir-buf			\ buffer for current directory block
0 value sua-buf			\ buffer for current sua block
0 value vol-desc		\ volume descriptor

2048 constant /sector

16 constant vol-desc-sector#  ( -- n )

\ logical block size (from volume descriptor)
: /block  ( -- n )   vol-desc 128 +  xw@  ;

\ root directory entry (in volume descriptor)
: root-dirent  ( -- adr )  vol-desc 156 +  ;

: release  ( -- )
   dir-buf      /block    free-mem
   sua-buf	/block	  free-mem
   vol-desc     /sector   free-mem
   close-disk
;

: read-abort  ( adr len byte# -- error? )
\   read-dev-bytes if  release ." Disk read failed" abort  then
   0 seek ?dup if exit then
   read-blks  drop  \ Ignore error code !!
;

: get-vol-desc  ( -- )
   vol-desc /sector vol-desc-sector# /sector * read-abort
;

\ **** Allocate memory for necessary data structures
: allocate-hsfs-buffers  ( -- )
   /sector alloc-mem is vol-desc
   get-vol-desc
   /block  alloc-mem is dir-buf
   /block  alloc-mem is sua-buf
;

\ File handles

\ #ifdef HSFSNAMES
\ \ Remove any version number ( ;nnn ) from the name.
\ : -version  ( adr len -- adr len' )
\ 2dup
\   bounds  ?do                        ( adr len )
\      \ If a ; is located, set len to the length before the ;
\      i c@  ascii ;  =
\      if  drop i over - leave  then   ( adr len' )
\   loop
\ ;
\ #endif HSFSNAMES

0 value file-desc		\ points to current dir entry
0 value sua-desc		\ points to current SUA entry

: select-file  ( adr -- )  is file-desc  ;
: +fd  ( n -- adr )  file-desc +  ;
: file-extent  ( -- n )  2 +fd xl@  ;
: filesize  ( -- n )  10 +fd xl@  ;

: hsfs-file-name  ( -- adr len )  33 +fd  32 +fd c@ ;
: dir?  ( -- flag )  25 +fd  c@  h# 02 and  0<>  ;
: dir-len ( -- len )  file-desc c@ ;

\ Directories

variable dir-block0	\ First block number in the directory file
variable dir-size	\ Number of bytes in the directory file

variable dir-block#	\ Next block number in the directory file
variable dir-last-block#	\ Last block number in the directory file
variable diroff		\ Offset into the current directory block
variable totoff		\ Total offset into the directory

\ RR fields

\ SUAs
variable sua-off	\ Offset into the current sua entry
: select-sua ( adr -- ) is sua-desc ;
: +suad ( n -- adr ) sua-desc + ;

\ return address of SUA, = addr of filename + len(filename) + 0/1 byte pad
: file-sua ( -- adr )
	hsfs-file-name dup ( addr len len )
	\ add in pad: 1 if len is even, 0 if odd
	2 mod 0= if 1 else 0 then + ( addr len' )
	+
;

: suf-sig ( -- adr len ) sua-desc 2 ;		 	\ signature bytes
: suf-len ( -- len ) 2 +suad c@ ; 			\ suf length

\ #ifdef PROCESS_CE
\ \ location of continuation area, if parsed CE signature
\ variable ce-lbn
\ variable ce-offset
\ variable ce-len
\ 
\ \ CE signature, continuation block
\ : suf-parse-ce-lbn ( -- loc ) 4 +suad xl@ ; 		\ location of cont
\ : suf-parse-ce-offset ( -- n ) 12 +suad xl@ ;		\ offset of cont
\ : suf-parse-ce-len ( -- n ) 20 +suad xl@ ;		\ len of cont
\ 
\ : clear-cont-flags ( -- )  0 ce-lbn ! 0 ce-len ! 0 ce-offset ! ;
\ 
\ \ read the continuation area specified by CE signature
\ : read-cont ( -- )  sua-buf /block ce-lbn /sector * read-abort ;
\ #endif /* PROCESS_CE */

\ NM signature, alternate name
: suf-parse-nm ( -- addr len )
	5 +suad
	suf-len 5 -
;

\ current suf is at or past end of the sua?
: end-sua ( -- end? )
	\ if (sua-off >= block size) then return (true);
	\ if (sua-desc[0] == 0 || sua-desc[1] == 0) then return (true);
	\ return (len(sua entry) == 0)
	sua-off @ /block >= if true exit then
	sua-desc c@ 0= if true exit then
 	1 +suad c@ 0= if true exit then
	suf-len 0=
;

\ select the next system use field
: next-suf  ( -- )
	\ sua-off += len(suf); sua-desc += len(suf);
	suf-len dup sua-off +! +suad select-sua
;

\ return the rock ridge file name associated with the current
\ dir-ent; returns 0 0 if can't find name.
\ ignores continuations
: rr-file-name ( -- adr len )
	\ select start of sua, record sua offset
	file-sua select-sua
	diroff @ sua-off !
	\ while (1) do
	\	if (end of sua) {
	\		break
	\	}
	\	if parse(sua) == 'NM' return suf-parse-nm;
	\	next-suf;
	\ done
	begin
		end-sua if 0 0 exit then
		suf-sig
		" NM" $= if suf-parse-nm exit then
		next-suf
		false
	until
;

\ #ifdef PROCESS_CE
\ \ Alternate verson of rr-file-name which chases continuations
\ \
\ \ return the rock ridge file name associated with the current
\ \ dir-ent; returns 0 0 if can't find name.
\ \ chases continuations
\ : rr-file-name ( -- adr len )
\ 	clear-cont-flags
\ 	\ select start of sua, record sua offset
\ 	file-sua select-sua
\ 	diroff @ sua-off !
\ 	\ while (1) do
\ 	\	if (end of sua) {
\ 	\		if (ce-lbn)
\ 	\			read-continuation;
\ 	\			clear-continuation-info;
\ 	\			fiddle sua pointers;
\ 	\		else
\ 	\			break;
\ 	\	}
\ 	\	if parse(sua) == 'NM' return suf-parse-nm;
\ 	\	if parse(sua) == 'CE'
\ 	\		ce-lbn = suf-parse-ce-lbn();
\ 	\		ce-len = suf-parse-ce-len();
\ 	\		ce-offset = suf-parse-ce-offset();
\ 	\	next-suf;
\ 	\ done
\ 	begin
\ 		end-sua if 
\ 			ce-lbn @ if 
\ 				read-cont
\ 				clear-cont-flags
\ 				sua-buf select-sua
\ 				0 sua-off !
\ 				end-sua if 0 0 exit then
\ 			else
\ 			 	0 0 exit
\ 			then
\ 		then
\ 		suf-sig
\ 		2dup " NM" $= if		\ NM
\ 			2drop suf-parse-nm exit
\ 		then
\ 		2dup " CE" $= if		\ CE
\ 			suf-parse-ce-lbn ce-lbn !
\ 			suf-parse-ce-offset ce-offset !
\ 			suf-parse-ce-len ce-len !
\ 			\ XXX debug " had CE" type cr
\ 		then
\ 		2drop
\ 		next-suf
\ 		false
\ 	until
\ ;
\ #endif /* PROCESS_CE */


\ file name of dir entry
: file-name ( -- adr len )
	rr-file-name 
\ #ifdef HSFSNAMES
\	\ if no rr name, use hsfs name minus version
\	dup 0= if 2drop hsfs-file-name -version then
\ #endif /* HSFSNAMES */
;

\ Read the next directory block, updating diroff and dir-block#
: get-dirblk  ( -- )
   dir-buf  /block  dir-block# @ /block *  read-abort
   0 diroff !
   1 dir-block# +!
;

\ **** Select the next directory entry
: next-file  ( -- end? )
	\ diroff += len(dir entry); totoff += len(dir entry);
	\ if (totoff >= dir-size) then return (true)
	\ if (diroff = block size) then get-dirblk
	\ if (len (next dir entry) == 0 && totoff < dir-size) then get-dirblk
	\ file-desc = dir-buf + diroff
	\ return (len(dir entry) == 0)
   file-desc c@  dup diroff +!  totoff +!
   totoff @  dir-size @ >=  if true exit then
   diroff @  /block =  if  get-dirblk  then
   dir-buf diroff @ + c@ 0=  
	dir-block# @ dir-last-block# @ <
	and if  get-dirblk  then
   dir-buf  diroff @  +  select-file
   file-desc c@ 0=
;

\ **** Select the first file in the current directory
: reset-dir  ( -- )
   dir-block0 @  dir-block# !
   get-dirblk
   0 totoff !
   dir-buf  diroff @  +  select-file
   next-file drop  next-file drop   \ Skip the "parent" and "self" entries
;

\ **** "cd" to the current file (read directory pointed to by dirent)
: set-dir  ( -- )
   file-extent dir-block0 !
   filesize   dir-size   !
   filesize /block / dir-block0 @ + dir-last-block# !
   reset-dir
;

\ **** Select the root directory
: froot  ( -- )  root-dirent select-file set-dir  ;

: dir  ( -- )  begin   file-name type cr  next-file until  ;


\ search directory block for file name
: lookup  ( adr len -- not-found? )
   \ #ifndef PATHLOOKUP
   froot
   \ #endif /* PATHLOOKUP */
   begin
      2dup file-name $=  if  2drop false exit  then
      next-file
   until
   2drop true
;

\ #ifdef PATHLOOKUP
\ : /string  ( adr len size -- adr+size len-size )  tuck - >r + r>  ;
\ 
\ \ Splits a string around a delimiter.  If the delimiter is found,
\ \ two strings are returned under true, otherwise one string under false.
\ : $split  ( adr len char -- remaining-adr,len  [ initial-adr,len ]  found?  )
\    2 pick  2 pick  bounds  ?do
\       dup i c@  =  if  i nip -1  then 
\    loop                                    ( adr len   adr' -1  |  char )
\    -1 =  if   ( adr len  adr' )
\       swap >r            ( adr adr' )  ( r: len )
\       2dup swap - swap   ( adr [adr'-adr] adr' )  ( r: len )
\       1+  r>             ( adr [adr'-adr] adr'+1 len )
\       2 pick - 1-        ( adr [adr'-adr]  adr'+1  len-[adr'-adr-1] )
\       2swap true         ( rem-adr,len initial-adr,len true )
\    else
\       false
\    then
\ ;
\ 
\ : path-lookup  ( adr len -- not-found? )
\    dup 0=  if  2drop true exit  then
\    over c@ ascii /  =  if  1 /string  then
\    froot
\    begin
\       ascii / $split  ( rem-adr,len  [ adr,len ] delim-found? )
\    while
\       lookup   if  ." Bad path" cr  2drop true exit  then
\       dir? 0=  if  ." Bad path" cr  2drop true exit  then
\       set-dir
\    repeat   ( rem-adr,len )
\ 
\    \ Now we have found the directory containing the file
\    lookup  if
\       ." File not found among: " cr
\       reset-dir  dir
\       true
\    else
\       false		\ File is already selected
\    then   ( flag )
\ ;
\ #endif /* PATHLOOKUP */

\ File reading
: read-file  ( adr -- error? )
   filesize  file-extent /block *  read-dev-bytes  ( error? )
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
\ : p_flags	( -- n )  6 +phdr ;
\ : p_align	( -- n )  7 +phdr ;

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

\ Installation

: initialize  ( -- )
   open-disk ?dup if exit then
   allocate-hsfs-buffers
;

hex
headers
( external )

: get-file  ( load-adr name-adr name-len -- error? )
   initialize
   \ #ifndef PATHLOOKUP
   lookup  if  ." lookup failed" cr drop release true exit  then
   \ #else /* PATHLOOKUP */
   \ path-lookup  if  drop release true exit  then
   \ #endif /* PATHLOOKUP */
   dir?  if
      ." Requested file is a directory" cr  drop release true exit
   then
   read-file ?dup if ." File read failed." cr exit then
   filesize " file-size" boot-eval !
   release
   false
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
     " adjust-header" boot-eval  if 
       " init-program" boot-eval
     then  ( entry-point )
     loadbase!
   then                     
   4000 loadbase!
   " ?go" boot-eval
;

\ 
\ The boot stuff itself
\
: do-boot
   4000 loadbase!
   \ #ifndef PATHLOOKUP
   loadbase " hsfsboot" get-file  if
   \ #else  /* PATHLOOKUP */
   \ loadbase " /hsfsboot" get-file  if
   \ #endif /* PATHLOOKUP */
        ." Boot load failed." cr exit
   then
   reloc&go
;

do-boot
