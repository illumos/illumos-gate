\ ident	"%Z%%M%	%I%	%E% SMI"
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
\


id: @(#)ufs.fth 1.4 95/08/04
purpose: UFS file system support package
copyright: Copyright 1995 Sun Microsystems, Inc. All Rights Reserved

headers
" /packages" find-package 0= if
   ." Can't find /packages" abort
then  push-package
new-device
   diagnostic-mode?  if  ." Loading "  then
   " ufs-file-system" device-name
   diagnostic-mode?  if
      ." package 1.4 04 Aug 1995 13:02:54. "  cr
   then

   0 0  " support" property

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
      2over 2over  ca+ swap cmove  ( adr,len1 adr,len2 )
      rot + ca+ 0 swap c!  drop    (  )
   ;

   : $=  ( str1$ str2$ -- same? )
      rot tuck <>  if
	 3drop false exit
      then  comp 0=
   ;

   " /openprom/client-services" find-package  0=  if
      ." Can't find client-services"  abort
   then constant cif-phandle

   instance defer cif-claim   ( align size virt -- base )
   instance defer cif-release ( size virt -- )

   : find-cif-method ( adr,len -- acf )
      cif-phandle find-method drop
   ;

   " claim"    find-cif-method to cif-claim
   " release"  find-cif-method to cif-release

   : ufs-alloc-mem ( size -- virt )  1 swap 0 cif-claim  ;
   : ufs-free-mem  ( virt size -- )  swap     cif-release  ;

   \
   \	UFS low-level block routines
   \

   d# 512 constant ublock
   d# 512 constant /super-block
   d#   8 constant ndaddr
   d#  16 constant super-block#  ( -- n )

   0 instance value temp-block
   0 instance value indirect-block
   0 instance value indirect1-block
   0 instance value inode
   0 instance value super-block


   \ Deblocker needs following

   \  read-blocks   ( adr #blocks block# -- #blocks-read )
   \  write-blocks  ( adr #blocks block# -- #blocks-written )

   : quad@  ( adr -- l )
      \ For little-endian machines
      \  l@
      \ For big-endian machines
      la1+ l@
   ;

   : +sb  ( index -- value )  super-block  swap la+ l@  ;
   : iblkno    ( -- n )  d# 04 +sb  ;
   : cgoffset  ( -- n )  d# 06 +sb  ;
   : cgmask    ( -- n )  d# 07 +sb  ;
   : bsize     ( -- n )  d# 12 +sb  ;
   : fragshift ( -- n )  d# 24 +sb  ;
   : fsbtodbc  ( -- n )  d# 25 +sb  ;
   : inopb     ( -- n )  d# 30 +sb  ;
   : ipg       ( -- n )  d# 46 +sb  ;
   : fpg       ( -- n )  d# 47 +sb  ;

   : /frag  ( -- fragsize )  bsize fragshift rshift ;


   : read-ublocks  ( adr len dev-block# -- error? )
      ublock * 0 " seek" $call-parent ?dup  if  exit  then
      ( adr len )  tuck " read" $call-parent <>
   ;
   : get-super-block  ( -- error? )
      super-block /super-block super-block# read-ublocks
   ;

   : cgstart   ( cg -- block# )
      dup cgmask invert and  cgoffset *   swap fpg *  +
   ;
   : cgimin    ( cg -- block# )  cgstart  iblkno +  ;

   : blkstofrags  ( #blocks -- #frags )  fragshift lshift  ;

   : fsbtodb  ( fs-blk# -- dev-blk# )  fsbtodbc lshift  ;

   : read-fs-blocks  ( adr len fs-blk# -- error? )  fsbtodb read-ublocks  ;

   \
   \	UFS inode routines
   \

   h# 80 constant /inode

   instance variable blkptr
   instance variable blklim
   instance variable indirptr
   instance variable indir1ptr
   0 instance value lblk#

   : itoo  ( i# -- offset )  inopb mod  ;
   : itog  ( i# -- group )  ipg /  ;
   : itod  ( i# -- block# )
      dup itog cgimin  swap ipg mod  inopb /  blkstofrags  +
   ;

   : +i  ( n -- )  inode +  ;

   : ftype ( -- n )  0 +i  w@  h# f000 and  ;
   : dir?      ( -- flag )  ftype h# 4000 =  ;
   : symlink?  ( -- flag )  ftype h# a000 =  ;
   : regular?  ( -- flag )  ftype h# 8000 =  ;

   : file-size  ( -- n )  8 +i quad@  ;
   : direct0    ( -- adr )  d# 40 +i  ;
   : indirect0  ( -- adr )  d# 88 +i  ;
   \ : indirect1  ( -- adr )  d# 92 +i  ;

   \ **** Select the indicated file for subsequent accesses
   : rewind  ( -- )
      direct0 blkptr !   indirect0 blklim !  indirect0 indirptr !
      0 to lblk#
   ;

   0 instance value current-file
   : select-file  ( i# -- error? )
      dup to current-file
      dup temp-block bsize  rot  itod
      read-fs-blocks ?dup  if  exit  then
      itoo /inode * temp-block +   inode /inode move
      rewind
      false
   ;

   : l@++  ( ptr -- value )  dup @ l@  /l rot +!  ;

   \ **** Locate the next block within the current file
   : next-block#  ( -- [ n ] error? )
      blkptr @  blklim @ =  if
	 indirptr @  indirect0  =  if
	    indirect-block bsize indirptr l@++ ( adr,len )
	    read-fs-blocks  if  true  exit  then
	    indirect-block  blkptr !   indirect-block bsize +  blklim !

	    indirect1-block bsize indirptr l@++ ( adr,len )
	    read-fs-blocks  if  true  exit  then
	    indirect1-block indir1ptr !
	 else
	    indirect-block bsize indir1ptr l@++ ( adr,len )
	    read-fs-blocks  if  true  exit  then
	    indirect-block  blkptr !   indirect-block bsize +  blklim !
	 then
      then
      lblk# 1+ to lblk#
      blkptr l@++  ( blk# )  ?dup  0=
   ;

   : block#>fs-block# ( lblk# -- [ n ] error? )
      dup lblk# <  if  rewind  then    ( target-blk# )
      begin  dup lblk# <>  while       ( target-blk# )
	 next-block#  if               ( target-blk# )
	    drop true  exit
	 else                          ( target-blk# blk# )
	    drop                       ( target-blk# )
	 then                          ( target-blk# )
      repeat  drop  next-block#        ( [ n ] error? )
   ;

   : read-one-block ( adr block# -- error? )
      block#>fs-block#  ?dup  if  drop  exit  then
      bsize  swap  read-fs-blocks
   ;

   : get-dirblk  ( -- error? )
      temp-block bsize  next-block#  0=  if
	 read-fs-blocks
      else
	 2drop true
      then
   ;

   \
   \	UFS directory routines
   \

   instance variable diroff
   instance variable totoff

   0 instance value current-dir

   \ **** Select the directory file
   : init-dir  ( i# -- error? )
      dup to current-dir
      select-file ?dup  if  exit  then
      get-dirblk ?dup  if  exit  then
      0 diroff !  0 totoff !
      false
   ;

   : root-dir? ( -- flag )  current-dir 2  =  ;

   \ **** Return the address of the current directory entry
   : dirent  ( -- adr )  temp-block diroff @ +  ;

   \ **** Select the next directory entry
   : next-dirent  ( -- end? )
      dirent  la1+ w@  dup diroff +!  totoff +!
      totoff @  file-size >=  if  true exit  then
      diroff @  bsize =  if
	 get-dirblk ?dup  if  exit  then
	 diroff off
      then
      false
   ;

   \ **** From directory, get handle of the file or subdir that it references
   \ For Unix, file handle is the inode #
   : file-handle  ( -- i# )  dirent l@  ;

   \ **** From directory, get name of file
   : file-name  ( -- adr len )  dirent la1+ wa1+ dup wa1+  swap w@  ;

   \ **** Select the root directory
   : froot  ( -- error? )  2 init-dir  ;

   \
   \	UFS high-level routines
   \
   \       After this point, the code should be independent of the disk format!

   : lookup  ( adr len -- i# false | true  )
      begin
	 2dup file-name  $=  if      ( adr,len )
	    2drop  file-handle       ( i# )
	    dup select-file ?dup  if ( i# true )
	       nip                   ( true )
	    else                     ( i# )
	       false                 ( i# false )
	    then  exit
	 then                        ( adr,len )
	 next-dirent                 ( adr,len end? )
      until  2drop true              ( true )
   ;


   h# 200 instance buffer: fpath-buf

   : follow-symlink ( tail$ -- tail$" )
      temp-block 0 read-one-block  if  2drop exit  then     ( tail-$ )
      temp-block cscount                                    ( tail-$ head-$' )
      fpath-buf 0 $append                                   ( $tail-$ )
      ?dup  if                                              ( $tail-$ )
	 " /" fpath-buf cscount $append                     ( $tail-$ )
	 fpath-buf cscount $append                          (  )
      else  drop  then                                      (  )
      fpath-buf cscount                                     ( tail-$' )
      over c@ ascii / =  if                                 ( path$ )
	 froot  if  2drop true  exit  then                  ( \path$ )
	 ascii / left-parse-string 2drop                    ( path$ )
      else                                                  ( path$ )
	 current-dir init-dir   if  2drop true  exit  then  ( tail-$ )
      then
   ;

   : ($chdir  ( adr len -- error? )		\ Fail if path is file, not dir
      ?dup 0=  if  drop true exit  then
      over c@ ascii / =  if                           ( path$ )
	 froot  if  2drop true  exit  then            ( \path$ )
	 ascii / left-parse-string 2drop              ( path$ )
      else                                            ( path$ )
	 current-dir  init-dir  drop                  ( path$ )
      then                                            ( path$ )
      begin					      ( path-$ )
	 ascii / left-parse-string                    ( tail-$ head-$ )
	 dup
      while					      ( tail-$ head-$ )
	 lookup    if  2drop true exit  then          ( tail-$ i# )
	 symlink?  if                                 ( tail-$ i# )
	    drop follow-symlink                       ( tail-$' )
	 else                                         ( tail-$ i# )
	    dir? 0=   if  2drop drop true exit  then  ( tail-$ i# )
	    init-dir  if  2drop true exit  then       ( tail$ )
	 then                                         ( tail$ )
      repeat                                          ( tail-$ head-$ )
      2drop 2drop false
   ;

   : $chdir ( dirpath$ -- error? )
      current-dir   >r  ($chdir  if  (  )  ( r: prev-dir )
	 r> init-dir drop  true      ( error )
      else                           (  )  ( r: prev-dir )
	 r> drop false               ( ok )
      then                           ( error? )
   ;

   : .dirname ( inode# -- )
      begin                      ( inode# )
	 file-handle over =  if  ( inode# )
	    ." /"                ( inode# )
	    file-name type  true ( inode# done )
	 else                    ( inode# )
	    false                ( inode# done? )
	 then                    ( inode# done? )
	 next-dirent or          ( inode# done? )
      until  drop                (  )
   ;

   \
   \	UFS installation routines
   \

   \ **** Allocate memory for necessary data structures
   : allocate-ufs-buffers  ( -- error? )
      /super-block ufs-alloc-mem to super-block
      get-super-block ?dup  if
	 ." failed to read super block" cr
	 super-block /super-block ufs-free-mem true exit
      then
      bsize  ufs-alloc-mem to temp-block
      bsize  ufs-alloc-mem to indirect-block
      bsize  ufs-alloc-mem to indirect1-block
      /inode ufs-alloc-mem to inode
      false
   ;

   : release  ( -- )
      inode            /inode         ufs-free-mem
      indirect-block   bsize          ufs-free-mem
      indirect1-block  bsize          ufs-free-mem
      temp-block       bsize          ufs-free-mem
      super-block      /super-block   ufs-free-mem
   ;

   false instance value file-open?

   \ UFS file interface

   0 instance value deblocker
   : init-deblocker  ( -- okay? )
      " "  " deblocker"  $open-package  to deblocker
      deblocker if
	 true
      else
	 ." Can't open deblocker package"  cr  false
      then
   ;

   \ Splits a string into two halves after the last occurrence of
   \ a delimiter character.
   \ adra,lena is the string after the delimiter
   \ adrb,lenb is the string before and including the delimiter
   \ lena = 0 if there was no delimiter

   \ adra,lena is the string after the delimiter
   \ adrb,lenb is the string before and including the delimiter
   \ lena = 0 if there was no delimiter

   : right-parse-string  ( adr len char -- adra lena  adrb lenb  )
      >r  2dup + 0                       ( adrb lenb  adra 0 )

      \ Throughout the loop, we maintain both substrings.
      \ Each time through, we add a character to the "after"
      \ string and remove it from the "before".
      \ The loop terminates when either the "before" string
      \ is empty or the desired character is found

      begin  2 pick  while               ( adrb lenb  adra lena )
	 over 1- c@  r@ =  if \ Found it ( adrb lenb  adra lena )
	    r> drop 2swap  exit          ( adrb lenb  adra lena )
	 then
	 2swap 1-  2swap swap 1- swap 1+ ( adrb lenb  adra lena )
      repeat                             ( adrb lenb  adr1 len1 )

      dup  if                            ( adrb lenb  adr1 len1 )
	 2swap  dup if 1-  then          ( adr1 len1 adrb lenb' )
      else                               ( adrb lenb  adr1 len1 )
	 2swap                           ( adr1 len1 adrb lenb )
      then                               ( adra lena adrb lenb )

      \ Character not found.  lena is 0.
      r> drop
   ;

   h# 200 instance buffer: fpath1-buf

   : file-lookup ( fname$ -- i# false | true )
      begin  lookup  0=  while                            ( i# )
	 dup select-file  if  drop true exit  then        ( i# )
	 symlink?  if                                     ( i# )
	    drop 0 0 follow-symlink                       ( path$/file$ )
	    fpath1-buf 0 $append fpath1-buf cscount       ( path$/file$ )
	    ascii / right-parse-string                    ( file$ path$ )
	    ?dup if                                       ( file$ path$ )
	       $chdir  if  2drop true  exit  then  else  drop
	    then                                          ( file$ )
	 else  false  exit  then                          ( file$ )
	 current-dir init-dir  if  2drop true  exit then  ( file$ )
      repeat  true                                        ( true )
   ;

   : ufs-open  ( adr len  -- success? )
      file-lookup  if       (  )
	 false              ( fail )
      else                  ( i# )
	 select-file  if    (  )
	    false           ( fail )
	 else               (  )
	    init-deblocker  ( success? )
	 then               ( success? )
      then                  ( success? )
   ;

   : (cwd)  ( -- ) tokenizer[ reveal ]tokenizer
      root-dir?  0=  if
	 current-dir  " .." $chdir drop
	 (cwd)  dup .dirname  init-dir drop
      then
   ;

   h# 100 instance buffer: ufs-args

   : get-my-args ( -- adr,len )
      my-args  ?dup  if   ( arg$ )
	 ufs-args pack  count  bounds ?do
	    i c@ ascii | =  if  ascii / i c!  then
	    i c@ ascii \ =  if  ascii / i c!  then
	 loop
      else
	 drop 0 ufs-args c!
      then  ufs-args count
   ;
   : ufs-args$ ( -- arg$ ) ufs-args count ;

   0 instance value file-offset

   external
   : block-size   ( -- #bytes/block )  bsize  ;
   : max-transfer ( -- #bytes/block )  block-size 4 *  ;

   : dma-alloc ( size -- virt )  " dma-alloc" $call-parent  ;
   : dma-free  ( virt size -- )  " dma-free"  $call-parent  ;

   : read-blocks ( adr block# #blocks -- #read )
      0 -rot  bounds ?do               ( adr  block-count )
	 over i read-one-block ?leave  ( adr count )
	 1+ swap bsize ca+ swap        ( adr' count+1 )
      loop  nip
   ;

   \ UFS Write is not supported
   : write-blocks  ( adr #blocks block# -- #blocks-written )  3drop  0  ;

   : open  ( -- okay? )
      allocate-ufs-buffers  if  false exit  then

      \ Select the root directory
      froot  drop

      get-my-args " <NoFile>"  $=  if  true exit  then

      ufs-args$  ascii / right-parse-string        ( file$ path$ )
      $chdir  if  2drop release false  exit  then  ( file$ )

      \ Filename ends in "/"; select the directory and exit with success
      dup  0=  if  2drop  true exit  then          ( file$ )

      ufs-open  ?dup  if  exit  then  ( failed? )

      release false
   ;

   : close  ( -- )
      deblocker ?dup  if close-package  then
      release
   ;

   : read  ( addr len -- actual-len )
      " read"  deblocker $call-method  dup  if ( #bytes-read )
	 dup file-offset + file-size >  if     ( #bytes-read )
	    drop file-size file-offset -       ( #bytes-left )
	 then                                  ( #bytes-read )
      then                                     ( #bytes-read )
      dup file-offset + to file-offset         ( actual-len  )
   ;

   \ UFS Write is not supported
   : write ( addr len -- actual-len )  2drop  0  ;

   : size  ( -- d )  file-size  0  ;


   : seek  ( offset.low offset.high -- failed? )

      \ Return error if offset.hi != 0
      dup 0<> if  2drop true  exit  then     ( offset.lo offset.hi )

      \ Return error if offset.lo > file-size
      over file-size >  if  2drop true  exit  then  ( offset.lo offset.hi )

      \ Looks like a reasonable offset
      over to file-offset                    ( offset.lo offset.hi )

      \ Finally give the deblocker chance to adjust
      " seek"   deblocker $call-method       ( offset.lo offset.hi failed? )
   ;
   : load  ( adr -- size )  file-size  read  ;

   headers
   : restore-file ( i# -- )
      ?dup  if
	 select-file 0=  if  regular?  if  file-offset 0  seek  drop  then  then
      then
   ;
   external
   : dir   ( -- )
      current-file
      current-dir init-dir drop
      begin  file-name type cr  next-dirent  until
      restore-file
   ;
   : cwd   ( -- )
      current-file
      root-dir?  if  ." /"  else  (cwd)  then
      restore-file
   ;

   headers

finish-device
pop-package

id: @(#)boot.fth 1.6 95/08/04
purpose: UFS File System Boot Block
copyright: Copyright 1995 Sun Microsystems, Inc. All Rights Reserved

headers
" /packages/disk-label" find-package 0=  if
   ." Can't find /packages/disk-label" abort
then dup  push-package  ( phandle )

\ Find the previous "open" definition.
defer prev-open ( -- ok? )
' false to prev-open
" open" rot find-method  if  to prev-open  then

external
: open ( -- okay? )
   \ Arg string is <part>[,<filespec>]
   \ Split off partition, and handle filename
   my-args  ascii , left-parse-string       ( file$ part$ )
   2drop  ?dup  if                          ( file$ )
      " ufs-file-system"  find-package  if  ( file$ phandle )
	 interpose                          (  )
      else                                  ( file$ )
	 2drop                              (  )
      then                                  (  )
   else                                     ( file )
      drop                                  (  )
   then  prev-open                          ( okay? )
;
headers

pop-package

headers
" /chosen" find-package  0=  if  false  then  ( phandle )
constant chosen-phandle

" /openprom/client-services" find-package 0=  if  false  then  ( phandle )
constant cif-phandle

defer cif-claim ( align size virt -- base )
defer cif-release ( size virt -- )
defer cif-open ( cstr -- ihandle|0 )
defer cif-close ( ihandle -- )
defer cif-read ( len adr ihandle -- #read )
defer cif-seek ( low high ihandle -- -1|0|1 )
defer cif-peer ( phandle -- phandle )
defer cif-getprop ( len adr cstr phandle -- )

: find-cif-method ( adr,len -- acf )
   cif-phandle find-method drop
;

" claim"    find-cif-method to cif-claim
" release"  find-cif-method to cif-release
" open"     find-cif-method to cif-open
" close"    find-cif-method to cif-close
" read"     find-cif-method to cif-read
" seek"     find-cif-method to cif-seek
" peer"     find-cif-method to cif-peer
" getprop"  find-cif-method to cif-getprop


d# 256 constant /devname-buf
/devname-buf buffer: devname
: clear-devname-buf ( -- )
   devname /devname-buf 0 fill
;

: devname$ ( -- adr,len )  devname cscount  ;

: chosen-property ( name$ -- value$ false -or- true )
   chosen-phandle get-package-property  if  true
   else
      decode-string 2swap 2drop  false
   then
;
: get-devname ( -- )
   clear-devname-buf
   " bootpath" chosen-property  if   (  )
      ." Can't find bootpath" abort  (  )
   then  devname$ $append            (  )
;

get-devname \ Initialize the device name buffer

: bootargs ( -- adr,len )
   " bootargs" chosen-property  if
      ." Can't find bootargs" abort
   then
;

: printable?  ( n -- flag ) \ true if n is a printable ascii character
   dup bl th 7f within  swap  th 80  th ff  between  or
;
: white-space? ( n -- flag ) \ true is n is non-printable? or a blank
   dup printable? 0=  swap  bl =  or
;

: -leading  ( adr len -- adr' len' )
   begin  dup  while   ( adr' len' )
      over c@  white-space? 0=  if  exit  then
      swap 1+ swap 1-
   repeat
;

: -trailing  (s adr len -- adr len' )
   dup  0  ?do   2dup + 1- c@   white-space? 0=  ?leave  1-    loop
;
: strip-blanks ( adr,len -- adr,len' )  -trailing -leading  ;

: (option?) ( char -- rem$ true -or- false )
   >r  bootargs  begin  strip-blanks  ?dup  while  ( $r )
      bl left-parse-string  r@ -rot                ( $r char $l )
      strip-blanks  ?dup  if                       ( $r char $l )
	 over dup c@ ascii -  =  if                ( $r char $l adr )
	    1+ c@ ascii - =  if                    ( $r char $l )
	       2drop r> 2drop 2drop  false  exit
	    then                                   ( $r char $l )
	    bounds  0 -rot  ?do                    ( $r char flag )
	       over i c@  =  or                    ( $r char flag )
	    loop  nip  if  r>  drop  true  exit  then
	 else                                      ( $r char $l adr )
	    2drop 2drop                            ( $r )
	 then                                      ( $r )
      else                                         ( $r char adr )
	 2drop                                     ( $r )
      then                                         ( $r )
   repeat  r>  2drop  false                        ( false )
;
: option?  ( char -- flag )
   (option?)  if  2drop  true  else  false  then
;

\ : don't-boot?  ( -- flag )  ascii L option?  ;
: halt?        ( -- flag )  ascii H option?  ;

: alternate-booter? ( -- fname true -or- false )
   ascii F (option?)  if                           ( adr,len )
      strip-blanks                                 ( adr,len' )
      bl left-parse-string  2swap 2drop  ?dup  if  ( fname$ )
	 true  exit
      then  drop                                   (  )
   then  false                                     ( false )
;

d# 256 constant /booter-name
/booter-name buffer: booter-name
: booter-name$ ( -- adr,len )  booter-name cscount  ;
: clear-booter-name ( -- )  booter-name /booter-name 0 fill  ;
: $cat-booter-name ( adr,len -- )  booter-name$ $append  ;

d# 256 constant /root-name
/root-name buffer: root-name
: root-name$ ( -- adr,len )  root-name cscount  ;
: clear-root-name ( -- )  root-name /root-name 0 fill  ;

: root$ ( -- adr,len )
   clear-root-name                      ( )
   /root-name root-name                 ( len,adr )
   " name" drop                         ( len,adr cstr )
   0 cif-peer                           ( len,adr cstr root )
   cif-getprop drop                     ( )
   " /" root-name$ $append              ( )
   root-name$                           ( rootname$ )
;

: plat-booter$ ( -- adr,len )
   clear-booter-name                    (  )
   alternate-booter?  0=  if            (  )
      " ufsboot"                        ( filename$ )
   then                                 ( filename$ )
   over c@ ascii / <>  if               ( filename$ )
      " /platform/"  $cat-booter-name   ( filename$ )
      root$  $cat-booter-name           ( filename$ )
   then  $cat-booter-name  booter-name$ ( booter$ )
;

: def-dirname$ ( -- dir$ )  " /platform/sun4u/"  ;

: def-booter$ ( -- adr,len )
   clear-booter-name                    (  )
   alternate-booter?  0=  if            (  )
      " ufsboot"                        ( filename$ )
   then                                 ( filename$ )
   over c@ ascii / <>  if               ( filename$ )
      def-dirname$  $cat-booter-name    ( filename$ )
   then  $cat-booter-name  booter-name$ ( booter$ )
;

d# 256 constant /filename-buf
/filename-buf buffer: filename-buf
: filename-buf$ ( -- adr,len )  filename-buf cscount  ;
: clear-filename-buf ( -- )  filename-buf /filename-buf 0 fill  ;
: $cat-filename ( adr,len -- )  filename-buf$ $append  ;

h# 10.0000 constant 1meg

: ufs-fopen ( adr,len -- ihandle|0 )  drop cif-open  ;
: ufs-fread ( buf,len ihandle -- #read )  >r swap r> cif-read  ;
: ufs-fclose ( ihandle -- )  cif-close  ;

: fname>devname$ ( fname$ -- dev$ )
   clear-filename-buf            ( fname$ )
   devname$ tuck $cat-filename   ( fname$ len )
   " ," $cat-filename            ( fname$ len )
   >r  $cat-filename  r>         ( len )
   filename-buf$  rot  ?do       ( bufadr )
      dup i ca+ c@ ascii / =  if ( bufadr )
	 ascii | over i ca+ c!   ( bufadr )
      then                       ( bufadr )
   loop  drop  filename-buf$     ( dev$ )
;

: set-file-size ( ihandle -- )
   " size" rot $call-method  ( size.lo size.hi )
   drop " to file-size" evaluate
;

h# 6000 constant loader-base

: get-file ( adr fname$ -- fail? )
   fname>devname$ ufs-fopen ?dup  if   ( adr ihandle )
      dup set-file-size                ( adr ihandle )
      over to loader-base              ( adr ihandle )
      >r  begin                        ( adr )
	 dup 1meg r@ ufs-fread         ( adr #read )
	 ?dup  while                   ( adr #read )
	 ca+                           ( adr" )
      repeat  drop r> ufs-fclose false ( ok )
   else                                ( adr )
      drop true                        ( failed )
   then                                ( failed? )
;

: get-redirect-info ( -- partition true -or- false )
   loader-base " /.SUNW-boot-redirect"  get-file  if  (  )
      false                            ( false )
   else                                ( adr )
      loader-base c@                   ( part )
      dup ascii 0 ascii 9 between  if  ( part )
	 diagnostic-mode?  if          ( part )
	    ." Redirected to slice: " dup emit cr
	 then                          ( part )
	 ascii 0 - ascii a +  true     ( part' true )
      else                             ( part )
	 drop false                    ( false )
      then                             ( part true | false )
   then                                ( part true | false )
;

: update-devname ( part -- )
   clear-devname-buf               ( part )
   get-devname  devname$           ( part adr,len )

   ca+ 1- dup 1- c@  ascii :  =  if  ( part adr:x )
      c!                             (  )
   else                              ( part adr:x )
      2drop                          (  )
   then                              (  )
;

: real-devname ( -- )
   get-redirect-info  if  ( part )
      update-devname      (  )
   then                   (  )
;

: allocate-memory ( size  -- virtual )  1 swap 0 cif-claim  ;
: free-memory     ( virt size -- )      swap  cif-release  ;

: sign-on ( -- )
   diagnostic-mode?  if
      ." FCode UFS Reader %I% %E% %U%. " cr
   then
;

: check-elf ( vadr -- flag )  l@ h# 7f454c46 ( \x7fELF ) =  ;

: force?  ( -- flag )  ascii X option? ;

: execit  ( -- )
   \ we rely on the prom to do the right thing with the executable, since
   \ it understands ELF32 and ELF64
   loader-base dup check-elf force? or if
      " to load-base init-program" evaluate
   else
      drop ." Not a valid ELF file" cr exit
   then
;

: do-boot ( -- )
   sign-on  real-devname
\   don't-boot?  if  exit  then
   halt?  if
      ." Halted with -H flag. " cr
      exit
   then
   loader-base  plat-booter$  ( adr,len )
   diagnostic-mode?  if  ." Loading: " 2dup type cr  then
   get-file  if
      loader-base def-booter$
      diagnostic-mode?  if  ." Loading: " 2dup type cr  then
      get-file  if
	 ." Boot load failed." cr exit
      then
   then
   execit
;

do-boot
