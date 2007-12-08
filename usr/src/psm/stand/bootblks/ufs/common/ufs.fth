
\ ident	"%Z%%M%	%I%	%E% SMI"
\ Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
\ Use is subject to license terms.
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


id: %Z%%M%	%I%	%E% SMI
purpose: UFS file system support package
copyright: Copyright 1995 Sun Microsystems, Inc. All Rights Reserved

headers
" /packages" get-package  push-package

new-device
   fs-pkg$  device-name  diag-cr?

   \
   \	UFS low-level block routines
   \

   h# 2000  constant  /max-bsize
   d# 512   constant  /disk-block

   0 instance value dev-ih
   0 instance value temp-block

   : blk>byte ( block# -- byte# )  /disk-block *  ;

   : read-disk-blocks  ( adr len dev-block# -- )
      blk>byte dev-ih  read-disk
   ;


   \
   \	UFS superblock routines
   \

   d# 512 constant /super-block
   d#  16 constant super-block#
   0 instance value super-block

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

   : get-super-block  ( -- )
      super-block /super-block super-block#  read-disk-blocks
   ;

   : cgstart   ( cg -- block# )
      dup cgmask invert and  cgoffset *   swap fpg *  +
   ;
   : cgimin       ( cg -- block# )  cgstart  iblkno +  ;
   : blkstofrags  ( #blocks -- #frags )  fragshift lshift  ;
   : lblkno       ( byte-off -- lblk# )  bsize /  ;
   : blkoff       ( byte-off -- blk-off )  bsize mod  ;
   : fsbtodb      ( fs-blk# -- dev-blk# )  fsbtodbc lshift  ;

   : read-fs-blocks  ( adr len fs-blk# -- )  fsbtodb read-disk-blocks  ;


   \
   \	UFS inode routines
   \

   h# 80 constant /inode
   0 instance value inode
   0 instance value iptr

   : itoo  ( i# -- offset )  inopb mod  ;
   : itog  ( i# -- group )  ipg /  ;
   : itod  ( i# -- block# )
      dup itog cgimin  swap ipg mod  inopb /  blkstofrags  +
   ;

   : +i  ( n -- adr )  iptr +  ;

   : ftype ( -- n )  0 +i  w@  h# f000 and  ;
   : dir?      ( -- flag )  ftype h# 4000 =  ;
   : symlink?  ( -- flag )  ftype h# a000 =  ;
   : regular?  ( -- flag )  ftype h# 8000 =  ;

   : file-size  ( -- n )        8 +i x@  ;
   : direct0    ( -- adr )  d# 40 +i  ;
   : indirect0  ( -- adr )  d# 88 +i  ;
   : indirect1  ( -- adr )  d# 92 +i  ;
   : indirect2  ( -- adr )  d# 96 +i  ;
   : comp?      ( -- flag ) d# 100 +i l@  4 and  0<> ;

   0 instance value current-file
   : iget  ( i# -- )
      dup temp-block bsize  rot  itod        ( i# adr len blk# )
      read-fs-blocks
      dup itoo  /inode *  temp-block +  inode /inode  move
      inode to iptr
      to current-file                        (  )
   ;

   : l@++  ( ptr -- value )  dup @ l@  /l rot +!  ;

   d# 12 constant #direct
   : #blk-addr/blk  bsize /l /  ;
   : #sgl-addr      #blk-addr/blk  ;
   : #dbl-addr      #sgl-addr #blk-addr/blk *  ;
\  : #tri-addr      #dbl-addr #blk-addr/blk *  ;

   : >1-idx ( blk# -- idx )  #blk-addr/blk mod  ;
   : >2-idx ( blk# -- idx )  #sgl-addr /  >1-idx  ;
\  : >3-idx ( blk# -- idx )  #dbl-addr /  >1-idx  ;

   \
   \ indirect block cache
   \ we assume reads will mostly be sequential, and only
   \ cache the current indirect block tree
   \
   : get-indir  ( fs-blk# var adr -- adr )
      -rot  dup >r   @ over  =  if             ( adr fs-blk#  r: var )
         r> 2drop  exit                        ( adr )
      then                                     ( adr fs-blk#  r: var )
      2dup  bsize swap  read-fs-blocks         ( adr fs-blk#  r: var )
      r> !                                     ( adr )
   ;
      
   0 instance value indir0-adr
   instance variable cur-indir0
   : get-indir0  ( fs-blk# -- adr )
      cur-indir0 indir0-adr  get-indir
   ;

   0 instance value indir1-adr
   instance variable cur-indir1
   : get-indir1  ( fs-blk# -- adr )
      cur-indir1 indir1-adr  get-indir
   ;

   \
   \ blkptr and blklim point to an array of blk#s,
   \ whether in the inode direct block array or in
   \ an indirect block
   \
   instance variable blkptr
   instance variable blklim

   : (bmap)  ( lblk# -- )
      dup  #direct <  if                           ( lblk# )
         direct0 swap la+  blkptr  !               (  )
         direct0 #direct la+  blklim  !
         exit
      then                                         ( lblk# )

      #direct -                                    ( lblk#' )
      dup  #sgl-addr <  if
         indirect0 l@  get-indir0                  ( lblk# adr )
         tuck  swap >1-idx la+  blkptr  !          ( adr )
         #blk-addr/blk la+  blklim  !
         exit
      then                                         ( lblk# )

      #sgl-addr -                                  ( lblk#' )
      dup  #dbl-addr <  if
         indirect1 l@  get-indir0                  ( lblk# adr )
         over >2-idx la+ l@  get-indir1            ( lblk# adr' )
         tuck  swap >1-idx la+  blkptr  !          ( adr )
         #blk-addr/blk la+  blklim  !              (  )
         exit
      then                                         ( lblk# )

\     #dbl-addr -                                  ( lblk#' )
\     dup  #tri-addr <  if
\        indirect2 l@  get-indir0                  ( lblk# adr )
\        over >3-idx la+ l@  get-indir1            ( lblk# adr' )
\        over >2-idx la+ l@  get-indir2            ( lblk# adr' )
\        tuck  swap >1-idx la+  blkptr  !          ( adr )
\        #blk-addr/blk la+  blklim  !              (  )
\        exit
\     then                                         ( lblk# )
      ." file too large" cr  drop true             ( failed )
   ;

   0 instance value cur-blk
   : bmap  ( lblk# -- fs-blk# )
      dup cur-blk <>  blkptr @  blklim @ =  or  if       ( lblk# )
         dup (bmap)                                      ( lblk# )
      then                                               ( lblk# )
      1+ to cur-blk                                      (  )
      blkptr l@++                                        ( fs-blk# )
   ;

   : read-one-block ( adr block# -- )
      bmap  ?dup  if
         bsize swap  read-fs-blocks
      else
         bsize  erase
      then
   ;

   : read-partial-block ( adr len off block# -- )
      bmap  ?dup  if
         fsbtodb  blk>byte +                        ( adr len byte# )
         dev-ih  read-disk
      else
         drop  erase
      then
   ;

   \
   \	UFS directory routines
   \

   instance variable dir-blk
   instance variable totoff
   instance variable dirptr
   0 instance value dir-buf

   : get-dirblk  ( -- )
      dir-buf bsize  dir-blk @  bmap    ( adr len fs-blk# )
      read-fs-blocks                    ( )
      1 dir-blk +!
   ;

   2 constant rootino

   : +d  ( n -- adr ) dirptr @  +  ;

   : dir-ino    ( -- adr ) 0 +d  l@  ;
   : reclen     ( -- adr ) 4 +d  w@  ;
   : namelen    ( -- adr ) 6 +d  w@  ;
   : dir-name   ( -- adr ) 8 +d  ;
   : dir-name$  ( -- file$ ) dir-name namelen  ;


   \
   \	UFS high-level routines
   \
   \       After this point, the code should be independent of the disk format!

   0 instance value search-dir
   : init-dent
      0 totoff !  0 dir-blk !
      current-file to search-dir
   ;

   : get-dent ( -- end-of-dir? )
      begin
         totoff @  file-size >=  if
            true  exit
         then
         totoff @  blkoff  0=  if
            get-dirblk
            dir-buf dirptr !
         else
            reclen dirptr +!
         then
         reclen totoff +!
         dir-ino  0<>
      until  false
   ;

   : dirlook  ( file$ -- not-found? )
      init-dent
      begin  get-dent 0=  while      ( file$ )
         2dup  dir-name$  $=  if     ( file$ )
            dir-ino iget             ( file$ )
            2drop  false exit        ( found )
         then                        ( file$ )
      repeat  2drop true             ( not-found )
   ;

   h# 200 constant /fpath-buf
   /fpath-buf instance buffer: fpath-buf
   : clr-fpath-buf  ( -- )  fpath-buf /fpath-buf  erase  ;
   : fpath-buf$  ( -- path$ )  fpath-buf cscount  ;

   : follow-symlink  ( tail$ -- tail$' )
      clr-fpath-buf                                         ( tail$ )
      fpath-buf file-size  0 0  read-partial-block          ( tail$ )
      ?dup  if                                              ( tail$ )
	 " /" fpath-buf$  $append                           ( tail$ )
	 fpath-buf$  $append                                (  )
      else  drop  then                                      (  )
      fpath-buf$                                            ( path$ )
      over c@  ascii /  =  if                               ( path$ )
	 str++  rootino                                     ( path$' i# )
      else                                                  ( path$ )
	 search-dir                                         ( path$ i# )
      then                                                  ( path$ i# )
      iget                                                  ( path$ )
   ;

   : lookup  ( path$ -- not-found? )
      over c@  ascii /  =  if
         str++  rootino                           ( path$' i# )
      else
         current-file                             ( path$ i# )
      then                                        ( path$ i# )
      iget                                        ( path$ )
      begin                                       ( path$ )
         ascii / left-parse-string                ( path$ file$ )
      dup  while
         dir? 0=  if  2drop true  exit  then
         dirlook  if  2drop true  exit  then      ( path$ )
         symlink?  if
            follow-symlink                        ( path$' )
         then                                     ( path$ )
      repeat                                      ( path$ file$ )
      2drop 2drop  false                          ( succeeded )
   ;

   : i#>name ( i# -- name$ )
      init-dent                      ( i# )
      begin  get-dent 0=  while      ( i# )
         dup dir-ino  =  if          ( i# )
            drop dir-name$  exit     ( name$ )
         then                        ( i# )
      repeat  drop " ???"            ( name$ )
   ;


   \
   \	UFS installation routines
   \

   /max-bsize  4 *
   /super-block    +
   /inode          +
   constant alloc-size

   \ **** Allocate memory for necessary data structures
   : allocate-buffers  ( -- )
      alloc-size mem-alloc  dup 0=  if
         ." no memory"  abort
      then                                ( adr )
      dup to temp-block   /max-bsize   +  ( adr )
      dup to dir-buf      /max-bsize   +  ( adr )
      dup to indir0-adr   /max-bsize   +  ( adr )
      dup to indir1-adr   /max-bsize   +  ( adr )
      dup to super-block  /super-block +  ( adr )
          to inode                        (  )
   ;

   : release-buffers  ( -- )
      temp-block  alloc-size  mem-free
   ;

   \ UFS file interface

   struct
      /x     field >busy
      /x     field >offset
      /inode field >inode
   constant /file-record

   d# 10                  constant #opens
   #opens /file-record *  constant /file-records

   /file-records  instance buffer: file-records

   -1 instance value current-fd
   : fd>record  ( fd -- record )  /file-record *  file-records +  ;


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

   : init-fd  ( fd -- )
      fd>record                ( rec )
      dup  >busy  1 swap  x!
      dup  >inode  inode swap  /inode  move
      >offset  0 swap  x!
   ;

   : set-fd  ( fd -- error? )
      dup fd>record  dup >busy x@  0=  if   ( fd rec )
         2drop true  exit                   ( failed )
      then
      >inode to iptr                        ( fd )
      to current-fd  false                  ( succeeded )
   ;


   \ get current lblk# and offset within it
   : file-blk+off ( -- off block# )
      file-offset@ dup  blkoff  swap lblkno
   ;

   \ advance file io stack by n
   : fio+  ( # adr len n -- #+n adr+n len-n )
      dup file-offset@ +  file-offset!
      dup >r  -  -rot   ( len' # adr  r: n )
      r@  +  -rot       ( adr' len' #  r: n )
      r>  +  -rot       ( #' adr' len' )
   ;

   : (cwd)  ( i# -- )  tokenizer[ reveal ]tokenizer
      dup rootino  <>  if
         \ open parent, find current name
         " .." lookup  drop
         i#>name                ( name$ )
         \ recurse to print path components above
         current-file (cwd)     ( name$ )
         \ and print this component
         type                   (  )
      else  drop  then          (  )
      \ slash is both root name and separator
      ." /"
   ;

   external

   : open ( -- okay? )
      my-args dev-open  dup 0=  if       ( 0 )
         exit                            ( failed )
      then  to dev-ih

      allocate-buffers
      get-super-block
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
         2drop false  exit         ( failed )
      then  -rot                   ( fd path$ )

      lookup  if                   ( fd )
         drop false  exit          ( failed )
      then

      dup init-fd  true            ( fd succeeded )
   ;

   : close-file  ( fd -- )
      free-slot   (  )
   ;

   : size-file  ( fd -- size )
      set-fd  if  0  else  file-size  then
   ;

   : seek-file  ( off fd -- off true | false )
      set-fd  if                ( off )
         drop false  exit       ( failed )
      then                      ( off )

      dup file-size >  if       ( off )
         drop false  exit       ( failed )
      then                      ( off )
      dup  file-offset!  true   ( off succeeded )
   ;

   : read-file  ( adr len fd -- #read )
      set-fd  if                   ( adr len )
         2drop 0  exit             ( 0 )
      then                         ( adr len )

      regular? 0=  if  2drop 0  exit  then

      \ adjust len if reading past eof
      dup  file-offset@ +  file-size  >  if
         dup  file-offset@ +  file-size -  -
      then
      dup 0=  if  nip exit  then

      0 -rot                              ( #read adr len )

      \ initial partial block
      file-offset@ blkoff  ?dup  if       ( #read adr len off )
         bsize swap -  over  min          ( #read adr len len' )
         3dup nip  file-blk+off           ( #read adr len len' adr len' off lblk# )
         read-partial-block               ( #read adr len len )
         fio+                             ( #read' adr' len' )
      then                                ( #read adr len )

      dup lblkno  0  ?do                  ( #read adr len )
         over  file-blk+off nip           ( #read adr len adr lblk# )
         read-one-block                   ( #read adr len )
         bsize fio+                       ( #read' adr' len' )
      loop                                ( #read adr len )

      \ final partial block
      dup  if                             ( #read adr len )
         2dup  file-blk+off               ( #read adr len adr len off lblk# )
         read-partial-block               ( #read adr len )
         dup fio+                         ( #read' adr' 0 )
      then  2drop                         ( #read )
   ;

   : cinfo-file  ( fd -- bsize fsize comp? )
      set-fd  if  0 0 0  else  bsize file-size comp?  then
   ;

   \ read ramdisk fcode at rd-offset
   : get-rd   ( adr len -- )
      rd-offset dev-ih  read-disk
   ;

   \ no additional props needed for ufs
   : bootprop  ( -- )  false  ;

   \ debug words
   headers

   : chdir  ( dir$ -- )
      current-file -rot            ( i# dir$ )
      lookup  if                   ( i# )
         to current-file           (  )
         ." no such dir" cr  exit
      then                         ( i# )
      dir? 0=  if                  ( i# )
         to current-file           (  )
         ." not a dir" cr  exit
      then  drop                   (  )
   ;

   : dir  ( -- )
      current-file iget
      init-dent
      begin  get-dent 0=  while
         dir-name$ type  cr
      repeat
   ;

   : cwd  ( -- )
      current-file        ( i# )
      dup (cwd)  cr       ( i# )
      iget                (  )
   ;

finish-device
pop-package
