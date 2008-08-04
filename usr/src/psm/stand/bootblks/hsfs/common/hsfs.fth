
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
purpose: HSFS file system support package for NewBoot
copyright: Copyright 2006 Sun Microsystems, Inc. All Rights Reserved

\ High Sierra, Rock Ridge (CD-ROM) file system reader and boot block

headers
" /packages" get-package  push-package

new-device
   fs-pkg$  device-name  diag-cr?

   \
   \	HSFS variables
   \
   0 instance value dev-ih
   0 instance value vol-desc
   0 instance value dir-buf
   0 instance value sua-buf
   0 instance value ce-buf

   \
   \	HSFS volume descriptor routines
   \

   \ unaligned load of 2-byte item
   : xw@  ( adr -- n )
      dup c@ swap char+   ( c0 adr+1 )
      c@                  ( c0 c1 )
      bwjoin
   ;

   \ unaligned store of 2-byte item
   : xw!  ( n adr -- )
      swap wbsplit swap 2 pick c! swap char+ c!
   ;

   \ unaligned load of 4-byte item
   : xl@  ( adr -- n )
      dup xw@ swap wa1+   ( w0 adr+2 )
      xw@                 ( w0 w1 )
      wljoin
   ;
   \ unaligned store of 4-byte item
   : xl!  ( n adr -- )
      swap lwsplit swap 2 pick xw! swap wa1+ xw!
   ;

   d# 2048 constant /sector
   d# 16 constant vol-desc-sector#  ( -- n )

   : +vd  ( index -- adr )
      vol-desc 0= if
         ." invalid access of +vd" cr abort
      then
      vol-desc +
   ;

   : root-dir  ( -- n )  d# 156 +vd  ;
   : /block    ( -- n )  d# 128 +vd xw@  ;
   : byte>blkoff  ( byte-off -- block-off )  /block mod  ;

   : get-vol-desc  ( -- )
      vol-desc  /sector  vol-desc-sector# /sector *  dev-ih  read-disk
   ;

   : read-fs-blocks  ( adr len fs-blk# -- )  /block *  dev-ih  read-disk  ;

   \
   \	HSFS directory routines
   \

   \ Current directory variables.
   instance variable cdir-blk		\ Current directory device block ptr.
   instance variable cdir-blk0          \ Current directory block0.
   instance variable cdir-offset	\ Current directory logical offset.
   instance variable cdir-size		\ Current directory logical size.
   instance variable cdir-ptr		\ Current directory entry pointer.
   false instance value cdir-rescan     \ Rescan current directory for symlink.

   \ Access of current directory entry.
   : +dr  ( n -- adr )  cdir-ptr @ +  ;

   : dir-entrylen    ( -- n )    d# 0  +dr c@  ;
   : dir-block0      ( -- n )    d# 2  +dr xl@  ;
   : dir-filesize    ( -- n )    d# 10 +dr xl@  ;
   : dir-flags       ( -- n )    d# 25 +dr c@  ;
   : dir-filenamelen ( -- n )    d# 32 +dr c@  ;
   : dir-filename    ( -- adr )  d# 33 +dr  ;

   : dir-isdir?      ( -- flag )  dir-flags  h# 02  and  0<>  ;
   : dir-file$       ( -- adr len )  dir-filename  dir-filenamelen  ;
   : dir-sualen      ( -- len )  dir-entrylen  d# 33 -  dir-filenamelen -  ;

   \ ISO name, including dot & dot-dot check
   : dir-iso$        ( -- adr len )
      dir-filenamelen 1  =  if
         dir-filename c@             ( name[0] )
         dup 0=  if
            drop " ."  exit          ( dot )
         then
         1 =  if                     (  )
            " .."  exit              ( dot-dot )
         then
      then
      dir-file$                      ( name$ )
   ;

   false instance value symlink?

   : get-dirblk  ( -- )
      dir-buf /block  cdir-blk @  read-fs-blocks
      1 cdir-blk +!
   ;

   : froot  ( -- )  root-dir cdir-ptr !  ;

   \
   \ SUAs - System Use Area in directory entry (Rock Ridge
   \  Extensions to High Sierra/ISO 9660 Format).
   \  Immediately follows directory entry name rounded up to
   \  a half-word boundary.
   \
   0 instance value sua-ptr
   0 instance value sua-len

   : +suf           ( n -- adr )    sua-ptr +  ;
   : suf-sig        ( -- adr len )  sua-ptr 2  ;
   : suf-len        ( -- len )      2 +suf c@  ;
   : suf-dat        ( -- data )     5 +suf  ;
   : suf-ce-lbn     ( -- lbn )      4 +suf xl@ ;
   : suf-ce-offset  ( -- offset )   d# 12 +suf xl@ ;
   : suf-ce-len     ( -- len )      d# 20 +suf xl@ ;

   : init-sua     ( -- )
      dir-file$ +  /w roundup  to sua-ptr
      dir-sualen               to sua-len
   ;

   : next-suf  ( -- )
      sua-len suf-len -  to sua-len
      suf-len +suf       to sua-ptr
   ;

   : end-sua  ( -- end? )
      sua-len 4 <
   ;

   : suf-nm$  ( -- adr len )  suf-dat  suf-len 5 -  ;

   \ Continuation suffix handling.  When a 'CE' suffix is seen,
   \ record the CE parameters (logical block#, offset and length
   \ of continuation).  We process the CE continuation only after
   \ we've finished processing the current SUA area.
   instance variable ce-lbn
   instance variable ce-offset
   instance variable ce-len
   : suf-ce-set  ( -- )
      suf-ce-lbn ce-lbn !
      suf-ce-offset ce-offset !
      suf-ce-len ce-len !
   ;
      
   : suf-ce-process  ( -- error? )
      ce-lbn @ 0= if
         true
      else
         sua-buf ce-len @ ce-lbn @  read-fs-blocks
         sua-buf   to sua-ptr
         ce-len @  to sua-len
         0 ce-len ! 0 ce-lbn ! 0 ce-offset !
         false
      then
   ;

   /buf-len  instance buffer: suf-sl-buf
   false     instance value   symlink-need-sep

   \ Format of Rock Ridge symlinks needs to be munged to unix-style
   \ name.  Format is:  <flag><nbytes>file-name<flag><nbytes>filename...
   \ where \ <flag> is flag byte (0=filename, 2=current dir, 4=parent
   \ dir, 8=root dir) and <nbytes> is one-byte byte count (zero for
   \ !filename).
   : suf-copy-to-symlinkbuf  ( name$  -- )
       false to symlink-need-sep
       suf-sl-buf -rot bounds do           ( dst )
          symlink-need-sep if
             ascii / over c! char+
          then
          true to symlink-need-sep
          i c@ dup 2 = if                   ( dst 2 )
             \ CURRENT (".")
             drop ascii . over c! char+ 2   ( dst' inc )
          else  dup 4 =  if                 ( dst 4 )
             \ PARENT ("..")
             drop " .." 2 pick swap move    ( dst )
             wa1+ 2                         ( dst' inc )
          else  dup 8 =  if                 ( dst 8 )
             \ ROOT ("/")
             drop ascii / over c! char+ 2   ( dst' inc )
             false to symlink-need-sep
          else  dup 0<> if
             ." unknown SL flag: " .x cr abort
          else                              ( dst c )
             drop                           ( dst )
             i char+ dup c@ >r              ( dst src+1  R:nbytes )
             char+ over r@ move             ( dst R:nbytes )
             r@ +                           ( dst' R:nbytes )
             r> wa1+                        ( dst' inc )
          then then then then
       +loop                                ( dst )
       0 swap c!
    ; 

   \ Saved 'NM' prefix buffer.
   /buf-len  instance buffer: suf-nm-buf
   0 instance value suf-nm-size
      
   \ Return the Rock Ridge file name associated with the current
   \ dirent ('NM' suffix).  Otherwise returns standard iso filename.
   \ Marks whether returned filename is a symbolic link ('SL' suffix)
   \ and also processes continuations ('CE' suffix).
   : rr-file$ ( -- adr len )
      false to symlink?
      0 to suf-nm-size

      \ select start of sua, record sua offset
      init-sua
      begin
         end-sua  if
            suf-ce-process if
               suf-nm-size if
                  suf-nm-buf suf-nm-size       ( NM$ )
               else
                  dir-iso$                     ( iso$ )
               then                            ( file$ )
               exit
            then
         then
         suf-sig                               ( sig-adr sig-len )
         2dup " NM"  $=  if
            suf-nm$ to suf-nm-size             ( sig-adr sig-len suf-nm-adr )
            suf-nm-buf suf-nm-size move
         then                                  ( sig-adr sig-len )
         2dup " SL"  $=  if
            true to symlink?
            suf-nm$ suf-copy-to-symlinkbuf
         then
         2dup " CE"  $=  if
            suf-ce-set
         then                                  ( sig-adr sig-len )
         2drop  next-suf                       (  )
      again
   ;

   \
   \	HSFS high-level routines
   \

   \ Used for rescanning current directory for symbolic links.

   \ Initializes current directory settings from current directory
   \ entry pointer or for rescan.  If it's not a rescan, we have
   \ access to the actual directory entry, so we can check whether
   \ it's a directory or not here.
   : init-dent  ( -- error? )
      cdir-rescan if
         false to cdir-rescan
         cdir-blk0 @ cdir-blk !
      else
         dir-isdir? 0= if
            true exit
         then
         dir-block0 dup cdir-blk ! cdir-blk0 !
         dir-filesize cdir-size !
      then                                    ( blk0 size )
      0 cdir-offset !
      false
   ;

   : get-dent ( -- error? )
      begin
         \ Check for end of directory, return true if we're past the EOF.
         cdir-offset @  cdir-size @  >=  if
            true  exit
         then

         \ If we're at a block boundary, get the next block.  Otherwise
         \ increment the directory pointer.
         cdir-offset @ byte>blkoff  0=  if
            get-dirblk
            dir-buf cdir-ptr !
         else
            dir-entrylen cdir-ptr +!
         then

         \ If dir-entrylen is not zero, increment the current directory
         \ file offset.  Otherwise, a dir-entrylen of zero indicates
         \ the end of a dir block, so round up cdir-offset to fetch the
         \ next one
         dir-entrylen ?dup if
            cdir-offset +!  true
         else
            cdir-offset @  /block  roundup  cdir-offset !
            false
         then
      until  false
   ;

   \ Look through current directory for file name 'file$'.
   \ Will leave current directory entry (cdir-ptr) pointing
   \ to matched entry on success.
   : dirlook  ( file$ -- error? )
      init-dent if
         true exit
      then
      begin  get-dent 0=  while      ( file$ )
         2dup rr-file$ $=  if        ( file$ )
            2drop false  exit        ( succeeded )
         then                        ( file$ )
      repeat 2drop true              ( failed )
   ;

   /buf-len  instance buffer: symlink-buf
   : symlink-buf$  ( -- path$ )  symlink-buf cscount  ;

   : follow-symlink  ( tail$ -- tail$' )

      \ copy symlink value (plus null) to buf
      suf-sl-buf cscount 1+  symlink-buf swap  move
      false to symlink?

      \ append to current path
      ?dup  if                                              ( tail$ )
	 " /" symlink-buf$  $append                         ( tail$ )
	 symlink-buf$  $append                              (  )
      else  drop  then                                      (  )
      symlink-buf$                                          ( path$ )
      over c@  ascii /  =  if                               ( path$ )
	 froot  str++                                       ( path$' )
      else
         true to cdir-rescan
      then                                                  ( path$ )
   ;

   : lookup  ( path$ -- error? )
      over c@  ascii /  =  if
	 froot  str++                            ( path$' )
      then                                       ( path$ )
      begin                                      ( path$ )
         ascii / left-parse-string               ( path$ file$ )
      dup  while                                 ( path$ file$ )
         dirlook  if
            2drop true  exit                     ( failed )
         then                                    ( path$ )
         symlink?  if
            follow-symlink                       ( path$' )
         then                                    ( path$ )
      repeat                                     ( path$ file$ )
      2drop 2drop  false                         ( succeeded )
   ;


   \
   \	HSFS installation routines
   \

   \ Allocate memory for necessary data structures.  Need to
   \ read volume desriptor sector in order to get /block value.
   : initialize  ( -- error? )
      /sector  mem-alloc to vol-desc
      get-vol-desc
      /block   mem-alloc to dir-buf
      /block   mem-alloc to sua-buf
      /block   mem-alloc to ce-buf
   ;

   : release-buffers  ( -- )
      ce-buf      /block  mem-free
      sua-buf	  /block  mem-free
      dir-buf     /block  mem-free
      vol-desc    /sector mem-free
      0 to vol-desc
   ;


   \ HSFS file interface
   struct
      /x     field >filesize
      /x     field >offset
      /x     field >block0
   constant /file-record

   d# 10                  constant #opens
   #opens /file-record *  constant /file-records

   /file-records  instance buffer: file-records

   -1 instance value current-fd

   : fd>record  ( fd -- record )  /file-record *  file-records +  ;

   : set-fd  ( fd -- error? )
      dup 0 #opens 1 - between 0= if
         drop true exit
      then
      dup fd>record  >block0 x@ 0= if
         drop true exit
      then
      to current-fd false
   ;

   : file-offset@  ( -- off )
      current-fd fd>record >offset x@
   ;

   : file-offset!  ( off -- )
      current-fd fd>record >offset x!
   ;

   : file-size@  ( -- size )
      current-fd fd>record >filesize x@
   ;

   : file-size!  ( size -- )
      current-fd fd>record >filesize x!
   ;

   : file-block0@  ( -- block0 )
      current-fd fd>record >block0 x@
   ;

   : file-block0!  ( block0 -- )
      current-fd fd>record >block0 x!
   ;

   : get-slot  ( -- fd false | true )
      #opens 0  do
         i fd>record >block0 x@  0=  if
            i false  unloop exit
         then
      loop  true
   ;

   : free-slot  ( fd -- )
      set-fd 0= if
         0 file-offset!
         0 file-size!
         0 file-block0!
      then
   ;

   \ initializes the open structure with information from
   \ the inode (on UFS) or directory entry (from HSFS).
   : init-fd  ( fd -- )
      to current-fd
      dir-block0 file-block0!
      dir-filesize file-size!
      0 file-offset!
   ;

   external

   : open ( -- okay? )
      my-args dev-open  dup 0=  if       ( 0 )
         exit                            ( failed )
      then  to dev-ih

      initialize  froot
      file-records /file-records  erase
      true                               ( succeeded )
   ;

   : close  ( -- )
      dev-ih dev-close
      release-buffers
   ;

   : open-file  ( path$ -- fd true | false )
      get-slot  if
	 2drop false  exit            ( failed )
      then  -rot                      ( fd path$ )

      lookup  if                      ( fd )
	 drop false  exit             ( failed )
      then

      dup init-fd true                ( fd success )
   ;

   : close-file  ( fd -- )
      free-slot   (  )
   ;

   : read-file   ( adr len fd -- #read )

      \ Check if fd is valid, if it is set current-fd.
      set-fd if
         2drop 0 exit
      then                                   ( adr len )

      \ Adjust len if less than len bytes remain.
      file-size@ file-offset@ - min          ( adr len' )

      \ Check for invalid length read.
      dup 0<=  if  2drop 0 exit  then

      \ Compute physical device byte offset.
      tuck                                   ( len adr len )
      file-block0@ /block * file-offset@ +   ( len adr len off )
      dev-ih read-disk                       ( #read )
   ;

   : seek-file  ( off fd -- error? )
      set-fd  if                ( off )
         drop false  exit       ( failed )
      then                      ( off )

      dup file-size@ >  if      ( off )
         drop false  exit       ( failed )
      then                      ( off )
      dup  file-offset!  true   ( off succeeded )
   ;

   : size-file  ( fd -- size )
      set-fd if
         0
      else
         file-size@
      then
   ;

   \ we don't support compression (yet)
   : cinfo-file  ( fd -- bsize fsize comp? )
      set-fd  if  0 0 0  else  /block file-size@ 0  then
   ;

   \ read ramdisk fcode at rd-offset
   : get-rd   ( adr len -- )
      rd-offset dev-ih  read-disk
   ;

   \ no additional props needed for hsfs
   : bootprop  ( -- )  false  ;

   \ debug words
   : chdir  ( path$ -- )
      2dup lookup if
         type ."  Not found" cr
      else
         dir-isdir? 0= if
            type ."  Not a directory" cr
         else
            type
	    ."  blk0 "
            cdir-blk0 @ .x
            ."  size "
            cdir-size @ .x
            cr
         then
      then
   ;

   : dir  ( -- )
      init-dent
      begin  get-dent 0=  while
         rr-file$ type
         ."  flags " dir-flags .x
         ." blk0 " dir-block0 .x
         ." size " dir-filesize .x
         cr
      repeat
      true to cdir-rescan
   ;
      

finish-device
pop-package

