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
purpose: boot block for OBP systems
copyright: Copyright 2007 Sun Microsystems, Inc. All Rights Reserved


headerless
d# 1024 dup  *     constant  1meg
d# 4  1meg   *     constant  4meg
d# 32 1meg   *     constant  32meg

headers
" /"  get-package  constant  root-ph

0                  value     fs-ih
false              value     nested?
0                  value     file-sz

/buf-len  buffer:  boot-dev
: boot-dev$  ( -- dev$ )  boot-dev cscount  ;

: loader-base  ( -- base )
   nested?  if
      h# 5000.0000
   else
      h# 5100.0000
   then
;


\
\ methods we expect of fs reader packages
\
headerless
: fs-open  ( file$ -- fd true | false )
   " open-file" fs-ih $call-method
;

: fs-close  ( fd -- )
   " close-file" fs-ih $call-method
;

: fs-size  ( fd -- size )
   " size-file" fs-ih $call-method
;

: fs-read  ( adr len fd -- #read )
   " read-file" fs-ih $call-method
;

: fs-getrd  ( adr len -- )
   " get-rd" fs-ih $call-method
;

: fs-bootprop  ( -- propval propname true  |  false )
   " bootprop" fs-ih $call-method
;
headers


\ zfs bootblks with all headers exceeds 7.5k
\ 'bigbootblk' allows us to load the fs reader from elsewhere
[ifdef] bigbootblk

: load-pkg  ( -- )
   boot-dev$  2dup dev-open  ?dup 0=  if  ( dev$ )
      open-abort
   then  >r 2drop                         ( r: ih )
   /fs-fcode  mem-alloc                   ( adr  r: ih )
   dup  /fs-fcode fs-offset r@  read-disk
   dup  1 byte-load
   /fs-fcode  mem-free                    ( r: ih )
   r>  dev-close
;

[else]

: load-pkg  ( -- )  ;

[then]


: get-bootdev  ( -- )
   \ first try boot archive (nested boot from ramdisk)
   \ then try boot device (direct boot from disk)
   " bootarchive" chosen-ph  get-package-property  if
      " bootpath" chosen-ph  get-string-prop            ( bootpath$ )
   else                                                 ( archiveprop$ )
      decode-string  2swap 2drop                        ( archivepath$ )
      true to nested?
   then                                                 ( bootpath$ )
   boot-dev swap  move                                  (  )
;

: mount-root  ( -- )
   boot-dev$ fs-pkg$  $open-package to fs-ih
   fs-ih 0=  if
      ." Can't mount root" abort
   then
;

\
\ cheap entertainment for those watching
\ boot progress
\
headerless
create spin-data
   ascii | c,  ascii / c,  ascii - c,  ascii \ c,

0 instance variable spindex

: spinner ( -- )
   spindex @  3 and  spin-data +   ( c-adr )
   c@ emit  (cr
   1 spindex +!
;

: spin-on   ( -- )  ['] spinner  d# 1000  alarm  ;
: spin-off  ( -- )  ['] spinner        0  alarm  ;

headers
\ allocate and return physical allocation size
: vmem-alloc-prop  ( size virt -- alloc-size virt )
   2dup  ['] vmem-alloc  catch  if            ( size virt ??? ??? )
      2drop                                   ( size virt )
      2dup  begin                             ( size virt len adr )
         over 32meg  min  >r                  ( size virt len adr  r: alloc-sz )
         r@ over  vmem-alloc                  ( size virt len adr adr  r: alloc-sz )
         nip  r@ +                            ( size virt len adr'  r: alloc-sz )
         swap r> -                            ( size virt adr len' )
         swap over  0=                        ( size virt len adr done? )
      until                                   ( size virt len adr )
      2drop nip  32meg                        ( virt 32meg )
   else                                       ( size virt virt )
      nip nip  0                              ( virt 0 )
   then                                       ( virt alloc-sz )
   swap
;

\ read in file and return buffer
\ if base==0, vmem-alloc will allocate virt
: get-file ( base fd -- [ virt size ] failed? )
   dup >r  fs-size                         ( base size  r: fd )
   dup rot  vmem-alloc-prop                ( size alloc-sz virt  r: fd )
   rot  2dup tuck  r>                      ( alloc-sz virt size size virt size fd )
   spin-on  fs-read  spin-off              ( alloc-sz virt size size size-rd )
   <>  if                                  ( alloc-sz virt size )
      3drop true  exit                     ( failed )
   then
   false                                   ( alloc-sz virt size succeeded )
;


false value is-elf?
false value is-archive?

: check-elf ( base -- is-elf? )
   l@  h# 7f454c46 ( \x7fELF )  =
;

: check-fcode ( base -- is-fcode? )
   c@ dup  h# f0 h# f3 between  swap h# fd =  or
;

: >bootblk  ( adr -- adr' )  d# 512 +  ;

\ figure out what we just loaded
: get-type  ( adr -- )
   dup check-elf to is-elf?

   \ if not nested, check for boot archive (executable after label)
   nested? invert  if
      >bootblk
      dup check-fcode           ( adr is-fcode? )
      over check-elf            ( adr is-fcode? is-elf? )
      or  to is-archive?
   then
   drop
;


\
\	file name routines
\

\ boot file (-F name or boot archive)
false     value    fflag?
/buf-len  buffer:  boot-file
: boot-file$  ( -- file$ )  boot-file cscount  ;

\ kernel name (final name or unix)
false     value    kern?
/buf-len  buffer:  kern-file
: kern-file$  ( -- file$ )  kern-file cscount  ;

\ platform name
/buf-len  buffer:  plat-name
: plat-name$  ( -- plat$ )  plat-name cscount  ;

\ arch name
/buf-len  buffer:  arch-name
: arch-name$  ( -- arch$ )  arch-name cscount  ;

\ final name after /platform massaging
/buf-len  buffer:  targ-file
: targ-file$  ( -- file$ )  targ-file cscount  ;

: init-targ  ( -- )
   targ-file /buf-len erase
   " /platform/"  targ-file swap  move
;

\ remove illegal file name chars (e.g., '/')
: munge-name ( name$ -- name$' )
   2dup                           ( name$ name$ )
   begin  dup  while
      over c@  ascii /  =  if
         over  ascii _  swap  c!  ( name$ name$' )
      then  str++
   repeat  2drop                  ( name$ )
;

\ if the platform exists in the FS, use it
\ else use a default (e.g., sun4v)
: get-arch  ( -- )
   " device_type"  root-ph  get-package-property  if
      \ some older sunfires don't have device_type set
      false                             ( sun4u )
   else                                 ( devtype-prop$ )
      decode-string  2swap 2drop        ( devtype$ )
      " sun4v" $=                       ( sun4v? )
   then                                 ( sun4v? )
   if  " sun4v"  else  " sun4u"  then   ( arch$ )
   arch-name swap  move
   " name"  root-ph  get-string-prop    ( name$ )
   munge-name                           ( name$' )
   init-targ  2dup targ-file$  $append
   targ-file$ fs-open  if               ( name$ fd )
      fs-close                          ( name$ )
   else                                 ( name$ )
      2drop  arch-name$                 ( default$ )
   then                                 ( name$ )
   plat-name swap  move                 (  )
;

\ make <pre> <file> into /platform/<pre>/<file>
: $plat-prepend  ( file$ pre$ -- file$' )
   init-targ
   targ-file$  $append                 ( file$ )
   " /" targ-file$  $append
   targ-file$  $append                 (  )
   targ-file$                          ( new$ )
;

: get-boot  ( -- file$ )
   fflag?  if
      boot-file$
   else
      " boot_archive"
   then
;

: get-kern  ( -- file$ )
   kern?  if
      kern-file$
   else
      " kernel/sparcv9/unix"
   then
;

\ if we're nested, load the kernel, else load the bootarchive
: get-targ  ( -- file$ )
   nested?  if
      get-kern
   else
      get-boot
   then
;


: try-file  ( file$ -- [ fd ] error? )
   diagnostic-mode?  if
      2dup ." Loading: " type cr
   then
   fs-open  invert         ( fd false | true )
;

\  try "/platform/<plat-name>/<file>"  e.g., SUNW,Sun-Blade-1000
\  then "/platform/<arch-name>/<file>"  e.g., sun4u
: open-path  ( file$ - fd )
   over c@ ascii /  <>  if
      2dup  plat-name$  $plat-prepend      ( file$ file$' )
      try-file  if                         ( file$ )
         2dup  arch-name$  $plat-prepend   ( file$ file$' )
         try-file  if                      ( file$ )
           open-abort
         then                              ( file$ fd )
      then                                 ( file$ fd )
   else                                    ( file$ )
      \ copy to targ-file for 'whoami' prop
      targ-file /buf-len  erase
      2dup targ-file swap  move
      2dup  try-file  if                   ( file$ )
        open-abort
      then                                 ( file$ fd )
   then                                    ( file$ fd )
   -rot 2drop                              ( fd )
;


\ ZFS support
\ -Z fsname  opens specified filesystem in disk pool

false     value    zflag?
/buf-len  buffer:  fs-name
: fs-name$  ( -- fs$ )  fs-name cscount  ;

[ifdef] zfs

: open-zfs-fs  ( fs$ -- )
   2dup  " open-fs" fs-ih $call-method  0=  if
      open-abort
   then
   2drop                     (  )
;

[else]

: open-zfs-fs ( fs$ -- )
   ." -Z not supported on non-zfs root"  abort
;

[then]


\
\	arg parsing
\

headerless
: printable?  ( n -- flag ) \ true if n is a printable ascii character
   dup bl th 7f within  swap  th 80  th ff  between  or
;
: white-space? ( n -- flag ) \ true is n is non-printable? or a blank
   dup printable? 0=  swap  bl =  or
;

: skip-blanks  ( adr len -- adr' len' )
   begin  dup  while   ( adr' len' )
      over c@  white-space? 0=  if  exit  then
      str++
   repeat
;

: skip-non-blanks  ( adr len -- adr' len' )
   begin  dup  while   ( adr' len' )
      over c@  white-space?  if  exit  then
      str++
   repeat
;

headers
\ left-parse-string w/ any white space as delimeter
: next-str  ( adr len -- adr' len' s-adr s-len )
   2dup  skip-non-blanks       ( s-adr len adr' len' )
   dup >r  2swap  r> -         ( adr' len' s-adr s-len )
;

: next-c  ( adr len -- adr' len' c )
   over c@ >r  str++  r>
;

false value halt?

: parse-bootargs  ( -- )
   " bootargs" chosen-ph  get-string-prop  ( arg$ )

   \ check for explicit kernel name
   skip-blanks  dup  if
      over c@  ascii -  <>  if
         next-str                          ( arg$ kern$ )
         \ use default kernel if user specific a debugger
         2dup  " kadb"  $=  >r             ( arg$ kern$  r: kadb? )
         2dup  " kmdb"  $=  r>  or         ( arg$ kern$ debugger? )
         invert  if                        ( arg$ kern$ )
            kern-file swap  move           ( arg$ )
            true to kern?
         else  2drop  then                 ( arg$ )
      then
   then

   \ process args
   begin
      skip-blanks  dup                     ( arg$ len )
   while
      next-c  ascii -  =  if
         next-c  case
            ascii D  of
               \ for "boot kadb -D kernel.foo/unix"
               skip-blanks  next-str       ( arg$ file$ )
               kern? invert  if
                  ?dup  if
                     kern-file swap  move  ( arg$ )
                     true to kern?
                  else  drop  then         ( arg$ )
               else  2drop  then           ( arg$ )
            endof
            ascii F  of
               skip-blanks  next-str       ( arg$ file$ )
               ?dup  if
                  boot-file swap  move     ( arg$ )
                  true to fflag?
               else  drop  then            ( arg$ )
            endof
            ascii H  of
               true to halt?
            endof
            ascii Z  of
               skip-blanks  next-str       ( arg$ fs-name$ )
               ?dup  if
                  fs-name swap  move       ( arg$ )
                  true to zflag?
               else  drop  then            ( arg$ )
            endof
         endcase
      then
   repeat
   2drop                                   (  )
;


0 value rd-alloc-sz

: "ramdisk"  ( -- dev$ )  " /ramdisk-root"  ;

: setup-bootprops  ( -- )
   chosen-ph  push-package

   nested? invert  if
      fs-type$ encode-string    " fstype"             property
      fs-ih encode-int          " bootfs"             property
      fs-bootprop  if  property  then
   else
      fs-type$ encode-string    " archive-fstype"     property
      fs-ih encode-int          " archfs"             property
   then

   is-archive?  if
      "ramdisk" encode-string   " bootarchive"        property
   else
      loader-base encode-int    " elfheader-address"  property
      file-sz encode-int        " elfheader-length"   property
      plat-name$ encode-string  " impl-arch-name"     property
      targ-file$ encode-string  " whoami"             property
      fs-pkg$ encode-string     " fs-package"         property
   then

   pop-package
;


\ load ramdisk fcode and tell the driver where
\ we put the ramdisk data
: setup-ramdisk  ( base size -- )
   /rd-fcode mem-alloc                ( base size adr )
   dup /rd-fcode  fs-getrd

   root-ph  push-package
   new-device
      "ramdisk" str++  device-name
      dup 1  byte-load
   finish-device
   pop-package
   
   /rd-fcode mem-free              ( base size )

   "ramdisk"  dev-open  dup 0=  if
      "ramdisk" open-abort
   then  >r                        ( base size  r: ih )
   rd-alloc-sz                     ( base size alloc-sz  r: ih )
   " create"  r@ $call-method      ( r: ih )
   r> dev-close                    (  )
;


\
\	ELF parsing
\

0 value elfhdr
0 value phdr

: +elfhdr	( index -- value )  elfhdr swap ca+ ;
: e_machine     ( -- n )  h# 12 +elfhdr w@ ;
: e_entry	( -- n )  h# 18 +elfhdr x@ ;
: e_phoff	( -- n )  h# 20 +elfhdr x@ ;
: e_phentsize	( -- n )  h# 36 +elfhdr w@ ;
: e_phnum	( -- n )  h# 38 +elfhdr w@ ;

1 constant pt_load
: +phdr		( index -- value )  phdr swap ca+ ;
: p_type	( -- n )  h#  0 +phdr l@ ;
: p_vaddr	( -- n )  h# 10 +phdr x@ ;
: p_memsz	( -- n )  h# 28 +phdr x@ ;

: get-phdr ( filebase index -- phdr )
   e_phentsize *  e_phoff +  +    ( phdr )
;

\ alloc 4MB pages for kernel text/data
: vmem-alloc-4mb  ( size virt -- base )
   swap  4meg roundup  swap
   4meg (mem-alloc)
;

\ OBP doesn't allocate memory for elf
\ programs, it assumes they'll fit
\ under the default 10MB limit
: fix-elf-mem  ( base -- )
   dup to elfhdr
   e_machine  d# 43  <>  if  drop exit  then       \ 64b only

   e_phnum 0  ?do
      dup i get-phdr  to phdr
      p_type pt_load =  p_vaddr h# a0.0000 >  and  if
         \ allocate 4MB segs for text & data
         p_vaddr  4meg 1-  and  if
            p_memsz p_vaddr  vmem-alloc  drop
         else
            p_memsz p_vaddr  vmem-alloc-4mb  drop
         then
      then
   loop  drop                   (  )
;


: load-file  ( -- virt )
   get-arch
   get-targ  open-path              ( fd )
   loader-base over  get-file  if   ( fd alloc-sz virt size )
      ." Boot load failed" abort
   then
   to file-sz                       ( fd alloc-sz virt )
   swap  to rd-alloc-sz             ( fd virt )
   swap  fs-close                   ( virt )
;

: setup-props  ( virt -- virt )
   dup get-type
   setup-bootprops
   is-archive?  if
      dup file-sz  setup-ramdisk
   then
;

: exec-file  ( virt -- )
   is-elf?  if
      dup  fix-elf-mem
   then
   is-archive?  if  >bootblk  then          ( virt' )
   " to load-base init-program"  evaluate
;

: do-boot ( -- )
   parse-bootargs
   halt?  if
      ." Halted with -H flag. " cr
      exit
   then
   get-bootdev
   load-pkg
   mount-root
   zflag?  nested? invert  and  if
      fs-name$  open-zfs-fs
   then
   load-file                        ( virt )
   setup-props
   exec-file                        (  )
;

\ Tadpole proms don't initialize my-self
0 to my-self

do-boot
