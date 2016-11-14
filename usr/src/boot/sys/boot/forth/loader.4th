\ Copyright (c) 1999 Daniel C. Sobral <dcs@FreeBSD.org>
\ Copyright (c) 2011-2015 Devin Teske <dteske@FreeBSD.org>
\ All rights reserved.
\
\ Redistribution and use in source and binary forms, with or without
\ modification, are permitted provided that the following conditions
\ are met:
\ 1. Redistributions of source code must retain the above copyright
\    notice, this list of conditions and the following disclaimer.
\ 2. Redistributions in binary form must reproduce the above copyright
\    notice, this list of conditions and the following disclaimer in the
\    documentation and/or other materials provided with the distribution.
\
\ THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
\ ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
\ IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
\ ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
\ FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
\ DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
\ OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
\ HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
\ LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
\ OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
\ SUCH DAMAGE.
\
\ $FreeBSD$

only forth definitions

s" arch-i386" environment? [if] [if]
	s" loader_version" environment?  [if]
		11 < [if]
			.( Loader version 1.1+ required) cr
			abort
		[then]
	[else]
		.( Could not get loader version!) cr
		abort
	[then]
[then] [then]

include /boot/forth/support.4th
include /boot/forth/color.4th
include /boot/forth/delay.4th
include /boot/forth/check-password.4th

only forth definitions

: bootmsg ( -- )
  loader_color? dup ( -- bool bool )
  if 7 fg 4 bg then
  ." Booting..."
  if me then
  cr
;

: try-menu-unset
  \ menu-unset may not be present
  s" beastie_disable" getenv
  dup -1 <> if
    s" YES" compare-insensitive 0= if
      exit
    then
  else
    drop
  then
  s" menu-unset"
  sfind if
    execute
  else
    drop
  then
  s" menusets-unset"
  sfind if
    execute
  else
    drop
  then
;

only forth also support-functions also builtins definitions

\ the boot-args was parsed to individual options while loaded
\ now compose boot-args, so the boot can set kernel arguments
\ note the command line switched for boot command will cause
\ environment variable boot-args to be ignored
\ There are 2 larger strings, acpi-user-options and existing boot-args
\ other switches are 1 byte each, so allocate boot-args+acpi + extra bytes
\ for rest. Be sure to review this, if more options are to be added into
\ environment.

: set-boot-args { | addr len baddr blen aaddr alen -- }
  s" boot-args" getenv dup -1 <> if
    to blen to baddr
  else
    drop
  then
  s" acpi-user-options" getenv dup -1 <> if
    to alen to aaddr
  else
    drop
  then

  \ allocate temporary space. max is:
  \  7 kernel switches
  \  26 for acpi, so use 40 for safety
  blen alen 40 + + allocate abort" out of memory"
  to addr
  \ boot-addr may have file name before options, copy it to addr
  baddr 0<> if
    baddr c@ [char] - <> if
      baddr blen [char] - strchr		( addr len )
      dup 0= if				\ no options, copy all
        2drop
        baddr addr blen move
        blen to len
        0 to blen
        0 to baddr
      else				( addr len )
        dup blen
        swap -
        to len				( addr len )
        to blen				( addr )
        baddr addr len move 		( addr )
        to baddr			\ baddr points now to first option
      then
    then
  then
  \ now add kernel switches
  len 0<> if
    bl addr len + c! len 1+ to len
  then
  [char] - addr len + c! len 1+ to len

  s" boot_single" getenv dup -1 <> if
     s" YES" compare-insensitive 0= if
       [char] s addr len + c! len 1+ to len
     then
  else
    drop
  then
  s" boot_verbose" getenv dup -1 <> if
     s" YES" compare-insensitive 0= if
       [char] v addr len + c! len 1+ to len
     then
  else
    drop
  then
  s" boot_kmdb" getenv dup -1 <> if
     s" YES" compare-insensitive 0= if
       [char] k addr len + c! len 1+ to len
     then
  else
    drop
  then
  s" boot_debug" getenv dup -1 <> if
     s" YES" compare-insensitive 0= if
       [char] d addr len + c! len 1+ to len
     then
  else
    drop
  then
  s" boot_reconfigure" getenv dup -1 <> if
     s" YES" compare-insensitive 0= if
       [char] r addr len + c! len 1+ to len
     then
  else
    drop
  then
  s" boot_ask" getenv dup -1 <> if
     s" YES" compare-insensitive 0= if
       [char] a addr len + c! len 1+ to len
     then
  else
    drop
  then

  \ now add remining boot args if blen != 0.
  \ baddr[0] is '-', if baddr[1] != 'B' append to addr,
  \ otherwise add space then copy
  blen 0<> if
    baddr 1+ c@ [char] B = if
      addr len + 1- c@ [char] - = if	 \ if addr[len -1] == '-'
	baddr 1+ to baddr
	blen 1- to blen
      else
	bl addr len + c! len 1+ to len
      then
    else
      baddr 1+ to baddr
      blen 1- to blen
    then
    baddr addr len + blen move
    len blen + to len
    0 to baddr
    0 to blen
  then
  \ last part - add acpi.
  alen 0<> if
    addr len + 1- c@ [char] - <> if
      bl addr len + c! len 1+ to len
      [char] - addr len + c! len 1+ to len
    then
    s" B acpi-user-options=" dup -rot		( len addr len )
    addr len + swap move			( len )
    len + to len
    aaddr addr len + alen move
    len alen + to len
  then

  \ check for left over '-'
  addr len 1- + c@ [char] - = if
    len 1- to len
				\ but now we may also have left over ' '
    len if ( len <> 0 )
      addr len 1- + c@ bl = if
	len 1- to len
      then
    then
  then

  \ if len != 0, set boot-args
  len 0<> if
    addr len s" boot-args" setenv
  then
  addr free drop
;

: boot
  0= if ( interpreted ) get_arguments then
  set-boot-args

  \ Unload only if a path was passed. Paths start with /
  dup if
    >r over r> swap
    c@ [char] / = if
      0 1 unload drop
    else
      s" kernelname" getenv? if ( a kernel has been loaded )
        try-menu-unset
        bootmsg 1 boot exit
      then
      load_kernel_and_modules
      ?dup if exit then
      try-menu-unset
      bootmsg 0 1 boot exit
    then
  else
    s" kernelname" getenv? if ( a kernel has been loaded )
      try-menu-unset
      bootmsg 1 boot exit
    then
    load_kernel_and_modules
    ?dup if exit then
    try-menu-unset
    bootmsg 0 1 boot exit
  then
  load_kernel_and_modules
  ?dup 0= if bootmsg 0 1 boot then
;

\ ***** boot-conf
\
\	Prepares to boot as specified by loaded configuration files.

: boot-conf
  0= if ( interpreted ) get_arguments then
  0 1 unload drop
  load_kernel_and_modules
  ?dup 0= if 0 1 autoboot then
;

also forth definitions previous

builtin: boot
builtin: boot-conf

only forth definitions also support-functions

\ 
\ in case the boot-args is set, parse it and extract following options:
\ -a to boot_ask=YES
\ -s to boot_single=YES
\ -v to boot_verbose=YES
\ -k to boot_kmdb=YES
\ -d to boot_debug=YES
\ -r to boot_reconfigure=YES
\ -B acpi-user-options=X to acpi-user-options=X
\ 
\ This is needed so that the menu can manage these options. Unfortunately, this
\ also means that boot-args will override previously set options, but we have no
\ way to control the processing order here. boot-args will be rebuilt at boot.
\ 
\ NOTE: The best way to address the order is to *not* set any above options
\ in boot-args.

: parse-boot-args  { | baddr blen -- }
  s" boot-args" getenv dup -1 = if drop exit then
  to blen
  to baddr

  baddr blen

  \ loop over all instances of switch blocks, starting with '-'
  begin
    [char] - strchr
    2dup to blen to baddr
    dup 0<>
  while				( addr len ) \ points to -
    \ block for switch B. keep it on top of the stack for case
    \ the property list will get empty.

    over 1+ c@ [char] B = if
	2dup			\ save "-B ...." in case options is empty
	2 - swap 2 +		( addr len len-2 addr+2 ) \ skip -B

      begin			\ skip spaces
        dup c@ bl =
      while
        1+ swap 1- swap
      repeat

				( addr len len' addr' )
      \ its 3 cases now: end of string, -switch, or option list

      over 0= if		\ end of string, remove trailing -B
	2drop			( addr len )
	swap 0 swap c!		\ store 0 at -B
	blen swap		( blen len )
	-			( rem )
	baddr swap		( addr rem )
	dup 0= if
	  s" boot-args" unsetenv
	  2drop
	  exit
	then
				\ trailing space(s)
	begin
	  over			( addr rem addr )
	  over + 1-		( addr rem addr+rem-1 )
	  c@ bl =
	while
	  1- swap		( rem-1 addr )
	  over			( rem-1 addr rem-1 )
	  over +		( rem-1 addr addr+rem-1 )
	  0 swap c!
	  swap
	repeat
	s" boot-args" setenv
	recurse			\ restart
	exit
      then
				( addr len len' addr' )
      dup c@ [char] - = if	\ it is switch. set to boot-args
	swap s" boot-args" setenv
	2drop
	recurse			\ restart
	exit
      then
				( addr len len' addr' )
      \ its options string "option1,option2,... -..."
      \ cut acpi-user-options=xxx and restart the parser
      \ or skip to next option block
      begin
	dup c@ dup 0<> swap bl <> and \ stop if space or 0
      while
	dup 18 s" acpi-user-options=" compare 0= if	\ matched
				( addr len len' addr' )
	  \ addr' points to acpi options, find its end [',' or ' ' or 0 ]
	  \ set it as acpi-user-options and move remaining to addr'
	  2dup			( addr len len' addr' len' addr' )
	  \ skip to next option in list
	  \ loop to first , or bl or 0
	  begin
	    dup c@ [char] , <> >r
	    dup c@ bl <> >r
	    dup c@ 0<> r> r> and and
	  while
	    1+ swap 1- swap
	  repeat
				( addr len len' addr' len" addr" )
	  >r >r 		( addr len len' addr' R: addr" len" )
	  over r@ -		( addr len len' addr' proplen R: addr" len" )
	  dup 5 +		( addr len len' addr' proplen proplen+5 )
	  allocate abort" out of memory"

	  0 s" set " strcat	( addr len len' addr' proplen caddr clen )
	  >r >r 2dup r> r> 2swap strcat ( addr len len' addr' proplen caddr clen )
	  2dup + 0 swap c!	\ terminate with 0
	  2dup evaluate drop free drop
				( addr len len' addr' proplen R: addr" len" )
	  \ acpi-user-options is set, now move remaining string to its place.
	  \ addr: -B, addr': acpi... addr": reminder
	  swap			( addr len len' proplen addr' )
	  r> r>			( addr len len' proplen addr' len" addr" )
	  dup c@ [char] , = if
	    \ skip , and move addr" to addr'
	    1+ swap 1-		( addr len len' proplen addr' addr" len" )
	    rot	swap 1+ move	( addr len len' proplen )
	  else	\ its bl or 0	( addr len len' proplen addr' len" addr" )
	    \ for both bl and 0 we need to copy to addr'-1 to remove
	    \ comma, then reset boot-args, and recurse will clear -B
	    \ if there are no properties left.
	    dup c@ 0= if
	      2drop		( addr len len' proplen addr' )
	      1- 0 swap c!	( addr len len' proplen )
	    else
	      >r >r		( addr len len' proplen addr' R: addr" len" )
	      1- swap 1+ swap
	      r> r>		( addr len len' proplen addr' len" addr" )
	      rot rot move	( addr len len' proplen )
	    then
	  then

	  2swap 2drop		( len' proplen )
	  nip			( proplen )
	  baddr blen rot -
	  s" boot-args" setenv
	  recurse
	  exit
	else
				( addr len len' addr' )
	  \ not acpi option, skip to next option in list
	  \ loop to first , or bl or 0
	  begin
	    dup c@ [char] , <> >r
	    dup c@ bl <> >r
	    dup c@ 0<> r> r> and and
	  while
	    1+ swap 1- swap
	  repeat
	  \ if its ',', skip over
	  dup c@ [char] , = if
	    1+ swap 1- swap
	  then
	then
      repeat
				( addr len len' addr' )
      \ this block is done, remove addr and len from stack
      2swap 2drop swap
    then

    over c@ [char] - = if	( addr len )
      2dup 1- swap 1+		( addr len len' addr' )
      begin			\ loop till ' ' or 0
	dup c@ dup 0<> swap bl <> and
      while
	dup c@ [char] s = if
	  s" set boot_single=YES" evaluate TRUE
	else dup c@ [char] v = if
	  s" set boot_verbose=YES" evaluate TRUE
	else dup c@ [char] k = if
	  s" set boot_kmdb=YES" evaluate TRUE
	else dup c@ [char] d = if
	  s" set boot_debug=YES" evaluate TRUE
	else dup c@ [char] r = if
	  s" set boot_reconfigure=YES" evaluate TRUE
	else dup c@ [char] a = if
	  s" set boot_ask=YES" evaluate TRUE
	then then then then then then
	dup TRUE = if
	  drop
	  dup >r		( addr len len' addr' R: addr' )
	  1+ swap 1-		( addr len addr'+1 len'-1 R: addr' )
	  r> swap move		( addr len )

	  2drop baddr blen 1-
	  \ check if we have space after '-', if so, drop '- '
	  swap dup 1+ c@ bl = if
	      2 + swap 2 -
	  else
	      swap
	  then
	  dup dup 0= swap 1 = or if	\ empty or only '-' is left.
	    2drop
	    s" boot-args" unsetenv
	    exit
	  else
	    s" boot-args" setenv
	  then
	  recurse
	  exit
	then
	1+ swap 1- swap
      repeat

      2swap 2drop
      dup c@ 0= if		\ end of string
	2drop
	exit
      else
	swap
      then
    then
  repeat

  2drop
;

\ ***** start
\
\       Initializes support.4th global variables, sets loader_conf_files,
\       processes conf files, and, if any one such file was successfully
\       read to the end, loads kernel and modules.

: start  ( -- ) ( throws: abort & user-defined )
  s" /boot/defaults/loader.conf" initialize
  include_bootenv
  include_conf_files
  include_transient
  parse-boot-args
  \ Will *NOT* try to load kernel and modules if no configuration file
  \ was successfully loaded!
  any_conf_read? if
    s" loader_delay" getenv -1 = if
      load_xen_throw
      load_kernel
      load_modules
    else
      drop
      ." Loading Kernel and Modules (Ctrl-C to Abort)" cr
      s" also support-functions" evaluate
      s" set delay_command='load_xen_throw load_kernel load_modules'" evaluate
      s" set delay_showdots" evaluate
      delay_execute
    then
  then
;

\ ***** initialize
\
\	Overrides support.4th initialization word with one that does
\	everything start one does, short of loading the kernel and
\	modules. Returns a flag

: initialize ( -- flag )
  s" /boot/defaults/loader.conf" initialize
  include_bootenv
  include_conf_files
  include_transient
  parse-boot-args
  any_conf_read?
;

\ ***** read-conf
\
\	Read a configuration file, whose name was specified on the command
\	line, if interpreted, or given on the stack, if compiled in.

: (read-conf)  ( addr len -- )
  conf_files string=
  include_conf_files \ Will recurse on new loader_conf_files definitions
;

: read-conf  ( <filename> | addr len -- ) ( throws: abort & user-defined )
  state @ if
    \ Compiling
    postpone (read-conf)
  else
    \ Interpreting
    bl parse (read-conf)
  then
; immediate

\ show, enable, disable, toggle module loading. They all take module from
\ the next word

: set-module-flag ( module_addr val -- ) \ set and print flag
  over module.flag !
  dup module.name strtype
  module.flag @ if ."  will be loaded" else ."  will not be loaded" then cr
;

: enable-module find-module ?dup if true set-module-flag then ;

: disable-module find-module ?dup if false set-module-flag then ;

: toggle-module find-module ?dup if dup module.flag @ 0= set-module-flag then ;

\ ***** show-module
\
\	Show loading information about a module.

: show-module ( <module> -- ) find-module ?dup if show-one-module then ;

\ Words to be used inside configuration files

: retry false ;         \ For use in load error commands
: ignore true ;         \ For use in load error commands

\ Return to strict forth vocabulary

: #type
  over - >r
  type
  r> spaces
;

: .? 2 spaces 2swap 15 #type 2 spaces type cr ;

: ?
  ['] ? execute
  s" boot-conf" s" load kernel and modules, then autoboot" .?
  s" read-conf" s" read a configuration file" .?
  s" enable-module" s" enable loading of a module" .?
  s" disable-module" s" disable loading of a module" .?
  s" toggle-module" s" toggle loading of a module" .?
  s" show-module" s" show module load data" .?
  s" try-include" s" try to load/interpret files" .?
  s" beadm" s" list or activate Boot Environments" .?
;

: try-include ( -- ) \ see loader.4th(8)
  ['] include ( -- xt ) \ get the execution token of `include'
  catch ( xt -- exception# | 0 ) if \ failed
    LF parse ( c -- s-addr/u ) 2drop \ advance >in to EOL (drop data)
    \ ... prevents words unused by `include' from being interpreted
  then
; immediate \ interpret immediately for access to `source' (aka tib)

include /boot/forth/beadm.4th
only forth definitions
