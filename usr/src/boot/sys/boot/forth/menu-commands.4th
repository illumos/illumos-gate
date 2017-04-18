\ Copyright (c) 2006-2015 Devin Teske <dteske@FreeBSD.org>
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
\ Copyright 2015 Toomas Soome <tsoome@me.com>

marker task-menu-commands.4th

include /boot/forth/menusets.4th

only forth definitions

variable osconsole_state
variable acpi_state
variable kernel_state
variable root_state
variable kmdb_state
variable debug_state
0 kmdb_state !
0 debug_state !
0 osconsole_state !
0 acpi_state !
0 kernel_state !
0 root_state !

also menu-namespace also menu-command-helpers

\
\ Boot
\

: init_boot ( N -- N )
	dup
	s" smartos" getenv? if
		s" set menu_keycode[N]=98" \ base command to execute
	else
		s" boot_single" getenv -1 <> if
			drop ( n n c-addr -- n n ) \ unused
			toggle_menuitem ( n n -- n n )
			s" set menu_keycode[N]=115" \ base command to execute
		else
			s" set menu_keycode[N]=98" \ base command to execute
		then
	then
	17 +c! \ replace 'N' with ASCII numeral
	evaluate
;

\
\ Alternate Boot
\

: init_altboot ( N -- N )
	dup
	s" smartos" getenv? if
		s" set menu_keycode[N]=114" \ base command to execute
	else
		s" boot_single" getenv -1 <> if
			drop ( n c-addr -- n ) \ unused
			toggle_menuitem ( n -- n )
			s" set menu_keycode[N]=109" \ base command to execute
		else
			s" set menu_keycode[N]=115" \ base command to execute
		then
	then
	17 +c! \ replace 'N' with ASCII numeral
	evaluate
;

: altboot ( N -- NOTREACHED )
	s" smartos" getenv? if
		s" alt-boot-args" getenv dup -1 <> if
			s" boot-args" setenv ( c-addr/u -- )
		then
		." NoInstall/Recovery mode boot. login/pw: root/root" cr
	else
		s" boot_single" 2dup getenv -1 <> if
			drop ( c-addr/u c-addr -- c-addr/u ) \ unused
			unsetenv ( c-addr/u -- )
		else
			2drop ( c-addr/u -- ) \ unused
			s" set boot_single=YES" evaluate
		then
	then
	0 boot ( state -- )
;

\
\ Single User Mode
\

: singleuser_enabled? ( -- flag )
	s" boot_single" getenv -1 <> dup if
		swap drop ( c-addr flag -- flag )
	then
;

: singleuser_enable ( -- )
	s" set boot_single=YES" evaluate
;

: singleuser_disable ( -- )
	s" boot_single" unsetenv
;

: init_singleuser ( N -- N )
	singleuser_enabled? if
		toggle_menuitem ( n -- n )
	then
;

: toggle_singleuser ( N -- N TRUE )
	toggle_menuitem
	menu-redraw

	\ Now we're going to make the change effective

	dup toggle_stateN @ 0= if
		singleuser_disable
	else
		singleuser_enable
	then

	TRUE \ loop menu again
;

\
\ Verbose Boot
\

: verbose_enabled? ( -- flag )
	s" boot_verbose" getenv -1 <> dup if
		swap drop ( c-addr flag -- flag )
	then
;

: verbose_enable ( -- )
	s" set boot_verbose=YES" evaluate
;

: verbose_disable ( -- )
	s" boot_verbose" unsetenv
;

: init_verbose ( N -- N )
	verbose_enabled? if
		toggle_menuitem ( n -- n )
	then
;

: toggle_verbose ( N -- N TRUE )
	toggle_menuitem
	menu-redraw

	\ Now we're going to make the change effective

	dup toggle_stateN @ 0= if
		verbose_disable
	else
		verbose_enable
	then

	TRUE \ loop menu again
;

\
\ kmdb
\

: kmdb_enabled? ( -- flag )
	s" boot_kmdb" getenv -1 <> dup if
		swap drop ( c-addr flag -- flag )
	then
;

: kmdb_enable ( -- )
	s" set boot_kmdb=YES" evaluate
;

: kmdb_disable ( -- )
	s" boot_kmdb" unsetenv
	s" boot_debug" unsetenv
;

: init_kmdb ( N -- N )
	dup kmdb_state !		\ store entry number for kmdb+debug
	kmdb_enabled? if
		toggle_menuitem ( n -- n )
	then
;

: toggle_kmdb ( N -- N TRUE )
	toggle_menuitem
	dup toggle_stateN @ 0= if ( kmdb is not set )
		debug_state @ if ( debug is set? )
			debug_state @ toggle_stateN @ if ( debug is enabled? )
				debug_state @ toggle_menuitem drop
			then
		then
	then
	menu-redraw

	\ Now we're going to make the change effective

	dup toggle_stateN @ 0= if
		kmdb_disable
	else
		kmdb_enable
	then

	TRUE \ loop menu again
;

\
\ kmdb + debug
\

: debug_disable ( -- )
	s" boot_debug" unsetenv
;

: debug_enabled? ( -- flag )
	\ -d is only allowed with -k
	s" boot_debug" getenv -1 <> kmdb_enabled? and dup if
		swap drop ( c-addr flag -- flag )
	else
		debug_disable		\ make sure env is not set
	then
;

: debug_enable ( -- )
	kmdb_enable
	s" set boot_debug=YES" evaluate
;

: init_debug ( N -- N )
	dup debug_state !		\ store entry number for kmdb
	kmdb_enabled? debug_enabled? and if
		toggle_menuitem ( n -- n )
	then
;

: toggle_debug ( N -- N TRUE )
	toggle_menuitem
	kmdb_enabled? 0= if
		kmdb_state @ toggle_menuitem drop
	then
	menu-redraw

	\ Now we're going to make the change effective

	dup toggle_stateN @ 0= if
		debug_disable
	else
		debug_enable
	then

	TRUE \ loop menu again
;

\
\ Reconfiguration boot
\

: reconfigure_enabled? ( -- flag )
	s" boot_reconfigure" getenv -1 <> dup if
		swap drop ( c-addr flag -- flag )
	then
;

: reconfigure_enable ( -- )
	s" set boot_reconfigure=YES" evaluate
;

: reconfigure_disable ( -- )
	s" boot_reconfigure" unsetenv
;

: init_reconfigure ( N -- N )
	reconfigure_enabled? if
		toggle_menuitem ( n -- n )
	then
;

: toggle_reconfigure ( N -- N TRUE )
	toggle_menuitem
	menu-redraw

	\ Now we're going to make the change effective

	dup toggle_stateN @ 0= if
		reconfigure_disable
	else
		reconfigure_enable
	then

	TRUE \ loop menu again
;

\
\ Escape to Prompt
\

: goto_prompt ( N -- N FALSE )

	s" set autoboot_delay=NO" evaluate

	cr
	." To get back to the menu, type `menu' and press ENTER" cr
	." or type `boot' and press ENTER to start illumos." cr
	cr

	FALSE \ exit the menu
;

\
\ Cyclestate (used by osconsole/acpi/kernel/root below)
\

: init_cyclestate ( N K -- N )
	over cycle_stateN ( n k -- n k addr )
	begin
		tuck @  ( n k addr -- n addr k c )
		over <> ( n addr k c -- n addr k 0|-1 )
	while
		rot ( n addr k -- addr k n )
		cycle_menuitem
		swap rot ( addr k n -- n k addr )
	repeat
	2drop ( n k addr -- n )
;

\
\ OS Console
\ getenv os_console, if not set getenv console, if not set, default to "text"
\ allowed serial consoles: ttya .. ttyd
\ if new console will be added (graphics?), this section needs to be updated
\
: init_osconsole ( N -- N )
	s" os_console" getenv dup -1 = if
		drop
		s" console" getenv dup -1 = if
			drop 0		\ default to text
		then
	then				( n c-addr/u | n 0 )

	dup 0<> if			( n c-addr/u )
		2dup s" ttyd" compare 0= if
			2drop 4
		else 2dup s" ttyc" compare 0= if
			2drop 3
		else 2dup s" ttyb" compare 0= if
			2drop 2
		else 2dup s" ttya" compare 0= if
			2drop 1
		else
			2drop 0		\ anything else defaults to text
		then then then then
	then
	osconsole_state !
;

: activate_osconsole ( N -- N )
	dup cycle_stateN @	( n -- n n2 )
	dup osconsole_state !	( n n2 -- n n2 )  \ copy for re-initialization

	case
	0 of s" text" endof
	1 of s" ttya" endof
	2 of s" ttyb" endof
	3 of s" ttyc" endof
	4 of s" ttyd" endof
	dup s" unknown state: " type . cr
	endcase
	s" os_console" setenv
;

: cycle_osconsole ( N -- N TRUE )
	cycle_menuitem	\ cycle cycle_stateN to next value
	activate_osconsole	\ apply current cycle_stateN
	menu-redraw	\ redraw menu
	TRUE		\ loop menu again
;

\
\ ACPI
\
: init_acpi ( N -- N )
	s" acpi-user-options" getenv dup -1 <> if
		evaluate		\ use ?number parse step

		\ translate option to cycle state
		case
		1 of 1 acpi_state ! endof
		2 of 2 acpi_state ! endof
		4 of 3 acpi_state ! endof
		8 of 4 acpi_state ! endof
		0 acpi_state !
		endcase
	else
		drop
	then
;

: activate_acpi ( N -- N )
	dup cycle_stateN @	( n -- n n2 )
	dup acpi_state !	( n n2 -- n n2 )  \ copy for re-initialization

	\ if N == 0, it's default, just unset env.
	dup 0= if
		drop
		s" acpi-user-options" unsetenv
	else
		case
		1 of s" 1" endof
		2 of s" 2" endof
		3 of s" 4" endof
		4 of s" 8" endof
		endcase
		s" acpi-user-options" setenv
	then
;

: cycle_acpi ( N -- N TRUE )
	cycle_menuitem	\ cycle cycle_stateN to next value
	activate_acpi	\ apply current cycle_stateN
	menu-redraw	\ redraw menu
	TRUE		\ loop menu again
;

\
\ Kernel
\

: init_kernel ( N -- N )
	kernel_state @  ( n -- n k )
	init_cyclestate ( n k -- n )
;

: activate_kernel ( N -- N )
	dup cycle_stateN @	( n -- n n2 )
	dup kernel_state !	( n n2 -- n n2 )  \ copy for re-initialization
	48 +			( n n2 -- n n2' ) \ kernel_state to ASCII num

	s" set kernel=${kernel_prefix}${kernel[N]}${kernel_suffix}"
	36 +c!		( n n2 c-addr/u -- n c-addr/u ) \ 'N' to ASCII num
	evaluate	( n c-addr/u -- n ) \ sets $kernel to full kernel-path
;

: cycle_kernel ( N -- N TRUE )
	cycle_menuitem	\ cycle cycle_stateN to next value
	activate_kernel \ apply current cycle_stateN
	menu-redraw	\ redraw menu
	TRUE		\ loop menu again
;

\
\ Root
\

: init_root ( N -- N )
	root_state @    ( n -- n k )
	init_cyclestate ( n k -- n )
;

: activate_root ( N -- N )
	dup cycle_stateN @	( n -- n n2 )
	dup root_state !	( n n2 -- n n2 )  \ copy for re-initialization
	48 +			( n n2 -- n n2' ) \ root_state to ASCII num

	s" set root=${root_prefix}${root[N]}${root_suffix}"
	30 +c!		( n n2 c-addr/u -- n c-addr/u ) \ 'N' to ASCII num
	evaluate	( n c-addr/u -- n ) \ sets $root to full kernel-path
;

: cycle_root ( N -- N TRUE )
	cycle_menuitem	\ cycle cycle_stateN to next value
	activate_root	\ apply current cycle_stateN
	menu-redraw	\ redraw menu
	TRUE		\ loop menu again
;

\
\ Menusets
\

: goto_menu ( N M -- N TRUE )
	menu-unset
	menuset-loadsetnum ( n m -- n )
	menu-redraw
	TRUE \ Loop menu again
;

\
\ Defaults
\

: unset_boot_options
	0 acpi_state !
	s" acpi-user-options" unsetenv
	s" boot-args" unsetenv
	s" boot_ask" unsetenv
	singleuser_disable
	verbose_disable
	kmdb_disable		\ disables debug as well
	reconfigure_disable
;

: set_default_boot_options ( N -- N TRUE )
	unset_boot_options
	2 goto_menu
;

\
\ Set boot environment defaults
\


: init_bootenv ( -- )
	s" set menu_caption[1]=${bemenu_current}${zfs_be_active}" evaluate
	s" set ansi_caption[1]=${beansi_current}${zfs_be_active}" evaluate
	s" set menu_caption[2]=${bemenu_bootfs}${currdev}" evaluate
	s" set ansi_caption[2]=${beansi_bootfs}${currdev}" evaluate
	s" set menu_caption[3]=${bemenu_page}${zfs_be_currpage}${bemenu_pageof}${zfs_be_pages}" evaluate
	s" set ansi_caption[3]=${beansi_page}${zfs_be_currpage}${bemenu_pageof}${zfs_be_pages}" evaluate
;

\
\ Redraw the entire screen. A long BE name can corrupt the menu
\

: be_draw_screen
	clear		\ Clear the screen (in screen.4th)
	print_version	\ print version string (bottom-right; see version.4th)
	draw-beastie	\ Draw FreeBSD logo at right (in beastie.4th)
	draw-brand	\ Draw brand.4th logo at top (in brand.4th)
	menu-init	\ Initialize menu and draw bounding box (in menu.4th)
;

\
\ Select a boot environment
\

: set_bootenv ( N -- N TRUE )
	dup s" bootenv_root[E]" 13 +c! getenv
	s" currdev" getenv compare 0= if
		s" zfs_be_active" getenv type ."  is already active"
		500 ms				\ sleep
	else
		dup s" set currdev=${bootenv_root[E]}" 27 +c! evaluate
		dup s" bootenvmenu_caption[E]" 20 +c! getenv
		s" zfs_be_active" setenv
		." Activating " s" currdev" getenv type cr
		s" unload" evaluate
		free-module-options
		unset_boot_options
		s" /boot/defaults/loader.conf" read-conf
		s" /boot/loader.conf" read-conf
		s" /boot/loader.conf.local" read-conf
		init_bootenv
	then

	be_draw_screen
	menu-redraw
	TRUE
;

\
\ Switch to the next page of boot environments
\

: set_be_page ( N -- N TRUE )
	s" zfs_be_currpage" getenv dup -1 = if
		drop s" 1"
	else
		0 s>d 2swap
		>number		( ud caddr/u -- ud' caddr'/u' )
		2drop
		1 um/mod	( ud u1 -- u2 u3 )
		swap drop	( ud2 u3 -- u3 )
		1+		\ increment the page number
		dup
		s" zfs_be_pages" getenv
		0 s>d 2swap
		>number		( ud caddr/u -- ud' caddr'/u' )
		2drop
		1 um/mod	( ud u1 -- u2 u3 )
		swap drop	( ud2 u3 -- u3 )
		> if drop 1 then
		s>d <# #s #>	\ convert back to a string
	then

	s" zfs_be_currpage" setenv
	s" be-set-page" evaluate
	3 goto_menu
;

only forth definitions
