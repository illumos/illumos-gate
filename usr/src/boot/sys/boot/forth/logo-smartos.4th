\
\ This file and its contents are supplied under the terms of the
\ Common Development and Distribution License ("CDDL"), version 1.0.
\ You may only use this file in accordance with the terms of version
\ 1.0 of the CDDL.
\
\ A full copy of the text of the CDDL should have accompanied this
\ source.  A copy of the CDDL is also available via the Internet at
\ http://www.illumos.org/license/CDDL.
\

\
\ Copyright 2019 Joyent, Inc.
\

52 logoX ! 11 logoY ! \ Initialize logo placement defaults

: logo+ ( x y c-addr/u -- x y' )
	2swap 2dup at-xy 2swap \ position the cursor
	[char] @ escc! \ replace @ with Esc
	type \ print to the screen
	1+ \ increase y for next time we're called
;

: logo ( x y -- ) \ color Illumos logo

	0 0 0 0 0 s" /boot/triton.png" fb-putimage if 2drop exit then

        s" @[31m--@[0;31m+--@[1;31m*@[0;33m--@[1;33m*" logo+
	s" @[31m|@[1m\@[0m @[31m|\ |@[33m\ @[1m|\" logo+
	s" @[31m| @[1m\@[0;31m|@[37m @[31m\| @[33m\@[1m| \" logo+
	s" @[31m+--@[1;31m*@[31m--+@[0;33m--@[1;33m*@[33m--@[33m*" logo+
	s" |@[31m\ |\ |\ @[33m|@[1m\ |" logo+
	s" | @[31m\| \| \@[33m| @[1m\|" logo+
	s" @[1m*@[0m--+@[31m--+@[33m--+@[1m--+" logo+
	s" @[1m \ |@[0;34m\ |\ |@[1m\ |" logo+
	s" @[1m  \| @[0;34m\| \| @[1m\|" logo+
	s" @[1m   *--+@[0;34m--@[1;34m*@[34m--@[34m*" logo+

	2drop
;
