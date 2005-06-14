\ #ident	"%Z%%M%	%I%	%E% SMI"
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

fcode-version1

alias headerless headers

 fload calling.fth
 noop
 : .noop  noop noop  ;

 : .failed	." failed!"  ;

 : .passed	." OK"  ;

 fload iftest.fth

 : .chkstk  depth if ." Stack Changed: " .s cr then ;

 .chkstk
 fload arithmetic.fth
 .chkstk
 fload stack.fth
 .chkstk
 fload create.fth
 .chkstk
 fload bytemanipulate.fth
 .chkstk
 fload loop.fth
 .chkstk
 fload storage.fth
 .chkstk
 fload access.fth
 .chkstk
 fload case.fth
 .chkstk
 fload catch.fth
 .chkstk
 fload parse.fth
 .chkstk
 fload find.fth
 .chkstk
 fload misc.fth
 .chkstk
 cr ." End of Tests" cr

end0

