\ #pragma ident	"%Z%%M%	%I%	%E% SMI"
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

." Access test: "
0 value word-test
0 value char-test
0 value end-test
0 value end-test2
variable var-test
create access-test
	h# 80004000 l,
	here to word-test
	h# 8000 w, h# 4000 w,
	here to char-test
	h# 1 c, h# 2 c, h# 3 c, h# 4 c,
	here to end-test
	h# a55aa55a ,
	here to end-test2
	

	" l,+"  access-test  la1+     word-test = .passed?
        " w,+"  word-test   2 wa+     char-test = .passed?
        " c,+"  char-test   4 ca+      end-test = .passed?
	" ,+"   end-test    cell+     end-test2 = .passed?
	" c@.1" char-test        c@ h#        1 = .passed?
	" c@.2" char-test char+  c@ h#        2 = .passed?
	" c@.3" char-test 2 ca+  c@ h#        3 = .passed?
	" c@.4" char-test 3 ca+  c@ h#        4 = .passed?
	" w@.1"	access-test      w@ h#     8000 = .passed?
	" w@.2" access-test wa1+ w@ h#     4000 = .passed?
	" w@.3" word-test        w@ h#     8000 = .passed?
	" w@.4" word-test wa1+   w@ h#     4000 = .passed?
	" w@.5" char-test        w@ h#     0102 = .passed?
        " w@.6" char-test wa1+   w@ h#     0304 = .passed?
	" <w@"	access-test     <w@ h# ffff8000 = .passed?
	" l@.1"	access-test      l@ h# 80004000 = .passed?
        " l@.2" word-test        l@ h# 80004000 = .passed?
	" l@.3" char-test        l@ h# 01020304 = .passed?
	" @!.1" h# 5a5aa5a5 var-test ! var-test @ h# 5a5aa5a5 = .passed?
	" c@c!.1" h# 55 var-test c! var-test c@ h# 55 = .passed?
	" w@w!.1" h# aa55 var-test w! var-test w@ h# aa55 = .passed?
	" l@l!.1" h# 5555aaaa var-test l! var-test l@ h# 5555aaaa = .passed?
	" @!.1" h# aaaa5555 var-test ! var-test @ h# aaaa5555 = .passed?
	" +!.1" 2 var-test ! 3 var-test +! var-test @ 5 = .passed?
	" 2!.1" 1 2 access-test 2! access-test @ 2 =
                access-test cell+ @ 1 = and       .passed?
	" 2@.1" access-test 2@ 2 = swap 1 = and   .passed?
cr
