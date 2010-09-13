\ #ident	"%Z%%M%	%I%	%E% SMI"
\ purpose: 
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

." Runtime storage access: "
	variable var-1 var-1 off
	4 constant const-1
	5 value val-1
	" variable (off) (get)"	var-1 @ 0= .passed?
	" variable (on) (set)"	var-1 on var-1 @ -1 = .passed?
	" variable (set)"	2 var-1 ! var-1 @ 2 = .passed?
	" constant.1"		const-1 4 = .passed?
	" value (get)"		val-1 5 = .passed?
	" value (set)"		2 to val-1 val-1 2 = .passed?
cr

." Compile time storage access: "
	" variable (get)"	: vtest1 var-1 @ = .passed? ; 2 vtest1
	" variable (set)"	: vtest2 1 var-1 ! 1 vtest1 ; vtest2
	" constant.2"		: ctest const-1 const-1 + 8 = .passed? ; ctest
	" value (get)"		: vtest3 val-1 = .passed? ; 2 vtest3
	" value (set)"		: vtest4 1 to val-1 1 vtest3 ; vtest4
cr	

