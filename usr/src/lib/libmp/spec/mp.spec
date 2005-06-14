#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libmp/spec/mp.spec

function	mp_gcd
include		<mp.h>
declaration void mp_gcd(MINT *, MINT *, MINT *)
version		SUNW_1.1
end		

function	mp_itom
include		<mp.h>
declaration	MINT *mp_itom(short)
version		SUNW_1.1
end		

function	mp_madd
include		<mp.h>
declaration	void mp_madd(MINT *, MINT *, MINT *)
version		SUNW_1.1
end		

function	mp_mcmp
include		<mp.h>
declaration	int mp_mcmp(MINT *, MINT *)
version		SUNW_1.1
end		

function	mp_mdiv
include		<mp.h>
declaration	void mp_mdiv(MINT *a, MINT *b, MINT *q, MINT *r)
version		SUNW_1.1
end		

function	mp_mfree
include		<mp.h>
declaration	void mp_mfree(MINT *a)
version		SUNW_1.1
end		

function	mp_min
include		<mp.h>
declaration	int mp_min(MINT *a)
version		SUNW_1.1
end		

function	mp_mout
include		<mp.h>
declaration	void mp_mout(MINT *a)
version		SUNW_1.1
end		

function	mp_msqrt
include		<mp.h>
declaration	int mp_msqrt(MINT *a, MINT *b, MINT *r)
version		SUNW_1.1
end		

function	mp_msub
include		<mp.h>
declaration	void mp_msub(MINT *a, MINT *b, MINT *c)
version		SUNW_1.1
end		

function	mp_mtox
include		<mp.h>
declaration	char * mp_mtox(MINT *a)
version		SUNW_1.1
end		

function	mp_mult
include		<mp.h>
declaration	void mp_mult(MINT *a, MINT *b, MINT *c)
version		SUNW_1.1
end		

function	mp_pow
include		<mp.h>
declaration	void mp_pow(MINT *a, MINT *b, MINT *c, MINT *d)
version		SUNW_1.1
end		

function	mp_rpow
include		<mp.h>
declaration	void mp_rpow(MINT *a, short n, MINT *b)
version		SUNW_1.1
end		

function	mp_sdiv
include		<mp.h>
declaration	void mp_sdiv(MINT *a, short n, MINT *q, short *r)
version		SUNW_1.1
end		

function	mp_xtom
include		<mp.h>
declaration	MINT * mp_xtom(char *a)
version		SUNW_1.1
end		

function	_mp_move
include		<mp.h>
declaration	void _mp_move(MINT *, MINT *)
version		SUNWprivate_1.1
end		

function	_mp_xalloc
include		<mp.h>
version		SUNWprivate_1.1
end		

function	_mp_xfree
include		<mp.h>
version		SUNWprivate_1.1
end		

