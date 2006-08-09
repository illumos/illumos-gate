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
# ident	"%Z%%M%	%I%	%E% SMI"
#

function	decimal_to_double 
include		<floatingpoint.h>
declaration	void decimal_to_double(double *px, decimal_mode *pm, \
			decimal_record *pd, fp_exception_field_type *ps)
version		SUNW_0.7
errno		
end

function	decimal_to_extended 
include		<floatingpoint.h>
declaration	void decimal_to_extended(extended *px, decimal_mode *pm, \
			decimal_record *pd, fp_exception_field_type *ps)
version		SUNW_0.7
errno		
end

function	decimal_to_quadruple 
include		<floatingpoint.h>
declaration	void decimal_to_quadruple(quadruple *px, decimal_mode *pm, \
			decimal_record *pd, fp_exception_field_type *ps)
version		SUNW_0.7
errno		
end

function	decimal_to_single 
include		<floatingpoint.h>
declaration	void decimal_to_single(single *px, decimal_mode *pm, \
			decimal_record *pd, fp_exception_field_type *ps)
version		SUNW_0.7
errno		
end

function	double_to_decimal 
include		<floatingpoint.h>
declaration	void double_to_decimal(double *px, decimal_mode *pm, \
			decimal_record *pd, fp_exception_field_type *ps)
version		SUNW_0.7
errno		
end

function	extended_to_decimal 
include		<floatingpoint.h>
declaration	void extended_to_decimal(extended *px, decimal_mode *pm, \
			decimal_record *pd, fp_exception_field_type *ps)
version		SUNW_0.7
errno		
end

function	file_to_decimal 
include		<floatingpoint.h>, <stdio.h>
declaration	void file_to_decimal(char **pc, int nmax, \
			int fortran_conventions, decimal_record *pd, \
			enum decimal_string_form *pform, char **pechar, \
			FILE *pf, int *pnread)
version		SUNW_0.7
errno		
end

function	fpgetmask 
include		<ieeefp.h>
declaration	fp_except fpgetmask(void)
version		SUNW_0.7
exception	false 
end

function	fpgetround 
include		<ieeefp.h>
declaration	fp_rnd fpgetround(void)
version		SUNW_1.1
end

function	fpgetsticky 
include		<ieeefp.h>
declaration	fp_except fpgetsticky(void)
version		SUNW_0.7
end

function	fpsetmask 
include		<ieeefp.h>
declaration	fp_except fpsetmask(fp_except mask)
version		SUNW_0.7
end

function	fpsetround 
include		<ieeefp.h>
declaration	fp_rnd fpsetround(fp_rnd rnd_dir)
version		SUNW_1.1
end

function	fpsetsticky 
include		<ieeefp.h>
declaration	fp_except fpsetsticky(fp_except sticky)
version		SUNW_0.7
end

function	func_to_decimal
include		<floatingpoint.h>, <stdio.h>
declaration	void func_to_decimal(char **pc, int nmax, \
			int fortran_conventions, \
			decimal_record *pd, \
			enum decimal_string_form *pform, \
			char **pechar, \
			int (*pget)(void), int *pnread, \
			int (*punget)(int c))
version		SUNW_0.7 
errno		
end

function	nextafter
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
filter		libm.so.2
end

function	_nextafter
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
filter		libm.so.2
end

function	quadruple_to_decimal 
include		<floatingpoint.h>
declaration	void quadruple_to_decimal(quadruple *px, decimal_mode *pm, \
			decimal_record *pd, fp_exception_field_type *ps)
version		SUNW_0.7 
errno		
end

function	scalb
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
filter		libm.so.2
end

function	_scalb
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
filter		libm.so.2
end

function	single_to_decimal 
include		<floatingpoint.h>
declaration	void single_to_decimal(single *px, decimal_mode *pm, \
			decimal_record *pd, fp_exception_field_type *ps)
version		SUNW_0.7 
errno		
end

function	_fpstart
declaration	void _fpstart(void)
arch		i386 amd64
version		SYSVABI_1.3
end

function	__fpstart
weak		_fpstart 
arch		i386 amd64
version		SYSVABI_1.3 
end

function	string_to_decimal 
include		<floatingpoint.h>, <stdio.h>
declaration	void string_to_decimal(char **pc, int nmax, \
			int fortran_conventions, decimal_record *pd, \
			enum decimal_string_form *pform, char **pechar)
version		SUNW_0.7 
errno		
end

function	isnan
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
filter		libm.so.2
end

function	_isnan
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
filter		libm.so.2
end

function	isnand
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
filter		libm.so.2
end

function	_isnand
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
filter		libm.so.2
end

function	isnanf 
version		SUNW_0.7 
filter		libm.so.2
end
