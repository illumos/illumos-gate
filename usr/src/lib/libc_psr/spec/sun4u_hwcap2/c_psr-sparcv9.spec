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
# usr/src/lib/libc_psr/spec/sun4u_hwcap2/c_psr-sparcv9.spec

function	memcmp extends libc/spec/gen.spec
arch		sparcv9
version		SUNWprivate_1.1
end		

function	_memcmp extends libc/spec/private.spec
arch		sparcv9
version		SUNWprivate_1.1
end		

function	memcpy extends libc/spec/gen.spec
arch		sparcv9
version		SUNWprivate_1.1
end		

function	_memcpy extends libc/spec/private.spec
arch		sparcv9
version		SUNWprivate_1.1
end		

function	memmove extends libc/spec/gen.spec
arch		sparcv9
version		SUNWprivate_1.1
end		

function	_memmove extends libc/spec/private.spec
arch		sparcv9
version		SUNWprivate_1.1
end		

function	memset extends libc/spec/gen.spec
arch		sparcv9
version		SUNWprivate_1.1
end		

function	_memset extends libc/spec/private.spec
arch		sparcv9
version		SUNWprivate_1.1
end		
