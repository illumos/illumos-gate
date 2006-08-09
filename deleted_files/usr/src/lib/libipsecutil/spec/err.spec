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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libipsecutil/spec/err.spec

function	err
include		<ipsec_util.h>
declaration	void err(int status, const char *fmt, ...)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	errx
include		<ipsec_util.h>
declaration	void errx(int status, const char *fmt, ...)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	warn
include		<ipsec_util.h>
declaration	void warn(const char *fmt, ...)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	warnx
include		<ipsec_util.h>
declaration	void warnx(const char *fmt, ...)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	verr
include		<ipsec_util.h>
declaration	void verr(int status, const char *fmt, va_list args)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	verrx
include		<ipsec_util.h>
declaration	void verrx(int status, const char *fmt, va_list args)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	vwarn
include		<ipsec_util.h>
declaration	void vwarn(const char *fmt, va_list args)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	vwarnx
include		<ipsec_util.h>
declaration	void vwarnx(const char *fmt, va_list args)
arch		i386 sparc
version		SUNWprivate_1.1
end
