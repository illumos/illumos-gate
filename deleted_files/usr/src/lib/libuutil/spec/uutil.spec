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

function	uu_error
include		<libuutil.h>
declaration	uint32_t uu_error(void);
version		SUNWprivate_1.1
end

function	uu_strerror
include		<libuutil.h>
declaration	const char *uu_strerror(uint32_t);
version		SUNWprivate_1.1
end

function	uu_alt_exit
include		<libuutil.h>
declaration	void uu_alt_exit(int);
version		SUNWprivate_1.1
end

function	uu_setpname
include		<libuutil.h>
declaration	const char *uu_setpname(char *);
version		SUNWprivate_1.1
end

function	uu_getpname
include		<libuutil.h>
declaration	const char *uu_getpname(void);
version		SUNWprivate_1.1
end

function	uu_warn
include		<libuutil.h>
declaration	void uu_warn(const char *, ...);
version		SUNWprivate_1.1
end

function	uu_vwarn
include		<libuutil.h>
declaration	void uu_vwarn(const char *, va_list);
version		SUNWprivate_1.1
end

function	uu_die
include		<libuutil.h>
declaration	void uu_die(const char *, ...);
version		SUNWprivate_1.1
end

function	uu_vdie
include		<libuutil.h>
declaration	void uu_vdie(const char *, va_list);
version		SUNWprivate_1.1
end

function	uu_xdie
include		<libuutil.h>
declaration	void uu_xdie(int, const char *, ...);
version		SUNWprivate_1.1
end

function	uu_vxdie
include		<libuutil.h>
declaration	void uu_vxdie(int, const char *, va_list);
version		SUNWprivate_1.1
end

function	uu_exit_ok
include		<libuutil.h>
declaration	int *uu_exit_ok(void);
version		SUNWprivate_1.1
end

function	uu_exit_fatal
include		<libuutil.h>
declaration	int *uu_exit_fatal(void);
version		SUNWprivate_1.1
end

function	uu_exit_usage
include		<libuutil.h>
declaration	int *uu_exit_usage(void);
version		SUNWprivate_1.1
end

function	uu_strtoint
include		<libuutil.h>
declaration	int uu_strtoint(const char *, void *, size_t, int, \
		    int64_t, int64_t);
version		SUNWprivate_1.1
end

function	uu_strtouint
include		<libuutil.h>
declaration	int uu_strtouint(const char *, void *, size_t, int, \
		    uint64_t, uint64_t);
version		SUNWprivate_1.1
end

function	uu_dprintf_create
include		<libuutil.h>
declaration	uu_dprintf_t *uu_dprintf_create(const char *, \
		    uu_dprintf_severity_t, uint_t);
version		SUNWprivate_1.1
end

function	uu_dprintf
include		<libuutil.h>
declaration	void uu_dprintf(uu_dprintf_t *, \
		    uu_dprintf_severity_t, const char *, ...);
version		SUNWprivate_1.1
end

function	uu_dprintf_destroy
include		<libuutil.h>
declaration	void uu_dprintf_destroy(uu_dprintf_t *);
version		SUNWprivate_1.1
end

function	uu_dprintf_getname
include		<libuutil.h>
declaration	const char *uu_dprintf_getname(uu_dprintf_t *);
version		SUNWprivate_1.1
end

function	uu_check_name
include		<libuutil.h>
declaration	int uu_check_name(const char *, uint_t);
version		SUNWprivate_1.1
end

function	uu_open_tmp
include		<libuutil.h>
declaration	int uu_open_tmp(const char *, uint_t);
version		SUNWprivate_1.1
end

function	uu_msprintf
include		<libuutil.h>
declaration	char *uu_msprintf(const char *, ...);
version		SUNWprivate_1.1
end

function	uu_zalloc
include		<libuutil.h>
declaration	void *uu_zalloc(size_t);
version		SUNWprivate_1.1
end

function	uu_free
include		<libuutil.h>
declaration	void uu_free(void *);
version		SUNWprivate_1.1
end
