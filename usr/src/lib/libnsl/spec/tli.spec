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

function	t_accept
include		<tiuser.h>
declaration	int t_accept(int fildes, int resfd, struct t_call *call)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_alloc
include		<tiuser.h>
declaration	char *t_alloc(int fildes, int struct_type, int fields)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	t_bind
include		<tiuser.h>
declaration	int t_bind(int fildes, struct t_bind *req, \
			struct t_bind	*ret)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_close
include		<tiuser.h>
declaration	int t_close(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_connect
include		<tiuser.h>
declaration	int t_connect(int fildes, struct t_call *sndcall, \
			struct t_call *rcvcall)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_error
include		<tiuser.h>
declaration	void t_error(const char *errmsg)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	t_free
include		<tiuser.h>
declaration	int t_free(char *ptr, int struct_type)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_getinfo
include		<tiuser.h>
declaration	int t_getinfo(int fildes, struct t_info *info)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_getstate
include		<tiuser.h>
declaration	int t_getstate(int	fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_listen
include		<tiuser.h>
declaration	int t_listen(int fildes, struct t_call *call)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_look
include		<tiuser.h>
declaration	int t_look(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_open
include		<tiuser.h>, <fcntl.h>
declaration	int t_open(const char *path, int oflag, struct t_info *info)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_optmgmt
include		<tiuser.h>
declaration	int t_optmgmt(int fildes, struct t_optmgmt *req, \
			struct t_optmgmt *ret)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_rcv
declaration	int t_rcv(int fildes, char *buf, unsigned nbytes, int *flags)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_rcvconnect
include		<tiuser.h>
declaration	int t_rcvconnect(int fildes, struct t_call *call)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_rcvdis
include		<tiuser.h>
declaration	int t_rcvdis(int fildes, struct t_discon *discon)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_rcvrel
include		<tiuser.h>
declaration	int t_rcvrel(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_rcvudata
include		<tiuser.h>
declaration	int t_rcvudata(int fildes, struct t_unitdata *unitdata, \
			int *flags)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_rcvuderr
declaration	int t_rcvuderr(int fildes, struct t_uderr *uderr)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_snd
include		<tiuser.h>
declaration	int t_snd(int fildes, char *buf, unsigned nbytes, int flags)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_snddis
include		<tiuser.h>
declaration	int t_snddis(int fildes, struct t_call *call)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_sndrel
include		<tiuser.h>
declaration	int t_sndrel(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_sndudata
include		<tiuser.h>
declaration	int t_sndudata(int fildes, struct t_unitdata *unitdata)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_strerror
include		<tiuser.h>
declaration	char *t_strerror(int errnum)
version		SUNW_0.7
end

function	_t_strerror
weak		t_strerror
version		SUNWprivate_1.1
end

function	t_sync
include		<tiuser.h>
declaration	int t_sync(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	t_unbind
include		<tiuser.h>
declaration	int t_unbind(int fildes)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end
