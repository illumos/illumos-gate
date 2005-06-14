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

function	_xti_accept
include		<xti.h>, <stropts.h>
declaration	int _xti_accept(int fd, int resfd, const struct t_call *call)
version		SUNW_1.1
end		

function	_xti_alloc
include		<xti.h>, <stropts.h>
declaration	void * _xti_alloc(int fd, int struct_type, int fields)
version		SUNW_1.1
end		

function	_xti_bind
include		<xti.h>, <stropts.h>
declaration	int _xti_bind(int fd, const struct t_bind *req, \
			struct t_bind *ret)
version		SUNW_1.1
end		

function	_xti_close
include		<xti.h>, <stropts.h>
declaration	int _xti_close(int fd)
version		SUNW_1.1
end		

function	_xti_connect
include		<xti.h>, <stropts.h>
declaration	int _xti_connect(int fd, const struct t_call *sndcall, \
			struct t_call *rcvcall)
version		SUNW_1.1
end		

function	_xti_error
include		<xti.h>, <stropts.h>
declaration	int _xti_error(const char *errmsg)
version		SUNW_1.1
end		

function	_xti_free
include		<xti.h>, <stropts.h>
declaration	int _xti_free(void *ptr, int struct_type)
version		SUNW_1.1
end		

function	_xti_getinfo
include		<xti.h>, <stropts.h>
declaration	int _xti_getinfo(int fd, struct t_info *info)
version		SUNW_1.1
end		

function	_xti_getprotaddr
include		<xti.h>, <stropts.h>
declaration	int _xti_getprotaddr(int fd, struct t_bind *boundaddr, \
			struct t_bind *peeraddr)
version		SUNW_1.1
end		

function	_xti_getstate
include		<xti.h>, <stropts.h>
declaration	int _xti_getstate(int fd)
version		SUNW_1.1
end		

function	_xti_listen
include		<xti.h>, <stropts.h>
declaration	int _xti_listen(int fd, struct t_call *call)
version		SUNW_1.1
end		

function	_xti_look
include		<xti.h>, <stropts.h>
declaration	int _xti_look(int fd)
version		SUNW_1.1
end		

function	_xti_open
include		<xti.h>, <stropts.h>
declaration	int _xti_open(const char *path, int flags, struct t_info *info)
version		SUNW_1.1
end		

function	_xti_optmgmt
include		<xti.h>, <stropts.h>
declaration	int _xti_optmgmt(int fd, const struct t_optmgmt *req, \
			struct t_optmgmt *ret)
version		SUNW_1.1
end		

function	_xti_rcv
include		<xti.h>, <stropts.h>
declaration	int _xti_rcv(int fd, void *buf, unsigned int nbytes, int *flags)
version		SUNW_1.1
end		

function	_xti_rcvconnect
include		<xti.h>, <stropts.h>
declaration	int _xti_rcvconnect(int fd, struct t_call *call)
version		SUNW_1.1
end		

function	_xti_rcvdis
include		<xti.h>, <stropts.h>
declaration	int _xti_rcvdis(int fd, struct t_discon *discon)
version		SUNW_1.1
end		

function	_xti_rcvrel
include		<xti.h>, <stropts.h>
declaration	int _xti_rcvrel(int fd)
version		SUNW_1.1
end		

function	_xti_rcvudata
include		<xti.h>, <stropts.h>
declaration	int _xti_rcvudata(int fd, struct t_unitdata *unitdata, \
			int *flags)
version		SUNW_1.1
end		

function	_xti_rcvuderr
include		<xti.h>, <stropts.h>
declaration	int _xti_rcvuderr(int fd, struct t_uderr *uderr)
version		SUNW_1.1
end		

function	_xti_snd
include		<xti.h>, <stropts.h>
declaration	int _xti_snd(int fd, void *buf, unsigned int nbytes, int flags)
version		SUNW_1.1
end		

function	_xti_snddis
include		<xti.h>, <stropts.h>
declaration	int _xti_snddis(int fd, const struct t_call *call)
version		SUNW_1.1
end		

function	_xti_sndrel
include		<xti.h>, <stropts.h>
declaration	int _xti_sndrel(int fd)
version		SUNW_1.1
end		

function	_xti_sndudata
include		<xti.h>, <stropts.h>
declaration	int _xti_sndudata(int fd, const struct t_unitdata *unitdata)
version		SUNW_1.1
end		

function	_xti_strerror
include		<xti.h>, <stropts.h>
declaration	const char * _xti_strerror(int errnum)
version		SUNW_1.1
end		

function	_xti_sync
include		<xti.h>, <stropts.h>
declaration	int _xti_sync(int fd)
version		SUNW_1.1
end		

function	_xti_unbind
include		<xti.h>, <stropts.h>
declaration	int _xti_unbind(int fd)
version		SUNW_1.1
end		

function	_xti_rcvreldata
include		<xti.h>, <stropts.h>
declaration	int _xti_rcvreldata(int fd, struct t_discon *discon)
version		SUNW_1.6
end		

function	_xti_rcvv
include		<xti.h>, <stropts.h>
declaration	int _xti_rcvv(int fd, struct t_iovec *tiov, \
			unsigned int tiovcount, int *flags)
version		SUNW_1.6
end		

function	_xti_rcvvudata
include		<xti.h>, <stropts.h>
declaration	int _xti_rcvvudata(int fd, struct t_unitdata *unitdata, \
			struct t_iovec *tiov, unsigned int tiovcount, \
			int *flags)
version		SUNW_1.6
end		

function	_xti_sndreldata
include		<xti.h>, <stropts.h>
declaration	int _xti_sndreldata(int fd, struct t_discon *discon)
version		SUNW_1.6
end		

function	_xti_sndv
include		<xti.h>, <stropts.h>
declaration	int _xti_sndv(int fd, const struct t_iovec *tiov, \
			unsigned int tiovcount, int flags)
version		SUNW_1.6
end		

function	_xti_sndvudata
include		<xti.h>, <stropts.h>
declaration	int _xti_sndvudata(int fd, struct t_unitdata *unitdata, \
			struct t_iovec *tiov, unsigned int tiovcount)
version		SUNW_1.6
end		

function	_xti_sysconf
include		<xti.h>, <stropts.h>
declaration	int _xti_sysconf(int name)
version		SUNW_1.6
end		

function	_xti_xns5_accept
include		<xti.h>, <stropts.h>
declaration	int _xti_xns5_accept(int fd, int resfd, \
			const struct t_call *call)
version		SUNW_1.6
end		

function	_xti_xns5_snd
include		<xti.h>, <stropts.h>
declaration	int _xti_xns5_snd(int fd, void *buf, \
			unsigned int nbytes, int flags)
version		SUNW_1.6
end		

