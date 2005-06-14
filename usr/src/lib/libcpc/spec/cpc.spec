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
# lib/libpctx/spec/cpc.spec

function	cpc_version
include		<libcpc.h>
declaration	uint_t cpc_version(uint_t)
version		SUNW_1.1
end

function	cpc_getcpuver
include		<libcpc.h>
declaration	int cpc_getcpuver(void)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_getcciname
include		<libcpc.h>
declaration	const char *cpc_getcciname(int cpuver)
version		SUNW_1.1
exception	( $return == 0 )
end

function	cpc_getcpuref
include		<libcpc.h>
declaration	const char *cpc_getcpuref(int cpuver)
version		SUNW_1.1
exception	( $return == 0 )
end

function	cpc_getusage
include		<libcpc.h>
declaration	const char *cpc_getusage(int cpuver)
version		SUNW_1.1
exception	( $return == 0 )
end

function	cpc_getnpic
include		<libcpc.h>
declaration	uint_t cpc_getnpic(int cpuver)
version		SUNW_1.1
exception	( $return == 0 )
end

function	cpc_walk_names
include		<libcpc.h>
declaration	void cpc_walk_names(int cpuver, int regno, void *arg,	       \
			void (*action)(void *arg,			       \
			int regno, const char *name, uint8_t bits))
version		SUNW_1.1
end

function	cpc_seterrfn
include		<libcpc.h>
declaration	void cpc_seterrfn(cpc_errfn_t *errfn)
version		SUNW_1.1
end

function	cpc_strtoevent
include		<libcpc.h>
declaration	int cpc_strtoevent(int cpuver, const char *spec,	       \
			cpc_event_t *event)
version		SUNW_1.1
exception	( $return != 0 )
end

function	cpc_eventtostr
include		<libcpc.h>
declaration	char *cpc_eventtostr(cpc_event_t *event)
version		SUNW_1.1
exception	( $return == 0 )
end

function	cpc_event_accum
include		<libcpc.h>
declaration	void cpc_event_accum(cpc_event_t *accum, cpc_event_t *event)
version		SUNW_1.1
end

function	cpc_event_diff
include		<libcpc.h>
declaration	void cpc_event_diff(cpc_event_t *diff, cpc_event_t *left,      \
			cpc_event_t *right)
version		SUNW_1.1
end

function	cpc_access
include		<libcpc.h>
declaration	int cpc_access(void)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_bind_event
include		<libcpc.h>
declaration	int cpc_bind_event(cpc_event_t *event, int flags)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_take_sample
include		<libcpc.h>
declaration	int cpc_take_sample(cpc_event_t *event)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_count_usr_events
include		<libcpc.h>
declaration	int cpc_count_usr_events(int enable)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_count_sys_events
include		<libcpc.h>
declaration	int cpc_count_sys_events(int enable)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_rele
include		<libcpc.h>
declaration	int cpc_rele(void)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_pctx_bind_event
include		<libpctx.h>, <libcpc.h>
declaration	int cpc_pctx_bind_event(pctx_t *pctx, id_t lwpid,	       \
			cpc_event_t *event, int flags)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_pctx_take_sample
include		<libpctx.h>, <libcpc.h>
declaration	int cpc_pctx_take_sample(pctx_t *pctx, id_t lwpid,	       \
			cpc_event_t *event)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_pctx_rele
include		<libpctx.h>, <libcpc.h>
declaration	int cpc_pctx_rele(pctx_t *pctx, id_t lwpid)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_pctx_invalidate
include		<libpctx.h>, <libcpc.h>
declaration	int cpc_pctx_invalidate(pctx_t *pctx, id_t lwpid)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_shared_open
include		<libcpc.h>
declaration	int cpc_shared_open(void)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_shared_close
include		<libcpc.h>
declaration	void cpc_shared_close(int fd)
version		SUNW_1.1
end

function	cpc_shared_bind_event
include		<libcpc.h>
declaration	int cpc_shared_bind_event(int fd, cpc_event_t *event, int flags)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_shared_take_sample
include		<libcpc.h>
declaration	int cpc_shared_take_sample(int fd, cpc_event_t *event)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_shared_rele
include		<libcpc.h>
declaration	int cpc_shared_rele(int fd)
version		SUNW_1.1
exception	( $return == -1 )
end

function	cpc_open
include		<libcpc.h>
declaration	cpc_t *cpc_open(int vers)
version		SUNW_1.2
exception	( $return == NULL )
end

function	cpc_close
include		<libcpc.h>
declaration	int cpc_close(cpc_t *cpc)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_set_create
include		<libcpc.h>
declaration	cpc_set_t *cpc_set_create(cpc_t *cpc)
version		SUNW_1.2
exception	( $return == NULL )
end

function	cpc_set_destroy
include		<libcpc.h>
declaration	int cpc_set_destroy(cpc_t *cpc, cpc_set_t *set)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_set_add_request
include		<libcpc.h>
declaration	int cpc_set_add_request(cpc_t *cpc, cpc_set_t *set,	\
			const char *event, uint64_t preset, uint_t flags, \
			uint_t nattrs, const cpc_attr_t *attrs)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_request_preset
include		<libcpc.h>
declaration	int cpc_request_preset(cpc_t *cpc, int index, uint64_t preset)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_set_restart
include		<libcpc.h>
declaration	int cpc_set_restart(cpc_t *cpc, cpc_set_t *set)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_buf_create
include		<libcpc.h>
declaration	cpc_buf_t *cpc_buf_create(cpc_t *cpc, cpc_set_t *set)
version		SUNW_1.2
exception	( $return == NULL )
end

function	cpc_buf_destroy
include		<libcpc.h>
declaration	int cpc_buf_destroy(cpc_t *cpc, cpc_buf_t *buf)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_bind_curlwp
include		<libcpc.h>
declaration	int cpc_bind_curlwp(cpc_t *cpc, cpc_set_t *set, uint_t flags)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_bind_cpu
include		<libcpc.h>
declaration	int cpc_bind_cpu(cpc_t *cpc, processorid_t id, cpc_set_t *set, \
			uint_t flags)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_bind_pctx
include		<libcpc.h>
declaration	int cpc_bind_pctx(cpc_t *cpc, pctx_t *pctx, id_t id, \
			cpc_set_t *set, uint_t flags)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_unbind
include		<libcpc.h>
declaration	int cpc_unbind(cpc_t *cpc, cpc_set_t *set)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_set_sample
include		<libcpc.h>
declaration	int cpc_set_sample(cpc_t *cpc, cpc_set_t *set, cpc_buf_t *buf)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_buf_zero
include		<libcpc.h>
declaration	void cpc_buf_zero(cpc_t *cpc, cpc_buf_t *buf)
version		SUNW_1.2
end

function	cpc_buf_sub
include		<libcpc.h>
declaration	void cpc_buf_sub(cpc_t *cpc, cpc_buf_t *ds, cpc_buf_t *a, \
			cpc_buf_t *b)
version		SUNW_1.2
end

function	cpc_buf_add
include		<libcpc.h>
declaration	void cpc_buf_add(cpc_t *cpc, cpc_buf_t *ds, cpc_buf_t *a, \
			cpc_buf_t *b)
version		SUNW_1.2
end

function	cpc_buf_copy
include		<libcpc.h>
declaration	void cpc_buf_copy(cpc_t *cpc, cpc_buf_t *ds, cpc_buf_t *src)
version		SUNW_1.2
end

function	cpc_buf_get
include		<libcpc.h>
declaration	int cpc_buf_get(cpc_t *cpc, cpc_buf_t *buf, int index, \
			uint64_t *val)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_buf_set
include		<libcpc.h>
declaration	int cpc_buf_set(cpc_t *cpc, cpc_buf_t *buf, int index, \
			uint64_t val)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_buf_hrtime
include		<libcpc.h>
declaration	hrtime_t cpc_buf_hrtime(cpc_t *cpc, cpc_buf_t *buf)
version		SUNW_1.2
end

function	cpc_buf_tick
include		<libcpc.h>
declaration	uint64_t cpc_buf_tick(cpc_t *cpc, cpc_buf_t *buf)
version		SUNW_1.2
end

function	cpc_walk_events_all
include		<libcpc.h>
declaration	void cpc_walk_events_all(cpc_t *cpc, void *arg, \
			void (*action)(void *arg, const char *event))
version		SUNW_1.2
end

function	cpc_walk_events_pic
include		<libcpc.h>
declaration	void cpc_walk_events_pic(cpc_t *cpc, uint_t picno, void *arg, \
		    void (*action)(void *arg, uint_t picno, const char *event));
version		SUNW_1.2
end

function	cpc_walk_attrs
include		<libcpc.h>
declaration	void cpc_walk_attrs(cpc_t *cpc, void *arg, \
    void (*action)(void *arg, const char *attr))
version		SUNW_1.2
end

function	cpc_walk_requests
include		<libcpc.h>
declaration	void cpc_walk_requests(cpc_t *cpc, cpc_set_t *set, void *arg, \
    void (*action)(void *arg, int index, const char *event, uint64_t preset,  \
	uint_t flags, int nattrs, const cpc_attr_t *attrs))
version		SUNW_1.2
end

function	cpc_enable
include		<libcpc.h>
declaration	int cpc_enable(cpc_t *cpc)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_disable
include		<libcpc.h>
declaration	int cpc_disable(cpc_t *cpc)
version		SUNW_1.2
exception	( $return == -1 )
end

function	cpc_npic
include		<libcpc.h>
declaration	uint_t cpc_npic(cpc_t *cpc)
version		SUNW_1.2
end

function	cpc_caps
include		<libcpc.h>
declaration	uint_t cpc_caps(cpc_t *cpc)
version		SUNW_1.2
end

function	cpc_cciname
include		<libcpc.h>
declaration	const char *cpc_cciname(cpc_t *cpc)
version		SUNW_1.2
exception	( $return == NULL )
end

function	cpc_cpuref
include		<libcpc.h>
declaration	const char *cpc_cpuref(cpc_t *cpc)
version		SUNW_1.2
exception	( $return == NULL )
end

function	cpc_seterrhndlr
include		<libcpc.h>
declaration	int cpc_seterrhndlr(cpc_t *cpc, cpc_errhndlr_t *fn)
version		SUNW_1.2
exception	( $return == -1 )
end
