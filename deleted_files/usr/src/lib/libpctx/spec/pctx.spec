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
# lib/libpctx/spec/pctx.spec

function	pctx_create
include		<libpctx.h>
declaration	pctx_t *pctx_create(const char *filename, char *const *argv, \
			void *arg, int verbose, pctx_errfn_t *errfn)
version		SUNW_1.1
exception	( $return == 0 )
end

function	pctx_capture
include		<libpctx.h>
declaration	pctx_t *pctx_capture(pid_t pid, \
			void *arg, int verbose, pctx_errfn_t *errfn)
version		SUNW_1.1
exception	( $return == 0 )
end

function	pctx_set_events
include		<libpctx.h>
declaration	int pctx_set_events(pctx_t *, ...)
version		SUNW_1.1
exception	( $return == -1 )
end

function	pctx_run
include		<libpctx.h>
declaration	int pctx_run(pctx_t *pctx, uint_t msec, uint_t nsamples, \
			int (*tick)(pctx_t *, pid_t, id_t, void *))
version		SUNW_1.1
exception	( $return != 0 )
end

function	pctx_release
include		<libpctx.h>
declaration	void pctx_release(pctx_t *pctx)
version		SUNW_1.1
end

function	__pctx_cpc
include		<libpctx.h>
declaration	int __pctx_cpc(pctx_t *pctx, struct __cpc *cpc,\
			int cmd, id_t lwpid, void *data1, void *data2, \
			void *data3, int bufsize);
version		SUNWprivate_1.1
exception	( $return == -1 )
end

function	__pctx_cpc_register_callback
include		<libpctx.h>
declaration	void __pctx_cpc_register_callback(void (*arg)(struct __cpc *, \
			struct __pctx *))
version		SUNWprivate_1.1
end
