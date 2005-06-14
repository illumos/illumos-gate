%/*
% * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
% * Use is subject to license terms.
% *
% * CDDL HEADER START
% *
% * The contents of this file are subject to the terms of the
% * Common Development and Distribution License, Version 1.0 only
% * (the "License").  You may not use this file except in compliance
% * with the License.
% *
% * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
% * or http://www.opensolaris.org/os/licensing.
% * See the License for the specific language governing permissions
% * and limitations under the License.
% *
% * When distributing Covered Code, include this CDDL HEADER in each
% * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
% * If applicable, add the following below this CDDL HEADER, with the
% * fields enclosed by brackets "[]" replaced with your own identifying
% * information: Portions Copyright [yyyy] [name of copyright owner]
% *
% * CDDL HEADER END
% */
%
%#pragma ident	"%Z%%M%	%I%	%E% SMI"
%

#ifdef RPC_SVC
%
%int mdc_in_daemon = 1;
%#include <signal.h>
#endif /* RPC_SVC */

#ifdef RPC_HDR
%#ifndef STRINGARRAY
#endif
typedef string stringarray<>;
#ifdef RPC_HDR
%#define STRINGARRAY
%#endif
#endif

struct mdc_err_t {
	int			mdc_errno; /* errno or negative error code */
	int			mdc_exitcode;	/* child exit code. */
	string			mdc_node<>;	/* associated node */
	string			mdc_misc<>;	/* misc text */
};

%
%/*
% * rpc argument and response structures
% */
struct mdc_bind_res_t {
	mdc_err_t	mdc_status;		/* status of RPC call */
};

struct mdcrpc_proxy_args_t {
	stringarray		argvlist<>;
	stringarray		environment<>;
};

#ifdef RPC_CLNT
%int _mdc_in_daemon = 0;
%#pragma weak mdc_in_daemon = _mdc_in_daemon
%void mdc_clrerror(mdc_err_t *mdcep);

#endif /* RPC_CLNT */

#ifdef RPC_HDR
%
%extern	int	mdc_in_daemon;
%
%/*
% * Null error structure initializer.
% */
%#define	MDC_NULL_ERR	{ 0, NULL, NULL }
%#define	MD_MDC_DEF_TO	{5, 0}		/* 5 seconds */
%#define	MD_MDC_PMAP_TO	{35, 0}		/* 35 seconds */
%#define	MD_MDC_PROXY_TO	{60 * 60, 0 }	/* 1hr */
%
%/*
% * various cluster errors, definition of MDC_NOTINCLUSTER must be changed
% * when new errors are added, since MDC_NOERROR has to come out to
% * be zero!
% */
enum mdc_errno_t {
	MDC_PROXYKILLED = -13,	/* remote was killed by signal */
	MDC_PROXYNOFORK,	/* could not fork remote */
	MDC_PROXYFAILED,	/* remote exited non-zero */
	MDC_NOTINCLUSTER,	/* host is not a node */
	MDC_NOACCESS,
	MDC_NOACCESS_CCR,
	MDC_RPCFAILED,
	BIND_LINKISDIR,	
	BIND_NOACCESS_SHARED,
	BIND_LOCALSET,
	BIND_NODISKSETCLASS,
	BIND_NOACCESS_DEVICE,
	BIND_BADDEVICE,
	MDC_NOERROR
};

%
%/*
% * Set MDC_THISVERS to the newest version of the protocol
% * This allows the preprocessor to force an error if the
% * protocol changes, since the kernel xdr routines may need to be
% * recoded.  Note that we can't explicitly set the version to a
% * symbol as rpcgen will then create erroneous routine names.
% */
%#define	MDC_V1			1
%#define	MDC_ORIGVERS		MDC_V1
%#define	MDC_THISVERS		1
%
%/* All powerful group 14 */
%#define	MDC_GID			14
%
%/*
% * External reference to constant null error struct. (declared in med_xdr.c)
% */
%extern	const	mdc_err_t		mdc_null_err;
%extern	const	struct	timeval		md_mdc_def_timeout;
%extern	const	struct	timeval		md_mdc_pmap_timeout;
%extern const	struct	timeval		md_mdc_proxy_timeout;
%
%/*
% * Some useful defines
% */
%#define	MDC_SERVNAME	"rpc.metacld"
%#define	MDC_SVC		"metacl"
%
#endif /* RPC_HDR */

#ifdef	RPC_XDR
%
%/*
% * Constant null error struct.
% */
%const		mdc_err_t		mdc_null_err = MDC_NULL_ERR;
%const	struct	timeval			md_mdc_def_timeout = MD_MDC_DEF_TO;
%const	struct	timeval			md_mdc_pmap_timeout = MD_MDC_PMAP_TO;
%const	struct	timeval			md_mdc_proxy_timeout = MD_MDC_PROXY_TO;

#endif	/* RPC_XDR */


%
%/*
% * services available
% */
program MDC_PROG {
	version MDC_VERS {
		mdc_bind_res_t	mdc_null(void)			= 0; 
		mdc_bind_res_t	mdc_bind_devs(void)		= 1;
		mdc_bind_res_t	mdc_proxy(mdcrpc_proxy_args_t)	= 2;
	} = 1;
} = 100281;
