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

%/* from rwall.x */
%
%/*
% * Remote write-all ONC service
% */

#ifdef RPC_HDR
%
#elif RPC_SVC
%
%/*
% *  Server side stub routines for the rpc.rwalld daemon
% */
%
#elif RPC_CLNT
%
%/*
% *  Client side stub routines for the rwall program
% */
%
#endif

typedef string wrapstring<>;	/* Define for RPC library's xdr_wrapstring */

program WALLPROG {
	version WALLVERS {
		/*
		 * There is no procedure 1
		 */
		void
		WALLPROC_WALL (wrapstring) = 2;
	} = 1;
} = 100008;

#ifdef RPC_HDR
%
%
%#if defined(__STDC__) || defined(__cplusplus)
%enum clnt_stat rwall(char *, char *);
%#else
%enum clnt_stat rwall();
%#endif
%
#endif
