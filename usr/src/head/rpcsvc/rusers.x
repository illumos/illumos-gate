/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 1991 Sun Microsystems, Inc.
 * #ident	"%Z%%M%	%I%	%E% SMI"
 */

%/*
% * Find out about remote users
% */

const RUSERS_MAXUSERLEN = 32;
const RUSERS_MAXLINELEN = 32;
const RUSERS_MAXHOSTLEN = 257;

struct rusers_utmp {
	string ut_user<RUSERS_MAXUSERLEN>;	/* aka ut_name */
	string ut_line<RUSERS_MAXLINELEN>;	/* device */
	string ut_host<RUSERS_MAXHOSTLEN>;	/* host user logged on from */
	int ut_type;				/* type of entry */
	int ut_time;				/* time entry was made */
	unsigned int ut_idle;			/* minutes idle */
};

typedef rusers_utmp utmp_array<>;

#ifdef RPC_HDR
%
%/*
% * Values for ut_type field above.
% */
#endif
const	RUSERS_EMPTY = 0;
const	RUSERS_RUN_LVL = 1;
const	RUSERS_BOOT_TIME = 2;
const	RUSERS_OLD_TIME = 3;
const	RUSERS_NEW_TIME = 4;
const	RUSERS_INIT_PROCESS = 5;
const	RUSERS_LOGIN_PROCESS = 6;
const	RUSERS_USER_PROCESS = 7;
const	RUSERS_DEAD_PROCESS = 8;
const	RUSERS_ACCOUNTING = 9;

program RUSERSPROG {

	version RUSERSVERS_3 {
		int
		RUSERSPROC_NUM(void) = 1;

		utmp_array
		RUSERSPROC_NAMES(void) = 2;

		utmp_array
		RUSERSPROC_ALLNAMES(void) = 3;
	} = 3;

} = 100002;

#ifdef RPC_HDR
%
%
%
%/*
% * The following structures are used by version 2 of the rusersd protocol.
% * They were not developed with rpcgen, so they do not appear as RPCL.
% */
%
%#define	RUSERSVERS_IDLE 2
%#define	RUSERSVERS 3		/* current version */
%#define	MAXUSERS 100
%
%/*
% * This is the structure used in version 2 of the rusersd RPC service.
% * It corresponds to the utmp structure for BSD systems.
% */
%struct ru_utmp {
%	char	ut_line[8];		/* tty name */
%	char	ut_name[8];		/* user id */
%	char	ut_host[16];		/* host name, if remote */
%	time_t	ut_time;		/* time on */
%};
%
%struct utmpidle {
%	struct ru_utmp ui_utmp;
%	unsigned ui_idle;
%};
%
%struct utmpidlearr {
%	struct utmpidle **uia_arr;
%	int uia_cnt;
%};
%
%int xdr_utmpidlearr();
%
%#if defined(__STDC__) || defined(__cplusplus)
%enum clnt_stat rusers(char *host, struct utmpidlearr *up);
%int rnusers(char *host);
%#else
%enum clnt_stat rusers();
%int rnusers();
%#endif
%
#endif
