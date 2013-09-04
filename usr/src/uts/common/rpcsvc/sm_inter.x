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
%/*
% * Copyright (c) 1986, 1994 by Sun Microsystems, Inc.
% * All rights reserved.
% */

%/* from sm_inter.x */

/*
 * Status monitor protocol specification
 */

program SM_PROG {
	version SM_VERS  {
		/* res_stat = stat_succ if status monitor agrees to monitor */
		/* res_stat = stat_fail if status monitor cannot monitor */
		/* if res_stat == stat_succ, state = state number of site */
                /* sm_name */
		struct sm_stat_res	SM_STAT(struct sm_name) = 1;

		/* res_stat = stat_succ if status monitor agrees to monitor */
		/* res_stat = stat_fail if status monitor cannot monitor */
		/* stat consists of state number of local site */
		struct sm_stat_res	SM_MON(struct mon) = 2;

		/* stat consists of state number of local site */
		struct sm_stat		SM_UNMON(struct mon_id) = 3;

		/* stat consists of state number of local site */
		struct sm_stat		SM_UNMON_ALL(struct my_id) = 4;

		void			SM_SIMU_CRASH(void) = 5;

		void			SM_NOTIFY(struct stat_chge) = 6;
	} = 1;
} = 100024;

const	SM_MAXSTRLEN = 1024;

struct sm_name {
	string mon_name<SM_MAXSTRLEN>;
};

struct my_id {
	string	 my_name<SM_MAXSTRLEN>;	/* name of the site iniates the */
					/* monitoring request */
	int	my_prog;	/* rpc program # of the requesting process */
	int	my_vers;	/* rpc version # of the requesting process */
	int	my_proc;	/* rpc procedure # of the requesting process */
};

struct mon_id {
	string	mon_name<SM_MAXSTRLEN>;	/* name of the site to be monitored */
	struct my_id my_id;
};


struct mon{
	struct mon_id mon_id;
	opaque priv[16]; 	/* private information to store at monitor */
				/* for requesting process */
};


/*
 * state # of status monitor monitonically increases each time
 * status of the site changes:
 * an even number (>= 0) indicates the site is down and
 * an odd number (> 0) indicates the site is up;
 */
struct sm_stat {
	int state;		/* state # of status monitor */
};

enum sm_res {
	stat_succ = 0,		/* status monitor agrees to monitor */
	stat_fail = 1		/* status monitor cannot monitor */
};

struct sm_stat_res {
	sm_res res_stat;
	int state;
};

/*
 * structure of the status message sent by the status monitor to the
 * requesting program when a monitored site changes status.
 */
struct sm_status {
	string mon_name<SM_MAXSTRLEN>;
	int state;
	opaque priv[16];		/* stored private information */
};

/*
 * structure sent between statd's to announce a state change (e.g.,
 * reboot).
 */
struct stat_chge {
	string mon_name<SM_MAXSTRLEN>;
	int state;
};
