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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef	__TMEXTERN_H
#define	__TMEXTERN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

	extern	void	setup_PCpipe();

/* tmautobaud.c	*/
	extern	int	auto_termio();
	extern	char	*autobaud();

/* tmchild.c 	*/
	extern	void	write_prompt();
	extern 	void 	timedout();

/* tmexpress.c 	*/
	extern	void	ttymon_express();

/* tmhandler.c 	*/
	extern	void	do_poll();
	extern 	void 	sigterm();
	extern 	void 	sigchild();
	extern 	void	state_change();
	extern 	void	re_read();
	extern 	void	got_carrier();

/* tmlock.c 	*/
	extern	int	tm_checklock();
	extern	int	tm_lock();

/* tmlog.c 	*/
	extern 	void 	log(const char *, ...);
	extern 	void 	fatal(const char *, ...);
	extern	void	openttymonlog(void);

/* tmparse.c 	*/
	extern	char	*getword();
	extern	char	quoted();

/* tmpeek.c 	*/
	extern	int	poll_data();

/* tmpmtab.c 	*/
	extern	void	read_pmtab();
	extern	void	purge();

/* tmsac.c 	*/
	extern 	void	openpid();
	extern 	void	openpipes();
	extern 	void	get_environ();
	extern	void	sacpoll();

/* tmsig.c 	*/
	extern 	void catch_signals();
	extern 	void child_sigcatch();

/* tmterm.c 	*/
	extern  int	push_linedisc();
	extern	int	set_termio();
	extern	int	initial_termio();
	extern	int	hang_up_line();
	extern	void 	flush_input();

/* tmttydefs.c 	*/
	extern	void	read_ttydefs();
	extern 	struct 	Gdef *find_def();
	extern  char 	*getword();
	extern	void	mkargv();

/* tmutmp.c 	*/
	extern 	int 	account();
	extern 	void 	cleanut();

/* tmutil.c 	*/
	extern	int	check_device();
	extern	int	check_cmd();
	extern	void	cons_printf(const char *, ...);

/* misc sys call or lib function call */
	extern	int	check_version();
	extern	int	fchown();
	extern	int	fchmod();

#ifdef	SYS_NAME
	extern 	void sys_name();
#endif


/* tmglobal.c 	*/
	extern	struct	pmtab	*PMtab;
	extern	int	Nentries;

	extern	int	Npollfd;

	extern	struct 	Gdef Gdef[];
	extern	int	Ndefs;
	extern	long	Mtime;

	extern	FILE	*Logfp;
	extern	int	Sfd, Pfd;
	extern	int	PCpipe[];
	extern	int	Lckfd;

	extern	char	State;
	extern	char	*Istate;
	extern	char	*Tag;
	extern	int	Reread_flag;

	extern	int 	Maxfiles;
	extern	int 	Maxfds;

	extern	char	**environ;
	extern	char	*optarg;
	extern	int	optind, opterr;

	extern	int	Nlocked;

	extern	sigset_t	Origmask;
	extern	struct	sigaction	Sigalrm;	/* SIGALRM */
	extern	struct	sigaction	Sigcld;		/* SIGCLD */
	extern	struct	sigaction	Sigint;		/* SIGINT */
	extern	struct	sigaction	Sigpoll;	/* SIGPOLL */
	extern	struct	sigaction	Sigterm;	/* SIGTERM */
#ifdef	DEBUG
	extern	struct	sigaction	Sigusr1;	/* SIGUSR1 */
	extern	struct	sigaction	Sigusr2;	/* SIGUSR2 */
#endif

#ifdef	DEBUG
	extern	FILE	*Debugfp;
	extern	void	debug(const char *, ...);
#endif

	extern	uid_t	Uucp_uid;
	extern	gid_t	Tty_gid;
	extern	struct	strbuf *peek_ptr;

	extern	int	Logmaxsz;
	extern	int	Splflag;

#ifdef	__cplusplus
}
#endif

#endif	/* __TMEXTERN_H */
