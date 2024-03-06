/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef	_TMEXTERN_H
#define	_TMEXTERN_H

#include <stdio.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termio.h>
#include <sys/stermio.h>
#include <sys/termiox.h>
#include "tmstruct.h"

#ifdef	__cplusplus
extern "C" {
#endif

/* admutil.c	*/
	extern	int	find_label(FILE *, char *);

/* sttytable.c	*/
	extern	const char *not_supported[];

/* sttyparse.c	*/
#ifdef EUC
	extern	char	*sttyparse(int, char *[], int, struct termio *,
	    struct termios *, struct termiox *, struct winsize *,
	    eucwidth_t *, struct eucioc *, ldterm_cs_data_user_t *,
	    ldterm_cs_data_user_t *);
	extern	int	get_ttymode(int, struct termio *, struct termios *,
	    struct stio *, struct termiox *, struct winsize *,
	    struct eucioc *, ldterm_cs_data_user_t *);
	extern	int	set_ttymode(int, int, struct termio *, struct termios *,
	    struct stio *, struct termiox *, struct winsize *,
	    struct winsize *, struct eucioc *, ldterm_cs_data_user_t *, int);
#else
	extern	char	*sttyparse(int, char *[], int, struct termio *,
	    struct termios *, struct termiox *, struct winsize *);
	extern	int	get_ttymode(int, struct termio *, struct termios *,
	    struct stio *, struct termiox *, struct winsize *);
	extern	int	set_ttymode(int, int, struct termio *, struct termios *,
	    struct stio *, struct termiox *, struct winsize *,
	    struct winsize *);
#endif

/* tmautobaud.c	*/
	extern	int	auto_termio(int);
	extern	char	*autobaud(int, int);

/* tmchild.c	*/
	extern	void	write_prompt(int, struct pmtab *, int, int);
	extern	void	timedout(int);
	extern	void	tmchild(struct pmtab *);
	extern	void	sigpoll(int);

/* tmexpress.c	*/
	extern	void	ttymon_express(int, char **);
	extern	void	revokedevaccess(char *, uid_t, gid_t, mode_t);

/* tmhandler.c	*/
	extern	void	do_poll(struct pollfd *, int);
	extern	void	sigalarm(int);
	extern	void	sigterm(int);
	extern	void	sigchild(int);
	extern	void	sigpoll_catch(int);
	extern	void	state_change(void);
	extern	void	re_read(void);
	extern	void	got_carrier(struct pmtab *);

/* tmlock.c	*/
	extern	int	tm_checklock(int);
	extern	int	tm_lock(int);
	extern	int	check_session(int);
	extern	char	*lastname(char *);

/* tmlog.c	*/
	extern	void	log(const char *, ...);
	extern	void	fatal(const char *, ...);
	extern	void	openttymonlog(void);

/* tmparse.c	*/
	extern	char	*getword(char *, int *, int);
	extern	char	quoted(char *, int *);

/* tmpeek.c	*/
	extern	int	poll_data(void);
	extern	void	sigint(int);

/* tmpmtab.c	*/
	extern	void	read_pmtab(void);
	extern	void	purge(void);

/* tmsac.c	*/
	extern	void	openpid(void);
	extern	void	openpipes(void);
	extern	void	get_environ(void);
	extern	void	sacpoll(void);

/* tmsig.c	*/
	extern	void catch_signals(void);
	extern	void child_sigcatch(void);

/* tmterm.c	*/
	extern  int	push_linedisc(int, char *, char *);
	extern	int	set_termio(int, char *, char *, int, long);
	extern	int	initial_termio(int, struct pmtab *);
	extern	int	hang_up_line(int);
	extern	void	flush_input(int);

/* tmttydefs.c	*/
	extern	void	read_ttydefs(const char *, int);
	extern	struct	Gdef *find_def(char *);
	extern	void	mkargv(char *, char **, int *, int);
	extern	int	check_flags(char *);
	extern	char	*strsave(char *);

/* tmutmp.c	*/
	extern	int	account(char *);
	extern	void	cleanut(pid_t, int);
	extern	int	checkut_line(char *line);
	extern	void	getty_account(char *);

/* tmutil.c	*/
	extern	int	check_device(char *);
	extern	int	check_cmd(char *);
	extern	void	cons_printf(const char *, ...);
	extern	void	copystr(char *, char *);
	extern	int	strcheck(char *, int);
	extern	int	vml(char *);

/* misc sys call or lib function call */
	extern	int	check_version(int, char *);

#ifdef	SYS_NAME
	extern	void sys_name(int);
#endif


/* tmglobal.c	*/
	extern	struct	Gdef DEFAULT;
	extern	int	Retry;
	extern	struct	rlimit Rlimit;
	extern	struct	pmtab	*PMtab;
	extern	struct	pollfd	*Pollp;
	extern	int	Nentries;

	extern	int	Npollfd;

	extern	struct	Gdef Gdef[];
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

	extern	int	Maxfiles;
	extern	int	Maxfds;

	extern	char	**environ;
	extern	char	*optarg;
	extern	int	optind, opterr;

	extern	int	Nlocked;

	extern	sigset_t	Origmask;
	extern	struct	sigaction	Sigalrm;	/* SIGALRM */
	extern	struct	sigaction	Sigcld;		/* SIGCLD */
	extern	struct	sigaction	Sigint;		/* SIGINT */
	extern	struct	sigaction	Sigpoll;	/* SIGPOLL */
	extern	struct	sigaction	Sigquit;	/* SIGQUIT */
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

/* ttymon.c	*/
	extern	struct	Gdef *get_speed(struct pmtab *);
	extern	void	open_device(struct pmtab *);
	extern	void	set_softcar(struct pmtab *);
	extern	void	setup_PCpipe(void);

/* ulockf.c	*/
	extern	int	fd_cklock(int);
	extern	int	fd_mklock(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _TMEXTERN_H */
