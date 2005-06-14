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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.5*/


extern	void	log();
extern	void	initialize();
extern	void	openlog();
extern	void	opendebug();
extern	void	debug();
extern	void	insert();
extern	void	startpms();
extern	void	startit();
extern	void	pollpms();
extern	void	pollfail();
extern	void	startpoll();
extern	void	sigpoll();
extern	void	sendpmmsg();
extern	void	purge();
extern	void	parse();
extern	void	read_table();
extern	void	readpipe();
extern	void	error();
extern	void	replace();
extern	void	reap();
extern	void	sendack();
extern	void	account();
extern	void	cleanutx();
extern	void	readutmpx();
extern	void	quit();
extern	void	usage();

extern	FILE	*open_temp();

extern	struct	sactab	*read_entry();
extern	struct	sactab	*findpm();

extern	char	*trim();
extern	char	*pstate();
extern	char	*nexttok();
extern	char	**mkargv();
extern	char	*make_tempname();
extern	char	**dump_table();

extern	time_t	time();
extern	long	atol();
extern	char	*ctime();
extern	char	*strchr();
extern	char	*strrchr();
extern	char	*strcat();
extern	char	*strpbrk();
extern	char	*strtok();
extern	char	*strcpy();
extern	char	*fgets();
extern	char	*malloc();
extern	char	*calloc();
extern	char	*mktemp();
extern	void	free();
extern	void	setutent();
extern	void	endutent();
extern	struct	utmp	*getutid();
extern	struct	utmp	*getutent();

extern	int	N_msgs;
extern	unsigned	Stime;
extern	int	Sfd;
extern	int	Cfd;
extern	int	Nentries;
extern	struct	sactab	*Sactab;
extern	struct	errmsg	Msgs[];
extern	char	Scratch[];

extern	char	Comment[];
extern	int	Saferrno;

extern	char	**environ;
extern	int	errno;
extern	char	*optarg;
extern	int	optind;
extern	int	opterr;
