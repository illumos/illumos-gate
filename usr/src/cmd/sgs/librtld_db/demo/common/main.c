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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <procfs.h>
#include <sys/auxv.h>
#include <libelf.h>
#include <sys/param.h>
#include <sys/machelf.h>
#include <stdarg.h>

#include <proc_service.h>

#include "rdb.h"
#include "disasm.h"
#include "gram.h"

#define	PROCSIZE	20

static void
init_proc()
{
	int		pfd;
	char		procname[PROCSIZE];
	sigset_t	sigset;
	fltset_t	fltset;
	sysset_t	sysset;
	long		oper, pflags;
	struct iovec	piov[2];

	/*
	 * open our own /proc file and set tracing flags
	 */
	(void) snprintf(procname, PROCSIZE, "/proc/%d/ctl", EC_SWORD(getpid()));
	if ((pfd = open(procname, O_WRONLY)) < 0) {
		(void) fprintf(stderr, "can't open %s\n", procname);
		exit(1);
	}

	/*
	 * inherit on fork, and kill-on-last-close
	 */
	oper = PCSET;
	piov[0].iov_base = (caddr_t)(&oper);
	piov[0].iov_len = sizeof (oper);
	pflags = PR_FORK;
	piov[1].iov_base = (caddr_t)&pflags;
	piov[1].iov_len = sizeof (pflags);

	if (writev(pfd, piov, 2) == -1)
		perr("init_proc: PCSET");

	/*
	 * no signal tracing
	 */
	oper = PCSTRACE;
	premptyset(&sigset);
	piov[1].iov_base = (caddr_t)&sigset;
	piov[1].iov_len = sizeof (sigset);
	if (writev(pfd, piov, 2) == -1)
		perr("PCSTRACE");

	/*
	 * no fault tracing
	 */
	oper = PCSFAULT;
	premptyset(&fltset);
	piov[1].iov_base = (caddr_t)&fltset;
	piov[1].iov_len = sizeof (fltset);
	if (writev(pfd, piov, 2) == -1)
		perr("PCSFAULT");

	/*
	 * no syscall tracing
	 */
	oper = PCSENTRY;
	premptyset(&sysset);
	piov[1].iov_base = (caddr_t)&sysset;
	piov[1].iov_len = sizeof (sysset);
	if (writev(pfd, piov, 2) == -1)
		perr("PSENTRY");

	/*
	 * except exit from exec() or execve()
	 */
	oper = PCSEXIT;
	premptyset(&sysset);
	praddset(&sysset, SYS_execve);
	if (writev(pfd, piov, 2) == -1)
		perr("PCSEXIT");

	(void) close(pfd);
}

int
main(int argc, char *argv[])
{
	int			pctlfd;
	int			pstatusfd;
	char			procname[PROCSIZE];
	char			*command;
	char			*rdb_commands = NULL;
	pid_t			cpid;
	pstatus_t		pstatus;
	sysset_t		sysset;
	int			c;
	int			error = 0;
	long			oper;
	struct iovec		piov[2];
	extern FILE		*yyin;

	command = argv[0];

	while ((c = getopt(argc, argv, "f:")) != EOF)
		switch (c) {
		case 'f':
			rdb_commands = optarg;
			break;
		case '?':
			break;
		}

	if (error || (optind == argc)) {
		(void) printf("usage: %s [-f file] executable "
		    "[executable arguments ...]\n", command);
		(void) printf("\t-f	command file\n");
		exit(1);
	}

	/*
	 * set up for tracing the child.
	 */
	init_proc();

	/*
	 * create a child to fork and exec from.
	 */
	if ((cpid = fork()) == 0) {
		(void) execv(argv[optind], &argv[optind]);
		perr(argv[optind]);
	}

	if (cpid == -1)	/* fork() failure */
		perr(command);

	/*
	 * initialize libelf
	 */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr, "elf_version() failed: %s\n",
		    elf_errmsg(0));
		exit(1);
	}

	/*
	 * initialize librtld_db
	 */
	if (rd_init(RD_VERSION) != RD_OK) {
		(void) fprintf(stderr, "librtld_db::rd_init() failed: version "
		    "submitted: %d\n", RD_VERSION);
		exit(1);
	}

	/* rd_log(1); */

	/*
	 * Child should now be waiting after the successful
	 * exec.
	 */
	(void) snprintf(procname, PROCSIZE, "/proc/%d/ctl", EC_SWORD(cpid));
	(void) printf("parent: %d child: %d child procname: %s\n",
	    EC_SWORD(getpid()), EC_SWORD(cpid), procname);
	if ((pctlfd = open(procname, O_WRONLY)) < 0) {
		perror(procname);
		(void) fprintf(stderr, "%s: can't open child %s\n",
		    command, procname);
		exit(1);
	}

	/*
	 * wait for child process.
	 */
	oper = PCWSTOP;
	piov[0].iov_base = (caddr_t)&oper;
	piov[0].iov_len = sizeof (oper);
	if (writev(pctlfd, piov, 1) == -1)
		perr("PCWSTOP");

	/*
	 * open /proc/<cpid>/status
	 */
	(void) snprintf(procname, PROCSIZE, "/proc/%d/status", EC_SWORD(cpid));
	if ((pstatusfd = open(procname, O_RDONLY)) == -1)
		perr(procname);

	if (read(pstatusfd, &pstatus, sizeof (pstatus)) == -1)
		perr("status read failed");

	/*
	 * Make sure that it stopped where we expected.
	 */
	while ((pstatus.pr_lwp.pr_why == PR_SYSEXIT) &&
	    (pstatus.pr_lwp.pr_what == SYS_execve)) {
		long	pflags = 0;
		if (!(pstatus.pr_lwp.pr_reg[R_PS] & ERRBIT)) {
			/* successfull exec(2) */
			break;
		}

		oper = PCRUN;
		piov[1].iov_base = (caddr_t)&pflags;
		piov[1].iov_len = sizeof (pflags);
		if (writev(pctlfd, piov, 2) == -1)
			perr("PCRUN1");

		oper = PCWSTOP;
		if (writev(pctlfd, piov, 1) == -1)
			perr("PCWSTOP");

		if (read(pstatusfd, &pstatus, sizeof (pstatus)) == -1)
			perr("status read failed");
	}

	premptyset(&sysset);
	oper = PCSEXIT;
	piov[1].iov_base = (caddr_t)&sysset;
	piov[1].iov_len = sizeof (sysset);
	if (writev(pctlfd, piov, 2) == -1)
		perr("PIOCSEXIT");

	/*
	 * Did we stop where we expected ?
	 */
	if ((pstatus.pr_lwp.pr_why != PR_SYSEXIT) ||
	    (pstatus.pr_lwp.pr_what != SYS_execve)) {
		long	pflags = 0;

		(void) fprintf(stderr, "Didn't catch the exec, why: %d "
		    "what: %d\n", pstatus.pr_lwp.pr_why,
		    pstatus.pr_lwp.pr_what);

		oper = PCRUN;
		piov[1].iov_base = (caddr_t)&pflags;
		piov[1].iov_len = sizeof (pflags);
		if (writev(pctlfd, piov, 2) == -1)
			perr("PCRUN2");
		exit(1);
	}

	(void) ps_init(pctlfd, pstatusfd, cpid, &proch);

	if (rdb_commands) {
		if ((yyin = fopen(rdb_commands, "r")) == NULL) {
			(void) printf("unable to open %s for input\n",
			    rdb_commands);
			perr("fopen");
		}
	} else {
		proch.pp_flags |= FLG_PP_PROMPT;
		rdb_prompt();
	}
	(void) yyparse();

	if (proch.pp_flags & FLG_PP_PACT) {
		long	pflags = PRCFAULT;

		(void) printf("\ncontinuing the hung process...\n");

		pctlfd = proch.pp_ctlfd;
		(void) ps_close(&proch);

		oper = PCRUN;
		piov[1].iov_base = (caddr_t)&pflags;
		piov[1].iov_len = sizeof (pflags);
		if (writev(pctlfd, piov, 2) == -1)
			perr("PCRUN2");
		(void) close(pctlfd);
	}

	return (0);
}
