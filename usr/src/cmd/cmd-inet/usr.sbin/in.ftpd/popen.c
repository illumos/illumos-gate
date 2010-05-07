/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/****************************************************************************    
  Copyright (c) 1999,2000 WU-FTPD Development Group.  
  All rights reserved.
   
  Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994  
    The Regents of the University of California. 
  Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.  
  Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.  
  Portions Copyright (c) 1989 Massachusetts Institute of Technology.  
  Portions Copyright (c) 1998 Sendmail, Inc.  
  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P.  Allman.  
  Portions Copyright (c) 1997 by Stan Barber.  
  Portions Copyright (c) 1997 by Kent Landfield.  
  Portions Copyright (c) 1991, 1992, 1993, 1994, 1995, 1996, 1997  
    Free Software Foundation, Inc.    
   
  Use and distribution of this software and its source code are governed   
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").  
   
  If you did not receive a copy of the license, it may be obtained online  
  at http://www.wu-ftpd.org/license.html.  
   
  $Id: popen.c,v 1.16 2000/07/01 18:17:39 wuftpd Exp $  
   
****************************************************************************/
#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif
#include "pathnames.h"
#include "proto.h"

/* 
 * Special version of popen which avoids call to shell.  This insures noone
 * may create a pipe to a hidden program as a side effect of a list or dir
 * command. 
 */
static int popen_fd = -1;
static pid_t popen_pid = -1;
/*
 * The globbed argv could end up being huge, so we must dynamically allocate
 * it.  Allocate it in chunks of GARGV_INC pointers.
 */
#define GARGV_INC	100
#define ARGV_INC	5

static char **argv;
static char **gargv;
static int argv_size;
static int gargv_size;

FILE *ftpd_popen(char *program, char *type, int closestderr)
{
    register char *cp;
    FILE *iop = NULL;
    int argc, gargc, pdes[2], i, devnullfd;
    char **pop, *vv[2];
    extern char *globerr;

    /*
     * ftpd never needs more than one pipe open at a time, so only one PID is
     * stored (in popen_pid). Protect against multiple pipes in case this
     * changes.
     */
    if (popen_fd != -1)
	return (NULL);

    if ((*type != 'r' && *type != 'w') || type[1])
	return (NULL);

    if (gargv == NULL) {
	gargv = (char **)malloc(GARGV_INC * sizeof (char *));
	if (gargv == NULL) {
	    return (NULL);
	}
	gargv_size = GARGV_INC;
    }

    if (argv == NULL) {
	argv = (char **)malloc(ARGV_INC * sizeof (char *));
	if (argv == NULL) {
	    return (NULL);
	}
	argv_size = ARGV_INC;
    }

    if (pipe(pdes) < 0)
	return (NULL);

    /* empty the array */
    (void) memset((void *) argv, 0, argv_size * sizeof(char *));
    /* break up string into pieces */
    for (argc = 0, cp = program; ;cp = NULL) {
	if (!(argv[argc++] = strtok(cp, " \t\n"))) {
	    break;
	}
	if (argc >= argv_size) {
	    char **tmp;

	    tmp = (char **)realloc(argv,
		(argv_size + ARGV_INC) * sizeof (char *));
	    if (tmp == NULL) {
		(void) close(pdes[0]);
		(void) close(pdes[1]);
		return (NULL);
	    } else {
		argv = tmp;
		argv_size += ARGV_INC;
	    }
	}
    }

    /* glob each piece */
    gargv[0] = argv[0];
    for (gargc = argc = 1; argv[argc]; argc++) {
	if (!(pop = ftpglob(argv[argc], B_TRUE)) || globerr != NULL) {	/* globbing failed */
	    if (pop) {
		blkfree(pop);
		free((char *) pop);
	    }
	    vv[0] = strspl(argv[argc], "");
	    vv[1] = NULL;
	    pop = copyblk(vv);
	}
	argv[argc] = (char *) pop;	/* save to free later */
	while (*pop) {
	    gargv[gargc++] = *pop++;
	    if (gargc >= gargv_size) {
		char **tmp;

		tmp = (char **)realloc(gargv,
		    (gargv_size + GARGV_INC) * sizeof (char *));
		if (tmp == NULL) {
		    (void) close(pdes[0]);
		    (void) close(pdes[1]);
		    goto pfree;
		} else {
		    gargv = tmp;
		    gargv_size += GARGV_INC;
		}
	    }
	}
    }
    gargv[gargc] = NULL;

#ifdef SIGCHLD
    (void) signal(SIGCHLD, SIG_DFL);
#endif
    switch (popen_pid = vfork()) {
    case -1:			/* error */
	(void) close(pdes[0]);
	(void) close(pdes[1]);
	goto pfree;
	/* NOTREACHED */
    case 0:			/* child */
	if (*type == 'r') {
	    if (pdes[1] != 1) {
		dup2(pdes[1], 1);
		if (closestderr) {
		    (void) close(2);
		    /* stderr output is written to fd 2, so make sure it isn't
		     * available to be assigned to another file */
		    if ((devnullfd = open(_PATH_DEVNULL, O_RDWR)) != -1) {
			if (devnullfd != 2) {
			    dup2(devnullfd, 2);
			    (void) close(devnullfd);
			}
		    }
		}
		else
		    dup2(pdes[1], 2);	/* stderr, too! */
		(void) close(pdes[1]);
	    }
	    (void) close(pdes[0]);
	}
	else {
	    if (pdes[0] != 0) {
		dup2(pdes[0], 0);
		(void) close(pdes[0]);
	    }
	    (void) close(pdes[1]);
	}
	closefds(3);
	/* begin CERT suggested fixes */
	close(0);
	i = geteuid();
	setid_priv_on(0);
	setgid(getegid());
	setuid(i);
	setid_priv_off(i);
	/* end CERT suggested fixes */
	execv(gargv[0], gargv);
	perror(gargv[0]);
	_exit(1);
    }
    /* parent; assume fdopen can't fail...  */
    if (*type == 'r') {
	iop = fdopen(pdes[0], type);
	(void) close(pdes[1]);
    }
    else {
	iop = fdopen(pdes[1], type);
	(void) close(pdes[0]);
    }
    popen_fd = fileno(iop);

  pfree:for (argc = 1; argv[argc]; argc++) {
	blkfree((char **) argv[argc]);
	free((char *) argv[argc]);
    }
    return (iop);
}

int ftpd_pclose(FILE *iop)
{
    pid_t pid;
#if defined(HAVE_SIGPROCMASK) || (defined(SVR4) && !defined(AUTOCONF))
    sigset_t sig, omask;
    int stat_loc;
    sigemptyset(&sig);
    sigaddset(&sig, SIGINT);
    sigaddset(&sig, SIGQUIT);
    sigaddset(&sig, SIGHUP);
#elif defined (_OSF_SOURCE)
    int omask;
    int status;
#else
    int omask;
    union wait stat_loc;
#endif

    /* pclose returns -1 if stream is not associated with a `popened'
     * command, or, if already `pclosed'. */
    if ((popen_fd == -1) || (popen_fd != fileno(iop)))
	return (-1);
    (void) fclose(iop);
#if defined(HAVE_SIGPROCMASK) || (!defined(AUTOCONF) && defined(SVR4))
    sigprocmask(SIG_BLOCK, &sig, &omask);
#else
    omask = sigblock(sigmask(SIGINT) | sigmask(SIGQUIT) | sigmask(SIGHUP));
#endif

#if (!defined(HAVE_SIGPROCMASK) || (!defined(SVR4) && !defined(AUTOCONF))) && defined (_OSF_SOURCE)
    while ((pid = wait(&status)) != popen_pid && pid != -1);
#elif ! defined(NeXT)
    while ((pid = wait((int *) &stat_loc)) != popen_pid && pid != -1);
#else
    while ((pid = wait(&stat_loc)) != popen_pid && pid != -1);
#endif
    popen_pid = -1;
    popen_fd = -1;
#ifdef SIGCHLD
    (void) signal(SIGCHLD, SIG_IGN);
#endif
#if defined(HAVE_SIGPROCMASK) || (defined(SVR4) && !defined(AUTOCONF))
    sigprocmask(SIG_SETMASK, &omask, (sigset_t *) NULL);
    return (pid == -1 ? -1 : WEXITSTATUS(stat_loc));
#else
    (void) sigsetmask(omask);
#ifdef _OSF_SOURCE
    return (pid == -1 ? -1 : status);
#elif defined(LINUX)
    return (pid == -1 ? -1 : WEXITSTATUS(stat_loc));
#else
    return (pid == -1 ? -1 : stat_loc.w_status);
#endif
#endif
}

#ifdef CLOSEFROM
void closefds(int startfd)
{
    closefrom(startfd);
}
#else

#ifdef HAVE_GETRLIMIT
#include <sys/resource.h>
#endif

void closefds(int startfd)
{
    int i, fds;
#ifdef HAVE_GETRLIMIT
    struct rlimit rlp;
#endif

#ifdef OPEN_MAX
    fds = OPEN_MAX;
#else
    fds = 31;
#endif

#ifdef HAVE_GETRLIMIT
    if ((getrlimit(RLIMIT_NOFILE, &rlp) == 0) &&
	(rlp.rlim_cur != RLIM_INFINITY)) {
	fds = rlp.rlim_cur;
    }
#else
#ifdef HAVE_GETDTABLESIZE
    if ((i = getdtablesize()) > 0)
	fds = i;
#else
#ifdef HAVE_SYSCONF
    fds = sysconf(_SC_OPEN_MAX);
#endif /* HAVE_SYSCONF */
#endif /* HAVE_GETDTABLESIZE */
#endif /* HAVE_GETRLIMIT */

    for (i = startfd; i < fds; i++)
	close(i);
}
#endif /* CLOSEFROM */
