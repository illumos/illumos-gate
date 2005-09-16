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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<signal.h>
#include	<sys/types.h>	/* abs k18 */
#include	<errno.h>
#include	<stdarg.h>
#include	"wish.h"
#include	"moremacros.h"
#include	"sizes.h"

#define RETVALSIZE 	50	
#define EXECERROR	1000

static char *Retpath = NULL;
extern pid_t Fmli_pid;	/* EFT abs k16 */

int set_ret_val();
int error_exec();

int
spawnv(file, arglist)
char	*file;
char	*arglist[];
{
	register pid_t	pid;	/* EFT abs k16 */
	register int	fd;

	alarm(0);
	switch (pid = fork()) {
	case -1:
		fprintf(stderr, "Can't create another process\r\n");
		break;
	case 0:
		sigignore(SIGHUP);         /* changed from signals .. */
		sigignore(SIGINT); 
		sigignore(SIGQUIT);        /* to sigignores and.. */ 
		sigignore(SIGUSR1);
		sigset(SIGTERM, SIG_DFL);  /* sigset.  abs */
		for (fd = 0; fd < _NFILE; fd++)
			close(fd);
		dup(dup(open("/dev/null", 2)));
		execvp(file, arglist);
		(void) error_exec(errno);
		_exit(127);
	default:
		break;
	}
	return pid;
}

int
spawn(char *file, ...)
{
	char	*arglist[20];
	register char	**p;
	va_list	ap;

	va_start(ap, file);
	for (p = arglist; p < arglist + sizeof(arglist)/sizeof(*arglist); p++)
		if ((*p = va_arg(ap, char *)) == NULL)
			break;
	va_end(ap);
	return	spawnv(file, arglist);
}

int
sysspawn(s)
char	*s;
{
	char	*arglist[4];

	arglist[0] = "sh";
	arglist[1] = "-c";
	arglist[2] = s;
	arglist[3] = NULL;
	return spawnv("/bin/sh", arglist);
}

int
waitspawn(pid)			/* see also waitspn below! for comments */
register pid_t	pid;		/* EFT abs k16 */
{
	register pid_t waitcode; /* EFT abs k16 */
	int	status;

	while ((waitcode = wait(&status)) != pid)
		if (waitcode == -1 && errno != EINTR)
			break;
	/* examine child status more carefully */
	waitcode = ((waitcode == -1) ? waitcode : status);
	return(set_ret_val(waitcode));
}

/*
 * SET_RET_VAL will return the exit value of the child
 * process given "status" (result of a "wait" system call).
 * It will also set the environment variable "RET" to
 * this exit value OR an "errno" string if an error is
 * encountered during exec).
 */
int
set_ret_val(status)
int status;
{
	char	retval_str[RETVALSIZE];
	int	retval;

	if (!Retpath) {
		char path[PATHSIZ]; 

		sprintf(path, "/tmp/fmlexec.%ld", Fmli_pid); 
		Retpath = strsave(path);
	}
	if (access(Retpath, 0) == 0) { 
		FILE	*fp, *fopen();

		strcpy(retval_str, "RET=");
		if ((fp = fopen(Retpath, "r")) == NULL) {
			unlink(Retpath);	
			strcat(retval_str, "1000");	/* "EXECERROR" */
			retval = EXECERROR; /* abs k13 */
		} else {
			(void) fgets(&retval_str[4], RETVALSIZE-5, fp); 
			fclose(fp);
			unlink(Retpath);
			retval = atoi(&retval_str[4]); /* abs k13 */
		}
	} else {
		/*
		 * if Retpath is not accessable and status is
		 * non zero, query status to discover what
		 * went wrong.
		 */
		if ((status & 0377) != 0) {
			fprintf(stderr,
			    "child terminated with signal %d",(status & 0177));
			if (status & 0200) {
				fprintf(stderr," and produced a corefile.\n");
			} else
				fprintf(stderr,"\n");
		}
		retval = ((status >> 8) &0377);
		sprintf(retval_str, "RET=%d", retval);
	}
	putAltenv(retval_str);
	return(retval);
}

/*
 * ERROR_EXEC will store "str" in a temporary file, typically
 * this string will correspond to the "errno" of a failed 
 * exec attempt
 */ 
int
error_exec(val)
int val;
{
	FILE *fp, *fopen();

	if (!Retpath) {
		char path[PATHSIZ]; 

		sprintf(path, "/tmp/fmlexec.%ld", Fmli_pid); 
		Retpath = strsave(path);
	}
	if ((fp = fopen(Retpath, "w")) == NULL)
		return(FAIL);
	fprintf(fp, "%d", EXECERROR + val); 
	fclose(fp);
	return(SUCCESS);
}
