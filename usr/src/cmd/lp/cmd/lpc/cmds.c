/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
** lpc -- line printer control program -- commands:
**
*/
#include <locale.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "msgs.h"
#include "lpc.h"

#define REQUEUE_CURR	0	/* Stop immediately and requeue current job */
#define WAIT_CURR	1	/* Finish current job before stopping */ 
#define ABORT_CURR	2	/* Abort current job */

int		 When;
char		*Reason;

extern char	*Printer;
extern char	*Lhost;

#if defined(__STDC__)
static	int	doarg(char *);
#else
static	int	doarg();
#endif

/*
 * kill an existing daemon and disable printing.
 */
void
#if defined(__STDC__)
_abort(int argc, char **argv)
#else
_abort(argc, argv)
int	  argc;
char	**argv;
#endif
{
	When = REQUEUE_CURR;
	Reason = NULL;
	if (argc == 1)
		printf(gettext("Usage: abort {all | printer ...}\n"));
	else if (argc == 2 && !strcmp(argv[1], "all"))
		do_all(disablepr);
	else
		while (--argc)
			disablepr(*++argv);
}


/*
 * Kill and restart the daemon.
 */
void
#if defined(__STDC__)
restart(int argc, char **argv)
#else
restart(argc, argv)
int	  argc;
char	**argv;
#endif
{
	When = REQUEUE_CURR;
	Reason = NULL;
	if (argc == 1)
		printf(gettext("Usage: restart {all | printer ...}\n"));
	else if (argc == 2 && !strcmp(argv[1], "all"))
		do_all(restartpr);
	else 
		while (--argc)
			restartpr(*++argv);
}


/*
 * Enable printing on the specified printer and startup the daemon.
 */
void
#if defined(__STDC__)
start(int argc, char **argv)
#else
start(argc, argv)
int	  argc;
char	**argv;
#endif
{
	if (argc == 1)
		printf(gettext("Usage: start {all | printer ...}\n"));
	else if (argc == 2 && !strcmp(argv[1], "all"))
		do_all(enablepr);
	else 
		while (--argc)
			enablepr(*++argv);
}
/*
 * Stop the specified daemon after completing the current job and disable
 * printing. 	(Disable only the printer not the queue )
 */
void
#if defined(__STDC__)
stop(int argc, char **argv)
#else
stop(argc, argv)
int	  argc;
char	**argv;
#endif
{
	When = WAIT_CURR;
	Reason = NULL;
	if (argc == 1)
		printf(gettext("Usage: stop {all | printer ...}\n"));
	else if (argc == 2 && !strcmp(argv[1], "all"))
		do_all(disablepr);
	else
		while (--argc)
			disablepr(*++argv);
}

/*
 * Enable everything and start printer (undo `down').
 */
void
#if defined(__STDC__)
up(int argc, char **argv)
#else
up(argc, argv)
int	  argc;
char	**argv;
#endif
{
	if (argc == 1)
		printf(gettext("Usage: up {all | printer ...}\n"));
	else if (argc == 2 && !strcmp(argv[1], "all"))
		do_all(uppr);
	else  
		while (--argc)
			uppr(*++argv);
}

/*
 * Disable queuing and printing and put a message into the status file
 * (reason for being down).
 */
void
#if defined(__STDC__)
down(int argc, char **argv)
#else
down(argc, argv)
int	  argc;
char	**argv[];
#endif
{
	if (argc == 1) {
		printf(gettext("Usage: down {all | printer} [message ...]\n"));
		return;
	}
	When = WAIT_CURR;
	Reason = get_reason(argc-2, &argv[2]);
	if (!strcmp(argv[1], "all"))
		do_all(downpr);
	else
		downpr(argv[1]);
}

/*
**	
** Queue Control commands (enable, disable)
**
*/

/*
 * Enable queuing to the printer (allow lpr's).
 */
void
#if defined(__STDC__)
enable(int argc, char **argv)
#else
enable(argc, argv)
int	  argc;
char	**argv;
#endif
{
	if (argc == 1)
		printf(gettext("Usage: enable {all | printer ...}\n"));
	else if (argc == 2 && !strcmp(argv[1], "all"))
		do_all(enableq);
	else
		while (--argc)
			enableq(*++argv);
}


/*
 * Disable queuing.
 */
void
#if defined(__STDC__)
disable(int argc, char **argv)
#else
disable(argc, argv)
int	  argc;
char	**argv;
#endif
{
	Reason = NULL;
	if (argc == 1)
		printf(gettext("Usage: disable {all | printer ...}\n"));
	else if (argc == 2 && !strcmp(argv[1], "all"))
		do_all(disableq);
	else 
		while (--argc)
			disableq(*++argv);
}

/*
**	Status of printers and queues
**/

/*
 * Print the status of each queue listed or all the queues.
 */
void
#if defined(__STDC__)
status(int argc, char **argv)
#else
status(argc, argv)
int	  argc;
char	**argv;
#endif
{
	if( (argc == 1) || (argc == 2 && !strcmp(argv[1], "all")))
		do_all(statuspr);
	else
		while (--argc)
			statuspr(*++argv);
}


/*
 * Put the specified jobs at the top of printer queue.
 */
void
#if defined(__STDC__)
topq(int argc, char **argv)
#else
topq(argc, argv)
int	  argc;
char	**argv;
#endif
{
	register int  i;
	int changed;

	if (argc < 3) {
		printf(gettext("Usage: topq printer [jobnum ...] [user ...]\n"));
		return;
	}

	--argc;
	Printer = *++argv;

	/*
	 * Check if it is a known printer 
	 */
	if(isprinter(Printer))
		printf("%s:\n", Printer);
	else{
                printf(gettext("%s: unknown printer\n"), Printer);
                return;
        }

	/*
	 * Find if a requestid or a user name is specified 
	 * Also accept job# (LPD style )
	 */
	changed = 0;
	for (i = argc; --i; ) {
                if (doarg(argv[i]) == 0) {
                        printf(gettext("\tjob %s is not in the queue\n"), argv[i]);
                        continue;
                } else
                        changed++;

	}
	if (!changed)
                printf(gettext("\tqueue order unchanged\n"));
	return;
	
} 

static
#if defined(__STDC__)
doarg(char *job)
#else
doarg(job)
char	*job;
#endif
{

	char *cp;
      	int jobnum, n;
	char *machine = NULL;
	
        /*
        ** Look for a job item consisting of system name, colon, number
        ** (example: ucbarpa:114)
        */
	if ((cp = strpbrk(job, "!:")) != NULL) {
		*cp++ = NULL;
		if (strcmp(Lhost, job))
			machine = job;
		job = cp;
	}

	 /*
         **  Check for job specified by number (example: 112 or 235ucbarpa).
         */
	if (isdigit(*job) ) {
		/*
		** Find machine name if it is of the type "job#machine"
		**/
		jobnum = strtol(job, &cp, 10);
		/* rest of the string ought to be a machine name */
		if (*cp && strcmp(Lhost, cp))
			machine = cp;
		job = (char *)malloc(strlen(Printer) + cp - job + 2);
		sprintf(job, "%s-%d", Printer, jobnum);
		n = topq_reqid(job, machine);
		free(job);
		return(n);
	}
	/*
	** If it is a request-id, process it.
	*/
	if (isrequest(job))
		return(topq_reqid(job, machine));

        /*
        ** Process item consisting of owner's name (example: henry).
	** job is user name.
        **/
	return(topq_user(job, machine));

}

char *
#if defined(__STDC__)
get_reason(int argc, char **argv)
#else
get_reason(argc, argv)
int	  argc;
char	**argv;
#endif
{
	char *cpto, *cpfrom;
	static char buf[1024];

	/* 
	 * Obtain the reason
	 */

	if (!argc)
		return(NULL);
	cpto = buf;
	while (--argc >= 0) {
		cpfrom = *argv++;
		while (*cpto++ = *cpfrom++)
			;
		cpto[-1] = ' ';
	}
	cpto[-1] = '\n';
	*cpto = NULL;

	return(buf);
}

/*
 * Remove all spool files and temporaries from the spooling area.
 */
void
#if defined(__STDC__)
clean(int argc, char **argv)
#else
clean(argc, argv)
int	  argc;
char	**argv;
#endif
{
	if (argc == 1)
		printf(gettext("Usage: clean {all | printer ...}\n"));
	else if (argc == 2 && !strcmp(argv[1], "all"))
		do_all(cleanpr);
	else 
		while (--argc)
			cleanpr(*++argv);
}

/*
 * Exit lpc
 */
/*ARGSUSED*/
void
#if defined(__STDC__)
quit(int argc, char **argv)
#else
quit(argc, argv)
int	  argc;
char	**argv;
#endif
{
	void	done();

	done(0);
}

