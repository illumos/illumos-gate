/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Pager: Routines to create a "more" running out of a particular file
 * descriptor.
 *
 * Copyright 1987, 1988 by MIT Student Information Processing Board
 *
 * For copyright information, see copyright.h.
 */

#include "ss_internal.h"
#include "copyright.h"
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <signal.h>

static char MORE[] = "more";
extern char *_ss_pager_name;
extern char *getenv();

/*
 * this needs a *lot* of work....
 *
 * run in same process
 * handle SIGINT sensibly
 * allow finer control -- put-page-break-here
 */

#ifndef NO_FORK
int ss_pager_create(void)
{
	int filedes[2];
     
	if (pipe(filedes) != 0)
		return(-1);

	switch((int) fork()) {
	case -1:
		return(-1);
	case 0:
		/*
		 * Child; dup read half to 0, close all but 0, 1, and 2
		 */
		if (dup2(filedes[0], 0) == -1)
			exit(1);
		ss_page_stdin();
	default:
		/*
		 * Parent:  close "read" side of pipe, return
		 * "write" side.
		 */
		(void) close(filedes[0]);
		return(filedes[1]);
	}
}
#else /* don't fork */
int ss_pager_create(void)
{
    int fd;
    fd = open("/dev/tty", O_WRONLY, 0);
    return fd;
}
#endif

void ss_page_stdin(void)
{
	int i;
#ifdef POSIX_SIGNALS
	struct sigaction sa;
	sigset_t mask;
#endif
	/*
	 * Close all fd's, excepting stdin/stdout/stderr
	 */
	closefrom(3);

#ifdef POSIX_SIGNALS
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
#else
	(void) signal(SIGINT, SIG_DFL);
#endif
	{
#ifdef POSIX_SIGNALS
		sigemptyset(&mask);
		sigaddset(&mask, SIGINT);
		sigprocmask(SIG_UNBLOCK, &mask, NULL);
#else
		int mask = sigblock(0);
		mask &= ~sigmask(SIGINT);
		sigsetmask(mask);
#endif
	}
	if (_ss_pager_name == NULL) {
		if ((_ss_pager_name = getenv("PAGER")) == NULL)
			_ss_pager_name = MORE;
	}
	(void) execlp(_ss_pager_name, _ss_pager_name, NULL);
	{
		/* minimal recovery if pager program isn't found */
		char buf[80];
		register int n;
		while ((n = read(0, buf, 80)) > 0)
			write(1, buf, (unsigned) n);
	}
	exit(errno);
}
