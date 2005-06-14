/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* from UCB 5.1 4/30/85 */

#include "tip.h"
/*
 * tip
 *
 * lower fork of tip -- handles passive side
 *  reading from the remote host
 */

static	sigjmp_buf sigbuf;

/*
 * TIPOUT wait state routine --
 *   sent by TIPIN when it wants to posses the remote host
 */
void
intIOT()
{

	write(repdes[1], &ccc, 1);
	read(fildes[0], &ccc, 1);
	siglongjmp(sigbuf, 1);
}

/*
 * Scripting command interpreter --
 *  accepts script file name over the pipe and acts accordingly
 */
void
intEMT()
{
	char c, line[256];
	register char *pline = line;
	char reply;

	read(fildes[0], &c, 1);
	while (c != '\n') {
		*pline++ = c;
		read(fildes[0], &c, 1);
	}
	*pline = '\0';
	if (boolean(value(SCRIPT)) && fscript != NULL)
		fclose(fscript);
	if (pline == line) {
		boolean(value(SCRIPT)) = FALSE;
		reply = 'y';
	} else {
		if ((fscript = fopen(line, "a")) == NULL)
			reply = 'n';
		else {
			reply = 'y';
			boolean(value(SCRIPT)) = TRUE;
		}
	}
	write(repdes[1], &reply, 1);
	siglongjmp(sigbuf, 1);
}

void
intTERM()
{

	if (boolean(value(SCRIPT)) && fscript != NULL)
		fclose(fscript);
	exit(0);
}

void
intSYS()
{

	boolean(value(BEAUTIFY)) = !boolean(value(BEAUTIFY));
	siglongjmp(sigbuf, 1);
}

/*
 * ****TIPOUT   TIPOUT****
 */
tipout()
{
	char buf[BUFSIZ];
	register char *cp;
	register int cnt;
	extern int errno;
	sigset_t omask, bmask, tmask;

	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGEMT, (sig_handler_t)intEMT);	/* attention from TIPIN */
	signal(SIGTERM, (sig_handler_t)intTERM); /* time to go signal */
	signal(SIGIOT, (sig_handler_t)intIOT);	/* scripting going on signal */
	signal(SIGHUP, (sig_handler_t)intTERM);	/* for dial-ups */
	signal(SIGSYS, (sig_handler_t)intSYS);	/* beautify toggle */
	(void) sigsetjmp(sigbuf, 1);

	sigemptyset(&omask);
	sigemptyset(&bmask);
	sigaddset(&bmask, SIGEMT);
	sigaddset(&bmask, SIGTERM);
	sigaddset(&bmask, SIGIOT);
	sigaddset(&bmask, SIGSYS);
	sigemptyset(&tmask);
	sigaddset(&tmask, SIGTERM);
	for (;;) {
		cnt = read(FD, buf, BUFSIZ);
		if (cnt <= 0) {
			/*
			 * If dialback is specified, ignore the hangup
			 * and clear the hangup condition on the device.
			 */
			if (cnt == 0 && DB) {
				int fd;

				DB = 0;
				if ((fd = open(DV, O_RDWR)) >= 0) {
					if (fd != FD)
						close(fd);
				}
				continue;
			}
			/* lost carrier */
			if ((cnt < 0 && errno == EIO) ||
			    (cnt == 0)) {
				(void) sigprocmask(SIG_BLOCK, &tmask, NULL);
				intTERM();
				/*NOTREACHED*/
			}
		} else {
			(void) sigprocmask(SIG_BLOCK, &bmask, &omask);
			if (!noparity)
				for (cp = buf; cp < buf + cnt; cp++)
					*cp &= 0177;

			write(1, buf, cnt);
			if (boolean(value(SCRIPT)) && fscript != NULL) {
				if (!boolean(value(BEAUTIFY))) {
					fwrite(buf, 1, cnt, fscript);
				} else {
					for (cp = buf; cp < buf + cnt; cp++)
						if ((*cp >= ' ' && *cp <= '~')||
						    any(*cp, value(EXCEPTIONS)))
							putc(*cp, fscript);
				}
			}
		}
		(void) sigprocmask(SIG_SETMASK, &omask, NULL);
	}
}
