/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "tip.h"
#include <limits.h>

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
intIOT(void)
{

	(void) write(repdes[1], &ccc, 1);
	(void) read(fildes[0], &ccc, 1);
	siglongjmp(sigbuf, 1);
}

/*
 * Scripting command interpreter --
 *  accepts script file name over the pipe and acts accordingly
 */
void
intEMT(void)
{
	char c, line[PATH_MAX];
	char *pline = line;
	char reply;

	(void) read(fildes[0], &c, 1);
	while (c != '\n' && line + sizeof (line) - pline > 1) {
		*pline++ = c;
		(void) read(fildes[0], &c, 1);
	}
	*pline = '\0';
	if (boolean(value(SCRIPT)) && fscript != NULL)
		(void) fclose(fscript);
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
	(void) write(repdes[1], &reply, 1);
	siglongjmp(sigbuf, 1);
}

void
intTERM(void)
{

	if (boolean(value(SCRIPT)) && fscript != NULL)
		(void) fclose(fscript);
	exit(0);
}

void
intSYS(void)
{

	boolean(value(BEAUTIFY)) = !boolean(value(BEAUTIFY));
	siglongjmp(sigbuf, 1);
}

/*
 * ****TIPOUT   TIPOUT****
 */
void
tipout(void)
{
	char buf[BUFSIZ];
	char *cp;
	int cnt;
	sigset_t omask, bmask, tmask;

	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	/* attention from TIPIN */
	(void) signal(SIGEMT, (sig_handler_t)intEMT);
	/* time to go signal */
	(void) signal(SIGTERM, (sig_handler_t)intTERM);
	/* scripting going on signal */
	(void) signal(SIGIOT, (sig_handler_t)intIOT);
	/* for dial-ups */
	(void) signal(SIGHUP, (sig_handler_t)intTERM);
	/* beautify toggle */
	(void) signal(SIGSYS, (sig_handler_t)intSYS);
	(void) sigsetjmp(sigbuf, 1);

	(void) sigemptyset(&omask);
	(void) sigemptyset(&bmask);
	(void) sigaddset(&bmask, SIGEMT);
	(void) sigaddset(&bmask, SIGTERM);
	(void) sigaddset(&bmask, SIGIOT);
	(void) sigaddset(&bmask, SIGSYS);
	(void) sigemptyset(&tmask);
	(void) sigaddset(&tmask, SIGTERM);
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
						(void) close(fd);
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

			(void) write(1, buf, cnt);
			if (boolean(value(SCRIPT)) && fscript != NULL) {
				if (!boolean(value(BEAUTIFY))) {
					(void) fwrite(buf, 1, cnt, fscript);
				} else {
					for (cp = buf; cp < buf + cnt; cp++)
						if ((*cp >= ' ' && *cp <= '~')||
						    any(*cp, value(EXCEPTIONS)))
							(void) putc(*cp,
							    fscript);
				}
			}
		}
		(void) sigprocmask(SIG_SETMASK, &omask, NULL);
	}
}
