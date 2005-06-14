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
 *
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved.
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California.
 * All Rights Reserved.
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include "talkd_impl.h"

static int nofork = 0;		/* to be set from the debugger */

static int announce_proc(CTL_MSG *request, char *remote_machine);
static void print_mesg(FILE *tf, CTL_MSG *request, char *remote_machine);

/*
 * Because the tty driver insists on attaching a terminal-less
 * process to any terminal that it writes on, we must fork a child
 * to protect ourselves.
 */

int
announce(CTL_MSG *request, char *remote_machine)
{
	pid_t pid, val;
	int status;

	if (nofork) {
		return (announce_proc(request, remote_machine));
	}

	if (pid = fork()) {

		/* we are the parent, so wait for the child */
		if (pid == (pid_t)-1) {
			/* the fork failed */
			return (FAILED);
		}

		do {
			val = wait(&status);
			if (val == (pid_t)-1) {
				if (errno == EINTR) {
					continue;
				} else {
					/* shouldn't happen */
					print_error("wait");
					return (FAILED);
				}
			}
		} while (val != pid);

		if ((status & 0377) > 0) {
			/* we were killed by some signal */
			return (FAILED);
		}

		/* Get the second byte, this is the exit/return code */
		return ((status>>8)&0377);
	} else {
		/* we are the child, go and do it */
		_exit(announce_proc(request, remote_machine));
	}
	/* NOTREACHED */
}


/*
 * See if the user is accepting messages. If so, announce that
 * a talk is requested.
 */
static int
announce_proc(CTL_MSG *request, char *remote_machine)
{
#define	TTY_BUFSZ	32
	char full_tty[TTY_BUFSZ];
	FILE *tf;
	struct stat stbuf;
	int fd;
	struct passwd *p;

	(void) snprintf(full_tty, TTY_BUFSZ, "/dev/%s", request->r_tty);
	p = getpwnam(request->r_name);

	if (p == 0 || access(full_tty, 0) != 0) {
		return (FAILED);
	}

	/* fopen uses O_CREAT|O_TRUNC, we don't want that */
	if ((fd = open(full_tty, O_WRONLY|O_NONBLOCK)) == -1) {
		return (PERMISSION_DENIED);
	}
	/* must be tty */
	if (!isatty(fd)) {
		(void) close(fd);
		return (PERMISSION_DENIED);
	}

	/*
	 * open gratuitously attaches the talkd to any tty it opens, so
	 * disconnect us from the tty before we catch a signal
	 */
	(void) setsid();

	if (fstat(fd, &stbuf) < 0 || stbuf.st_uid != p->pw_uid) {
		(void) close(fd);
		return (PERMISSION_DENIED);
	}

	if ((stbuf.st_mode&020) == 0) {
		(void) close(fd);
		return (PERMISSION_DENIED);
	}

	if ((tf = fdopen(fd, "w")) == NULL) {
		(void) close(fd);
		return (PERMISSION_DENIED);
	}

	print_mesg(tf, request, remote_machine);
	(void) fclose(tf);
	return (SUCCESS);
}

#define	max(a, b) ((a) > (b) ? (a) : (b))
#define	N_LINES	5
#define	N_CHARS	300

/*
 * Build a block of characters containing the message.
 * It is sent blank filled and in a single block to
 * try to keep the message in one piece if the recipient
 * is in vi at the time.
 */
static void
print_mesg(FILE *tf, CTL_MSG *request, char *remote_machine)
{
	struct timeval clock;
	struct tm *localclock;
	char line_buf[N_LINES][N_CHARS];
	int sizes[N_LINES];
	char *bptr, *lptr;
	int i, j, max_size;

	/*
	 * [3 wakeup chars + (lines * max chars/line) +
	 * (lines * strlen("\r\n")) + 1(NUL)].
	 */
	char big_buf[3 + (N_LINES * (N_CHARS - 1)) + (N_LINES * 2) + 1];
	/*
	 * ( (length of (request->l_name) - 1(NUL)) *
	 * (strlen("M-") + 1('^') + 1(printable char)) ) + 1(NUL).
	 */
	char l_username[((NAME_SIZE - 1) * 4) + 1];
	int len, k;

	i = 0;
	max_size = 0;

	(void) gettimeofday(&clock, NULL);
	localclock = localtime(&clock.tv_sec);

	(void) sprintf(line_buf[i], " ");

	sizes[i] = strlen(line_buf[i]);
	max_size = max(max_size, sizes[i]);
	i++;

	(void) snprintf(line_buf[i], N_CHARS,
	    "Message from Talk_Daemon@%s at %d:%02d ...", hostname,
	    localclock->tm_hour, localclock->tm_min);

	sizes[i] = strlen(line_buf[i]);
	max_size = max(max_size, sizes[i]);
	i++;

	len = (strlen(request->l_name) > NAME_SIZE - 1) ? (NAME_SIZE - 1) :
	    strlen(request->l_name);
	for (j = 0, k = 0; j < len; j++) {
		if (!isprint((unsigned char)request->l_name[j])) {
			char c;
			if (!isascii((unsigned char)request->l_name[j])) {
				l_username[k++] = 'M';
				l_username[k++] = '-';
				c = toascii(request->l_name[j]);
			}
			if (iscntrl((unsigned char)request->l_name[j])) {
				l_username[k++] = '^';
				/* add decimal 64 to the control character */
				c = request->l_name[j] + 0100;
			}
			l_username[k++] = c;
		} else {
			l_username[k++] = request->l_name[j];
		}
	}
	l_username[k] = '\0';

	(void) snprintf(line_buf[i], N_CHARS,
	    "talk: connection requested by %s@%s.", l_username, remote_machine);

	sizes[i] = strlen(line_buf[i]);
	max_size = max(max_size, sizes[i]);
	i++;

	(void) snprintf(line_buf[i], N_CHARS, "talk: respond with:  talk %s@%s",
	    l_username, remote_machine);

	sizes[i] = strlen(line_buf[i]);
	max_size = max(max_size, sizes[i]);
	i++;

	(void) sprintf(line_buf[i], " ");

	sizes[i] = strlen(line_buf[i]);
	max_size = max(max_size, sizes[i]);
	i++;

	bptr = big_buf;
	*(bptr++) = '\a';	/* send something to wake them up */
	*(bptr++) = '\r';	/* add a \r in case of raw mode */
	*(bptr++) = '\n';
	for (i = 0; i < N_LINES; i++) {
		/* copy the line into the big buffer */
		lptr = line_buf[i];
		while (*lptr != '\0') {
			*(bptr++) = *(lptr++);
		}

		/* pad out the rest of the lines with blanks */
		for (j = sizes[i]; j < max_size; j++) {
			*(bptr++) = ' ';
		}

		*(bptr++) = '\r';	/* add a \r in case of raw mode */
		*(bptr++) = '\n';
	}
	*bptr = '\0';

	(void) fputs(big_buf, tf);
	(void) fflush(tf);
	(void) setsid();
}
