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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "rcv.h"
#include <locale.h>


/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Perform message editing functions.
 */

static void edit1(int *msgvec, char *ed);

/*
 * Edit a message list.
 */

int 
editor(int *msgvec)
{
	char *edname;

	if ((edname = value("EDITOR")) == NOSTR || *edname == '\0')
		edname = EDITOR;
	edit1(msgvec, edname);
	return(0);
}

/*
 * Invoke the visual editor on a message list.
 */

int 
visual(int *msgvec)
{
	char *edname;

	if ((edname = value("VISUAL")) == NOSTR || *edname == '\0')
		edname = VISUAL;
	edit1(msgvec, edname);
	return(0);
}

/*
 * Edit a message by writing the message into a funnily-named file
 * (which should not exist) and forking an editor on it.
 * We get the editor from the stuff above.
 */

static void 
edit1(int *msgvec, char *ed)
{
	register int c, lastc = '\n';
	pid_t pid;
	int *ip, mesg, blank = 1;
	long ms, lines;
	void (*sigint)(int), (*sigquit)(int);
	FILE *ibuf, *obuf;
	struct message *mp;
	off_t size;
	struct stat statb;
	long modtime;
	int fd = -1;

	/*
	 * Set signals; locate editor.
	 */

	sigint = sigset(SIGINT, SIG_IGN);
	sigquit = sigset(SIGQUIT, SIG_IGN); 
	ed = safeexpand(ed);

	/*
	 * Deal with each message to be edited . . .
	 */

	for (ip = msgvec; *ip && ip-msgvec < msgCount; ip++) {
		mesg = *ip;
		touch(mesg);
		mp = &message[mesg-1];
		dot = mp;
		if (mp->m_text) {
			if (!access(tempZedit, 2)) {
				printf(gettext("%s: file exists\n"), tempZedit);
				goto out;
			}

			/*
			 * Copy the message into the edit file.
			 */

			if ((fd = open(tempZedit, O_RDWR|O_CREAT|
					O_EXCL, 0600)) < 0 ||
				(obuf = fdopen(fd, "w")) == NULL) {
				perror(tempZedit);
				goto out;
			}
			if (msend(mp, obuf, 0, fputs) < 0) {
				perror(tempZedit);
				fclose(obuf);
				removefile(tempZedit);
				goto out;
			}
			fflush(obuf);
			if (fferror(obuf)) {
				perror(tempZedit);
				fclose(obuf);
				removefile(tempZedit);
				goto out;
			}
			fclose(obuf);

			/*
			 * If we are in read only mode, make the
			 * temporary message file readonly as well.
			 */

			if (readonly)
				chmod(tempZedit, 0400);

			/*
			 * Fork/execl the editor on the edit file.
			 */

			if (stat(tempZedit, &statb) < 0)
				modtime = 0;
			else
				modtime = statb.st_mtime;
			pid = vfork();
			if (pid == (pid_t)-1) {
				perror("fork");
				removefile(tempZedit);
				goto out;
			}
			if (pid == 0) {
				sigchild();
				if (sigint != SIG_IGN)
					sigset(SIGINT, SIG_DFL);
				if (sigquit != SIG_IGN)
					sigset(SIGQUIT, SIG_DFL);
				execlp(ed, ed, tempZedit, (char *)0);
				perror(ed);
				_exit(1);
			}
			while (wait(&mesg) != pid)
				;

			/*
			 * If in read only mode, just remove the editor
			 * temporary and return.
			 */

			if (readonly) {
				removefile(tempZedit);
				continue;
			}

			/*
			 * Now copy the message to the end of the
			 * temp file.
			 */

			if (stat(tempZedit, &statb) < 0) {
				perror(tempZedit);
				continue;
			}
			if (modtime == statb.st_mtime) {
				removefile(tempZedit);
				continue;
			}
			if ((ibuf = fopen(tempZedit, "r")) == NULL) {
				perror(tempZedit);
				removefile(tempZedit);
				continue;
			}
			removefile(tempZedit);
			fseek(otf, (long) 0, 2);
			size = fsize(otf);
			mp->m_flag |= MODIFY;
			mp->m_offset = size;
			ms = 0L;
			lines = 0;
			while ((c = getc(ibuf)) != EOF) {
				if (c == '\n') {
					lines++;
					blank = lastc == '\n';
				}
				lastc = c;
				putc(c, otf);
				if (ferror(otf))
					break;
				ms++;
			}
			if (!blank) {
				putc('\n', otf);
				ms++;
				lines++;
			}
			mp->m_size = ms;
			mp->m_lines = lines;
			fflush(otf);
			if (fferror(otf))
				perror("/tmp");
			fclose(ibuf);
			setclen(mp);
		} else {
			printf("\n%s\n", gettext(
"*** Message content is not printable: pipe to command or save to a file ***"));
		}
	}

	/*
	 * Restore signals and return.
	 */

out:
	sigset(SIGINT, sigint);
	sigset(SIGQUIT, sigquit);
}
