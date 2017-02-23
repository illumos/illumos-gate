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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

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
 * Rcv -- receive mail rationally.
 *
 * Termination processing.
 */

static void		writeback(int noremove);

#define PRIV(x)		setgid(myegid), (x), setgid(myrgid);

/*
 * Save all of the undetermined messages at the top of "mbox"
 * Save all untouched messages back in the system mailbox.
 * Remove the system mailbox, if none saved there.
 */

void
quit(
    int noremove	/* don't remove system mailbox, trunc it instead */
)
{
	int mcount, p, modify, autohold, anystat, holdbit, nohold, fd;
	FILE *ibuf, *obuf, *fbuf, *readstat;
	register struct message *mp;
	register int c;
	char *id;
	int appending;
	char *mbox = Getf("MBOX");

	/*
	 * If we are read only, we can't do anything,
	 * so just return quickly.
	 */

	mcount = 0;
	if (readonly)
		return;
	/*
	 * See if there any messages to save in mbox.  If no, we
	 * can save copying mbox to /tmp and back.
	 *
	 * Check also to see if any files need to be preserved.
	 * Delete all untouched messages to keep them out of mbox.
	 * If all the messages are to be preserved, just exit with
	 * a message.
	 *
	 * If the luser has sent mail to himself, refuse to do
	 * anything with the mailbox, unless mail locking works.
	 */

#ifndef CANLOCK
	if (selfsent) {
		printf(gettext("You have new mail.\n"));
		return;
	}
#endif

	/*
	 * Adjust the message flags in each message.
	 */

	anystat = 0;
	autohold = value("hold") != NOSTR;
	appending = value("append") != NOSTR;
	holdbit = autohold ? MPRESERVE : MBOX;
	nohold = MBOXED|MBOX|MSAVED|MDELETED|MPRESERVE;
	if (value("keepsave") != NOSTR)
		nohold &= ~MSAVED;
	for (mp = &message[0]; mp < &message[msgCount]; mp++) {
		if (mp->m_flag & MNEW) {
			receipt(mp);
			mp->m_flag &= ~MNEW;
			mp->m_flag |= MSTATUS;
		}
		if (mp->m_flag & MSTATUS)
			anystat++;
		if ((mp->m_flag & MTOUCH) == 0)
			mp->m_flag |= MPRESERVE;
		if ((mp->m_flag & nohold) == 0)
			mp->m_flag |= holdbit;
	}
	modify = 0;
	if (Tflag != NOSTR) {
		if ((readstat = fopen(Tflag, "w")) == NULL)
			Tflag = NOSTR;
	}
	for (c = 0, p = 0, mp = &message[0]; mp < &message[msgCount]; mp++) {
		if (mp->m_flag & MBOX)
			c++;
		if (mp->m_flag & MPRESERVE)
			p++;
		if (mp->m_flag & MODIFY)
			modify++;
		if (Tflag != NOSTR && (mp->m_flag & (MREAD|MDELETED)) != 0) {
			id = hfield("message-id", mp, addone);
			if (id != NOSTR)
				fprintf(readstat, "%s\n", id);
			else {
				id = hfield("article-id", mp, addone);
				if (id != NOSTR)
					fprintf(readstat, "%s\n", id);
			}
		}
	}
	if (Tflag != NOSTR)
		fclose(readstat);
	if (p == msgCount && !modify && !anystat) {
		if (p == 1)
			printf(gettext("Held 1 message in %s\n"), mailname);
		else
			printf(gettext("Held %d messages in %s\n"), p,
			    mailname);
		return;
	}
	if (c == 0) {
		writeback(noremove);
		return;
	}

	/*
	 * Create another temporary file and copy user's mbox file
	 * therein.  If there is no mbox, copy nothing.
	 * If they have specified "append" don't copy the mailbox,
	 * just copy saveable entries at the end.
	 */

	mcount = c;
	if (!appending) {
		if ((fd = open(tempQuit, O_RDWR|O_CREAT|O_EXCL, 0600)) < 0 ||
		(obuf = fdopen(fd, "w")) == NULL) {
			perror(tempQuit);
			return;
		}
		if ((ibuf = fopen(tempQuit, "r")) == NULL) {
			perror(tempQuit);
			removefile(tempQuit);
			fclose(obuf);
			return;
		}
		removefile(tempQuit);
		if ((fbuf = fopen(mbox, "r")) != NULL) {
			while ((c = getc(fbuf)) != EOF)
				putc(c, obuf);
			fclose(fbuf);
		}
		fflush(obuf);
		if (fferror(obuf)) {
			perror(tempQuit);
			fclose(ibuf);
			fclose(obuf);
			return;
		}
		fclose(obuf);
		if ((fd = open(mbox, O_RDWR|O_CREAT|O_TRUNC, MBOXPERM)) < 0 ||
		    (obuf = fdopen(fd, "r+")) == NULL) {
			perror(mbox);
			fclose(ibuf);
			return;
		}
		if (issysmbox)
			touchlock();
	} else {	/* we are appending */
		if ((fd = open(mbox, O_RDWR|O_CREAT, MBOXPERM)) < 0 ||
		    (obuf = fdopen(fd, "a")) == NULL) {
			perror(mbox);
			return;
		}
	}
	for (mp = &message[0]; mp < &message[msgCount]; mp++)
		if (mp->m_flag & MBOX) {
			if (msend(mp, obuf, (int)value("alwaysignore") ?
			    M_IGNORE|M_SAVING : M_SAVING, fputs) < 0) {
				perror(mbox);
				if (!appending)
					fclose(ibuf);
				fclose(obuf);
				return;
			}
			mp->m_flag &= ~MBOX;
			mp->m_flag |= MBOXED;
			if (issysmbox)
				touchlock();
		}

	/*
	 * Copy the user's old mbox contents back
	 * to the end of the stuff we just saved.
	 * If we are appending, this is unnecessary.
	 */

	if (!appending) {
		rewind(ibuf);
		c = getc(ibuf);
		while (c != EOF) {
			putc(c, obuf);
			if (ferror(obuf))
				break;
			c = getc(ibuf);
		}
		fclose(ibuf);
		fflush(obuf);
	}
	trunc(obuf);
	if (fferror(obuf)) {
		perror(mbox);
		fclose(obuf);
		return;
	}
	fclose(obuf);
	if (mcount == 1)
		printf(gettext("Saved 1 message in %s\n"), mbox);
	else
		printf(gettext("Saved %d messages in %s\n"), mcount, mbox);

	/*
	 * Now we are ready to copy back preserved files to
	 * the system mailbox, if any were requested.
	 */
	writeback(noremove);
}

/*
 * Preserve all the appropriate messages back in the system
 * mailbox, and print a nice message indicating how many were
 * saved.  Incorporate any new mail that we found.
 */
static void
writeback(int noremove)
{
	register struct message *mp;
	register int p, c;
	struct stat st;
	FILE *obuf = 0, *fbuf = 0, *rbuf = 0;
	void (*fhup)(int), (*fint)(int), (*fquit)(int);
	int fd = -1;

	fhup = sigset(SIGHUP, SIG_IGN);
	fint = sigset(SIGINT, SIG_IGN);
	fquit = sigset(SIGQUIT, SIG_IGN);

	if (issysmbox)
		lockmail();
	if ((fbuf = fopen(mailname, "r+")) == NULL) {
		perror(mailname);
		goto die;
	}
	if (!issysmbox)
		lock(fbuf, "r+", 1);
	fstat(fileno(fbuf), &st);
	if (st.st_size > mailsize) {
		printf(gettext("New mail has arrived.\n"));
		snprintf(tempResid, PATHSIZE, "%s/:saved/%s", maildir, myname);
		PRIV(rbuf = fopen(tempResid, "w+"));
		if (rbuf == NULL) {
			snprintf(tempResid, PATHSIZE, "/tmp/Rq%-ld", mypid);
			fd = open(tempResid,O_RDWR|O_CREAT|O_EXCL, 0600);
			PRIV(rbuf = fdopen(fd, "w+"));
			if (rbuf == NULL) {
				snprintf(tempResid, PATHSIZE,
					"%s/:saved/%s", maildir,
				    myname);
				perror(tempResid);
				fclose(fbuf);
				goto die;
			}
		}
#ifdef APPEND
		fseek(fbuf, mailsize, 0);
		while ((c = getc(fbuf)) != EOF)
			putc(c, rbuf);
#else
		p = st.st_size - mailsize;
		while (p-- > 0) {
			c = getc(fbuf);
			if (c == EOF) {
				perror(mailname);
				fclose(fbuf);
				goto die;
			}
			putc(c, rbuf);
		}
#endif
		fclose(fbuf);
		fseek(rbuf, 0L, 0);
		if (issysmbox)
			touchlock();
	}

	if ((obuf = fopen(mailname, "r+")) == NULL) {
		perror(mailname);
		goto die;
	}
#ifndef APPEND
	if (rbuf != NULL)
		while ((c = getc(rbuf)) != EOF)
			putc(c, obuf);
#endif
	p = 0;
	for (mp = &message[0]; mp < &message[msgCount]; mp++)
		if ((mp->m_flag&MPRESERVE)||(mp->m_flag&MTOUCH)==0) {
			p++;
			if (msend(mp, obuf, 0, fputs) < 0) {
				perror(mailname);
				goto die;
			}
			if (issysmbox)
				touchlock();
		}
#ifdef APPEND
	if (rbuf != NULL)
		while ((c = getc(rbuf)) != EOF)
			putc(c, obuf);
#endif
	fflush(obuf);
	trunc(obuf);
	if (fferror(obuf)) {
		perror(mailname);
		goto die;
	}
	alter(mailname);
	if (p) {
		if (p == 1)
			printf(gettext("Held 1 message in %s\n"), mailname);
		else
			printf(gettext("Held %d messages in %s\n"), p,
			    mailname);
	}

	if (!noremove && (fsize(obuf) == 0) && (value("keep") == NOSTR)) {
		if (stat(mailname, &st) >= 0)
			PRIV(delempty(st.st_mode, mailname));
	}

die:
	if (rbuf) {
		fclose(rbuf);
		PRIV(removefile(tempResid));
	}
	if (obuf)
		fclose(obuf);
	if (issysmbox)
		unlockmail();
	sigset(SIGHUP, fhup);
	sigset(SIGINT, fint);
	sigset(SIGQUIT, fquit);
}

void
lockmail(void)
{
    PRIV(maillock(lockname,10));
}

void
unlockmail(void)
{
    PRIV(mailunlock());
}
