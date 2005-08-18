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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mail.h"
/*
 *  NAME
 *	sendlist - send copy to specified users
 *
 *  SYNOPSIS
 *	int sendlist(reciplist *list, int letnum, int level)
 *
 *  DESCRIPTION
 *	sendlist() will traverse the current recipient list and
 *	send a copy of the given letter to each user specified,
 *	invoking send() to do the sending. It returns
 *	1 if the sending fails, 0 otherwise.
 */


/*
 * mailx and mailtool read the SENDMAIL from an environment, since few
 *  people use /bin/mail as their user agent and since /bin/mail is often
 *  called as root or made setuid it's safer to leave this hardwired.
 */

static char *sendmail_prog = SENDMAIL;

static void notifybiff(char *);

int
sendlist(reciplist *list, int letnum, int level)
{
	recip *to;
	int rc = 0;
	FILE *fp;
	int nargs = 4;			/* "sendmail", "-oi", "--", .. NULL */
	char **argv;
	char **p;

	/* Deliver mail directly to a mailbox */
	if (deliverflag) {
		/*
		 * Note failure to deliver to any one of the recipients
		 * should be considered a failure, so that the user
		 * get's an indication of that failure.
		 */
		for (to = &(list->recip_list); to; to = to->next) {
			if (to->name)
				if (!send_mbox(to->name, letnum))
					rc = 1;
		}
		return (rc);
	}

	/*
	 * build argv list, allowing for arbitrarily long deliver lists
	 * and then  hand the message off to sendmail
	 */

	if (!ismail)
		nargs += 2;	/* for "-f", "Rpath" */

	for (to = &(list->recip_list); to; to = to->next)
		if (to->name)
			nargs++;

	argv = malloc(nargs * sizeof (char *));

	if (argv == NULL)
		return (1);

	p = argv;

	*p++ = sendmail_prog;

	/* If we're rmail add "-f", "Rpath" to the the command line */
	if (!ismail) {
		*p++ = "-f";
		*p++ = Rpath;
	}

	*p++ = "-oi";
	*p++ = "--";		/* extra protection: end of argument list */

	for (to = &(list->recip_list); to; to = to->next)
		if (to->name)
			*p++ = to->name;

	*p = NULL;

	fp = popenvp(sendmail_prog, argv, "w", 0);

	free(argv);

	if (fp == NULL)
		return (1);

	copylet(letnum, fp, ORDINARY);
	rc = pclosevp(fp);
	if (!rc)
		return (0);
	else
		return (1);
}

/*
 * send_mbox(user, letnum)  Sends the letter specified by letnum to the
 *	"user"'s mailbox. It returns 1 if the sending fails;
 *	0 on success.
 */



int
send_mbox(char *mbox, int letnum)
{
	char file[PATH_MAX];
	char biffmsg[PATH_MAX];
	int mbfd;
	FILE *malf;
	int rc;
	uid_t useruid, saved_uid;
	void (*istat)(), (*qstat)(), (*hstat)();

	if (!islocal(mbox, &useruid))
		return (1);
	(void) strlcpy(file, maildir, sizeof (file));
	if (strlcat(file, mbox, sizeof (file)) >= sizeof (file)) {
		rc = FALSE;
		goto done;
	}

	/*
	 * We need to setgid and seteuid here since the users's mail box
	 * might be NFS mounted and since root can't write across NFS.
	 * Note this won't work with Secure NFS/RPC's.  Since delivering to
	 * NFS mounted directories isn't really supported that's OK for now.
	 */
	setgid(mailgrp);
	saved_uid = geteuid();
	seteuid(useruid);
	lock(mbox);

	/* ignore signals */
	istat = signal(SIGINT, SIG_IGN);
	qstat = signal(SIGQUIT, SIG_IGN);
	hstat = signal(SIGHUP, SIG_IGN);
	/* now access mail box */
	mbfd = accessmf(file);
	if (mbfd == -1) {	/* mail box access failed, bail out */
		unlock();
		rc = FALSE;
		sav_errno = EACCES;
		goto done;
	} else {
				/* mail box is ok, now do append */
		if ((malf = fdopen(mbfd, "a")) != NULL) {
			(void) snprintf(biffmsg, sizeof (biffmsg),
			    "%s@%d\n", mbox, ftell(malf));
			rc = copylet(letnum, malf, ORDINARY);
			fclose(malf);
		}
	}

	if (rc == FALSE)
		fprintf(stderr, "%s: Cannot append to %s\n", program, file);
	else
		notifybiff(biffmsg);

done:
	/* restore signal */
	(void) signal(SIGINT, istat);
	(void) signal(SIGQUIT, qstat);
	(void) signal(SIGHUP, hstat);
	unlock();
	seteuid(saved_uid);
	return (rc);
}

#include <sys/socket.h>
#include <netinet/in.h>

static void
notifybiff(char *msg)
{
	static struct sockaddr_in addr;
	static int f = -1;

	if (addr.sin_family == 0) {
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_LOOPBACK;
		addr.sin_port = htons(IPPORT_BIFFUDP);
	}
	if (f < 0)
		f = socket(AF_INET, SOCK_DGRAM, 0);
	sendto(f, msg, strlen(msg)+1, 0, (struct sockaddr *)&addr,
		sizeof (addr));
}
