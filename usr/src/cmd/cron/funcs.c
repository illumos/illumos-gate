/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <dirent.h>
#include <libintl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <tzfile.h>
#include "cron.h"

#define	CANTCD		"can't change directory to the at directory"
#define	NOREADDIR	"can't read the at directory"
#define	YEAR		1900
extern int audit_cron_is_anc_name(char *);

time_t
num(char **ptr)
{
	time_t n = 0;
	while (isdigit(**ptr)) {
		n = n*10 + (**ptr - '0');
		*ptr += 1; }
	return (n);
}


static int dom[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

int
days_btwn(int m1, int d1, int y1, int m2, int d2, int y2)
{
	/*
	 * calculate the number of "full" days in between
	 * m1/d1/y1 and m2/d2/y2.
	 * NOTE: there should not be more than a year separation in the
	 * dates. also, m should be in 0 to 11, and d should be in 1 to 31.
	 */

	int	days;
	int	m;

	if ((m1 == m2) && (d1 == d2) && (y1 == y2))
		return (0);
	if ((m1 == m2) && (d1 < d2)) {
		/*
		 * In case of d2==29 ,d1==28 and m1==m2==Feb and year is not
		 * a leap year, this function should return the days till the
		 * the next Feb 29.See Bug 4257355.
		 */
		if (d2 > days_in_mon(m2, y2)) {
			int p;
			for (p = 1; ! isleap(y2+YEAR+p); p++)
				;
			return (p*365 + d2-d1-1);
		}
		return (d2-d1-1);
	}
	/* the remaining dates are on different months */
	days = (days_in_mon(m1, y1)-d1) + (d2-1);
	m = (m1 + 1) % 12;
	while (m != m2) {
		if (m == 0)
			y1++;
		days += days_in_mon(m, y1);
		m = (m + 1) % 12;
	}
	return (days);
}

int
days_in_mon(int m, int y)
{
	/*
	 * returns the number of days in month m of year y
	 * NOTE: m should be in the range 0 to 11
	 */
	return (dom[m] + (((m == 1) && isleap(y + YEAR)) ? 1 : 0));
}

void *
xmalloc(size_t size)
{
	char *p;

	if ((p = malloc(size)) == NULL) {
		perror("malloc");
		exit(55);
	}
	return (p);
}

void *
xcalloc(size_t nElements, size_t size)
{
	void *p;

	if ((p = calloc(nElements, size)) == NULL) {
		perror("calloc");
		exit(55);
	}
	return (p);
}

char *
xstrdup(const char *str)
{
	int	len;
	char	*p;

	len = strlen(str);
	p = xmalloc(len + 1);
	(void) memcpy(p, str, len);
	p[len] = '\0';

	return (p);
}

void
cron_sendmsg(char action, char *login, char *fname, char etype)
{
	static int	msgfd = -2;
	struct message	*pmsg, msgbuf;
	int	i;

	(void) memset(&msgbuf, 0, sizeof (msgbuf));
	pmsg = &msgbuf;
	if (msgfd == -2) {
		if ((msgfd = open(FIFO, O_WRONLY|O_NDELAY)) < 0) {
			if (errno == ENXIO || errno == ENOENT)
				(void) fprintf(stderr, gettext("cron may not"
				    " be running - call your system"
				    " administrator\n"));
			else
				(void) fprintf(stderr, gettext(
				    "error in message queue open\n"));
			return;
		}
	}
	pmsg->etype = etype;
	pmsg->action = action;
	(void) strlcpy(pmsg->fname, fname, FLEN);
	(void) strlcpy(pmsg->logname, login, LLEN);
	if ((i = write(msgfd, pmsg, sizeof (struct message))) < 0)
		(void) fprintf(stderr, gettext("error in message send\n"));
	else if (i != sizeof (struct message))
		(void) fprintf(stderr, gettext(
		    "error in message send: Premature EOF\n"));
}

char
*errmsg(int errnum)
{
	char *msg;
	static char msg_buf[32];

	msg = strerror(errnum);

	if (msg == NULL) {
		(void) snprintf(msg_buf, sizeof (msg_buf),
		    gettext("Error %d"), errnum);
		return (msg_buf);
	} else
		return (msg);
}

int
filewanted(struct dirent *direntry)
{
	char		*p;
	char		c;

	p = direntry->d_name;
	(void) num(&p);
	if (p == direntry->d_name)
		return (0);	/* didn't start with a number */
	if (*p++ != '.')
		return (0);	/* followed by a period */
	c = *p++;
	if (c < 'a' || c > 'z')
		return (0);	/* followed by a queue name */
	if (audit_cron_is_anc_name(direntry->d_name))
		return (0);
	return (1);
}

int
isvalid_shell(const char *shell)
{
	char *t;
	int ret = 0;

	while ((t =  getusershell()) != NULL) {
		if (strcmp(t, shell) == 0) {
			ret = 1;
			break;
		}
	}
	endusershell();
	return (ret);
}

int
isvalid_dir(const char *dir)
{
	char *cwd = getcwd(NULL, 0);

	if (dir[0] != '/' || chdir(dir) == -1) {
		return (0);
	}
	if (cwd != NULL) {
		(void) chdir(cwd);
	}
	return (1);
}
