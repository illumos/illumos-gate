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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

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

#include <sys/param.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <protocols/rwhod.h>

static DIR	*dirp;

#define	HOSTLIM	100
static int	hostslim = HOSTLIM;
static int	nhosts;
struct	hs {
	struct	whod *hs_wd;
	int	hs_nusers;
};
static int	hscmp(), ucmp(), lcmp(), tcmp();

#define	RWHODIR		"/var/spool/rwho"

static char	*interval();
static time_t	now;
static int	aflg;
static int	rflg = 1;

#define	down(h)		(now - (h)->hs_wd->wd_recvtime > 11 * 60)

/* ARGSUSED */
int
main(int argc, char **argv)
{
	struct dirent *dp;
	int f, i;
	struct whod *buf;
	int cc;
	char *name;
	struct hs *hs;
	struct hs *hsp;
	struct whod *wd;
	struct whoent *we;
	int maxloadav = 0;
	int (*cmp)() = hscmp;
	ptrdiff_t hoff;

	name = *argv;
	while (*++argv)
		while (**argv)
			switch (*(*argv)++) {
			case 'a':
				aflg++;
				break;
			case 'l':
				cmp = lcmp;
				break;
			case 'u':
				cmp = ucmp;
				break;
			case 't':
				cmp = tcmp;
				break;
			case 'r':
				rflg = -rflg;
				break;
			case '-':
				break;
			default:
				(void) fprintf(stderr, "Usage: %s [ -alrtu ]"
				    " (choose at most one of l, t, or u)\n",
				    name);
				exit(1);
			}

	if ((hs = malloc(hostslim * sizeof (struct hs))) == NULL) {
		(void) fprintf(stderr, "initial hs malloc failed\n");
		exit(1);
	}
	hsp = hs;
	if ((buf = malloc(sizeof (struct whod))) == NULL) {
		(void) fprintf(stderr, "initial buf malloc failed\n");
		exit(1);
	}

	if (chdir(RWHODIR) < 0) {
		perror(RWHODIR);
		exit(1);
	}
	dirp = opendir(".");
	if (dirp == NULL) {
		perror(RWHODIR);
		exit(1);
	}
	while (dp = readdir(dirp)) {
		if (dp->d_ino == 0)
			continue;
		if (strncmp(dp->d_name, "whod.", 5))
			continue;
		if (nhosts == hostslim) {
			/*
			 * We trust that the file system's limit on the number
			 * of files in a directory will kick in long before
			 * integer overflow.
			 */
			hostslim = hostslim << 1;

			/*
			 * hsp points into an area about to be moved,
			 * so we first remember its offset into hs[],
			 * then restore it after realloc() has moved
			 * the data.
			 */
			hoff = hsp - hs;
			hs = realloc(hs, hostslim * sizeof (struct hs));
			if (hs == NULL) {
				(void) fprintf(stderr, "too many hosts\n");
				exit(1);
			}
			hsp = hs + hoff;
		}
		f = open(dp->d_name, 0);
		if (f > 0) {
			int whdrsize = sizeof (*buf) - sizeof (buf->wd_we);

			cc = read(f, buf, sizeof (struct whod));
			if (cc >= whdrsize) {
				hsp->hs_wd = malloc(whdrsize);
				wd = buf;
				bcopy((char *)buf, (char *)hsp->hs_wd,
				    whdrsize);
				hsp->hs_nusers = 0;
				for (i = 0; i < 2; i++)
					if (wd->wd_loadav[i] > maxloadav)
						maxloadav = wd->wd_loadav[i];
				/* LINTED:  pointer alignment */
				we = (struct whoent *)(((char *)buf)+cc);
				while (--we >= wd->wd_we)
					if (aflg || we->we_idle < 3600)
						hsp->hs_nusers++;
				nhosts++; hsp++;
			}
		}
		(void) close(f);
	}
	(void) time(&now);
	qsort((char *)hs, nhosts, sizeof (hs[0]), cmp);
	if (nhosts == 0) {
		(void) printf("no hosts!?!\n");
		exit(1);
	}
	for (i = 0; i < nhosts; i++) {
		hsp = &hs[i];
		if (down(hsp)) {
			(void) printf("%-12s%s\n", hsp->hs_wd->wd_hostname,
			    interval((int)(now - hsp->hs_wd->wd_recvtime),
				"down"));
			continue;
		}
		(void) printf("%-12s%s,  %4d user%s  load %*.2f,"
		    " %*.2f, %*.2f\n",
		    hsp->hs_wd->wd_hostname,
		    interval(hsp->hs_wd->wd_sendtime -
			hsp->hs_wd->wd_boottime, "  up"),
		    hsp->hs_nusers,
		    hsp->hs_nusers == 1 ? ", " : "s,",
		    maxloadav >= 1000 ? 5 : 4,
			hsp->hs_wd->wd_loadav[0] / 100.0,
		    maxloadav >= 1000 ? 5 : 4,
			hsp->hs_wd->wd_loadav[1] / 100.0,
		    maxloadav >= 1000 ? 5 : 4,
			hsp->hs_wd->wd_loadav[2] / 100.0);
		free(hsp->hs_wd);
	}

	return (0);
}

static char *
interval(int time, char *updown)
{
	static char resbuf[32];
	int days, hours, minutes;

	if (time < 0 || time > 10*365*24*60*60) {
		(void) sprintf(resbuf, "   %s ??:??", updown);
		return (resbuf);
	}
	minutes = (time + 59) / 60;		/* round to minutes */
	hours = minutes / 60; minutes %= 60;
	days = hours / 24; hours %= 24;
	if (days)
		(void) sprintf(resbuf, "%s %2d+%02d:%02d",
		    updown, days, hours, minutes);
	else
		(void) sprintf(resbuf, "%s    %2d:%02d",
		    updown, hours, minutes);
	return (resbuf);
}

static int
hscmp(struct hs *h1, struct hs *h2)
{

	return (rflg * strcmp(h1->hs_wd->wd_hostname, h2->hs_wd->wd_hostname));
}

/*
 * Compare according to load average.
 */
static int
lcmp(struct hs *h1, struct hs *h2)
{

	if (down(h1))
		if (down(h2))
			return (tcmp(h1, h2));
		else
			return (rflg);
	else if (down(h2))
		return (-rflg);
	else
		return (rflg *
			(h2->hs_wd->wd_loadav[0] - h1->hs_wd->wd_loadav[0]));
}

/*
 * Compare according to number of users.
 */
static int
ucmp(struct hs *h1, struct hs *h2)
{

	if (down(h1))
		if (down(h2))
			return (tcmp(h1, h2));
		else
			return (rflg);
	else if (down(h2))
		return (-rflg);
	else
		return (rflg * (h2->hs_nusers - h1->hs_nusers));
}

/*
 * Compare according to uptime.
 */
static int
tcmp(struct hs *h1, struct hs *h2)
{

	return (rflg * (
		(down(h2) ? h2->hs_wd->wd_recvtime - now :
		    h2->hs_wd->wd_sendtime - h2->hs_wd->wd_boottime)
		-
		(down(h1) ? h1->hs_wd->wd_recvtime - now :
		    h1->hs_wd->wd_sendtime - h1->hs_wd->wd_boottime)));
}
