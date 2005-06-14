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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
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

#include <sys/param.h>

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <protocols/rwhod.h>

static	DIR *dirp;

static	struct whod wd;
#define	NUSERS	1000
static	struct myutmp {
	char	myhost[32];
	int	myidle;
	struct	outmp myutmp;
} myutmp[NUSERS];
static	int utmpcmp(const void *, const void *);
static	int nusers;

#define	WHDRSIZE	(sizeof (wd) - sizeof (wd.wd_we))
#define	RWHODIR		"/var/spool/rwho"
/*
 * this macro should be shared with ruptime.
 */
#define	down(w, now)	((now) - (w)->wd_recvtime > 11 * 60)

static	time_t now;
static	int aflg = 0;

int
main(int argc, char **argv)
{
	struct dirent *dp;
	int cc, width;
	register struct whod *w = &wd;
	register struct whoent *we;
	register struct myutmp *mp;
	int f, n, i;

	argc--, argv++;
again:
	if (argc > 0 && strcmp(argv[0], "-a") == 0) {
		argc--, argv++;
		aflg++;
		goto again;
	}
	(void) time(&now);
	if (chdir(RWHODIR) < 0) {
		perror(RWHODIR);
		return (EXIT_FAILURE);
	}
	dirp = opendir(".");
	if (dirp == NULL) {
		perror(RWHODIR);
		return (EXIT_FAILURE);
	}
	mp = myutmp;
	while (dp = readdir(dirp)) {
		if (dp->d_ino == 0)
			continue;
		if (strncmp(dp->d_name, "whod.", 5))
			continue;
		f = open(dp->d_name, 0);
		if (f < 0)
			continue;
		cc = read(f, (char *)&wd, sizeof (struct whod));
		if (cc < WHDRSIZE) {
			(void) close(f);
			continue;
		}
		if (down(w, now)) {
			(void) close(f);
			continue;
		}
		cc -= WHDRSIZE;
		we = w->wd_we;
		for (n = cc / sizeof (struct whoent); n > 0; n--) {
			if (aflg == 0 && we->we_idle >= 60*60) {
				we++;
				continue;
			}
			if (nusers >= NUSERS) {
				(void) printf("too many users\n");
				return (EXIT_FAILURE);
			}
			mp->myutmp = we->we_utmp; mp->myidle = we->we_idle;
			(void) strncpy(mp->myhost, w->wd_hostname,
			    sizeof (mp->myhost));
			nusers++; we++; mp++;
		}
		(void) close(f);
	}
	qsort((char *)myutmp, nusers, sizeof (struct myutmp), utmpcmp);
	mp = myutmp;
	width = 0;
	for (i = 0; i < nusers; i++) {
		int j = strlen(mp->myhost) + 1 + strlen(mp->myutmp.out_line);
		if (j > width)
			width = j;
		mp++;
	}
	mp = myutmp;
	for (i = 0; i < nusers; i++) {
		char buf[BUFSIZ];
		(void) snprintf(buf, BUFSIZ, "%.*s:%.*s",
		    sizeof (mp->myhost), mp->myhost,
		    sizeof (mp->myutmp.out_line), mp->myutmp.out_line);
		(void) printf("%-8.*s %-*s %.12s",
		    sizeof (mp->myutmp.out_name), mp->myutmp.out_name,
		    width, buf,
		    ctime((time_t *)&mp->myutmp.out_time) + 4);
		mp->myidle /= 60;
		if (mp->myidle) {
			if (aflg) {
				if (mp->myidle >= 100*60)
					mp->myidle = 100*60 - 1;
				if (mp->myidle >= 60)
					(void) printf(" %2d", mp->myidle / 60);
				else
					(void) fputs("   ", stdout);
			} else
				(void) printf(" ");
			(void) printf(":%02d", mp->myidle % 60);
		}
		(void) puts("");
		mp++;
	}
	return (EXIT_SUCCESS);
}

static int
utmpcmp(const void *p1, const void *p2)
{
	const struct myutmp *u1 = p1, *u2 = p2;
	int rc;

	rc = strncmp(u1->myutmp.out_name, u2->myutmp.out_name,
	    sizeof (u1->myutmp.out_name));
	if (rc != 0)
		return (rc);
	rc = strncmp(u1->myhost, u2->myhost, sizeof (u1->myhost));
	if (rc != 0)
		return (rc);
	return (strncmp(u1->myutmp.out_line, u2->myutmp.out_line,
	    sizeof (u1->myutmp.out_line)));
}
