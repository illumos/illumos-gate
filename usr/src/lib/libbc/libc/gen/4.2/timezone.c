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
 * Copyright 1986 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
	  /* from UCB 4.4 83/09/25 */

/*
 * The arguments are the number of minutes of time
 * you are westward from Greenwich and whether DST is in effect.
 * It returns a string
 * giving the name of the local timezone.
 *
 * Sorry, I don't know all the names.
 */

static struct zone {
	int	offset;
	char	*stdzone;
	char	*dlzone;
} zonetab[] = {
	-12*60,    "NZST", "NZDT",	/* New Zealand */
	-10*60,    "EST",  "EST",	/* Aust: Eastern */
	-10*60+30, "CST",  "CST",	/* Aust: Central */
	 -8*60,    "WST",  0,		/* Aust: Western */
	 -9*60,    "JST",  0,		/* Japanese */
	  0*60,    "GMT",  "BST",	/* Great Britain and Eire */
	 -1*60,    "MET",  "MET DST",	/* Middle European */
	 -2*60,    "EET",  "EET DST",	/* Eastern European */
	  3*60+30, "NST",  "NDT",	/* Newfoundland */
	  4*60,    "AST",  "ADT",	/* Atlantic */
	  5*60,    "EST",  "EDT",	/* Eastern */
	  6*60,    "CST",  "CDT",	/* Central */
	  7*60,    "MST",  "MDT",	/* Mountain */
	  8*60,    "PST",  "PDT",	/* Pacific */
	  9*60,    "YST",  "YDT",	/* Yukon */
	 10*60,    "HST",  "HDT",	/* Hawaiian */
	-1
};

char *timezone(zone, dst)
{
	register struct zone *zp;
	static char czone[10];
	char *sign;
	register char *p, *q;
	char *getenv(), *index();

	if (p = getenv("TZNAME")) {
		if (q = index(p, ',')) {
			if (dst)
				return(++q);
			else {
				*q = '\0';
				strncpy(czone, p, sizeof(czone)-1);
				czone[sizeof(czone)-1] = '\0';
				*q = ',';
				return (czone);
			}
		}
		return(p);
	}
	for (zp=zonetab; zp->offset!=-1; zp++)
		if (zp->offset==zone) {
			if (dst && zp->dlzone)
				return(zp->dlzone);
			if (!dst && zp->stdzone)
				return(zp->stdzone);
		}
	if (zone<0) {
		zone = -zone;
		sign = "+";
	} else
		sign = "-";
	sprintf(czone, "GMT%s%d:%02d", sign, zone/60, zone%60);
	return(czone);
}
