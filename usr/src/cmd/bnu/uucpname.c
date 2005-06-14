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
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "uucp.h"

/*
 * get the uucp name
 * return:
 *	none
 */
void
uucpname(name)
register char *name;
{
	char *s;
	char NameBuf[MAXBASENAME + 1];
	FILE *NameFile;

	NameBuf[0] = '\0';
	if ((NameFile = fopen(SYSNAMEFILE, "r")) != NULL) {
		if (fscanf(NameFile, "%14s", NameBuf) != 1) {
			(void) fprintf(stderr,
				gettext("No system name specified in %s\n"),
				SYSNAMEFILE);
			cleanup(-1);
		}
		s = NameBuf;
		(void) fclose(NameFile);
	} else {
#ifdef BSD4_2
	char	NameBuf[MAXBASENAME + 1];

	gethostname(NameBuf, MAXBASENAME);
	/* strip off any domain name part */
	if ((s = index(NameBuf, '.')) != NULL)
		*s = '\0';
	s = NameBuf;
	s[MAXBASENAME] = '\0';
#else /* !BSD4_2 */
#ifdef UNAME
	struct utsname utsn;

	uname(&utsn);
	s = utsn.nodename;
#else /* !UNAME */
	char	NameBuf[MAXBASENAME + 1], *strchr();
	FILE	*NameFile;

	s = MYNAME;
	NameBuf[0] = '\0';

	if ((NameFile = fopen("/etc/whoami", "r")) != NULL) {
		/* etc/whoami wins */
		(void) fgets(NameBuf, MAXBASENAME + 1, NameFile);
		(void) fclose(NameFile);
		NameBuf[MAXBASENAME] = '\0';
		if (NameBuf[0] != '\0') {
			if ((s = strchr(NameBuf, '\n')) != NULL)
				*s = '\0';
			s = NameBuf;
		}
	}
#endif /* UNAME */
#endif /* BSD4_2 */
	}

	(void) strncpy(name, s, MAXBASENAME);
	name[MAXBASENAME] = '\0';
	/* strip off any domain name from the host name */
	if ((s = strchr(name, '.')) != NULL)
		*s = '\0';
	return;
}
