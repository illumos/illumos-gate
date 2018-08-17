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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include "pkgstrct.h"
#include "pkglocale.h"

#define	MSG_INVALID	"invalid entry"

void
tputcfent(struct cfent *ept, FILE *fp)
{
	int	count, status;
	char	*pt;
	struct pinfo *pinfo;
	struct	tm	*timep;
	char	timeb[BUFSIZ];

	if (ept->path == NULL)
		return;

	(void) fprintf(fp, pkg_gt("Pathname: %s\n"), ept->path);
	(void) fprintf(fp, pkg_gt("Type: "));

	switch (ept->ftype) {
	case 'f':
		(void) fputs(pkg_gt("regular file\n"), fp);
		break;

	case 'd':
		(void) fputs(pkg_gt("directory\n"), fp);
		break;

	case 'x':
		(void) fputs(pkg_gt("exclusive directory\n"), fp);
		break;

	case 'v':
		(void) fputs(pkg_gt("volatile file\n"), fp);
		break;

	case 'e':
		(void) fputs(pkg_gt("editted file\n"), fp);
		break;

	case 'p':
		(void) fputs(pkg_gt("named pipe\n"), fp);
		break;

	case 'i':
		(void) fputs(pkg_gt("installation file\n"), fp);
		break;

	case 'c':
	case 'b':
		(void) fprintf(fp, pkg_gt("%s special device\n"),
		    (ept->ftype == 'b') ? pkg_gt("block") :
		    pkg_gt("character"));

		if (ept->ainfo.major == BADMAJOR)
			(void) fprintf(fp, pkg_gt("Major device number: %s\n"),
			    MSG_INVALID);
		else
			(void) fprintf(fp, pkg_gt("Major device number: %ld\n"),
			    ept->ainfo.major);

		if (ept->ainfo.minor == BADMINOR)
			(void) fprintf(fp, pkg_gt("Minor device number: %s\n"),
			    MSG_INVALID);
		else
			(void) fprintf(fp, pkg_gt("Minor device number: %ld\n"),
			    ept->ainfo.minor);

		break;

	case 'l':
		(void) fputs(pkg_gt("linked file\n"), fp);
		pt = (ept->ainfo.local ? ept->ainfo.local :
		    (char *)pkg_gt("(unknown)"));
		(void) fprintf(fp, pkg_gt("Source of link: %s\n"), pt);
		break;

	case 's':
		(void) fputs(pkg_gt("symbolic link\n"), fp);
		pt = (ept->ainfo.local ? ept->ainfo.local :
		    (char *)pkg_gt("(unknown)"));
		(void) fprintf(fp, pkg_gt("Source of link: %s\n"), pt);
		break;

	default:
		(void) fputs(pkg_gt("unknown\n"), fp);
		break;
	}

	if (!strchr("lsin", ept->ftype)) {
		if (ept->ainfo.mode == BADMODE)
			(void) fprintf(fp, pkg_gt("Expected mode: %s\n"),
			    "?");
		else
			(void) fprintf(fp, pkg_gt("Expected mode: %04lo\n"),
			    ept->ainfo.mode);

		(void) fprintf(fp, pkg_gt("Expected owner: %s\n"),
		    ept->ainfo.owner);
		(void) fprintf(fp, pkg_gt("Expected group: %s\n"),
		    ept->ainfo.group);
	}
	if (strchr("?infv", ept->ftype)) {
		(void) fprintf(fp,
		    pkg_gt("Expected file size (bytes): %llu\n"),
		    ept->cinfo.size);
		(void) fprintf(fp,
		    pkg_gt("Expected sum(1) of contents: %ld\n"),
		    ept->cinfo.cksum);
		if (ept->cinfo.modtime > 0) {
			timep = localtime(&(ept->cinfo.modtime));
			(void) strftime(timeb, sizeof (timeb),
			    pkg_gt("Expected last modification: %b %d %X %Y\n"),
			    timep);
			(void) fputs(timeb, fp);
		} else
			(void) fprintf(fp,
			    pkg_gt("Expected last modification: ?\n"));
	}
	if (ept->ftype == 'i') {
		(void) fputc('\n', fp);
		return;
	}

	status = count = 0;
	if ((pinfo = ept->pinfo) != NULL) {
		(void) fprintf(fp,
		    pkg_gt("Referenced by the following packages:\n\t"));
		while (pinfo) {
			/*
			 * Check for partially installed object.  Need
			 * to explicitly check for '!', because objects
			 * that are provided by a server will have a
			 * different status character.
			 */
			if (pinfo->status == '!')
				status++;
			(void) fprintf(fp, "%-14s ", pinfo->pkg);
			if ((++count % 5) == 0) {
				(void) fputc('\n', fp);
				(void) fputc('\t', fp);
				count = 0;
			}
			pinfo = pinfo->next;
		}
		(void) fputc('\n', fp);
	}
	(void) fprintf(fp, pkg_gt("Current status: %s\n"),
	    status ? pkg_gt("partially installed") :
	    pkg_gt("installed"));
	(void) fputc('\n', fp);
}
