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


#ident	"%Z%%M%	%I%	%E% SMI"	/* from SVR4 bnu:gtcfile.c 2.5 */

#include "uucp.h"

#define NCSAVE	30	/* no more than 30 saved C files, please */
static int ncsave;
static struct cs_struct csave[NCSAVE];
int Dfileused = FALSE;
static char jobid[NAMESIZE];

extern void wfcommit(), wfremove(), putdfiles();
extern int job_size(), fgrade(), retseq();

/*	commitall()
 *
 *	commit any and all saved C files
 *
 *	returns
 *		nothing
 */

void
commitall()
{
	char sys[NAMESIZE+5];
	char cmfile[NAMESIZE+5];
	int i;
	int n;

	for (i = 0; i < ncsave; i++) {
		if (Sgrades) {
			if ((job_size(&csave[i]) == FAIL) ||
			    (fgrade(&csave[i]) == FAIL)) {
				wfremove(csave[i].file);
				continue;
			}
		}
		else {
			Dfileused = TRUE;
			csave[i].grade = Grade;
		}

		/* make new file name for for the job */

		if (Sgrades) {
			n = retseq(csave[i].sys);
			(void) sprintf(cmfile, "%c.%.*s%c%.4x", *csave[i].file,
				SYSNSIZE, csave[i].sys, csave[i].grade, n);
		}
		else
			(void) strncpy(cmfile, csave[i].file, NAMESIZE-1);
		cmfile[NAMESIZE-1] = '\0';

		DEBUG(9, "User job queued to %c queue\n", csave[i].grade);
		(void) sprintf(sys, "/%c", csave[i].grade);
		(void) strcat(csave[i].sys, sys);
		if (Dfileused) {
			putdfiles(csave[i]);
			Dfileused = FALSE;
		}
		wfcommit(csave[i].file, cmfile, csave[i].sys);
		(void) strncpy(csave[i].file, cmfile, NAMESIZE);
	}

	ncsave = 0;

	/* set real jobid */

	(void) strncpy(jobid, BASENAME(csave[0].file, '.'), NAMESIZE);
	return;
}

/*
 *	gtcfile - copy into file the name of the saved C file for system sys
 *
 *	returns
 *		SUCCESS	-> found one
 *		FAIL	-> none saved
 *
 */

int
gtcfile(file, sys)
char	*file, *sys;
{
	register int	i;

	for (i = 0; i < ncsave; i++)
		if (strncmp(sys, csave[i].sys, SYSNSIZE) == SAME) {
			(void) strncpy(file, csave[i].file, NAMESIZE-1);
			return(SUCCESS);
		}

	return(FAIL);
}

/*
 *	jid - returns the real job id of this uucp file transfer
 *
 *	returns
 *		jobid
 *
 */

char *
jid()
{
	return(jobid);
}

/*
 *	svcfile  - save the name of a C. file for system sys for re-using
 *	returns
 *		none
 */

void
svcfile(file, sys, grd)
char	*file, *sys, *grd;
{
	ASSERT(ncsave < NCSAVE, "TOO MANY SAVED C FILES", "", ncsave);
	(void) strncpy(csave[ncsave].file, BASENAME(file, '/'), NAMESIZE-1);
	(void) strncpy(csave[ncsave].sys, sys, NAMESIZE-1);
	(void) strncpy (csave[ncsave].sgrade, grd, NAMESIZE-1);
	ncsave++;
	return;
}

void
wfabort()
{
	register int	i;

	for (i = 0; i < ncsave; i++)
		wfremove(csave[i].file);
	ncsave = 0;
	return;
}

/*
 *	wfcommit - move wfile1 in current directory to SPOOL/sys/dir/wfile2
 *	return
 *		none
 */

void
wfcommit(wfile1, wfile2, sys)
char	*wfile1, *wfile2, *sys;
{
	char	cmitfile[MAXFULLNAME];
	char	remote[NAMESIZE];
	char	*fileBase;
	char	*p;

	/* make remote directory if it does not exist */

	(void) strncpy(remote, sys, NAMESIZE);
	if ((p = strchr(remote, '/')) != NULL) {
		*p++ = '\0';

		DEBUG(6, "create remote spool area %s\n", remote);
		mkremdir(remote);
	}

	if (p != NULL)
		DEBUG(6, "create service grade directory %s under remote spool\n", p);
	else
		DEBUG(6, "create remote spool area %s\n", sys);

	mkremdir(sys);

	DEBUG(6, "commit %s ", wfile1);

	fileBase = BASENAME(wfile2, '/');
	sprintf(cmitfile, "%s/%s", RemSpool, fileBase);
	DEBUG(6, "to %s\n", cmitfile);

	ASSERT(access(cmitfile, 0) != 0, Fl_EXISTS, cmitfile, 0);
	ASSERT(xmv(wfile1, cmitfile) == 0, Ct_LINK, cmitfile, errno);
	return;
}
