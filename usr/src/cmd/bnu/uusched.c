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
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"uucp.h"

#define USAGE	"[-xNUM] [-uNUM]"
#define MAXGRADE	52

struct m {
	char	mach[15];
	char	jgrade[2*MAXGRADE+1];
} M[UUSTAT_TBL+2];

short Uopt;
void cleanup(), exuucico();

void logent(){}		/* to load ulockf.c */

int
main(argc, argv, envp)
int argc;
char *argv[];
char **envp;
{
	struct m *m, *machine();
	DIR *spooldir, *subdir, *gradedir;
	char f[256], g[256], fg[256], subf[256];
	int numgrade;
	char *gradelist, *gradeptr[MAXGRADE+1];
	short num, snumber;
	char lckname[MAXFULLNAME];
	struct limits limitval;
	int i, maxnumb;
	FILE *fp;

	Uopt = 0;
	Env = envp;

	(void) strcpy(Progname, "uusched");
	while ((i = getopt(argc, argv, "u:x:")) != EOF) {
		switch(i){
		case 'x':
			Debug = atoi(optarg);
			if (Debug <= 0) {
				fprintf(stderr,
				"WARNING: %s: invalid debug level %s ignored, using level 1\n",
				Progname, optarg);
				Debug = 1;
			}
#ifdef SMALL
			fprintf(stderr,
			"WARNING: uusched built with SMALL flag defined -- no debug info available\n");
#endif /* SMALL */
			break;
		case 'u':
			Uopt = atoi(optarg);
			if (Uopt <= 0) {
				fprintf(stderr,
				"WARNING: %s: invalid debug level %s ignored, using level 1\n",
				Progname, optarg);
				Uopt = 1;
			}
			break;
		default:
			(void) fprintf(stderr, "\tusage: %s %s\n",
			    Progname, USAGE);
			cleanup(1);
		}
	}
	if (argc != optind) {
		(void) fprintf(stderr, "\tusage: %s %s\n", Progname, USAGE);
		cleanup(1);
	}

	DEBUG(9, "Progname (%s): STARTED\n", Progname);
	if (scanlimit("uusched", &limitval) == FAIL) {
	    DEBUG(1, "No limits for uusched in %s\n", LIMITS);
	    maxnumb = -1;
	} else {
	    maxnumb = limitval.totalmax;
	    if (maxnumb < 0) {
		DEBUG(4, "Non-positive limit for uusched in %s\n", LIMITS);
		DEBUG(1, "No limits for uusched\n%s", "");
	    } else {
		DEBUG(4, "Uusched limit %d -- ", maxnumb);
		i = cuantos(S_LOCKPRE, X_LOCKDIR);
		if (i >= maxnumb) {
			DEBUG(4, "found %d -- cleaning up\n", i);
			cleanup(0);
		}
		DEBUG(4, "continuing\n", maxnumb);
	    }
	}

	if (chdir(SPOOL) != 0 || (spooldir = opendir(SPOOL)) == NULL)
		cleanup(101);		/* good old code 101 */
	while (gdirf(spooldir, f, SPOOL) == TRUE) {
	    subdir = opendir(f);
	    ASSERT(subdir != NULL, Ct_OPEN, f, errno);
	    while (gdirf(subdir, g, f) == TRUE) {
		(void) sprintf(fg, "%s/%s", f, g);
		gradedir = opendir(fg);
		ASSERT(gradedir != NULL, Ct_OPEN, g, errno);
		while (gnamef(gradedir, subf) == TRUE) {
		    if (subf[1] == '.') {
		        if (subf[0] == CMDPRE) {
			    /* Note - we can break now, since we
			     * have found a job grade with at least
			     * one C. file.
			    */
			    (void) strncat(machine(f)->jgrade, g, strlen(g));
			    break;
			}
		    }
		}
		closedir(gradedir);
	    }
	    closedir(subdir);
	}

	/* Make sure the overflow entry is null since it may be incorrect */
	M[UUSTAT_TBL].mach[0] = NULLCHAR;

	/* count the number of systems */
	for (num=0, m=M; m->mach[0] != '\0'; m++, num++) {
	    DEBUG(5, "machine: %s, ", M[num].mach);
	    DEBUG(5, "job grade list: %s\n", M[num].jgrade);
	}
	DEBUG(5, "Execute num=%d \n", num);
	while (num > 0) {
	    /*
	     * create lock file once we have work to do
	     * (but only if there is a job limit)
	     */
	    if (maxnumb > 0) {
	    	    for (i = 0; i < maxnumb; i++) {
			    (void) sprintf(lckname, "%s.%d", S_LOCK, i);
			    if (mklock(lckname) == SUCCESS)
			    	    break;
		    }
		    if (i == maxnumb) {
			    DEBUG(4, "found %d -- cleaning up\n", i);
			    cleanup(0);
		    }
	    }
	    snumber = (time((time_t *) 0) % num);  /* random num */
	    (void) strcpy(Rmtname, M[snumber].mach);
	    gradelist = M[snumber].jgrade;
	    DEBUG(5, "num=%d, ", num);
	    DEBUG(5, "snumber=%d, ", snumber);
	    DEBUG(5, "Rmtname=%s, ", Rmtname);
	    DEBUG(5, "job grade list= %s\n", gradelist);

	    numgrade = getargs(gradelist, gradeptr, MAXGRADE);
	    for (i=0; i<numgrade; i++) {
		(void) sprintf(lckname, "%s.%s.%s", LOCKPRE, Rmtname, gradeptr[i]);
		if (cklock(lckname) != FAIL && callok(Rmtname) == 0) {
		    /* no lock file and status time ok */
		    DEBUG(5, "call exuucico(%s)\n", Rmtname);
		    exuucico(Rmtname);
		    break;
		}
		else {
		    /* job grade locked - look for the next one */
		    DEBUG(5, "job grade %s locked or inappropriate status\n",
			gradeptr[i]);
		}
	    }
	    
	    M[snumber] = M[num-1];
	    num--;
	}
	cleanup(0);

	/* NOTREACHED */
	return (0);
}

struct m	*
machine(name)
char	*name;
{
	struct m *m;
	size_t	namelen;

	namelen = strlen(name);
	DEBUG(9, "machine(%s) called\n", name);
	for (m = M; m->mach[0] != '\0'; m++)
		/* match on overlap? */
		if (EQUALSN(name, m->mach, MAXBASENAME)) {
			/* check for job grade */
			if (m->jgrade[0] != NULLCHAR)
				(void) strncat(m->jgrade, " ", 1);

			/* use longest name */
			if (namelen > strlen(m->mach))
				(void) strcpy(m->mach, name);
			return(m);
		}

	/*
	 * The table is set up with 2 extra entries
	 * When we go over by one, output error to errors log
	 * When more than one over, just reuse the previous entry
	 */
	if (m-M >= UUSTAT_TBL) {
	    if (m-M == UUSTAT_TBL) {
		errent("MACHINE TABLE FULL", "", UUSTAT_TBL,
		__FILE__, __LINE__);
	    }
	    else
		/* use the last entry - overwrite it */
		m = &M[UUSTAT_TBL];
	}

	(void) strcpy(m->mach, name);
	m->jgrade[0] = NULLCHAR;
	return(m);
}

void
exuucico(name)
char *name;
{
	char cmd[BUFSIZ];
	int status;
	pid_t pid, ret;
	char uopt[5];
	char sopt[BUFSIZ];

	(void) sprintf(sopt, "-s%s", name);
	if (Uopt)
	    (void) sprintf(uopt, "-x%.1d", Uopt);

	if ((pid = vfork()) == 0) {
	    if (Uopt)
	        (void) execle(UUCICO, "UUCICO", "-r1", uopt, sopt, (char *) 0, Env);
	    else
	        (void) execle(UUCICO, "UUCICO", "-r1", sopt, (char *) 0, Env);

	    cleanup(100);
	}
	while ((ret = wait(&status)) != pid)
	    if (ret == -1 && errno != EINTR)
		break;

	DEBUG(3, "ret=%ld, ", (ret == pid ? (long) status : (long) ret));
	return;
}


void
cleanup(code)
int	code;
{
	rmlock(CNULL);
	exit(code);
}
