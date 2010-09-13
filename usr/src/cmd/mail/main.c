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

#include "mail.h"
#ifdef SVR4
#include <locale.h>
#endif
/*
 *	mail [ -ehpPqrtw ] [-x debuglevel] [ -f file ] [ -F user(s) ]
 *	mail -T file persons
 *	mail [ -tw ] [ -m messagetype ] persons
 *	rmail [ -tw ] persons
 */
int
main(int argc, char **argv)
{
	register int i;
	char *cptr, *p;
	struct stat statb;
	static char pn[] = "main";
	extern char **environ;
	int env_var_idx, next_slot_idx;
	int tmpfd = -1;

#ifdef SVR4
	(void) setlocale(LC_ALL, "");
#endif
	/* fix here for bug #1086130 - security hole	*/
	/* skip over the LD_* env variable		*/
	env_var_idx = 0; next_slot_idx = 0;
	while (environ[env_var_idx] != NULL) {
			environ[next_slot_idx] = environ[env_var_idx];
		if (strncmp(environ[env_var_idx], "LD_", 3)) {
			next_slot_idx++;
		}
		env_var_idx++;
	}
	environ[next_slot_idx] = NULL;

#ifdef SIGCONT
#ifdef SVR4
	{
	struct sigaction nsig;
	nsig.sa_handler = SIG_DFL;
	sigemptyset(&nsig.sa_mask);
	nsig.sa_flags = SA_RESTART;
	(void) sigaction(SIGCONT, &nsig, (struct sigaction *)0);
	}
#else
	sigset(SIGCONT, SIG_DFL);
#endif
#endif

	/*
	 *	Strip off path name of this command for use in messages
	 */
	if ((program = strrchr(argv[0], '/')) != NULL) {
		program++;
	} else {
		program = argv[0];
	}

	/* Close all file descriptors except stdin, stdout & stderr */
	closefrom(STDERR_FILENO + 1);

	/*
	 *	Get group id for mail, exit if none exists
	 */
	if ((grpptr = getgrnam("mail")) == NULL) {
		errmsg(E_GROUP, "");
		exit(1);
	} else {
		mailgrp = grpptr->gr_gid;
	}

	/*
	 *	Save the *id for later use.
	 */
	my_uid = getuid();
	my_gid = getgid();
	my_euid = geteuid();
	my_egid = getegid();

	/*
	 *	What command (rmail or mail)?
	 */
	if (strcmp(program, "rmail") == SAME) {
		ismail = FALSE;
	}

	/*
	 *	Parse the command line and adjust argc and argv
	 *	to compensate for any options
	 */
	i = parse(argc, argv);
	argv += (i - 1);
	argc -= (i - 1);

	/* block a potential security hole */
	if (flgT && (my_euid != 0)) {
		setgid(my_gid);
		Tout(pn, "Setgid unset\n");
	}

	if (debug == 0) {
		/* If not set as an invocation option, check for system-wide */
		/* global flag */
		char *xp = xgetenv("DEBUG");
		if (xp != (char *)NULL) {
			debug = atoi(xp);
			if (debug < 0) {
				/* Keep trace file even if successful */
				keepdbgfile = -1;
				debug = -debug;
			}
		}
	}
	if (debug > 0) {
		strcpy(dbgfname, "/tmp/MLDBGXXXXXX");
		if ((tmpfd = mkstemp(dbgfname)) == -1) {
			fprintf(stderr, "%s: can't open debugging file '%s'\n",
				program, dbgfname);
			exit(13);
		}
		if ((dbgfp = fdopen(tmpfd, "w")) == (FILE *)NULL) {
			fprintf(stderr, "%s: can't open debugging file '%s'\n",
				program, dbgfname);
			(void) close(tmpfd);
			exit(13);
		}
		setbuf(dbgfp, NULL);
		fprintf(dbgfp, "main(): debugging level == %d\n", debug);
		fprintf(dbgfp, "main(): trace file ='%s': kept %s\n", dbgfname,
			((keepdbgfile < 0) ?
				"on success or failure." : "only on failure."));
	}

	if (!ismail && (goerr > 0 || !i)) {
		Dout(pn, 11, "!ismail, goerr=%d, i=%d\n", goerr, i);
		if (goerr > 0) {
			errmsg(E_SYNTAX, "Usage: rmail [-wt] person(s)");
		}
		if (!i) {
			errmsg(E_SYNTAX, "At least one user must be specified");
		}
		Dout(pn, 11, "exiting!\n");
		done(0);
	}

	umsave = umask(7);
	uname(&utsn);
	if ((p = xgetenv("CLUSTER")) != (char *)NULL) {
		/*
		 * We are not who we appear...
		 */
		thissys = p;
	} else {
		thissys = utsn.nodename;
	}
	Dout(pn, 11, "thissys = '%s', uname = '%s'\n", thissys, utsn.nodename);

	failsafe = xgetenv("FAILSAFE");
	if (failsafe)
		Dout(pn, 11, "failsafe processing enabled to %s\n", failsafe);

	/*
	 *	Use environment variables
	 */
	home = getenv("HOME");
	if (!home || !*home) {
		home = ".";
	}

	my_name[0] = '\0';
	pwd = getpwuid(my_uid);
	if (pwd)
		(void) strlcpy(my_name, pwd->pw_name, sizeof (my_name));

	/* If root, use LOGNAME if set */
	if (my_uid == 0) {
		/* If root, use LOGNAME if set */
		if (((cptr = getenv("LOGNAME")) != NULL) &&
		    (strlen(cptr) != 0)) {
			(void) strlcpy(my_name, cptr, sizeof (my_name));
		}
	}
	Dout(pn, 11, "my_name = '%s'\n", my_name);

	/*
	 *	Catch signals for cleanup
	 */
	if (setjmp(sjbuf)) {
		done(0);
	}
	for (i = SIGINT; i < SIGCLD; i++) {
		setsig(i, delete);
	}
	setsig(SIGHUP, sig_done);
	setsig(SIGTERM, sig_done);

	cksaved(my_name);

	/*
	 *	Rmail is always invoked to send mail
	 */
	Dout(pn, 11, "ismail=%d, argc=%d\n", ismail, argc);
	if (ismail && (argc == 1)) {
		sending = FALSE;
		printmail();

	} else {
		sending = TRUE;
		sendmail(argc, argv);
	}
	done(0);
}
