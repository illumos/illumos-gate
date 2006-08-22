/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "tip.h"

void	cleanup(void);
void	timeout(void);

/*
 * Botch the interface to look like cu's
 */
void
cumain(int argc, char *argv[])
{
	int i;
	static char sbuf[14];

	if (argc < 2) {
usage:
		(void) fprintf(stderr,
	"usage: cu telno [-t] [-s speed] [-a acu] [-l line] [-#]\n");
		exit(8);
	}
	CU = DV = NOSTR;
	for (; argc > 1; argv++, argc--) {
		if (argv[1][0] != '-')
			PN = argv[1];
		else if (argv[1][1] != '\0' && argv[1][2] != '\0') {
			(void) fprintf(stderr,
			    "cu: extra characters after flag: %s\n",
			    argv[1]);
			goto usage;
		} else switch (argv[1][1]) {

		case 't':
			HW = 1, DU = -1;
			--argc;
			continue;

		case 'a':
			CU = argv[2]; ++argv; --argc;
			break;

		case 's':
			if (argc < 3)
				goto usage;
			if (speed(atoi(argv[2])) == 0) {
				(void) fprintf(stderr,
				    "cu: unsupported speed %s\n",
				    argv[2]);
				exit(3);
			}
			BR = atoi(argv[2]); ++argv; --argc;
			break;

		case 'l':
			DV = argv[2]; ++argv; --argc;
			break;

		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			if (CU)
				CU[strlen(CU)-1] = argv[1][1];
			if (DV)
				DV[strlen(DV)-1] = argv[1][1];
			break;

		default:
			(void) fprintf(stderr, "cu: bad flag %s\n", argv[1]);
			goto usage;
		}
	}
	(void) signal(SIGINT, (sig_handler_t)cleanup);
	(void) signal(SIGQUIT, (sig_handler_t)cleanup);
	(void) signal(SIGHUP, (sig_handler_t)cleanup);
	(void) signal(SIGTERM, (sig_handler_t)cleanup);

	/*
	 * The "cu" host name is used to define the
	 * attributes of the generic dialer.
	 */
	(void) snprintf(sbuf, sizeof (sbuf), "cu%d", BR);
	if ((i = hunt(sbuf)) == 0) {
		(void) printf("all ports busy\n");
		exit(3);
	}
	if (i == -1) {
		(void) printf("link down\n");
		delock(uucplock);
		exit(3);
	}
	setbuf(stdout, NULL);
	loginit();
	gid = getgid();
	egid = getegid();
	uid = getuid();
	euid = geteuid();
	userperm();
	vinit();
	setparity("none");
	boolean(value(VERBOSE)) = 0;
	if (HW)
		ttysetup(speed(BR));
	if (connect()) {
		(void) printf("Connect failed\n");
		myperm();
		delock(uucplock);
		exit(1);
	}
	if (!HW)
		ttysetup(speed(BR));
}
