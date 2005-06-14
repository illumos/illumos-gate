/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 *
 * Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 * All rights reserved.
 *
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lastcomm.h"

/*
 * lc_pacct() provides the functionality of lastcomm when applied to the basic
 * SVR4 accounting file, /var/adm/pacct.  Definitions for this accounting file
 * format are given in <sys/acct.h>.
 */

extern ulong_t expand(comp_t);

static int
ok(int argc, char *argv[], int index, struct acct *acp)
{
	int j;

	for (j = index; j < argc; j++)
		if (strcmp(getname(acp->ac_uid), argv[j]) &&
		    strcmp(getdev(acp->ac_tty), argv[j]) &&
		    strncmp(acp->ac_comm, argv[j], fldsiz(acct, ac_comm)))
			break;
	return (j == argc);
}

int
lc_pacct(char *name, int argc, char *argv[], int index)
{
	struct acct buf[NACCT];
	int bn, cc;
	struct acct *acp;
	struct stat sb;
	time_t t;
	int fd;

	if ((fd = open(name, O_RDONLY)) < 0) {
		perror(name);
		return (1);
	}

	(void) fstat(fd, &sb);

	if (sb.st_size % sizeof (struct acct)) {
		(void) fprintf(stderr, gettext("lastcomm: accounting file"
		    " is corrupted\n"));
		return (1);
	}

	for (bn = ((unsigned)sb.st_size / BUF_SIZ) + 1; bn >= 0; bn--) {
		if (lseek(fd, (unsigned)bn * BUF_SIZ, 0) == -1) {
			perror("lseek");
			return (1);
		}
		cc = read(fd, buf, BUF_SIZ);
		if (cc < 0) {
			perror("read");
			return (1);
		}
		acp = buf + (cc / sizeof (buf[0])) - 1;
		for (; acp >= buf; acp--) {
			char *cp;
			ulong_t x;

			if (acp->ac_flag > 0100) {
				(void) fprintf(stderr, gettext("lastcomm: "
				    "accounting file is corrupted\n"));
				return (1);
			}
			if (acp->ac_comm[0] == '\0')
				(void) strcpy(acp->ac_comm, "?");
			for (cp = &acp->ac_comm[0];
			    cp < &acp->ac_comm[fldsiz(acct, ac_comm)] && *cp;
			    cp++)
				if (!isascii(*cp) || iscntrl(*cp))
					*cp = '?';
			if (argc > index && !ok(argc, argv, index, acp))
				continue;
			x = expand(acp->ac_utime) + expand(acp->ac_stime);
			t = acp->ac_btime;
			(void) printf("%-*.*s %s %-*s %-*s %6.2f secs %.16s\n",
			    fldsiz(acct, ac_comm), fldsiz(acct, ac_comm),
			    acp->ac_comm,
			    flagbits(acp->ac_flag),
			    NMAX, getname(acp->ac_uid),
			    LMAX, getdev(acp->ac_tty),
			    x / (double)HZ, ctime(&t));
		}
	}
	return (0);
}
