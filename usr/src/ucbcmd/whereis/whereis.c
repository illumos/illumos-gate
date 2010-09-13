/*
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/param.h>
#include <dirent.h>
#include <stdio.h>
#include <ctype.h>

static char *bindirs[] = {
	"/etc",
	"/sbin",
	"/usr/bin",
	"/usr/ccs/bin",
	"/usr/ccs/lib",
	"/usr/lang",
	"/usr/lbin",
	"/usr/lib",
	"/usr/sbin",
	"/usr/ucb",
	"/usr/ucblib",
	"/usr/ucbinclude",
	"/usr/games",
	"/usr/local",
	"/usr/local/bin",
	"/usr/new",
	"/usr/old",
	"/usr/hosts",
	"/usr/include",
	"/usr/etc",
	0
};
static char *mandirs[] = {
	"/usr/man/man1",
	"/usr/man/man1b",
	"/usr/man/man1c",
	"/usr/man/man1f",
	"/usr/man/man1m",
	"/usr/man/man1s",
	"/usr/man/man2",
	"/usr/man/man3",
	"/usr/man/man3b",
	"/usr/man/man3c",
	"/usr/man/man3e",
	"/usr/man/man3g",
	"/usr/man/man3j",
	"/usr/man/man3k",
	"/usr/man/man3l",
	"/usr/man/man3m",
	"/usr/man/man3n",
	"/usr/man/man3s",
	"/usr/man/man3w",
	"/usr/man/man3x",
	"/usr/man/man3x11",
	"/usr/man/man3xt",
	"/usr/man/man4",
	"/usr/man/man4b",
	"/usr/man/man5",
	"/usr/man/man6",
	"/usr/man/man7",
	"/usr/man/man7b",
	"/usr/man/man8",
	"/usr/man/man9e",
	"/usr/man/man9f",
	"/usr/man/man9s",
	"/usr/man/manl",
	"/usr/man/mann",
	"/usr/man/mano",
	0
};
static char *srcdirs[]  = {
	"/usr/src/cmd",
	"/usr/src/head",
	"/usr/src/lib",
	"/usr/src/lib/libc",
	"/usr/src/lib/libc/port",
	"/usr/src/lib/libc/port/gen",
	"/usr/src/lib/libc/port/print",
	"/usr/src/lib/libc/port/stdio",
	"/usr/src/lib/libc/port/sys",
	"/usr/src/lib/libc/sparc",
	"/usr/src/lib/libc/sparc/gen",
	"/usr/src/lib/libc/sparc/sys",
	"/usr/src/ucbcmd",
	"/usr/src/ucblib",
	"/usr/src/ucbinclude",
	"/usr/src/uts",
	"/usr/src/uts/common",
	"/usr/src/uts/sun",
	"/usr/src/uts/sun4",
	"/usr/src/uts/sun4c",
	"/usr/src/uts/sparc",
	"/usr/src/local",
	"/usr/src/new",
	"/usr/src/old",
	0
};

char	sflag = 1;
char	bflag = 1;
char	mflag = 1;
char	**Sflag;
int	Scnt;
char	**Bflag;
int	Bcnt;
char	**Mflag;
int	Mcnt;
char	uflag;

void getlist(int *, char ***, char ***, int *);
void zerof(void);
void lookup(char *);
void looksrc(char *);
void lookbin(char *);
void lookman(char *);
void findv(char **, int, char *);
void find(char **, char *);
void findin(char *, char *);

/*
 * whereis name
 * look for source, documentation and binaries
 */
int
main(int argc, char *argv[])
{

	argc--, argv++;
	if (argc == 0) {
usage:
		fprintf(stderr, "whereis [ -sbmu ] [ -SBM dir ... -f ] "
		    "name...\n");
		exit(1);
	}
	do
		if (argv[0][0] == '-') {
			char *cp = argv[0] + 1;
			while (*cp) {

				switch (*cp++) {

			case 'f':
				break;

			case 'S':
				getlist(&argc, &argv, &Sflag, &Scnt);
				break;

			case 'B':
				getlist(&argc, &argv, &Bflag, &Bcnt);
				break;

			case 'M':
				getlist(&argc, &argv, &Mflag, &Mcnt);
				break;

			case 's':
				zerof();
				sflag++;
				continue;

			case 'u':
				uflag++;
				continue;

			case 'b':
				zerof();
				bflag++;
				continue;

			case 'm':
				zerof();
				mflag++;
				continue;

			default:
				goto usage;
				}
			}
			argv++;
		} else
			lookup(*argv++);
	while (--argc > 0);
	return (0);
}

void
getlist(int *argcp, char ***argvp, char ***flagp, int *cntp)
{

	(*argvp)++;
	*flagp = *argvp;
	*cntp = 0;
	for ((*argcp)--; *argcp > 0 && (*argvp)[0][0] != '-'; (*argcp)--)
		(*cntp)++, (*argvp)++;
	(*argcp)++;
	(*argvp)--;
}

void
zerof(void)
{

	if (sflag && bflag && mflag)
		sflag = bflag = mflag = 0;
}
int	count;
int	print;

void
lookup(char *cp)
{
	char *dp;

	for (dp = cp; *dp; dp++)
		continue;
	for (; dp > cp; dp--) {
		if (*dp == '.') {
			*dp = 0;
			break;
		}
	}
	for (dp = cp; *dp; dp++)
		if (*dp == '/')
			cp = dp + 1;
	if (uflag) {
		print = 0;
		count = 0;
	} else
		print = 1;
again:
	if (print)
		printf("%s:", cp);
	if (sflag) {
		looksrc(cp);
		if (uflag && print == 0 && count != 1) {
			print = 1;
			goto again;
		}
	}
	count = 0;
	if (bflag) {
		lookbin(cp);
		if (uflag && print == 0 && count != 1) {
			print = 1;
			goto again;
		}
	}
	count = 0;
	if (mflag) {
		lookman(cp);
		if (uflag && print == 0 && count != 1) {
			print = 1;
			goto again;
		}
	}
	if (print)
		printf("\n");
}

void
looksrc(char *cp)
{
	if (Sflag == 0) {
		find(srcdirs, cp);
	} else
		findv(Sflag, Scnt, cp);
}

void
lookbin(char *cp)
{
	if (Bflag == 0)
		find(bindirs, cp);
	else
		findv(Bflag, Bcnt, cp);
}

void
lookman(char *cp)
{
	if (Mflag == 0) {
		find(mandirs, cp);
	} else
		findv(Mflag, Mcnt, cp);
}

void
findv(char **dirv, int dirc, char *cp)
{

	while (dirc > 0)
		findin(*dirv++, cp), dirc--;
}

void
find(char **dirs, char *cp)
{

	while (*dirs)
		findin(*dirs++, cp);
}

void
findin(char *dir, char *cp)
{
	DIR *dirp;
	struct dirent *dp;

	dirp = opendir(dir);
	if (dirp == NULL)
		return;
	while ((dp = readdir(dirp)) != NULL) {
		if (itsit(cp, dp->d_name)) {
			count++;
			if (print)
				printf(" %s/%s", dir, dp->d_name);
		}
	}
	closedir(dirp);
}

int
itsit(char *cp, char *dp)
{
	int i = strlen(dp);

	if (dp[0] == 's' && dp[1] == '.' && itsit(cp, dp+2))
		return (1);
	while (*cp && *dp && *cp == *dp)
		cp++, dp++, i--;
	if (*cp == 0 && *dp == 0)
		return (1);
	while (isdigit(*dp))
		dp++;
	if (*cp == 0 && *dp++ == '.') {
		--i;
		while (i > 0 && *dp)
			if (--i, *dp++ == '.')
				return (*dp++ == 'C' && *dp++ == 0);
		return (1);
	}
	return (0);
}
