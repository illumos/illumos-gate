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

#include	<stdio.h>
#include	<dirent.h>
#include	<regexpr.h>
#include	<string.h>
#include	<errno.h>
#include	<fcntl.h>
#include	<locale.h>
#include	<sys/types.h>
#include	<sys/file.h>
#include	<sys/mman.h>
#include	<sys/stat.h>
#include	<unistd.h>

#define	P_locale	"/usr/lib/locale/"
#define	L_locale	(sizeof (P_locale))
#define	MESSAGES	"/LC_MESSAGES/"
#define	ESIZE		BUFSIZ

/* External functions */

extern	int	getopt();
extern	void	exit();
extern	char	*strecpy();
extern	char	*strrchr();
extern	char	*strchr();


/* External variables */

extern	char	*optarg;
extern	int	optind;

/* Internal functions */

static	void	usage();
static	void	prnt_str();
static	int	attach();
static	void	find_msgs();
static	char	*syserr();

/* Internal variables */

static	char	*cmdname; 	/* points to the name of the command */
static	int	lflg;		/* set if locale is specified on command line */
static	int	mflg;		/* set if message file is specified on */
				/* command line */
static	char	locale[15];	/* save name of current locale */
static  char	*msgfile;	/* points to the argument immediately */
				/* following the m option */
static	char	*text;		/* pointer to search pattern */
static	int	textflg;	/* set if text pattern is specified on */
				/* command line */
static	int	sflg;		/* set if the s option is specified */
static	char	*fname;		/* points to message file name */
static	int	msgnum;		/* message number */

int
main(int argc, char **argv)
{
	int	ch;
	char	*end;
	int	addr;
	int	len;
	int	len1;
	int	fd;
	size_t	size;
	char	pathname[128];
	char	*cp;
	char	ebuf[ESIZE];
	DIR	*dirp;
	struct	dirent	*dp;

	/* find last level of path in command name */
	if (cmdname = strrchr(*argv, '/'))
		++cmdname;
	else
		cmdname = *argv;

	/* parse command line */
	while ((ch = getopt(argc, argv, "sl:m:")) != -1)
		switch (ch) {
			case	'l':
				lflg++;
				(void) strcpy(locale, optarg);
				continue;
			case	'm':
				mflg++;
				msgfile = optarg;
				continue;
			case	's':
				sflg++;
				continue;
			default:
				usage();
			}
	if (mflg && optind < argc) {
		text = argv[optind++];
		textflg++;
	}
	if (optind != argc)
		usage();

	/* create full path name to message files */
	if (!lflg)
		(void) strcpy(locale, setlocale(LC_MESSAGES, ""));
	(void) strcpy(pathname, P_locale);
	(void) strcpy(&pathname[L_locale - 1], locale);
	(void) strcat(pathname, MESSAGES);
	len = strlen(pathname);

	if (textflg) {
			/* compile regular expression */
		if (compile(text, &ebuf[0], &ebuf[ESIZE]) == (char *)NULL) {
			(void) fprintf(stderr,
			    "%s: ERROR: regular expression compile failed\n",
			    cmdname);
			exit(1);
		}
	}

	/* access message files */
	if (mflg) {
		end = msgfile + strlen(msgfile) + 1;
		if (*msgfile == ',' || *(end - 2) == ',')
			usage();
		while ((fname = strtok(msgfile, ",\0")) != NULL) {
			if (strchr(fname, '/') != (char *)NULL) {
				cp = fname;
				len1 = 0;
			} else {
				cp = pathname;
				len1 = len;
			}
			msgfile = msgfile + strlen(fname) + 1;
			if ((addr = attach(cp, len1, &fd, &size)) == -1) {
				(void) fprintf(stderr,
	"%s: ERROR: failed to access message file '%s'\n", cmdname, cp);
				if (end != msgfile)
					continue;
				else
					break;
			}
			find_msgs(addr, ebuf);
			(void) munmap((caddr_t)addr, size);
			(void) close(fd);
			if (end == msgfile)
				break;
		}
	} else { /* end if (mflg) */
		if ((dirp = opendir(pathname)) == NULL) {
			(void) fprintf(stderr, "%s: ERROR: %s %s\n",
			    cmdname, pathname, syserr());
			exit(1);
		}
		while ((dp = readdir(dirp)) != NULL) {
			if (dp->d_name[0] == '.')
				continue;
			fname = dp->d_name;
			if ((addr = attach(pathname, len, &fd, &size)) == -1) {
				(void) fprintf(stderr,
	"%s: ERROR: failed to access message file '%s'\n", cmdname, pathname);
				continue;
			}
			find_msgs(addr, ebuf);
			(void) munmap((caddr_t)addr, size);
			(void) close(fd);
		}
		(void) closedir(dirp);
	}
	return (0);
}


/* print usage message */
static void
usage()
{
	(void) fprintf(stderr,
	    "usage: srchtxt [-s]\n       srchtxt [-s] -l locale\n"
	    "       srchtxt [-s] [-l locale] [-m msgfile,...] [text]\n");
	exit(1);
}

/*
 * print string - non-graphic characters are printed as alphabetic
 * escape sequences
 */
static	void
prnt_str(instring)
char	*instring;
{
	char	outstring[1024];

	(void) strecpy(outstring, instring, NULL);
	if (sflg)
		(void) fprintf(stdout, "%s\n", outstring);
	else
		(void) fprintf(stdout, "<%s:%d>%s\n", fname, msgnum, outstring);
}

/* mmap a message file to the address space */
static int
attach(path, len, fdescr, size)
char	*path;
int	len;
int	*fdescr;
size_t	*size;
{
	int	fd = -1;
	caddr_t	addr;
	struct	stat	sb;

	(void) strcpy(&path[len], fname);
	if ((fd = open(path, O_RDONLY)) != -1 &&
	    fstat(fd, &sb) != -1 &&
	    (addr = mmap(0, sb.st_size,
		PROT_READ, MAP_SHARED,
		fd, 0)) != (caddr_t)-1) {
		*fdescr = fd;
		*size = sb.st_size;
		return ((int)addr);
	} else {
		if (fd == -1)
			(void) close(fd);
		return (-1);
	}
}


/* find messages in message files */
static void
find_msgs(addr, regexpr)
int	addr;
char	*regexpr;
{
	int	num_msgs;
	char	*msg;

	num_msgs = *(int *)addr;
	for (msgnum = 1; msgnum <= num_msgs; msgnum++) {
		msg = (char *)(*(int *)(addr + sizeof (int) * msgnum) + addr);
		if (textflg) {
			if (step(msg, regexpr))
				prnt_str(msg);
			continue;
		}
		prnt_str(msg);
	}
}

/* print description of error */
static char *
syserr()
{
	return (strerror(errno));
}
