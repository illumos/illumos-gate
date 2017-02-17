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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* Copyright (c) 1981 Regents of the University of California */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <pwd.h>
#include <locale.h>
#include <limits.h>
#include <unistd.h>

#define	BUFSIZE	(LINE_MAX*2)	/* This should agree with what's in ex.h */

#include "ex_tune.h"

#define	FTYPE(A)	(A.st_mode)
#define	FMODE(A)	(A.st_mode)
#define	IDENTICAL(A, B)	(A.st_dev == B.st_dev && A.st_ino == B.st_ino)
#define	ISBLK(A)	((A.st_mode & S_IFMT) == S_IFBLK)
#define	ISCHR(A)	((A.st_mode & S_IFMT) == S_IFCHR)
#define	ISDIR(A)	((A.st_mode & S_IFMT) == S_IFDIR)
#define	ISFIFO(A)	((A.st_mode & S_IFMT) == S_IFIFO)
#define	ISREG(A)	((A.st_mode & S_IFMT) == S_IFREG)

/*
 * Expreserve - preserve a file in usrpath(preserve)
 *
 * This routine is very naive - it doesn't remove anything from
 * usrpath(preserve)... this may mean that we  * stuff there...
 * the danger in doing anything with usrpath(preserve)
 * is that the clock may be messed up and we may get confused.
 *
 * We are called in two ways - first from the editor with no arguments
 * and the standard input open on the temp file. Second with an argument
 * to preserve the entire contents of /var/tmp (root only).
 *
 * BUG: should do something about preserving Rx... (register contents)
 *      temporaries.
 */

struct 	header {
	time_t	Time;			/* Time temp file last updated */
	int	Uid;			/* This user's identity */
#ifndef VMUNIX
	short	Flines;			/* Number of lines in file */
#else
	int	Flines;
#endif
	unsigned char	Savedfile[FNSIZE];	/* The current file name */
	short	Blocks[LBLKS];		/* Blocks where line pointers stashed */
	short	encrypted;		/* Encrypted temp file flag */
} H;

#define	eq(a, b) strcmp(a, b) == 0

void notify(int, unsigned char *, int, int);
void mkdigits(unsigned char *);

int
main(argc)
	int argc;
{
	DIR *tf;
	struct dirent64 *direntry;
	unsigned char *filname;
	struct stat64 stbuf;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
	/*
	 * If only one argument, then preserve the standard input.
	 */
	if (argc == 1) {
		if (copyout((unsigned char *) 0))
			return (1);
		return (0);
	}

	/*
	 * If not super user, then can only preserve standard input.
	 */
	if (getuid()) {
		fprintf(stderr, gettext("NOT super user\n"));
		return (1);
	}

	/*
	 * ... else preserve all the stuff in /var/tmp, removing
	 * it as we go.
	 */
	if (chdir(TMPDIR) < 0) {
		perror(TMPDIR);
		return (1);
	}

	if ((tf = opendir(".")) == NULL)
	{
		perror(TMPDIR);
		return (1);
	}
	while ((direntry = readdir64(tf)) != NULL)
	{
		filname = (unsigned char *)direntry->d_name;
		/*
		 * Ex temporaries must begin with Ex;
		 * we check that the 12th character of the name is null
		 * so we won't have to worry about non-null terminated names
		 * later on.
		 */
		if (filname[0] != 'E' || filname[1] != 'x' || filname[12])
			continue;
		if (stat64((char *)filname, &stbuf))
			continue;
		if (!ISREG(stbuf))
			continue;
		/*
		 * Save the file.
		 */
		(void) copyout(filname);
	}
	closedir(tf);
	return (0);
}

unsigned char	mydir[] =	USRPRESERVE;
unsigned char	pattern[] =	"/Exaa`XXXXXXXXXX";

/*
 * Copy file name into usrpath(preserve)/...
 * If name is (char *) 0, then do the standard input.
 * We make some checks on the input to make sure it is
 * really an editor temporary, generate a name for the
 * file (this is the slowest thing since we must stat
 * to find a unique name), and finally copy the file.
 */
int
copyout(unsigned char *name)
{
	int i;
	static int reenter;
	unsigned char buf[BUFSIZE];
	unsigned char	savdir[PATH_MAX+1];
	unsigned char	savfil[PATH_MAX+1];
	struct passwd *pp;
	struct stat64	stbuf;
	int savfild;

	/*
	 * The first time we put in the digits of our
	 * process number at the end of the pattern.
	 */
	if (reenter == 0) {
		mkdigits(pattern);
		reenter++;
	}

	/*
	 * If a file name was given, make it the standard
	 * input if possible.
	 */
	if (name != 0) {
		(void) close(0);
		/*
		 * Need read/write access for arcane reasons
		 * (see below).
		 */
		if (open(name, O_RDWR) < 0)
			return (-1);
	}

	/*
	 * Get the header block.
	 */
	(void) lseek(0, 0l, 0);
	if (read(0, (char *)&H, sizeof (H)) != sizeof (H)) {
format:
		if (name == 0)
			fprintf(stderr, gettext("Buffer format error\t"));
		else {
			/*
			 * avoid having a bunch of NULL Ex* files
			 * hanging around
			 */
			struct stat64 stbuf;

			if (stat64((char *)name, &stbuf) == 0)
			if (stbuf.st_size == 0)
				(void) unlink((char *)name);
		}
		return (-1);
	}

	/*
	 * Consistency checks so we don't copy out garbage.
	 */
	if (H.Flines < 0) {
#ifdef DEBUG
		fprintf(stderr, "Negative number of lines\n");
#endif
		goto format;
	}
	if (H.Blocks[0] != HBLKS || H.Blocks[1] != HBLKS+1) {
#ifdef DEBUG
		fprintf(stderr, "Blocks %d %d\n", H.Blocks[0], H.Blocks[1]);
#endif
		goto format;
	}
	if (name == 0 && H.Uid != getuid()) {
#ifdef DEBUG
		fprintf(stderr, "Wrong user-id\n");
#endif
		goto format;
	}
	if (lseek(0, 0l, 0)) {
#ifdef DEBUG
		fprintf(stderr, gettext("Negative number of lines\n"));
#endif
		goto format;
	}

	/*
	 * If no name was assigned to the file, then give it the name
	 * LOST, by putting this in the header.
	 */
	if (H.Savedfile[0] == 0) {
		(void) strcpy(H.Savedfile, "LOST");
		(void) write(0, (char *) &H, sizeof (H));
		H.Savedfile[0] = 0;
		(void) lseek(0, 0l, 0);
	}

	/*
	 * See if preservation directory for user exists.
	 */

	strcpy(savdir, mydir);
	pp = getpwuid(H.Uid);
	if (pp)
		strcat(savdir, pp->pw_name);
	else {
		fprintf(stderr, gettext("Unable to get uid for user.\n"));
		return (-1);
	}
	if (lstat64((char *)savdir, &stbuf) < 0 || !S_ISDIR(stbuf.st_mode)) {
		/* It doesn't exist or it isn't a directory, safe to unlink */
		(void) unlink((char *)savdir);
		if (mkdir((char *)savdir, 0700) < 0) {
			fprintf(stderr,
				gettext("Unable to create directory \"%s\"\n"),
				savdir);
			perror("");
			return (-1);
		}
		(void) chmod((char *)savdir, 0700);
		(void) chown((char *)savdir, H.Uid, 2);
	}

	/*
	 * File is good.  Get a name and create a file for the copy.
	 */
	(void) close(1);
	if ((savfild = mknext(savdir, pattern)) < 0) {
		if (name == 0)
			perror((char *)savfil);
		return	(1);
	}
	strcpy(savfil, savdir);
	strcat(savfil, pattern);
	/*
	 * Make target owned by user.
	 */

	(void) fchown(savfild, H.Uid, 2);

	/*
	 * Copy the file.
	 */
	for (;;) {
		i = read(0, buf, BUFSIZE);
		if (i < 0) {
			if (name)
				perror(gettext("Buffer read error"));
			(void) unlink((char *)savfil);
			return (-1);
		}
		if (i == 0) {
			if (name)
				(void) unlink((char *)name);
			notify(H.Uid, H.Savedfile, (int) name, H.encrypted);
			return (0);
		}
		if (write(savfild, buf, i) != i) {
			if (name == 0)
				perror((char *)savfil);
			(void) unlink((char *)savfil);
			return (-1);
		}
	}
}

/*
 * Blast the last 5 characters of cp to be the process number.
 */
void
mkdigits(unsigned char *cp)
{
	pid_t i;
	int j;

	for (i = getpid(), j = 10, cp += strlen(cp); j > 0; i /= 10, j--)
		*--cp = i % 10 | '0';
}

/*
 * Make the name in cp be unique by clobbering up to
 * three alphabetic characters into a sequence of the form 'aab', 'aac', etc.
 * Mktemp gets weird names too quickly to be useful here.
 */
int
mknext(unsigned char *dir, unsigned char *cp)
{
	unsigned char *dcp;
	struct stat stb;
	unsigned char path[PATH_MAX+1];
	int fd;

	strcpy(path, dir);
	strcat(path, cp);
	dcp = path + strlen(path) - 1;

	while (isdigit(*dcp))
		dcp--;

	do {
		if (dcp[0] == 'z') {
			dcp[0] = 'a';
			if (dcp[-1] == 'z') {
				dcp[-1] = 'a';
				if (dcp[-2] == 'z') {
					fprintf(stderr,
						gettext("Can't find a name\t"));
						return (-1);
				}
				dcp[-2]++;
			} else
				dcp[-1]++;
		} else
			dcp[0]++;

	} while (((fd = open(path, O_CREAT|O_EXCL|O_WRONLY, 0600)) < 0) &&
		errno == EEXIST);
	/* copy out patern */
	strcpy(cp, path + strlen(dir));
	return (fd);
}

/*
 * Notify user uid that their file fname has been saved.
 */
void
notify(int uid, unsigned char *fname, int flag, int cryflag)
{

#define MAXHOSTNAMELEN 256

	struct passwd *pp = getpwuid(uid);
	FILE *mf;
	unsigned char cmd[BUFSIZE];

	char hostname[MAXHOSTNAMELEN];
	int namelen = MAXHOSTNAMELEN ;

	if (gethostname((char *)hostname, namelen) == -1)
	  return;

	if (pp == NULL)
		return;
	sprintf((char *)cmd, "/usr/bin/mail %s", pp->pw_name);
	mf = popen((char *)cmd, "w");
	if (mf == NULL)
		return;
	setbuf(mf, (char *)cmd);
	if (fname[0] == 0) {
		fprintf(mf, flag ?
"A copy of an editor buffer of yours was saved on %s when the system went down.\n" :
"A copy of an editor buffer of yours was saved on %s when the editor was killed\nor was unable to save your changes.\n", hostname);
		fprintf(mf,
"No name was associated with this buffer so it has been named \"LOST\".\n");
	} else
		fprintf(mf, flag ?
"A copy of an editor buffer of your file \"%s\"%s was saved on %s\nwhen the system \
went down.\n" :
"A copy of an editor buffer of your file \"%s\"%s was saved on %s\nwhen the editor \
was killed or was unable to save your changes.\n", fname, (cryflag) ? "[ENCRYPTED]" : "", hostname);
		/*
		 * "the editor was killed" is perhaps still not an ideal
		 * error message.  Usually, either it was forceably terminated
		 * or the phone was hung up, but we don't know which.
		 */
	fprintf(mf,
"This buffer can be retrieved using the \"recover\" command of the editor.\n");
	fprintf(mf,
"An easy way to do this is to give the command \"vi -r %s\".\n",
		(fname[0] == 0) ? "LOST" : (char *) fname);
	fprintf(mf, "This works for \"edit\" and \"ex\" also.\n");
	(void) pclose(mf);
}
