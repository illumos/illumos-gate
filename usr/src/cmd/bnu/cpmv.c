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
 * 	Copyright (c) 1999 by Sun Microsystems, Inc.
 * 	All rights reserved.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* from SVR4 bnu:cpmv.c	2.13 */

#include "uucp.h"

/*
 * copy f1 to f2 locally
 *	f1	-> source file name
 *	f2	-> destination file name
 * return:
 *	0	-> ok
 *	FAIL	-> failed
 */

static int
xcp(f1, f2)
char *f1, *f2;
{
	register int	fd1, fd2;
	register int	nr, nw;
	char buf[BUFSIZ];
	char *temp_p, temp[MAXFULLNAME];

	if ((fd1 = open(f1, O_RDONLY)) == -1)
		return (FAIL);

	if (DIRECTORY(f2)) {
		(void) strcat(f2, "/");
		(void) strcat(f2, BASENAME(f1, '/'));
	}
	DEBUG(4, "file name is %s\n", f2);

	(void) strcpy(temp, f2);
	if ((temp_p = strrchr(temp, '/')) == NULL)
	    temp_p = temp;
	else
	    temp_p++;
	(void) strcpy(temp_p, ".TM.XXXXXX");
	temp_p = temp;
	DEBUG(4, "temp name is %s\n", temp_p);

	if ((fd2 = mkstemp(temp_p)) == -1) {
		/* open of temp may fail if called from uidxcp() */
		/* in this case, try f2 since it is pre-created */
		temp_p = f2;
		if ((fd2 = open(temp_p, O_CREAT | O_TRUNC | O_WRONLY,
		    PUB_FILEMODE)) == -1) {
			DEBUG(5, "open of file returned errno %d\n", errno);
			(void) close(fd1);
			return (FAIL);
		}
		DEBUG(4, "using file name directly.%s\n", "");
	}
	(void) chmod(temp_p, PUB_FILEMODE);

	/*	copy, looking for read or write failures */
	while ((nr = read(fd1, buf, sizeof (buf))) > 0 &&
		(nw = write(fd2, buf, nr)) == nr)
		;

	close(fd1);
	close(fd2);

	if (nr != 0 || nw == -1) {
		(void) unlink(temp_p);
		return (FAIL);
	}
	if (temp_p != f2) {
	    if (rename(temp_p, f2) != 0) {
		DEBUG(5, "rename failed: errno %d\n", errno);
		(void) unlink(temp_p);
		return (FAIL);
	    }
	}
	return (0);
}


/*
 * move f1 to f2 locally
 * returns:
 *	0	-> ok
 *	FAIL	-> failed
 */

int
xmv(f1, f2)
register char *f1, *f2;
{
	register int do_unlink, ret;
	struct stat sbuf;

	if (stat(f2, &sbuf) == 0)
		do_unlink = ((sbuf.st_mode & S_IFMT) == S_IFREG);
	else
		do_unlink = 1;

	if (do_unlink)
		(void) unlink(f2);	/* i'm convinced this is the right */
					/* thing to do */
	if ((ret = link(f1, f2)) < 0) {
	    /* copy file */
	    ret = xcp(f1, f2);
	}

	if (ret == 0)
	    (void) unlink(f1);
	return (ret);
}

/*
 * toCorrupt - move file to CORRUPTDIR
 * return - none
 */

void
toCorrupt(file)
char *file;
{
	char corrupt[MAXFULLNAME];

	(void) sprintf(corrupt, "%s/%s", CORRUPTDIR, BASENAME(file, '/'));
	(void) link(file, corrupt);
	ASSERT(unlink(file) == 0, Ct_UNLINK, file, errno);
}

/*
 * append f1 to f2
 *	f1	-> source FILE pointer
 *	f2	-> destination FILE pointer
 * return:
 *	SUCCESS	-> ok
 *	FAIL	-> failed
 *
 * to avoid confusing mail, turn lines with just "." into "..".
 */
int
xfappend(fp1, fp2)
register FILE	*fp1, *fp2;
{
	char	buf[BUFSIZ];

	while (fgets(buf, sizeof (buf), fp1) != NULL) {
		if (buf[0] == '.' && buf[1] == '\n')
			strcpy(buf, "..\n");
		fputs(buf, fp2);
	}

	return (ferror(fp1) || ferror(fp2) ? FAIL : SUCCESS);
}


/*
 * copy f1 to f2 locally under uid of uid argument
 *	f1	-> source file name
 *	f2	-> destination file name
 *	Uid and Euid are global
 * return:
 *	0	-> ok
 *	FAIL	-> failed
 * NOTES:
 *  for V7 systems, flip-flop between real and effective uid is
 *  not allowed, so fork must be done.  This code will not
 *  work correctly when realuid is root on System 5 because of
 *  a bug in setuid.
 */

int
uidxcp(f1, f2)
char *f1, *f2;
{
	int status;
	char full[MAXFULLNAME];

	(void) strcpy(full, f2);
	if (DIRECTORY(f2)) {
	    (void) strcat(full, "/");
	    (void) strcat(full, BASENAME(f1, '/'));
	}

	/* create full owned by uucp */
	(void) close(creat(full, PUB_FILEMODE));
	(void) chmod(full, PUB_FILEMODE);

	/* do file copy as read uid */
#ifndef V7
	(void) setuid(Uid);
	status = xcp(f1, full);
	(void) setuid(Euid);
	return (status);

#else /* V7 */

	if (vfork() == 0) {
	    setuid(Uid);
	    _exit(xcp(f1, full));
	}
	wait(&status);
	return (status);
#endif
}

/*
 * put file in public place
 * if successful, filename is modified
 * returns:
 *	0	-> success
 *	FAIL	-> failure
 */
int
putinpub(file, tmp, user)
char *file, *user, *tmp;
{
	int status;
	char fullname[MAXFULLNAME];

	(void) sprintf(fullname, "%s/%s/", Pubdir, user);
	if (mkdirs(fullname, PUBMASK) != 0) {
		/* cannot make directories */
		return (FAIL);
	}
	(void) strcat(fullname, BASENAME(file, '/'));
	status = xmv(tmp, fullname);
	if (status == 0) {
		(void) strcpy(file, fullname);
		(void) chmod(fullname, PUB_FILEMODE);
	}
	return (status);
}
