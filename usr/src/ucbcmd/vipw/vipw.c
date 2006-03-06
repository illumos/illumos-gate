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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/fcntl.h>

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <strings.h>

/*
 * Password file editor with locking.
 */

#define	DEFAULT_EDITOR	"/usr/bin/vi"

static int copyfile(char *, char *);
static int editfile(char *, char *, char *, time_t *);
static int sanity_check(char *, time_t *, char *);
static int validsh(char *);

char	*ptemp = "/etc/ptmp";
char	*stemp = "/etc/stmp";
char	*passwd = "/etc/passwd";
char	*shadow = "/etc/shadow";
char	buf[BUFSIZ];

int
main(void)
{
	int fd;
	FILE *ft, *fp;
	char *editor;
	int ok = 0;
	time_t o_mtime, n_mtime;
	struct stat osbuf, sbuf, oshdbuf, shdbuf;
	char c;

	(void)signal(SIGINT, SIG_IGN);
	(void)signal(SIGQUIT, SIG_IGN);
	(void)signal(SIGHUP, SIG_IGN);
	setbuf(stderr, (char *)NULL);

	editor = getenv("VISUAL");
	if (editor == 0)
		editor = getenv("EDITOR");
	if (editor == 0)
		editor = DEFAULT_EDITOR;

	(void)umask(0077);
	if (stat(passwd, &osbuf) < 0) {
                (void)fprintf(stderr,"vipw: can't stat passwd file.\n");
                goto bad;
        } 

	if (copyfile(passwd, ptemp))
		goto bad;

	if (stat(ptemp, &sbuf) < 0) {
                (void)fprintf(stderr,
			"vipw: can't stat ptemp file, %s unchanged\n",
			passwd);
		goto bad;
	}

	o_mtime = sbuf.st_mtime;

	if (editfile(editor, ptemp, passwd, &n_mtime)) {
		if (sanity_check(ptemp, &n_mtime, passwd))
			goto bad;
		if (o_mtime >= n_mtime)
			goto bad;
	}

	ok++;
	if (o_mtime < n_mtime) {
		fprintf(stdout, "\nYou have modified the password file.\n");
		fprintf(stdout,
	"Press 'e' to edit the shadow file for consistency,\n 'q' to quit: ");
		if ((c = getchar()) == 'q') {
			if (chmod(ptemp, (osbuf.st_mode & 0644)) < 0) {
				(void) fprintf(stderr, "vipw: %s: ", ptemp);
				perror("chmod");
				goto bad;
			}
			if (rename(ptemp, passwd) < 0) {
				(void) fprintf(stderr, "vipw: %s: ", ptemp);
				perror("rename");
				goto bad;
			}
			if (((osbuf.st_gid != sbuf.st_gid) ||
					(osbuf.st_uid != sbuf.st_uid)) &&
			(chown(passwd, osbuf.st_uid, osbuf.st_gid) < 0)) {
				(void) fprintf(stderr, "vipw: %s ", ptemp);
				perror("chown");
			}
			goto bad;
		} else if (c == 'e') {
			if (stat(shadow, &oshdbuf) < 0) {
				(void) fprintf(stderr,
					"vipw: can't stat shadow file.\n");
				goto bad;
			}

			if (copyfile(shadow, stemp))
				goto bad;
			if (stat(stemp, &shdbuf) < 0) {
				(void) fprintf(stderr,
					"vipw: can't stat stmp file.\n");
				goto bad;
			}

			if (editfile(editor, stemp, shadow, &o_mtime))
				goto bad;
			ok++;
			if (chmod(ptemp, (osbuf.st_mode & 0644)) < 0) {
				(void) fprintf(stderr, "vipw: %s: ", ptemp);
				perror("chmod");
				goto bad;
			}
			if (chmod(stemp, (oshdbuf.st_mode & 0400)) < 0) {
				(void) fprintf(stderr, "vipw: %s: ", stemp);
				perror("chmod");
				goto bad;
			}
			if (rename(ptemp, passwd) < 0) {
				(void) fprintf(stderr, "vipw: %s: ", ptemp);
				perror("rename");
				goto bad;
			}
			if (((osbuf.st_gid != sbuf.st_gid) ||
					(osbuf.st_uid != sbuf.st_uid)) &&
			(chown(passwd, osbuf.st_uid, osbuf.st_gid) < 0)) {
				(void) fprintf(stderr, "vipw: %s ", ptemp);
				perror("chown");
			}
			if (rename(stemp, shadow) < 0) {
				(void) fprintf(stderr, "vipw: %s: ", stemp);
				perror("rename");
				goto bad;
			} else if (((oshdbuf.st_gid != shdbuf.st_gid) ||
					(oshdbuf.st_uid != shdbuf.st_uid)) &&
			(chown(shadow, oshdbuf.st_uid, oshdbuf.st_gid) < 0)) {
				(void) fprintf(stderr, "vipw: %s ", stemp);
				perror("chown");
				}
		}
	}
bad:
	(void) unlink(ptemp);
	(void) unlink(stemp);
	return (ok ? 0 : 1);
	/* NOTREACHED */
}


int
copyfile(char *from, char *to)
{
	int fd;
	FILE *fp, *ft;

	fd = open(to, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (fd < 0) {
		if (errno == EEXIST) {
			(void) fprintf(stderr, "vipw: %s file busy\n", from);
			exit(1);
		}
		(void) fprintf(stderr, "vipw: "); perror(to);
		exit(1);
	}
	ft = fdopen(fd, "w");
	if (ft == NULL) {
		(void) fprintf(stderr, "vipw: "); perror(to);
		return( 1 );
	}
	fp = fopen(from, "r");
	if (fp == NULL) {
		(void) fprintf(stderr, "vipw: "); perror(from);
		return( 1 );
	}
	while (fgets(buf, sizeof (buf) - 1, fp) != NULL)
		fputs(buf, ft);
	(void) fclose(ft);
	(void) fclose(fp);
	return( 0 );
}

int
editfile(char *editor, char *temp, char *orig, time_t *mtime)
{
	(void)sprintf(buf, "%s %s", editor, temp);
	if (system(buf) == 0) {
		return (sanity_check(temp, mtime, orig));
	}
	return(1);
}


int
validsh(char *rootsh)
{

	char	*sh, *getusershell();
	int	ret = 0;

	setusershell();
	while((sh = getusershell()) != NULL ) {
		if( strcmp( rootsh, sh) == 0 ) {
			ret = 1;
			break;
		}
	}
	endusershell();
	return(ret);
}

/*
 * sanity checks
 * return 0 if ok, 1 otherwise
 */
int
sanity_check(char *temp, time_t *mtime, char *orig)
{
	int i, ok = 0;
	FILE *ft;
	struct stat sbuf, statbuf;
	char *ldir;
	int isshadow = 0;

	if (!strcmp(orig, shadow))
		isshadow = 1;

	/* sanity checks */
	if (stat(temp, &sbuf) < 0) {
		(void)fprintf(stderr,
		    "vipw: can't stat %s file, %s unchanged\n",
		    temp, orig);
		return(1);
	}
	*mtime = sbuf.st_mtime;
	if (sbuf.st_size == 0) {
		(void)fprintf(stderr, "vipw: bad %s file, %s unchanged\n",
		    temp, orig);
		return(1);
	}
	ft = fopen(temp, "r");
	if (ft == NULL) {
		(void)fprintf(stderr,
		    "vipw: can't reopen %s file, %s unchanged\n",
		    temp, orig);
		return(1);
	}

	while (fgets(buf, sizeof (buf) - 1, ft) != NULL) {
		char *cp;

		cp = index(buf, '\n');
		if (cp == 0)
			continue;	/* ??? allow very long lines
					 * and passwd files that do
					 * not end in '\n' ???
					 */
		*cp = '\0';

		cp = index(buf, ':');
		if (cp == 0)		/* lines without colon
					 * separated fields
					 */
			continue;
		*cp = '\0';

		if (strcmp(buf, "root"))
			continue;

		/* root password */
		*cp = ':';
		cp = index(cp + 1, ':');
		if (cp == 0)
			goto bad_root;

		/* root uid for password */
		if (!isshadow)
			if (atoi(cp + 1) != 0) {

				(void)fprintf(stderr, "root UID != 0:\n%s\n",
				    buf);
				break;
			}
		/* root uid for passwd and sp_lstchg for shadow */
		cp = index(cp + 1, ':');
		if (cp == 0)
			goto bad_root;

		/* root's gid for passwd and sp_min for shadow*/
		cp = index(cp + 1, ':');
		if (cp == 0)
			goto bad_root;

		/* root's gecos for passwd and sp_max for shadow*/
		cp = index(cp + 1, ':');
		if (isshadow) {
			for (i=0; i<3; i++)
				if ((cp = index(cp + 1, ':')) == 0)
					goto bad_root;
		} else {
			if (cp == 0) {
bad_root:		(void)fprintf(stderr,
				    "Missing fields in root entry:\n%s\n", buf);
				break;
			}
		}
		if (!isshadow) {
			/* root's login directory */
			ldir = ++cp;
			cp = index(cp, ':');
			if (cp == 0)
				goto bad_root;
			*cp = '\0';
			if (stat(ldir, &statbuf) < 0) {
				*cp = ':';
				(void) fprintf(stderr,
				    "root login dir doesn't exist:\n%s\n",
				    buf);
				break;
			} else if (!S_ISDIR(statbuf.st_mode)) {
				*cp = ':';
				(void) fprintf(stderr,
				    "root login dir is not a directory:\n%s\n",
				    buf);
				break;
			}

			*cp = ':';
			/* root's login shell */
			++cp;
			if (*cp && ! validsh(cp)) {
				(void)fprintf(stderr,
				    "Invalid root shell:\n%s\n", buf);
				break;
			}
		}

		ok++;
	}
	(void)fclose(ft);
	if (ok)
		return(0);
	else {
		(void)fprintf(stderr,
		    "vipw: you mangled the %s file, %s unchanged\n",
		    temp, orig);
		return(1);
	}			
}
