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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Administrative tool to add a new user to the publickey database
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <rpc/key_prot.h>
#include <rpcsvc/ypclnt.h>
#include <sys/wait.h>
#include <netdb.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#define	MAXMAPNAMELEN 256

extern	char	*program_name;

static	char	*basename(char *path);
static	int	match(char *line, char *name);
static	int	_openchild(char *command, FILE **fto, FILE **ffrom);
static	char	SHELL[] = "/bin/sh";
static	char	UPDATEFILE[] = "updaters";
static	char	MAKE[] = "/usr/ccs/bin/make";

/*
 * Determine if requester is allowed to update the given map,
 * and update it if so. Returns the yp status, which is zero
 * if there is no access violation.
 */
int
mapupdate(char *name, char *mapname, uint_t op, char *data)
{
	char	updater[MAXMAPNAMELEN + 40];
	FILE	*childargs;
	FILE	*childrslt;
#ifdef WEXITSTATUS
	int	status;
#else
	union wait status;
#endif
	pid_t	pid;
	uint_t	yperrno;
	int	namelen, datalen;
	struct	stat	stbuf;

#ifdef DEBUG
	(void) fprintf(stderr, "%s %s\n", name, data);
#endif
	namelen = strlen(name);
	datalen = strlen(data);
	errno = 0;
	if (stat(MAKE, &stbuf) < 0)
		switch (errno) {
		case ENOENT:
			(void) fprintf(stderr,
			"%s: %s not found, please install on the system\n",
			program_name, MAKE);
			return (1);
		default:
			(void) fprintf(stderr,
				"%s: cannot access %s, errno=%d.\n",
				program_name, MAKE, errno);
			return (1);
		}
	(void) sprintf(updater, "%s -s -f %s %s",
			MAKE, UPDATEFILE, mapname);
	pid = _openchild(updater, &childargs, &childrslt);
	if (pid < 0)
		return (YPERR_YPERR);

	/*
	 * Write to child
	 */
	(void) fprintf(childargs, "%s\n", name);
	(void) fprintf(childargs, "%u\n", op);
	(void) fprintf(childargs, "%u\n", namelen);
	(void) fwrite(name, namelen, 1, childargs);
	(void) fprintf(childargs, "\n");
	(void) fprintf(childargs, "%u\n", datalen);
	(void) fwrite(data, datalen, 1, childargs);
	(void) fprintf(childargs, "\n");
	(void) fclose(childargs);

	/*
	 * Read from child
	 */
	(void) fscanf(childrslt, "%d", &yperrno);
	(void) fclose(childrslt);

	(void) wait(&status);
#ifdef WEXITSTATUS
	if (WEXITSTATUS(status) != 0) {
#else
	if (status.w_retcode != 0) {
#endif
		return (YPERR_YPERR);
	}
	return (yperrno);
}

/*
 * returns pid, or -1 for failure
 */
static int
_openchild(char *command, FILE **fto, FILE **ffrom)
{
	int i;
	pid_t pid;
	int pdto[2];
	int pdfrom[2];
	char *com;

	if (pipe(pdto) < 0) {
		goto error1;
	}
	if (pipe(pdfrom) < 0) {
		goto error2;
	}
#ifdef VFORK
	switch (pid = vfork()) {
#else
	switch (pid = fork()) {
#endif
	case -1:
		goto error3;

	case 0:
		/*
		 * child: read from pdto[0], write into pdfrom[1]
		 */
		(void) close(0);
		(void) dup(pdto[0]);
		(void) close(1);
		(void) dup(pdfrom[1]);
		closefrom(3);
		com = malloc((unsigned)strlen(command) + 6);
		if (com == NULL) {
			_exit(~0);
		}
		(void) sprintf(com, "exec %s", command);
		execl(SHELL, basename(SHELL), "-c", com, NULL);
		_exit(~0);

	default:
		/*
		 * parent: write into pdto[1], read from pdfrom[0]
		 */
		*fto = fdopen(pdto[1], "w");
		(void) close(pdto[0]);
		*ffrom = fdopen(pdfrom[0], "r");
		(void) close(pdfrom[1]);
		break;
	}
	return (pid);

	/*
	 * error cleanup and return
	 */
error3:
	(void) close(pdfrom[0]);
	(void) close(pdfrom[1]);
error2:
	(void) close(pdto[0]);
	(void) close(pdto[1]);
error1:
	return (-1);
}

static char *
basename(char *path)
{
	char	*p;

	p = strrchr(path, '/');
	if (p == NULL)
		return (path);
	return (p + 1);
}

/*
 * Determine if requester is allowed to update the given map,
 * and update it if so. Returns the status, which is zero
 * if there is no access violation, 1 otherwise.
 * This function updates the local file.
 */
int
localupdate(char *name, char *filename, uint_t op, char *data)
{
	char	line[256];
	FILE	*rf;
	FILE	*wf;
	int	wfd;
	char	tmpname[80];
	int	err;

	/*
	 * Check permission
	 */
	if (strcmp(name, "nobody") == 0) {
		/* cannot change keys for nobody */
		(void) fprintf(stderr,
			"%s: cannot change key-pair for %s\n",
			program_name, name);
		return (1);
	}

	/*
	 * Open files
	 */
	(void) memset(tmpname, 0, 80);
	(void) sprintf(tmpname, "%s.tmp", filename);
	rf = fopen(filename, "r");
	if (rf == NULL) {
		(void) fprintf(stderr,
		"%s: cannot read %s\n", program_name, filename);
		return (1);
	}

	(void) umask(0);

	/*
	 * Create the new file with the correct permissions
	 */
	wfd = open(tmpname, O_CREAT|O_RDWR|O_TRUNC,
					S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if (wfd == -1) {
		(void) fprintf(stderr, "%s: cannot create '%s' to write to.\n",
			program_name, tmpname);
		(void) fclose(rf);
		return (1);
	}
	wf = fdopen(wfd, "w");
	if (wf == NULL) {
		(void) fprintf(stderr, "%s: cannot fdopen '%s'.\n",
			program_name, tmpname);
		(void) close(wfd);
		(void) fclose(rf);
		return (1);
	}

	err = -1;
	while (fgets(line, sizeof (line), rf)) {
		if (err < 0 && match(line, name)) {
			switch (op) {
			case YPOP_INSERT:
				err = 1;
				break;
			case YPOP_STORE:
			case YPOP_CHANGE:
				(void) fprintf(wf, "%s\t%s\n", name, data);
				err = 0;
				break;
			case YPOP_DELETE:
				/* do nothing */
				err = 0;
				break;
			}
		} else {
			fputs(line, wf);
		}
	}
	if (err < 0) {
		switch (op) {
		case YPOP_CHANGE:
		case YPOP_DELETE:
			err = 1;
			break;
		case YPOP_INSERT:
		case YPOP_STORE:
			err = 0;
			(void) fprintf(wf, "%s\t%s\n", name, data);
			break;
		}
	}
	(void) fclose(wf);
	(void) fclose(rf);
	if (err == 0) {
		if (rename(tmpname, filename) < 0) {
			(void) fprintf(stderr,
				"%s: cannot rename %s to %s\n",
				program_name, tmpname, filename);
			return (1);
		}
	} else {
		if (unlink(tmpname) < 0) {
			(void) fprintf(stderr,
				"%s: cannot delete %s\n",
				program_name, tmpname);
			return (1);
		}
	}
	return (err);
}

static int
match(char *line, char *name)
{
	int	len;

	len = strlen(name);
	return (strncmp(line, name, len) == 0 &&
		(line[len] == ' ' || line[len] == '\t'));
}
