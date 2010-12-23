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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1996-1998, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3 */
/*LINTLIBRARY*/

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "valtools.h"
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "libadm.h"

#define	E_SYNTAX	"does not meet suggested filename syntax standard"
#define	E_READ		"is not readable"
#define	E_WRITE		"is not writable"
#define	E_EXEC		"is not executable"
#define	E_CREAT		"cannot be created"
#define	E_ABSOLUTE	"must begin with a slash (/)"
#define	E_RELATIVE	"must not begin with a slash (/)"
#define	E_EXIST		"does not exist"
#define	E_NEXIST	"must not already exist"
#define	E_BLK		"must specify a block special device"
#define	E_CHR		"must specify a character special device"
#define	E_DIR		"must specify a directory"
#define	E_REG		"must be a regular file"
#define	E_NONZERO	"must be a file of non-zero length"

#define	H_READ		"must be readable"
#define	H_WRITE		"must be writable"
#define	H_EXEC		"must be executable"
#define	H_CREAT		"will be created if it does not exist"
#define	H_ABSOLUTE	E_ABSOLUTE
#define	H_RELATIVE	E_RELATIVE
#define	H_EXIST		"must already exist"
#define	H_NEXIST	"must not already exist"
#define	H_BLK		E_BLK
#define	H_CHR		E_CHR
#define	H_DIR		E_DIR
#define	H_REG		E_REG
#define	H_NONZERO	E_NONZERO

#define	MSGSIZ	1024
#define	STDHELP \
	"A pathname is a filename, optionally preceded by parent directories."

static char	*errstr;
static char	*badset = "*?[]{}()<> \t'`\"\\|^";

static void
addhlp(char *msg, char *text)
{
	static int count;

	if (text == NULL) {
		count = 0;
		return;
	}
	if (!count++)
		(void) strcat(msg, " The pathname you enter:");
	(void) strcat(msg, "\\n\\t-\\ ");
	(void) strcat(msg, text);
}

static char *
sethlp(int pflags)
{
	char	*msg;

	msg = calloc(MSGSIZ, sizeof (char));
	addhlp(msg, NULL); /* initialize count */
	(void) strcpy(msg, STDHELP);

	if (pflags & P_EXIST)
		addhlp(msg, H_EXIST);
	else if (pflags & P_NEXIST)
		addhlp(msg, H_NEXIST);

	if (pflags & P_ABSOLUTE)
		addhlp(msg, H_ABSOLUTE);
	else if (pflags & P_RELATIVE)
		addhlp(msg, H_RELATIVE);

	if (pflags & P_READ)
		addhlp(msg, H_READ);
	if (pflags & P_WRITE)
		addhlp(msg, H_WRITE);
	if (pflags & P_EXEC)
		addhlp(msg, H_EXEC);
	if (pflags & P_CREAT)
		addhlp(msg, H_CREAT);

	if (pflags & P_BLK)
		addhlp(msg, H_BLK);
	else if (pflags & P_CHR)
		addhlp(msg, H_CHR);
	else if (pflags & P_DIR)
		addhlp(msg, H_DIR);
	else if (pflags & P_REG)
		addhlp(msg, H_REG);

	if (pflags & P_NONZERO)
		addhlp(msg, H_NONZERO);

	return (msg);
}

int
ckpath_stx(int pflags)
{
	if (((pflags & P_ABSOLUTE) && (pflags & P_RELATIVE)) ||
	    ((pflags & P_NEXIST) && (pflags &
		(P_EXIST|P_NONZERO|P_READ|P_WRITE|P_EXEC))) ||
	    ((pflags & P_CREAT) && (pflags & (P_EXIST|P_NEXIST|P_BLK|P_CHR))) ||
	    ((pflags & P_BLK) && (pflags & (P_CHR|P_REG|P_DIR|P_NONZERO))) ||
	    ((pflags & P_CHR) && (pflags & (P_REG|P_DIR|P_NONZERO))) ||
	    ((pflags & P_DIR) && (pflags & P_REG))) {
		return (1);
	}
	return (0);
}

int
ckpath_val(char *path, int pflags)
{
	struct stat64 status;
	int	fd;
	char	*pt;

	if ((pflags & P_RELATIVE) && (*path == '/')) {
		errstr = E_RELATIVE;
		return (1);
	}
	if ((pflags & P_ABSOLUTE) && (*path != '/')) {
		errstr = E_ABSOLUTE;
		return (1);
	}
	if (stat64(path, &status)) {
		if (pflags & P_EXIST) {
			errstr = E_EXIST;
			return (1);
		}
		for (pt = path; *pt; pt++) {
			if (!isprint((unsigned char)*pt) ||
				strchr(badset, *pt)) {
				errstr = E_SYNTAX;
				return (1);
			}
		}
		if (pflags & P_CREAT) {
			if (pflags & P_DIR) {
				if ((mkdir(path, 0755)) != 0) {
					errstr = E_CREAT;
					return (1);
				}
			} else {
				if ((fd = creat(path, 0644)) < 0) {
					errstr = E_CREAT;
					return (1);
				}
				(void) close(fd);
			}
		}
		return (0);
	} else if (pflags & P_NEXIST) {
		errstr = E_NEXIST;
		return (1);
	}
	if ((status.st_mode & S_IFMT) == S_IFREG) {
		/* check non zero status */
		if ((pflags & P_NONZERO) && (status.st_size < 1)) {
			errstr = E_NONZERO;
			return (1);
		}
	}
	if ((pflags & P_CHR) && ((status.st_mode & S_IFMT) != S_IFCHR)) {
		errstr = E_CHR;
		return (1);
	}
	if ((pflags & P_BLK) && ((status.st_mode & S_IFMT) != S_IFBLK)) {
		errstr = E_BLK;
		return (1);
	}
	if ((pflags & P_DIR) && ((status.st_mode & S_IFMT) != S_IFDIR)) {
		errstr = E_DIR;
		return (1);
	}
	if ((pflags & P_REG) && ((status.st_mode & S_IFMT) != S_IFREG)) {
		errstr = E_REG;
		return (1);
	}
	if ((pflags & P_READ) && !(status.st_mode & S_IREAD)) {
		errstr = E_READ;
		return (1);
	}
	if ((pflags & P_WRITE) && !(status.st_mode & S_IWRITE)) {
		errstr = E_WRITE;
		return (1);
	}
	if ((pflags & P_EXEC) && !(status.st_mode & S_IEXEC)) {
		errstr = E_EXEC;
		return (1);
	}
	return (0);
}

void
ckpath_err(int pflags, char *error, char *input)
{
	char	buffer[2048];
	char	*defhlp;

	if (input) {
		if (ckpath_val(input, pflags)) {
			(void) sprintf(buffer, "Pathname %s.", errstr);
			puterror(stdout, buffer, error);
			return;
		}
	}
	defhlp = sethlp(pflags);
	puterror(stdout, defhlp, error);
	free(defhlp);
}

void
ckpath_hlp(int pflags, char *help)
{
	char	*defhlp;

	defhlp = sethlp(pflags);
	puthelp(stdout, defhlp, help);
	free(defhlp);
}

int
ckpath(char *pathval, int pflags, char *defstr, char *error, char *help,
	char *prompt)
{
	char	*defhlp,
		input[MAX_INPUT],
		buffer[256];

	if ((pathval == NULL) || ckpath_stx(pflags))
		return (2); /* usage error */

	if (!prompt) {
		if (pflags & P_ABSOLUTE)
			prompt = "Enter an absolute pathname";
		else if (pflags & P_RELATIVE)
			prompt = "Enter a relative pathname";
		else
			prompt = "Enter a pathname";
	}
	defhlp = sethlp(pflags);

start:
	putprmpt(stderr, prompt, NULL, defstr);
	if (getinput(input)) {
		free(defhlp);
		return (1);
	}

	if (strlen(input) == 0) {
		if (defstr) {
			(void) strcpy(pathval, defstr);
			free(defhlp);
			return (0);
		}
		puterror(stderr, NULL, "Input is required.");
		goto start;
	}
	if (strcmp(input, "?") == 0) {
		puthelp(stderr, defhlp, help);
		goto start;
	}
	if (ckquit && (strcmp(input, "q") == 0)) {
		free(defhlp);
		return (3);
	}

	if (ckpath_val(input, pflags)) {
		(void) sprintf(buffer, "Pathname %s.", errstr);
		puterror(stderr, buffer, error);
		goto start;
	}
	(void) strcpy(pathval, input);
	free(defhlp);
	return (0);
}
