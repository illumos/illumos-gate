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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>	/* creat() declaration */
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include "install.h"
#include "libadm.h"
#include "libinst.h"
#include "pkginstall.h"
#include "messages.h"

extern char	tmpdir[], instdir[];
extern int	pkgverbose;

static int	do_exec(int update, char *script, char *output,
			char *inport, char *alt_user);
static char	path[PATH_MAX];
static char	*resppath = NULL;
static int	fd;
static int	respfile_defined = 0;
static int	respfile_ro = 0;	/* read only resp file */

/*
 * This informs the calling routine if a read-only response file has been
 * provided on the command line.
 */
int
rdonly_respfile(void)
{
	return (respfile_ro);
}

int
is_a_respfile(void)
{
	return (respfile_defined);
}

/*
 * This function creates a working copy of the checkinstall script.
 * This is needed in situations where the packages parent directories modes
 * are set too restrictively, i.e. 700.
 *
 * Returns: A pointer to the location of the copied checkinstall
 * script or NULL
 */

char *
dup_chkinstall(char *script)
{
	char	*dstpath;
	size_t	dstpathLen;
	int	r;
static	char	*tmpname = "checkinstallXXXXXX";

	/* determine length for destination script path */

	dstpathLen = strlen(tmpdir) + strlen(tmpname) + 3;

	/* allocate storage to hold destination script path */

	dstpath = (char *)malloc(dstpathLen);
	if (dstpath == (char *)NULL) {
		return ((char *)NULL);
	}

	/* create destination script path */

	(void) snprintf(dstpath, dstpathLen, "%s/%s", tmpdir, tmpname);

	if (mktemp(dstpath) == NULL) {
		progerr(ERR_TMPFILE_CHK);
		(void) free(dstpath);
		return (NULL);
	}

	/* make copy of script */

	r = copyf(script, dstpath, (time_t)0);
	if (r != 0) {
		progerr(ERR_CANNOT_COPY, script, dstpath);
		return (NULL);
	}

	/* Make the copy of the script readable by all */

	if (chmod(dstpath, 0444) != 0) {
		progerr(ERR_CHMOD_CHK);
		(void) free(dstpath);
		return (NULL);
	}

	return (dstpath);
}

/*
 * This function creates a temporary working copy of a read-only response
 * file. It changes the resppath pointer to point to the working copy.
 */
static int
dup_respfile(void)
{
	char	tpath[PATH_MAX];
	int	r;

	(void) strlcpy(tpath, path, sizeof (tpath));

	(void) snprintf(path, sizeof (path), "%s/respXXXXXX", tmpdir);

	resppath = mktemp(path);
	if (resppath == NULL) {
		progerr(ERR_TMPRESP);
		return (99);
	}

	/* Copy the contents of the user's response file to the working copy. */

	r = copyf(tpath, resppath, (time_t)0);
	if (r != 0) {
		progerr(ERR_NORESPCOPY, tpath, resppath);
		return (99);
	}

	/*
	 * Make it writable by the non-privileged installation user-id,
	 * but readable by the world.
	 */

	if (chmod(resppath, 0644) != 0) {
		progerr(ERR_CHMOD, resppath);
		return (99);
	}

	respfile_ro = 0;

	return (0);
}

/*
 * This function establishes the response file passed on the command line if
 * it's called with a valid string. If called with NULL, it checks to see if
 * there's a response file already. If there isn't, it creates a temporary.
 */
int
set_respfile(char *respfile, char *pkginst, int resp_stat)
{
	if (respfile == NULL && !respfile_defined) {
		/* A temporary response file needs to be constructed. */
		(void) snprintf(path, sizeof (path), "%s/respXXXXXX", tmpdir);
		resppath = mktemp(path);
		if (resppath == NULL) {
			progerr(ERR_TMPRESP);
			return (99);
		}
	} else {
		/* OK, we're being passed a response file or directory. */
		if (isdir(respfile) == 0) {
			(void) snprintf(path, sizeof (path),
				"%s/%s", respfile, pkginst);
		} else {
			(void) strlcpy(path, respfile, sizeof (path));
		}

		resppath = path;
		respfile_ro = resp_stat;
	}

	respfile_defined++;

	return (0);
}

/* This exposes the working response file. */
char *
get_respfile(void)
{
	return (resppath);
}

/*
 * Execute the request script if present assuming the response file
 * isn't read only.
 */
int
reqexec(int update, char *script, int non_abi_scripts,
	boolean_t enable_root_user)
{
	char	*req_user;

	/*
	 * determine which alternative user to execute the request script as
	 * if the default user "install" is not defined.
	 */

	if (enable_root_user == B_TRUE) {
		/* use the root user */
		req_user = CHK_USER_ROOT;
	} else if (non_abi_scripts != 0) {
		/* non-compliant package user */
		req_user = CHK_USER_NON;
	} else {
		/* standard non-privileged user */
		req_user = CHK_USER_ALT;
	}

	/*
	 * If we can't get to the the script or the response file, skip this.
	 */
	if (access(script, F_OK) != 0 || respfile_ro)
		return (0);

	/* No interact means no interact. */
	if (echoGetFlag() == B_FALSE) {
		ptext(stderr, ERR_INTR);
		return (5);
	}

	/* If there's no response file, create one. */
	if (!respfile_defined)
		if (set_respfile(NULL, NULL, 0))
			return (99);

	/* Clear out the old response file (if there is one). */
	if ((access(resppath, F_OK) == 0) && unlink(resppath)) {
		progerr(ERR_RMRESP, resppath);
		return (99);
	}

	/*
	 * Create a zero length response file which is only writable
	 * by the non-privileged installation user-id, but is readable
	 * by the world
	 */
	if ((fd = open(resppath, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644)) < 0) {
		progerr(ERR_CRERESP, resppath);
		return (99);
	}
	(void) close(fd);

	return (do_exec(update, script, resppath, REQ_STDIN, req_user));
}

int
chkexec(int update, char *script)
{
	/*
	 * If we're up against a read-only response file from the command
	 * line. Create a working copy.
	 */
	if (respfile_ro) {
		if (dup_respfile())

			return (99);

		/* Make sure we can get to it. */
		if ((access(resppath, F_OK) != 0)) {
			progerr(ERR_ACCRESP, resppath);
			return (7);
		}
	}

	/* If there's no response file, create a fresh one. */
	else if (!respfile_defined) {
		if (set_respfile(NULL, NULL, 0))
			return (99);

		/*
		 * create a zero length response file which is only writable
		 * by the non-priveledged installation user-id, but is readable
		 * by the world
		 */
		fd = open(resppath, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644);
		if (fd < 0) {
			progerr(ERR_CRERESP, resppath);
			return (99);
		}
		(void) close(fd);
	}

	return (do_exec(update, script, resppath, CHK_STDIN, CHK_USER_ALT));
}

static int
do_exec(int update, char *script, char *output, char *inport, char *alt_user)
{
	char		*gname;
	char		*tmp_script;
	char		*uname;
	gid_t		instgid;
	int		retcode = 0;
	struct group	*grp;
	struct passwd	*pwp;
	uid_t		instuid;

	/*
	 * Determine which user to run the request script as:
	 * - if CHK_USER is a valid user, run the script as CHK_USER
	 * - otherwise, if alt_user is a valid user, run the script
	 * -- as alt_user
	 * - otherwise, output an error message and return failure
	 */

	if ((pwp = getpwnam(CHK_USER)) != (struct passwd *)NULL) {
		instuid = pwp->pw_uid;
		uname = CHK_USER;
	} else if ((pwp = getpwnam(alt_user)) != (struct passwd *)NULL) {
		instuid = pwp->pw_uid;
		uname = alt_user;
	} else {
		ptext(stderr, ERR_BADUSER, CHK_USER, CHK_USER_ALT);
		return (1);
	}

	/*
	 * Determine which group to run the request script as:
	 * - If CHK_GRP is a valid group, run the script as CHK_GRP
	 * - otherwise, assume group "1" user "other"
	 */

	if ((grp = getgrnam(CHK_GRP)) != (struct group *)NULL) {
		instgid = grp->gr_gid;
		gname = CHK_GRP;
	} else {
		instgid = (gid_t)1;	/* "other" group id */
		gname = "other";	/* "other" group name */
	}

	echoDebug(DBG_DO_EXEC_REQUEST_USER, script, output, uname, instuid,
		gname, instgid);

	(void) chown(output, instuid, instgid);

	/*
	 * Copy the checkinstall script to tmpdir in case parent directories
	 * are restrictive, i.e. 700. Only do this for non updates, i.e.
	 * package installs and not patch package installs.
	 */
	if (update) {
		tmp_script = strdup(script);
	} else if ((tmp_script = dup_chkinstall(script)) == NULL) {
		/* Use the original checkinstall script */
		tmp_script = strdup(script);
	}

	if (pkgverbose)
		retcode = pkgexecl(inport, CHK_STDOUT, uname, CHK_GRP, SHELL,
		    "-x", tmp_script, output, NULL);
	else
		retcode = pkgexecl(inport, CHK_STDOUT, uname, CHK_GRP, SHELL,
		    tmp_script, output, NULL);

	free(tmp_script);
	return (retcode);
}
