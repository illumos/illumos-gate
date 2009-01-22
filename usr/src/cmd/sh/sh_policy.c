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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Policy backing functions for kpolicy=suser,profiles=yes
 *
 */

#include <sys/param.h>
#include <grp.h>
#include <pwd.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include "sh_policy.h"


static char *username;

/*
 * get the ruid and passwd name
 */
void
secpolicy_init(void)
{
	uid_t		ruid;
	struct passwd	*passwd_ent;

	if (username != NULL) {
		free(username);
		username = NULL;
	}

	ruid = getuid();

	if ((passwd_ent = getpwuid(ruid)) == NULL) {
		secpolicy_print(SECPOLICY_ERROR, ERR_PASSWD);
	} else if ((username = strdup(passwd_ent->pw_name)) == NULL) {
		secpolicy_print(SECPOLICY_ERROR, ERR_MEM);
	}
}


/*
 * stuff pfexec full path at the begining of the argument vector
 * for the command to be pfexec'd
 *
 * return newly allocated argv on success, else return NULL.
 */
static char **
secpolicy_set_argv(char **arg_v)
{
	int	i;
	int	arg_c = 0;
	char	**pfarg_v = NULL;

	if (*arg_v == NULL) {
		return (pfarg_v);
	}
	for (i = 0; arg_v[i] != NULL; i++) {
		arg_c++;
	}
	/* +2 for PFEXEC and null termination */
	if ((pfarg_v = calloc(arg_c + 2, sizeof (char *))) == NULL) {
		return (pfarg_v);
	}
	pfarg_v[0] = PFEXEC;
	for (i = 0; i < arg_c; i++) {
		pfarg_v[i + 1] = arg_v[i];
	}

	return (pfarg_v);
}


/*
 * gets realpath for cmd.
 * return 0 on success,  else return ENOENT.
 */
static int
secpolicy_getrealpath(const char *cmd, char *cmd_realpath)
{
	register char	*mover;
	char	cwd[MAXPATHLEN];

	/*
	 * What about relative paths?  Were we passed one?
	 */
	mover = (char *)cmd;
	if (*mover != '/') {
		/*
		 * Everything in here will be considered a relative
		 * path, and therefore we need to prepend cwd to it.
		 */
		if (getcwd(cwd, MAXPATHLEN) == NULL) {
			secpolicy_print(SECPOLICY_ERROR, ERR_CWD);
		}
		strcat(cwd, "/");
		if (strlcat(cwd, cmd, MAXPATHLEN) >= MAXPATHLEN) {
			return (ENOENT);
		}
		mover = cwd;
	}
	/*
	 * Resolve ".." and other such nonsense.
	 * Now, is there *REALLY* a file there?
	 */
	if (realpath(mover, cmd_realpath) == NULL) {
		return (ENOENT);
	}

	return (0);
}


/*
 * check if the command has execution attributes
 * return -
 *    - NOATTRS   : command in profile but has no execution attributes
 *    - ENOMEM    : memory allocation errors
 *    - ENOENT    : command not in profile
 */

int
secpolicy_pfexec(const char *command, char **arg_v, const char **xecenv)
{
	register int	status = NOATTRS;
	char		**pfarg_v = (char **)NULL;
	char		cmd_realpath[MAXPATHLEN + 1];
	execattr_t	*exec;

	if ((status = secpolicy_getrealpath(command, cmd_realpath)) != 0) {
		return (status);
	}
	if ((exec = getexecuser(username, KV_COMMAND,
	    (const char *)cmd_realpath, GET_ONE)) == NULL) {
		/*
		 * command not in profile
		 */
		return (ENOENT);
	}
	/*
	 * In case of "All" profile, we'd go through pfexec
	 * if it had any attributes.
	 */
	if ((exec->attr != NULL) && (exec->attr->length != 0)) {
		/*
		 * command in profile and has attributes
		 */
		free_execattr(exec);
		arg_v[0] = (char *)command;
		pfarg_v = secpolicy_set_argv(arg_v);
		if (pfarg_v != NULL) {
			errno = 0;
			if (xecenv == NULL) {
				execv(PFEXEC, (char *const *)pfarg_v);
			} else {
				execve(PFEXEC, (char *const *)pfarg_v,
				    (char *const *)xecenv);
			}
			free(pfarg_v);
			status = errno;
		} else {
			status = ENOMEM;
		}
	} else {
		/*
		 * command in profile, but has no attributes
		 */
		free_execattr(exec);
		status = NOATTRS;
	}


	return (status);
}
