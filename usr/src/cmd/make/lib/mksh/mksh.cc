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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


/*
 *	mksh.cc
 *
 *	Execute the command(s) of one Make or DMake rule
 */

/*
 * Included files
 */
#include <mksh/dosys.h>		/* redirect_io() */
#include <mksh/misc.h>		/* retmem() */
#include <mksh/mksh.h>
#include <errno.h>
#include <signal.h>


/*
 * Workaround for NFS bug. Sometimes, when running 'chdir' on a remote
 * dmake server, it fails with "Stale NFS file handle" error.
 * The second attempt seems to work.
 */
int
my_chdir(char * dir) {
	int res = chdir(dir);
	if (res != 0 && (errno == ESTALE || errno == EAGAIN)) {
		/* Stale NFS file handle. Try again */
		res = chdir(dir);
	}
	return res;
}


/*
 * File table of contents
 */
static void	change_sunpro_dependencies_value(char *oldpath, char *newpath);
static void	init_mksh_globals(char *shell);
static void	set_env_vars(char *env_list[]);


static void
set_env_vars(char *env_list[])
{
	char			**env_list_p;

	for (env_list_p = env_list;
	     *env_list_p != (char *) NULL;
	     env_list_p++) {
		putenv(*env_list_p);
	}
}

static void
init_mksh_globals(char *shell)
{
/*
	MBSTOWCS(wcs_buffer, "SHELL");
	shell_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, shell);
	(void) SETVAR(shell_name, GETNAME(wcs_buffer, FIND_LENGTH), false);
 */
	char * dmake_shell;
	if ((dmake_shell = getenv("DMAKE_SHELL")) == NULL) {
		dmake_shell = shell;
	} 
	MBSTOWCS(wcs_buffer, dmake_shell);
	shell_name = GETNAME(wcs_buffer, FIND_LENGTH);
}

/*
 * Change the pathname in the value of the SUNPRO_DEPENDENCIES env variable
 * from oldpath to newpath.
 */
static void
change_sunpro_dependencies_value(char *oldpath, char *newpath)
{
	char		buf[MAXPATHLEN];
	static char	*env;
	int		length;
	int		oldpathlen;
	char		*sp_dep_value;

	/* check if SUNPRO_DEPENDENCIES is set in the environment */
	if ((sp_dep_value = getenv("SUNPRO_DEPENDENCIES")) != NULL) {
		oldpathlen = strlen(oldpath);
		/* check if oldpath is indeed in the value of SUNPRO_DEPENDENCIES */
		if (strncmp(oldpath, sp_dep_value, oldpathlen) == 0) {
			(void) sprintf(buf,
				       "%s%s",
				       newpath,
				       sp_dep_value + oldpathlen);
			length = 2 +
				strlen("SUNPRO_DEPENDENCIES") +
				strlen(buf);
			env = getmem(length);
			(void) sprintf(env,
				       "%s=%s",
				       "SUNPRO_DEPENDENCIES",
				       buf);
			(void) putenv(env);
		}
	}
}


