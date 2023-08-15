/***************************************************************************
 *
 * util_helper.c - HAL utilities for helper (as e.g. prober/addons) et al.
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <grp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <pwd.h>
#include <unistd.h>

#include "logger.h"

#include "util_helper.h"

#ifdef __linux__
extern char **environ;
#endif

static char **argv_buffer = NULL;
static size_t argv_size = 0;

#ifdef sun
#include <priv.h>
void
drop_privileges(int keep_auxgroups)
{
	priv_set_t *pPrivSet;

	/*
	 * Start with the 'basic' privilege set and then remove any
	 * of the 'basic' privileges that will not be needed.
	 */
	if ((pPrivSet = priv_allocset()) == NULL) {
		return;
	}

	/*
	 * Establish the basic set of privileges.
	 * Note: fork/exec required for libdevinfo devlink
	 * interfaces are included in the basic set.
	 */
	priv_basicset(pPrivSet);

	/* Clear privileges we will not need from the 'basic' set */
	(void) priv_delset(pPrivSet, PRIV_FILE_LINK_ANY);
	(void) priv_delset(pPrivSet, PRIV_PROC_INFO);
	(void) priv_delset(pPrivSet, PRIV_PROC_SESSION);

	/* for sysevent need to be root and have this privilege */
	(void) priv_addset(pPrivSet, PRIV_SYS_CONFIG);

	/* need proc_audit privilege */
	(void) priv_addset(pPrivSet, PRIV_PROC_AUDIT);

	/* Set the permitted privilege set. */
	(void) setppriv(PRIV_SET, PRIV_PERMITTED, pPrivSet);

	/* Set the limit privilege set. */
	(void) setppriv(PRIV_SET, PRIV_LIMIT, pPrivSet);

	priv_freeset(pPrivSet);
}
#else /* !sun */

/** Drop root privileges: Set the running user id to HAL_USER and
 *  group to HAL_GROUP, and optionally retain auxiliary groups of HAL_USER.
 */
void
drop_privileges (int keep_auxgroups)
{
	struct passwd *pw = NULL;
	struct group *gr = NULL;

	/* determine user id */
	pw = getpwnam (HAL_USER);
	if (!pw)  {
		HAL_DEBUG (("drop_privileges: user " HAL_USER " does not exist"));
		exit (-1);
	}

	/* determine primary group id */
	gr = getgrnam (HAL_GROUP);
	if (!gr) {
		HAL_DEBUG (("drop_privileges: group " HAL_GROUP " does not exist"));
		exit (-1);
	}

	if (keep_auxgroups) {
		if (initgroups (HAL_USER, gr->gr_gid)) {
			HAL_DEBUG(("drop_privileges: could not initialize groups"));
			exit (-1);
		}
	}

	if (setgid (gr->gr_gid)) {
		HAL_DEBUG (("drop_privileges: could not set group id"));
		exit (-1);
	}

	if (setuid (pw->pw_uid)) {
		HAL_DEBUG (("drop_privileges: could not set user id"));
		exit (-1);
	}
}
#endif /* !sun */

void
hal_set_proc_title_init (int argc, char *argv[])
{
#ifdef __linux__
	unsigned int i;
	char **new_environ, *endptr;

	/* This code is really really ugly. We make some memory layout
	 * assumptions and reuse the environment array as memory to store
	 * our process title in */

	for (i = 0; environ[i] != NULL; i++)
		;

	endptr = i ? environ[i-1] + strlen (environ[i-1]) : argv[argc-1] + strlen (argv[argc-1]);

	argv_buffer = argv;
	argv_size = endptr - argv_buffer[0];

	/* Make a copy of environ */

	new_environ = malloc (sizeof(char*) * (i + 1));
	for (i = 0; environ[i] != NULL; i++)
		new_environ[i] = strdup (environ[i]);
	new_environ[i] = NULL;

	environ = new_environ;
#endif
}

/* this code borrowed from avahi-daemon's setproctitle.c (LGPL v2) */
void
hal_set_proc_title (const char *format, ...)
{
#ifdef __linux__
	size_t len;
	va_list ap;

	if (argv_buffer == NULL)
		goto out;

	va_start (ap, format);
	vsnprintf (argv_buffer[0], argv_size, format, ap);
	va_end (ap);

	len = strlen (argv_buffer[0]);

	memset (argv_buffer[0] + len, 0, argv_size - len);
	argv_buffer[1] = NULL;
out:
	;
#endif
}

